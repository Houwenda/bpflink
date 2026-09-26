use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use crate::socket::{BpfListener, BpfStream};
use crate::transport::TransportMode;
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerAddr {
    pub ip: IpAddr,
}

impl PeerAddr {
    pub fn parse_with_interface(
        input: impl AsRef<str>,
        interface: impl AsRef<str>,
    ) -> Result<Self> {
        Ok(Self {
            ip: parse_scoped_ip(input, interface)?,
        })
    }
}

pub fn parse_scoped_ip(input: impl AsRef<str>, interface: impl AsRef<str>) -> Result<IpAddr> {
    let input = input.as_ref();
    let interface = interface.as_ref();
    let Some((addr, scope)) = input.split_once('%') else {
        return input
            .parse()
            .map_err(|_| Error::Config("invalid IP address"));
    };

    if scope.is_empty() {
        return Err(Error::Config("IPv6 scope id must not be empty"));
    }
    if scope != interface {
        return Err(Error::Config("IPv6 scope id must match interface"));
    }

    let addr = addr
        .parse::<Ipv6Addr>()
        .map_err(|_| Error::Config("invalid scoped IPv6 address"))?;
    if !addr.is_unicast_link_local() {
        return Err(Error::Config(
            "IPv6 scope id is only supported for link-local addresses",
        ));
    }

    Ok(IpAddr::V6(addr))
}

#[derive(Clone, Debug)]
pub struct Link {
    runtime_driver: Option<Arc<crate::runtime::RuntimeDriver>>,
    service_ports: Vec<u16>,
    local_ip: Option<IpAddr>,
    transport_mode: TransportMode,
    #[cfg(feature = "test-util")]
    test_driver: Option<crate::runtime::TestDriver>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkStats {
    pub service_ports: Vec<u16>,
    pub transport_mode: &'static str,
    pub mtu: usize,
    pub payload_target: usize,
    pub sees_sent_configured: Option<bool>,
    pub filter_configured: Option<bool>,
    pub listener_count: usize,
    pub session_count: usize,
    pub command_count: usize,
    pub poll_count: usize,
    pub stream_write_count: usize,
    pub outbound_datagram_count: usize,
    pub inbound_accept_count: usize,
    pub inbound_data_count: usize,
    pub ignored_icmp_count: usize,
    pub closed_session_count: usize,
    pub idle_timeout_count: usize,
    pub backpressure_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkConfig {
    /// Interface name such as `en0`, `bridge100`, or `eth0`.
    pub interface: String,
    /// Local IP address that already belongs to the selected interface.
    pub local_ip: IpAddr,
    /// Complete build-time service-port set for this link.
    pub service_ports: Vec<u16>,
    /// Transport implementation used for streams created by this link.
    pub transport_mode: TransportMode,
}

#[derive(Debug, Default)]
pub struct LinkBuilder {
    interface: Option<String>,
    local_ip: Option<IpAddr>,
    service_ports: Vec<u16>,
    transport_mode: TransportMode,
}

impl Link {
    pub fn builder() -> LinkBuilder {
        LinkBuilder::default()
    }

    #[cfg(feature = "test-util")]
    pub fn new_for_test_with_service_ports(service_ports: impl IntoIterator<Item = u16>) -> Self {
        let service_ports = crate::bpf::filter::normalize_service_ports(
            &service_ports.into_iter().collect::<Vec<_>>(),
        )
        .expect("valid test service ports");
        Self {
            runtime_driver: None,
            service_ports: service_ports.clone(),
            local_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            transport_mode: TransportMode::Kcp,
            test_driver: Some(crate::runtime::TestDriver::with_service_ports(
                service_ports,
            )),
        }
    }

    #[cfg(feature = "test-util")]
    pub fn recorded_commands(&self) -> Vec<crate::runtime::TestCommand> {
        self.test_driver
            .as_ref()
            .map(crate::runtime::TestDriver::commands)
            .unwrap_or_default()
    }

    pub async fn connect(&self, peer: PeerAddr, service_port: u16) -> Result<BpfStream> {
        self.ensure_service_port(service_port)?;
        #[cfg(feature = "test-util")]
        if let Some(driver) = &self.test_driver {
            driver.record(crate::runtime::TestCommand::Connect { peer, service_port });
            return driver.connect(peer, service_port);
        }

        if let Some(driver) = &self.runtime_driver {
            return driver.connect(peer, service_port).await;
        }

        Err(Error::DriverClosed)
    }

    /// Connects to a peer and returns [`Error::Timeout`] if the runtime does
    /// not complete the operation before `timeout`.
    pub async fn connect_timeout(
        &self,
        peer: PeerAddr,
        service_port: u16,
        timeout: Duration,
    ) -> Result<BpfStream> {
        tokio::time::timeout(timeout, self.connect(peer, service_port))
            .await
            .map_err(|_| Error::Timeout)?
    }

    pub async fn listen(&self, service_port: u16) -> Result<BpfListener> {
        self.ensure_service_port(service_port)?;
        #[cfg(feature = "test-util")]
        if let Some(driver) = &self.test_driver {
            driver.record(crate::runtime::TestCommand::Listen { service_port });
            return driver.listen(service_port);
        }

        if let Some(driver) = &self.runtime_driver {
            return driver.listen(service_port).await;
        }

        Err(Error::DriverClosed)
    }

    pub async fn stats(&self) -> Result<LinkStats> {
        #[cfg(feature = "test-util")]
        if let Some(driver) = &self.test_driver {
            return Ok(driver.snapshot(&self.service_ports, self.transport_mode.as_str()));
        }

        self.runtime_driver
            .as_ref()
            .ok_or(Error::LinkClosed)?
            .snapshot()
            .await
            .map(LinkStats::from)
    }

    pub(crate) async fn runtime_snapshot(&self) -> Result<crate::runtime::RuntimeSnapshot> {
        self.runtime_driver
            .as_ref()
            .ok_or(Error::LinkClosed)?
            .snapshot()
            .await
    }

    /// Gracefully shuts down the link runtime and wakes listener/stream
    /// handles owned by this link.
    pub async fn shutdown(&self) -> Result<()> {
        #[cfg(feature = "test-util")]
        if let Some(driver) = &self.test_driver {
            driver.shutdown();
            return Ok(());
        }

        self.runtime_driver
            .as_ref()
            .ok_or(Error::LinkClosed)?
            .shutdown_blocking()
    }

    /// Shuts down the link runtime and returns [`Error::Timeout`] if the
    /// shutdown acknowledgement is not observed before `timeout`.
    pub async fn shutdown_timeout(&self, timeout: Duration) -> Result<()> {
        #[cfg(feature = "test-util")]
        if let Some(driver) = &self.test_driver {
            driver.shutdown();
            return Ok(());
        }

        let driver = self
            .runtime_driver
            .as_ref()
            .ok_or(Error::LinkClosed)?
            .clone();
        tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking(move || driver.shutdown_blocking()),
        )
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::LinkClosed)?
    }

    pub async fn close(self) -> Result<()> {
        self.shutdown().await
    }

    pub fn service_ports(&self) -> &[u16] {
        &self.service_ports
    }

    pub fn local_ip(&self) -> Option<IpAddr> {
        self.local_ip
    }

    pub fn transport_mode(&self) -> TransportMode {
        self.transport_mode
    }

    fn ensure_service_port(&self, requested: u16) -> Result<()> {
        if !self.service_ports.contains(&requested) {
            return Err(Error::ServicePortNotConfigured { requested });
        }
        Ok(())
    }
}

impl LinkConfig {
    /// Creates a link configuration with KCP as the default transport.
    pub fn new(
        interface: impl Into<String>,
        local_ip: IpAddr,
        service_ports: impl IntoIterator<Item = u16>,
    ) -> Self {
        Self {
            interface: interface.into(),
            local_ip,
            service_ports: service_ports.into_iter().collect(),
            transport_mode: TransportMode::default(),
        }
    }

    pub fn transport_mode(mut self, mode: TransportMode) -> Self {
        self.transport_mode = mode;
        self
    }

    /// Validates and normalizes the configuration without opening a packet
    /// backend.
    pub fn validate(mut self) -> Result<Self> {
        validate_interface_name(&self.interface)?;
        self.service_ports = crate::bpf::filter::normalize_service_ports(&self.service_ports)?;
        Ok(self)
    }

    pub async fn build(self) -> Result<Link> {
        LinkBuilder::from_config(self).build().await
    }
}

impl LinkBuilder {
    pub fn from_config(config: LinkConfig) -> Self {
        Self::default().config(config)
    }

    pub fn config(mut self, config: LinkConfig) -> Self {
        self.interface = Some(config.interface);
        self.local_ip = Some(config.local_ip);
        self.service_ports = config.service_ports;
        self.transport_mode = config.transport_mode;
        self
    }

    pub fn interface(mut self, name: impl Into<String>) -> Self {
        self.interface = Some(name.into());
        self
    }

    pub fn local_ipv4(mut self, addr: Ipv4Addr) -> Self {
        self.local_ip = Some(IpAddr::V4(addr));
        self
    }

    pub fn local_ipv6(mut self, addr: Ipv6Addr) -> Self {
        self.local_ip = Some(IpAddr::V6(addr));
        self
    }

    pub fn local_ip(mut self, addr: IpAddr) -> Self {
        self.local_ip = Some(addr);
        self
    }

    pub fn local_scoped_ip(mut self, addr: impl AsRef<str>) -> Result<Self> {
        let interface = self.interface.as_deref().ok_or(Error::Config(
            "interface is required before local_scoped_ip",
        ))?;
        self.local_ip = Some(parse_scoped_ip(addr, interface)?);
        Ok(self)
    }

    pub fn service_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.service_ports = ports.into_iter().collect();
        self
    }

    pub fn transport_mode(mut self, mode: TransportMode) -> Self {
        self.transport_mode = mode;
        self
    }

    pub async fn build(self) -> Result<Link> {
        let interface = self
            .interface
            .ok_or(Error::Config("interface is required"))?;
        let local_ip = self.local_ip.ok_or(Error::Config("local_ip is required"))?;
        let config = LinkConfig {
            interface,
            local_ip,
            service_ports: self.service_ports,
            transport_mode: self.transport_mode,
        }
        .validate()?;

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let runtime_driver = crate::runtime::RuntimeDriver::spawn_bpf(
                &config.interface,
                config.local_ip,
                &config.service_ports,
                config.transport_mode,
            )?;
            Ok(Link {
                runtime_driver: Some(Arc::new(runtime_driver)),
                service_ports: config.service_ports,
                local_ip: Some(config.local_ip),
                transport_mode: config.transport_mode,
                #[cfg(feature = "test-util")]
                test_driver: None,
            })
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = config;
            Err(Error::UnsupportedPlatform(
                "bpf runtime is only implemented on macOS and Linux",
            ))
        }
    }
}

fn validate_interface_name(interface: &str) -> Result<()> {
    if interface.trim().is_empty() {
        return Err(Error::Config("interface must not be empty"));
    }
    if interface.len() >= libc::IFNAMSIZ {
        return Err(Error::Config("interface name is too long"));
    }
    Ok(())
}

impl From<crate::runtime::RuntimeSnapshot> for LinkStats {
    fn from(snapshot: crate::runtime::RuntimeSnapshot) -> Self {
        Self {
            service_ports: snapshot.service_ports,
            transport_mode: snapshot.transport_mode,
            mtu: snapshot.mtu,
            payload_target: snapshot.payload_target,
            sees_sent_configured: snapshot.sees_sent_configured,
            filter_configured: snapshot.filter_configured,
            listener_count: snapshot.listener_count,
            session_count: snapshot.session_count,
            command_count: snapshot.command_count,
            poll_count: snapshot.poll_count,
            stream_write_count: snapshot.stream_write_count,
            outbound_datagram_count: snapshot.outbound_datagram_count,
            inbound_accept_count: snapshot.inbound_accept_count,
            inbound_data_count: snapshot.inbound_data_count,
            ignored_icmp_count: snapshot.ignored_icmp_count,
            closed_session_count: snapshot.closed_session_count,
            idle_timeout_count: snapshot.idle_timeout_count,
            backpressure_count: snapshot.backpressure_count,
        }
    }
}
