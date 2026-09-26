//! Diagnostics helpers for validating the packet I/O boundary.

use std::net::IpAddr;

use crate::bpf::FrameIo;
use crate::{Error, Result};
use crate::{Link, PeerAddr};
use tokio::io::AsyncWriteExt;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::bpf::BpfDevice;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BpfProbeReport {
    pub interface: String,
    pub mtu: usize,
    pub read_polls: usize,
    pub frames_seen: usize,
    pub sees_sent_configured: Option<bool>,
    pub filter_configured: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeProbeConfig {
    pub interface: String,
    pub local_ip: IpAddr,
    pub service_ports: Vec<u16>,
    pub active_service_port: u16,
    pub connect_peer_ip: Option<IpAddr>,
    pub write_payload: Option<Vec<u8>>,
    pub transport_mode: crate::TransportMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeProbeReport {
    pub interface: String,
    pub local_ip: IpAddr,
    pub service_ports: Vec<u16>,
    pub active_service_port: u16,
    pub transport_mode: &'static str,
    pub mtu: usize,
    pub payload_target: usize,
    pub sees_sent_configured: Option<bool>,
    pub filter_configured: Option<bool>,
    pub listener_count: usize,
    pub session_count: usize,
    pub command_count: usize,
    pub poll_count: usize,
    pub connect_peer_ip: Option<IpAddr>,
    pub stream_write_count: usize,
    pub outbound_datagram_count: usize,
    pub inbound_accept_count: usize,
    pub inbound_data_count: usize,
    pub ignored_icmp_count: usize,
    pub closed_session_count: usize,
    pub idle_timeout_count: usize,
    pub backpressure_count: usize,
}

pub fn probe_bpf_interface(interface: impl AsRef<str>) -> Result<BpfProbeReport> {
    let interface = interface.as_ref();
    validate_interface(interface)?;
    probe_bpf_interface_impl(interface)
}

pub async fn probe_runtime_command_loop(config: RuntimeProbeConfig) -> Result<RuntimeProbeReport> {
    validate_interface(&config.interface)?;
    let service_ports = crate::bpf::filter::normalize_service_ports(&config.service_ports)?;
    if !service_ports.contains(&config.active_service_port) {
        return Err(Error::ServicePortNotConfigured {
            requested: config.active_service_port,
        });
    }

    let builder = Link::builder()
        .interface(config.interface.clone())
        .local_ip(config.local_ip)
        .service_ports(service_ports.clone());
    let builder = builder.transport_mode(config.transport_mode);
    let link = builder.build().await?;
    let listener = link.listen(config.active_service_port).await?;
    let mut connected_stream = None;
    if let Some(peer_ip) = config.connect_peer_ip {
        let mut stream = link
            .connect(PeerAddr { ip: peer_ip }, config.active_service_port)
            .await?;
        if let Some(payload) = &config.write_payload {
            stream.write_all(payload).await.map_err(Error::Io)?;
        }
        connected_stream = Some(stream);
    }
    let snapshot = link.runtime_snapshot().await?;
    drop(connected_stream);

    Ok(RuntimeProbeReport {
        interface: config.interface,
        local_ip: config.local_ip,
        service_ports,
        active_service_port: listener.service_port(),
        transport_mode: snapshot.transport_mode,
        mtu: snapshot.mtu,
        payload_target: snapshot.payload_target,
        sees_sent_configured: snapshot.sees_sent_configured,
        filter_configured: snapshot.filter_configured,
        listener_count: snapshot.listener_count,
        session_count: snapshot.session_count,
        command_count: snapshot.command_count,
        poll_count: snapshot.poll_count,
        connect_peer_ip: config.connect_peer_ip,
        stream_write_count: snapshot.stream_write_count,
        outbound_datagram_count: snapshot.outbound_datagram_count,
        inbound_accept_count: snapshot.inbound_accept_count,
        inbound_data_count: snapshot.inbound_data_count,
        ignored_icmp_count: snapshot.ignored_icmp_count,
        closed_session_count: snapshot.closed_session_count,
        idle_timeout_count: snapshot.idle_timeout_count,
        backpressure_count: snapshot.backpressure_count,
    })
}

fn validate_interface(interface: &str) -> Result<()> {
    if interface.trim().is_empty() {
        return Err(Error::Config("interface must not be empty"));
    }
    if interface.len() >= libc::IFNAMSIZ {
        return Err(Error::Config("interface name is too long"));
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn probe_bpf_interface_impl(interface: &str) -> Result<BpfProbeReport> {
    let mut device = BpfDevice::open(interface)?;
    probe_open_device(interface, &mut device)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn probe_bpf_interface_impl(_interface: &str) -> Result<BpfProbeReport> {
    Err(Error::UnsupportedPlatform(
        "bpf diagnostics are only implemented on macOS and Linux",
    ))
}

fn probe_open_device<D: FrameIo>(interface: &str, device: &mut D) -> Result<BpfProbeReport> {
    let mut frames = Vec::new();
    let frames_seen = device.read_frames(&mut frames)?;
    Ok(BpfProbeReport {
        interface: interface.to_string(),
        mtu: device.mtu(),
        read_polls: 1,
        frames_seen,
        sees_sent_configured: device.sees_sent_configured(),
        filter_configured: device.filter_configured(),
    })
}

#[cfg(test)]
mod tests {
    use super::{probe_open_device, validate_interface};
    use crate::bpf::FrameIo;

    #[derive(Debug)]
    struct FakeFrameIo {
        mtu: usize,
        frames: Vec<Vec<u8>>,
    }

    impl FrameIo for FakeFrameIo {
        fn read_frames(&mut self, out: &mut Vec<Vec<u8>>) -> crate::Result<usize> {
            let count = self.frames.len();
            out.append(&mut self.frames);
            Ok(count)
        }

        fn write_frame(&mut self, _frame: &[u8]) -> crate::Result<()> {
            Ok(())
        }

        fn mtu(&self) -> usize {
            self.mtu
        }

        fn sees_sent_configured(&self) -> Option<bool> {
            Some(true)
        }

        fn filter_configured(&self) -> Option<bool> {
            Some(false)
        }
    }

    #[test]
    fn probe_report_counts_frames_from_open_device() {
        let mut device = FakeFrameIo {
            mtu: 1400,
            frames: vec![vec![0xaa], vec![0xbb]],
        };

        let report = probe_open_device("en0", &mut device).unwrap();

        assert_eq!(report.interface, "en0");
        assert_eq!(report.mtu, 1400);
        assert_eq!(report.read_polls, 1);
        assert_eq!(report.frames_seen, 2);
        assert_eq!(report.sees_sent_configured, Some(true));
        assert_eq!(report.filter_configured, Some(false));
    }

    #[test]
    fn validate_interface_rejects_empty_names() {
        assert!(matches!(
            validate_interface(" "),
            Err(crate::Error::Config("interface must not be empty"))
        ));
    }
}
