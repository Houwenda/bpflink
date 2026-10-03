use std::collections::HashMap;
use std::net::IpAddr as StdIpAddr;

use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address,
};

use crate::bpf::filter::normalize_service_ports;
use crate::bpf::FrameIo;
use crate::{Error, Result};

use super::device::StackDevice;
use super::udp::{new_udp_socket, UDP_PAYLOAD_CAPACITY};

pub(crate) struct StackConfig {
    pub(crate) local_ip: StdIpAddr,
    pub(crate) local_prefix_len: u8,
    pub(crate) default_gateway: Option<StdIpAddr>,
    pub(crate) service_ports: Vec<u16>,
    pub(crate) ethernet_addr: EthernetAddress,
}

pub(crate) enum PollOutcome {
    Idle,
    ReceivedUdp {
        src: StdIpAddr,
        src_port: u16,
        service_port: u16,
        payload: Vec<u8>,
    },
    IgnoredIcmp,
}

pub(crate) struct StackDriver<D: FrameIo> {
    device: StackDevice<D>,
    interface: Interface,
    sockets: SocketSet<'static>,
    udp_handles: HashMap<u16, SocketHandle>,
    ignored_icmp_count: usize,
}

impl<D: FrameIo> StackDriver<D> {
    pub(crate) fn new(config: StackConfig, device: D) -> Result<Self> {
        let service_ports = normalize_service_ports(&config.service_ports)?;

        let mut device = StackDevice::new_for_service_ports(device, service_ports.clone());
        let iface_config = InterfaceConfig::new(HardwareAddress::Ethernet(config.ethernet_addr));
        let mut interface = Interface::new(iface_config, &mut device, Instant::from_millis(0));
        interface.update_ip_addrs(|addrs| {
            let address = match config.local_ip {
                StdIpAddr::V4(addr) => IpAddress::Ipv4(Ipv4Address::from_octets(addr.octets())),
                StdIpAddr::V6(addr) => IpAddress::Ipv6(smoltcp_ipv6(addr)),
            };
            let _ = addrs.push(IpCidr::new(address, config.local_prefix_len));
        });
        if let Some(gateway) = config.default_gateway {
            match (config.local_ip, gateway) {
                (StdIpAddr::V4(_), StdIpAddr::V4(gateway)) => {
                    interface
                        .routes_mut()
                        .add_default_ipv4_route(Ipv4Address::from_octets(gateway.octets()))
                        .map_err(|_| Error::Config("failed to install IPv4 default route"))?;
                }
                (StdIpAddr::V6(_), StdIpAddr::V6(gateway)) => {
                    interface
                        .routes_mut()
                        .add_default_ipv6_route(smoltcp_ipv6(gateway))
                        .map_err(|_| Error::Config("failed to install IPv6 default route"))?;
                }
                _ => return Err(Error::Config("default gateway address family mismatch")),
            }
        }

        let mut sockets = SocketSet::new(Vec::new());
        let mut udp_handles = HashMap::new();
        for service_port in service_ports {
            let mut socket = new_udp_socket();
            socket
                .bind(service_port)
                .map_err(|_| Error::Config("failed to bind UDP service_port"))?;
            udp_handles.insert(service_port, sockets.add(socket));
        }

        Ok(Self {
            device,
            interface,
            sockets,
            udp_handles,
            ignored_icmp_count: 0,
        })
    }

    pub(crate) fn poll(&mut self, now: Instant) -> Result<PollOutcome> {
        let _ = self
            .interface
            .poll(now, &mut self.device, &mut self.sockets);
        self.ignored_icmp_count += self.device.take_ignored_icmp_count();

        for (service_port, udp_handle) in &self.udp_handles {
            let socket = self.sockets.get_mut::<udp::Socket>(*udp_handle);
            let mut payload = vec![0; UDP_PAYLOAD_CAPACITY];
            match socket.recv_slice(&mut payload) {
                Ok((len, meta)) => {
                    payload.truncate(len);
                    let src = match meta.endpoint.addr {
                        IpAddress::Ipv4(addr) => StdIpAddr::V4(addr.octets().into()),
                        IpAddress::Ipv6(addr) => StdIpAddr::V6(addr.octets().into()),
                        #[allow(unreachable_patterns)]
                        _ => continue,
                    };
                    return Ok(PollOutcome::ReceivedUdp {
                        src,
                        src_port: meta.endpoint.port,
                        service_port: *service_port,
                        payload,
                    });
                }
                Err(udp::RecvError::Exhausted) => {}
                Err(udp::RecvError::Truncated) => {
                    return Err(Error::PacketParse("truncated UDP payload"));
                }
            }
        }
        if self.ignored_icmp_count > 0 {
            self.ignored_icmp_count -= 1;
            Ok(PollOutcome::IgnoredIcmp)
        } else {
            Ok(PollOutcome::Idle)
        }
    }

    pub(crate) fn send_udp(
        &mut self,
        service_port: u16,
        dst: StdIpAddr,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<()> {
        let dst = match dst {
            StdIpAddr::V4(addr) => IpAddress::Ipv4(Ipv4Address::from_octets(addr.octets())),
            StdIpAddr::V6(addr) => IpAddress::Ipv6(smoltcp_ipv6(addr)),
        };
        let local_is_ipv4 = self.interface.ipv4_addr().is_some();
        if local_is_ipv4 != matches!(dst, IpAddress::Ipv4(_)) {
            return Err(Error::Config("peer address family does not match local_ip"));
        }
        let endpoint = IpEndpoint::new(dst, dst_port);
        let udp_handle =
            *self
                .udp_handles
                .get(&service_port)
                .ok_or(Error::ServicePortNotConfigured {
                    requested: service_port,
                })?;
        let socket = self.sockets.get_mut::<udp::Socket>(udp_handle);
        socket
            .send_slice(payload, endpoint)
            .map_err(|_| Error::PacketParse("failed to enqueue UDP payload"))?;
        let _ = self.interface.poll_egress(
            Instant::from_millis(0),
            &mut self.device,
            &mut self.sockets,
        );
        if let Some(err) = self.device.take_tx_error() {
            return Err(err);
        }
        Ok(())
    }
}

fn smoltcp_ipv6(addr: std::net::Ipv6Addr) -> Ipv6Address {
    let segments = addr.segments();
    Ipv6Address::new(
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7],
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};

    use smoltcp::wire::EthernetAddress;

    use crate::bpf::FrameIo;
    use crate::transport::{BpflinkHeader, PacketType, DEFAULT_PAYLOAD_TARGET};
    use crate::Error;

    #[derive(Clone, Debug, Default)]
    struct FakeStats {
        readable: Vec<Vec<u8>>,
        written: Vec<Vec<u8>>,
    }

    #[derive(Clone, Debug, Default)]
    struct FakeFrameIo {
        stats: Arc<Mutex<FakeStats>>,
    }

    impl FakeFrameIo {
        fn written_count(&self) -> usize {
            self.stats
                .lock()
                .expect("fake stats poisoned")
                .written
                .len()
        }
    }

    impl FrameIo for FakeFrameIo {
        fn read_frames(&mut self, _out: &mut Vec<Vec<u8>>) -> crate::Result<usize> {
            let mut stats = self.stats.lock().expect("fake stats poisoned");
            let count = stats.readable.len();
            _out.append(&mut stats.readable);
            Ok(count)
        }

        fn write_frame(&mut self, frame: &[u8]) -> crate::Result<()> {
            self.stats
                .lock()
                .expect("fake stats poisoned")
                .written
                .push(frame.to_vec());
            Ok(())
        }

        fn mtu(&self) -> usize {
            1500
        }
    }

    #[test]
    fn send_udp_to_on_link_peer_uses_configured_ipv4_prefix() {
        let fake = FakeFrameIo::default();
        let stats = fake.clone();
        let mut driver = super::StackDriver::new(
            super::StackConfig {
                local_ip: "192.0.2.1".parse().unwrap(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
            fake,
        )
        .expect("stack driver starts");

        driver
            .send_udp(40000, "192.0.2.2".parse().unwrap(), 40000, b"bpflink")
            .expect("on-link send is accepted");

        assert!(
            stats.written_count() > 0,
            "expected smoltcp to emit at least an ARP frame for an on-link peer"
        );
    }

    #[test]
    fn send_udp_to_on_link_peer_uses_configured_ipv6_prefix() {
        let fake = FakeFrameIo::default();
        let stats = fake.clone();
        let mut driver = super::StackDriver::new(
            super::StackConfig {
                local_ip: "fd00::1".parse().unwrap(),
                local_prefix_len: 64,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
            fake,
        )
        .expect("stack driver starts");

        driver
            .send_udp(40000, "fd00::2".parse().unwrap(), 40000, b"bpflink")
            .expect("on-link IPv6 send is accepted");

        assert!(
            stats.written_count() > 0,
            "expected smoltcp to emit at least an IPv6 neighbor discovery frame"
        );
    }

    #[test]
    fn send_udp_buffers_segment_burst_while_neighbor_is_unresolved() {
        let fake = FakeFrameIo::default();
        let mut driver = super::StackDriver::new(
            super::StackConfig {
                local_ip: "192.0.2.1".parse().unwrap(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
            fake,
        )
        .expect("stack driver starts");
        let payload = vec![0x5a; DEFAULT_PAYLOAD_TARGET - BpflinkHeader::encoded_len()];

        for _ in 0..4 {
            driver
                .send_udp(40000, "192.0.2.2".parse().unwrap(), 40000, &payload)
                .expect("segment burst is buffered while ARP resolves");
        }
    }

    #[test]
    fn poll_buffers_more_than_eight_inbound_udp_packets() {
        let local_ip = "192.0.2.1".parse().unwrap();
        let peer_ip = "192.0.2.2".parse().unwrap();
        let service_port = 40000;
        let readable = (0..16u64)
            .map(|connection_id| {
                udp_frame(
                    peer_ip,
                    local_ip,
                    50000,
                    service_port,
                    bpflink_datagram(PacketType::Data, service_port, connection_id, 0, b"burst"),
                )
            })
            .collect();
        let fake = FakeFrameIo {
            stats: Arc::new(Mutex::new(FakeStats {
                readable,
                ..FakeStats::default()
            })),
        };
        let mut driver = super::StackDriver::new(
            super::StackConfig {
                local_ip: local_ip.into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![service_port],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
            fake,
        )
        .expect("stack driver starts");

        let mut received = 0;
        for _ in 0..16 {
            if matches!(
                driver.poll(smoltcp::time::Instant::from_millis(0)).unwrap(),
                super::PollOutcome::ReceivedUdp { .. }
            ) {
                received += 1;
            }
        }

        assert_eq!(received, 16);
    }

    #[test]
    fn poll_accepts_raw_udp_payloads_on_configured_ports() {
        let local_ip = "192.0.2.1".parse().unwrap();
        let peer_ip = "192.0.2.53".parse().unwrap();
        let service_port = 53000;
        let readable = vec![udp_frame(
            peer_ip,
            local_ip,
            53,
            service_port,
            b"dns response".to_vec(),
        )];
        let fake = FakeFrameIo {
            stats: Arc::new(Mutex::new(FakeStats {
                readable,
                ..FakeStats::default()
            })),
        };
        let mut driver = super::StackDriver::new(
            super::StackConfig {
                local_ip: local_ip.into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![service_port],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
            fake,
        )
        .expect("stack driver starts");

        let outcome = driver
            .poll(smoltcp::time::Instant::from_millis(0))
            .expect("poll succeeds");

        assert!(matches!(
            outcome,
            super::PollOutcome::ReceivedUdp {
                src: IpAddr::V4(src),
                src_port: 53,
                service_port: 53000,
                payload,
            } if src == peer_ip && payload == b"dns response"
        ));
    }

    #[test]
    fn poll_accepts_inbound_ipv6_udp_packets() {
        let local_ip: Ipv6Addr = "fd00::1".parse().unwrap();
        let peer_ip: Ipv6Addr = "fd00::2".parse().unwrap();
        let service_port = 40000;
        let readable = vec![udp_ipv6_frame(
            peer_ip,
            local_ip,
            50000,
            service_port,
            bpflink_datagram(PacketType::Data, service_port, 7, 0, b"ipv6"),
        )];
        let fake = FakeFrameIo {
            stats: Arc::new(Mutex::new(FakeStats {
                readable,
                ..FakeStats::default()
            })),
        };
        let mut driver = super::StackDriver::new(
            super::StackConfig {
                local_ip: IpAddr::V6(local_ip),
                local_prefix_len: 64,
                default_gateway: None,
                service_ports: vec![service_port],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
            fake,
        )
        .expect("stack driver starts");

        let outcome = driver
            .poll(smoltcp::time::Instant::from_millis(0))
            .expect("poll succeeds");

        assert!(matches!(
            outcome,
            super::PollOutcome::ReceivedUdp {
                src: IpAddr::V6(src),
                src_port: 50000,
                service_port: 40000,
                payload
            } if src == peer_ip && !payload.is_empty()
        ));
    }

    #[test]
    fn poll_and_send_use_configured_service_port_set() {
        let local_ip = Ipv4Addr::new(192, 0, 2, 1);
        let peer_ip = Ipv4Addr::new(192, 0, 2, 2);
        let readable = vec![udp_frame(
            peer_ip,
            local_ip,
            50000,
            40001,
            bpflink_datagram(PacketType::Data, 40001, 7, 0, b"port two"),
        )];
        let fake = FakeFrameIo {
            stats: Arc::new(Mutex::new(FakeStats {
                readable,
                ..FakeStats::default()
            })),
        };
        let mut driver = super::StackDriver::new(
            super::StackConfig {
                local_ip: local_ip.into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000, 40001],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
            fake,
        )
        .expect("stack driver starts");

        let outcome = driver
            .poll(smoltcp::time::Instant::from_millis(0))
            .expect("poll succeeds");
        assert!(matches!(
            outcome,
            super::PollOutcome::ReceivedUdp {
                src: IpAddr::V4(src),
                src_port: 50000,
                service_port: 40001,
                payload,
            } if src == peer_ip && !payload.is_empty()
        ));

        let err = driver
            .send_udp(40002, peer_ip.into(), 40002, b"not configured")
            .unwrap_err();
        assert!(matches!(
            err,
            Error::ServicePortNotConfigured { requested: 40002 }
        ));
    }

    #[test]
    fn send_udp_to_off_link_ipv4_peer_uses_default_gateway_route() {
        let fake = FakeFrameIo::default();
        let stats = fake.clone();
        let mut driver = super::StackDriver::new(
            super::StackConfig {
                local_ip: "192.0.2.10".parse().unwrap(),
                local_prefix_len: 24,
                default_gateway: Some("192.0.2.1".parse().unwrap()),
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
            fake,
        )
        .expect("stack driver starts");

        driver
            .send_udp(40000, "203.0.113.7".parse().unwrap(), 40000, b"bpflink")
            .expect("off-link IPv4 send is routed through the default gateway");

        assert!(
            stats.written_count() > 0,
            "expected smoltcp to emit at least an ARP frame for the default gateway"
        );
    }

    #[test]
    fn send_udp_to_off_link_ipv6_peer_uses_default_gateway_route() {
        let fake = FakeFrameIo::default();
        let stats = fake.clone();
        let mut driver = super::StackDriver::new(
            super::StackConfig {
                local_ip: "2001:db8:1::10".parse().unwrap(),
                local_prefix_len: 64,
                default_gateway: Some("fe80::1".parse().unwrap()),
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
            fake,
        )
        .expect("stack driver starts");

        driver
            .send_udp(40000, "2001:db8:2::20".parse().unwrap(), 40000, b"bpflink")
            .expect("off-link IPv6 send is routed through the default gateway");

        assert!(
            stats.written_count() > 0,
            "expected smoltcp to emit at least an IPv6 neighbor discovery frame for the default gateway"
        );
    }

    fn bpflink_datagram(
        packet_type: PacketType,
        service_port: u16,
        connection_id: u64,
        stream_id: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        BpflinkHeader {
            packet_type,
            service_port,
            connection_id,
            stream_id,
        }
        .encode(payload, &mut out)
        .expect("encode bpflink datagram");
        out
    }

    fn udp_frame(
        src: std::net::Ipv4Addr,
        dst: std::net::Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let ip_len = 20 + udp_len;
        let mut frame = vec![0; 14 + ip_len];
        frame[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

        let ip = 14;
        frame[ip] = 0x45;
        frame[ip + 2..ip + 4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        frame[ip + 8] = 64;
        frame[ip + 9] = 17;
        frame[ip + 12..ip + 16].copy_from_slice(&src.octets());
        frame[ip + 16..ip + 20].copy_from_slice(&dst.octets());
        let ip_checksum = checksum(&frame[ip..ip + 20]);
        frame[ip + 10..ip + 12].copy_from_slice(&ip_checksum.to_be_bytes());

        let udp = ip + 20;
        frame[udp..udp + 2].copy_from_slice(&src_port.to_be_bytes());
        frame[udp + 2..udp + 4].copy_from_slice(&dst_port.to_be_bytes());
        frame[udp + 4..udp + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        frame[udp + 8..udp + 8 + payload.len()].copy_from_slice(&payload);
        let udp_checksum = udp_checksum(src, dst, &frame[udp..udp + udp_len]);
        frame[udp + 6..udp + 8].copy_from_slice(&udp_checksum.to_be_bytes());
        frame
    }

    fn udp_checksum(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, udp_packet: &[u8]) -> u16 {
        let mut pseudo = Vec::with_capacity(12 + udp_packet.len() + 1);
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&(udp_packet.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(udp_packet);
        if pseudo.len() % 2 != 0 {
            pseudo.push(0);
        }
        checksum(&pseudo)
    }

    fn udp_ipv6_frame(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        payload: Vec<u8>,
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut frame = vec![0; 14 + 40 + udp_len];
        frame[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());

        let ip = 14;
        frame[ip] = 0x60;
        frame[ip + 4..ip + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        frame[ip + 6] = 17;
        frame[ip + 7] = 64;
        frame[ip + 8..ip + 24].copy_from_slice(&src.octets());
        frame[ip + 24..ip + 40].copy_from_slice(&dst.octets());

        let udp = ip + 40;
        frame[udp..udp + 2].copy_from_slice(&src_port.to_be_bytes());
        frame[udp + 2..udp + 4].copy_from_slice(&dst_port.to_be_bytes());
        frame[udp + 4..udp + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        frame[udp + 8..udp + 8 + payload.len()].copy_from_slice(&payload);
        let udp_checksum = udp_ipv6_checksum(src, dst, &frame[udp..udp + udp_len]);
        frame[udp + 6..udp + 8].copy_from_slice(&udp_checksum.to_be_bytes());
        frame
    }

    fn udp_ipv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, udp_packet: &[u8]) -> u16 {
        let mut pseudo = Vec::with_capacity(40 + udp_packet.len() + 1);
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.extend_from_slice(&(udp_packet.len() as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0]);
        pseudo.push(17);
        pseudo.extend_from_slice(udp_packet);
        if pseudo.len() % 2 != 0 {
            pseudo.push(0);
        }
        checksum(&pseudo)
    }

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in bytes.chunks(2) {
            let word = if chunk.len() == 2 {
                u16::from_be_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], 0])
            };
            sum += u32::from(word);
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
        }
        !(sum as u16)
    }
}
