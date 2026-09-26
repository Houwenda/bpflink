const IPV4_MIN_HEADER_LEN: usize = 20;
const ICMP_HEADER_LEN: usize = 8;
const UDP_HEADER_LEN: usize = 8;
const IP_PROTOCOL_ICMP: u8 = 1;
const IP_PROTOCOL_UDP: u8 = 17;
const ICMP_DESTINATION_UNREACHABLE: u8 = 3;
const ICMP_PORT_UNREACHABLE: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcmpDisposition {
    IgnoreAndCount,
    NotRelated,
}

pub(crate) fn classify_ethernet_ipv4_icmp_unreachable(
    ethernet_frame: &[u8],
    service_ports: &[u16],
) -> IcmpDisposition {
    if ethernet_frame.len() < 14 {
        return IcmpDisposition::NotRelated;
    }
    if ethernet_frame[12..14] != 0x0800u16.to_be_bytes() {
        return IcmpDisposition::NotRelated;
    }

    classify_icmp_unreachable(&ethernet_frame[14..], service_ports)
}

pub(crate) fn classify_icmp_unreachable(
    ipv4_packet: &[u8],
    service_ports: &[u16],
) -> IcmpDisposition {
    let Some(outer_header_len) = ipv4_header_len(ipv4_packet) else {
        return IcmpDisposition::NotRelated;
    };
    if ipv4_packet.get(9).copied() != Some(IP_PROTOCOL_ICMP) {
        return IcmpDisposition::NotRelated;
    }

    let icmp = &ipv4_packet[outer_header_len..];
    if icmp.len() < ICMP_HEADER_LEN {
        return IcmpDisposition::NotRelated;
    }
    if icmp[0] != ICMP_DESTINATION_UNREACHABLE || icmp[1] != ICMP_PORT_UNREACHABLE {
        return IcmpDisposition::NotRelated;
    }

    let quoted_ip = &icmp[ICMP_HEADER_LEN..];
    let Some(quoted_header_len) = ipv4_header_len(quoted_ip) else {
        return IcmpDisposition::NotRelated;
    };
    if quoted_ip.get(9).copied() != Some(IP_PROTOCOL_UDP) {
        return IcmpDisposition::NotRelated;
    }

    let udp_start = quoted_header_len;
    if quoted_ip.len() < udp_start + UDP_HEADER_LEN {
        return IcmpDisposition::NotRelated;
    }

    let dst_port = u16::from_be_bytes([quoted_ip[udp_start + 2], quoted_ip[udp_start + 3]]);
    if service_ports.contains(&dst_port) {
        IcmpDisposition::IgnoreAndCount
    } else {
        IcmpDisposition::NotRelated
    }
}

fn ipv4_header_len(packet: &[u8]) -> Option<usize> {
    let first = *packet.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(first & 0x0f) * 4;
    if header_len < IPV4_MIN_HEADER_LEN || packet.len() < header_len {
        return None;
    }
    Some(header_len)
}

#[cfg(test)]
mod tests {
    use super::{classify_icmp_unreachable, IcmpDisposition};

    const SERVICE_PORT: u16 = 40000;

    #[test]
    fn icmp_related_port_unreachable_is_ignored() {
        let packet = related_port_unreachable_packet(SERVICE_PORT);

        assert_eq!(
            classify_icmp_unreachable(&packet, &[SERVICE_PORT]),
            IcmpDisposition::IgnoreAndCount
        );
        assert_eq!(
            classify_icmp_unreachable(&packet, &[SERVICE_PORT + 1, SERVICE_PORT]),
            IcmpDisposition::IgnoreAndCount
        );
    }

    fn related_port_unreachable_packet(service_port: u16) -> Vec<u8> {
        let mut packet = vec![0; 20 + 8 + 20 + 8];
        packet[0] = 0x45;
        packet[9] = 1;
        packet[20] = 3;
        packet[21] = 3;

        let quoted_ip = 28;
        packet[quoted_ip] = 0x45;
        packet[quoted_ip + 9] = 17;

        let quoted_udp = quoted_ip + 20;
        packet[quoted_udp..quoted_udp + 2].copy_from_slice(&12345u16.to_be_bytes());
        packet[quoted_udp + 2..quoted_udp + 4].copy_from_slice(&service_port.to_be_bytes());
        packet[quoted_udp + 4..quoted_udp + 6].copy_from_slice(&8u16.to_be_bytes());
        packet
    }
}
