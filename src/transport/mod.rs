pub(crate) mod engine;
pub(crate) mod header;
pub(crate) mod kcp;
pub(crate) mod session;
pub(crate) mod timers;

pub use engine::TransportMode;
pub(crate) use engine::{SimpleTransportEngine, TransportEngine, TransportEvent};
pub(crate) use header::{BpflinkHeader, PacketType};
pub(crate) use kcp::KcpTransportEngine;
pub(crate) use session::{ReliableSession, SessionEvent};

pub(crate) const DEFAULT_PAYLOAD_TARGET: usize = 1200;
const IPV4_UDP_HEADER_LEN: usize = 20 + 8;
const IPV6_UDP_HEADER_LEN: usize = 40 + 8;

pub(crate) fn payload_target_for_ipv4_mtu(mtu: usize) -> usize {
    payload_target_for_mtu(mtu, IPV4_UDP_HEADER_LEN)
}

pub(crate) fn payload_target_for_ipv6_mtu(mtu: usize) -> usize {
    payload_target_for_mtu(mtu, IPV6_UDP_HEADER_LEN)
}

fn payload_target_for_mtu(mtu: usize, header_len: usize) -> usize {
    let mtu_payload = mtu.saturating_sub(header_len);
    DEFAULT_PAYLOAD_TARGET
        .min(mtu_payload)
        .max(BpflinkHeader::encoded_len())
}

#[cfg(test)]
mod tests {
    #[test]
    fn payload_target_tracks_smaller_ipv4_mtu() {
        assert_eq!(super::payload_target_for_ipv4_mtu(1500), 1200);
        assert_eq!(super::payload_target_for_ipv4_mtu(576), 548);
    }

    #[test]
    fn payload_target_tracks_smaller_ipv6_mtu() {
        assert_eq!(super::payload_target_for_ipv6_mtu(1500), 1200);
        assert_eq!(super::payload_target_for_ipv6_mtu(1280), 1200);
        assert_eq!(super::payload_target_for_ipv6_mtu(576), 528);
    }
}
