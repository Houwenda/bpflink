use smoltcp::socket::udp;

pub(crate) const UDP_PACKET_CAPACITY: usize = 256;
pub(crate) const UDP_PAYLOAD_CAPACITY: usize = 2048;
const UDP_SOCKET_PAYLOAD_CAPACITY: usize = UDP_PAYLOAD_CAPACITY * 64;

pub(crate) fn new_udp_socket() -> udp::Socket<'static> {
    let rx_meta = vec![udp::PacketMetadata::EMPTY; UDP_PACKET_CAPACITY];
    let tx_meta = vec![udp::PacketMetadata::EMPTY; UDP_PACKET_CAPACITY];
    let rx_payload = vec![0; UDP_SOCKET_PAYLOAD_CAPACITY];
    let tx_payload = vec![0; UDP_SOCKET_PAYLOAD_CAPACITY];

    udp::Socket::new(
        udp::PacketBuffer::new(rx_meta, rx_payload),
        udp::PacketBuffer::new(tx_meta, tx_payload),
    )
}
