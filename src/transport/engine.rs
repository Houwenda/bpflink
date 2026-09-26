use std::time::Instant;

use crate::link::PeerAddr;
use crate::transport::{BpflinkHeader, ReliableSession, SessionEvent};
use crate::Result;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TransportMode {
    Simple,
    #[default]
    Kcp,
}

impl TransportMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::Kcp => "kcp",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransportEvent {
    Established,
    DataAvailable,
    Closed,
    Reset,
}

pub(crate) trait TransportEngine: Send {
    fn connection_id(&self) -> u64;
    fn on_packet(
        &mut self,
        header: BpflinkHeader,
        payload: &[u8],
        now: Instant,
    ) -> Result<TransportEvent>;
    fn write(&mut self, bytes: &[u8]) -> Result<usize>;
    fn read(&mut self, out: &mut [u8]) -> Result<usize>;
    fn poll_output(&mut self, now: Instant, out: &mut Vec<Vec<u8>>) -> Result<()>;
    fn close(&mut self);
    fn reset(&mut self);
    fn idle_expired(&self, now: Instant) -> bool;
    fn remote_closed(&self) -> bool;
}

pub(crate) struct SimpleTransportEngine {
    session: ReliableSession,
}

impl SimpleTransportEngine {
    pub(crate) fn connect(
        peer: PeerAddr,
        service_port: u16,
        now: Instant,
        payload_target: usize,
    ) -> Self {
        Self {
            session: ReliableSession::connect_with_payload_target(
                peer,
                service_port,
                now,
                payload_target,
            ),
        }
    }
}

impl TransportEngine for SimpleTransportEngine {
    fn connection_id(&self) -> u64 {
        self.session.connection_id()
    }

    fn on_packet(
        &mut self,
        header: BpflinkHeader,
        payload: &[u8],
        now: Instant,
    ) -> Result<TransportEvent> {
        self.session
            .on_packet(header, payload, now)
            .map(TransportEvent::from)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<usize> {
        self.session.write(bytes)
    }

    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        self.session.read(out)
    }

    fn poll_output(&mut self, now: Instant, out: &mut Vec<Vec<u8>>) -> Result<()> {
        self.session.poll_output(now, out)
    }

    fn close(&mut self) {
        self.session.close();
    }

    fn reset(&mut self) {
        self.session.reset();
    }

    fn idle_expired(&self, now: Instant) -> bool {
        self.session.idle_expired(now)
    }

    fn remote_closed(&self) -> bool {
        self.session.remote_closed()
    }
}

impl From<SessionEvent> for TransportEvent {
    fn from(event: SessionEvent) -> Self {
        match event {
            SessionEvent::Established => Self::Established,
            SessionEvent::DataAvailable => Self::DataAvailable,
            SessionEvent::Closed => Self::Closed,
            SessionEvent::Reset => Self::Reset,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use crate::link::PeerAddr;
    use crate::transport::{BpflinkHeader, PacketType, TransportEngine, TransportEvent};

    use super::SimpleTransportEngine;

    #[test]
    fn simple_engine_connect_accept_establishes_connection_ids() {
        let now = Instant::now();
        let (client, server) = connected_pair(now);

        assert_eq!(client.connection_id(), server.connection_id());
    }

    #[test]
    fn simple_engine_ordered_data_is_read_after_delivery() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);

        assert_eq!(client.write(b"hello world").unwrap(), 11);
        let mut output = Vec::new();
        client.poll_output(now, &mut output).unwrap();

        for datagram in output {
            let (header, payload) = BpflinkHeader::decode(&datagram).unwrap();
            assert_eq!(header.packet_type, PacketType::Data);
            assert_eq!(
                server.on_packet(header, payload, now).unwrap(),
                TransportEvent::DataAvailable
            );
        }

        let mut read = [0; 32];
        let len = server.read(&mut read).unwrap();
        assert_eq!(&read[..len], b"hello world");
    }

    #[test]
    fn simple_engine_close_after_write_emits_data_before_fin() {
        let now = Instant::now();
        let (mut client, _server) = connected_pair(now);

        client.write(b"echo before fin").unwrap();
        client.close();
        let mut output = Vec::new();
        client.poll_output(now, &mut output).unwrap();

        assert_eq!(output.len(), 2);
        let (data_header, data_payload) = BpflinkHeader::decode(&output[0]).unwrap();
        let (fin_header, fin_payload) = BpflinkHeader::decode(&output[1]).unwrap();
        assert_eq!(data_header.packet_type, PacketType::Data);
        assert_eq!(data_payload, b"echo before fin");
        assert_eq!(fin_header.packet_type, PacketType::Fin);
        assert!(fin_payload.is_empty());
    }

    #[test]
    fn simple_engine_buffers_out_of_order_data_until_gap_arrives() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);

        client.write(b"first").unwrap();
        client.write(b"second").unwrap();
        let mut output = Vec::new();
        client.poll_output(now, &mut output).unwrap();
        assert_eq!(output.len(), 2);

        let (second_header, second_payload) = BpflinkHeader::decode(&output[1]).unwrap();
        assert_eq!(
            server
                .on_packet(second_header, second_payload, now)
                .unwrap(),
            TransportEvent::Established
        );
        let mut read = [0; 32];
        assert_eq!(server.read(&mut read).unwrap(), 0);

        let (first_header, first_payload) = BpflinkHeader::decode(&output[0]).unwrap();
        assert_eq!(
            server.on_packet(first_header, first_payload, now).unwrap(),
            TransportEvent::DataAvailable
        );
        let len = server.read(&mut read).unwrap();
        assert_eq!(&read[..len], b"firstsecond");
    }

    #[test]
    fn simple_engine_defers_fin_until_missing_data_arrives() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);

        client.write(b"first").unwrap();
        client.write(b"second").unwrap();
        client.close();
        let mut output = Vec::new();
        client.poll_output(now, &mut output).unwrap();
        assert_eq!(output.len(), 3);

        let (second_header, second_payload) = BpflinkHeader::decode(&output[1]).unwrap();
        let (fin_header, fin_payload) = BpflinkHeader::decode(&output[2]).unwrap();
        assert_eq!(fin_header.packet_type, PacketType::Fin);
        assert_eq!(fin_header.stream_id, 2);
        assert_eq!(
            server
                .on_packet(second_header, second_payload, now)
                .unwrap(),
            TransportEvent::Established
        );
        assert_eq!(
            server.on_packet(fin_header, fin_payload, now).unwrap(),
            TransportEvent::Established
        );

        let (first_header, first_payload) = BpflinkHeader::decode(&output[0]).unwrap();
        assert_eq!(
            server.on_packet(first_header, first_payload, now).unwrap(),
            TransportEvent::DataAvailable
        );
        let mut read = [0; 32];
        let len = server.read(&mut read).unwrap();
        assert_eq!(&read[..len], b"firstsecond");
        assert!(server.remote_closed());
    }

    fn connected_pair(now: Instant) -> (SimpleTransportEngine, SimpleTransportEngine) {
        let peer = PeerAddr {
            ip: Ipv4Addr::new(10, 0, 0, 2).into(),
        };
        let mut client = SimpleTransportEngine::connect(peer, 40000, now, 1200);
        let mut server = SimpleTransportEngine::connect(peer, 40000, now, 1200);

        let mut client_output = Vec::new();
        client.poll_output(now, &mut client_output).unwrap();
        assert_eq!(client_output.len(), 1);
        let (connect_header, connect_payload) = BpflinkHeader::decode(&client_output[0]).unwrap();
        assert_eq!(connect_header.packet_type, PacketType::Connect);
        assert_eq!(
            server
                .on_packet(connect_header, connect_payload, now)
                .unwrap(),
            TransportEvent::Established
        );

        let mut server_output = Vec::new();
        server.poll_output(now, &mut server_output).unwrap();
        assert_eq!(server_output.len(), 1);
        let (accept_header, accept_payload) = BpflinkHeader::decode(&server_output[0]).unwrap();
        assert_eq!(accept_header.packet_type, PacketType::Accept);
        assert_eq!(
            client
                .on_packet(accept_header, accept_payload, now)
                .unwrap(),
            TransportEvent::Established
        );

        (client, server)
    }
}
