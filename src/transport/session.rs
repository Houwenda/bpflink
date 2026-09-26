use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::link::PeerAddr;
use crate::transport::timers::SessionTimers;
use crate::transport::{BpflinkHeader, PacketType};
use crate::{Error, Result};

#[cfg(test)]
use crate::transport::payload_target_for_ipv4_mtu;

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);
const MAX_BUFFERED_BYTES: usize = 1024 * 1024;
const SESSION_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) type ConnectionId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionId(pub(crate) u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionEvent {
    Established,
    DataAvailable,
    Closed,
    Reset,
}

pub(crate) struct ReliableSession {
    service_port: u16,
    connection_id: ConnectionId,
    session_id: SessionId,
    payload_target: usize,
    established: bool,
    initiator: bool,
    sent_connect: bool,
    pending_accept: bool,
    pending_ack: bool,
    pending_fin: bool,
    pending_reset: bool,
    closed_local: bool,
    closed_remote: bool,
    outbound_data: VecDeque<Vec<u8>>,
    unacked_data: VecDeque<(u32, Vec<u8>)>,
    out_of_order_data: BTreeMap<u32, Vec<u8>>,
    inbound_data: VecDeque<u8>,
    pending_remote_fin_seq: Option<u32>,
    next_send_seq: u32,
    next_recv_seq: u32,
    timers: SessionTimers,
}

impl ReliableSession {
    #[cfg(test)]
    pub(crate) fn connect(_peer: PeerAddr, service_port: u16, now: Instant) -> Self {
        Self::connect_with_payload_target(
            _peer,
            service_port,
            now,
            payload_target_for_ipv4_mtu(1500),
        )
    }

    pub(crate) fn connect_with_payload_target(
        _peer: PeerAddr,
        service_port: u16,
        now: Instant,
        payload_target: usize,
    ) -> Self {
        let connection_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            service_port,
            connection_id,
            session_id: SessionId(connection_id),
            payload_target,
            established: false,
            initiator: true,
            sent_connect: false,
            pending_accept: false,
            pending_ack: false,
            pending_fin: false,
            pending_reset: false,
            closed_local: false,
            closed_remote: false,
            outbound_data: VecDeque::new(),
            unacked_data: VecDeque::new(),
            out_of_order_data: BTreeMap::new(),
            inbound_data: VecDeque::new(),
            pending_remote_fin_seq: None,
            next_send_seq: 0,
            next_recv_seq: 0,
            timers: SessionTimers::for_session(now),
        }
    }

    pub(crate) fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    pub(crate) fn on_packet(
        &mut self,
        header: BpflinkHeader,
        payload: &[u8],
        now: Instant,
    ) -> Result<SessionEvent> {
        if header.service_port != self.service_port {
            return Err(Error::PacketParse("packet for different service port"));
        }
        self.timers.refresh(now);

        match header.packet_type {
            PacketType::Connect => {
                self.connection_id = header.connection_id;
                self.session_id = SessionId(header.connection_id);
                self.established = true;
                self.initiator = false;
                self.pending_accept = true;
                Ok(SessionEvent::Established)
            }
            PacketType::Accept => {
                self.ensure_connection(header.connection_id)?;
                self.established = true;
                Ok(SessionEvent::Established)
            }
            PacketType::Data => {
                self.ensure_connection(header.connection_id)?;
                if header.stream_id == self.next_recv_seq {
                    self.inbound_data.extend(payload.iter().copied());
                    self.next_recv_seq = self.next_recv_seq.wrapping_add(1);
                    self.drain_ordered_data();
                    self.pending_ack = true;
                    Ok(SessionEvent::DataAvailable)
                } else if header.stream_id > self.next_recv_seq {
                    self.out_of_order_data
                        .entry(header.stream_id)
                        .or_insert_with(|| payload.to_vec());
                    self.pending_ack = true;
                    Ok(SessionEvent::Established)
                } else {
                    self.pending_ack = true;
                    Ok(SessionEvent::Established)
                }
            }
            PacketType::Fin => {
                self.ensure_connection(header.connection_id)?;
                self.pending_remote_fin_seq = Some(header.stream_id);
                if self.apply_pending_remote_fin() {
                    Ok(SessionEvent::Closed)
                } else {
                    self.pending_ack = true;
                    Ok(SessionEvent::Established)
                }
            }
            PacketType::Reset => {
                self.ensure_connection(header.connection_id)?;
                self.closed_remote = true;
                Ok(SessionEvent::Reset)
            }
            PacketType::Ping => {
                self.ensure_connection(header.connection_id)?;
                while self
                    .unacked_data
                    .front()
                    .map(|(seq, _)| *seq < header.stream_id)
                    .unwrap_or(false)
                {
                    self.unacked_data.pop_front();
                }
                Ok(SessionEvent::Established)
            }
        }
    }

    pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<usize> {
        if self.closed_local || self.closed_remote {
            return Err(Error::ConnectionClosed);
        }
        let max_payload = self
            .payload_target
            .checked_sub(BpflinkHeader::encoded_len())
            .ok_or(Error::Config(
                "payload target is smaller than bpflink header",
            ))?;
        if max_payload == 0 {
            return Err(Error::Config("payload target leaves no room for data"));
        }

        if self.buffered_bytes() + bytes.len() > MAX_BUFFERED_BYTES {
            return Err(Error::Backpressure);
        }

        for chunk in bytes.chunks(max_payload) {
            self.outbound_data.push_back(chunk.to_vec());
        }
        Ok(bytes.len())
    }

    pub(crate) fn read(&mut self, out: &mut [u8]) -> Result<usize> {
        let mut read = 0;
        while read < out.len() {
            let Some(byte) = self.inbound_data.pop_front() else {
                break;
            };
            out[read] = byte;
            read += 1;
        }
        Ok(read)
    }

    pub(crate) fn poll_output(&mut self, now: Instant, out: &mut Vec<Vec<u8>>) -> Result<()> {
        if self.pending_reset {
            self.pending_reset = false;
            self.push_packet(PacketType::Reset, &[], out)?;
            return Ok(());
        }

        if self.initiator && !self.sent_connect {
            self.sent_connect = true;
            self.push_packet(PacketType::Connect, &[], out)?;
        }

        if self.pending_accept {
            self.pending_accept = false;
            self.push_packet(PacketType::Accept, &[], out)?;
        }

        if self.pending_ack {
            self.pending_ack = false;
            self.push_packet_with_stream_id(PacketType::Ping, self.next_recv_seq, &[], out)?;
        }

        if self.timers.retransmit_due(now) {
            for (seq, payload) in &self.unacked_data {
                self.push_packet_with_stream_id(PacketType::Data, *seq, payload, out)?;
            }
            self.timers.mark_retransmitted(now);
        }

        while let Some(payload) = self.outbound_data.pop_front() {
            let seq = self.next_send_seq;
            self.next_send_seq = self.next_send_seq.wrapping_add(1);
            self.push_packet_with_stream_id(PacketType::Data, seq, &payload, out)?;
            self.unacked_data.push_back((seq, payload));
        }

        if self.pending_fin {
            self.pending_fin = false;
            self.push_packet_with_stream_id(PacketType::Fin, self.next_send_seq, &[], out)?;
        }

        Ok(())
    }

    pub(crate) fn close(&mut self) {
        if !self.closed_local {
            self.closed_local = true;
            self.pending_fin = true;
        }
    }

    pub(crate) fn reset(&mut self) {
        if !self.closed_local {
            self.closed_local = true;
            self.pending_reset = true;
            self.pending_fin = false;
            self.outbound_data.clear();
            self.unacked_data.clear();
        }
    }

    pub(crate) fn idle_expired(&self, now: Instant) -> bool {
        self.timers.idle_expired(now, SESSION_IDLE_TIMEOUT)
    }

    pub(crate) fn remote_closed(&self) -> bool {
        self.closed_remote
    }

    fn drain_ordered_data(&mut self) {
        while let Some(payload) = self.out_of_order_data.remove(&self.next_recv_seq) {
            self.inbound_data.extend(payload.iter().copied());
            self.next_recv_seq = self.next_recv_seq.wrapping_add(1);
        }
        self.apply_pending_remote_fin();
    }

    fn apply_pending_remote_fin(&mut self) -> bool {
        if self.pending_remote_fin_seq == Some(self.next_recv_seq) {
            self.closed_remote = true;
        }
        self.closed_remote
    }

    fn buffered_bytes(&self) -> usize {
        self.outbound_data
            .iter()
            .map(Vec::len)
            .chain(self.unacked_data.iter().map(|(_, payload)| payload.len()))
            .sum()
    }

    fn ensure_connection(&self, connection_id: ConnectionId) -> Result<()> {
        if connection_id == self.connection_id {
            Ok(())
        } else {
            Err(Error::PacketParse("packet for different connection"))
        }
    }

    fn push_packet(
        &self,
        packet_type: PacketType,
        payload: &[u8],
        out: &mut Vec<Vec<u8>>,
    ) -> Result<()> {
        self.push_packet_with_stream_id(packet_type, self.session_id.0 as u32, payload, out)
    }

    fn push_packet_with_stream_id(
        &self,
        packet_type: PacketType,
        stream_id: u32,
        payload: &[u8],
        out: &mut Vec<Vec<u8>>,
    ) -> Result<()> {
        let header = BpflinkHeader {
            packet_type,
            service_port: self.service_port,
            connection_id: self.connection_id,
            stream_id,
        };
        let mut datagram = Vec::new();
        header.encode(payload, &mut datagram)?;
        if datagram.len() > self.payload_target {
            return Err(Error::PayloadTooLarge {
                len: datagram.len(),
                max: self.payload_target,
            });
        }
        out.push(datagram);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use crate::link::PeerAddr;
    use crate::transport::{BpflinkHeader, PacketType, DEFAULT_PAYLOAD_TARGET};

    use super::{ReliableSession, SessionEvent};

    #[test]
    fn reliable_session_connect_accept_establishes_session_ids() {
        let now = Instant::now();
        let (client, server) = connected_pair(now);

        assert!(client.established);
        assert!(server.established);
        assert_eq!(client.connection_id, server.connection_id);
        assert_eq!(client.session_id, server.session_id);
    }

    #[test]
    fn reliable_session_ordered_data_is_read_after_delivery() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);

        assert_eq!(client.write(b"hello world").unwrap(), 11);
        let mut output: Vec<Vec<u8>> = Vec::new();
        client.poll_output(now, &mut output).unwrap();

        for datagram in output {
            let (header, payload) = BpflinkHeader::decode(&datagram).unwrap();
            assert_eq!(header.packet_type, PacketType::Data);
            assert_eq!(
                server.on_packet(header, payload, now).unwrap(),
                SessionEvent::DataAvailable
            );
        }

        let mut read = [0; 32];
        let len = server.read(&mut read).unwrap();
        assert_eq!(&read[..len], b"hello world");
    }

    #[test]
    fn reliable_session_large_write_is_segmented_to_payload_target() {
        let now = Instant::now();
        let (mut client, _server) = connected_pair(now);
        let bytes = vec![0x5a; DEFAULT_PAYLOAD_TARGET * 2 + 7];

        assert_eq!(client.write(&bytes).unwrap(), bytes.len());
        let mut output: Vec<Vec<u8>> = Vec::new();
        client.poll_output(now, &mut output).unwrap();

        assert!(output.len() > 1);
        assert!(output
            .iter()
            .all(|datagram| datagram.len() <= DEFAULT_PAYLOAD_TARGET));
        let total_payload: usize = output
            .iter()
            .map(|datagram| BpflinkHeader::decode(datagram).unwrap().1.len())
            .sum();
        assert_eq!(total_payload, bytes.len());
    }

    #[test]
    fn reliable_session_segments_to_configured_payload_target() {
        let now = Instant::now();
        let peer = PeerAddr {
            ip: Ipv4Addr::new(10, 0, 0, 2).into(),
        };
        let mut session = ReliableSession::connect_with_payload_target(peer, 40000, now, 548);
        let bytes = vec![0x5a; 1000];

        assert_eq!(session.write(&bytes).unwrap(), bytes.len());
        let mut output: Vec<Vec<u8>> = Vec::new();
        session.poll_output(now, &mut output).unwrap();

        assert!(output.iter().all(|datagram| datagram.len() <= 548));
    }

    #[test]
    fn reliable_session_retransmits_unacked_data_and_deduplicates_delivery() {
        let now = Instant::now();
        let later = now + std::time::Duration::from_millis(300);
        let (mut client, mut server) = connected_pair(now);

        client.write(b"retry me").unwrap();
        let mut first_output: Vec<Vec<u8>> = Vec::new();
        client.poll_output(now, &mut first_output).unwrap();
        assert_eq!(first_output.len(), 1);

        let mut retry_output: Vec<Vec<u8>> = Vec::new();
        client.poll_output(later, &mut retry_output).unwrap();
        assert_eq!(retry_output, first_output);

        let (header, payload) = BpflinkHeader::decode(&first_output[0]).unwrap();
        assert_eq!(
            server.on_packet(header, payload, now).unwrap(),
            SessionEvent::DataAvailable
        );
        let (header, payload) = BpflinkHeader::decode(&retry_output[0]).unwrap();
        assert_eq!(
            server.on_packet(header, payload, later).unwrap(),
            SessionEvent::Established
        );

        let mut read = [0; 16];
        let len = server.read(&mut read).unwrap();
        assert_eq!(&read[..len], b"retry me");
    }

    #[test]
    fn reliable_session_ack_prunes_retransmit_queue() {
        let now = Instant::now();
        let later = now + std::time::Duration::from_millis(300);
        let (mut client, mut server) = connected_pair(now);

        client.write(b"ack me").unwrap();
        let mut client_output: Vec<Vec<u8>> = Vec::new();
        client.poll_output(now, &mut client_output).unwrap();
        assert_eq!(client_output.len(), 1);

        let (header, payload) = BpflinkHeader::decode(&client_output[0]).unwrap();
        assert_eq!(
            server.on_packet(header, payload, now).unwrap(),
            SessionEvent::DataAvailable
        );

        let mut server_output: Vec<Vec<u8>> = Vec::new();
        server.poll_output(now, &mut server_output).unwrap();
        assert_eq!(server_output.len(), 1);
        let (ack_header, ack_payload) = BpflinkHeader::decode(&server_output[0]).unwrap();
        assert_eq!(ack_header.packet_type, PacketType::Ping);

        assert_eq!(
            client.on_packet(ack_header, ack_payload, now).unwrap(),
            SessionEvent::Established
        );

        let mut retry_output: Vec<Vec<u8>> = Vec::new();
        client.poll_output(later, &mut retry_output).unwrap();
        assert!(retry_output.is_empty());
    }

    #[test]
    fn reliable_session_close_emits_fin_and_peer_reports_closed() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);

        client.close();
        let mut output = Vec::new();
        client.poll_output(now, &mut output).unwrap();

        assert_eq!(output.len(), 1);
        let (header, payload) = BpflinkHeader::decode(&output[0]).unwrap();
        assert_eq!(header.packet_type, PacketType::Fin);
        assert_eq!(
            server.on_packet(header, payload, now).unwrap(),
            SessionEvent::Closed
        );
    }

    #[test]
    fn reliable_session_close_after_write_emits_data_before_fin() {
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
    fn reliable_session_buffers_out_of_order_data_until_gap_arrives() {
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
            SessionEvent::Established
        );
        let mut read = [0; 32];
        assert_eq!(server.read(&mut read).unwrap(), 0);

        let (first_header, first_payload) = BpflinkHeader::decode(&output[0]).unwrap();
        assert_eq!(
            server.on_packet(first_header, first_payload, now).unwrap(),
            SessionEvent::DataAvailable
        );
        let len = server.read(&mut read).unwrap();
        assert_eq!(&read[..len], b"firstsecond");
    }

    #[test]
    fn reliable_session_defers_fin_until_missing_data_arrives() {
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
            SessionEvent::Established
        );
        assert_eq!(
            server.on_packet(fin_header, fin_payload, now).unwrap(),
            SessionEvent::Established
        );

        let (first_header, first_payload) = BpflinkHeader::decode(&output[0]).unwrap();
        assert_eq!(
            server.on_packet(first_header, first_payload, now).unwrap(),
            SessionEvent::DataAvailable
        );
        let mut read = [0; 32];
        let len = server.read(&mut read).unwrap();
        assert_eq!(&read[..len], b"firstsecond");
        assert!(server.remote_closed());
    }

    #[test]
    fn reliable_session_rejects_writes_after_close() {
        let now = Instant::now();
        let (mut client, _server) = connected_pair(now);

        client.close();

        assert!(matches!(
            client.write(b"late write"),
            Err(crate::Error::ConnectionClosed)
        ));
    }

    #[test]
    fn reliable_session_applies_outbound_backpressure() {
        let now = Instant::now();
        let peer = PeerAddr {
            ip: Ipv4Addr::new(10, 0, 0, 2).into(),
        };
        let mut session = ReliableSession::connect_with_payload_target(peer, 40000, now, 548);

        let result = session.write(&vec![0x5a; 2 * 1024 * 1024]);

        assert!(matches!(result, Err(crate::Error::Backpressure)));
    }

    #[test]
    fn reliable_session_reports_idle_timeout() {
        let now = Instant::now();
        let (client, _server) = connected_pair(now);

        assert!(!client.idle_expired(now + std::time::Duration::from_secs(29)));
        assert!(client.idle_expired(now + std::time::Duration::from_secs(31)));
    }

    fn connected_pair(now: Instant) -> (ReliableSession, ReliableSession) {
        let peer = PeerAddr {
            ip: Ipv4Addr::new(10, 0, 0, 2).into(),
        };
        let mut client = ReliableSession::connect(peer, 40000, now);
        let mut server = ReliableSession::connect(peer, 40000, now);

        let mut client_output: Vec<Vec<u8>> = Vec::new();
        client.poll_output(now, &mut client_output).unwrap();
        assert_eq!(client_output.len(), 1);
        let (connect_header, connect_payload) = BpflinkHeader::decode(&client_output[0]).unwrap();
        assert_eq!(connect_header.packet_type, PacketType::Connect);
        assert_eq!(
            server
                .on_packet(connect_header, connect_payload, now)
                .unwrap(),
            SessionEvent::Established
        );

        let mut server_output: Vec<Vec<u8>> = Vec::new();
        server.poll_output(now, &mut server_output).unwrap();
        assert_eq!(server_output.len(), 1);
        let (accept_header, accept_payload) = BpflinkHeader::decode(&server_output[0]).unwrap();
        assert_eq!(accept_header.packet_type, PacketType::Accept);
        assert_eq!(
            client
                .on_packet(accept_header, accept_payload, now)
                .unwrap(),
            SessionEvent::Established
        );

        (client, server)
    }
}
