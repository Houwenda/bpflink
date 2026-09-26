use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use kcp_core::{KcpCoreConfig, KcpEngine, NodeDelayConfig};

use crate::link::PeerAddr;
use crate::transport::engine::{TransportEngine, TransportEvent};
use crate::transport::{BpflinkHeader, PacketType};
use crate::{Error, Result};

static NEXT_KCP_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);
const KCP_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const KCP_MAX_SEND_QUEUE: usize = 1024;

pub(crate) struct KcpTransportEngine {
    service_port: u16,
    connection_id: u64,
    payload_target: usize,
    established: bool,
    initiator: bool,
    sent_connect: bool,
    pending_accept: bool,
    pending_fin: bool,
    pending_reset: bool,
    closed_local: bool,
    closed_remote: bool,
    inbound_data: VecDeque<u8>,
    kcp: KcpEngine,
    last_activity: Instant,
}

impl KcpTransportEngine {
    pub(crate) fn connect(
        _peer: PeerAddr,
        service_port: u16,
        now: Instant,
        payload_target: usize,
    ) -> Self {
        let connection_id = NEXT_KCP_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
        let mut kcp = KcpEngine::new(kcp_conv(connection_id), kcp_config(payload_target));
        let _ = kcp.start();
        Self {
            service_port,
            connection_id,
            payload_target,
            established: false,
            initiator: true,
            sent_connect: false,
            pending_accept: false,
            pending_fin: false,
            pending_reset: false,
            closed_local: false,
            closed_remote: false,
            inbound_data: VecDeque::new(),
            kcp,
            last_activity: now,
        }
    }

    fn drain_kcp_recv(&mut self) -> Result<bool> {
        let mut received = false;
        loop {
            let Some(bytes) = self.kcp.recv().map_err(map_kcp_error)? else {
                break;
            };
            self.inbound_data.extend(bytes.iter().copied());
            received = true;
        }
        Ok(received)
    }

    fn push_kcp_output(&mut self, out: &mut Vec<Vec<u8>>) -> Result<()> {
        for packet in self.kcp.drain_output() {
            self.push_packet(PacketType::Data, 0, &packet, out)?;
        }
        Ok(())
    }

    fn push_packet(
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

    fn ensure_connection(&self, connection_id: u64) -> Result<()> {
        if connection_id == self.connection_id {
            Ok(())
        } else {
            Err(Error::PacketParse("packet for different connection"))
        }
    }
}

impl TransportEngine for KcpTransportEngine {
    fn connection_id(&self) -> u64 {
        self.connection_id
    }

    fn on_packet(
        &mut self,
        header: BpflinkHeader,
        payload: &[u8],
        now: Instant,
    ) -> Result<TransportEvent> {
        if header.service_port != self.service_port {
            return Err(Error::PacketParse("packet for different service port"));
        }
        self.last_activity = now;

        match header.packet_type {
            PacketType::Connect => {
                self.connection_id = header.connection_id;
                self.kcp.set_conv(kcp_conv(header.connection_id));
                self.established = true;
                self.initiator = false;
                self.pending_accept = true;
                Ok(TransportEvent::Established)
            }
            PacketType::Accept => {
                self.ensure_connection(header.connection_id)?;
                self.established = true;
                Ok(TransportEvent::Established)
            }
            PacketType::Data => {
                self.ensure_connection(header.connection_id)?;
                self.kcp
                    .input(Bytes::copy_from_slice(payload))
                    .map_err(map_kcp_error)?;
                if self.drain_kcp_recv()? {
                    Ok(TransportEvent::DataAvailable)
                } else {
                    Ok(TransportEvent::Established)
                }
            }
            PacketType::Fin => {
                self.ensure_connection(header.connection_id)?;
                self.closed_remote = true;
                Ok(TransportEvent::Closed)
            }
            PacketType::Reset => {
                self.ensure_connection(header.connection_id)?;
                self.closed_remote = true;
                Ok(TransportEvent::Reset)
            }
            PacketType::Ping => {
                self.ensure_connection(header.connection_id)?;
                Ok(TransportEvent::Established)
            }
        }
    }

    fn write(&mut self, bytes: &[u8]) -> Result<usize> {
        if self.closed_local || self.closed_remote {
            return Err(Error::ConnectionClosed);
        }
        if self.kcp.send_queue_len() >= KCP_MAX_SEND_QUEUE {
            return Err(Error::Backpressure);
        }
        self.kcp
            .send(Bytes::copy_from_slice(bytes))
            .map_err(map_kcp_send_error)?;
        Ok(bytes.len())
    }

    fn read(&mut self, out: &mut [u8]) -> Result<usize> {
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

    fn poll_output(&mut self, _now: Instant, out: &mut Vec<Vec<u8>>) -> Result<()> {
        if self.pending_reset {
            self.pending_reset = false;
            self.push_packet(PacketType::Reset, self.connection_id as u32, &[], out)?;
            return Ok(());
        }

        if self.initiator && !self.sent_connect {
            self.sent_connect = true;
            self.push_packet(PacketType::Connect, self.connection_id as u32, &[], out)?;
        }

        if self.pending_accept {
            self.pending_accept = false;
            self.push_packet(PacketType::Accept, self.connection_id as u32, &[], out)?;
        }

        self.kcp.update().map_err(map_kcp_error)?;
        self.kcp.flush().map_err(map_kcp_error)?;
        self.push_kcp_output(out)?;

        if self.pending_fin && !self.kcp.has_unsent_data() {
            self.pending_fin = false;
            self.push_packet(PacketType::Fin, self.connection_id as u32, &[], out)?;
        }

        Ok(())
    }

    fn close(&mut self) {
        if !self.closed_local {
            self.closed_local = true;
            self.pending_fin = true;
        }
    }

    fn reset(&mut self) {
        if !self.closed_local {
            self.closed_local = true;
            self.pending_reset = true;
            self.pending_fin = false;
        }
    }

    fn idle_expired(&self, now: Instant) -> bool {
        now.duration_since(self.last_activity) > KCP_IDLE_TIMEOUT
    }

    fn remote_closed(&self) -> bool {
        self.closed_remote
    }
}

fn kcp_config(payload_target: usize) -> KcpCoreConfig {
    let mtu = payload_target
        .saturating_sub(BpflinkHeader::encoded_len())
        .max(25) as u32;
    KcpCoreConfig {
        mtu,
        nodelay: NodeDelayConfig::fast(),
        stream_mode: true,
        ..Default::default()
    }
}

fn kcp_conv(connection_id: u64) -> u32 {
    let conv = connection_id as u32;
    if conv == 0 {
        1
    } else {
        conv
    }
}

fn map_kcp_error(_error: kcp_core::KcpCoreError) -> Error {
    Error::PacketParse("kcp protocol error")
}

fn map_kcp_send_error(error: kcp_core::KcpCoreError) -> Error {
    if matches!(error, kcp_core::KcpCoreError::Buffer { .. }) {
        Error::Backpressure
    } else {
        map_kcp_error(error)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use crate::link::PeerAddr;
    use crate::transport::{BpflinkHeader, PacketType, TransportEngine, TransportEvent};

    use super::KcpTransportEngine;

    #[test]
    fn kcp_engine_delivers_bytes_through_bpflink_data_packets() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);

        assert_eq!(client.write(b"hello kcp").unwrap(), 9);
        exchange_until_idle(&mut client, &mut server, now);

        let mut read = [0; 32];
        let len = server.read(&mut read).unwrap();
        assert_eq!(&read[..len], b"hello kcp");
    }

    #[test]
    fn kcp_engine_retransmits_until_acknowledged() {
        let now = Instant::now();
        let (mut client, _server) = connected_pair(now);

        client.write(b"retry over kcp").unwrap();
        let mut first_output = Vec::new();
        client.poll_output(now, &mut first_output).unwrap();
        assert!(first_output
            .iter()
            .any(
                |datagram| BpflinkHeader::decode(datagram).unwrap().0.packet_type
                    == PacketType::Data
            ));

        std::thread::sleep(Duration::from_millis(220));
        let mut retry_output = Vec::new();
        client
            .poll_output(Instant::now(), &mut retry_output)
            .unwrap();
        assert!(
            retry_output
                .iter()
                .any(
                    |datagram| BpflinkHeader::decode(datagram).unwrap().0.packet_type
                        == PacketType::Data
                ),
            "expected unacked KCP data to be retransmitted"
        );
    }

    #[test]
    fn kcp_engine_stops_retransmitting_after_ack() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);

        client.write(b"acked over kcp").unwrap();
        let mut client_output = Vec::new();
        client.poll_output(now, &mut client_output).unwrap();
        assert!(client_output
            .iter()
            .any(
                |datagram| BpflinkHeader::decode(datagram).unwrap().0.packet_type
                    == PacketType::Data
            ));

        for datagram in client_output {
            let (header, payload) = BpflinkHeader::decode(&datagram).unwrap();
            server.on_packet(header, payload, now).unwrap();
        }
        let mut server_ack = Vec::new();
        server.poll_output(now, &mut server_ack).unwrap();
        for datagram in server_ack {
            let (header, payload) = BpflinkHeader::decode(&datagram).unwrap();
            client.on_packet(header, payload, now).unwrap();
        }

        std::thread::sleep(Duration::from_millis(220));
        let mut retry_output = Vec::new();
        client
            .poll_output(Instant::now(), &mut retry_output)
            .unwrap();
        assert!(
            !retry_output
                .iter()
                .any(
                    |datagram| BpflinkHeader::decode(datagram).unwrap().0.packet_type
                        == PacketType::Data
                ),
            "acked KCP data should not be retransmitted"
        );
    }

    #[test]
    fn kcp_engine_reassembles_out_of_order_segments() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);
        let payload: Vec<u8> = (0..3000).map(|index| (index % 251) as u8).collect();

        client.write(&payload).unwrap();
        let mut client_output = Vec::new();
        client.poll_output(now, &mut client_output).unwrap();
        let mut data_datagrams: Vec<_> = client_output
            .into_iter()
            .filter(|datagram| {
                BpflinkHeader::decode(datagram).unwrap().0.packet_type == PacketType::Data
            })
            .collect();
        assert!(
            data_datagrams.len() > 1,
            "large KCP payload should be segmented"
        );

        data_datagrams.reverse();
        for datagram in data_datagrams {
            let (header, payload) = BpflinkHeader::decode(&datagram).unwrap();
            server.on_packet(header, payload, now).unwrap();
        }

        let mut read = vec![0; payload.len()];
        let len = server.read(&mut read).unwrap();
        assert_eq!(len, payload.len());
        assert_eq!(read, payload);
    }

    #[test]
    fn kcp_engine_defers_fin_until_data_is_acknowledged() {
        let now = Instant::now();
        let (mut client, mut server) = connected_pair(now);

        client.write(b"close after kcp data").unwrap();
        client.close();
        let mut client_output = Vec::new();
        client.poll_output(now, &mut client_output).unwrap();

        assert!(client_output
            .iter()
            .any(
                |datagram| BpflinkHeader::decode(datagram).unwrap().0.packet_type
                    == PacketType::Data
            ));
        assert!(!client_output
            .iter()
            .any(
                |datagram| BpflinkHeader::decode(datagram).unwrap().0.packet_type
                    == PacketType::Fin
            ));

        for datagram in client_output {
            let (header, payload) = BpflinkHeader::decode(&datagram).unwrap();
            server.on_packet(header, payload, now).unwrap();
        }
        let mut server_output = Vec::new();
        server.poll_output(now, &mut server_output).unwrap();
        for datagram in server_output {
            let (header, payload) = BpflinkHeader::decode(&datagram).unwrap();
            client.on_packet(header, payload, now).unwrap();
        }

        let mut fin_output = Vec::new();
        client.poll_output(now, &mut fin_output).unwrap();
        assert!(fin_output
            .iter()
            .any(
                |datagram| BpflinkHeader::decode(datagram).unwrap().0.packet_type
                    == PacketType::Fin
            ));

        let mut read = [0; 32];
        let len = server.read(&mut read).unwrap();
        assert_eq!(&read[..len], b"close after kcp data");
    }

    fn connected_pair(now: Instant) -> (KcpTransportEngine, KcpTransportEngine) {
        let peer = PeerAddr {
            ip: Ipv4Addr::new(10, 0, 0, 2).into(),
        };
        let mut client = KcpTransportEngine::connect(peer, 40000, now, 1200);
        let mut server = KcpTransportEngine::connect(peer, 40000, now, 1200);

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

    fn exchange_until_idle(
        client: &mut KcpTransportEngine,
        server: &mut KcpTransportEngine,
        now: Instant,
    ) {
        for _ in 0..8 {
            let mut client_output = Vec::new();
            client.poll_output(now, &mut client_output).unwrap();
            let mut server_output = Vec::new();
            server.poll_output(now, &mut server_output).unwrap();
            if client_output.is_empty() && server_output.is_empty() {
                return;
            }
            for datagram in client_output {
                let (header, payload) = BpflinkHeader::decode(&datagram).unwrap();
                server.on_packet(header, payload, now).unwrap();
            }
            for datagram in server_output {
                let (header, payload) = BpflinkHeader::decode(&datagram).unwrap();
                client.on_packet(header, payload, now).unwrap();
            }
        }
    }
}
