use std::collections::HashMap;
use std::net::IpAddr;
#[cfg(feature = "test-util")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "test-util")]
use std::sync::Arc;
use std::sync::{mpsc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::EthernetAddress;
use tokio::sync::oneshot;

#[cfg(feature = "test-util")]
use crate::link::LinkStats;
use crate::link::PeerAddr;
use crate::socket::{BpfListener, BpfStream, StreamReadHandle};
use crate::stack::smoltcp_driver::{PollOutcome, StackConfig, StackDriver};
use crate::transport::KcpTransportEngine;
use crate::transport::{
    payload_target_for_ipv4_mtu, payload_target_for_ipv6_mtu, BpflinkHeader, PacketType,
    SimpleTransportEngine, TransportEngine, TransportEvent, TransportMode,
};
use crate::{Error, Result};

use crate::bpf::FrameIo;

#[cfg(feature = "test-util")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TestCommand {
    Listen { service_port: u16 },
    Connect { peer: PeerAddr, service_port: u16 },
    StreamWrite { session_id: u64, len: usize },
    StreamReadPoll { session_id: u64 },
    Close { session_id: u64 },
    Abort { session_id: u64 },
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeSnapshot {
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
    /// ICMP Port Unreachable packets related to bpflink traffic that were
    /// counted and ignored instead of closing a session.
    pub ignored_icmp_count: usize,
    /// Sessions removed from runtime state after peer FIN/reset or idle reap.
    /// Local stream shutdown alone does not increment this counter because the
    /// session is kept for unacked data retransmission.
    pub closed_session_count: usize,
    /// Sessions removed specifically by idle timeout.
    pub idle_timeout_count: usize,
    /// Stream writes rejected because the session outbound buffer is full.
    pub backpressure_count: usize,
}

#[derive(Debug)]
pub(crate) struct RuntimeDriver {
    sender: mpsc::Sender<DriverCommand>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeStreamHandle {
    sender: mpsc::Sender<DriverCommand>,
}

impl RuntimeStreamHandle {
    fn new(sender: mpsc::Sender<DriverCommand>) -> Self {
        Self { sender }
    }

    pub(crate) fn write(&self, session_id: u64, bytes: &[u8]) -> std::io::Result<()> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.sender
            .send(DriverCommand::StreamWrite {
                session_id,
                bytes: bytes.to_vec(),
                reply,
            })
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, Error::LinkClosed))?;
        receiver
            .recv()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, Error::LinkClosed))?
            .map_err(error_to_io)
    }

    pub(crate) fn read_poll(&self, session_id: u64) -> std::io::Result<()> {
        self.sender
            .send(DriverCommand::StreamReadPoll { session_id })
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, Error::LinkClosed))
    }

    pub(crate) fn close(&self, session_id: u64) {
        let _ = self.sender.send(DriverCommand::Close { session_id });
    }

    pub(crate) async fn abort(&self, session_id: u64) -> Result<()> {
        let (reply, receiver) = oneshot::channel();
        self.sender
            .send(DriverCommand::Abort { session_id, reply })
            .map_err(|_| Error::LinkClosed)?;
        receiver.await.map_err(|_| Error::LinkClosed)?
    }
}

impl RuntimeDriver {
    #[cfg(test)]
    pub(crate) fn spawn_with_device<D>(device: D, config: StackConfig) -> Result<Self>
    where
        D: FrameIo + Send + 'static,
    {
        Self::spawn_with_device_with_transport(device, config, TransportMode::Simple)
    }

    pub(crate) fn spawn_with_device_with_transport<D>(
        device: D,
        config: StackConfig,
        transport_mode: TransportMode,
    ) -> Result<Self>
    where
        D: FrameIo + Send + 'static,
    {
        let mtu = device.mtu();
        let payload_target = match config.local_ip {
            IpAddr::V4(_) => payload_target_for_ipv4_mtu(mtu),
            IpAddr::V6(_) => payload_target_for_ipv6_mtu(mtu),
        };
        let sees_sent_configured = device.sees_sent_configured();
        let filter_configured = device.filter_configured();
        let service_ports = config.service_ports.clone();
        let stack = StackDriver::new(config, device)?;
        let (sender, receiver) = mpsc::channel();
        let state_sender = sender.clone();
        let thread = thread::spawn(move || {
            let mut state = DriverState::new(
                stack,
                DriverStateConfig {
                    service_ports,
                    mtu,
                    payload_target,
                    sees_sent_configured,
                    filter_configured,
                    transport_mode,
                },
                state_sender,
            );
            run_driver_loop(receiver, &mut state);
        });

        Ok(Self {
            sender,
            thread: Mutex::new(Some(thread)),
        })
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    pub(crate) fn spawn_bpf(
        interface: &str,
        local_ip: IpAddr,
        service_ports: &[u16],
        transport_mode: TransportMode,
    ) -> Result<Self> {
        let device = crate::bpf::BpfDevice::open_filtered(interface, service_ports)?;
        let ethernet_addr = EthernetAddress(crate::bpf::interface_ethernet_addr(interface)?);
        let local_prefix_len = crate::bpf::interface_ip_prefix_len(interface, local_ip)?;
        let default_gateway = crate::bpf::interface_default_gateway(interface, local_ip)?;
        Self::spawn_with_device_with_transport(
            device,
            StackConfig {
                local_ip,
                local_prefix_len,
                default_gateway,
                service_ports: service_ports.to_vec(),
                ethernet_addr,
            },
            transport_mode,
        )
    }

    pub(crate) async fn listen(&self, service_port: u16) -> Result<BpfListener> {
        let (reply, receiver) = oneshot::channel();
        self.send(DriverCommand::Listen {
            service_port,
            reply,
        })?;
        receiver.await.map_err(|_| Error::DriverClosed)?
    }

    pub(crate) async fn connect(&self, peer: PeerAddr, service_port: u16) -> Result<BpfStream> {
        let (reply, receiver) = oneshot::channel();
        self.send(DriverCommand::Connect {
            peer,
            service_port,
            reply,
        })?;
        let stream = receiver.await.map_err(|_| Error::DriverClosed)??;
        let (stream, read_handle) = BpfStream::new_runtime(
            stream.session_id,
            stream.service_port,
            stream.peer,
            RuntimeStreamHandle::new(self.sender.clone()),
        );
        self.send(DriverCommand::AttachReadHandle {
            session_id: stream.session_id(),
            read_handle,
        })?;
        Ok(stream)
    }

    pub(crate) async fn snapshot(&self) -> Result<RuntimeSnapshot> {
        let (reply, receiver) = oneshot::channel();
        self.send(DriverCommand::Snapshot { reply })?;
        receiver.await.map_err(|_| Error::LinkClosed)
    }

    pub(crate) fn shutdown_blocking(&self) -> Result<()> {
        let (reply, receiver) = mpsc::sync_channel(1);
        self.sender
            .send(DriverCommand::Shutdown { reply: Some(reply) })
            .map_err(|_| Error::LinkClosed)?;
        receiver.recv().map_err(|_| Error::LinkClosed)?;
        if let Some(thread) = self.thread.lock().expect("runtime thread poisoned").take() {
            let _ = thread.join();
        }
        Ok(())
    }

    fn send(&self, command: DriverCommand) -> Result<()> {
        self.sender.send(command).map_err(|_| Error::LinkClosed)
    }
}

impl Drop for RuntimeDriver {
    fn drop(&mut self) {
        let _ = self.sender.send(DriverCommand::Shutdown { reply: None });
        if let Some(thread) = self.thread.lock().expect("runtime thread poisoned").take() {
            let _ = thread.join();
        }
    }
}

enum DriverCommand {
    Listen {
        service_port: u16,
        reply: oneshot::Sender<Result<BpfListener>>,
    },
    Connect {
        peer: PeerAddr,
        service_port: u16,
        reply: oneshot::Sender<Result<ConnectedStream>>,
    },
    StreamWrite {
        session_id: u64,
        bytes: Vec<u8>,
        reply: mpsc::SyncSender<Result<()>>,
    },
    StreamReadPoll {
        session_id: u64,
    },
    Close {
        session_id: u64,
    },
    Abort {
        session_id: u64,
        reply: oneshot::Sender<Result<()>>,
    },
    AttachReadHandle {
        session_id: u64,
        read_handle: StreamReadHandle,
    },
    Snapshot {
        reply: oneshot::Sender<RuntimeSnapshot>,
    },
    Shutdown {
        reply: Option<mpsc::SyncSender<()>>,
    },
}

struct ConnectedStream {
    session_id: u64,
    service_port: u16,
    peer: PeerAddr,
}

struct RuntimeSession {
    local_service_port: u16,
    peer: PeerAddr,
    peer_port: u16,
    connection_id: u64,
    engine: Box<dyn TransportEngine>,
    read_handle: Option<StreamReadHandle>,
}

struct DriverState<D: FrameIo> {
    sender: mpsc::Sender<DriverCommand>,
    stack: StackDriver<D>,
    service_ports: Vec<u16>,
    mtu: usize,
    payload_target: usize,
    sees_sent_configured: Option<bool>,
    filter_configured: Option<bool>,
    transport_mode: TransportMode,
    listeners: HashMap<u16, BpfListener>,
    sessions: HashMap<u64, RuntimeSession>,
    next_stream_id: u64,
    command_count: usize,
    poll_count: usize,
    stream_write_count: usize,
    outbound_datagram_count: usize,
    inbound_accept_count: usize,
    inbound_data_count: usize,
    ignored_icmp_count: usize,
    closed_session_count: usize,
    idle_timeout_count: usize,
    backpressure_count: usize,
}

#[derive(Clone, Debug)]
struct DriverStateConfig {
    service_ports: Vec<u16>,
    mtu: usize,
    payload_target: usize,
    sees_sent_configured: Option<bool>,
    filter_configured: Option<bool>,
    transport_mode: TransportMode,
}

impl<D: FrameIo> DriverState<D> {
    fn new(
        stack: StackDriver<D>,
        config: DriverStateConfig,
        sender: mpsc::Sender<DriverCommand>,
    ) -> Self {
        Self {
            sender,
            stack,
            service_ports: config.service_ports,
            mtu: config.mtu,
            payload_target: config.payload_target,
            sees_sent_configured: config.sees_sent_configured,
            filter_configured: config.filter_configured,
            transport_mode: config.transport_mode,
            listeners: HashMap::new(),
            sessions: HashMap::new(),
            next_stream_id: 1,
            command_count: 0,
            poll_count: 0,
            stream_write_count: 0,
            outbound_datagram_count: 0,
            inbound_accept_count: 0,
            inbound_data_count: 0,
            ignored_icmp_count: 0,
            closed_session_count: 0,
            idle_timeout_count: 0,
            backpressure_count: 0,
        }
    }

    fn listen(&mut self, service_port: u16) -> Result<BpfListener> {
        self.ensure_service_port(service_port)?;

        let listener = self
            .listeners
            .entry(service_port)
            .or_insert_with(|| BpfListener::new(service_port))
            .clone();
        Ok(listener)
    }

    fn connect(
        &mut self,
        peer: PeerAddr,
        service_port: u16,
        now: Instant,
    ) -> Result<ConnectedStream> {
        self.ensure_service_port(service_port)?;

        let mut engine = self.new_transport_engine(peer, service_port, now);
        let mut datagrams = Vec::new();
        engine.poll_output(now, &mut datagrams)?;
        self.outbound_datagram_count += datagrams.len();
        for datagram in datagrams {
            self.stack
                .send_udp(service_port, peer.ip, service_port, &datagram)?;
        }

        let stream_id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1);
        self.sessions.insert(
            stream_id,
            RuntimeSession {
                local_service_port: service_port,
                peer,
                peer_port: service_port,
                connection_id: engine.connection_id(),
                engine,
                read_handle: None,
            },
        );
        Ok(ConnectedStream {
            session_id: stream_id,
            service_port,
            peer,
        })
    }

    fn stream_write(&mut self, session_id: u64, bytes: &[u8], now: Instant) -> Result<()> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(Error::SessionNotFound)?;
        if let Err(err) = session.engine.write(bytes) {
            if matches!(err, Error::Backpressure) {
                self.backpressure_count += 1;
            }
            return Err(err);
        }
        let mut datagrams = Vec::new();
        session.engine.poll_output(now, &mut datagrams)?;
        self.stream_write_count += 1;
        self.outbound_datagram_count += datagrams.len();
        for datagram in datagrams {
            self.stack.send_udp(
                session.local_service_port,
                session.peer.ip,
                session.peer_port,
                &datagram,
            )?;
        }
        Ok(())
    }

    fn attach_read_handle(&mut self, session_id: u64, read_handle: StreamReadHandle) {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.read_handle = Some(read_handle);
        }
    }

    fn close(&mut self, session_id: u64) {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.engine.close();
            let mut datagrams = Vec::new();
            if session
                .engine
                .poll_output(Instant::now(), &mut datagrams)
                .is_ok()
            {
                self.outbound_datagram_count += datagrams.len();
                for datagram in datagrams {
                    let _ = self.stack.send_udp(
                        session.local_service_port,
                        session.peer.ip,
                        session.peer_port,
                        &datagram,
                    );
                }
            }
        }
    }

    fn abort(&mut self, session_id: u64) -> Result<()> {
        let Some(mut session) = self.sessions.remove(&session_id) else {
            return Err(Error::SessionNotFound);
        };

        session.engine.reset();
        let mut datagrams = Vec::new();
        session.engine.poll_output(Instant::now(), &mut datagrams)?;
        self.outbound_datagram_count += datagrams.len();
        for datagram in datagrams {
            let _ = self.stack.send_udp(
                session.local_service_port,
                session.peer.ip,
                session.peer_port,
                &datagram,
            );
        }
        if let Some(read_handle) = session.read_handle {
            read_handle.close();
        }
        self.closed_session_count += 1;
        Ok(())
    }

    fn remove_session(&mut self, session_id: u64) {
        if let Some(session) = self.sessions.remove(&session_id) {
            if let Some(read_handle) = session.read_handle {
                read_handle.close();
            }
            self.closed_session_count += 1;
        }
    }

    fn shutdown(&mut self) {
        for listener in self.listeners.values() {
            listener.close();
        }
        self.listeners.clear();

        let session_ids: Vec<u64> = self.sessions.keys().copied().collect();
        for session_id in session_ids {
            self.close(session_id);
            self.remove_session(session_id);
        }
    }

    fn snapshot(&self) -> RuntimeSnapshot {
        RuntimeSnapshot {
            service_ports: self.service_ports.clone(),
            transport_mode: self.transport_mode.as_str(),
            mtu: self.mtu,
            payload_target: self.payload_target,
            sees_sent_configured: self.sees_sent_configured,
            filter_configured: self.filter_configured,
            listener_count: self.listeners.len(),
            session_count: self.sessions.len(),
            command_count: self.command_count,
            poll_count: self.poll_count,
            stream_write_count: self.stream_write_count,
            outbound_datagram_count: self.outbound_datagram_count,
            inbound_accept_count: self.inbound_accept_count,
            inbound_data_count: self.inbound_data_count,
            ignored_icmp_count: self.ignored_icmp_count,
            closed_session_count: self.closed_session_count,
            idle_timeout_count: self.idle_timeout_count,
            backpressure_count: self.backpressure_count,
        }
    }

    fn poll_once(&mut self, started_at: Instant) -> Result<()> {
        self.poll_count += 1;
        let now = Instant::now();
        match self.stack.poll(smoltcp_now(started_at))? {
            PollOutcome::Idle => {}
            PollOutcome::IgnoredIcmp => {
                self.ignored_icmp_count += 1;
            }
            PollOutcome::ReceivedUdp {
                src,
                src_port,
                service_port,
                payload,
            } => self.dispatch_udp(src, src_port, service_port, &payload, now)?,
        }
        self.poll_session_outputs(now)?;
        self.expire_idle_sessions(now);
        Ok(())
    }

    fn expire_idle_sessions(&mut self, now: Instant) {
        let expired: Vec<u64> = self
            .sessions
            .iter()
            .filter_map(|(session_id, session)| {
                session.engine.idle_expired(now).then_some(*session_id)
            })
            .collect();
        for session_id in expired {
            self.idle_timeout_count += 1;
            self.remove_session(session_id);
        }
    }

    fn poll_session_outputs(&mut self, now: Instant) -> Result<()> {
        let mut outbound = Vec::new();
        for session in self.sessions.values_mut() {
            let mut datagrams = Vec::new();
            session.engine.poll_output(now, &mut datagrams)?;
            self.outbound_datagram_count += datagrams.len();
            for datagram in datagrams {
                outbound.push((
                    session.local_service_port,
                    session.peer.ip,
                    session.peer_port,
                    datagram,
                ));
            }
        }

        for (service_port, ip, port, datagram) in outbound {
            self.stack.send_udp(service_port, ip, port, &datagram)?;
        }
        Ok(())
    }

    fn dispatch_udp(
        &mut self,
        src: IpAddr,
        src_port: u16,
        service_port: u16,
        datagram: &[u8],
        now: Instant,
    ) -> Result<()> {
        let (header, payload) = BpflinkHeader::decode(datagram)?;
        if header.service_port != service_port {
            return Ok(());
        }
        match header.packet_type {
            PacketType::Connect => self.accept_inbound(src, src_port, header, payload, now),
            _ => self.dispatch_session_packet(src, src_port, header, payload, now),
        }
    }

    fn accept_inbound(
        &mut self,
        src: IpAddr,
        src_port: u16,
        header: BpflinkHeader,
        payload: &[u8],
        now: Instant,
    ) -> Result<()> {
        let Some(listener) = self.listeners.get(&header.service_port).cloned() else {
            return Ok(());
        };
        let peer = PeerAddr { ip: src };
        let mut engine = self.new_transport_engine(peer, header.service_port, now);
        engine.on_packet(header, payload, now)?;

        let stream_id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1);
        let (stream, read_handle) = BpfStream::new_runtime(
            stream_id,
            header.service_port,
            peer,
            RuntimeStreamHandle::new(self.sender.clone()),
        );
        listener.push_pending(stream)?;

        let mut datagrams = Vec::new();
        engine.poll_output(now, &mut datagrams)?;
        self.outbound_datagram_count += datagrams.len();
        for datagram in datagrams {
            self.stack
                .send_udp(header.service_port, src, src_port, &datagram)?;
        }

        self.sessions.insert(
            stream_id,
            RuntimeSession {
                local_service_port: header.service_port,
                peer,
                peer_port: src_port,
                connection_id: engine.connection_id(),
                engine,
                read_handle: Some(read_handle),
            },
        );
        self.inbound_accept_count += 1;
        Ok(())
    }

    fn dispatch_session_packet(
        &mut self,
        src: IpAddr,
        src_port: u16,
        header: BpflinkHeader,
        payload: &[u8],
        now: Instant,
    ) -> Result<()> {
        let Some(session_id) = self.sessions.iter().find_map(|(session_id, session)| {
            (session.connection_id == header.connection_id
                && session.peer.ip == src
                && session.peer_port == src_port
                && session.local_service_port == header.service_port)
                .then_some(*session_id)
        }) else {
            return Ok(());
        };
        let session = self
            .sessions
            .get_mut(&session_id)
            .expect("session id selected from sessions");
        let event = session.engine.on_packet(header, payload, now)?;
        if matches!(event, TransportEvent::Closed | TransportEvent::Reset) {
            self.remove_session(session_id);
            return Ok(());
        }
        if matches!(event, TransportEvent::DataAvailable) {
            let mut buf = [0; 2048];
            loop {
                let read = session.engine.read(&mut buf)?;
                if read == 0 {
                    break;
                }
                if let Some(read_handle) = &session.read_handle {
                    read_handle.push_bytes(&buf[..read]);
                }
                self.inbound_data_count += 1;
            }
        }
        let mut datagrams = Vec::new();
        session.engine.poll_output(now, &mut datagrams)?;
        self.outbound_datagram_count += datagrams.len();
        for datagram in datagrams {
            self.stack.send_udp(
                session.local_service_port,
                session.peer.ip,
                session.peer_port,
                &datagram,
            )?;
        }
        if session.engine.remote_closed() {
            self.remove_session(session_id);
        }
        Ok(())
    }

    fn new_transport_engine(
        &self,
        peer: PeerAddr,
        service_port: u16,
        now: Instant,
    ) -> Box<dyn TransportEngine> {
        match self.transport_mode {
            TransportMode::Simple => Box::new(SimpleTransportEngine::connect(
                peer,
                service_port,
                now,
                self.payload_target,
            )),
            TransportMode::Kcp => Box::new(KcpTransportEngine::connect(
                peer,
                service_port,
                now,
                self.payload_target,
            )),
        }
    }

    fn ensure_service_port(&self, service_port: u16) -> Result<()> {
        if self.service_ports.contains(&service_port) {
            Ok(())
        } else {
            Err(Error::ServicePortNotConfigured {
                requested: service_port,
            })
        }
    }
}

fn run_driver_loop<D: FrameIo>(
    receiver: mpsc::Receiver<DriverCommand>,
    state: &mut DriverState<D>,
) {
    let started_at = Instant::now();
    loop {
        match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(command) => {
                state.command_count += 1;
                if !handle_command(command, state, started_at) {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if state.poll_once(started_at).is_err() {
            break;
        }
    }
}

fn handle_command<D: FrameIo>(
    command: DriverCommand,
    state: &mut DriverState<D>,
    started_at: Instant,
) -> bool {
    match command {
        DriverCommand::Listen {
            service_port,
            reply,
        } => {
            let _ = reply.send(state.listen(service_port));
            true
        }
        DriverCommand::Connect {
            peer,
            service_port,
            reply,
        } => {
            let _ = started_at;
            let _ = reply.send(state.connect(peer, service_port, Instant::now()));
            true
        }
        DriverCommand::StreamWrite {
            session_id,
            bytes,
            reply,
        } => {
            let _ = started_at;
            let _ = reply.send(state.stream_write(session_id, &bytes, Instant::now()));
            true
        }
        DriverCommand::StreamReadPoll { session_id } => {
            let _ = state.sessions.contains_key(&session_id);
            true
        }
        DriverCommand::Close { session_id } => {
            state.close(session_id);
            true
        }
        DriverCommand::Abort { session_id, reply } => {
            let _ = reply.send(state.abort(session_id));
            true
        }
        DriverCommand::AttachReadHandle {
            session_id,
            read_handle,
        } => {
            state.attach_read_handle(session_id, read_handle);
            true
        }
        DriverCommand::Snapshot { reply } => {
            let _ = reply.send(state.snapshot());
            true
        }
        DriverCommand::Shutdown { reply } => {
            state.shutdown();
            if let Some(reply) = reply {
                let _ = reply.send(());
            }
            false
        }
    }
}

fn smoltcp_now(started_at: Instant) -> SmolInstant {
    let elapsed = started_at.elapsed();
    SmolInstant::from_millis(elapsed.as_millis().min(i64::MAX as u128) as i64)
}

fn error_to_io(error: Error) -> std::io::Error {
    let kind = match error {
        Error::DriverClosed
        | Error::LinkClosed
        | Error::StreamClosed
        | Error::SessionNotFound
        | Error::ConnectionClosed => std::io::ErrorKind::BrokenPipe,
        Error::Backpressure => std::io::ErrorKind::WouldBlock,
        _ => std::io::ErrorKind::Other,
    };
    std::io::Error::new(kind, error)
}

#[cfg(feature = "test-util")]
#[derive(Clone, Debug)]
pub(crate) struct TestDriver {
    commands: Arc<Mutex<Vec<TestCommand>>>,
    listeners: Arc<Mutex<HashMap<u16, BpfListener>>>,
    stream_close_handles: Arc<Mutex<Vec<StreamReadHandle>>>,
    service_ports: Vec<u16>,
    next_session_id: Arc<AtomicU64>,
}

#[cfg(feature = "test-util")]
impl Default for TestDriver {
    fn default() -> Self {
        Self {
            commands: Arc::new(Mutex::new(Vec::new())),
            listeners: Arc::new(Mutex::new(HashMap::new())),
            stream_close_handles: Arc::new(Mutex::new(Vec::new())),
            service_ports: Vec::new(),
            next_session_id: Arc::new(AtomicU64::new(1)),
        }
    }
}

#[cfg(feature = "test-util")]
impl TestDriver {
    pub(crate) fn with_service_ports(service_ports: Vec<u16>) -> Self {
        Self {
            service_ports,
            ..Self::default()
        }
    }

    pub(crate) fn record(&self, command: TestCommand) {
        self.commands
            .lock()
            .expect("test driver poisoned")
            .push(command);
    }

    pub(crate) fn commands(&self) -> Vec<TestCommand> {
        self.commands.lock().expect("test driver poisoned").clone()
    }

    pub(crate) fn listen(&self, service_port: u16) -> Result<BpfListener> {
        let listener = BpfListener::new(service_port);
        self.listeners
            .lock()
            .expect("test driver poisoned")
            .insert(service_port, listener.clone());
        Ok(listener)
    }

    pub(crate) fn connect(&self, _peer: PeerAddr, service_port: u16) -> Result<BpfStream> {
        let listener = self
            .listeners
            .lock()
            .expect("test driver poisoned")
            .get(&service_port)
            .cloned()
            .ok_or(Error::DriverClosed)?;
        let client_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let server_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let (client, server) = BpfStream::pair_with_test_commands(
            client_id,
            server_id,
            service_port,
            _peer,
            self.commands.clone(),
        );
        {
            let mut handles = self
                .stream_close_handles
                .lock()
                .expect("test driver stream handles poisoned");
            let (client_read, client_write) = client.pipe_handles_for_test();
            let (server_read, server_write) = server.pipe_handles_for_test();
            handles.extend([client_read, client_write, server_read, server_write]);
        }
        listener.push_pending(server)?;
        Ok(client)
    }

    pub(crate) fn shutdown(&self) {
        self.record(TestCommand::Shutdown);
        for listener in self
            .listeners
            .lock()
            .expect("test driver poisoned")
            .values()
        {
            listener.close();
        }
        for handle in self
            .stream_close_handles
            .lock()
            .expect("test driver stream handles poisoned")
            .iter()
        {
            handle.close();
        }
    }

    pub(crate) fn snapshot(
        &self,
        fallback_service_ports: &[u16],
        transport_mode: &'static str,
    ) -> LinkStats {
        let listeners = self.listeners.lock().expect("test driver poisoned");
        let stream_handles = self
            .stream_close_handles
            .lock()
            .expect("test driver stream handles poisoned");
        let commands = self.commands.lock().expect("test driver poisoned");
        LinkStats {
            service_ports: if self.service_ports.is_empty() {
                fallback_service_ports.to_vec()
            } else {
                self.service_ports.clone()
            },
            transport_mode,
            mtu: 1500,
            payload_target: crate::transport::DEFAULT_PAYLOAD_TARGET,
            sees_sent_configured: None,
            filter_configured: None,
            listener_count: listeners.len(),
            session_count: stream_handles.len() / 2,
            command_count: commands.len(),
            poll_count: 0,
            stream_write_count: commands
                .iter()
                .filter(|command| matches!(command, TestCommand::StreamWrite { .. }))
                .count(),
            outbound_datagram_count: 0,
            inbound_accept_count: 0,
            inbound_data_count: 0,
            ignored_icmp_count: 0,
            closed_session_count: 0,
            idle_timeout_count: 0,
            backpressure_count: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use smoltcp::wire::EthernetAddress;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::bpf::FrameIo;
    use crate::link::PeerAddr;
    use crate::stack::smoltcp_driver::{StackConfig, StackDriver};
    use crate::transport::payload_target_for_ipv4_mtu;
    use crate::transport::{BpflinkHeader, PacketType};
    use crate::transport::{KcpTransportEngine, TransportEngine, TransportMode};
    use crate::Error;

    #[derive(Clone, Debug, Default)]
    struct FakeStats {
        reads: usize,
        writes: usize,
        readable: Vec<Vec<u8>>,
    }

    #[derive(Clone, Debug)]
    struct FakeFrameIo {
        stats: Arc<Mutex<FakeStats>>,
    }

    impl FakeFrameIo {
        fn new(stats: Arc<Mutex<FakeStats>>) -> Self {
            Self { stats }
        }
    }

    impl FrameIo for FakeFrameIo {
        fn read_frames(&mut self, _out: &mut Vec<Vec<u8>>) -> crate::Result<usize> {
            let mut stats = self.stats.lock().expect("fake stats poisoned");
            stats.reads += 1;
            let count = stats.readable.len();
            _out.append(&mut stats.readable);
            Ok(count)
        }

        fn write_frame(&mut self, _frame: &[u8]) -> crate::Result<()> {
            self.stats.lock().expect("fake stats poisoned").writes += 1;
            Ok(())
        }

        fn mtu(&self) -> usize {
            1500
        }

        fn sees_sent_configured(&self) -> Option<bool> {
            Some(true)
        }

        fn filter_configured(&self) -> Option<bool> {
            Some(true)
        }
    }

    #[derive(Clone, Debug)]
    struct FakeFrameIoWithMtu {
        stats: Arc<Mutex<FakeStats>>,
        mtu: usize,
    }

    impl FakeFrameIoWithMtu {
        fn new(stats: Arc<Mutex<FakeStats>>, mtu: usize) -> Self {
            Self { stats, mtu }
        }
    }

    impl FrameIo for FakeFrameIoWithMtu {
        fn read_frames(&mut self, out: &mut Vec<Vec<u8>>) -> crate::Result<usize> {
            FakeFrameIo::new(self.stats.clone()).read_frames(out)
        }

        fn write_frame(&mut self, frame: &[u8]) -> crate::Result<()> {
            FakeFrameIo::new(self.stats.clone()).write_frame(frame)
        }

        fn mtu(&self) -> usize {
            self.mtu
        }

        fn sees_sent_configured(&self) -> Option<bool> {
            Some(true)
        }

        fn filter_configured(&self) -> Option<bool> {
            Some(true)
        }
    }

    #[tokio::test]
    async fn runtime_loop_processes_commands_and_reports_snapshot() {
        let stats = Arc::new(Mutex::new(FakeStats::default()));
        let driver = super::RuntimeDriver::spawn_with_device(
            FakeFrameIo::new(stats.clone()),
            StackConfig {
                local_ip: Ipv4Addr::new(10, 0, 0, 1).into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
        )
        .expect("runtime driver starts");

        let listener = driver.listen(40000).await.expect("listen command succeeds");
        assert_eq!(listener.service_port(), 40000);

        let stream = driver
            .connect(
                PeerAddr {
                    ip: Ipv4Addr::new(10, 0, 0, 2).into(),
                },
                40000,
            )
            .await
            .expect("connect command succeeds");
        assert_eq!(stream.service_port(), 40000);

        let snapshot = driver.snapshot().await.expect("snapshot command succeeds");
        assert_eq!(snapshot.service_ports, vec![40000]);
        assert_eq!(snapshot.mtu, 1500);
        assert_eq!(snapshot.sees_sent_configured, Some(true));
        assert_eq!(snapshot.filter_configured, Some(true));
        assert_eq!(snapshot.listener_count, 1);
        assert_eq!(snapshot.session_count, 1);
        assert!(snapshot.command_count >= 3);

        drop(driver);
        assert!(stats.lock().expect("fake stats poisoned").reads > 0);
    }

    #[tokio::test]
    async fn runtime_shutdown_closes_listener_streams_and_thread() {
        let stats = Arc::new(Mutex::new(FakeStats::default()));
        let driver = super::RuntimeDriver::spawn_with_device(
            FakeFrameIo::new(stats),
            StackConfig {
                local_ip: Ipv4Addr::new(10, 0, 0, 1).into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
        )
        .expect("runtime driver starts");

        let listener = driver.listen(40000).await.expect("listen command succeeds");
        let mut stream = driver
            .connect(
                PeerAddr {
                    ip: Ipv4Addr::new(10, 0, 0, 2).into(),
                },
                40000,
            )
            .await
            .expect("connect command succeeds");

        driver.shutdown_blocking().expect("runtime shuts down");

        let err = listener.accept().await.expect_err("listener is closed");
        assert!(matches!(err, Error::ListenerClosed));

        let mut buf = [0; 1];
        assert_eq!(stream.read(&mut buf).await.expect("read side closes"), 0);
        let err = stream.write_all(b"after shutdown").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
        let err = driver.snapshot().await.unwrap_err();
        assert!(matches!(err, Error::LinkClosed));
    }

    #[tokio::test]
    async fn runtime_stream_write_routes_payload_to_transport_output() {
        let stats = Arc::new(Mutex::new(FakeStats::default()));
        let driver = super::RuntimeDriver::spawn_with_device(
            FakeFrameIo::new(stats.clone()),
            StackConfig {
                local_ip: Ipv4Addr::new(10, 0, 0, 1).into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
        )
        .expect("runtime driver starts");

        let mut stream = driver
            .connect(
                PeerAddr {
                    ip: Ipv4Addr::new(10, 0, 0, 2).into(),
                },
                40000,
            )
            .await
            .expect("connect command succeeds");
        let after_connect = driver.snapshot().await.expect("connect is processed");

        stream.write_all(b"ping").await.expect("write succeeds");
        let snapshot = driver.snapshot().await.expect("write is processed");

        assert_eq!(snapshot.session_count, 1);
        assert_eq!(snapshot.stream_write_count, 1);
        assert!(snapshot.outbound_datagram_count > after_connect.outbound_datagram_count);
    }

    #[tokio::test]
    async fn runtime_kcp_mode_reports_snapshot_and_routes_stream_writes() {
        let stats = Arc::new(Mutex::new(FakeStats::default()));
        let driver = super::RuntimeDriver::spawn_with_device_with_transport(
            FakeFrameIo::new(stats.clone()),
            StackConfig {
                local_ip: Ipv4Addr::new(10, 0, 0, 1).into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
            TransportMode::Kcp,
        )
        .expect("runtime driver starts");

        let mut stream = driver
            .connect(
                PeerAddr {
                    ip: Ipv4Addr::new(10, 0, 0, 2).into(),
                },
                40000,
            )
            .await
            .expect("connect command succeeds");
        let after_connect = driver.snapshot().await.expect("connect is processed");
        assert_eq!(after_connect.transport_mode, "kcp");

        stream
            .write_all(b"ping over kcp")
            .await
            .expect("write succeeds");
        let snapshot = driver.snapshot().await.expect("write is processed");

        assert_eq!(snapshot.stream_write_count, 1);
        assert!(snapshot.outbound_datagram_count > after_connect.outbound_datagram_count);
    }

    #[tokio::test]
    async fn runtime_kcp_shutdown_defers_fin_while_data_is_unacked() {
        let stats = Arc::new(Mutex::new(FakeStats::default()));
        let driver = super::RuntimeDriver::spawn_with_device_with_transport(
            FakeFrameIo::new(stats),
            StackConfig {
                local_ip: Ipv4Addr::new(10, 0, 0, 1).into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
            TransportMode::Kcp,
        )
        .expect("runtime driver starts");
        let mut stream = driver
            .connect(
                PeerAddr {
                    ip: Ipv4Addr::new(10, 0, 0, 2).into(),
                },
                40000,
            )
            .await
            .expect("connect command succeeds");

        stream
            .write_all(b"data before shutdown")
            .await
            .expect("write succeeds");
        let after_write = driver.snapshot().await.expect("write is processed");
        stream.shutdown().await.expect("shutdown succeeds");
        let after_shutdown = driver.snapshot().await.expect("shutdown is processed");

        assert_eq!(after_shutdown.transport_mode, "kcp");
        assert_eq!(after_shutdown.session_count, 1);
        assert_eq!(after_shutdown.closed_session_count, 0);
        assert_eq!(
            after_shutdown.outbound_datagram_count, after_write.outbound_datagram_count,
            "KCP FIN should wait until written data is acknowledged"
        );
    }

    #[tokio::test]
    async fn runtime_segments_stream_writes_to_device_mtu_payload_target() {
        let stats = Arc::new(Mutex::new(FakeStats::default()));
        let driver = super::RuntimeDriver::spawn_with_device(
            FakeFrameIoWithMtu::new(stats, 576),
            StackConfig {
                local_ip: Ipv4Addr::new(10, 0, 0, 1).into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
        )
        .expect("runtime driver starts");

        let mut stream = driver
            .connect(
                PeerAddr {
                    ip: Ipv4Addr::new(10, 0, 0, 2).into(),
                },
                40000,
            )
            .await
            .expect("connect command succeeds");
        let after_connect = driver.snapshot().await.expect("connect is processed");

        stream
            .write_all(&vec![0x5a; 1000])
            .await
            .expect("write succeeds");
        let snapshot = driver.snapshot().await.expect("write is processed");

        assert_eq!(
            snapshot.outbound_datagram_count - after_connect.outbound_datagram_count,
            2
        );
    }

    #[tokio::test]
    async fn runtime_uses_ipv6_payload_target_for_ipv6_local_ip() {
        let stats = Arc::new(Mutex::new(FakeStats::default()));
        let driver = super::RuntimeDriver::spawn_with_device(
            FakeFrameIoWithMtu::new(stats, 576),
            StackConfig {
                local_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                local_prefix_len: 128,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
        )
        .expect("runtime driver starts");

        let snapshot = driver.snapshot().await.expect("snapshot succeeds");

        assert_eq!(snapshot.payload_target, 528);
    }

    #[tokio::test]
    async fn runtime_rejects_peer_address_family_mismatch() {
        let stats = Arc::new(Mutex::new(FakeStats::default()));
        let driver = super::RuntimeDriver::spawn_with_device(
            FakeFrameIo::new(stats),
            StackConfig {
                local_ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
                local_prefix_len: 128,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
        )
        .expect("runtime driver starts");

        let result = driver
            .connect(
                PeerAddr {
                    ip: Ipv4Addr::new(10, 0, 0, 2).into(),
                },
                40000,
            )
            .await;

        assert!(matches!(result, Err(crate::Error::Config(_))));
    }

    #[tokio::test]
    async fn runtime_loop_retransmits_unacked_stream_data() {
        let stats = Arc::new(Mutex::new(FakeStats::default()));
        let driver = super::RuntimeDriver::spawn_with_device(
            FakeFrameIo::new(stats),
            StackConfig {
                local_ip: Ipv4Addr::new(10, 0, 0, 1).into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
        )
        .expect("runtime driver starts");

        let mut stream = driver
            .connect(
                PeerAddr {
                    ip: Ipv4Addr::new(10, 0, 0, 2).into(),
                },
                40000,
            )
            .await
            .expect("connect command succeeds");
        stream.write_all(b"ping").await.expect("write succeeds");
        let after_write = driver.snapshot().await.expect("write is processed");

        tokio::time::sleep(Duration::from_millis(320)).await;
        let snapshot = driver.snapshot().await.expect("snapshot succeeds");

        assert!(
            snapshot.outbound_datagram_count > after_write.outbound_datagram_count,
            "expected runtime loop to retransmit unacked stream data"
        );
    }

    #[tokio::test]
    async fn runtime_dispatches_inbound_connect_and_stream_data_to_listener() {
        let local_ip = Ipv4Addr::new(10, 0, 0, 1);
        let peer_ip = Ipv4Addr::new(10, 0, 0, 2);
        let service_port = 40000;
        let connection_id = 0x1020_3040_5060_7080;
        let stats = Arc::new(Mutex::new(FakeStats {
            readable: vec![
                udp_frame(
                    peer_ip,
                    local_ip,
                    50000,
                    service_port,
                    bpflink_datagram(PacketType::Connect, service_port, connection_id, 0, b""),
                ),
                udp_frame(
                    peer_ip,
                    local_ip,
                    50000,
                    service_port,
                    bpflink_datagram(PacketType::Data, service_port, connection_id, 0, b"inbound"),
                ),
            ],
            ..FakeStats::default()
        }));
        let driver = super::RuntimeDriver::spawn_with_device(
            FakeFrameIo::new(stats),
            StackConfig {
                local_ip: local_ip.into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![service_port],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
        )
        .expect("runtime driver starts");
        let listener = driver.listen(service_port).await.expect("listen succeeds");

        let mut accepted = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("accept wakes")
            .expect("accepted stream");
        let mut buf = [0; 7];
        tokio::time::timeout(Duration::from_secs(1), accepted.read_exact(&mut buf))
            .await
            .expect("read wakes")
            .expect("read succeeds");

        assert_eq!(&buf, b"inbound");
        let snapshot = driver.snapshot().await.expect("snapshot succeeds");
        assert_eq!(snapshot.inbound_accept_count, 1);
        assert_eq!(snapshot.inbound_data_count, 1);
    }

    #[tokio::test]
    async fn runtime_dispatches_inbound_connect_on_any_configured_service_port() {
        let local_ip = Ipv4Addr::new(10, 0, 0, 1);
        let peer_ip = Ipv4Addr::new(10, 0, 0, 2);
        let service_port = 40001;
        let connection_id = 0x1122_3040_5060_7080;
        let stats = Arc::new(Mutex::new(FakeStats {
            readable: vec![udp_frame(
                peer_ip,
                local_ip,
                50000,
                service_port,
                bpflink_datagram(PacketType::Connect, service_port, connection_id, 0, b""),
            )],
            ..FakeStats::default()
        }));
        let driver = super::RuntimeDriver::spawn_with_device(
            FakeFrameIo::new(stats),
            StackConfig {
                local_ip: local_ip.into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000, service_port],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
        )
        .expect("runtime driver starts");
        let listener = driver.listen(service_port).await.expect("listen succeeds");

        let accepted = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("accept wakes")
            .expect("accepted stream");

        assert_eq!(accepted.service_port(), service_port);
        let snapshot = driver.snapshot().await.expect("snapshot succeeds");
        assert_eq!(snapshot.service_ports, vec![40000, service_port]);
        assert_eq!(snapshot.inbound_accept_count, 1);
    }

    #[tokio::test]
    async fn runtime_routes_same_connection_id_by_peer_endpoint() {
        let local_ip = Ipv4Addr::new(10, 0, 0, 1);
        let peer_ip = Ipv4Addr::new(10, 0, 0, 2);
        let service_port = 40000;
        let connection_id = 0x1020_3040_5060_7080;
        let stats = Arc::new(Mutex::new(FakeStats {
            readable: vec![
                udp_frame(
                    peer_ip,
                    local_ip,
                    50000,
                    service_port,
                    bpflink_datagram(PacketType::Connect, service_port, connection_id, 0, b""),
                ),
                udp_frame(
                    peer_ip,
                    local_ip,
                    50001,
                    service_port,
                    bpflink_datagram(PacketType::Connect, service_port, connection_id, 0, b""),
                ),
                udp_frame(
                    peer_ip,
                    local_ip,
                    50001,
                    service_port,
                    bpflink_datagram(PacketType::Data, service_port, connection_id, 0, b"two"),
                ),
                udp_frame(
                    peer_ip,
                    local_ip,
                    50000,
                    service_port,
                    bpflink_datagram(PacketType::Data, service_port, connection_id, 0, b"one"),
                ),
            ],
            ..FakeStats::default()
        }));
        let driver = super::RuntimeDriver::spawn_with_device(
            FakeFrameIo::new(stats),
            StackConfig {
                local_ip: local_ip.into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![service_port],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
        )
        .expect("runtime driver starts");
        let listener = driver.listen(service_port).await.expect("listen succeeds");

        let mut first = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("first accept wakes")
            .expect("first stream");
        let mut second = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("second accept wakes")
            .expect("second stream");
        let mut first_buf = [0; 3];
        let mut second_buf = [0; 3];
        tokio::time::timeout(Duration::from_secs(1), second.read_exact(&mut second_buf))
            .await
            .expect("second read wakes")
            .expect("second read succeeds");
        tokio::time::timeout(Duration::from_secs(1), first.read_exact(&mut first_buf))
            .await
            .expect("first read wakes")
            .expect("first read succeeds");

        assert_eq!(&first_buf, b"one");
        assert_eq!(&second_buf, b"two");
        let snapshot = driver.snapshot().await.expect("snapshot succeeds");
        assert_eq!(snapshot.inbound_accept_count, 2);
        assert_eq!(snapshot.inbound_data_count, 2);
    }

    #[tokio::test]
    async fn runtime_kcp_dispatches_inbound_connect_and_stream_data_to_listener() {
        let local_ip = Ipv4Addr::new(10, 0, 0, 1);
        let peer_ip = Ipv4Addr::new(10, 0, 0, 2);
        let service_port = 40000;
        let now = Instant::now();
        let mut peer_engine = KcpTransportEngine::connect(
            PeerAddr { ip: peer_ip.into() },
            service_port,
            now,
            payload_target_for_ipv4_mtu(1500),
        );
        let mut datagrams = Vec::new();
        peer_engine
            .poll_output(now, &mut datagrams)
            .expect("connect datagram is produced");
        peer_engine
            .write(b"inbound kcp")
            .expect("peer write succeeds");
        peer_engine
            .poll_output(now, &mut datagrams)
            .expect("data datagram is produced");
        assert!(
            datagrams.len() >= 2,
            "expected connect and at least one kcp data datagram"
        );

        let readable = datagrams
            .into_iter()
            .map(|datagram| udp_frame(peer_ip, local_ip, 50000, service_port, datagram))
            .collect();
        let stats = Arc::new(Mutex::new(FakeStats {
            readable,
            ..FakeStats::default()
        }));
        let driver = super::RuntimeDriver::spawn_with_device_with_transport(
            FakeFrameIo::new(stats),
            StackConfig {
                local_ip: local_ip.into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![service_port],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
            TransportMode::Kcp,
        )
        .expect("runtime driver starts");
        let listener = driver.listen(service_port).await.expect("listen succeeds");

        let mut accepted = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("accept wakes")
            .expect("accepted stream");
        let mut buf = [0; 11];
        tokio::time::timeout(Duration::from_secs(1), accepted.read_exact(&mut buf))
            .await
            .expect("read wakes")
            .expect("read succeeds");

        assert_eq!(&buf, b"inbound kcp");
        let snapshot = driver.snapshot().await.expect("snapshot succeeds");
        assert_eq!(snapshot.transport_mode, "kcp");
        assert_eq!(snapshot.inbound_accept_count, 1);
        assert_eq!(snapshot.inbound_data_count, 1);
    }

    #[tokio::test]
    async fn runtime_kcp_routes_multiple_inbound_streams_independently() {
        let local_ip = Ipv4Addr::new(10, 0, 0, 1);
        let peer_ip = Ipv4Addr::new(10, 0, 0, 2);
        let service_port = 40000;
        let readable = [
            kcp_peer_datagrams(peer_ip, service_port, b"one"),
            kcp_peer_datagrams(peer_ip, service_port, b"two"),
        ]
        .into_iter()
        .enumerate()
        .flat_map(|(index, datagrams)| {
            datagrams.into_iter().map(move |datagram| {
                udp_frame(
                    peer_ip,
                    local_ip,
                    50000 + index as u16,
                    service_port,
                    datagram,
                )
            })
        })
        .collect();
        let stats = Arc::new(Mutex::new(FakeStats {
            readable,
            ..FakeStats::default()
        }));
        let driver = super::RuntimeDriver::spawn_with_device_with_transport(
            FakeFrameIo::new(stats),
            StackConfig {
                local_ip: local_ip.into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![service_port],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
            TransportMode::Kcp,
        )
        .expect("runtime driver starts");
        let listener = driver.listen(service_port).await.expect("listen succeeds");

        let mut first = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("first accept wakes")
            .expect("first stream");
        let mut second = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("second accept wakes")
            .expect("second stream");
        let mut first_buf = [0; 3];
        let mut second_buf = [0; 3];
        tokio::time::timeout(Duration::from_secs(1), first.read_exact(&mut first_buf))
            .await
            .expect("first read wakes")
            .expect("first read");
        tokio::time::timeout(Duration::from_secs(1), second.read_exact(&mut second_buf))
            .await
            .expect("second read wakes")
            .expect("second read");

        assert_eq!(&first_buf, b"one");
        assert_eq!(&second_buf, b"two");
        let snapshot = driver.snapshot().await.expect("snapshot succeeds");
        assert_eq!(snapshot.inbound_accept_count, 2);
        assert_eq!(snapshot.inbound_data_count, 2);
    }

    #[tokio::test]
    async fn runtime_stream_shutdown_sends_fin_and_keeps_session_for_retransmit() {
        let stats = Arc::new(Mutex::new(FakeStats::default()));
        let driver = super::RuntimeDriver::spawn_with_device(
            FakeFrameIo::new(stats),
            StackConfig {
                local_ip: Ipv4Addr::new(10, 0, 0, 1).into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
        )
        .expect("runtime driver starts");
        let mut stream = driver
            .connect(
                PeerAddr {
                    ip: Ipv4Addr::new(10, 0, 0, 2).into(),
                },
                40000,
            )
            .await
            .expect("connect command succeeds");
        let after_connect = driver.snapshot().await.expect("connect is processed");

        stream.shutdown().await.expect("shutdown succeeds");
        let snapshot = driver.snapshot().await.expect("shutdown is processed");

        assert_eq!(snapshot.session_count, 1);
        assert_eq!(snapshot.closed_session_count, 0);
        assert!(snapshot.outbound_datagram_count > after_connect.outbound_datagram_count);
    }

    #[tokio::test]
    async fn runtime_stream_abort_sends_reset_and_removes_session() {
        let stats = Arc::new(Mutex::new(FakeStats::default()));
        let driver = super::RuntimeDriver::spawn_with_device(
            FakeFrameIo::new(stats),
            StackConfig {
                local_ip: Ipv4Addr::new(10, 0, 0, 1).into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
        )
        .expect("runtime driver starts");
        let stream = driver
            .connect(
                PeerAddr {
                    ip: Ipv4Addr::new(10, 0, 0, 2).into(),
                },
                40000,
            )
            .await
            .expect("connect command succeeds");
        let after_connect = driver.snapshot().await.expect("connect is processed");

        stream.abort().await.expect("abort succeeds");
        let snapshot = driver.snapshot().await.expect("abort is processed");

        assert_eq!(snapshot.session_count, 0);
        assert_eq!(snapshot.closed_session_count, 1);
        assert!(snapshot.outbound_datagram_count > after_connect.outbound_datagram_count);
    }

    #[tokio::test]
    async fn runtime_closes_read_side_when_fin_arrives() {
        let local_ip = Ipv4Addr::new(10, 0, 0, 1);
        let peer_ip = Ipv4Addr::new(10, 0, 0, 2);
        let service_port = 40000;
        let connection_id = 0x2020_3040_5060_7080;
        let stats = Arc::new(Mutex::new(FakeStats {
            readable: vec![
                udp_frame(
                    peer_ip,
                    local_ip,
                    50000,
                    service_port,
                    bpflink_datagram(PacketType::Connect, service_port, connection_id, 0, b""),
                ),
                udp_frame(
                    peer_ip,
                    local_ip,
                    50000,
                    service_port,
                    bpflink_datagram(PacketType::Fin, service_port, connection_id, 0, b""),
                ),
            ],
            ..FakeStats::default()
        }));
        let driver = super::RuntimeDriver::spawn_with_device(
            FakeFrameIo::new(stats),
            StackConfig {
                local_ip: local_ip.into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![service_port],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
        )
        .expect("runtime driver starts");
        let listener = driver.listen(service_port).await.expect("listen succeeds");

        let mut accepted = tokio::time::timeout(Duration::from_secs(1), listener.accept())
            .await
            .expect("accept wakes")
            .expect("accepted stream");
        let mut buf = [0; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), accepted.read(&mut buf))
            .await
            .expect("read completes")
            .expect("read succeeds");
        let snapshot = driver.snapshot().await.expect("snapshot succeeds");

        assert_eq!(read, 0);
        assert_eq!(snapshot.session_count, 0);
        assert_eq!(snapshot.closed_session_count, 1);
    }

    #[tokio::test]
    async fn runtime_removes_idle_sessions() {
        let stats = Arc::new(Mutex::new(FakeStats::default()));
        let stack = StackDriver::new(
            StackConfig {
                local_ip: Ipv4Addr::new(10, 0, 0, 1).into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
            FakeFrameIo::new(stats),
        )
        .expect("stack driver starts");
        let (sender, _receiver) = std::sync::mpsc::channel();
        let mut state = super::DriverState::new(
            stack,
            super::DriverStateConfig {
                service_ports: vec![40000],
                mtu: 1500,
                payload_target: payload_target_for_ipv4_mtu(1500),
                sees_sent_configured: Some(true),
                filter_configured: Some(true),
                transport_mode: crate::transport::TransportMode::Simple,
            },
            sender,
        );
        let now = Instant::now();
        state
            .connect(
                PeerAddr {
                    ip: Ipv4Addr::new(10, 0, 0, 2).into(),
                },
                40000,
                now,
            )
            .expect("connect succeeds");

        state.expire_idle_sessions(now + Duration::from_secs(31));

        let snapshot = state.snapshot();
        assert_eq!(snapshot.session_count, 0);
        assert_eq!(snapshot.idle_timeout_count, 1);
        assert_eq!(snapshot.closed_session_count, 1);
    }

    #[tokio::test]
    async fn runtime_close_keeps_unacked_data_retransmitting_until_peer_fin_or_idle() {
        let stats = Arc::new(Mutex::new(FakeStats::default()));
        let stack = StackDriver::new(
            StackConfig {
                local_ip: Ipv4Addr::new(10, 0, 0, 1).into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
            FakeFrameIo::new(stats),
        )
        .expect("stack driver starts");
        let (sender, _receiver) = std::sync::mpsc::channel();
        let mut state = super::DriverState::new(
            stack,
            super::DriverStateConfig {
                service_ports: vec![40000],
                mtu: 1500,
                payload_target: payload_target_for_ipv4_mtu(1500),
                sees_sent_configured: Some(true),
                filter_configured: Some(true),
                transport_mode: crate::transport::TransportMode::Simple,
            },
            sender,
        );
        let now = Instant::now();
        let stream = state
            .connect(
                PeerAddr {
                    ip: Ipv4Addr::new(10, 0, 0, 2).into(),
                },
                40000,
                now,
            )
            .expect("connect succeeds");

        state
            .stream_write(stream.session_id, b"needs retransmit", now)
            .expect("write succeeds");
        state.close(stream.session_id);
        let after_close = state.snapshot();

        state
            .poll_session_outputs(now + Duration::from_millis(320))
            .expect("retransmit poll succeeds");
        let after_retransmit = state.snapshot();

        assert_eq!(after_close.session_count, 1);
        assert_eq!(after_close.closed_session_count, 0);
        assert!(after_retransmit.outbound_datagram_count > after_close.outbound_datagram_count);
    }

    #[tokio::test]
    async fn runtime_write_backpressure_is_reported_to_stream() {
        let stats = Arc::new(Mutex::new(FakeStats::default()));
        let driver = super::RuntimeDriver::spawn_with_device(
            FakeFrameIo::new(stats),
            StackConfig {
                local_ip: Ipv4Addr::new(10, 0, 0, 1).into(),
                local_prefix_len: 24,
                default_gateway: None,
                service_ports: vec![40000],
                ethernet_addr: EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            },
        )
        .expect("runtime driver starts");
        let mut stream = driver
            .connect(
                PeerAddr {
                    ip: Ipv4Addr::new(10, 0, 0, 2).into(),
                },
                40000,
            )
            .await
            .expect("connect command succeeds");

        let result = stream.write_all(&vec![0x5a; 2 * 1024 * 1024]).await;
        let snapshot = driver.snapshot().await.expect("snapshot succeeds");

        assert!(result.is_err());
        assert_eq!(snapshot.backpressure_count, 1);
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

    fn kcp_peer_datagrams(peer_ip: Ipv4Addr, service_port: u16, payload: &[u8]) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let mut engine = KcpTransportEngine::connect(
            PeerAddr { ip: peer_ip.into() },
            service_port,
            now,
            payload_target_for_ipv4_mtu(1500),
        );
        let mut datagrams = Vec::new();
        engine
            .poll_output(now, &mut datagrams)
            .expect("connect datagram is produced");
        engine.write(payload).expect("kcp write succeeds");
        engine
            .poll_output(now, &mut datagrams)
            .expect("data datagram is produced");
        datagrams
    }

    fn udp_frame(
        src: Ipv4Addr,
        dst: Ipv4Addr,
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

    fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp_packet: &[u8]) -> u16 {
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
