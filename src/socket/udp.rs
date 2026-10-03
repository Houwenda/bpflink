use std::collections::VecDeque;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use crate::link::PeerAddr;
use crate::runtime::RuntimeUdpHandle;
use crate::{Error, Result};

#[cfg(feature = "test-util")]
use crate::runtime::TestCommand;

/// A UDP datagram received by [`BpfUdpSocket`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BpfUdpPacket {
    pub source: SocketAddr,
    pub payload: Vec<u8>,
}

/// A raw UDP datagram socket backed by the owning [`crate::Link`] runtime.
///
/// `BpfUdpSocket` sends and receives ordinary UDP payloads on one configured
/// service port. It reuses the `Link` packet backend and does not open an OS
/// UDP socket.
#[derive(Clone, Debug)]
pub struct BpfUdpSocket {
    service_port: u16,
    runtime_handle: Option<RuntimeUdpHandle>,
    inner: UdpDeliveryHandle,
    #[cfg(feature = "test-util")]
    test_commands: Option<Arc<Mutex<Vec<TestCommand>>>>,
}

#[derive(Clone, Debug)]
pub(crate) struct UdpDeliveryHandle {
    inner: Arc<Mutex<UdpInner>>,
}

impl UdpDeliveryHandle {
    pub(crate) fn push_packet(&self, packet: BpfUdpPacket) {
        let mut inner = self.inner.lock().expect("udp socket poisoned");
        if inner.closed {
            return;
        }
        inner.pending.push_back(packet);
        if let Some(waker) = inner.recv_waker.take() {
            waker.wake();
        }
    }

    pub(crate) fn close(&self) {
        let mut inner = self.inner.lock().expect("udp socket poisoned");
        inner.closed = true;
        if let Some(waker) = inner.recv_waker.take() {
            waker.wake();
        }
    }
}

impl BpfUdpSocket {
    pub(crate) fn new_runtime(
        service_port: u16,
        runtime_handle: RuntimeUdpHandle,
    ) -> (Self, UdpDeliveryHandle) {
        let delivery = UdpDeliveryHandle {
            inner: Arc::new(Mutex::new(UdpInner::default())),
        };
        (
            Self {
                service_port,
                runtime_handle: Some(runtime_handle),
                inner: delivery.clone(),
                #[cfg(feature = "test-util")]
                test_commands: None,
            },
            delivery,
        )
    }

    #[cfg(feature = "test-util")]
    pub(crate) fn new_for_test(
        service_port: u16,
        commands: Arc<Mutex<Vec<TestCommand>>>,
    ) -> (Self, UdpDeliveryHandle) {
        let delivery = UdpDeliveryHandle {
            inner: Arc::new(Mutex::new(UdpInner::default())),
        };
        (
            Self {
                service_port,
                runtime_handle: None,
                inner: delivery.clone(),
                test_commands: Some(commands),
            },
            delivery,
        )
    }

    pub fn service_port(&self) -> u16 {
        self.service_port
    }

    pub async fn send_to(&self, payload: &[u8], peer: PeerAddr, peer_port: u16) -> Result<()> {
        #[cfg(feature = "test-util")]
        self.record(TestCommand::UdpSend {
            service_port: self.service_port,
            peer,
            peer_port,
            len: payload.len(),
        });

        if let Some(handle) = &self.runtime_handle {
            return handle
                .send_to(self.service_port, peer, peer_port, payload)
                .await;
        }
        Ok(())
    }

    pub async fn recv_from(&self) -> Result<BpfUdpPacket> {
        poll_fn(|cx| {
            let mut inner = self.inner.inner.lock().expect("udp socket poisoned");
            if let Some(packet) = inner.pending.pop_front() {
                return Poll::Ready(Ok(packet));
            }
            if inner.closed {
                return Poll::Ready(Err(Error::LinkClosed));
            }
            inner.recv_waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    pub async fn recv_from_timeout(&self, timeout: Duration) -> Result<BpfUdpPacket> {
        tokio::time::timeout(timeout, self.recv_from())
            .await
            .map_err(|_| Error::Timeout)?
    }

    pub fn close(&self) {
        self.inner.close();
    }

    #[cfg(feature = "test-util")]
    fn record(&self, command: TestCommand) {
        if let Some(commands) = &self.test_commands {
            commands
                .lock()
                .expect("test command log poisoned")
                .push(command);
        }
    }
}

#[derive(Debug, Default)]
struct UdpInner {
    pending: VecDeque<BpfUdpPacket>,
    recv_waker: Option<std::task::Waker>,
    closed: bool,
}
