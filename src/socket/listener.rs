use std::collections::VecDeque;
use std::future::poll_fn;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use crate::socket::BpfStream;
use crate::{Error, Result};

/// A listener for inbound bpflink streams on one configured service port.
///
/// `BpfListener` accepts [`BpfStream`] handles from the owning [`crate::Link`].
/// It listens at bpflink's UDP-backed transport layer; it is not an OS TCP
/// listener and does not bind a kernel TCP socket.
#[derive(Clone, Debug)]
pub struct BpfListener {
    service_port: u16,
    inner: Arc<Mutex<ListenerInner>>,
}

impl BpfListener {
    pub(crate) fn new(service_port: u16) -> Self {
        Self {
            service_port,
            inner: Arc::new(Mutex::new(ListenerInner::default())),
        }
    }

    pub fn service_port(&self) -> u16 {
        self.service_port
    }

    pub async fn accept(&self) -> Result<BpfStream> {
        poll_fn(|cx| {
            let mut inner = self.inner.lock().expect("listener poisoned");
            if let Some(stream) = inner.pending.pop_front() {
                return Poll::Ready(Ok(stream));
            }
            if inner.closed {
                return Poll::Ready(Err(Error::ListenerClosed));
            }
            inner.accept_waker = Some(cx.waker().clone());
            Poll::Pending
        })
        .await
    }

    /// Accepts one pending stream or returns [`Error::Timeout`] when no stream
    /// arrives before `timeout`.
    pub async fn accept_timeout(&self, timeout: Duration) -> Result<BpfStream> {
        tokio::time::timeout(timeout, self.accept())
            .await
            .map_err(|_| Error::Timeout)?
    }

    pub(crate) fn push_pending(&self, stream: BpfStream) -> Result<()> {
        let mut inner = self.inner.lock().expect("listener poisoned");
        if inner.closed {
            return Err(Error::ListenerClosed);
        }
        inner.pending.push_back(stream);
        if let Some(waker) = inner.accept_waker.take() {
            waker.wake();
        }
        Ok(())
    }

    /// Closes this listener handle and wakes pending `accept` calls.
    ///
    /// Closing a listener does not close the owning [`crate::Link`] or its
    /// packet backend. A later `Link::listen` call may listen on the same
    /// configured service port again.
    pub fn close(&self) {
        let mut inner = self.inner.lock().expect("listener poisoned");
        inner.closed = true;
        inner.pending.clear();
        if let Some(waker) = inner.accept_waker.take() {
            waker.wake();
        }
    }
}

#[derive(Debug, Default)]
struct ListenerInner {
    pending: VecDeque<BpfStream>,
    accept_waker: Option<std::task::Waker>,
    closed: bool,
}
