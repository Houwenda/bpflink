use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::link::PeerAddr;
use crate::runtime::RuntimeStreamHandle;
use crate::Result;

#[cfg(feature = "test-util")]
use crate::runtime::TestCommand;

/// A bpflink async byte stream.
///
/// `BpfStream` implements [`AsyncRead`] and [`AsyncWrite`] with TCP-like stream
/// semantics at the Rust API boundary, but it is not an OS TCP socket and does
/// not send TCP segments on the wire. bpflink stream data is carried in UDP
/// packets owned by the enclosing [`crate::Link`] runtime.
#[derive(Debug)]
pub struct BpfStream {
    session_id: u64,
    service_port: u16,
    peer: Option<PeerAddr>,
    runtime_handle: Option<RuntimeStreamHandle>,
    read_side: Arc<Mutex<Pipe>>,
    write_side: Arc<Mutex<Pipe>>,
    #[cfg(feature = "test-util")]
    test_commands: Option<Arc<Mutex<Vec<TestCommand>>>>,
}

#[derive(Clone, Debug)]
pub(crate) struct StreamReadHandle {
    read_side: Arc<Mutex<Pipe>>,
}

impl StreamReadHandle {
    pub(crate) fn push_bytes(&self, bytes: &[u8]) {
        let mut pipe = self.read_side.lock().expect("stream pipe poisoned");
        pipe.buffer.extend(bytes.iter().copied());
        if let Some(waker) = pipe.read_waker.take() {
            waker.wake();
        }
    }

    pub(crate) fn close(&self) {
        let mut pipe = self.read_side.lock().expect("stream pipe poisoned");
        pipe.closed = true;
        if let Some(waker) = pipe.read_waker.take() {
            waker.wake();
        }
    }
}

impl BpfStream {
    pub(crate) fn new_runtime(
        session_id: u64,
        service_port: u16,
        peer: PeerAddr,
        runtime_handle: RuntimeStreamHandle,
    ) -> (Self, StreamReadHandle) {
        let read_side = Arc::new(Mutex::new(Pipe::default()));
        let write_side = Arc::new(Mutex::new(Pipe::default()));
        let stream = Self {
            session_id,
            service_port,
            peer: Some(peer),
            runtime_handle: Some(runtime_handle),
            read_side: read_side.clone(),
            write_side,
            #[cfg(feature = "test-util")]
            test_commands: None,
        };
        (stream, StreamReadHandle { read_side })
    }

    #[cfg(feature = "test-util")]
    fn pair(
        client_session_id: u64,
        server_session_id: u64,
        service_port: u16,
        peer: PeerAddr,
    ) -> (Self, Self) {
        let client_read = Arc::new(Mutex::new(Pipe::default()));
        let server_read = Arc::new(Mutex::new(Pipe::default()));
        (
            Self {
                session_id: client_session_id,
                service_port,
                peer: Some(peer),
                runtime_handle: None,
                read_side: client_read.clone(),
                write_side: server_read.clone(),
                #[cfg(feature = "test-util")]
                test_commands: None,
            },
            Self {
                session_id: server_session_id,
                service_port,
                peer: Some(peer),
                runtime_handle: None,
                read_side: server_read,
                write_side: client_read,
                #[cfg(feature = "test-util")]
                test_commands: None,
            },
        )
    }

    #[cfg(feature = "test-util")]
    pub(crate) fn pair_with_test_commands(
        client_session_id: u64,
        server_session_id: u64,
        service_port: u16,
        peer: PeerAddr,
        commands: Arc<Mutex<Vec<TestCommand>>>,
    ) -> (Self, Self) {
        let (mut client, mut server) =
            Self::pair(client_session_id, server_session_id, service_port, peer);
        client.test_commands = Some(commands.clone());
        server.test_commands = Some(commands);
        (client, server)
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn service_port(&self) -> u16 {
        self.service_port
    }

    pub fn peer_addr(&self) -> Option<PeerAddr> {
        self.peer
    }

    /// Aborts this stream immediately.
    ///
    /// Unlike `AsyncWrite::poll_shutdown`, abort does not try to gracefully
    /// drain pending stream data. Runtime-backed streams send a reset packet and
    /// remove the local session; test streams close their in-memory pipes.
    pub async fn abort(mut self) -> Result<()> {
        #[cfg(feature = "test-util")]
        self.record(TestCommand::Abort {
            session_id: self.session_id,
        });

        if let Some(handle) = self.runtime_handle.take() {
            handle.abort(self.session_id).await?;
        } else {
            if let Ok(mut pipe) = self.read_side.lock() {
                pipe.closed = true;
                if let Some(waker) = pipe.read_waker.take() {
                    waker.wake();
                }
            }
            if let Ok(mut pipe) = self.write_side.lock() {
                pipe.closed = true;
                if let Some(waker) = pipe.read_waker.take() {
                    waker.wake();
                }
            }
        }
        Ok(())
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

    #[cfg(feature = "test-util")]
    pub(crate) fn pipe_handles_for_test(&self) -> (StreamReadHandle, StreamReadHandle) {
        (
            StreamReadHandle {
                read_side: self.read_side.clone(),
            },
            StreamReadHandle {
                read_side: self.write_side.clone(),
            },
        )
    }
}

impl AsyncRead for BpfStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        #[cfg(feature = "test-util")]
        self.record(TestCommand::StreamReadPoll {
            session_id: self.session_id,
        });

        {
            let mut pipe = self.read_side.lock().expect("stream pipe poisoned");
            if pipe.buffer.is_empty() {
                if pipe.closed {
                    return Poll::Ready(Ok(()));
                }
                pipe.read_waker = Some(cx.waker().clone());
            } else {
                while buf.remaining() > 0 {
                    let Some(byte) = pipe.buffer.pop_front() else {
                        break;
                    };
                    buf.put_slice(&[byte]);
                }
                return Poll::Ready(Ok(()));
            }
        }

        if let Some(handle) = &self.runtime_handle {
            if let Err(err) = handle.read_poll(self.session_id) {
                let pipe = self.read_side.lock().expect("stream pipe poisoned");
                if pipe.closed {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(err));
            }
        }

        Poll::Pending
    }
}

impl AsyncWrite for BpfStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        #[cfg(feature = "test-util")]
        self.record(TestCommand::StreamWrite {
            session_id: self.session_id,
            len: bytes.len(),
        });

        if let Some(handle) = &self.runtime_handle {
            handle.write(self.session_id, bytes)?;
            return Poll::Ready(Ok(bytes.len()));
        }

        let mut pipe = self.write_side.lock().expect("stream pipe poisoned");
        if pipe.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                crate::Error::StreamClosed,
            )));
        }
        pipe.buffer.extend(bytes.iter().copied());
        if let Some(waker) = pipe.read_waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        #[cfg(feature = "test-util")]
        self.record(TestCommand::Close {
            session_id: self.session_id,
        });

        if let Some(handle) = &self.runtime_handle {
            handle.close(self.session_id);
            return Poll::Ready(Ok(()));
        }

        let mut pipe = self.write_side.lock().expect("stream pipe poisoned");
        pipe.closed = true;
        if let Some(waker) = pipe.read_waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for BpfStream {
    fn drop(&mut self) {
        #[cfg(feature = "test-util")]
        self.record(TestCommand::Close {
            session_id: self.session_id,
        });

        if let Some(handle) = &self.runtime_handle {
            handle.close(self.session_id);
            return;
        }

        if let Ok(mut pipe) = self.write_side.lock() {
            pipe.closed = true;
            if let Some(waker) = pipe.read_waker.take() {
                waker.wake();
            }
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Pipe {
    buffer: VecDeque<u8>,
    read_waker: Option<Waker>,
    closed: bool,
}
