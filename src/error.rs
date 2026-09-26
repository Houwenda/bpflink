use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{operation}: {source}")]
    IoContext {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("packet parse error: {0}")]
    PacketParse(&'static str),
    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(&'static str),
    #[error("payload too large: {len} > {max}")]
    PayloadTooLarge { len: usize, max: usize },
    #[error("transport backpressure; retry the write later")]
    Backpressure,
    #[error("link is closed")]
    LinkClosed,
    #[error("listener is closed")]
    ListenerClosed,
    #[error("stream is closed")]
    StreamClosed,
    #[error("session was not found")]
    SessionNotFound,
    #[error("service port is not configured: requested {requested}")]
    ServicePortNotConfigured { requested: u16 },
    #[error("connection is closed")]
    ConnectionClosed,
    #[error("runtime driver or session is closed")]
    DriverClosed,
    #[error("operation timed out")]
    Timeout,
}

#[cfg(test)]
mod tests {
    #[test]
    fn io_context_display_includes_operation() {
        let err = super::Error::IoContext {
            operation: "BIOCSETIF",
            source: std::io::Error::from_raw_os_error(libc::EINVAL),
        };

        assert!(err.to_string().contains("BIOCSETIF"));
    }

    #[test]
    fn driver_closed_display_mentions_session_or_runtime() {
        let message = super::Error::DriverClosed.to_string();

        assert!(message.contains("runtime"));
        assert!(message.contains("session"));
    }
}
