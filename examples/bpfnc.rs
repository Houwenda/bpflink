use std::env;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::time::Duration;

use bpflink::{parse_scoped_ip, Error, Link, PeerAddr, Result, TransportMode};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Listen { linger_ms: u64 },
    Connect { peer_ip: IpAddr, linger_ms: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Config {
    mode: Mode,
    direction: Direction,
    interface: String,
    local_ip: IpAddr,
    service_port: u16,
    transport_mode: TransportMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    FullDuplex,
    SendOnly,
    RecvOnly,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config = Config::parse_from(env::args()).map_err(Error::Config)?;
    run(config).await
}

async fn run(config: Config) -> Result<()> {
    eprintln!(
        "bpfnc: mode={} direction={} interface={} local_ip={} service_port={} transport={}",
        config.mode_name(),
        config.direction_name(),
        config.interface,
        config.local_ip,
        config.service_port,
        config.transport_name()
    );

    let link = Link::builder()
        .interface(config.interface.clone())
        .local_ip(config.local_ip)
        .service_ports([config.service_port])
        .transport_mode(config.transport_mode)
        .build()
        .await?;

    match config.mode {
        Mode::Listen { linger_ms } => {
            let listener = link.listen(config.service_port).await?;
            eprintln!("bpfnc: listening");
            let stream = listener.accept().await?;
            eprintln!("bpfnc: accepted");
            pump_stdio(stream, config.direction).await?;
            if linger_ms > 0 {
                tokio::time::sleep(Duration::from_millis(linger_ms)).await;
            }
        }
        Mode::Connect { peer_ip, linger_ms } => {
            eprintln!("bpfnc: connecting peer_ip={peer_ip}");
            let stream = link
                .connect(PeerAddr { ip: peer_ip }, config.service_port)
                .await?;
            eprintln!("bpfnc: connected");
            pump_stdio(stream, config.direction).await?;
            if linger_ms > 0 {
                tokio::time::sleep(Duration::from_millis(linger_ms)).await;
            }
        }
    }

    eprintln!("bpfnc: shutdown");
    Ok(())
}

async fn pump_stdio(stream: bpflink::BpfStream, direction: Direction) -> Result<()> {
    let (mut stream_reader, mut stream_writer) = tokio::io::split(stream);
    let mut stdin = io::stdin();
    let mut stdout = io::stdout();

    match direction {
        Direction::SendOnly => {
            let sent = copy_to_stream_with_retry(&mut stdin, &mut stream_writer).await?;
            stream_writer.shutdown().await.map_err(Error::Io)?;
            eprintln!("bpfnc: sent_bytes={sent}");
            eprintln!("bpfnc: received_bytes=0");
            return Ok(());
        }
        Direction::RecvOnly => {
            let received = tokio::io::copy(&mut stream_reader, &mut stdout)
                .await
                .map_err(Error::Io)?;
            stdout.flush().await.map_err(Error::Io)?;
            eprintln!("bpfnc: sent_bytes=0");
            eprintln!("bpfnc: received_bytes={received}");
            return Ok(());
        }
        Direction::FullDuplex => {}
    }

    let stdin_to_stream = async {
        let bytes = copy_to_stream_with_retry(&mut stdin, &mut stream_writer).await?;
        stream_writer.shutdown().await?;
        Ok::<u64, std::io::Error>(bytes)
    };
    let stream_to_stdout = async {
        let bytes = tokio::io::copy(&mut stream_reader, &mut stdout).await?;
        stdout.flush().await?;
        Ok::<u64, std::io::Error>(bytes)
    };

    let (sent, received) =
        tokio::try_join!(stdin_to_stream, stream_to_stdout).map_err(Error::Io)?;
    eprintln!("bpfnc: sent_bytes={sent}");
    eprintln!("bpfnc: received_bytes={received}");
    Ok(())
}

async fn copy_to_stream_with_retry<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0; 16 * 1024];
    let mut total = 0u64;
    loop {
        let len = reader.read(&mut buf).await?;
        if len == 0 {
            return Ok(total);
        }
        let mut written = 0;
        while written < len {
            match writer.write(&buf[written..len]).await {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        ErrorKind::WriteZero,
                        "stream write returned zero",
                    ));
                }
                Ok(n) => {
                    written += n;
                    total += n as u64;
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(err) => return Err(err),
            }
        }
    }
}

impl Config {
    fn parse_from<I, S>(args: I) -> std::result::Result<Self, &'static str>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args: Vec<String> = args.into_iter().map(Into::into).collect();
        let command = args.get(1).ok_or("missing mode")?;
        let interface = value(&args, "--interface")?.to_string();
        let local_ip = parse_scoped_ip(
            value_any(&args, &["--local-ip", "--local-ipv4"])?,
            &interface,
        )
        .map_err(|_| "invalid --local-ip")?;
        let service_port = value(&args, "--service-port")?
            .parse()
            .map_err(|_| "invalid --service-port")?;
        if service_port == 0 {
            return Err("--service-port must be non-zero");
        }
        let transport_mode = parse_transport_mode(&args)?;
        let direction = parse_direction(&args)?;
        let mode = match command.as_str() {
            "listen" => Mode::Listen {
                linger_ms: parse_linger_ms(&args)?,
            },
            "connect" => Mode::Connect {
                peer_ip: parse_scoped_ip(
                    optional_value(&args, "--peer-ip")
                        .or_else(|| optional_value(&args, "--peer-ipv4"))
                        .ok_or("--peer-ip is required for connect mode")?,
                    &interface,
                )
                .map_err(|_| "invalid --peer-ip")?,
                linger_ms: parse_linger_ms(&args)?,
            },
            _ => return Err("mode must be listen or connect"),
        };

        Ok(Self {
            mode,
            direction,
            interface,
            local_ip,
            service_port,
            transport_mode,
        })
    }

    fn mode_name(&self) -> &'static str {
        match self.mode {
            Mode::Listen { .. } => "listen",
            Mode::Connect { .. } => "connect",
        }
    }

    fn transport_name(&self) -> &'static str {
        match self.transport_mode {
            TransportMode::Simple => "simple",
            TransportMode::Kcp => "kcp",
        }
    }

    fn direction_name(&self) -> &'static str {
        match self.direction {
            Direction::FullDuplex => "full-duplex",
            Direction::SendOnly => "send-only",
            Direction::RecvOnly => "recv-only",
        }
    }
}

fn value<'a>(args: &'a [String], flag: &str) -> std::result::Result<&'a str, &'static str> {
    optional_value(args, flag).ok_or("missing required argument")
}

fn value_any<'a>(args: &'a [String], flags: &[&str]) -> std::result::Result<&'a str, &'static str> {
    flags
        .iter()
        .find_map(|flag| optional_value(args, flag))
        .ok_or("missing required argument")
}

fn optional_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find_map(|pair| (pair[0] == flag).then_some(pair[1].as_str()))
}

fn parse_transport_mode(args: &[String]) -> std::result::Result<TransportMode, &'static str> {
    match optional_value(args, "--transport").unwrap_or("kcp") {
        "simple" => Ok(TransportMode::Simple),
        "kcp" => Ok(TransportMode::Kcp),
        _ => Err("invalid --transport"),
    }
}

fn parse_direction(args: &[String]) -> std::result::Result<Direction, &'static str> {
    let send_only = args.iter().any(|arg| arg == "--send-only");
    let recv_only = args.iter().any(|arg| arg == "--recv-only");
    match (send_only, recv_only) {
        (true, true) => Err("--send-only and --recv-only are mutually exclusive"),
        (true, false) => Ok(Direction::SendOnly),
        (false, true) => Ok(Direction::RecvOnly),
        (false, false) => Ok(Direction::FullDuplex),
    }
}

fn parse_linger_ms(args: &[String]) -> std::result::Result<u64, &'static str> {
    optional_value(args, "--linger-ms")
        .map(|value| value.parse().map_err(|_| "invalid --linger-ms"))
        .transpose()
        .map(|value| value.unwrap_or(1000))
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use std::net::IpAddr;

    use bpflink::TransportMode;
    use tokio::io::{AsyncWrite, ReadBuf};

    use super::{copy_to_stream_with_retry, Config, Direction, Mode};

    #[test]
    fn parses_listen_mode_with_kcp_default() {
        let config = Config::parse_from([
            "bpfnc",
            "listen",
            "--interface",
            "en0",
            "--local-ip",
            "192.0.2.2",
            "--service-port",
            "40000",
        ])
        .unwrap();

        assert_eq!(config.interface, "en0");
        assert_eq!(config.local_ip, IpAddr::from([192, 0, 2, 2]));
        assert_eq!(config.service_port, 40000);
        assert_eq!(config.transport_mode, TransportMode::Kcp);
        assert_eq!(config.mode, Mode::Listen { linger_ms: 1000 });
        assert_eq!(config.direction, Direction::FullDuplex);
    }

    #[test]
    fn parses_connect_mode_with_scoped_peer_and_simple_transport() {
        let config = Config::parse_from([
            "bpfnc",
            "connect",
            "--interface",
            "en0",
            "--local-ip",
            "fe80::1%en0",
            "--service-port",
            "40000",
            "--peer-ip",
            "fe80::2%en0",
            "--transport",
            "simple",
        ])
        .unwrap();

        assert_eq!(config.local_ip, "fe80::1".parse::<IpAddr>().unwrap());
        assert_eq!(config.transport_mode, TransportMode::Simple);
        assert_eq!(
            config.mode,
            Mode::Connect {
                peer_ip: "fe80::2".parse().unwrap(),
                linger_ms: 1000,
            }
        );
    }

    #[test]
    fn parses_connect_mode_with_custom_linger() {
        let config = Config::parse_from([
            "bpfnc",
            "connect",
            "--interface",
            "en0",
            "--local-ip",
            "192.0.2.1",
            "--service-port",
            "40000",
            "--peer-ip",
            "192.0.2.2",
            "--linger-ms",
            "2500",
        ])
        .unwrap();

        assert_eq!(
            config.mode,
            Mode::Connect {
                peer_ip: IpAddr::from([192, 0, 2, 2]),
                linger_ms: 2500,
            }
        );
    }

    #[test]
    fn connect_mode_requires_peer_ip() {
        let err = Config::parse_from([
            "bpfnc",
            "connect",
            "--interface",
            "en0",
            "--local-ip",
            "192.0.2.2",
            "--service-port",
            "40000",
        ])
        .unwrap_err();

        assert_eq!(err, "--peer-ip is required for connect mode");
    }

    #[test]
    fn parses_send_only_and_recv_only_modes() {
        let send = Config::parse_from([
            "bpfnc",
            "connect",
            "--interface",
            "en0",
            "--local-ip",
            "192.0.2.1",
            "--service-port",
            "40000",
            "--peer-ip",
            "192.0.2.2",
            "--send-only",
        ])
        .unwrap();
        assert_eq!(send.direction, Direction::SendOnly);

        let recv = Config::parse_from([
            "bpfnc",
            "listen",
            "--interface",
            "en0",
            "--local-ip",
            "192.0.2.2",
            "--service-port",
            "40000",
            "--recv-only",
        ])
        .unwrap();
        assert_eq!(recv.direction, Direction::RecvOnly);
    }

    #[test]
    fn rejects_conflicting_transfer_direction_flags() {
        let err = Config::parse_from([
            "bpfnc",
            "listen",
            "--interface",
            "en0",
            "--local-ip",
            "192.0.2.2",
            "--service-port",
            "40000",
            "--send-only",
            "--recv-only",
        ])
        .unwrap_err();

        assert_eq!(err, "--send-only and --recv-only are mutually exclusive");
    }

    #[tokio::test]
    async fn copy_to_stream_retries_would_block_writes() {
        let mut reader = OneShotReader {
            bytes: b"retry payload".to_vec(),
            done: false,
        };
        let mut writer = WouldBlockOnceWriter {
            bytes: Vec::new(),
            blocked: false,
        };

        let copied = copy_to_stream_with_retry(&mut reader, &mut writer)
            .await
            .unwrap();

        assert_eq!(copied, 13);
        assert_eq!(writer.bytes, b"retry payload");
        assert!(writer.blocked);
    }

    struct OneShotReader {
        bytes: Vec<u8>,
        done: bool,
    }

    impl tokio::io::AsyncRead for OneShotReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.done {
                return Poll::Ready(Ok(()));
            }
            let bytes = std::mem::take(&mut self.bytes);
            buf.put_slice(&bytes);
            self.done = true;
            Poll::Ready(Ok(()))
        }
    }

    struct WouldBlockOnceWriter {
        bytes: Vec<u8>,
        blocked: bool,
    }

    impl AsyncWrite for WouldBlockOnceWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if !self.blocked {
                self.blocked = true;
                return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)));
            }
            self.bytes.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
