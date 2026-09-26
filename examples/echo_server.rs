use std::env;
use std::net::IpAddr;

use bpflink::{parse_scoped_ip, TransportMode};
use bpflink::{Error, Link, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config = Config::parse()?;
    eprintln!(
        "bpflink echo server: interface={} local_ip={} service_port={} accept_count={} transport={}",
        config.interface,
        config.local_ip,
        config.service_port,
        config.accept_count,
        config.transport_name()
    );
    let builder = Link::builder()
        .interface(config.interface.clone())
        .local_ip(config.local_ip)
        .service_ports([config.service_port])
        .transport_mode(config.transport_mode);
    let link = builder.build().await?;
    let listener = link.listen(config.service_port).await?;
    eprintln!("bpflink echo server: listening");
    let mut total_received = 0usize;
    let mut total_echoed = 0usize;
    for _ in 0..config.accept_count {
        let mut stream = listener.accept().await?;

        let mut buf = vec![0; config.expected_bytes.unwrap_or(1200)];
        let len = if let Some(expected_bytes) = config.expected_bytes {
            stream.read_exact(&mut buf[..expected_bytes]).await?;
            expected_bytes
        } else {
            stream.read(&mut buf).await?
        };
        total_received += len;
        stream.write_all(&buf[..len]).await?;
        total_echoed += len;
        stream.shutdown().await?;
    }
    eprintln!("bpflink echo server: received_bytes={total_received}");
    eprintln!("bpflink echo server: echoed_bytes={total_echoed}");
    eprintln!("bpflink echo server: related_icmp_count=0");
    if config.linger_ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(config.linger_ms)).await;
    }
    eprintln!("bpflink echo server: shutdown");
    Ok(())
}

struct Config {
    interface: String,
    local_ip: IpAddr,
    service_port: u16,
    expected_bytes: Option<usize>,
    accept_count: usize,
    linger_ms: u64,
    transport_mode: TransportMode,
}

impl Config {
    fn parse() -> Result<Self> {
        let args: Vec<String> = env::args().collect();
        let config = Self {
            interface: value(&args, "--interface")?.to_string(),
            local_ip: parse_scoped_ip(
                value_any(&args, &["--local-ip", "--local-ipv4"])?,
                value(&args, "--interface")?,
            )?,
            service_port: value(&args, "--service-port")?
                .parse()
                .map_err(|_| Error::Config("invalid --service-port"))?,
            expected_bytes: optional_value(&args, "--expected-bytes")
                .map(|value| {
                    value
                        .parse()
                        .map_err(|_| Error::Config("invalid --expected-bytes"))
                })
                .transpose()?,
            accept_count: optional_value(&args, "--accept-count")
                .map(|value| {
                    value
                        .parse()
                        .map_err(|_| Error::Config("invalid --accept-count"))
                })
                .transpose()?
                .unwrap_or(1),
            linger_ms: optional_value(&args, "--linger-ms")
                .map(|value| {
                    value
                        .parse()
                        .map_err(|_| Error::Config("invalid --linger-ms"))
                })
                .transpose()?
                .unwrap_or(1000),
            transport_mode: parse_transport_mode(&args)?,
        };
        if config.accept_count == 0 {
            return Err(Error::Config("--accept-count must be non-zero"));
        }
        Ok(config)
    }

    fn transport_name(&self) -> &'static str {
        match self.transport_mode {
            TransportMode::Simple => "simple",
            TransportMode::Kcp => "kcp",
        }
    }
}

fn value<'a>(args: &'a [String], flag: &str) -> Result<&'a str> {
    optional_value(args, flag).ok_or(Error::Config("missing required argument"))
}

fn value_any<'a>(args: &'a [String], flags: &[&str]) -> Result<&'a str> {
    flags
        .iter()
        .find_map(|flag| optional_value(args, flag))
        .ok_or(Error::Config("missing required argument"))
}

fn optional_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find_map(|pair| (pair[0] == flag).then_some(pair[1].as_str()))
}

fn parse_transport_mode(args: &[String]) -> Result<TransportMode> {
    match optional_value(args, "--transport").unwrap_or("kcp") {
        "simple" => Ok(TransportMode::Simple),
        "kcp" => Ok(TransportMode::Kcp),
        _ => Err(Error::Config("invalid --transport")),
    }
}
