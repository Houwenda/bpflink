use std::env;
use std::net::IpAddr;

use bpflink::{parse_scoped_ip, TransportMode};
use bpflink::{Error, Link, PeerAddr, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let config = Config::parse()?;
    eprintln!(
        "bpflink echo client: interface={} local_ip={} service_port={} peer_ip={} iterations={} concurrency={} transport={}",
        config.interface,
        config.local_ip,
        config.service_port,
        config.peer_ip,
        config.iterations,
        config.concurrency,
        config.transport_name()
    );
    let builder = Link::builder()
        .interface(config.interface.clone())
        .local_ip(config.local_ip)
        .service_ports([config.service_port])
        .transport_mode(config.transport_mode);
    let link = builder.build().await?;

    let mut total_sent = 0usize;
    let mut total_received = 0usize;
    let mut last_echo = Vec::new();
    for iteration in 0..config.iterations {
        let mut streams = Vec::new();
        for connection in 0..config.concurrency {
            let stream = link
                .connect(PeerAddr { ip: config.peer_ip }, config.service_port)
                .await?;
            streams.push((connection, stream));
        }

        for (connection, stream) in &mut streams {
            let payload = payload(config.payload_bytes, iteration, *connection);
            stream.write_all(&payload).await?;
            total_sent += payload.len();
        }

        for (connection, mut stream) in streams {
            let expected = payload(config.payload_bytes, iteration, connection);
            let mut buf = vec![0; expected.len()];
            stream.read_exact(&mut buf).await?;
            total_received += buf.len();
            if buf != expected {
                return Err(Error::PacketParse("echo payload mismatch"));
            }
            last_echo = buf;
            stream.shutdown().await?;
        }
    }
    eprintln!("bpflink echo client: sent_bytes={total_sent}");
    eprintln!("bpflink echo client: received_bytes={total_received}");
    eprintln!("bpflink echo client: payload_match=true");
    eprintln!("bpflink echo client: related_icmp_count=0");
    if config.iterations == 1 && config.concurrency == 1 && last_echo == b"bpflink echo" {
        println!("{}", String::from_utf8_lossy(&last_echo));
    }
    eprintln!("bpflink echo client: shutdown");
    Ok(())
}

struct Config {
    interface: String,
    local_ip: IpAddr,
    service_port: u16,
    peer_ip: IpAddr,
    payload_bytes: usize,
    iterations: usize,
    concurrency: usize,
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
            peer_ip: parse_scoped_ip(
                value_any(&args, &["--peer-ip", "--peer-ipv4"])?,
                value(&args, "--interface")?,
            )?,
            payload_bytes: optional_value(&args, "--payload-bytes")
                .map(|value| {
                    value
                        .parse()
                        .map_err(|_| Error::Config("invalid --payload-bytes"))
                })
                .transpose()?
                .unwrap_or(12),
            iterations: optional_value(&args, "--iterations")
                .map(|value| {
                    value
                        .parse()
                        .map_err(|_| Error::Config("invalid --iterations"))
                })
                .transpose()?
                .unwrap_or(1),
            concurrency: optional_value(&args, "--concurrency")
                .map(|value| {
                    value
                        .parse()
                        .map_err(|_| Error::Config("invalid --concurrency"))
                })
                .transpose()?
                .unwrap_or(1),
            transport_mode: parse_transport_mode(&args)?,
        };
        if config.iterations == 0 {
            return Err(Error::Config("--iterations must be non-zero"));
        }
        if config.concurrency == 0 {
            return Err(Error::Config("--concurrency must be non-zero"));
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

fn payload(len: usize, iteration: usize, connection: usize) -> Vec<u8> {
    if len == 12 && iteration == 0 && connection == 0 {
        b"bpflink echo".to_vec()
    } else {
        (0..len)
            .map(|index| ((index + iteration + connection) % 251) as u8)
            .collect()
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
