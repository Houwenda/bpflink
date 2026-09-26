use std::env;
use std::net::IpAddr;
use std::process::ExitCode;

use bpflink::diagnostics::{probe_runtime_command_loop, RuntimeProbeConfig};
use bpflink::parse_scoped_ip;
use bpflink::Error;
use bpflink::TransportMode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let config = match parse_args(env::args().skip(1)) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            eprintln!(
                "usage: cargo run --example runtime_smoke -- <interface> <local-ip> [service-port] [--peer-ip <peer-ip>] [--transport simple|kcp]"
            );
            return ExitCode::from(2);
        }
    };

    match probe_runtime_command_loop(config).await {
        Ok(report) => {
            println!("bpflink runtime smoke");
            println!("interface: {}", report.interface);
            println!("local_ip: {}", report.local_ip);
            println!("service_ports: {:?}", report.service_ports);
            println!("active_service_port: {}", report.active_service_port);
            println!("transport_mode: {}", report.transport_mode);
            println!("command_loop: ok");
            println!("mtu: {}", report.mtu);
            println!("payload_target: {}", report.payload_target);
            println!(
                "sees_sent_configured: {}",
                report
                    .sees_sent_configured
                    .map(|configured| configured.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
            println!(
                "filter_configured: {}",
                report
                    .filter_configured
                    .map(|configured| configured.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
            println!("listener_count: {}", report.listener_count);
            println!("session_count: {}", report.session_count);
            println!("command_count: {}", report.command_count);
            println!("poll_count: {}", report.poll_count);
            println!(
                "connect_peer_ip: {}",
                report
                    .connect_peer_ip
                    .map(|peer| peer.to_string())
                    .unwrap_or_else(|| "none".to_string())
            );
            println!("stream_write_count: {}", report.stream_write_count);
            println!(
                "outbound_datagram_count: {}",
                report.outbound_datagram_count
            );
            println!("inbound_accept_count: {}", report.inbound_accept_count);
            println!("inbound_data_count: {}", report.inbound_data_count);
            println!("ignored_icmp_count: {}", report.ignored_icmp_count);
            println!("closed_session_count: {}", report.closed_session_count);
            println!("idle_timeout_count: {}", report.idle_timeout_count);
            println!("backpressure_count: {}", report.backpressure_count);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("bpflink runtime smoke failed: {err}");
            if is_permission_denied(&err) {
                print_permission_hint();
            }
            ExitCode::from(1)
        }
    }
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<RuntimeProbeConfig, &'static str> {
    let interface = args.next().ok_or("missing interface")?;
    let local_ip = parse_scoped_ip(args.next().ok_or("missing local-ip")?, &interface)
        .map_err(|_| "invalid local-ip")?;
    let mut rest = args.peekable();
    let service_port = match rest.peek() {
        Some(value) if is_option_flag(value) => 40000,
        Some(_) => rest
            .next()
            .expect("peeked value exists")
            .parse::<u16>()
            .map_err(|_| "invalid service-port")?,
        None => 40000,
    };
    let (connect_peer_ip, parsed_transport_mode) = parse_options(rest, &interface)?;
    let write_payload = connect_peer_ip.map(|_| b"bpflink-smoke".to_vec());

    Ok(RuntimeProbeConfig {
        interface,
        local_ip,
        service_ports: vec![service_port],
        active_service_port: service_port,
        connect_peer_ip,
        write_payload,
        transport_mode: parsed_transport_mode,
    })
}

fn default_transport_mode() -> TransportMode {
    TransportMode::Kcp
}

type ParsedTransportMode = TransportMode;

fn parse_options(
    mut args: impl Iterator<Item = String>,
    interface: &str,
) -> Result<(Option<IpAddr>, ParsedTransportMode), &'static str> {
    let mut peer = None;
    let mut transport_mode = default_transport_mode();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--peer-ip" | "--peer-ipv4" => {
                peer = Some(
                    parse_scoped_ip(args.next().ok_or("missing value for --peer-ip")?, interface)
                        .map_err(|_| "invalid peer-ip")?,
                );
            }
            "--transport" => {
                let value = args.next().ok_or("missing value for --transport")?;
                transport_mode = match value.as_str() {
                    "simple" => TransportMode::Simple,
                    "kcp" => TransportMode::Kcp,
                    _ => return Err("invalid --transport"),
                };
            }
            _ => return Err("unknown argument"),
        }
    }
    Ok((peer, transport_mode))
}

fn is_option_flag(value: &str) -> bool {
    matches!(value, "--peer-ip" | "--peer-ipv4" | "--transport")
}

fn is_permission_denied(err: &Error) -> bool {
    match err {
        Error::Io(io) => io.kind() == std::io::ErrorKind::PermissionDenied,
        Error::IoContext { source, .. } => source.kind() == std::io::ErrorKind::PermissionDenied,
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn print_permission_hint() {
    eprintln!("hint: Linux AF_PACKET sockets require CAP_NET_RAW");
    eprintln!("try: docker run --cap-add NET_RAW --cap-add NET_ADMIN ...");
}

#[cfg(not(target_os = "linux"))]
fn print_permission_hint() {
    eprintln!("hint: macOS /dev/bpf* usually requires sudo");
}
