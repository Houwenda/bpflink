use std::env;
use std::process::ExitCode;

use bpflink::diagnostics::probe_bpf_interface;
use bpflink::Error;

fn main() -> ExitCode {
    let interface = match parse_interface(env::args().skip(1)) {
        Ok(interface) => interface,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("usage: cargo run --example bpf_smoke -- <interface>");
            eprintln!("   or: cargo run --example bpf_smoke -- --interface <interface>");
            return ExitCode::from(2);
        }
    };

    match probe_bpf_interface(&interface) {
        Ok(report) => {
            println!("bpflink bpf smoke");
            println!("interface: {}", report.interface);
            println!("open_config_read: ok");
            println!("mtu: {}", report.mtu);
            println!("read_polls: {}", report.read_polls);
            println!("frames_seen: {}", report.frames_seen);
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
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("bpflink bpf smoke failed: {err}");
            if is_permission_denied(&err) {
                print_permission_hint(&interface);
            }
            ExitCode::from(1)
        }
    }
}

fn parse_interface(mut args: impl Iterator<Item = String>) -> Result<String, &'static str> {
    let Some(first) = args.next() else {
        return Err("missing interface");
    };
    if first == "--interface" {
        return args.next().ok_or("missing value for --interface");
    }
    Ok(first)
}

fn is_permission_denied(err: &Error) -> bool {
    match err {
        Error::Io(io) => io.kind() == std::io::ErrorKind::PermissionDenied,
        Error::IoContext { source, .. } => source.kind() == std::io::ErrorKind::PermissionDenied,
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn print_permission_hint(_interface: &str) {
    eprintln!("hint: Linux AF_PACKET sockets require CAP_NET_RAW");
    eprintln!("try: docker run --cap-add NET_RAW --cap-add NET_ADMIN ...");
}

#[cfg(not(target_os = "linux"))]
fn print_permission_hint(interface: &str) {
    eprintln!("hint: macOS /dev/bpf* usually requires sudo");
    eprintln!("try: sudo cargo run --example bpf_smoke -- {interface}");
}
