# Release Checklist

This checklist is for preparing a `bpflink` crate release candidate.

## Scope

- Runtime targets: macOS/Darwin `/dev/bpf*` and Linux
  `AF_PACKET + SO_ATTACH_FILTER`.
- Platform support scope: only macOS and Linux are supported for this release;
  Windows is a future support target, and other operating systems are out of
  scope.
- Public API: `Link`, `LinkBuilder`, `PeerAddr`, `BpfStream`,
  `BpfListener`, `BpfUdpSocket`, `BpfUdpPacket`, `TransportMode`, and
  diagnostics helpers.
- Service-port API: declare the full build-time set with
  `LinkBuilder::service_ports([...])`; dynamic service-port registration is
  outside this release.
- Default transport: KCP.
- Fallback transport: simple reliable stream via `TransportMode::Simple`.

## Local Verification

Run from a clean working tree:

```bash
cargo fmt --check
cargo clippy --all-targets --features test-util -- -D warnings
cargo test --features test-util
cargo check --examples
cargo test --doc
cargo doc --no-deps
cargo package --list
cargo package --allow-dirty
```

`cargo package --allow-dirty` is acceptable for a local dry run before the
release commit is made; use plain `cargo package` from the release commit.

## macOS Hardware/VM Smoke

Use `docs/macos-validation.md` as the canonical validation flow. At minimum,
record fresh results for:

- `bpf_smoke` on the release host interface.
- `runtime_smoke` with IPv4 and IPv6 local addresses.
- default-KCP `echo_server`/`echo_client` host-to-VM and VM-to-host.
- explicit `--transport simple` fallback smoke.
- `bpfnc --send-only` / `bpfnc --recv-only` file-transfer smoke.
- BPF fd sampling during a multi-stream pressure run.

## Linux Docker Smoke

Use `docs/linux-validation.md` as the canonical Linux validation flow. At
minimum, record fresh results for:

- Linux container `cargo test --features test-util`.
- Linux container `cargo check --examples`.
- `bpf_smoke --interface eth0` with `NET_RAW`/`NET_ADMIN`.
- `runtime_smoke --interface eth0 --local-ip <container-ip>` with default KCP.
- explicit `runtime_smoke ... --transport simple` fallback.
- two-container IPv4 KCP `echo_server`/`echo_client`.
- two-container explicit `--transport simple` fallback smoke.
- permission failure without `NET_RAW` reports `socket AF_PACKET SOCK_RAW`
  rather than silently running unfiltered.

## Documentation Review

- README current status matches the code and validation record.
- `docs/macos-validation.md` records the latest tested host/VM pair.
- CHANGELOG has an entry for the release version and known bounds.
- Historical plans that describe superseded behavior are marked as such.

## Publish Guardrails

- Do not claim Linux support beyond the validated `AF_PACKET + SO_ATTACH_FILTER`
  runtime boundary.
- Do not claim BSD, iOS, tvOS, or other non-macOS/Linux runtime support.
- Do not claim Windows runtime support yet; Windows is only a future target.
- Do not claim TCP wire compatibility.
- Do not claim encryption, authentication, NAT traversal guarantees, or
  production-grade congestion control.
- Do not publish if BPF permissions or code signing requirements changed
  without updating README, `docs/macos-validation.md`, and
  `docs/linux-validation.md` as applicable.
