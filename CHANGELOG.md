# Changelog

All notable changes to `bpflink` are recorded here.

## 0.1.0 - Unreleased

Initial macOS/Linux validation release candidate.

### Added

- BPF-backed runtime for Darwin `/dev/bpf*` with interface-name binding.
- smoltcp Ethernet/ARP/NDP/IPv4/IPv6/UDP stack boundary.
- TCP-like async public API: `Link`, `BpfStream`, and `BpfListener`.
- Raw UDP datagram public API: `BpfUdpSocket` and `BpfUdpPacket`.
- Structured runtime configuration through `LinkConfig`, including validation
  before opening a packet backend.
- Build-time service-port sets via `LinkBuilder::service_ports([...])`; a
  single `Link` can listen or connect on any declared port, and undeclared
  ports return `Error::ServicePortNotConfigured`.
- Explicit lifecycle API through `Link::shutdown`, `Link::close`, and
  `BpfListener::close`.
- Immediate stream abort through `BpfStream::abort()`.
- Timeout helpers through `Link::connect_timeout`, `Link::shutdown_timeout`,
  and `BpfListener::accept_timeout`.
- Public runtime stats through `Link::stats`, including configured service
  ports, MTU, payload target, filter status, session counts, packet counters,
  ICMP ignore count, idle timeout count, and backpressure count.
- Default KCP transport with a simple reliable transport fallback.
- Explicit IPv4 and IPv6 local/peer address support, including link-local
  `fe80::...%iface` parsing at the API/CLI boundary.
- Classic BPF service-port-set filter for ARP, IPv4 ICMP, IPv6 ICMPv6, and
  matching IPv4/IPv6 UDP traffic. The first release supports up to 16 service
  ports per `Link`.
- Diagnostics and smoke examples for BPF device setup, runtime command loop,
  echo validation, nc-like manual transfer, and DNS UDP request/response
  checks.
- Runtime diagnostics use the same build-time service-port set model as
  `LinkBuilder::service_ports([...])`, with a separate active probe port.
- Linux `AF_PACKET/SOCK_RAW` packet I/O backend with classic BPF
  `SO_ATTACH_FILTER` service-port-set filtering.
- IPv4 and IPv6 off-link peer support by reading the selected interface's
  default gateway and installing it into smoltcp's in-process route table.

### Validation

- Local automated suite passes with `test-util`.
- macOS host/VM validation passes for IPv4 and IPv6 echo in both directions.
- Default KCP validation covers send smoke, echo, segmented payloads,
  multi-stream pressure, and BPF fd sampling.
- Linux/arm64 Docker validation passes on `rust:1-bookworm` for fmt, clippy,
  `test-util`, examples, `bpf_smoke`, KCP runtime smoke, simple runtime smoke,
  two-container IPv4 KCP echo, two-container simple fallback echo, and
  `NET_RAW` permission failure reporting.
- macOS `en0` client to remote Linux `enp1s0` server validation passes for
  off-link IPv4 KCP echo and simple fallback echo.
- IPv6 default-gateway discovery is covered by macOS route-message parser tests,
  Linux `/proc/net/ipv6_route` parser tests, and smoltcp off-link IPv6 route
  injection tests. Public-IPv6 end-to-end BPF echo requires the selected macOS
  Ethernet interface to have a routable IPv6 address and IPv6 default gateway.
- Linux x86_64 target compilation passes with
  `cargo check --target x86_64-unknown-linux-gnu --features test-util`.

### Known Bounds

- Supported runtime platforms are limited to macOS and Linux.
- macOS uses Darwin `/dev/bpf*`; Linux uses `AF_PACKET + SO_ATTACH_FILTER`.
- Windows is a future support target.
- BSD and other operating systems are not supported.
- The wire protocol is not TCP; the public API is TCP-like.
- The first release does not provide encryption, authentication, automatic
  address discovery, dual-stack selection, or true TCP half-close semantics.
- Service ports are fixed at `Link` build time; dynamic service-port
  registration is not part of this release.
