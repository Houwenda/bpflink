# bpflink UDP DNS Resolver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a minimal BPF-backed UDP datagram API and a DNS resolver example that resolves A/AAAA records from a caller-selected DNS server.

**Architecture:** `BpfUdpSocket` is a lightweight handle created from `Link`, sharing the existing runtime and configured service-port set. The smoltcp layer returns all UDP payloads for configured ports; runtime dispatch keeps bpflink frames on the existing stream path and routes ordinary UDP payloads to datagram sockets. `examples/dns_resolver.rs` hand-builds DNS queries and parses the response records it needs.

**Tech Stack:** Rust 2021, tokio, smoltcp UDP sockets, existing BPF backends, no new DNS dependency.

**Spec:** `docs/superpowers/specs/2026-10-03-bpflink-udp-dns-resolver-design.md`

## Global Constraints

- Only macOS and Linux runtime platforms are supported.
- `BpfUdpSocket` must reuse `Link` and must not open its own BPF fd or OS UDP socket.
- UDP sockets may use only build-time configured `service_ports`.
- Existing `BpfStream` / `BpfListener` behavior and wire protocol must remain compatible.
- DNS example supports only A, AAAA, and both.
- DNS example must not include concrete real IP addresses in committed docs/tests.

## Review Focus

- Raw UDP payloads that are not bpflink frames must reach `BpfUdpSocket` instead of being dropped.
- Valid bpflink frames on the same service port must continue to reach stream sessions/listeners, not datagram sockets.
- Pending `recv_from` must wake on datagram arrival, timeout, close, and link shutdown.
- DNS compressed names and truncated packets must not panic or read out of bounds.
- Address-family mismatch must still fail through existing stack/runtime validation.

---

### Task 1: Public UDP Socket Handle

**Files:**
- Create: `src/socket/udp.rs`
- Modify: `src/socket/mod.rs`
- Modify: `src/lib.rs`
- Modify: `src/link.rs`
- Modify: `src/runtime.rs`
- Test: `tests/link_api.rs`
- Test: `tests/async_api.rs`

**Interfaces:**
- Consumes: existing `Link`, `PeerAddr`, `RuntimeDriver`, `TestDriver`, `Error`, `Result`.
- Produces:
  - `pub struct BpfUdpSocket`
  - `pub struct BpfUdpPacket { pub source: std::net::SocketAddr, pub payload: Vec<u8> }`
  - `impl Link { pub async fn udp_socket(&self, service_port: u16) -> Result<BpfUdpSocket>; }`
  - `impl BpfUdpSocket { service_port, send_to, recv_from, recv_from_timeout, close }`

- [ ] **Step 1: Write failing public API tests**

Add tests that create `Link::new_for_test_with_service_ports([53000])`, call `udp_socket(53000)`, assert `service_port()`, send a payload to `PeerAddr`, inject a test datagram through test-util support, receive `BpfUdpPacket`, and assert undeclared ports return `Error::ServicePortNotConfigured`.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --features test-util link_api::udp async_api::udp`

Expected: FAIL because `udp_socket` / `BpfUdpSocket` do not exist.

- [ ] **Step 3: Implement socket handle and test-util routing**

Implement `src/socket/udp.rs` with an internal queue, waker, close state, and runtime/test handles. Add runtime commands for UDP send/register if needed. Add `TestDriver` support for recording sends and injecting inbound datagrams for test links.

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test --features test-util link_api::udp async_api::udp`

Expected: PASS.

### Task 2: Runtime Raw UDP Dispatch

**Files:**
- Modify: `src/stack/smoltcp_driver.rs`
- Modify: `src/runtime.rs`
- Test: `src/stack/smoltcp_driver.rs`
- Test: `src/runtime.rs`

**Interfaces:**
- Consumes: `BpfUdpSocket` internal push/close handle from Task 1.
- Produces: runtime dispatch that routes ordinary UDP payloads to datagram sockets while preserving bpflink stream dispatch.

- [ ] **Step 1: Write failing stack/runtime tests**

Add a stack test proving a configured-port UDP payload `b"dns"` is returned by `StackDriver::poll`. Add a runtime test proving an inbound non-bpflink UDP response is received by a registered UDP socket. Add a runtime test proving a valid bpflink connect packet still creates an accepted stream and not a UDP packet.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --features test-util stack::smoltcp_driver::tests::poll_accepts_raw_udp_payloads runtime::tests::runtime_routes_raw_udp_to_udp_socket runtime::tests::runtime_keeps_bpflink_frames_on_stream_path`

Expected: FAIL because raw UDP payloads are dropped or no runtime UDP routing exists.

- [ ] **Step 3: Implement stack and runtime dispatch**

Remove stack-level bpflink payload filtering. In `DriverState::dispatch_udp`, attempt `BpflinkHeader::decode`; matching headers go through existing stream logic, other payloads push `BpfUdpPacket` to the registered UDP socket for `service_port`.

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test --features test-util stack::smoltcp_driver::tests::poll_accepts_raw_udp_payloads runtime::tests::runtime_routes_raw_udp_to_udp_socket runtime::tests::runtime_keeps_bpflink_frames_on_stream_path`

Expected: PASS.

### Task 3: DNS Resolver Example

**Files:**
- Create: `examples/dns_resolver.rs`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Test: `examples/dns_resolver.rs`

**Interfaces:**
- Consumes: `Link::udp_socket`, `BpfUdpSocket::send_to`, `BpfUdpSocket::recv_from_timeout`, `parse_scoped_ip`, `PeerAddr`.
- Produces: `cargo run --example dns_resolver -- --interface ... --local-ip ... --local-port ... --dns-server ... --name ... --type A|AAAA|both`.

- [ ] **Step 1: Write failing DNS codec tests**

Inside `examples/dns_resolver.rs`, add tests for encoding an A query, parsing A and AAAA answers, handling compression pointers, rejecting transaction id mismatch, rejecting non-zero rcode, and rejecting truncated packets.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --example dns_resolver`

Expected: FAIL because the example/code does not exist yet or codec functions are missing.

- [ ] **Step 3: Implement DNS CLI and codec**

Implement CLI parsing, DNS query construction, response parsing, and BPF UDP send/receive loop with timeout. Use no DNS crate and no real IP addresses in committed docs/tests.

- [ ] **Step 4: Run tests to verify pass**

Run: `cargo test --example dns_resolver`

Expected: PASS.

### Task 4: Full Verification and Documentation Consistency

**Files:**
- Modify as needed: `README.md`, `CHANGELOG.md`, `RELEASE.md`

**Interfaces:**
- Consumes: all tasks above.
- Produces: verified crate state ready for manual BPF DNS smoke.

- [ ] **Step 1: Run full verification**

Run:

```bash
cargo fmt --check
cargo test --features test-util
cargo test --examples
cargo check --examples
cargo clippy --all-targets --features test-util -- -D warnings
cargo doc --no-deps
git diff --check
```

Expected: all commands pass.

- [ ] **Step 2: Final self-review**

Scan for contradictions with the spec, accidental real IPs in docs/tests, old naming, and any DNS example claim beyond A/AAAA UDP request/response support.

Expected: no unresolved mismatch.
