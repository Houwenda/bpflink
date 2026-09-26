# bpflink IPv6 Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add macOS IPv6 validation support while preserving the existing IPv4 runtime and API compatibility path.

**Architecture:** Generalize public peer/local address fields from `Ipv4Addr` to `IpAddr`, keep `local_ipv4()` as a compatibility builder, and add `local_ipv6()`/`local_ip()`. Extend smoltcp configuration to install either IPv4 or IPv6 CIDR, extend runtime packet dispatch to carry `IpAddr`, and extend macOS BPF filtering to pass IPv6 UDP service traffic and ICMPv6/NDP.

**Tech Stack:** Rust 2021, smoltcp 0.12 Ethernet medium with IPv4 and IPv6 UDP, macOS `/dev/bpf*`, classic BPF filter.

**Spec:** `docs/superpowers/specs/2026-09-26-bpflink-bpf-transport-design.md`

## Global Constraints

- BPF remains the only packet backend.
- First implementation target is macOS Darwin BPF.
- Existing IPv4 API path must continue to work via `LinkBuilder::local_ipv4`.
- IPv6 support is limited to direct interface addresses supplied by the caller; no automatic address discovery.
- KCP is not part of this plan.

## Review Focus

- IPv4 regression: existing IPv4 examples/tests must still pass.
- Address family mismatch: connecting to an IPv6 peer from an IPv4-configured `Link`, or vice versa, should fail cleanly.
- BPF filter correctness: IPv4 ARP/ICMP/UDP behavior must remain, and IPv6 UDP service traffic plus ICMPv6 must pass.
- IPv6 neighbor discovery: BPF must not drop ICMPv6.
- Examples/diagnostics: old `--local-ipv4`/`--peer-ipv4` flags should remain accepted while new IP-neutral flags are added.

---

### Task 1: Generalize Address Model

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/link.rs`
- Modify: `src/runtime.rs`
- Modify: `src/transport/session.rs`
- Test: `tests/link_api.rs`

**Interfaces:**
- Produces: `pub struct PeerAddr { pub ip: std::net::IpAddr }`.
- Produces: `LinkBuilder::local_ip(IpAddr)`, `local_ipv4(Ipv4Addr)`, and `local_ipv6(Ipv6Addr)`.
- Produces: runtime/session code using `IpAddr`.

- [ ] **Step 1: Write failing tests**

Add tests that construct IPv4 and IPv6 `PeerAddr`, use `local_ipv4()` compatibility, use new `local_ipv6()`, and reject missing local address with `local_ip is required`.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --features test-util link_api`
Expected: FAIL because address model is IPv4-only.

- [ ] **Step 3: Implement address model**

Change peer/local runtime-facing address types to `IpAddr`, preserve `local_ipv4()` as a wrapper around `local_ip(IpAddr::V4(...))`, and add `local_ipv6()`.

- [ ] **Step 4: Run tests**

Run: `cargo test --features test-util link_api`
Expected: PASS.

### Task 2: Add IPv6 smoltcp Runtime Support

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/stack/smoltcp_driver.rs`
- Modify: `src/runtime.rs`
- Modify: `src/transport/mod.rs`
- Test: `src/stack/smoltcp_driver.rs`
- Test: `src/runtime.rs`

**Interfaces:**
- Consumes: `PeerAddr { ip: IpAddr }`.
- Produces: `StackConfig { local_ip: IpAddr, local_prefix_len: u8, service_port, ethernet_addr }`.
- Produces: `PollOutcome::ReceivedUdp { src: IpAddr, ... }`.
- Produces: `StackDriver::send_udp(dst: IpAddr, ...)`.

- [ ] **Step 1: Write failing tests**

Add a test that `StackDriver` can send IPv6 UDP to an on-link peer and emits an Ethernet frame. Add a test that an inbound IPv6 UDP bpflink datagram is returned as `PollOutcome::ReceivedUdp { src: IpAddr::V6(..) }`.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --features test-util stack::smoltcp_driver`
Expected: FAIL because smoltcp is not compiled/configured for IPv6 and `StackConfig` is IPv4-only.

- [ ] **Step 3: Implement IPv6 stack config**

Enable smoltcp `proto-ipv6`, install `IpCidr::Ipv6` when local address is IPv6, calculate payload target with IPv6 header overhead, and reject address-family mismatches in `send_udp`.

- [ ] **Step 4: Run tests**

Run: `cargo test --features test-util stack::smoltcp_driver`
Expected: PASS.

### Task 3: Extend macOS BPF and Prefix Discovery

**Files:**
- Modify: `src/bpf/macos.rs`
- Modify: `src/bpf/mod.rs`
- Modify: `src/runtime.rs`
- Test: `src/bpf/macos.rs`

**Interfaces:**
- Produces: `interface_ip_prefix_len(interface: &str, local_ip: IpAddr) -> Result<u8>`.
- Produces: BPF filter accepting IPv4 ARP/ICMP/UDP, IPv6 ICMPv6, and IPv6 UDP matching the service port.

- [ ] **Step 1: Write failing tests**

Extend BPF filter tests to assert IPv6 ICMPv6 is accepted, IPv6 UDP dst/src service port is accepted, and non-matching IPv6 UDP is dropped.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --features test-util service_filter`
Expected: FAIL because filter is IPv4-only.

- [ ] **Step 3: Implement BPF IPv6 filter and prefix lookup**

Add IPv6 cBPF offsets for EtherType `0x86dd`, next header, UDP ports, and ICMPv6. Add `getifaddrs` IPv6 prefix lookup from `sockaddr_in6` netmask bytes.

- [ ] **Step 4: Run tests**

Run: `cargo test --features test-util service_filter`
Expected: PASS.

### Task 4: Diagnostics, Examples, and Docs

**Files:**
- Modify: `src/diagnostics.rs`
- Modify: `examples/runtime_smoke.rs`
- Modify: `examples/echo_server.rs`
- Modify: `examples/echo_client.rs`
- Modify: `README.md`
- Modify: `docs/macos-validation.md`

**Interfaces:**
- Consumes: `IpAddr` runtime config.
- Produces: IP-neutral diagnostics reports and CLI flags.

- [ ] **Step 1: Write failing tests**

Update diagnostics API tests to use `local_ip` and `connect_peer_ip`; keep old IPv4 builder compatibility covered in link tests.

- [ ] **Step 2: Implement diagnostics/examples**

Rename report fields to `local_ip` and `connect_peer_ip`, accept `--local-ip`/`--peer-ip`, and keep `--local-ipv4`/`--peer-ipv4` aliases.

- [ ] **Step 3: Verify automated suite**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --features test-util -- -D warnings
cargo test --features test-util
cargo check --examples
cargo build --examples
```

Expected: all pass.

### Task 5: macOS Host/VM IPv6 Validation

**Files:**
- Modify: `docs/macos-validation.md`

**Interfaces:**
- Consumes: built `runtime_smoke`, `echo_server`, and `echo_client`.
- Produces: recorded IPv6 smoke and host/VM echo result.

- [ ] **Step 1: Discover IPv6 addresses**

Use `ifconfig bridge100` locally and `ssh <user>@<vm-ip> ifconfig en0` remotely. Prefer ULA/global IPv6 addresses over link-local scope identifiers.

- [ ] **Step 2: Runtime smoke**

Run local and VM `runtime_smoke` with IPv6 local addresses. Expected: `filter_configured: true`, command loop ok.

- [ ] **Step 3: Echo validation**

Run host-to-VM and VM-to-host IPv6 echo with `4096` bytes. Expected: sent bytes equal received bytes and payload matches.

- [ ] **Step 4: Final verification and commit**

Run automated suite again, update docs with observed IPv6 results, request code review, fix blocking findings, and commit.
