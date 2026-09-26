# bpflink Optional KCP Engine Implementation Plan

> Superseded: this plan records the earlier experimental-KCP implementation
> path. KCP has since been promoted to the default transport by
> `docs/superpowers/specs/2026-09-28-bpflink-kcp-default-ipv6-enhancements-design.md`
> and `docs/superpowers/plans/2026-09-28-bpflink-kcp-default-ipv6-enhancements.md`.
> Use those documents plus `README.md` for current release behavior.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add KCP as an experimental, optional internal transport engine while keeping the existing simple reliable engine and public stream API stable.

**Architecture:** Introduce a crate-internal transport engine boundary used by `RuntimeSession`, then adapt the existing `ReliableSession` behind it before adding a KCP-backed implementation. KCP datagrams continue to ride inside the existing bpflink UDP payload/header framing; connection setup, peer routing, BPF, smoltcp, and public `BpfStream`/`BpfListener` APIs remain unchanged.

**Tech Stack:** Rust 2021, optional `kcp-core = "0.3"` behind an `experimental-kcp` feature, existing smoltcp Ethernet IPv4/IPv6 UDP runtime, macOS Darwin BPF.

**Spec:** `docs/superpowers/specs/2026-09-26-bpflink-bpf-transport-design.md`

## Global Constraints

- BPF remains the only packet backend.
- Runtime platform support is limited to macOS and Linux. Windows is a future
  support target; other operating systems are unsupported.
- KCP does not enter the stable public API; `BpfStream` and `BpfListener` behavior remains TCP-like async byte stream.
- The simple reliable engine must remain available as the default until KCP host/VM validation is complete.
- KCP mode must work with both IPv4 and explicit IPv6 addresses already supported by `PeerAddr { ip: IpAddr }`.
- KCP is used as a pure protocol engine; do not bind a system UDP socket or bypass smoltcp/BPF.

## Review Focus

- Engine parity: simple mode must preserve all current tests and wire behavior.
- KCP byte delivery: segmented writes, out-of-order KCP segments, and retransmission timers must deliver exactly-once application bytes.
- Close semantics: KCP mode must not regress DATA-before-FIN, read-side close, stream drop, or idle timeout behavior.
- Backpressure: KCP send buffering must honor the existing bounded write/backpressure behavior.
- Validation: macOS host/VM echo must pass for KCP mode on IPv4 and IPv6 before considering KCP as a default candidate.

---

### Task 1: Add Internal Transport Engine Boundary

**Files:**
- Create: `src/transport/engine.rs`
- Modify: `src/transport/mod.rs`
- Modify: `src/runtime.rs`
- Modify: `src/transport/session.rs`
- Test: `src/transport/engine.rs`
- Test: `src/runtime.rs`

**Interfaces:**
- Produces: `pub(crate) enum TransportMode { Simple, #[cfg(feature = "experimental-kcp")] Kcp }`.
- Produces: `pub(crate) enum TransportEvent { Established, DataAvailable, Closed, Reset }`.
- Produces: `pub(crate) trait TransportEngine` with methods matching current runtime needs: `connection_id`, `on_packet`, `write`, `read`, `poll_output`, `close`, `idle_expired`, `remote_closed`.
- Produces: `SimpleTransportEngine` wrapping the existing `ReliableSession`.
- Consumes: current `ReliableSession` and `SessionEvent`.

- [ ] **Step 1: Write failing engine parity tests**

Add tests that create `SimpleTransportEngine` pairs and assert connect/accept, ordered data read, DATA before FIN, out-of-order DATA buffering, and FIN deferral match the current `ReliableSession` behavior.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --features test-util transport::engine`
Expected: FAIL because `transport::engine` does not exist.

- [ ] **Step 3: Implement the simple engine wrapper**

Create `src/transport/engine.rs`, move no protocol logic yet, and wrap `ReliableSession` behind the new trait/enum types. Export the engine module from `src/transport/mod.rs`.

- [ ] **Step 4: Wire runtime through the engine abstraction in simple mode**

Change `RuntimeSession` to hold the engine abstraction while preserving simple mode as the only constructed mode. Keep packet framing, listener acceptance, counters, and read-handle behavior unchanged.

- [ ] **Step 5: Verify task**

Run:

```bash
cargo test --features test-util transport::engine
cargo test --features test-util runtime_
cargo test --features test-util
```

Expected: PASS.

### Task 2: Add Optional KCP Engine Adapter

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/transport/engine.rs`
- Modify: `src/transport/kcp.rs`
- Test: `src/transport/kcp.rs`

**Interfaces:**
- Consumes: `TransportEngine` from Task 1.
- Produces: `KcpTransportEngine` behind `#[cfg(feature = "experimental-kcp")]`.
- Produces: optional dependency `kcp-core = "0.3"`.

- [ ] **Step 1: Write failing KCP pair tests**

Under `#[cfg(feature = "experimental-kcp")]`, add tests for a client/server `KcpTransportEngine` pair:

- connect/accept keeps the existing bpflink handshake outside KCP;
- `write(b"...")` emits one or more bpflink `Data` datagrams containing KCP segments;
- feeding those datagrams to the peer and polling KCP delivers the original bytes;
- feeding ACK/output back to the sender stops unnecessary retransmission after KCP acknowledges data.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --features "test-util experimental-kcp" kcp`
Expected: FAIL because the optional dependency/adapter does not exist.

- [ ] **Step 3: Add dependency and KCP adapter**

Add `experimental-kcp = ["dep:kcp-core"]` to `Cargo.toml`. Implement `KcpTransportEngine` in `src/transport/kcp.rs`; it must expose the same engine interface and must not perform socket I/O. KCP output is encoded as existing `PacketType::Data` bpflink datagrams for the runtime to send through smoltcp/BPF.

- [ ] **Step 4: Verify task**

Run:

```bash
cargo test --features "test-util experimental-kcp" kcp
cargo test --features "test-util experimental-kcp" transport::engine
cargo clippy --all-targets --features "test-util experimental-kcp" -- -D warnings
```

Expected: PASS.

### Task 3: Add Experimental Mode Selection Without Stable API Commitment

**Files:**
- Modify: `src/link.rs`
- Modify: `src/runtime.rs`
- Modify: `src/diagnostics.rs`
- Modify: `examples/runtime_smoke.rs`
- Modify: `examples/echo_server.rs`
- Modify: `examples/echo_client.rs`
- Test: `tests/link_api.rs`
- Test: `tests/diagnostics_api.rs`

**Interfaces:**
- Consumes: `TransportMode`.
- Produces: `LinkBuilder::experimental_transport_mode(mode: TransportMode)` behind `#[cfg(feature = "experimental-kcp")]` and marked doc-hidden.
- Produces: example-only `--transport simple|kcp` flags when built with `experimental-kcp`.
- Produces: diagnostics report field `transport_mode: &'static str` or equivalent enum-safe display value.

- [ ] **Step 1: Write failing mode selection tests**

Add tests that default `LinkBuilder` uses simple mode, and that `experimental_transport_mode(TransportMode::Kcp)` is accepted when `experimental-kcp` is enabled.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --features "test-util experimental-kcp" link_api diagnostics_api`
Expected: FAIL because mode selection is not implemented.

- [ ] **Step 3: Implement experimental mode plumbing**

Thread `TransportMode` through `LinkBuilder`, `RuntimeDriver::spawn_bpf`, `RuntimeDriver::spawn_with_device`, and `DriverState`. Keep simple mode as default. Examples may expose `--transport kcp` only when compiled with `experimental-kcp`.

- [ ] **Step 4: Verify task**

Run:

```bash
cargo test --features "test-util experimental-kcp"
cargo check --examples --features experimental-kcp
```

Expected: PASS.

### Task 4: Runtime KCP Echo and Stress Coverage

**Files:**
- Modify: `src/runtime.rs`
- Modify: `tests/async_api.rs`
- Test: `src/runtime.rs`
- Test: `tests/async_api.rs`

**Interfaces:**
- Consumes: KCP mode selection from Task 3.
- Produces: in-memory runtime coverage for KCP stream read/write and multiple streams.

- [ ] **Step 1: Write failing KCP runtime tests**

Add `#[cfg(feature = "experimental-kcp")]` tests that run the runtime with fake frame I/O and KCP mode, covering:

- stream write routes to KCP datagrams;
- inbound KCP data is routed to the correct stream read handle;
- shutdown sends DATA before FIN when data and close happen in the same tick;
- many stream pairs route independently in `test-util` mode where applicable.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test --features "test-util experimental-kcp" runtime_kcp`
Expected: FAIL until runtime dispatch constructs KCP sessions and polls KCP timers.

- [ ] **Step 3: Implement runtime KCP construction and timer polling**

Construct `KcpTransportEngine` when mode is KCP. Ensure `DriverState::poll_once` calls `poll_output` often enough for KCP update/retransmission, and keep existing outbound datagram counters meaningful.

- [ ] **Step 4: Verify task**

Run:

```bash
cargo test --features "test-util experimental-kcp" runtime_
cargo test --features "test-util experimental-kcp" async_api
```

Expected: PASS.

### Task 5: Documentation and macOS KCP Validation

**Files:**
- Modify: `README.md`
- Modify: `docs/macos-validation.md`
- Modify: `docs/superpowers/specs/2026-09-26-bpflink-bpf-transport-design.md`

**Interfaces:**
- Consumes: examples with `--transport kcp`.
- Produces: recorded KCP validation results.

- [ ] **Step 1: Update docs for experimental KCP mode**

Document that KCP is optional/experimental, simple mode remains default, and KCP is selected only when built with `--features experimental-kcp`.

- [ ] **Step 2: Run automated suite**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets --features "test-util experimental-kcp" -- -D warnings
cargo test --features "test-util experimental-kcp"
cargo check --examples --features experimental-kcp
cargo build --examples --features experimental-kcp
```

Expected: PASS.

- [ ] **Step 3: Run macOS host/VM validation**

Build/copy/sign examples with `experimental-kcp`, then run:

- IPv4 host-to-VM KCP echo, 4096 bytes;
- IPv4 VM-to-host KCP echo, 4096 bytes;
- IPv6 host-to-VM KCP echo, 4096 bytes;
- IPv6 VM-to-host KCP echo, 4096 bytes.

Expected: each client reports sent bytes equal received bytes and `payload_match=true`; each server reports matching received/echoed bytes.

- [ ] **Step 4: Final verification and commit**

Run the full command set from Step 2 again, update docs with observed validation results, request code review, fix blocking findings, and commit.
