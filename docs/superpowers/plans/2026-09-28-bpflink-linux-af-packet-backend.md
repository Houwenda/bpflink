# bpflink Linux AF_PACKET Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> Historical note: this plan records the first Linux backend implementation.
> Current release scope treats Linux as a supported macOS/Linux runtime target,
> not an experimental-only path. Any single-port `service_port` or
> `open_filtered(interface, service_port)` references below are historical; the
> current API uses `LinkBuilder::service_ports([...])` and installs a
> service-port-set classic BPF filter.

**Goal:** Add a Linux runtime backend using `AF_PACKET` packet I/O and classic BPF socket filtering, then validate it in Docker.

**Architecture:** Keep the public `Link`/`BpfStream`/`BpfListener` API unchanged. Factor the existing macOS classic BPF service filter into a shared builder, then implement `src/bpf/linux.rs` as a `FrameIo` backend backed by a nonblocking `AF_PACKET/SOCK_RAW` socket bound to an interface. Reuse the existing runtime, smoltcp stack, KCP/default transport, and diagnostics snapshot paths.

**Tech Stack:** Rust 2021, `libc`, Linux `AF_PACKET`, `SO_ATTACH_FILTER`, smoltcp Ethernet IPv4/IPv6 UDP, existing KCP/simple transport, Docker Linux/aarch64 validation.

**Spec:** `docs/superpowers/specs/2026-09-28-bpflink-linux-af-packet-design.md`

## Global Constraints

- Public API remains `Link`, `LinkBuilder`, `PeerAddr`, `BpfStream`, `BpfListener`, and `TransportMode`.
- Linux packet I/O uses `AF_PACKET/SOCK_RAW`; Linux filtering uses `SO_ATTACH_FILTER` classic BPF.
- Do not add eBPF/XDP/TC/AF_XDP, libpcap, nftables, routing, sysctl, cgroup, or fwmark control.
- Docker validation requires IPv4 KCP echo; Docker IPv6 echo is not a first-release completion criterion.
- Linux runtime filter installation must return `filter_configured: Some(true)` on success and must not silently run unfiltered when filter installation fails.
- macOS `/dev/bpf*` behavior must not regress.
- BPF ioctl constants for Darwin continue to come from libc/system bindings.

## Review Focus

- Linux `AF_PACKET` fd setup: interface index binding and nonblocking mode must be correct, or `bpf_smoke` can pass compile but never see/write real frames. Covered by Task 2 unit tests and Task 5 Docker `bpf_smoke`.
- Shared cBPF filter parity: macOS and Linux must install equivalent service-port filter bytecode. Covered by Task 1 characterization tests.
- Prefix/MAC/MTU discovery: Linux must reject missing or mismatched interface/address metadata instead of using bogus defaults. Covered by Task 2 tests and Task 5 `runtime_smoke`.
- Runtime platform cfg: `LinkBuilder::build()` must construct Linux runtime only on Linux and preserve Darwin behavior. Covered by Task 3 Linux container compile and macOS checks.
- Docker permissions: verification must fail clearly without `CAP_NET_RAW`/`CAP_NET_ADMIN` and pass with documented capabilities. Covered by Task 5 docs and manual Docker runs.

---

## File Structure

- Create `src/bpf/filter.rs`: shared classic BPF service-port filter builder and tests.
- Modify `src/bpf/mod.rs`: export shared filter module and Linux metadata helpers.
- Modify `src/bpf/macos.rs`: consume shared filter builder for `BIOCSETF`, keep Darwin-specific open/ioctl/read behavior.
- Modify `src/bpf/linux.rs`: replace stub with Linux `BpfDevice`, metadata helpers, `SO_ATTACH_FILTER`, and `FrameIo`.
- Modify `src/runtime.rs` and `src/link.rs`: extend runtime construction cfg from Darwin-only to Darwin or Linux.
- Modify diagnostics/examples docs as needed to describe Linux experimental target.
- Create `docs/linux-validation.md`: Docker build/run validation flow.

### Task 1: Shared classic BPF service filter

**Files:**
- Create: `src/bpf/filter.rs`
- Modify: `src/bpf/mod.rs`
- Modify: `src/bpf/macos.rs`
- Test: `src/bpf/filter.rs`
- Test: `src/bpf/macos.rs`

**Interfaces:**
- Produces: `pub(crate) fn service_filter_program(service_port: u16) -> Result<Vec<libc::sock_filter>>`.
- Produces: `pub(crate) fn accept_all_program() -> Vec<libc::sock_filter>` if needed by smoke/open paths.
- Consumes: current macOS cBPF service-port semantics in `src/bpf/macos.rs`.

- [ ] **Step 1: Write failing shared filter characterization tests**

Move or mirror the existing macOS service filter tests into `src/bpf/filter.rs` with these test names:

- `service_filter_accepts_control_and_matching_udp_only`
- `service_filter_drops_fragmented_or_optioned_udp`
- `service_filter_accepts_ipv6_icmpv6_and_matching_udp_only`
- `service_filter_accepts_ipv6_udp_behind_common_extension_headers`

The tests must execute `service_filter_program(40000)` against synthetic Ethernet frames and assert the same accept/drop results currently asserted by macOS tests.

- [ ] **Step 2: Run tests to verify failure**

Run: `cargo test bpf::filter`

Expected: FAIL because `src/bpf/filter.rs` or `service_filter_program` does not exist.

- [ ] **Step 3: Implement `src/bpf/filter.rs`**

Move the service filter instruction builder and tiny test interpreter from `src/bpf/macos.rs` into `src/bpf/filter.rs`. Keep the returned type as `Vec<libc::sock_filter>` so both Darwin `bpf_program` and Linux `sock_fprog` can consume it.

- [ ] **Step 4: Wire macOS `BIOCSETF` to the shared builder**

Update `src/bpf/macos.rs` so `configure_bpf(..., Some(service_port))` calls `service_filter_program(service_port)` and passes the resulting instruction slice to `BIOCSETF`.

- [ ] **Step 5: Verify task**

Run:

```bash
cargo test bpf::filter
cargo test bpf::macos::tests::service_filter
cargo test --features test-util
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/bpf/filter.rs src/bpf/mod.rs src/bpf/macos.rs
git commit -m "refactor: share classic bpf service filter"
```

### Task 2: Linux interface metadata helpers

**Files:**
- Modify: `src/bpf/linux.rs`
- Modify: `src/bpf/mod.rs`
- Test: `src/bpf/linux.rs`

**Interfaces:**
- Produces: `pub(crate) fn interface_ethernet_addr(interface: &str) -> Result<[u8; 6]>`.
- Produces: `pub(crate) fn interface_ip_prefix_len(interface: &str, local_ip: IpAddr) -> Result<u8>`.
- Produces: Linux-private helpers for `if_index(interface) -> Result<i32>` and `interface_mtu(interface) -> Result<usize>`.

- [ ] **Step 1: Write failing Linux helper tests**

Add Linux-module unit tests that do not require a real interface:

- `prefix_len_from_netmask_accepts_only_contiguous_masks`
- `ipv6_prefix_len_from_netmask_accepts_only_contiguous_masks`
- `linux_sockaddr_normalization_keeps_ipv6_addresses_plain`

These should mirror macOS prefix-length tests and pin Linux helper behavior.

- [ ] **Step 2: Run tests to verify failure in Linux container**

Run inside Linux container: `cargo test --features test-util bpf::linux`

Expected: FAIL because Linux helpers are still stubbed.

- [ ] **Step 3: Implement Linux metadata helpers in `src/bpf/linux.rs`**

Use `libc::if_nametoindex` or `SIOCGIFINDEX` for ifindex, `SIOCGIFHWADDR` for MAC, `SIOCGIFMTU` for MTU, and `getifaddrs` netmasks for prefix length. Return `Error::IoContext { operation, source }` for syscall/ioctl failures and `Error::Config` for not-found or invalid metadata.

- [ ] **Step 4: Export Linux metadata helpers from `src/bpf/mod.rs`**

Add Linux cfg exports matching the macOS names:

```rust
#[cfg(target_os = "linux")]
pub(crate) use linux::interface_ethernet_addr;
#[cfg(target_os = "linux")]
pub(crate) use linux::interface_ip_prefix_len;
```

- [ ] **Step 5: Verify task**

Run:

```bash
cargo test --features test-util
docker run --rm -v "$PWD":/work -w /work rust:1-bookworm \
  cargo test --features test-util bpf::linux
```

Expected: macOS suite PASS; Linux helper tests PASS in Docker.

- [ ] **Step 6: Commit**

```bash
git add src/bpf/linux.rs src/bpf/mod.rs
git commit -m "feat: add linux interface metadata helpers"
```

### Task 3: Linux AF_PACKET FrameIo backend

**Files:**
- Modify: `src/bpf/linux.rs`
- Modify: `src/runtime.rs`
- Modify: `src/link.rs`
- Test: `src/bpf/linux.rs`
- Test: `tests/link_api.rs`

**Interfaces:**
- Consumes: `service_filter_program(service_port: u16) -> Result<Vec<libc::sock_filter>>` from Task 1.
- Consumes: Linux metadata helpers from Task 2.
- Produces: `BpfDevice::open(interface: &str) -> Result<Self>`.
- Produces: `BpfDevice::open_filtered(interface: &str, service_port: u16) -> Result<Self>`.
- Produces: Linux `impl FrameIo for BpfDevice`.

- [ ] **Step 1: Write failing Linux backend tests**

Add unit tests for pure construction helpers:

- `sockaddr_ll_uses_interface_index_and_eth_p_all`
- `linux_attach_filter_rejects_zero_service_port`
- `linux_bpf_device_reports_filter_status_from_open_path`

Where direct socket calls are required, gate tests with `#[cfg(target_os = "linux")]` and keep them narrow; hardware behavior is validated in Docker smoke.

- [ ] **Step 2: Run tests to verify failure**

Run inside Linux container:

```bash
cargo test --features test-util bpf::linux
cargo check --examples
```

Expected: FAIL because `BpfDevice` still returns `UnsupportedPlatform`.

- [ ] **Step 3: Implement `BpfDevice::open_with_filter(interface, service_port)`**

Create a nonblocking close-on-exec `AF_PACKET/SOCK_RAW` socket with protocol `ETH_P_ALL`, bind it to `sockaddr_ll` for the interface index, load MTU, and install `SO_ATTACH_FILTER` when `service_port` is provided.

- [ ] **Step 4: Implement Linux `FrameIo`**

Implement:

- `read_frames(&mut self, out: &mut Vec<Vec<u8>>) -> Result<usize>` using nonblocking `recv`/`read`.
- `write_frame(&mut self, frame: &[u8]) -> Result<()>` using `send`/`write` of a complete Ethernet frame.
- `mtu(&self) -> usize`.
- `filter_configured(&self) -> Option<bool>`.
- `sees_sent_configured(&self) -> Option<bool>` returning `None`.

- [ ] **Step 5: Enable Linux runtime cfg**

Update `RuntimeDriver::spawn_bpf` and `LinkBuilder::build` cfg guards so Linux uses the same runtime construction path as Darwin:

```rust
#[cfg(any(target_os = "macos", target_os = "linux"))]
```

Keep every other operating system unsupported. Windows is a future target, not
part of this implementation.

- [ ] **Step 6: Verify task**

Run:

```bash
cargo test --features test-util
cargo check --examples
docker run --rm -v "$PWD":/work -w /work rust:1-bookworm \
  cargo test --features test-util
docker run --rm -v "$PWD":/work -w /work rust:1-bookworm \
  cargo check --examples
```

Expected: macOS and Linux compile/test PASS.

- [ ] **Step 7: Commit**

```bash
git add src/bpf/linux.rs src/runtime.rs src/link.rs tests/link_api.rs
git commit -m "feat: add linux af_packet bpf device"
```

### Task 4: Linux Docker validation docs and smoke examples

**Files:**
- Create: `docs/linux-validation.md`
- Modify: `README.md`
- Modify: `RELEASE.md`
- Modify: `docs/macos-validation.md` only if shared status language needs adjustment.

**Interfaces:**
- Consumes: Linux runtime support from Task 3.
- Produces: documented Docker validation flow and updated status language.

- [ ] **Step 1: Write docs for Linux validation**

Create `docs/linux-validation.md` with commands for:

- building or running a Linux Rust container;
- required `--cap-add NET_RAW --cap-add NET_ADMIN`;
- `cargo test --features test-util`;
- `cargo check --examples`;
- `bpf_smoke --interface eth0`;
- `runtime_smoke --interface eth0 --local-ip <container-ip>`;
- two-container IPv4 KCP echo;
- explicit simple fallback smoke.

- [ ] **Step 2: Update README status**

Change README runtime target wording from macOS-only to:

- macOS/Darwin `/dev/bpf*` validated runtime target;
- Linux `AF_PACKET + SO_ATTACH_FILTER` experimental runtime target once Docker validation passes;
- Windows future target; all other operating systems unsupported.

- [ ] **Step 3: Update RELEASE checklist**

Add Linux Docker smoke items under release verification, while preserving macOS hardware smoke items.

- [ ] **Step 4: Verify docs**

Run:

```bash
cargo test --doc
cargo doc --no-deps
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add docs/linux-validation.md README.md RELEASE.md docs/macos-validation.md
git commit -m "docs: add linux docker validation flow"
```

### Task 5: Docker runtime validation

**Files:**
- Modify: `docs/linux-validation.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: all previous tasks.
- Produces: recorded Docker Linux validation results.

- [ ] **Step 1: Build or pull Linux Rust test image**

Use the local Docker daemon. If no image exists, pull/build a Rust image appropriate for Linux/aarch64. Record the image name used in `docs/linux-validation.md`.

- [ ] **Step 2: Run Linux compile/test verification**

Run in container:

```bash
cargo fmt --check
cargo clippy --all-targets --features test-util -- -D warnings
cargo test --features test-util
cargo check --examples
```

Expected: PASS.

- [ ] **Step 3: Run single-container packet smoke**

Run with `--cap-add NET_RAW --cap-add NET_ADMIN`:

```bash
cargo run --example bpf_smoke -- --interface eth0
```

Expected: open/config/read boundary ok, MTU positive, `filter_configured` false for unfiltered smoke.

- [ ] **Step 4: Run single-container runtime smoke**

Discover container `eth0` IPv4 and run:

```bash
cargo run --example runtime_smoke -- eth0 <container-ipv4> 40000
```

Expected: command loop ok, `transport_mode: kcp`, `filter_configured: true`, `payload_target` consistent with MTU.

- [ ] **Step 5: Run two-container IPv4 KCP echo**

Start server and client containers on the same Docker bridge network. Run `echo_server` in server container and `echo_client` in client container for `4096` bytes.

Expected: client sent `4096`, received `4096`, `payload_match=true`.

- [ ] **Step 6: Run explicit simple fallback smoke**

Run one echo or runtime smoke with `--transport simple`.

Expected: simple mode succeeds without changing BPF/smoltcp path.

- [ ] **Step 7: Record results**

Update `docs/linux-validation.md` with observed Docker daemon/kernel, image, interface names, container IPs, commands, and results. Update `CHANGELOG.md` to mention Linux AF_PACKET backend validation.

- [ ] **Step 8: Final verification and commit**

Run on macOS host:

```bash
cargo fmt --check
cargo clippy --all-targets --features test-util -- -D warnings
cargo test --features test-util
cargo check --examples
cargo test --doc
cargo package --allow-dirty
```

Expected: PASS.

Commit:

```bash
git add docs/linux-validation.md CHANGELOG.md
git commit -m "docs: record linux docker validation"
```
