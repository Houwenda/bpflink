# bpflink BPF Transport 实施计划

> **给 agentic workers：** 必须使用子技能：推荐 `superpowers:subagent-driven-development`，或使用 `superpowers:executing-plans` 逐任务执行本计划。步骤使用 checkbox（`- [ ]`）语法跟踪。

**目标：** 构建第一版可在 macOS 上验证的 `bpflink` Rust crate，包含由 `Link` 持有的 BPF runtime、smoltcp IPv4/UDP 栈、简单可靠 transport，以及 `BpfStream` / `BpfListener` async API。

**架构：** `Link` 拥有 BPF 设备、smoltcp interface、transport sessions、listener registry 和 driver thread。`BpfStream` 与 `BpfListener` 是轻量 handle，通过 channel 和 waker 与 `Link` driver 通信；socket 不直接打开 BPF。wire protocol 是 smoltcp IPv4/Ethernet 上的 UDP payload，不是 TCP wire protocol。

**技术栈：** Rust 2021、Tokio、smoltcp、libc、thiserror、tracing、表驱动单元测试或 proptest、macOS `/dev/bpfN` 作为第一版 runtime backend。

**Spec：** `docs/superpowers/specs/2026-09-26-bpflink-bpf-transport-design.md`

> 当前平台策略更新：本早期计划中的 BSD/Linux 编译边界属于历史阶段。
> 当前代码和发布边界已收敛为仅支持 macOS 与 Linux；Windows 是后续支持目标；
> BSD、iOS、tvOS 和其他系统不再作为支持或预留边界。
>
> 当前 API 更新：本早期计划中的单端口 `service_port(...)` builder 形态已被
> `service_ports([...])` build-time 端口集合取代。历史任务正文保留当时设计，
> 以便追溯，不作为当前 API 参考。

## 全局约束

- 当前支持目标收敛为 macOS 与 Linux；Windows 是后续目标，其他系统不支持。
- BPF 是唯一 packet backend；不要添加 TUN、TAP、AF_PACKET 或通用 backend 抽象。
- Public API 命名使用 `Link`、`BpfStream`、`BpfListener`。
- `Link` 拥有 `BpfDevice`；stream/listener handle 不能直接打开、复制或关闭 BPF fd。
- API 必须接受接口名，例如 `Link::builder().interface("en0")`。
- 第一版要求调用方传入 `local_ipv4`。
- 第一版将 `service_port` 同时作为 smoltcp UDP port 和 bpflink 逻辑服务号；后续如需拆分另起设计。
- 第一版 IPv4-only，IPv6/NDP 作为计划目标后置。
- 复用宿主 IPv4，并接受 Darwin ICMP Port Unreachable；相关 ICMP 不能 reset session。
- 不实现 TCP wire protocol，也不使用 smoltcp TCP。
- 本计划不实现 transport 内加密。
- 使用 `MIT OR Apache-2.0`；明显改编自 `pnet_datalink` 的文件必须保留 attribution。
- 避免依赖 IP fragmentation；默认 transport payload 目标大小是 1200 bytes。

## Review Focus

- 接口名无效或缺失：`Link::builder().build()` 必须在启动 driver 前返回 typed error。
- 多个 stream/listener 共享一个 `Link`：测试必须证明只有 `Link` 拥有 BPF runtime state，handle 都通过 driver command 工作。
- malformed UDP payload header：stack 必须 drop，不能 panic，也不能影响其他 session。
- 相关 ICMP Port Unreachable：stack 必须计数并忽略，不能 reset session。
- 超大应用写入：transport 必须分片或稳定拒绝，不能发出超过 1200-byte 目标大小的 payload。

---

## 文件结构

- `Cargo.toml`：crate 元数据、features、依赖、license。
- `LICENSE-MIT`、`LICENSE-APACHE`：许可证文件。
- `src/lib.rs`：public exports 和 crate docs。
- `src/error.rs`：共享错误类型。
- `src/link.rs`：`Link`、`LinkBuilder`、public connect/listen API、driver 生命周期。
- `src/runtime.rs`：内部 driver thread command、event、shutdown。
- `src/bpf/mod.rs`：平台模块选择和 crate 内部 `BpfDevice` 接口。
- `src/bpf/frame.rs`：BPF read buffer 的 frame iterator。
- `src/bpf/ioctl.rs`：macOS ioctl 常量和 wrapper。
- `src/bpf/macos.rs`：macOS `/dev/bpfN` open/configure/read/write 实现。
- `src/bpf/linux.rs`：Linux `AF_PACKET/SOCK_RAW` packet I/O 与 classic BPF socket filter 实现。
- `src/stack/mod.rs`：stack exports。
- `src/stack/device.rs`：基于 `BpfDevice` 的 smoltcp `Device` adapter。
- `src/stack/smoltcp_driver.rs`：smoltcp interface 和 UDP socket polling。
- `src/stack/udp.rs`：UDP socket helper 和 send/receive 小工具。
- `src/stack/icmp.rs`：ICMP Port Unreachable 分类。
- `src/transport/mod.rs`：transport exports。
- `src/transport/header.rs`：bpflink UDP payload header encode/decode。
- `src/transport/session.rs`：session id、session state、driver-facing operations。
- `src/transport/kcp.rs`：第一版 reliable-stream 实现，保持可替换；可以先用极简实现，但文件边界按 KCP/可靠层预留。
- `src/transport/timers.rs`：retransmit/keepalive timing helper。
- `src/socket/mod.rs`：socket exports。
- `src/socket/stream.rs`：`BpfStream` handle 和 `AsyncRead` / `AsyncWrite`。
- `src/socket/listener.rs`：`BpfListener` handle 和 `accept`。
- `examples/echo_server.rs`：macOS 手动验证 server。
- `examples/echo_client.rs`：macOS 手动验证 client。
- `tests/`：只放 public API integration tests；crate-internal 行为使用各模块内的 `#[cfg(test)]` unit tests，避免 integration tests 访问 `pub(crate)` 接口。

## Task 1：Crate 骨架和 Public API Shell

**Files：**
- Create: `Cargo.toml`
- Create: `LICENSE-MIT`
- Create: `LICENSE-APACHE`
- Create: `src/lib.rs`
- Create: `src/error.rs`
- Create: `src/link.rs`
- Create: `src/runtime.rs`
- Create: `src/socket/mod.rs`
- Create: `src/socket/stream.rs`
- Create: `src/socket/listener.rs`
- Test: `tests/link_api.rs`

**Interfaces：**
- Produces: `pub struct Link`、`pub struct LinkBuilder`、`pub struct BpfStream`、`pub struct BpfListener`、`pub enum Error`、`pub type Result<T>`。
- Produces: `impl Link { pub fn builder() -> LinkBuilder; pub async fn connect(&self, peer: PeerAddr, service_port: u16) -> Result<BpfStream>; pub async fn listen(&self, service_port: u16) -> Result<BpfListener>; }`
- Produces: `pub struct PeerAddr { pub ip: std::net::Ipv4Addr }`。
- Produces: `impl LinkBuilder { pub fn interface(self, name: impl Into<String>) -> Self; pub fn local_ipv4(self, addr: Ipv4Addr) -> Self; pub fn service_port(self, port: u16) -> Self; pub async fn build(self) -> Result<Link>; }`
- Produces: `pub enum Error { Config(&'static str), Io(std::io::Error), PacketParse(&'static str), UnsupportedPlatform(&'static str), PayloadTooLarge { len: usize, max: usize }, DriverClosed, Timeout }`。

- [ ] **Step 1：写 failing public API tests**

创建 `tests/link_api.rs`，包含：

```rust
#[tokio::test]
async fn builder_requires_interface_local_ip_and_service_port() {
    // 缺少任一 required field 时返回 Error::Config。
}

#[tokio::test]
async fn stream_and_listener_are_created_from_link_handles() {
    // 使用 test-only Link::new_for_test() 证明 listen/connect 提交 driver command，
    // 且不会直接构造 BPF。
}
```

- [ ] **Step 2：运行测试并确认失败**

Run: `cargo test --features test-util --test link_api`

Expected: FAIL，因为 crate 文件和 API 尚不存在。

- [ ] **Step 3：实现 crate skeleton**

创建上述文件。`LinkBuilder::build()` 校验 required fields，缺失时返回 `Error::Config`；字段齐全时先返回 `Error::UnsupportedPlatform("runtime not implemented yet")`，Task 6 再替换为真实 driver 启动。在 `Cargo.toml` 增加只供测试使用的 `test-util` feature，并增加 `#[cfg(feature = "test-util")] pub fn Link::new_for_test(...) -> Link`，使用 in-memory channels 而不是 BPF。

- [ ] **Step 4：实现 socket handle shell**

`BpfStream` 和 `BpfListener` 只保存 id、channel、waker 状态；不包含 fd-like 字段，也不 import `crate::bpf`。

- [ ] **Step 5：运行测试**

Run: `cargo test --features test-util --test link_api`

Expected: PASS。

- [ ] **Step 6：Commit**

```bash
git add Cargo.toml LICENSE-MIT LICENSE-APACHE src tests/link_api.rs
git commit -m "feat: add bpflink public api shell"
```

## Task 2：BPF Frame Parsing 和平台边界

**Files：**
- Create: `src/bpf/mod.rs`
- Create: `src/bpf/frame.rs`
- Create: `src/bpf/ioctl.rs`
- Create: `src/bpf/macos.rs`
- Create: `src/bpf/linux.rs`
- Test: `src/bpf/frame.rs` 内的 `#[cfg(test)]` unit tests

**Interfaces：**
- Consumes: `crate::Error`、`crate::Result`。
- Produces: `pub(crate) trait FrameIo { fn read_frames(&mut self, out: &mut Vec<Vec<u8>>) -> Result<usize>; fn write_frame(&mut self, frame: &[u8]) -> Result<()>; fn mtu(&self) -> usize; }`。这是 crate-private 测试接缝，不是 public backend abstraction。
- Produces: `pub(crate) struct BpfDevice`。
- Produces: `impl BpfDevice { pub(crate) fn open(interface: &str) -> Result<Self>; }`
- Produces: `impl FrameIo for BpfDevice`。
- Produces: `pub(crate) fn iter_bpf_frames(buf: &[u8]) -> impl Iterator<Item = Result<&[u8]>>`。

- [ ] **Step 1：写 failing frame parser tests**

在 `src/bpf/frame.rs` 内添加 `#[cfg(test)] mod tests`，构造 synthetic BPF read buffer：

```rust
#[test]
fn bpf_frame_iterates_multiple_frames_with_padding() {
    // 两个 fake bpf_hdr record，带 padding，最终 yield 两个 frame byte slices。
}

#[test]
fn bpf_frame_rejects_truncated_header_or_frame() {
    // 截断 header/frame 时返回 Error::PacketParse，不能 panic。
}
```

- [ ] **Step 2：运行测试并确认失败**

Run: `cargo test bpf_frame`

Expected: FAIL，因为 `src/bpf/frame.rs` 尚不存在。

- [ ] **Step 3：实现 `src/bpf/frame.rs`**

按照 macOS `bpf_hdr` 解析 BPF header，使用 `BPF_WORDALIGN` 对齐每个 record。截断 buffer 返回 `Error::PacketParse`。

- [ ] **Step 4：实现平台模块边界**

`src/bpf/mod.rs` 在 `target_os = "macos"` 选择 `macos`，在 `target_os = "linux"` 选择 `linux`，其他系统不导出 runtime backend 并返回 `Error::UnsupportedPlatform`。

- [ ] **Step 5：实现 macOS BPF open/configure/read/write**

在 `src/bpf/macos.rs` 实现 `/dev/bpfN` open loop 和 ioctl setup：`BIOCSETIF`、runtime 路径 `BIOCSETF(service_port)`、`BIOCIMMEDIATE`、`BIOCSHDRCMPLT`、`BIOCSSEESENT(true)` 并容忍 `EINVAL` 降级、`BIOCGBLEN`、nonblocking fd。明显改编自 `pnet_datalink` 的文件加入 attribution header。

- [ ] **Step 6：运行 parser tests 和 compile check**

Run: `cargo test bpf_frame`

Expected: PASS。

Run: `cargo check`

Expected: macOS 上 PASS。

- [ ] **Step 7：Commit**

```bash
git add src/bpf src/error.rs
git commit -m "feat: add macos bpf device foundation"
```

## Task 3：smoltcp Device 和 IPv4 UDP Driver

**Files：**
- Create: `src/stack/mod.rs`
- Create: `src/stack/device.rs`
- Create: `src/stack/smoltcp_driver.rs`
- Create: `src/stack/udp.rs`
- Modify: `src/link.rs`
- Test: `src/stack/device.rs` 内的 `#[cfg(test)]` unit tests

**Interfaces：**
- Consumes: `FrameIo::read_frames`、`FrameIo::write_frame`、`FrameIo::mtu`。
- Produces: `pub(crate) struct StackDriver<D: FrameIo>`。
- Produces: `pub(crate) enum PollOutcome { Idle, ReceivedUdp { src: Ipv4Addr, src_port: u16, payload: Vec<u8> }, IgnoredIcmp }`。
- Produces: `impl<D: FrameIo> StackDriver<D> { pub(crate) fn new(config: StackConfig, device: D) -> Result<Self>; pub(crate) fn poll(&mut self, now: smoltcp::time::Instant) -> Result<PollOutcome>; pub(crate) fn send_udp(&mut self, dst: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Result<()>; }`
- Produces: `pub(crate) struct StackConfig { pub local_ipv4: Ipv4Addr, pub service_port: u16, pub ethernet_addr: smoltcp::wire::EthernetAddress }`。

- [ ] **Step 1：写 failing smoltcp device tests**

在 `src/stack/device.rs` 内添加 `#[cfg(test)] mod tests`，使用 fake in-memory `FrameIo`：

```rust
#[test]
fn stack_device_capabilities_are_ethernet_with_configured_mtu() {
    // Stack device reports Medium::Ethernet 和 fake MTU。
}

#[test]
fn stack_device_tx_writes_complete_ethernet_frame_to_device() {
    // 通过 TxToken 发送时，fake device output 记录一个完整 Ethernet frame。
}
```

- [ ] **Step 2：运行测试并确认失败**

Run: `cargo test stack_device`

Expected: FAIL，因为 stack modules 尚不存在。

- [ ] **Step 3：实现 `stack::device`**

把 BPF frame queue 包装成 smoltcp `Device`。RX 每个 token 消费一个 queued Ethernet frame；TX 每个 token 写出一个完整 Ethernet frame。

- [ ] **Step 4：实现最小 IPv4 UDP `StackDriver`**

构造 Ethernet/IPv4 smoltcp `Interface`，安装 local IPv4 address，创建 configured service port 的 UDP socket state，并暴露 `send_udp`。

- [ ] **Step 5：运行测试和 compile check**

Run: `cargo test stack_device`

Expected: PASS。

Run: `cargo check`

Expected: PASS。

- [ ] **Step 6：Commit**

```bash
git add src/stack src/link.rs Cargo.toml
git commit -m "feat: add smoltcp ipv4 udp driver"
```

## Task 4：UDP Header 和 ICMP 分类

**Files：**
- Create: `src/transport/mod.rs`
- Create: `src/transport/header.rs`
- Create: `src/stack/icmp.rs`
- Modify: `src/stack/smoltcp_driver.rs`
- Test: `src/transport/header.rs` 内的 `#[cfg(test)]` unit tests
- Test: `src/stack/icmp.rs` 内的 `#[cfg(test)]` unit tests

**Interfaces：**
- Produces: `pub(crate) struct BpflinkHeader { pub packet_type: PacketType, pub service_port: u16, pub connection_id: u64, pub stream_id: u32 }`。
- Produces: `impl BpflinkHeader { pub const MAGIC: [u8; 4]; pub const VERSION: u8; pub fn encode(&self, payload: &[u8], out: &mut Vec<u8>) -> Result<()>; pub fn decode(bytes: &[u8]) -> Result<(Self, &[u8])>; }`
- Produces: `pub(crate) enum PacketType { Connect, Accept, Data, Fin, Reset, Ping }`。
- Produces: `pub(crate) fn classify_icmp_unreachable(ipv4_packet: &[u8], service_port: u16) -> IcmpDisposition`。
- Produces: `pub(crate) const DEFAULT_PAYLOAD_TARGET: usize = 1200`。

- [ ] **Step 1：写 failing header tests**

在 `src/transport/header.rs` 内添加 `#[cfg(test)] mod tests`：

```rust
#[test]
fn transport_header_round_trips_with_payload() {
    // Encode 再 decode 后保留 packet_type、service_port、connection_id、stream_id 和 payload。
}

#[test]
fn transport_header_malformed_magic_version_or_short_header_is_rejected() {
    // Decode 返回 Error::PacketParse。
}
```

- [ ] **Step 2：写 failing ICMP tests**

在 `src/stack/icmp.rs` 内添加 `#[cfg(test)] mod tests`：

```rust
#[test]
fn icmp_related_port_unreachable_is_ignored() {
    // ICMP 引用 configured service_port 时返回 IcmpDisposition::IgnoreAndCount。
}
```

- [ ] **Step 3：运行测试并确认失败**

Run: `cargo test transport_header`

Expected: FAIL，因为 header module 尚不存在。

Run: `cargo test icmp_`

Expected: FAIL，因为 ICMP module 尚不存在。

- [ ] **Step 4：实现 header encode/decode**

使用固定大小 network-order 字段：magic、version、packet_type、service_port、connection_id `u64`、stream_id `u32`，之后是 payload。

- [ ] **Step 5：实现 ICMP classifier**

解析足够的 IPv4/ICMP，识别 Destination Unreachable / Port Unreachable，并检查 quoted UDP destination port 是否是本 crate service port。相关 ICMP 返回 `IgnoreAndCount`。

- [ ] **Step 6：导出 payload target 常量**

在 transport 层导出 `DEFAULT_PAYLOAD_TARGET = 1200`。不要让 `stack` 层依赖该常量；应用写入的分片或拒绝逻辑由 Task 5 的 reliable layer 负责。

- [ ] **Step 7：运行测试**

Run: `cargo test transport_header`

Expected: PASS。

Run: `cargo test icmp_`

Expected: PASS。

- [ ] **Step 8：Commit**

```bash
git add src/transport src/stack
git commit -m "feat: add bpflink udp header and icmp handling"
```

## Task 5：Reliable Session Engine

**Files：**
- Create: `src/transport/session.rs`
- Create: `src/transport/kcp.rs`
- Create: `src/transport/timers.rs`
- Modify: `src/runtime.rs`
- Test: `src/transport/session.rs` 内的 `#[cfg(test)]` unit tests

**Interfaces：**
- Consumes: `BpflinkHeader`、`PacketType`、`DEFAULT_PAYLOAD_TARGET`。
- Produces: `pub(crate) type ConnectionId = u64`。
- Produces: `pub(crate) struct SessionId(pub(crate) u64)`。
- Produces: `pub(crate) struct ReliableSession`。
- Produces: `pub(crate) enum SessionEvent { Established, DataAvailable, Closed, Reset }`。
- Produces: `impl ReliableSession { pub(crate) fn connect(peer: PeerAddr, service_port: u16, now: std::time::Instant) -> Self; pub(crate) fn on_packet(&mut self, header: BpflinkHeader, payload: &[u8], now: std::time::Instant) -> Result<SessionEvent>; pub(crate) fn write(&mut self, bytes: &[u8]) -> Result<usize>; pub(crate) fn read(&mut self, out: &mut [u8]) -> Result<usize>; pub(crate) fn poll_output(&mut self, now: std::time::Instant, out: &mut Vec<Vec<u8>>) -> Result<()>; }`
- Produces: 每个输出 datagram 不超过 `DEFAULT_PAYLOAD_TARGET`。

- [ ] **Step 1：写 failing reliable session tests**

在 `src/transport/session.rs` 内添加 `#[cfg(test)] mod tests`：

```rust
#[test]
fn reliable_session_connect_accept_establishes_session_ids() {
    // Client connect packet 和 server accept packet 让两端进入 Established。
}

#[test]
fn reliable_session_ordered_data_is_read_after_delivery() {
    // 一端写入的 DATA packet payload 可在另一端按序读出。
}

#[test]
fn reliable_session_large_write_is_segmented_to_payload_target() {
    // 写入超过 DEFAULT_PAYLOAD_TARGET 的数据会产生多个 datagram，且都不超限。
}
```

- [ ] **Step 2：运行测试并确认失败**

Run: `cargo test reliable_session`

Expected: FAIL，因为 reliable session modules 尚不存在。

- [ ] **Step 3：实现最小 reliable session**

先用简单 stop-and-wait 或 KCP-backed engine。上面的 crate-internal interface 保持稳定；如果使用 `kcp-core`，只封装在 `transport/kcp.rs` 内部。

- [ ] **Step 4：实现 session timers**

增加 retransmit 和 keepalive timer helper，满足测试和 driver polling。向 `runtime` 暴露 next-deadline calculation。

- [ ] **Step 5：运行测试**

Run: `cargo test reliable_session`

Expected: PASS。

- [ ] **Step 6：Commit**

```bash
git add src/transport src/runtime.rs Cargo.toml
git commit -m "feat: add reliable bpflink sessions"
```

## Task 6：Link Driver 和 Async Socket API

**Files：**
- Modify: `src/link.rs`
- Modify: `src/runtime.rs`
- Modify: `src/socket/stream.rs`
- Modify: `src/socket/listener.rs`
- Create: `examples/echo_server.rs`
- Create: `examples/echo_client.rs`
- Test: `tests/async_api.rs`

**Interfaces：**
- Consumes: `StackDriver`、`ReliableSession`、`BpflinkHeader`。
- Produces: `impl tokio::io::AsyncRead for BpfStream`。
- Produces: `impl tokio::io::AsyncWrite for BpfStream`。
- Produces: `impl BpfListener { pub async fn accept(&self) -> Result<BpfStream>; }`。
- Produces: driver commands `Listen`、`Connect`、`StreamWrite`、`StreamReadPoll`、`Close`。

- [ ] **Step 1：写 failing async API tests**

创建 `tests/async_api.rs`，使用 `test-util` feature 暴露的 in-memory driver：

```rust
#[tokio::test]
async fn listener_accepts_stream_from_shared_link() {
    // link.listen() 和 link.connect() 使用同一个 driver，并产生 connected handles。
}

#[tokio::test]
async fn stream_async_read_write_round_trips_bytes() {
    // 一个 BpfStream 的 AsyncWrite 可从 peer 读出。
}

#[tokio::test]
async fn dropping_stream_does_not_shutdown_link_or_other_streams() {
    // drop 第一个 stream 后，第二个 stream/listener 仍可工作。
}
```

- [ ] **Step 2：运行测试并确认失败**

Run: `cargo test --features test-util --test async_api`

Expected: FAIL，因为 driver 和 async traits 尚未完成。

- [ ] **Step 3：实现 driver thread lifecycle**

`LinkBuilder::build()` 打开 `BpfDevice`，构建 `StackDriver`，启动 driver thread，并返回 `Link`。`Link` 只持有创建 handle 所需的 driver channels 和 shared state。

- [ ] **Step 4：实现 `listen` 和 `connect`**

`Link::listen(service_port)` 注册 listener。`Link::connect(peer, service_port)` 创建 session，发送初始 connect packet，并在 established 后返回 `BpfStream`，超时则返回 error。

- [ ] **Step 5：实现 async stream traits**

`BpfStream::poll_read`、`poll_write`、`poll_flush`、`poll_shutdown` 通过 channel 和 waker 与 driver/session state 通信，不能直接访问 BPF。

- [ ] **Step 6：实现 examples**

`examples/echo_server.rs` 接受 `--interface`、`--local-ipv4`、`--service-port`。`examples/echo_client.rs` 接受相同参数，并增加 `--peer-ipv4`，发送单次 echo payload。

- [ ] **Step 7：运行 async API tests**

Run: `cargo test --features test-util --test async_api`

Expected: PASS。

- [ ] **Step 8：运行完整自动检查**

Run: `cargo test --features test-util`

Expected: PASS。

Run: `cargo check --examples`

Expected: PASS。

- [ ] **Step 9：Commit**

```bash
git add src examples tests/async_api.rs Cargo.toml
git commit -m "feat: expose async bpflink stream api"
```

## Task 7：macOS 手动验证和文档

**Files：**
- Create: `README.md`
- Create: `docs/macos-validation.md`
- Modify: `examples/echo_server.rs`
- Modify: `examples/echo_client.rs`

**Interfaces：**
- Consumes: example binaries 和 `Link` public API。
- Produces: 两台 macOS 机器或两个可达接口的手动验证流程。

- [ ] **Step 1：写验证文档**

记录 prerequisites、权限、示例命令、预期日志和已知 Darwin ICMP 行为。

- [ ] **Step 2：给 examples 增加 tracing**

examples 记录 interface、local IPv4、service port、peer、bytes sent/received、related ICMP count 和 shutdown。

- [ ] **Step 3：运行静态检查**

Run: `cargo test --features test-util`

Expected: PASS。

Run: `cargo check --examples`

Expected: PASS。

- [ ] **Step 4：在硬件/网络条件具备时运行 macOS smoke**

Run server:

```bash
cargo run --example echo_server -- --interface en0 --local-ipv4 <server-ip> --service-port 40000
```

Run client:

```bash
cargo run --example echo_client -- --interface en0 --local-ipv4 <client-ip> --service-port 40000 --peer-ipv4 <server-ip>
```

Expected: client 收到 echo payload。如果权限或网络设置阻塞验证，把确切错误记录到 `docs/macos-validation.md`。

- [ ] **Step 5：Commit**

```bash
git add README.md docs/macos-validation.md examples
git commit -m "docs: add macos bpflink validation flow"
```

## 自审

### Spec 覆盖

- macOS-first BPF runtime：Task 2、3、6、7。
- BPF-only 且不做 generic backend：Task 2 和全局约束。
- 接口名和 caller-provided IPv4：Task 1 和 6。
- `Link` 拥有 BPF，socket 是 handle：Task 1 和 6，并有 Review Focus 测试。
- IPv4 smoltcp UDP：Task 3。
- UDP payload header 且不做 TCP wire protocol：Task 4。
- ICMP Port Unreachable ignore 行为：Task 4。
- reliable stream 和 payload size handling：Task 5。
- async `BpfStream` / `BpfListener`：Task 6。
- macOS 手动验证：Task 7。

没有刻意留下未覆盖的 spec requirement。

### Step scan

每个 task 都有 failing-test step、implementation step、verification step 和 commit step。步骤包含后续任务依赖的精确文件路径和 public/internal signatures。

### Type consistency

计划一致使用 `Link`、`LinkBuilder`、`BpfStream`、`BpfListener`、`PeerAddr`、`BpfDevice`、`FrameIo`、`StackDriver`、`PollOutcome`、`BpflinkHeader`、`ReliableSession`、`SessionId`、`ConnectionId`、`SessionEvent`。

### Review Focus 映射

- 接口名无效或缺失：Task 1 `builder_requires_interface_local_ip_and_service_port`。
- 多个 stream/listener 共享一个 `Link`：Task 6 `listener_accepts_stream_from_shared_link` 和 `dropping_stream_does_not_shutdown_link_or_other_streams`。
- malformed UDP payload header：Task 4 `transport_header_malformed_magic_version_or_short_header_is_rejected`。
- 相关 ICMP Port Unreachable：Task 4 `icmp_related_port_unreachable_is_ignored`。
- 超大应用写入：Task 5 `reliable_session_large_write_is_segmented_to_payload_target`。

### Proportion

计划定义阶段、文件、signature 和测试，不嵌入完整实现。它比 spec 更长，因为需要把第一版实现拆成可独立 review 的任务，但没有把代码正文转录进计划。
