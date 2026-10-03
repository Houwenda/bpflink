# bpflink UDP Datagram and DNS Resolver Design

## 背景

`bpflink` 当前 public API 面向可靠字节流：`Link` 拥有 BPF/smoltcp
runtime，调用方通过 `BpfStream` 和 `BpfListener` 使用 bpflink 自有的
UDP payload 协议。这个模型不能直接兼容普通 DNS server，因为 DNS 使用标准
UDP request/response payload；当前 runtime 会把非 bpflink payload 忽略掉。

本期目标是在不破坏现有 stream/KCP 行为的前提下，增加一个最小 UDP datagram
能力，并提供 `dns_resolver` example：通过 BPF 收发 UDP 包，从指定 DNS server
解析指定域名的 A/AAAA 记录。

## 目标

- 新增最小 public API：`BpfUdpSocket`。
- `BpfUdpSocket` 由现有 `Link` 创建，复用同一个 BPF backend、smoltcp stack、
  service-port filter 和 off-link route 注入能力。
- 支持从指定本地 service port 向任意 peer IP/UDP port 发送 raw UDP payload。
- 支持接收普通 UDP response payload，并返回来源 IP/port。
- 保持现有 `BpfStream` / `BpfListener` wire behavior 不变。
- 新增 `examples/dns_resolver.rs`，仅支持 DNS A、AAAA 和 both。
- DNS example 不引入 DNS crate，手写最小 DNS query/response 编解码。
- 支持 IPv4 与 IPv6 DNS server，具体可用性由所选 `local_ip` address family
  和当前 route/neighbor discovery 能力决定。

## 非目标

- 不实现完整 DNS resolver：不做 TCP fallback、递归策略、缓存、搜索域、
  DNSSEC、CNAME 递归追踪或 EDNS。
- 不新增 host route、PF/firewall、系统 DNS 配置或普通 OS UDP socket 依赖。
- 不支持动态 service-port 注册；UDP socket 只能使用 `Link` build-time
  `service_ports` 中声明过的 port。
- 不让普通 UDP datagram 进入 bpflink stream transport。

## Public API

新增导出：

```rust
pub struct BpfUdpSocket;

pub struct BpfUdpPacket {
    pub source: std::net::SocketAddr,
    pub payload: Vec<u8>,
}
```

`Link` 新增：

```rust
impl Link {
    pub async fn udp_socket(&self, service_port: u16) -> Result<BpfUdpSocket>;
}
```

`BpfUdpSocket` 提供：

```rust
impl BpfUdpSocket {
    pub fn service_port(&self) -> u16;
    pub async fn send_to(&self, payload: &[u8], peer: PeerAddr, peer_port: u16) -> Result<()>;
    pub async fn recv_from(&self) -> Result<BpfUdpPacket>;
    pub async fn recv_from_timeout(&self, timeout: std::time::Duration) -> Result<BpfUdpPacket>;
    pub fn close(&self);
}
```

语义：

- `send_to` 使用 socket 的 local service port 作为 UDP source port。
- `recv_from` 等待该 service port 上的普通 UDP datagram。
- `recv_from_timeout` 超时返回 `Error::Timeout`。
- `close` 关闭本地 handle，并唤醒 pending `recv_from`。
- `Link::shutdown` 关闭 listener、stream 和 UDP socket handles。

## Runtime 分发

`StackDriver::poll` 继续从 smoltcp UDP socket 收包，但不再要求 payload 必须是
bpflink frame。它返回该 service port 上收到的 UDP payload。

`DriverState::dispatch_udp` 负责分类：

- 如果 payload 可解码为 bpflink header，且 header service port 与实际
  service port 一致，则走现有 stream transport 分发。
- 否则将 payload 作为 raw UDP datagram 投递给该 service port 上的
  `BpfUdpSocket`。
- 如果没有对应 `BpfUdpSocket`，普通 UDP datagram 被忽略。

这样同一个 `Link` 可以在不同 service port 上同时使用 stream 和 raw UDP；同一
port 上也可以安全共存：bpflink frame 仍属于 stream，其它 payload 属于 raw UDP。

## DNS Resolver Example

文件：`examples/dns_resolver.rs`

CLI 参数：

```text
--interface <name>
--local-ip <ip-or-scoped-ip>
--local-port <u16>
--dns-server <ip-or-scoped-ip>
--dns-port <u16>         # optional, default 53
--name <domain>
--type A|AAAA|both       # optional, default both
--timeout-ms <u64>       # optional, default 3000
```

行为：

- 创建 `Link`，`service_ports([local_port])`。
- 创建 `BpfUdpSocket`。
- 对 A/AAAA 分别发送一个 DNS query。
- 等待 matching transaction id 的 response。
- 解析 answer section 中 class IN 且 type 为 A/AAAA 的记录。
- 输出格式：

```text
A 192.0.2.1
AAAA 2001:db8::1
```

错误处理：

- malformed CLI 参数返回 `Error::Config`。
- timeout 返回 `Error::Timeout`。
- DNS rcode 非 0、transaction id 不匹配、问题/答案截断返回
  `Error::PacketParse`。

## 测试策略

- `tests/link_api.rs` 覆盖 `Link::udp_socket` 的 service port 校验和 test-util
  fake routing。
- `tests/async_api.rs` 覆盖 `BpfUdpSocket::send_to` / `recv_from_timeout` 的
  async 行为和 close 唤醒。
- `src/stack/smoltcp_driver.rs` 单元测试覆盖普通 UDP payload 不被 stack 层丢弃。
- `src/runtime.rs` 单元测试覆盖普通 UDP response 投递到 datagram socket，且
  bpflink frame 仍走 stream dispatch。
- `examples/dns_resolver.rs` 自带 DNS 编解码测试：A、AAAA、name compression、
  rcode、transaction id mismatch、truncated answer。
- 发布前跑：
  - `cargo fmt --check`
  - `cargo test --features test-util`
  - `cargo test --examples`
  - `cargo check --examples`
  - `cargo clippy --all-targets --features test-util -- -D warnings`
  - `cargo doc --no-deps`
  - `git diff --check`
