# bpflink BPF 用户态 Transport 设计

日期：2026-09-26

> 当前平台策略更新：本设计中的 BSD/Linux 编译边界表述属于早期阶段记录。
> 当前代码和发布边界已收敛为仅支持 macOS 与 Linux；Windows 是后续支持目标；
> BSD、iOS、tvOS 和其他系统不再作为支持或预留边界。
>
> 当前 API 更新：本文中出现的单端口 `service_port(...)` 示例属于历史记录。
> 当前 public API 要求在构建 `Link` 时通过 `service_ports([...])` 声明完整端口集合，
> `listen(port)` / `connect(peer, port)` 只能使用已声明端口。

## 目标

`bpflink` 是一个 Rust crate，用 BPF 作为底层 packet I/O，在用户态实现基于 UDP wire protocol 的可靠 stream transport。当前支持面已收敛为 macOS 与 Linux；Windows 是后续支持目标，其他系统不支持。

对外接口提供 TCP-like async API，而不是 TCP wire protocol：

- `Link`：运行时入口，负责打开接口、驱动 BPF、smoltcp 和 transport。
- `BpfStream`：实现 `tokio::io::AsyncRead` 和 `tokio::io::AsyncWrite`。
- `BpfListener`：接受远端 `BpfStream`。
- 后续可增加 `BpfUdpSocket`，但不是第一阶段必须项。

`Link` 是 BPF 设备和网络栈运行时的所有者。`BpfStream`、`BpfListener` 不直接打开 BPF 设备，而是由 `Link` 创建的轻量 handle。一个 `Link` 可以创建多个 stream 和 listener；每个 socket 单独创建 BPF 设备是明确非目标。

本期成功标准：

1. 在 macOS 上通过接口名，例如 `en0`，打开 BPF 设备。
2. 复用宿主 IP 地址，通过 BPF 发送和接收 Ethernet frame；macOS 验证从
   IPv4 起步，并扩展到显式 IPv6 地址。
3. 使用 smoltcp 处理 Ethernet、ARP/NDP、IPv4/IPv6、UDP。
4. 在 UDP payload 内运行 KCP 或更简单的可靠 transport。
5. 对外提供 `BpfStream` async stream API，能跑 echo 验证。
6. 多个 `BpfStream` / `BpfListener` 共享同一个 `Link` 和同一个 BPF 运行时。
7. 接受 Darwin 可能产生 ICMP Port Unreachable，并在本协议栈内忽略相关 ICMP 错误。

## 非目标

第一版不做这些事情：

- 不实现标准 TCP wire protocol。
- 不使用 smoltcp TCP 作为主传输。
- 不支持 TUN、TAP、AF_PACKET 或其他非 BPF backend。
- 不修改 PF、防火墙规则、系统路由或系统网络配置。
- 不保证隔离宿主 Darwin TCP/IP stack。
- 不实现完整 QUIC。
- 不实现 dual-stack 自动选择或自动地址发现；IPv6 使用调用方显式传入的本机
  地址和 peer 地址。
- 不支持 Windows、BSD、iOS、tvOS 或其他非 macOS/Linux 系统；Windows 是后续支持目标。

## 已确认决策

### BPF 是项目核心

本项目不是一个通用 packet backend 抽象库。BPF 是关键目标，其他设备类型与本项目无关。

因此内部可以有很薄的平台边界：

```text
src/bpf/
  mod.rs
  macos.rs      // 第一版实现
  linux.rs      // 后续实现 Linux AF_PACKET + classic BPF socket filter
  ioctl.rs
  frame.rs
```

但不设计 `TunDevice`、`TapDevice`、`AfPacketDevice` 等通用 backend。

### 第一版在 macOS 上开发验证

当前平台策略已收敛为只支持 macOS 与 Linux：

- `target_os = "macos"`：实现 `/dev/bpfN` 打开、ioctl、read/write。
- `target_os = "linux"`：实现 `AF_PACKET/SOCK_RAW` packet I/O，并使用
  classic BPF socket filter。
- Windows：后续支持目标。
- BSD、iOS、tvOS 和其他系统：不支持，也不保留预留模块边界。

早期“BSD/Linux 编译边界”的表述已被上述平台策略取代。

### 地址模型复用宿主 IP

第一版复用宿主接口 IP 地址，不创建独立 userspace IP，也不修改系统路由。
最初的验证从 IPv4 开始；当前阶段增加 macOS 上的显式 IPv6 验证。

这意味着：

- Darwin 仍会看到入站 UDP packet。
- 对 IPv4，如果没有对应系统 UDP socket，Darwin 可能产生 ICMP Port
  Unreachable。
- 本协议栈不依赖这些 ICMP 错误，也不会把相关 ICMP 错误作为 session 终止信号。
- 对 IPv6，BPF filter 必须保留 ICMPv6，以免破坏 Neighbor Discovery。

这是有意接受的风险，不在第一版中尝试压制。

### API 必须支持传入接口名

`Link` 初始化必须允许调用方指定接口名：

```rust
let link = Link::builder()
    .interface("en0")
    .local_ip(local_ip)
    .service_port(40000)
    .build()
    .await?;

let listener = link.listen(443).await?;
let stream = link.connect(peer_addr, 443).await?;
```

第一版要求调用方显式传入本机 IP，避免实现期依赖复杂的平台地址枚举。IPv4
兼容 API 使用 `local_ipv4`；IPv6 使用 `local_ipv6` 或通用 `local_ip`。后续
可以增加自动发现。

### `Link` 持有 BPF 设备

`BpfDevice` 的所有权属于 `Link`。`Link` 内部持有：

- BPF fd / frame I/O。
- smoltcp `Interface` 和 UDP socket。
- transport session table。
- listener registry。
- driver thread。

`BpfStream` 和 `BpfListener` 只保存与 `Link` driver 通信所需的 channel、session id、service id 和 waker 状态。它们不能直接创建、复制或关闭底层 BPF fd。

推荐使用模式：

```rust
let link = Link::builder()
    .interface("en0")
    .local_ip(local_ip)
    .service_port(40000)
    .build()
    .await?;

let listener = link.listen(443).await?;

tokio::spawn(async move {
    loop {
        let stream = listener.accept().await?;
        tokio::spawn(handle_stream(stream));
    }
});

let outbound = link.connect(peer_addr, 443).await?;
```

如果一个进程需要绑定多个网络接口，应显式创建多个 `Link`，例如一个 `Link` 绑定 `en0`，另一个 `Link` 绑定 `en1`。

### IPv4 起步，当前阶段支持显式 IPv6

第一版最初只验证：

- Ethernet
- ARP
- IPv4
- UDP

当前阶段已把 macOS IPv6 纳入实现和实机验证目标：

- NDP
- IPv6
- ICMPv6
- UDPv6

代码边界上不应把 IPv4 写死进 transport core。可靠 transport 的 session、
KCP、stream API 使用 `IpAddr` 承载 peer/local 地址。IPv6 第一阶段不做
dual-stack 自动选择。BPF filter 放行 ICMPv6、无 extension header 的 UDPv6
service traffic，以及单个 8-byte Hop-by-Hop、Routing 或 Destination Options
extension header 后的 UDPv6 service traffic；IPv6 Fragment header 继续丢弃。

### 内部线程驱动，外部 async API

crate 对外暴露 async API，但内部使用专用 driver thread 驱动网络栈：

```text
Application async tasks
  ↓ channels / wakers
BpfStream / BpfListener
  ↓
Link driver thread
  ↓
Transport sessions
  ↓
smoltcp UDP socket
  ↓
BpfDevice
```

第一版选择“内部线程 + channel + waker”的实现方式，降低 BPF fd readiness、smoltcp poll model 和 KCP timer 混在 Tokio task 内的复杂度。后续如果确认 Tokio `AsyncFd` 对 BPF fd 足够稳定，再考虑迁移为 dedicated runtime task。

## 架构

```text
Application
  ↓ AsyncRead / AsyncWrite
BpfStream / BpfListener
  ↓
Link
  ↓
KCP 或极简可靠 stream
  ↓
bpflink UDP payload header
  ↓
smoltcp UDP / IPv4 / ARP / Ethernet
  ↓
BpfDevice
  ↓
/dev/bpfN
  ↓
en0
```

### 分层职责

`socket` 层：

- 提供 `BpfStream` 和 `BpfListener`。
- 实现 async read/write。
- 不暴露 KCP、smoltcp、BPF 细节。
- 不持有 BPF fd；只通过 `Link` driver 管理的 channel 和 session/listener handle 工作。

`link` 层：

- 拥有 `BpfDevice`、smoltcp driver、transport sessions 和 listener registry。
- 从 public API 创建 `BpfStream` 和 `BpfListener`。
- 保证多个 socket 共享同一个 BPF runtime。

`transport` 层：

- 第一版使用 `kcp-core` 或等价的极简可靠流。
- 负责连接 ID、service port、可靠有序字节流、关闭/reset。
- 不实现 TCP wire compatibility。

`stack` 层：

- 管理 smoltcp `Interface`、UDP socket、ARP cache、poll timing。
- 从 BPF 收到 Ethernet frame 后交给 smoltcp。
- 从 transport 收到 UDP payload 后交给 smoltcp 发出。

`bpf` 层：

- 打开和配置 BPF 设备。
- 绑定接口名。
- 解析 BPF read buffer 中的多个 `bpf_hdr + frame`。
- 写出完整 Ethernet frame。
- 提供 smoltcp `Device` 所需的 RX/TX token。

## BPF 实现策略

`BpfDevice` 自研实现，参考 `pnet_datalink` 的 BPF 实现，而不是直接以 `pnet_datalink` 公开 API 作为核心依赖。

原因：

- `bpflink` 需要控制 smoltcp `Device` token 生命周期。
- `bpflink` 需要控制内部线程、waker、统计、过滤和 ICMP 处理。
- `pnet_datalink` 的公开抽象是 datalink channel，不是为本项目的 smoltcp + transport runtime 定制。

macOS 初始化流程参考：

```text
open /dev/bpfN
BIOCSETIF(interface)
BIOCSETF(service_port)
BIOCIMMEDIATE
BIOCSHDRCMPLT
BIOCSSEESENT(true, tolerate EINVAL)
BIOCGBLEN
fcntl(O_NONBLOCK)
```

实际实现时需要根据 macOS BPF 行为确认 ioctl 顺序和错误处理。runtime 路径应在绑定接口后安装 classic BPF filter，仅接收 ARP、IPv4 ICMP、以及匹配本 `service_port` 的未分片 IPv4 UDP；第一版端口匹配按常见无 IPv4 options 的 `IHL=20` offset 实现，并丢弃 fragmented 或带 IPv4 options 的 UDP，后续如果要支持带 IPv4 options 的 UDP，需要把 filter 改为按 IHL 计算动态 offset。独立 BPF smoke 可以保留未过滤打开路径用于观察接口可读性。`BIOCSSEESENT(true)` 用于尽量看到本机发送帧以支持 smoke/验证；如果平台返回 `EINVAL`，记录为未配置而不是失败。无论是否能看到 sent frame，transport 层仍应能忽略本协议中来自自身 connection/session 的异常包。

## `pnet_datalink` 许可与可复用范围

`pnet_datalink` 使用 `MIT OR Apache-2.0` 双许可证。可以参考、复制和修改其 BPF 实现，但应保留对应版权和许可声明。

本项目建议：

- crate 同样采用 `MIT OR Apache-2.0`。
- 如果某些文件明显改编自 `pnet_datalink`，在文件头部注明：

```rust
// Portions adapted from libpnet/pnet_datalink, licensed MIT OR Apache-2.0.
// Copyright (c) 2014-2016 Robert Clipsham.
```

- 仓库保留 `LICENSE-MIT` 和 `LICENSE-APACHE`。
- 如果大段复制，增加 `ACKNOWLEDGEMENTS.md` 或第三方声明。

## UDP payload protocol

底层 wire transport 是 UDP。`BpfStream` 只是 API 兼容 TCP-like stream，不表示网络上发送 TCP segment。

第一版 payload header 保持简单：

```text
magic
version
packet_type
service_port
connection_id
kcp_conv 或 simple_stream_id
payload
```

`connection_id` 第一版使用 64-bit 随机值，后续如需会话迁移或更强碰撞余量再扩展为 128-bit。`kcp_conv` 如果使用 KCP，则保留 KCP 自身所需的 32-bit conversation id。

第一版不做 transport 内加密。是否增加 HMAC 或 AEAD 后置确认。上层如果需要传输安全，应优先通过 rustls 等基于 `AsyncRead/AsyncWrite` 的协议实现。

## KCP / 可靠层

KCP 已作为默认内部 transport，不改变稳定的 `BpfStream` /
`BpfListener` API。极简可靠层继续作为 `TransportMode::Simple` 显式回退，
用于回归、诊断和故障绕行。

KCP 实现应使用不绑定系统 UDP socket 的纯协议引擎，例如 `kcp-core` 风格的
实现：

```text
UDP payload in  -> kcp.input()
app write       -> kcp.send()
timer           -> kcp.update()
kcp output      -> smoltcp UDP send
app read        <- kcp.recv()
```

`src/transport/kcp.rs` 封装具体 KCP crate，runtime 只依赖 crate-internal
transport engine trait。public API 只暴露 `TransportMode` 选择默认 KCP 或
simple 回退，不暴露 KCP 引擎细节。

不做 TCP-over-KCP-over-UDP。KCP 或简单可靠层承载应用字节流，不承载 TCP segment。

当前极简可靠层状态：

- 支持 Connect/Accept/Data/Ping/Fin/Reset packet type。
- `AsyncWrite::shutdown` 和 stream drop 会触发 FIN 并回收本地 session。
- 收到 FIN 或 Reset 时，runtime 关闭对应 stream 的读侧并回收 session。
- outbound queued/unacked 数据有上限；超限返回 backpressure，runtime 将其映射为
  `std::io::ErrorKind::WouldBlock`。
- session 有 idle timeout 检测，runtime poll 时回收超时 session。
- 当前仍不是完整 KCP 或 TCP 等价可靠层；极简可靠层已有有限乱序缓存和 FIN
  deferral，但拥塞控制、窗口协商、路径质量自适应仍是后续工作。

## ICMP Port Unreachable 处理

因为第一版复用宿主 IP，Darwin 可能为自定义 UDP packet 生成 ICMP Port Unreachable。

处理策略：

- stack 层识别相关 ICMP unreachable；BPF 层只负责 frame I/O。
- 如果 ICMP 引用的是 bpflink service port 或 connection，默认忽略。
- 不把相关 ICMP 作为连接 reset。
- 通过 tracing 记录计数，便于调试。

第一版不要求阻止 Darwin 发送 ICMP。

## MTU 策略

第一版避免依赖 IP fragmentation。

当前约束：

- Darwin `BpfDevice::mtu()` 必须读取真实接口 MTU。macOS 使用
  `SIOCGIFMTU`，不能固定假设 1500。
- smoltcp `DeviceCapabilities` 使用接口 MTU。
- IPv4 UDP payload target 使用
  `min(1200, interface_mtu - IPv4 header 20 - UDP header 8)`。
- IPv6 UDP payload target 使用
  `min(1200, interface_mtu - IPv6 header 40 - UDP header 8)`。
- payload target 下限为 bpflink header 长度；如果某个 MTU 小到无法容纳
  bpflink header 后的应用数据，transport write 必须稳定返回配置错误或
  payload-too-large 错误，不能发出超过 MTU 的 datagram。
- reliable transport 按 payload target 分片应用写入，不依赖 IP
  fragmentation。
- smoltcp UDP socket 的 RX/TX metadata 容量必须能承受小规模 stream burst；
  当前测试覆盖超过 8 个入站 UDP packet 的 burst。

IPv6 当前实现边界：

- public API 使用 `IpAddr`，并保持 `local_ipv4` 兼容路径，新增
  `local_ipv6`/`local_ip`。
- `smoltcp` feature 启用 `proto-ipv6`，stack 层支持 IPv6/UDPv6 poll 和 send
  路径。
- 地址解析依赖 smoltcp 的 Ethernet IPv6/NDP 行为，BPF filter 放行 ICMPv6。
- IPv6 payload target 使用 `min(1200, interface_mtu - IPv6 header 40 - UDP
  header 8)`。
- 不混合 dual-stack 自动选择；IPv6 验证阶段提供显式 `local_ip` 和
  `peer_ip` 配置。
- 单个 8-byte Hop-by-Hop、Routing 或 Destination Options extension header
  后的 UDPv6 service packet 可以进入 runtime；IPv6 Fragment header 继续丢弃。

IPv6 link-local scope 方案：

- Public API 继续使用 `IpAddr` 作为运行时地址模型，避免把平台 scope id 泄漏到
  transport session。
- CLI/examples 接受 `fe80::1%en0` 形式，并在边界校验 scope 必须等于
  `LinkBuilder::interface()`。
- `parse_scoped_ip()`、`PeerAddr::parse_with_interface()` 和
  `LinkBuilder::local_scoped_ip()` 在 API 边界解析 scope，runtime 内部仍只承载
  裸 `IpAddr`。
- BPF/smoltcp 层发送仍使用裸 IPv6 地址；scope 只用于选择接口、校验地址归属和
  用户输入解析，不进入 wire protocol。

IPv6 后续增强：

- 更完整地区分 ICMPv6 必要消息和错误消息。
- 更完整支持可变长度和多级 IPv6 extension header 下的 UDP port filter。
- 增加自动发现接口 IPv6 地址。

## 初始模块结构

```text
src/
  lib.rs
  link.rs
  runtime.rs

  bpf/
    mod.rs
    macos.rs
    linux.rs
    ioctl.rs
    frame.rs

  stack/
    mod.rs
    device.rs
    smoltcp_driver.rs
    udp.rs

  transport/
    mod.rs
    header.rs
    session.rs
    kcp.rs
    timers.rs

  socket/
    mod.rs
    stream.rs
    listener.rs
```

## 实施阶段

### Phase 1：macOS BPF + smoltcp UDP

- 实现 `BpfDevice`。
- 支持传入接口名。
- 支持 IPv4 配置。
- 能在两台 macOS 机器之间发送和接收 UDP payload。

### Phase 2：ICMP 观测与忽略

- 识别与 bpflink service port 相关的 ICMP Port Unreachable。
- 默认忽略。
- 加入 tracing 计数。

### Phase 3：KCP stream echo

- 接入 KCP 或极简可靠流。
- 实现 session 建立、关闭、reset。
- 跑 reliable echo。

### Phase 4：Async API

- 实现 `Link`。
- 实现 `BpfStream: AsyncRead + AsyncWrite`。
- 实现 `BpfListener`。
- 用 echo server/client 验证。

### Phase 5：IPv6 实现与验证

- 将 public/runtime 地址模型扩展为 `IpAddr`，保留 IPv4 兼容 API。
- 启用 smoltcp IPv6/UDPv6 路径，并按 IPv6 header 开销计算 payload target。
- macOS BPF filter 放行 ICMPv6、匹配 service port 的无 extension header
  UDPv6，以及单个 8-byte 常见 extension header 后的 UDPv6。
- 在 macOS host/VM 上完成 IPv6 runtime smoke 和双向 echo 验证。

## 待确认但不阻塞第一版的问题

- 后续是否需要自动发现接口 IPv4/IPv6 地址。
- 后续是否将 `connection_id` 从 64-bit 扩展为 128-bit。
- 是否在协议头中加入 HMAC。
- `service_port` 是否和 UDP port 完全一致，还是保留为逻辑服务号。
- Linux 后续是走 eBPF/cBPF、libpcap，还是明确放弃运行支持。

这些问题不影响 macOS BPF runtime 的核心闭环。

## 自审：一致性与目标兼容性

### 与原 md 文档的关系

| 原 md 结论 | 本设计处理 | 结论 |
| --- | --- | --- |
| BPF 作为 L2 packet RX/TX backend | 采用 BPF-only，且自研 `BpfDevice` | 一致 |
| 避免 userspace TCP，改用 UDP 上的可靠 transport | 使用 KCP 或极简可靠流承载 byte stream | 一致 |
| 对上层提供 TCP-like API 而不是 TCP wire protocol | `BpfStream` 实现 async stream，不发送 TCP segment | 一致 |
| 使用 smoltcp 处理 Ethernet/IP/UDP/ARP | 第一版保留 smoltcp UDP/IPv4/ARP，并在当前阶段扩展到 UDPv6/NDP | 一致 |
| 接受 Darwin stack 仍会看到 packet | 明确复用宿主 IP，并接受 ICMP Port Unreachable | 一致 |
| IPv6 是后续阶段 | IPv4 MVP 已完成，当前阶段补充显式 IPv6/NDP 验证 | 一致 |
| PoC 可用 KCP，长期可替换 | 第一版优先 KCP，模块边界允许后续替换 | 一致 |

### 与本期目标的兼容性

| 本期目标 | 本设计处理 | 结论 |
| --- | --- | --- |
| macOS 开发验证 | macOS 是唯一第一版运行目标 | 兼容 |
| 平台支持收敛 | 当前只支持 macOS 与 Linux；Windows 为后续目标，其他系统不支持 | 兼容 |
| BPF 是关键目标 | 不做 TUN/TAP/AF_PACKET backend | 兼容 |
| API 支持传入接口名 | `Link::builder().interface("en0")` | 兼容 |
| 先创建 BPF/Link，再创建 stream/listener | `Link` 独占 `BpfDevice`，socket 是轻量 handle | 兼容 |
| 先 IPv4，IPv6 作为计划目标 | Phase 1 IPv4，Phase 5 IPv6 实现与验证 | 兼容 |
| 使用 `bpflink`、`Link`、`BpfStream` 风格命名 | 全文采用该命名 | 兼容 |
| 内部线程 + async API | 明确采用内部 driver thread + channel/waker | 兼容 |

### 已修复的潜在模糊点

- “跨平台”不再泛化为跨 TUN/TAP/AF_PACKET backend，也不保留 BSD 预留边界；当前支持面收敛为 macOS 与 Linux。
- “Linux BPF”明确为 Linux `AF_PACKET` packet I/O + classic BPF socket filter，避免把 Linux 描述成 Darwin `/dev/bpf*` 设备。
- “复用宿主 IP”与“避免 Darwin 干扰”之间的边界已写清：接受 ICMP，忽略相关 ICMP，不阻止系统发包。
- “TCP-like API”与“TCP wire protocol”已区分：不发送 TCP segment。
- “KCP”被定义为第一版 reliable stream 实现选择，不进入 public API。
- “每个 socket 是否创建 BPF”已明确：只有 `Link` 持有 BPF，stream/listener 不直接打开 BPF。
