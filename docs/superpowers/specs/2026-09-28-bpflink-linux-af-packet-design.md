# bpflink Linux AF_PACKET 后端设计

日期：2026-09-28

> 历史说明：本文记录 Linux 后端首次落地时的设计上下文。当前 Linux 已纳入
> macOS/Linux 支持边界，不再标注为 experimental。本文中单端口
> `service_port(...)` / `open_filtered(interface, service_port)` 示例已被当前
> build-time 多端口 API 取代：调用方使用 `LinkBuilder::service_ports([...])`
> 声明完整端口集合，后端安装 service-port-set cBPF filter。

## 目标

为 `bpflink` 增加 Linux 第一版运行支持，在 Docker Linux 环境中完成开发和验证。
Linux 后端保持现有 public API 不变：

- `Link::builder().interface(...).local_ip(...).service_ports(...)`
- `BpfStream`
- `BpfListener`
- `TransportMode::{Kcp, Simple}`

Linux 第一版不引入新的 public socket 类型，也不改变 wire protocol。现有 KCP/simple
transport、smoltcp Ethernet/IPv4/IPv6/UDP 路径、runtime command loop 和 diagnostics
继续复用。

本期成功标准：

1. `target_os = "linux"` 下 `LinkBuilder::build()` 不再返回
   `UnsupportedPlatform`，而是创建 Linux packet backend。
2. Linux backend 可以按接口名打开并绑定真实接口，例如 Docker 容器里的 `eth0`。
3. Linux backend 可以读写完整 Ethernet frame，满足现有 `FrameIo` trait。
4. Linux backend 获取接口 MAC、MTU、IPv4/IPv6 prefix，用于现有 smoltcp driver。
5. Linux backend 在 socket 上安装 classic BPF service-port filter，只接收控制流量和
   本 crate service UDP traffic。
6. Docker 中通过 `bpf_smoke`、`runtime_smoke` 和两端 echo 验证 IPv4 KCP 路径。
7. macOS/Darwin `/dev/bpf*` 行为不回归。

## 选型决策

### Linux packet I/O 使用 AF_PACKET

Linux 没有 macOS `/dev/bpf*` 风格的 packet I/O 设备。第一版 Linux 后端使用：

```text
socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL))
bind(sockaddr_ll { sll_family = AF_PACKET, sll_protocol = ETH_P_ALL, sll_ifindex })
recv/read full Ethernet frame
send/sendto full Ethernet frame
```

这与 `pnet_datalink` Linux backend 的工程路线一致：用 `AF_PACKET` 作为 L2 packet
I/O，在接口 index 上绑定，发送和接收包含 link-layer header 的完整 Ethernet frame。
`pnet_datalink` 可作为实现参考，但不作为核心依赖。

不直接依赖 `pnet_datalink` 的原因：

- `bpflink` 已有 `FrameIo`、diagnostics、runtime ownership、filter status 和 smoltcp
  `Device` 集成点。
- `pnet_datalink` 的 channel 抽象不暴露本项目需要的 service-port filter 和 runtime
  counters 边界。
- 直接自研 Linux `BpfDevice` 更容易与 macOS `BpfDevice` 保持一致的内部接口。

### Linux 上的 BPF 目标是 socket classic BPF filter

Linux 第一版保留 “BPF 是关键目标” 的含义，但具体语义是：

- packet I/O：`AF_PACKET`
- packet filter：`SO_ATTACH_FILTER` classic BPF socket filter

也就是说，Linux 不是 `/dev/bpf*` 后端，而是 “AF_PACKET packet I/O + classic BPF
socket filter”。文档、README 和 diagnostics 必须明确这一点，避免把 Linux 描述成
Darwin BPF 设备。

### Mullvad Linux 实现作为权限/控制面参考，不作为 packet I/O 路线

Mullvad 的 macOS split tunnel BPF 实现适合作为 Darwin BPF 行为参考；但 Mullvad
Linux 主要走 nftables/netlink/cgroup/fwmark 等 firewall/routing 控制面，不是本项目
需要的 raw Ethernet frame backend。

本项目从 Mullvad Linux 路线吸收这些工程原则：

- 对 Linux capability 和 namespace 行为保持显式验证。
- Docker 测试必须写清楚需要的 capability。
- 涉及内核 API 的错误必须带 operation context，不能吞掉。

本期不引入 nftables、cgroup、fwmark 或 routing 控制。

## 非目标

第一版 Linux 支持不做这些事情：

- 不实现 eBPF/XDP/TC/AF_XDP。
- 不使用 libpcap 作为核心 packet I/O。
- 不修改 nftables/iptables、系统路由、sysctl 或 namespace 外部配置。
- 不保证 NAT traversal 或跨主机 Linux 生产环境稳定性。
- 不实现 Linux firewall/kill-switch/split-tunnel 控制面。
- 不承诺 IPv6 Docker echo 第一版必须通过；IPv6 保持代码路径不封死，优先保证
  Linux IPv4 KCP echo。
- 不改变 macOS `/dev/bpf*` 实现。

## 架构

当前平台边界保持：

```text
src/bpf/
  mod.rs
  macos.rs
  linux.rs
  frame.rs
  ioctl.rs
```

Linux 后端实现 `src/bpf/linux.rs` 中的 `BpfDevice`，并提供与 macOS 后端同名的内部
helpers：

- `BpfDevice::open(interface)`
- `BpfDevice::open_filtered(interface, service_port)`
- `interface_ethernet_addr(interface) -> Result<[u8; 6]>`
- `interface_ip_prefix_len(interface, local_ip: IpAddr) -> Result<u8>`

`src/bpf/mod.rs` 在 `target_os = "linux"` 下导出这些 helper，使
`RuntimeDriver::spawn_bpf()` 可以继续走同一套跨平台调用路径。

### BpfDevice 字段

Linux `BpfDevice` 需要持有：

- raw socket fd/file。
- interface name。
- interface index。
- MTU。
- `filter_configured`。
- 可选 `sees_sent_configured`：Linux 没有 Darwin `BIOCSSEESENT`；diagnostics 中可返回
  `None`，或在确认可观测自发包语义后返回固定值。

`FrameIo` 行为：

- `read_frames(out)` 非阻塞读取最多一批 frame；`WouldBlock` 返回 `Ok(0)`。
- Linux `AF_PACKET` 每次 read 是一个 Ethernet frame，不包含 Darwin `bpf_hdr`，因此
  不使用 `bpf::frame::iter_bpf_frames`。
- `write_frame(frame)` 写出完整 Ethernet frame。
- `mtu()` 返回接口 MTU。
- `filter_configured()` 返回安装 socket filter 的结果。

### 接口 metadata

Linux 后端需要获取：

- ifindex：`if_nametoindex` 或 `SIOCGIFINDEX`。
- MAC：`SIOCGIFHWADDR`。
- MTU：`SIOCGIFMTU`。
- prefix：`getifaddrs` 遍历接口地址和 netmask。

IPv6 link-local scope 仍在 public API 边界解析，runtime 内部继续使用 `IpAddr`。

### Classic BPF filter

Linux filter 使用 `setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, sock_fprog)` 安装。

filter 语义应与 macOS runtime filter 尽量一致：

- 接收 ARP。
- 接收 IPv4 ICMP。
- 接收 IPv6 ICMPv6。
- 接收匹配 `service_port` 的 IPv4 UDP，丢弃 fragmented 或 IPv4 options UDP。
- 接收匹配 `service_port` 的 IPv6 UDP。
- 接收单个 8-byte Hop-by-Hop、Routing 或 Destination Options header 后的 IPv6 UDP。
- 丢弃 IPv6 Fragment header 后的 UDP。

实现上应优先把 macOS 当前 cBPF 程序构建逻辑抽成平台无关 helper，避免两份 filter
逐渐漂移。平台层只负责把 `Vec<libc::sock_filter>`/`sock_fprog` 交给各自内核 API：

- macOS：`BIOCSETF`
- Linux：`SO_ATTACH_FILTER`

如果抽象成本过高，第一版可以复制 filter builder，但必须保留两边 characterization
tests，确保端口匹配语义一致。

## Docker 验证

本机 Docker daemon 当前是 Linux/aarch64；本地没有预置镜像。验证计划应允许拉取或构建
Linux Rust 测试镜像。

### 容器权限

Linux packet socket 至少需要：

```bash
--cap-add NET_RAW
```

部分接口配置和诊断可能需要：

```bash
--cap-add NET_ADMIN
```

第一版测试命令可以使用：

```bash
docker run --rm --cap-add NET_RAW --cap-add NET_ADMIN ...
```

不要求 `--privileged` 作为默认验证方式；只有在定位 Docker/arcbox 特定权限问题时才作为
临时诊断。

### 验证层级

1. **Linux compile/test**
   - 在 Linux 容器内运行 `cargo test --features test-util`。
   - 在 Linux 容器内运行 `cargo check --examples`。
   - 目标是验证 `target_os = "linux"` cfg 和 Linux binding 编译。

2. **单容器 packet smoke**
   - 在容器内运行 `bpf_smoke --interface eth0`。
   - 期望：open/config/read boundary ok，MTU/MAC 可获取，filter 状态可观测。

3. **单容器 runtime smoke**
   - 在容器内运行 `runtime_smoke --interface eth0 --local-ip <container-ip>`。
   - 期望：command loop ok，payload target 合理，filter configured true。

4. **两容器 IPv4 echo**
   - 同一 Docker bridge network 下启动 server/client。
   - server 使用容器 A 的 `eth0` IPv4。
   - client 使用容器 B 的 `eth0` IPv4，peer 指向容器 A。
   - KCP 默认 echo `4096` bytes，payload match。
   - simple fallback 至少做一次 smoke。

5. **非回归**
   - macOS 本机 `cargo test --features test-util`。
   - macOS `cargo check --examples`。
   - macOS BPF smoke 可作为发布前验证，不要求每个 Linux 开发循环都跑。

## 文档更新

README 和 `docs/macos-validation.md` 之外，需要新增或更新 Linux 验证文档：

- Linux 后端不是 `/dev/bpf*`。
- Linux 使用 `AF_PACKET + SO_ATTACH_FILTER`。
- Docker 需要 `CAP_NET_RAW`，可能需要 `CAP_NET_ADMIN`。
- Docker 验证当前优先 IPv4 KCP。
- Linux runtime target 从 “planned compile boundary” 调整为 “experimental runtime
  target”。

## 风险

- Docker 环境的 packet socket 行为可能与真实 Linux 主机不同，尤其是 self-sent frame、
  bridge forwarding、capability 和 checksum offload。
- `SO_ATTACH_FILTER` 的 `sock_filter` ABI 与 Darwin `bpf_program` 使用相同 instruction
  结构但不同安装 API，需要测试确认 bytecode jump offsets 一致。
- Linux `AF_PACKET` 可能捕获 outbound/self-sent frame，runtime 必须继续依赖现有
  connection/session routing 和 filter 语义避免误处理。
- macOS 和 Linux filter builder 如果复制实现，后续容易漂移。
- Docker 容器镜像拉取依赖网络；实现计划需要允许提前构建本地测试镜像。

## 与现有设计的一致性

| 现有结论 | Linux 第一版处理 | 状态 |
| --- | --- | --- |
| BPF 是关键目标 | Linux 使用 classic BPF socket filter | 一致 |
| 不支持 TUN/TAP/AF_PACKET 等非 BPF backend | 本期修改该边界：Linux packet I/O 使用 AF_PACKET，但 filter 仍是 BPF；文档必须明确这是 Linux 特例 | 有意变更 |
| macOS 是第一版唯一运行目标 | Linux 进入实验运行目标 | 有意扩展 |
| public API 不变 | `Link`/stream/listener 不变 | 一致 |
| KCP 默认，simple fallback | Linux 复用同一 transport | 一致 |
| 不修改系统网络配置 | 不做 nftables/route/sysctl | 一致 |

## 开放问题

这些问题在本 spec 中固定为以下决策，避免实施阶段摇摆：

- Docker IPv6 echo 不纳入第一版完成标准；Linux 第一版必须保持 IPv6 代码路径可编译，
  并通过共享 filter/unit tests 覆盖 IPv6 filter 语义，但硬件/容器 echo 只要求 IPv4。
- Linux runtime filter 安装成功时 diagnostics 必须返回 `filter_configured: Some(true)`；
  filter 安装失败不能静默降级为未过滤运行。
- 第一版实施应优先抽出公共 cBPF builder，例如 `src/bpf/filter.rs`。只有在抽取导致
  明确的跨平台 ABI 阻塞时，才允许临时复制 builder；如果复制，必须在同一提交中为
  macOS/Linux 都保留等价 characterization tests。
