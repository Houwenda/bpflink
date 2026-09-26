# bpflink KCP 默认化与 IPv6 增强设计

日期：2026-09-28

## 目标

本次变更把已经完成 host/VM 验证的 KCP transport 从实验模式提升为默认内部
transport，同时保留 simple transport 作为显式回退选项。对外仍然提供
`Link`、`BpfStream`、`BpfListener` 这组 TCP-like async API；KCP 是默认
实现细节，不要求调用方理解或直接操作 KCP。

同时补齐两个轻量 IPv6 项：

- 支持接口绑定场景下解析 `fe80::...%iface` 形式的 IPv6 link-local 地址。
- macOS BPF service filter 支持常见 IPv6 extension header 后面的 UDP service
  port 过滤。

## 决策

- `TransportMode::Kcp` 是默认值，并作为稳定 public API 暴露。
- `TransportMode::Simple` 继续保留，供回归、诊断和故障绕行使用。
- 删除 `experimental-kcp` feature；`kcp-core` 和 `bytes` 成为普通依赖。
- `LinkBuilder::transport_mode(mode)` 取代
  `experimental_transport_mode(mode)`。
- examples 的 `--transport simple|kcp` 始终可用，默认值为 `kcp`。
- link-local scope 在 API/CLI 边界解析，内部仍然使用 `IpAddr`。因为 `Link`
  已绑定接口，scope id 只用于校验和消歧，不进入 runtime session key。
- 本期不做 dual-stack 自动选择，不自动枚举地址，不改变宿主网络配置。
- IPv6 extension header filter 第一阶段支持单个 8-byte
  Hop-by-Hop、Routing 或 Destination Options header 后的 UDP。IPv6 Fragment
  header 继续丢弃，因为无状态 BPF filter 无法可靠解析非首片 UDP port。

## 成功标准

1. 无 `experimental-kcp` feature 时，crate、tests、examples 均可编译。
2. `TransportMode::default()` 为 `Kcp`。
3. 现有 simple mode 测试继续可通过，显式 `--transport simple` 可用。
4. `fe80::...%iface` 在接口匹配时可解析为 `IpAddr::V6`，scope 不匹配时报错。
5. macOS BPF filter 测试覆盖 IPv6 UDP 直连和单个 extension header 后的 service
   port 匹配。
6. 本机自动化验证、host/VM KCP IPv4/IPv6 echo、并发/长循环 smoke 和 BPF fd
   泄漏抽样完成并记录。
