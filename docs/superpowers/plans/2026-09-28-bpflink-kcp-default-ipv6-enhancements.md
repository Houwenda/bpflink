# bpflink KCP 默认化与 IPv6 增强实现计划

> **For agentic workers:** 使用 superpowers:executing-plans 实施。新增行为遵守
> TDD：先写失败测试，再实现。

**Spec:** `docs/superpowers/specs/2026-09-28-bpflink-kcp-default-ipv6-enhancements-design.md`

## 全局约束

- BPF 仍然是唯一 packet backend；平台支持面收敛为 macOS 与 Linux。
  Windows 是后续支持目标，其他系统不支持。
- public stream API 不变：`BpfStream`/`BpfListener` 仍是调用方主要入口。
- KCP 默认化不能移除 simple transport。
- IPv6 link-local scope 只在边界解析和校验，内部 session/routing 仍用 `IpAddr`。
- BPF ioctl 常量继续来自现有 libc/system binding 路线；BPF 行为以 Mullvad 实现和
  Apple/XNU 语义为工程对照。

## Task 1: KCP 默认化

**Files:** `Cargo.toml`, `src/lib.rs`, `src/link.rs`, `src/runtime.rs`,
`src/diagnostics.rs`, `src/transport/*`, `examples/*`, `tests/*`

- [ ] 写/调整测试，确认 `TransportMode::default() == Kcp`、builder 可显式选择
  KCP/Simple、diagnostics 可配置 KCP。
- [ ] 删除 `experimental-kcp` feature gate，使 `bytes`/`kcp-core` 成为普通依赖。
- [ ] 将 `TransportMode` 稳定导出，公开 `LinkBuilder::transport_mode`。
- [ ] examples 默认 KCP，`--transport simple|kcp` 始终可用。
- [ ] 运行 `cargo test --features test-util` 和 `cargo check --examples`。

## Task 2: IPv6 link-local scope 解析

**Files:** `src/link.rs`, `src/lib.rs`, `examples/*`, `tests/link_api.rs`

- [ ] 先写测试覆盖 `fe80::1%en0` 成功、scope 不匹配失败、非 link-local 携带 scope
  失败。
- [ ] 增加 public 边界 helper，并让 examples 支持 scoped local/peer 地址。
- [ ] 保持 runtime 内部只接收 `IpAddr`。

## Task 3: IPv6 extension header BPF filter

**Files:** `src/bpf/macos.rs`

- [ ] 先调整/新增 BPF filter characterization tests，要求单个 8-byte
  Hop-by-Hop/Routing/Destination Options header 后的 UDP service port 可通过。
- [ ] 扩展静态 cBPF 程序，仍保留 ICMPv6/NDP、直连 UDP 和 IPv4 行为。
- [ ] 继续丢弃 Fragment header，并在注释/文档中说明。

## Task 4: 文档、review、验证与提交

**Files:** `README.md`, `docs/macos-validation.md`, design spec

- [ ] 更新文档，移除 experimental 说法，记录默认 KCP、simple 回退、scope 和
  extension header 支持边界。
- [ ] 运行格式、clippy、测试、examples build。
- [ ] 做整分支 review，修复 Critical/Important 问题。
- [ ] 做 host/VM 实机验证：KCP IPv4/IPv6 echo、simple 回归、并发/长循环 smoke、
  BPF fd 泄漏抽样。
- [ ] 提交。

## Review Focus

- KCP 默认化是否漏掉 feature cfg，导致默认构建或 examples 仍依赖
  `experimental-kcp`。
- 默认变更是否破坏 simple transport 回退。
- scoped IPv6 是否错误地把 `%iface` 带入 runtime 内部地址。
- BPF filter jump offset 是否误放行非 service port UDP 或误丢 ICMPv6。
- 文档是否仍存在 “KCP experimental/simple default/extension header dropped” 的旧结论。
