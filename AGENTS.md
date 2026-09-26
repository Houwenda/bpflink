# 协作说明

## 语言偏好

除非特别指定，否则在聊天、写文档、写代码注释时使用简体中文。

## BPF 实现参考

后续涉及 macOS/BSD BPF 相关实现、调试和行为确认时，优先参考 Mullvad VPN 的 macOS BPF 实现作为工程对照；再结合 Apple XNU `bpf.h`/系统头文件确认 ioctl 常量、参数类型和内核语义。不要手写可直接复用 libc/system binding 的 BPF ioctl 常量。
