# macOS validation flow

## Prerequisites

- Two reachable macOS hosts or two reachable interfaces.
- An interface name such as `en0`.
- The IPv4 or IPv6 address already configured on each host interface.
- Permission to open `/dev/bpf*`; running with `sudo` is usually required.

`bpflink` intentionally reuses the host IP address. For IPv4, Darwin may still
see incoming UDP packets and may emit ICMP Port Unreachable if no matching
kernel UDP socket exists. The crate treats related ICMP Port Unreachable as
count-and-ignore input; it must not reset a bpflink session. For IPv6, the BPF
service filter must also pass ICMPv6 so Neighbor Discovery can continue to
work. IPv6 validation can use ULA/global-style addresses or link-local
`fe80::...%iface` input at the API/CLI boundary. The service filter accepts
direct UDPv6 and UDPv6 behind one 8-byte Hop-by-Hop, Routing, or Destination
Options extension header; IPv6 Fragment headers are still dropped.

## Build checks

```bash
cargo test --features test-util
cargo check --examples
```

KCP is the default transport. The simple reliable engine remains available via
`--transport simple` for regression and fallback validation.

```bash
cargo test --features test-util
cargo check --examples
cargo clippy --all-targets --features test-util -- -D warnings
```

Expected automated status for this revision:

- unit and integration tests pass with `test-util`;
- reliable session tests cover FIN close, write-after-close rejection,
  outbound backpressure, and idle-timeout detection;
- smoltcp tests cover IPv4 and IPv6 UDP send/receive paths;
- smoltcp tests cover off-link IPv4 and IPv6 sends through an injected default
  gateway route;
- macOS route-message parser tests cover IPv6 default-gateway discovery for the
  selected interface;
- BPF filter tests cover IPv4 ARP/ICMP/service UDP and IPv6 ICMPv6/service
  UDP, including service UDPv6 behind one common 8-byte extension header;
- examples compile;
- BPF device smoke passes on the development Mac;
- runtime command loop smoke passes on the development Mac;
- BPF send smoke passes on the development Mac;
- hardware echo passes across the local macOS host and the VM in both
  directions for IPv4 and IPv6;
- multi-stream pressure validation passes on the host-to-VM direction;
- one-server-process BPF fd sampling shows one `/dev/bpf*` fd before and after
  multi-stream validation.

## BPF device smoke

Run this first on the development Mac. It validates the BPF open/config/read
boundary without requiring the full bpflink runtime command loop:

```bash
sudo cargo run --example bpf_smoke -- en0
```

Equivalent named-argument form:

```bash
sudo cargo run --example bpf_smoke -- --interface en0
```

Expected success output:

```text
bpflink bpf smoke
interface: en0
open_config_read: ok
mtu: 1500
read_polls: 1
frames_seen: <0 or more>
sees_sent_configured: <true, false, or unknown>
filter_configured: false
```

`frames_seen` may be `0` on a quiet interface because the probe performs a
single nonblocking read poll. A successful run proves `/dev/bpf*` open,
interface binding, immediate mode, header-complete mode, nonblocking setup,
and BPF header peeling through `FrameIo::read_frames`. The standalone BPF smoke
uses the unfiltered open path, so `filter_configured` is expected to be `false`.
If a future platform rejects `BIOCSSEESENT`, the probe reports
`sees_sent_configured: false` and continues because this option only controls
whether self-sent frames are captured.

## Runtime command loop smoke

After `bpf_smoke` passes, run the runtime command loop smoke. This validates
`LinkBuilder::build()`, single-BPF runtime ownership, driver thread startup,
`listen` command handling, snapshot command handling, and clean shutdown:

```bash
cargo run --example runtime_smoke -- en0 <local-ip> 40000
```

Expected success output:

```text
bpflink runtime smoke
interface: en0
local_ip: <local-ip>
service_ports: [40000]
active_service_port: 40000
transport_mode: kcp
command_loop: ok
mtu: 1500
payload_target: 1200
sees_sent_configured: true
filter_configured: true
listener_count: 1
session_count: 0
command_count: 2
poll_count: <1 or more>
connect_peer_ip: none
stream_write_count: 0
outbound_datagram_count: 0
inbound_accept_count: 0
inbound_data_count: 0
ignored_icmp_count: 0
closed_session_count: 0
idle_timeout_count: 0
backpressure_count: 0
```

This is not yet an end-to-end transport echo test. It proves the real runtime
thread can own the BPF-backed stack and respond to commands from the public
`Link` handle.

## BPF send smoke

After the command loop smoke passes, run a single-machine send-side smoke by
passing a reachable peer on the same network, such as the default gateway or
the VM address. The peer does not need to run bpflink; this smoke only
validates that `connect` and a small stream write traverse the BPF-backed
runtime send path:

```bash
cargo run --example runtime_smoke -- en0 <local-ip> 40000 --peer-ip <peer-ip>
```

Expected success output:

```text
bpflink runtime smoke
interface: en0
local_ip: <local-ip>
service_ports: [40000]
active_service_port: 40000
transport_mode: kcp
command_loop: ok
mtu: 1500
payload_target: 1200
sees_sent_configured: true
filter_configured: true
listener_count: 1
session_count: 1
command_count: <4 or more>
poll_count: <1 or more>
connect_peer_ip: <peer-ip>
stream_write_count: 1
outbound_datagram_count: <2 or more>
inbound_accept_count: 0
inbound_data_count: 0
ignored_icmp_count: <0 or more>
closed_session_count: <0 or more>
idle_timeout_count: 0
backpressure_count: 0
```

This still does not require a remote bpflink process. The first outbound
datagram is the simplified connect packet; the second comes from the smoke
payload write.

The equivalent simple-engine send-side smoke is:

```bash
cargo run --example runtime_smoke -- en0 <local-ip> 40000 --peer-ip <peer-ip> --transport simple
```

Expected differences from KCP mode:

- `transport_mode: simple`;
- outbound `Data` datagrams contain the simple reliable stream payload;
- the BPF/smoltcp path and `BpfStream` API remain unchanged.

## Off-link IPv6 peer smoke

For IPv6 peers outside the selected interface prefix, the runtime reads that
interface's IPv6 default gateway from the Darwin route sysctl dump and installs
it into smoltcp's in-process route table. smoltcp then resolves the gateway
with NDP while keeping the packet's IPv6 destination as the off-link peer.

This smoke requires the selected BPF interface to be Ethernet-like and to have
a routable IPv6 address plus an IPv6 default gateway. A `utun*` route is not a
valid substitute for the current BPF Ethernet runtime because the runtime needs
an Ethernet MAC address, MTU, and L2 frame I/O on the selected interface.

Client:

```bash
cargo run --example echo_client -- \
  --interface <macos-interface> \
  --local-ip <macos-local-ipv6> \
  --service-port 40031 \
  --peer-ip <remote-linux-ipv6> \
  --payload-bytes 4096 \
  --transport kcp
```

Server:

```bash
docker run --rm --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD":/work -w /work \
  rust:1-bookworm \
  cargo run --example echo_server -- \
    --interface <linux-public-interface> \
    --local-ip <remote-linux-ipv6> \
    --service-port 40031 \
    --expected-bytes 4096 \
    --transport kcp
```

Expected result:

- client logs `sent_bytes=4096`, `received_bytes=4096`, and
  `payload_match=true`;
- server logs `received_bytes=4096` and `echoed_bytes=4096`;
- host routing rules are not changed.

If the macOS Ethernet interface only has link-local IPv6 and public IPv6 egress
is routed through `utun*`, this end-to-end smoke is blocked by the environment.
The code path remains covered by macOS IPv6 route parser tests and smoltcp
off-link IPv6 route-injection tests until a routable IPv6 Ethernet interface is
available.

## Intended echo commands

Server:

```bash
sudo cargo run --example echo_server -- --interface en0 --local-ip <server-ip> --service-port 40000
```

Client:

```bash
sudo cargo run --example echo_client -- --interface en0 --local-ip <client-ip> --service-port 40000 --peer-ip <server-ip>
```

KCP echo uses the default transport. The explicit `--transport kcp` flag is
accepted but optional:

```bash
sudo cargo run --example echo_server -- --interface en0 --local-ip <server-ip> --service-port 40000 --transport kcp
sudo cargo run --example echo_client -- --interface en0 --local-ip <client-ip> --service-port 40000 --peer-ip <server-ip> --transport kcp
```

Expected logs once real driver routing is connected:

- server logs the interface, local IP, service port, received byte count,
  echoed byte count, related ICMP count, and shutdown;
- client logs the interface, local IP, service port, peer IP, sent byte
  count, received byte count, related ICMP count, and shutdown;
- client prints the echoed payload.

## nc-like manual validation

`bpfnc` is the lowest-friction example for interactive checks and one-way file
transfer. It logs status to stderr and keeps stdout as raw stream data.

Listen:

```bash
sudo cargo run --example bpfnc -- listen --interface en0 --local-ip <server-ip> --service-port 40000
```

Connect:

```bash
sudo cargo run --example bpfnc -- connect --interface en0 --local-ip <client-ip> --service-port 40000 --peer-ip <server-ip>
```

File transfer:

```bash
sudo cargo run --example bpfnc -- listen --interface en0 --local-ip <server-ip> --service-port 40000 --recv-only > received.bin
sudo cargo run --example bpfnc -- connect --interface en0 --local-ip <client-ip> --service-port 40000 --peer-ip <server-ip> --send-only < payload.bin
```

`bpfnc` uses KCP by default, accepts `--transport simple`, supports
`--send-only`/`--recv-only` for file transfer, and supports scoped IPv6 input
such as `fe80::1%en0`.

Full-duplex mode is intended for two interactive terminals. If the listener is
started through a non-interactive SSH command or with stdin already closed, it
will send a stream close immediately after accept; the connecting side may then
report a normal `BrokenPipe`/`DriverClosed` if it continues writing. For one-way
checks, run the receiver with `--recv-only` and the sender with `--send-only`.
Both `listen` and `connect` keep the link alive for `--linger-ms 1000` by
default so final KCP packets have a short drain window.

Observed `bpfnc` file-transfer smoke on the host/VM pair:

- host `bridge100` connected to VM `en0` over IPv4 with default KCP;
- client used `--send-only`, sent `33` bytes from stdin, and received `0`
  bytes on stdout;
- server used `--recv-only`, received `33` bytes on stdin-to-file, and sent
  `0` bytes;
- source and received file SHA-256 both matched
  `0310aba13eab0895acc0012ed953cbe3cd3b3ca2872083a12c72002a198cafe5`.

## Current smoke result

`bpf_smoke` was run successfully on the local macOS development host:

```bash
cargo run --example bpf_smoke -- en0
```

Observed result:

```text
bpflink bpf smoke
interface: en0
open_config_read: ok
mtu: 1500
read_polls: 1
frames_seen: 0
sees_sent_configured: true
filter_configured: false
```

This validates the BPF device boundary on `en0` for open/config/nonblocking
read and BPF header peeling.

`runtime_smoke` was run successfully on the same local macOS development host:

```bash
cargo run --example runtime_smoke -- en0 <local-ip> 40000
```

Observed result:

```text
bpflink runtime smoke
interface: en0
local_ip: <local-ip>
service_ports: [40000]
active_service_port: 40000
transport_mode: simple
command_loop: ok
mtu: 1500
payload_target: 1200
sees_sent_configured: true
filter_configured: true
listener_count: 1
session_count: 0
command_count: 2
poll_count: 1
connect_peer_ip: none
stream_write_count: 0
outbound_datagram_count: 0
inbound_accept_count: 0
inbound_data_count: 0
ignored_icmp_count: 0
closed_session_count: 0
idle_timeout_count: 0
backpressure_count: 0
```

This validates the real runtime command loop boundary.

`runtime_smoke` send mode was also run successfully against the local network
gateway:

```bash
cargo run --example runtime_smoke -- en0 <local-ip> 40000 --peer-ipv4 <gateway-ip>
```

Observed result:

```text
bpflink runtime smoke
interface: en0
local_ip: <local-ip>
service_ports: [40000]
active_service_port: 40000
transport_mode: simple
command_loop: ok
mtu: 1500
payload_target: 1200
sees_sent_configured: true
filter_configured: true
listener_count: 1
session_count: 1
command_count: 5
poll_count: 4
connect_peer_ip: <gateway-ip>
stream_write_count: 1
outbound_datagram_count: 2
inbound_accept_count: 0
inbound_data_count: 0
ignored_icmp_count: 0
closed_session_count: 0
idle_timeout_count: 0
backpressure_count: 0
```

This validates the local send-side runtime boundary.

## Current verified result

The latest validation used:

- host interface: `<host-interface>`, IPv4 `<host-ipv4>`, IPv6
  `<host-ipv6>`, MTU `1500`;
- VM interface: `<vm-interface>`, IPv4 `<vm-ipv4>`, IPv6
  `<vm-ipv6>`, MTU `1500`;
- host link-local IPv6: `<host-link-local-ipv6>%<host-interface>`;
- VM link-local IPv6: `<vm-link-local-ipv6>%<vm-interface>`;
- VM SSH target: `<user>@<vm-ip>`.
- Remote copied Mach-O examples may need `codesign --force --sign -` on the VM
  before execution; otherwise AMFI can reject a copied ad-hoc signature with
  `embedded signature doesn't match attached signature`.

Fresh local verification:

```bash
cargo fmt --check
cargo clippy --all-targets --features test-util -- -D warnings
cargo test --features test-util
cargo check --examples
cargo build --examples
```

Observed status:

- lib tests with default KCP and simple fallback coverage: `68 passed`;
- async API integration tests: `6 passed`;
- diagnostics API tests: `3 passed`;
- link API tests: `10 passed`;
- examples compile without warnings.

The lib suite includes runtime coverage for:

- classic BPF service-port filter semantics for ARP, IPv4 ICMP, matching IPv4
  UDP, IPv6 ICMPv6, matching IPv6 UDP, non-matching drop cases, fragmented
  IPv4 UDP drops, and IPv4-options UDP drops;
- IPv4 and IPv6 smoltcp UDP send/receive paths;
- off-link IPv4 and IPv6 smoltcp default-route sends;
- macOS route sysctl default-gateway parsing for IPv6;
- shutdown sending FIN while keeping the local session alive for retransmission
  until peer FIN/reset or idle reaping;
- write-then-close ordering DATA before FIN;
- out-of-order DATA buffering and FIN deferral until missing DATA arrives;
- inbound FIN closing the stream read side and removing the session;
- outbound backpressure surfacing through stream writes;
- idle session reaping;
- UDP RX metadata burst handling beyond eight packets.

MTU/runtime smoke:

```text
host bridge100 runtime_smoke:
mtu: 1500
payload_target: 1200
sees_sent_configured: true
filter_configured: true

VM en0 runtime_smoke:
mtu: 1500
payload_target: 1200
sees_sent_configured: true
filter_configured: true
```

IPv6 runtime smoke:

```text
host bridge100 runtime_smoke:
local_ip: <host-ipv6>
mtu: 1500
payload_target: 1200
sees_sent_configured: true
filter_configured: true

VM en0 runtime_smoke:
local_ip: <vm-ipv6>
mtu: 1500
payload_target: 1200
sees_sent_configured: true
filter_configured: true
```

Bidirectional echo:

- host `bridge100` to VM `en0`, `4096` bytes: client received `4096`, payload
  matched, related ICMP count `0`;
- VM `en0` to host `bridge100`, `4096` bytes: client received `4096`, payload
  matched, related ICMP count `0`.
- IPv6 host `bridge100` to VM `en0`, `4096` bytes: client received `4096`,
  payload matched, related ICMP count `0`; server received and echoed `4096`.
- IPv6 VM `en0` to host `bridge100`, `4096` bytes: client received `4096`,
  payload matched, related ICMP count `0`; server received and echoed `4096`.

Default KCP validation:

```text
IPv4 KCP send smoke:
host <host-interface> <host-ipv4> -> VM <vm-interface> <vm-ipv4>:
transport_mode: kcp
stream_write_count: 1
outbound_datagram_count: 2

VM <vm-interface> <vm-ipv4> -> host <host-interface> <host-ipv4>:
transport_mode: kcp
stream_write_count: 1
outbound_datagram_count: 2

IPv6 KCP send smoke:
host <host-interface> <host-ipv6> ->
VM <vm-interface> <vm-ipv6>:
transport_mode: kcp
stream_write_count: 1
outbound_datagram_count: 2

VM <vm-interface> <vm-ipv6> ->
host <host-interface> <host-ipv6>:
transport_mode: kcp
stream_write_count: 1
outbound_datagram_count: 2
```

Default KCP echo:

- IPv4 host `bridge100` to VM `en0`, `4096` bytes: client sent `4096`,
  received `4096`, `payload_match=true`, related ICMP count `0`; server
  received and echoed `4096`.
- IPv4 VM `en0` to host `bridge100`, `4096` bytes: client sent `4096`,
  received `4096`, `payload_match=true`, related ICMP count `0`; server
  received and echoed `4096`.
- IPv6 host `bridge100` to VM `en0`, `4096` bytes: client sent `4096`,
  received `4096`, `payload_match=true`, related ICMP count `0`; server
  received and echoed `4096`. This path needs the server runtime to stay alive
  briefly after echoing; `echo_server` now defaults to `--linger-ms 1000`.
- IPv6 VM `en0` to host `bridge100`, `4096` bytes: client sent `4096`,
  received `4096`, `payload_match=true`, related ICMP count `0`; server
  received and echoed `4096`.

Latest local host/VM IPv6 echo smoke:

- host `<host-vm-bridge-interface>` to VM `<vm-interface>`, default KCP,
  `4096` bytes: client sent `4096`, received `4096`, `payload_match=true`,
  related ICMP count `0`; server received and echoed `4096`;
- VM `<vm-interface>` to host `<host-vm-bridge-interface>`, default KCP,
  `4096` bytes: client sent `4096`, received `4096`, `payload_match=true`,
  related ICMP count `0`; server received and echoed `4096`;
- host `<host-vm-bridge-interface>` to VM `<vm-interface>`, simple fallback,
  `256` bytes: client sent `256`, received `256`, `payload_match=true`,
  related ICMP count `0`; server received and echoed `256`;
- VM `<vm-interface>` to host `<host-vm-bridge-interface>`, simple fallback,
  `256` bytes: client sent `256`, received `256`, `payload_match=true`,
  related ICMP count `0`; server received and echoed `256`.

Scoped link-local runtime smoke:

```text
host <host-interface> <host-link-local-ipv6>%<host-interface> ->
VM <vm-link-local-ipv6>%<host-interface>:
transport_mode: kcp
stream_write_count: 1
outbound_datagram_count: 2
```

Multi-stream pressure:

```bash
# VM server
sudo -n /tmp/echo_server \
  --interface en0 \
  --local-ipv4 <vm-ipv4> \
  --service-port 40547 \
  --expected-bytes 1024 \
  --accept-count 80 \
  --linger-ms 500

# host client
cargo run --example echo_client -- \
  --interface <host-interface> \
  --local-ipv4 <host-ipv4> \
  --service-port 40547 \
  --peer-ipv4 <vm-ipv4> \
  --payload-bytes 1024 \
  --iterations 10 \
  --concurrency 8
```

Observed result:

```text
client sent_bytes=81920
client received_bytes=81920
client payload_match=true
server received_bytes=81920
server echoed_bytes=81920
```

Before the `DATA` before `FIN` fix, the same 8-concurrent stream case could
fail on the client with `UnexpectedEof` while the server had already echoed all
bytes. The regression test now covers this packet ordering requirement.

FD sampling:

- VM server process before multi-stream validation: one `/dev/bpf0` fd;
- VM server process after `32` stream validation while lingering: one
  `/dev/bpf0` fd;
- the server exited cleanly after linger.
- Host server process `18879` before reverse-direction `32` stream validation:
  one `/dev/bpf0` fd;
- Host server process `18879` after reverse-direction `32` stream validation
  while lingering: one `/dev/bpf0` fd;
- the host server exited cleanly after linger.

The attempted `80` stream pressure run first exposed an RX metadata capacity
bug: only `8/16` synthetic inbound UDP packets were delivered in the new
regression test. Increasing `UDP_PACKET_CAPACITY` to `256` fixed the regression
and the `80` stream hardware pressure run passed.

Local host post-run BPF smoke:

```text
bpflink bpf smoke
interface: bridge100
open_config_read: ok
mtu: 1500
read_polls: 1
frames_seen: 0
sees_sent_configured: true
filter_configured: false
```

The latest default-KCP pressure run also covered `80` host-to-VM streams
(`10` iterations × `8` concurrency) with `81920` bytes sent and received.
