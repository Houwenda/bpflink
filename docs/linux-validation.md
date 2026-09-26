# Linux validation flow

Linux support uses `AF_PACKET/SOCK_RAW` for packet I/O and classic BPF via
`SO_ATTACH_FILTER` for the service-port socket filter. It does not use
macOS `/dev/bpf*`, eBPF, XDP, TC, AF_XDP, libpcap, nftables, routing rule
changes, or sysctl changes. The runtime may read the interface default gateway
and install it into smoltcp's in-process route table; it does not modify the
host route table.

The first Linux validation target is Docker IPv4 with the default KCP
transport. IPv6 code paths are compiled and tested. Off-link IPv6 peers are
supported when the selected interface has an IPv6 default gateway; Docker IPv6
echo is still not a first release gate.

## Prerequisites

- Docker with Linux containers.
- A Rust Linux image such as `rust:1-bookworm`.
- Capability to create packet sockets in the container:
  `--cap-add NET_RAW`.
- `--cap-add NET_ADMIN` for broader interface diagnostics and smoke parity.

Use the repository root as the working directory for all commands.

## Build checks

```bash
docker run --rm \
  -v "$PWD":/work -w /work \
  rust:1-bookworm \
  cargo test --features test-util

docker run --rm \
  -v "$PWD":/work -w /work \
  rust:1-bookworm \
  cargo check --examples
```

Expected automated status:

- Linux cfg compilation succeeds.
- Linux interface metadata helper tests pass.
- Linux `/proc/net/route` and `/proc/net/ipv6_route` default-gateway parser
  tests pass.
- Linux `sockaddr_ll` and classic BPF socket-filter construction tests pass.
- Shared smoltcp tests cover off-link IPv4 and IPv6 send paths with default
  route injection.
- Shared runtime, stream, transport, and smoltcp tests pass.
- Examples compile on Linux.
- `cargo check --target x86_64-unknown-linux-gnu --features test-util`
  passes when the Rust target std component is installed.

## Single-container BPF smoke

Run `bpf_smoke` against Docker's default `eth0` interface:

```bash
docker run --rm \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD":/work -w /work \
  rust:1-bookworm \
  cargo run --example bpf_smoke -- --interface eth0
```

Expected success output:

```text
bpflink bpf smoke
interface: eth0
open_config_read: ok
mtu: <container mtu>
read_polls: 1
frames_seen: <0 or more>
sees_sent_configured: unknown
filter_configured: false
```

The standalone BPF smoke uses the unfiltered open path, so
`filter_configured: false` is expected. Linux has no Darwin `BIOCSSEESENT`;
diagnostics report `sees_sent_configured: unknown`.

## Single-container runtime smoke

Resolve the container IPv4 address and run the runtime command loop smoke:

```bash
docker run --rm \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD":/work -w /work \
  rust:1-bookworm \
  sh -lc 'LOCAL_IP=$(hostname -I | awk "{print \$1}"); cargo run --example runtime_smoke -- eth0 "$LOCAL_IP" 40000'
```

Expected success output includes:

```text
bpflink runtime smoke
interface: eth0
local_ip: <container-ip>
service_ports: [40000]
active_service_port: 40000
transport_mode: kcp
command_loop: ok
filter_configured: true
sees_sent_configured: unknown
listener_count: 1
```

This validates `LinkBuilder::build()`, AF_PACKET socket ownership, Linux
metadata discovery, socket filter installation, driver thread startup, listener
command handling, snapshot command handling, and clean shutdown.

The explicit simple fallback runtime smoke is:

```bash
docker run --rm \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD":/work -w /work \
  rust:1-bookworm \
  sh -lc 'LOCAL_IP=$(hostname -I | awk "{print \$1}"); cargo run --example runtime_smoke -- eth0 "$LOCAL_IP" 40000 --transport simple'
```

Expected differences from KCP mode:

- `transport_mode: simple`;
- `filter_configured: true`;
- same AF_PACKET/smoltcp/runtime command path.

## Two-container IPv4 KCP echo

Create an isolated Docker bridge network:

```bash
docker network create bpflink-smoke
```

Start the server in one terminal:

```bash
docker run --rm --name bpflink-server \
  --network bpflink-smoke \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD":/work -w /work \
  rust:1-bookworm \
  sh -lc 'LOCAL_IP=$(hostname -I | awk "{print \$1}"); cargo run --example echo_server -- --interface eth0 --local-ip "$LOCAL_IP" --service-port 40000 --expected-bytes 4096 --transport kcp'
```

From another terminal, resolve the server IP and run the client:

```bash
SERVER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bpflink-server)

docker run --rm --name bpflink-client \
  --network bpflink-smoke \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD":/work -w /work \
  rust:1-bookworm \
  sh -lc 'LOCAL_IP=$(hostname -I | awk "{print \$1}"); cargo run --example echo_client -- --interface eth0 --local-ip "$LOCAL_IP" --service-port 40000 --peer-ip '"$SERVER_IP"' --payload-bytes 4096 --transport kcp'
```

Expected result:

- server logs `received_bytes=4096` and `echoed_bytes=4096`;
- client logs `sent_bytes=4096`, `received_bytes=4096`, and
  `payload_match=true`;
- both processes exit successfully.

Clean up the network after the run:

```bash
docker network rm bpflink-smoke
```

## Two-container simple fallback smoke

Repeat the same server/client commands with `--transport simple` and a small
payload:

```bash
docker network create bpflink-smoke

docker run --rm --name bpflink-server \
  --network bpflink-smoke \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD":/work -w /work \
  rust:1-bookworm \
  sh -lc 'LOCAL_IP=$(hostname -I | awk "{print \$1}"); cargo run --example echo_server -- --interface eth0 --local-ip "$LOCAL_IP" --service-port 40000 --expected-bytes 256 --transport simple'
```

Client:

```bash
SERVER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bpflink-server)

docker run --rm --name bpflink-client \
  --network bpflink-smoke \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD":/work -w /work \
  rust:1-bookworm \
  sh -lc 'LOCAL_IP=$(hostname -I | awk "{print \$1}"); cargo run --example echo_client -- --interface eth0 --local-ip "$LOCAL_IP" --service-port 40000 --peer-ip '"$SERVER_IP"' --payload-bytes 256 --transport simple'
```

Expected result:

- client reports `payload_match=true`;
- simple transport uses the same Linux AF_PACKET and socket-filter backend.

Then clean up:

```bash
docker network rm bpflink-smoke
```

## Off-link IPv4 peer smoke

For peers outside the local prefix, the runtime reads the selected interface's
IPv4 default gateway and installs it into smoltcp's route table. This allows
the user-space stack to ARP the gateway and emit Ethernet frames whose IP
destination remains the off-link peer.

macOS client to remote Linux server:

```bash
# Linux server
docker run --rm --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD":/work -w /work \
  rust:1-bookworm \
  cargo run --example echo_server -- \
    --interface <linux-public-interface> \
    --local-ip <linux-public-ip> \
    --service-port 40030 \
    --expected-bytes 4096 \
    --transport kcp

# macOS client
cargo run --example echo_client -- \
  --interface <macos-interface> \
  --local-ip <macos-local-ip> \
  --service-port 40030 \
  --peer-ip <linux-public-ip> \
  --payload-bytes 4096 \
  --transport kcp
```

Expected result:

- client logs `sent_bytes`, `received_bytes`, and `payload_match=true`;
- server logs matching `received_bytes` and `echoed_bytes`;
- the path works through the selected interface's normal IPv4 gateway without
  changing host routing rules.

## Off-link IPv6 peer smoke

For IPv6 peers outside the selected interface prefix, the runtime reads the
selected interface's IPv6 default gateway from `/proc/net/ipv6_route` on Linux
or the route socket sysctl dump on macOS, then installs that gateway into
smoltcp's route table. This allows the user-space stack to resolve the gateway
with NDP and emit Ethernet frames whose IPv6 destination remains the off-link
peer.

This smoke requires both ends to have routable IPv6 addresses on Ethernet-like
interfaces. On macOS, do not use a `utun*` VPN interface for this BPF Ethernet
runtime; choose an interface with a configured global/ULA IPv6 address and an
IPv6 default gateway.

macOS client to remote Linux server:

```bash
# Linux server
docker run --rm --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD":/work -w /work \
  rust:1-bookworm \
  cargo run --example echo_server -- \
    --interface <linux-public-interface> \
    --local-ip <linux-public-ipv6> \
    --service-port 40031 \
    --expected-bytes 4096 \
    --transport kcp

# macOS client
cargo run --example echo_client -- \
  --interface <macos-interface> \
  --local-ip <macos-local-ipv6> \
  --service-port 40031 \
  --peer-ip <linux-public-ipv6> \
  --payload-bytes 4096 \
  --transport kcp
```

Expected result:

- client logs `sent_bytes`, `received_bytes`, and `payload_match=true`;
- server logs matching `received_bytes` and `echoed_bytes`;
- the path works through the selected interface's normal IPv6 gateway without
  changing host routing rules.

If macOS only has a link-local IPv6 address on the selected Ethernet interface,
the public-IPv6 off-link echo cannot run from that interface. In that case the
automated parser tests and smoltcp route-injection test still validate the code
path, but end-to-end public IPv6 echo needs a routable IPv6 address on the BPF
interface.

## Permission failure check

Docker's default capability set may already include `NET_RAW`. To validate the
failure path, explicitly drop it. Linux should fail clearly while opening the
AF_PACKET socket:

```bash
docker run --rm \
  --cap-drop NET_RAW \
  -v "$PWD":/work -w /work \
  rust:1-bookworm \
  cargo run --example bpf_smoke -- --interface eth0
```

Expected failure includes `socket AF_PACKET SOCK_RAW: Operation not permitted`
and a `CAP_NET_RAW` hint. Do not treat an unfiltered or partially configured
Linux backend as a successful smoke run.

## Observed Docker Validation

Last recorded validation: 2026-09-29.

Environment:

- Docker daemon: `29.6.1 linux/arm64`.
- Container image: `rust:1-bookworm`.
- Container kernel: `Linux 6.18.38-arcbox aarch64`.
- Rust toolchain: `rustc 1.98.1`, `cargo 1.98.1`.
- Interface: Docker `eth0`.
- Observed MTU: `1500`.

Automated Linux container verification:

```text
cargo fmt --check: pass
cargo clippy --all-targets --features test-util -- -D warnings: pass
cargo test --features test-util: pass
cargo check --examples: pass
cargo check --target x86_64-unknown-linux-gnu --features test-util: pass
```

IPv6 route discovery and injection coverage:

```text
Linux /proc/net/ipv6_route default-gateway parser test: pass
macOS route sysctl default IPv6 gateway parser test: pass
smoltcp off-link IPv6 default-route send test: pass
```

Remote Linux IPv6 runtime smoke:

```text
interface: <linux-public-interface>
local_ip: <linux-public-ipv6>
transport_mode: kcp
command_loop: ok
mtu: 1500
payload_target: 1200
sees_sent_configured: unknown
filter_configured: true
listener_count: 1
```

Single-container packet smoke:

```text
interface: eth0
open_config_read: ok
mtu: 1500
read_polls: 1
frames_seen: 0
sees_sent_configured: unknown
filter_configured: false
```

Single-container runtime smoke:

```text
local_ip: <container-ip>
transport_mode: kcp
command_loop: ok
mtu: 1500
payload_target: 1200
sees_sent_configured: unknown
filter_configured: true
listener_count: 1
```

Explicit simple runtime smoke:

```text
local_ip: <container-ip>
transport_mode: simple
command_loop: ok
filter_configured: true
```

Two-container IPv4 KCP echo:

```text
server eth0: <server-container-ip>
client eth0: <client-container-ip>
client sent_bytes=4096
client received_bytes=4096
client payload_match=true
server received_bytes=4096
server echoed_bytes=4096
```

Two-container explicit simple fallback echo:

```text
server eth0: <server-container-ip>
client eth0: <client-container-ip>
client sent_bytes=256
client received_bytes=256
client payload_match=true
server received_bytes=256
server echoed_bytes=256
```

Permission failure check with `--cap-drop NET_RAW`:

```text
bpflink bpf smoke failed: socket AF_PACKET SOCK_RAW: Operation not permitted (os error 1)
hint: Linux AF_PACKET sockets require CAP_NET_RAW
try: docker run --cap-add NET_RAW --cap-add NET_ADMIN ...
```

Cross-platform macOS `/dev/bpf*` <-> Linux `AF_PACKET` echo:

```text
macOS interface: <macos-vm-bridge-interface>
macOS local_ip: <macos-vm-bridge-ip>
Linux Docker host-network interface: <linux-host-interface>
Linux local_ip: <linux-host-ip>
Linux peer MAC as seen by macOS ARP: <linux-peer-mac>
MTU: 1500
```

KCP macOS client -> Linux server:

```text
client sent_bytes=4096
client received_bytes=4096
client payload_match=true
server received_bytes=4096
server echoed_bytes=4096
```

KCP Linux client -> macOS server:

```text
client sent_bytes=4096
client received_bytes=4096
client payload_match=true
server received_bytes=4096
server echoed_bytes=4096
```

Simple macOS client -> Linux server:

```text
client sent_bytes=256
client received_bytes=256
client payload_match=true
server received_bytes=256
server echoed_bytes=256
```

Simple Linux client -> macOS server:

```text
client sent_bytes=256
client received_bytes=256
client payload_match=true
server received_bytes=256
server echoed_bytes=256
```

Off-link IPv4 macOS client -> remote Linux server:

```text
macOS interface: <macos-interface>
macOS local_ip: <macos-local-ip>
macOS default gateway: <macos-default-gateway>
Linux interface: <linux-public-interface>
Linux local_ip: <linux-public-ip>
```

KCP:

```text
client sent_bytes=4096
client received_bytes=4096
client payload_match=true
server received_bytes=4096
server echoed_bytes=4096
```

Simple:

```text
client sent_bytes=256
client received_bytes=256
client payload_match=true
server received_bytes=256
server echoed_bytes=256
```

Off-link IPv6 macOS client -> remote Linux server readiness:

```text
macOS selected Ethernet interface: <macos-interface>
macOS selected-interface IPv6 state: <global-or-ula-ipv6-required>
macOS selected-interface IPv6 default gateway: <ipv6-default-gateway-required>
Linux interface: <linux-public-interface>
Linux local_ip: <linux-public-ipv6>
```

The implementation and parser tests are present. A public-IPv6 end-to-end BPF
echo should be run when the macOS selected Ethernet interface has a routable
IPv6 address and an IPv6 default gateway. A host where public IPv6 egress is
only available through `utun*` is not a valid target for this Ethernet BPF
smoke.
