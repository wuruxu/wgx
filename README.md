<h1>
  <img src="wgx-logo.png" alt="WG^x logo" width="128" height="128" style="vertical-align: middle;">
</h1>
wgx is a high-performance WireGuard client in userspace. It supports both a
local SOCKS5 proxy mode and a TUN-device mode that is compatible with the
standard `wireguard-go`/`wg` userspace workflow.

It is inspired by [wireproxy](https://github.com/windtf/wireproxy), but takes a different implementation path: `wgx` is written in C, built on [libuv](https://libuv.org/), and implements WireGuard and a TCP forwarding path in userspace with performance as the first priority.

The two supported modes are:

```text
SOCKS5 mode:
browser / curl / app -> SOCKS5 -> wgx -> WireGuard UDP tunnel -> Internet

TUN mode:
browser / curl / app -> Linux routing -> TUN -> wgx -> WireGuard UDP tunnel -> Internet
```

No TUN device is required for SOCKS5 mode, and the process does not need root
privileges for normal proxy usage. TUN mode is available when you want a
drop-in userspace WireGuard interface with the familiar `wg` UAPI control path.

## Features

- WireGuard client implemented in userspace.
- Local SOCKS5 proxy for TCP traffic.
- TUN-device mode for system routing through a WireGuard interface.
- Fully compatible with the standard `wireguard-go`/`wg` UAPI workflow in TUN mode.
- Written in C with libuv event loops.
- c-ares based asynchronous DNS resolver with optional cache.
- IPv4 and IPv6 WireGuard tunnel source address support.
- Reads standard WireGuard `.conf` files.
- Can auto-detect the local tunnel address from `[Interface] Address`.
- Optimized userspace TCP path for large pages and large resources:
  - delayed ACK
  - SACK blocks
  - receive-window backpressure
  - ring buffers for pending and send queues

## Requirements

Linux is the primary target.

Dependencies:

- libuv
- libsodium
- c-ares
- pthread

On Debian / Ubuntu:

```bash
sudo apt install build-essential libuv1-dev libsodium-dev libc-ares-dev
```

## Build

```bash
make
```

The binary is created as:

```bash
./wgx
```

## SOCKS5 Mode

Start a SOCKS5 proxy from a WireGuard config:

```bash
./wgx --socks5 127.0.0.1:8899 --config wg0.conf
```

SOCKS5 username/password authentication is also supported:

```bash
./wgx --socks5 user:pass@127.0.0.1:8899 --config wg0.conf
```

If `USER:PASS@` is present, clients must authenticate with the same username and password. If it is omitted, the proxy runs in no-auth mode.

If your config contains an `Address` entry, `wgx` will use it automatically:

```ini
[Interface]
PrivateKey = ...
Address = 10.67.179.113/32, fc00:bbbb:bbbb:bb01::4:b370/128
DNS = 1.1.1.1

[Peer]
PublicKey = ...
# Optional:
PresharedKey = <base64-preshared-key>
Endpoint = wg.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
```

You can still override the address from the command line:

```bash
./wgx \
  --socks5 127.0.0.1:8899 \
  --wg-addr 192.168.111.6 \
  --wg-addr6 fd08:5399:1111::6 \
  --config wg0.conf
```

Command-line addresses have priority over `[Interface] Address`.

## Use With curl

Use remote DNS resolution through SOCKS5:

```bash
curl --socks5-hostname 127.0.0.1:8899 https://www.kernel.org/
```

With SOCKS5 username/password authentication:

```bash
curl --socks5-hostname user:pass@127.0.0.1:8899 https://www.kernel.org/
```

## Use With Chrome

```bash
google-chrome --proxy-server="socks5://127.0.0.1:8899"
```

With username/password authentication, Chrome will prompt for credentials when the proxy requires them:

```bash
google-chrome --proxy-server="socks5://127.0.0.1:8899"
```

## Configuration

`wgx` accepts standard WireGuard-style config files:

```ini
[Interface]
PrivateKey = <private-key>
Address = <ipv4-cidr>, <ipv6-cidr>
DNS = <dns-server-ip>[, <dns-server-ip>]
ListenPort = 51820

[Peer]
PublicKey = <peer-public-key>
PresharedKey = <optional-psk>
Endpoint = <host>:<port>
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

In SOCKS5 mode, `Address` is used as the local source address inside the WireGuard tunnel. If no IPv4 address is present in the config, pass `--wg-addr` explicitly.

In SOCKS5 mode, `DNS` is used by the local SOCKS5 resolver for domain names sent by clients, for example `DNS = 192.168.111.1` or `DNS = 192.168.111.1, fd00::1`. Only DNS server IP addresses are used; search domains are ignored. `SOCKS5_DNS_SERVER` can still be set to override the config value.

## Logging

```bash
LOG_LEVEL=debug ./wgx --socks5 127.0.0.1:8899 --config wg0.conf
```

Supported values:

- `silent`
- `error`
- `verbose`
- `debug`

## TUN Mode

`wgx` also supports TUN-device mode. This mode is designed to work like a
userspace WireGuard implementation such as `wireguard-go`: `wgx` creates and
drives the TUN interface, exposes a WireGuard UAPI socket under
`/var/run/wireguard/<interface>.sock`, and can be configured with the standard
`wg` command.

```bash
sudo ./wgx -f wg0
```

In another terminal, apply a stripped WireGuard config and configure the
interface address/routes:

```bash
wg-quick strip wg0.conf > /tmp/wg0.stripped.conf
sudo wg setconf wg0 /tmp/wg0.stripped.conf
sudo ip addr add 192.168.111.6/32 dev wg0
sudo ip route add 1.1.1.1/32 dev wg0
curl --interface wg0 https://1.1.1.1/cdn-cgi/trace
```

TUN mode requires root privileges and external interface/route setup, matching
the behavior expected by users of `wireguard-go` and the standard WireGuard
tools.

## Project Goals

`wgx` is designed for users who want either a WireGuard-backed SOCKS5 proxy or
a userspace TUN interface with low overhead and good behavior under browser and
curl workloads.

The implementation favors:

- performance first
- predictable event-driven I/O
- fewer blocking operations
- efficient handling of concurrent connections
- robust behavior on large web pages and large assets

## Credits

This project is inspired by [wireproxy](https://github.com/windtf/wireproxy).

WireGuard is a registered trademark of Jason A. Donenfeld. This project is an independent userspace implementation and is not affiliated with the official WireGuard project.
