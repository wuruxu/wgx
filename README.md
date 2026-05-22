<h1>
  <img src="wgx-logo.png" alt="WG^x logo" width="68" height="68" style="vertical-align: middle;">
   wgx
</h1>
wgx is a high-performance WireGuard client in userspace that exposes as a local SOCKS5 proxy.

It is inspired by [wireproxy](https://github.com/windtf/wireproxy), but takes a different implementation path: `wgx` is written in C, built on [libuv](https://libuv.org/), and implements WireGuard and a TCP forwarding path in userspace with performance as the first priority.

The main use case is simple:

```text
browser / curl / app -> SOCKS5 -> wgx -> WireGuard UDP tunnel -> Internet
```

No TUN device is required for SOCKS5 mode, and the process does not need root privileges for normal proxy usage.

## Features

- WireGuard client implemented in userspace.
- Local SOCKS5 proxy for TCP traffic.
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
- OpenSSL / libcrypto
- c-ares
- pthread

On Debian / Ubuntu:

```bash
sudo apt install build-essential libuv1-dev libssl-dev libc-ares-dev
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

[Peer]
PublicKey = ...
Endpoint = example.com:51820
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
ListenPort = 51820

[Peer]
PublicKey = <peer-public-key>
PresharedKey = <optional-psk>
Endpoint = <host>:<port>
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

In SOCKS5 mode, `Address` is used as the local source address inside the WireGuard tunnel. If no IPv4 address is present in the config, pass `--wg-addr` explicitly.

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

`wgx` also contains a TUN-device mode, but the primary focus of this project is SOCKS5 proxy mode.

```bash
sudo ./wgx wg0
```

TUN mode requires root privileges and external interface/route setup, similar to other userspace WireGuard implementations.

## Project Goals

`wgx` is designed for users who want a WireGuard-backed SOCKS5 proxy with low overhead and good behavior under browser workloads.

The implementation favors:

- performance first
- predictable event-driven I/O
- fewer blocking operations
- efficient handling of concurrent connections
- robust behavior on large web pages and large assets

## Credits

This project is inspired by [wireproxy](https://github.com/windtf/wireproxy).

WireGuard is a registered trademark of Jason A. Donenfeld. This project is an independent userspace implementation and is not affiliated with the official WireGuard project.
