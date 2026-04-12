# wgx

A userspace WireGuard daemon written in C, built on top of libuv.  
It implements the [WireGuard protocol](https://www.wireguard.com/protocol/) entirely in userspace — no kernel module required.

Two operating modes are supported:

| Mode | Interface | Use case |
|------|-----------|----------|
| **TUN mode** | Creates a kernel TUN device | Drop-in replacement for `wg-quick` / `wireguard-tools` |
| **SOCKS5 mode** | No TUN, no root required | Transparent TCP proxy through a WireGuard tunnel |

---

## Table of Contents

- [Requirements](#requirements)
- [Building](#building)
- [TUN Mode](#tun-mode)
- [SOCKS5 Mode](#socks5-mode)
- [Configuration File Format](#configuration-file-format)
- [Environment Variables](#environment-variables)
- [Logging](#logging)
- [Architecture Notes](#architecture-notes)

---

## Requirements

| Dependency | Notes |
|------------|-------|
| Linux kernel ≥ 4.1 | TUN mode needs `tun` module |
| libuv ≥ 1.x | Event loop |
| OpenSSL ≥ 1.1 | ChaCha20-Poly1305 AEAD |
| wireguard-tools | Optional — only needed for `wg setconf` / `wg show` in TUN mode |

Install on Ubuntu / Debian:

```bash
sudo apt install libuv1-dev libssl-dev wireguard-tools
```

Install on Arch Linux:

```bash
sudo pacman -S libuv openssl wireguard-tools
```

---

## Building

```bash
git clone https://github.com/yourname/wgx
cd wgx
make
```

The binary is `wgx` in the project root.

```bash
# Optional: install system-wide
sudo make install        # installs to /usr/local/bin/wgx
```

---

## TUN Mode

TUN mode creates a real network interface, exactly like the reference userspace implementation `wireguard-go`.  
You configure it with standard `wg` / `wg-quick` tooling.

### Quickstart

```bash
# 1. Create the TUN interface and start the daemon (requires root)
sudo wgx wg0

# 2. Assign the VPN IP address
sudo ip address add dev wg0 10.0.0.2/24

# 3. Load the WireGuard configuration
sudo wg setconf wg0 /etc/wireguard/wg0.conf

# 4. Bring the interface up
sudo ip link set wg0 up
```

### Foreground mode (useful for debugging)

```bash
LOG_LEVEL=verbose sudo wgx --foreground wg0
# or
LOG_LEVEL=verbose sudo wgx -f wg0
```

### Daemonize (default)

Without `--foreground`, `wgx` forks into the background automatically.

```bash
sudo wgx wg0
# Process exits immediately; daemon runs in background.
# Check status:
sudo wg show wg0
```

### Full example: connecting to a VPN server

Given `/etc/wireguard/wg0.conf`:

```ini
[Interface]
PrivateKey = <your-private-key>

[Peer]
PublicKey = <server-public-key>
Endpoint = vpn.example.com:51820
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
```

```bash
# Start daemon
sudo wgx wg0

# Configure IP + route
sudo ip address add dev wg0 10.0.0.2/32
sudo wg setconf wg0 /etc/wireguard/wg0.conf
sudo ip link set wg0 up

# Route traffic through the VPN
sudo ip route add 10.0.0.0/24 dev wg0

# Verify handshake
sudo wg show wg0
```

### Full tunnel (route all traffic through VPN)

```bash
sudo wgx wg0
sudo ip address add dev wg0 10.0.0.2/32
sudo wg setconf wg0 /etc/wireguard/wg0.conf
sudo ip link set wg0 up

# Save default gateway before changing it
DEFAULT_GW=$(ip route show default | awk '{print $3; exit}')
DEFAULT_IF=$(ip route show default | awk '{print $5; exit}')

# Route VPN server directly via original gateway
sudo ip route add vpn.example.com/32 via $DEFAULT_GW dev $DEFAULT_IF

# Send everything else through WireGuard
sudo ip route add 0.0.0.0/0 dev wg0
```

---

## SOCKS5 Mode

SOCKS5 mode starts a standard SOCKS5 proxy (RFC 1928) that tunnels all TCP connections through a WireGuard encrypted channel — **with no TUN device and no kernel interface**.

The daemon includes a userspace TCP/IP stack that sends and receives raw IPv4 packets inside WireGuard transport messages.  
It reads the WireGuard configuration directly from a `.conf` file, so **no `wg setconf` or root privileges are needed**.

### Usage

```bash
wgx \
  --socks5 BIND-ADDR:PORT \
  --wg-addr MY-VPN-IP \
  --config /path/to/wg.conf
```

| Flag | Description |
|------|-------------|
| `--socks5 ADDR:PORT` | Bind address and port for the local SOCKS5 server |
| `--wg-addr IP` | Your WireGuard VPN IP address (used as the source IP in tunneled packets) |
| `--config FILE` | Path to a standard WireGuard `.conf` file |

### Quickstart

```bash
# Start the SOCKS5 proxy on 127.0.0.1:1080
./wgx \
  --socks5 127.0.0.1:1080 \
  --wg-addr 192.168.111.6 \
  --config wg1.conf
```

```
wgx SOCKS5 proxy: 127.0.0.1:1080  VPN-IP=192.168.111.6  config=wg1.conf
```

Then in another terminal:

```bash
# curl
curl --socks5 127.0.0.1:1080 http://ipinfo.io

# wget
wget -e "https_proxy=socks5://127.0.0.1:1080" https://example.com

# or export globally for the session
export ALL_PROXY=socks5://127.0.0.1:1080
curl http://ipinfo.io
```

### Example: checking your public IP

```bash
# Start proxy
./wgx --socks5 127.0.0.1:1080 --wg-addr 10.0.0.2 --config wg0.conf &

# Wait for handshake (~2s)
sleep 3

# Should show the VPN server's public IP, not your own
curl --socks5 127.0.0.1:1080 https://ipinfo.io/ip
```

### Example: using with git

```bash
export ALL_PROXY=socks5://127.0.0.1:1080
git clone https://github.com/yourname/yourrepo
```

### Example: using with ssh (via nc proxy)

```bash
ssh -o ProxyCommand='nc -x 127.0.0.1:1080 %h %p' user@internal-host
```

### Example: verbose logging to diagnose handshake

```bash
LOG_LEVEL=verbose ./wgx \
  --socks5 127.0.0.1:1080 \
  --wg-addr 10.0.0.2 \
  --config wg0.conf
```

Output shows:

```
[14:02:01.123] (wg0) Sent handshake initiation (our_idx=0x3f1a2b0c)
[14:02:01.387] (wg0) UDP recv: type=2 len=92 from 203.0.113.1
[14:02:01.388] (wg0) Session established (initiator)
SOCKS5 proxy listening on 127.0.0.1:1080
```

### How SOCKS5 mode works

```
curl ──SOCKS5──► wgx ──WireGuard/UDP──► WireGuard server ──► Internet
                 (userspace                      (kernel or
                  TCP/IP stack)                   userspace)
```

1. curl sends a SOCKS5 CONNECT request for e.g. `ipinfo.io:80`
2. wgx resolves the hostname and builds a TCP SYN packet
3. The SYN is encrypted and sent as a WireGuard transport message over UDP
4. The remote WireGuard server decapsulates it and forwards the TCP connection
5. The SYN-ACK comes back through the tunnel; the handshake completes
6. Data flows bidirectionally through the encrypted tunnel

**Supported SOCKS5 address types:**
- IPv4 (`ATYP=1`)
- Domain name (`ATYP=3`) — resolved via `getaddrinfo` / system DNS
- IPv6 (`ATYP=4`) — connection refused (IPv4 only tunnel)

---

## Configuration File Format

Both modes use the standard WireGuard `.conf` format.

```ini
[Interface]
PrivateKey = <base64-encoded 32-byte private key>
ListenPort = 51820          # optional; 0 = random port

[Peer]
PublicKey = <base64-encoded 32-byte public key>
PresharedKey = <base64>     # optional
Endpoint = host:port        # hostname or IP
AllowedIPs = 0.0.0.0/0     # comma-separated CIDRs
PersistentKeepalive = 25    # seconds; 0 = disabled
```

Multiple `[Peer]` sections are supported.

### Generating keys

```bash
# Private key
wg genkey

# Public key from private key
echo "<private-key>" | wg pubkey

# Preshared key
wg genpsk
```

---

## Environment Variables

| Variable | Values | Description |
|----------|--------|-------------|
| `LOG_LEVEL` | `silent`, `error` (default), `verbose` | Control log verbosity |
| `WG_TUN_FD` | integer | Pre-opened TUN file descriptor (for daemonize) |
| `WG_PROCESS_FOREGROUND` | `1` | Force foreground mode |

---

## Logging

Log output goes to **stderr** and is controlled by `LOG_LEVEL`:

```bash
# No output (silent)
LOG_LEVEL=silent wgx wg0

# Errors only (default)
wgx wg0

# Full debug output
LOG_LEVEL=verbose wgx --foreground wg0
```

Log format:

```
[HH:MM:SS.mmm] (ifname) message
```

Example verbose output during handshake:

```
[10:15:42.001] (wg0) Device started on port 51820 (IPv6: yes)
[10:15:42.120] (wg0) Sent handshake initiation (our_idx=0xdeadbeef)
[10:15:42.341] (wg0) UDP recv: type=2 len=92 from 203.0.113.1
[10:15:42.342] (wg0) Session established (initiator)
[10:15:42.342] (wg0) Sent handshake initiation flushed 0 queued packets
```

---

## Architecture Notes

```
wgx/src/
├── main.c          — argument parsing, startup, signal handling
├── device.c        — device lifecycle, packet routing, UDP recv/send
├── noise.c         — Noise_IKpsk2 handshake protocol
├── crypto.c        — ChaCha20-Poly1305, BLAKE2s, HKDF
├── blake2s.c       — BLAKE2s hash
├── allowedips.c    — radix trie for IP→peer routing
├── replay.c        — anti-replay sliding window
├── timers.c        — retransmit, keepalive, rekey timers
├── uapi.c          — WireGuard UAPI socket (wg-tools compatible)
├── tun.c           — TUN device open/read/write
├── tai64n.c        — TAI64N timestamp
├── conf.c          — .conf file parser (SOCKS5 mode)
├── tcpstack.c      — userspace IPv4/TCP stack (SOCKS5 mode)
└── socks5.c        — SOCKS5 server (SOCKS5 mode)
```

The event loop (libuv) drives all I/O: UDP receive, TUN polling, UAPI connections, SOCKS5 client connections, TCP retransmit timers, and WireGuard keepalive timers — all single-threaded except for `pthread_mutex`-protected handshake state.
