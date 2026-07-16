# rawsocket — Go Raw IP Packet Builder & Cross-Platform Raw Socket Library

[![Go Reference](https://pkg.go.dev/badge/github.com/obeliskdev/rawsocket.svg)](https://pkg.go.dev/github.com/obeliskdev/rawsocket)
[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8.svg)](https://go.dev)

`rawsocket` is a high-performance Go library for crafting, sending, and receiving raw IP packets.
It supports TCP, UDP, ICMP, IGMP, ESP, and custom raw IP payloads with a unified cross-platform
socket abstraction (pcap on Windows, `AF_INET/SOCK_RAW` on Linux/macOS).

## Features

- **Packet crafting** — Build TCP, UDP, ICMP, IGMP, ESP, and raw IP packets with a fluent options API
- **Cross-platform** — Windows (pcap/Npcap) and Unix (raw sockets) via a single `RawSocket` interface
- **Zero-allocation hot paths** — Builders use `sync.Pool` and stack-allocated scratch buffers; `IPIterator.Next()` is alloc-free after warmup
- **IPv4 & IPv6** — TCP/UDP/RawIP builders auto-select IP version; ICMP/IGMP are IPv4-only
- **TCP legit options** — Automatic MSS, window scale, timestamps, and SACK for realistic SYN/ACK/FIN packets
- **IP range iteration** — Parse CIDRs, ranges, and single IPs; shuffle and skip-local-address support
- **Thread-safe** — `GetSelfIP` uses `sync.Once`; all shared state is lock-protected
- **Packet stream** — `Iter()` returns a channel for reactive packet processing

## Safety and Permissions

Raw networking can affect live systems.

- Use only in environments you control.
- Linux/macOS usually require root or `CAP_NET_RAW`.
- Windows requires administrator privileges and [Npcap](https://npcap.com/) with packet-capture support.

## Installation

```bash
go get github.com/obeliskdev/rawsocket
```

## Quick Start

### 1. Build a TCP SYN packet

```go
package main

import (
	"fmt"
	"net"

	"github.com/obeliskdev/rawsocket"
)

func main() {
	src := net.TCPAddr{IP: net.IPv4(10, 0, 0, 10), Port: 45000}
	dst := net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443}

	packet, err := rawsocket.BuildTCPPacket(
		src,
		dst,
		rawsocket.WithTCPSYN(true),
		rawsocket.WithTCPSequence(1001),
		rawsocket.WithTCPWindow(65535),
		rawsocket.WithTCPLegitOptions(true), // MSS + window scale + timestamps
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("packet size:", len(packet))
}
```

### 2. Send on a raw socket

```go
sock, err := rawsocket.OpenRawSocket(rawsocket.IPPROTO_TCP)
if err != nil {
	panic(err)
}
defer sock.Close()

_, err = sock.Write(packet, &net.IPAddr{IP: dst.IP})
if err != nil {
	panic(err)
}
```

### 3. Receive packets

```go
buf := make([]byte, 65535)
n, from, err := sock.Read(buf)
if err != nil {
	panic(err)
}
fmt.Println("read", n, "bytes from", from.String())
```

### 4. Stream packets via channel

```go
for wp := range sock.Iter() {
	fmt.Printf("from %s: %d bytes\n", wp.IPAddr, len(wp.Packet.Data()))
}
```

## Packet Builders

### Convenience helpers

Each returns `([]byte, error)` so errors are explicit in production code:

| Helper | Protocol | Address Type |
|--------|----------|--------------|
| `BuildTCPPacket` | TCP | `net.TCPAddr` |
| `BuildUDPPacket` | UDP | `net.UDPAddr` |
| `BuildICMPPacket` | ICMPv4 | `net.IPAddr` |
| `BuildIGMPPacket` | IGMP | `net.IPAddr` |
| `BuildESPPacket` | ESP | `net.IPAddr` |
| `BuildRawIPPacket` | Custom IP | `net.IPAddr` |

### Builder constructors

`NewTCP`, `NewUDP`, `NewICMP`, `NewIGMP`, `NewESP`, `NewRawIP` — each accepts variadic options.

### Available options

**TCP:** `WithTCPSYN`, `WithTCPACK`, `WithTCPRST`, `WithTCPPSH`, `WithTCPFIN`, `WithTCPURG`,
`WithTCPECE`, `WithTCPCWR`, `WithTCPNS`, `WithTCPSequence`, `WithTCPAckNumber`, `WithTCPWindow`,
`WithTCPPayload`, `WithTCPOptions`, `WithTCPLegitOptions`

**UDP:** `WithUDPPayload`

**ICMP:** `WithICMPType`, `WithICMPPayload`

**IGMP:** `WithIGMPType`, `WithIGMPMaxResponseTime`, `WithIGMPGroupAddress`

**ESP:** `WithESPSPI`, `WithESPSequence`, `WithESPPayload`

**RawIP:** `WithRawIPProtocol`, `WithRawIPPayload`

### IPv6 support

TCP, UDP, and RawIP builders automatically detect IPv4/IPv6 based on the source and destination
addresses. ICMP and IGMP builders currently support IPv4 only.

## Socket API

`OpenRawSocket(protocol)` returns a `RawSocket` interface:

```go
type RawSocket interface {
    Write([]byte, net.Addr) (int, error)
    Read([]byte) (int, net.Addr, error)
    NextPacket() (gopacket.Packet, *net.IPAddr, error)
    Iter() chan WrappedPacket
    Close() error
}
```

### Supported protocols

| Constant | Description |
|----------|-------------|
| `IPPROTO_TCP` | TCP packets |
| `IPPROTO_UDP` | UDP packets |
| `IPPROTO_ICMP` | ICMP (v4/v6 auto-selected) |
| `IPPROTO_IGMP` | IGMP |
| `IPPROTO_ESP` | IPSec ESP |
| `IPPROTO_IP` | All IP packets |
| `IPPROTO_RAW` | Raw (no protocol filtering) |

## Utilities

### GetSelfIP

```go
ip := rawsocket.GetSelfIP() // cached, thread-safe, returns IPv4
```

Discovers the local outbound IPv4 address via a UDP dial (with 5s timeout), falling back to
interface enumeration. Result is computed once via `sync.Once`.

### IPIterator

Accepts IPs, CIDRs, and hyphenated ranges. Supports shuffle and skip-local filtering.

```go
it := rawsocket.ToIPIterator("8.8.8.8", "1.1.1.0/30", "192.168.1.10-192.168.1.12")
it.SetSkipLocal(true)
it.Shuffle()

for it.HasNext() {
	ip := it.Next()
	if ip == nil {
		break
	}
	// build/send packet to ip
}
```

`Next()` is zero-allocation after the first call — IPs are incremented in place.

## Performance

Builders use `sync.Pool` for scratch buffers and stack-allocated layer slices to minimize
garbage collection pressure. Benchmark results (Windows, i7-13700K):

| Benchmark | ns/op | B/op | allocs/op |
|-----------|-------|------|-----------|
| UDPBuild | ~140 | 120 | 2 |
| ICMPBuild | ~145 | 120 | 2 |
| TCPBuildSYN | ~107 | 48 | 1 |
| IGMPBuild | ~125 | 64 | 3 |
| ESPBuild | ~120 | 248 | 3 |
| RawIPBuild | ~100 | 120 | 2 |

Run benchmarks:

```bash
go test -bench=Benchmark -benchmem -run=^Benchmark
```

## Testing

```bash
go test -race ./...
```

Some tests require elevated network permissions (root/admin) and may be skipped automatically
in unprivileged environments.

## Notes

- Prefer `Build...Packet(...)` helpers in production so errors are explicit.
- ICMP/IGMP builders operate on IPv4 packet formats only.
- The `LegitOptions` flag on TCP generates realistic TCP options (MSS, window scale,
  timestamps, SACK) for SYN/ACK/FIN packets to mimic legitimate traffic.
- Windows requires [Npcap](https://npcap.com/) installed for pcap-based capture.

## License

MIT. See `LICENSE`.