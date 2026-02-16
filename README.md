# rawsocket

`rawsocket` is a Go library for building and sending raw IP packets with a compact API.

It supports packet construction for TCP, UDP, ICMP, IGMP, ESP, and custom raw IP payloads, then sends/receives packets through a cross-platform `RawSocket` interface.

## Features

- Build IPv4 and IPv6 packets for:
  - TCP
  - UDP
  - ICMP (IPv4)
  - IGMP (IPv4)
  - ESP
  - Raw IP (custom protocol number)
- Functional options API (`WithTCP...`, `WithUDP...`, etc.)
- Automatic IP header lengths and checksums (`gopacket` serialization)
- Cross-platform socket abstraction:
  - Unix-like systems: native raw sockets
  - Windows: `pcap` backend
- Streaming packet read API:
  - `Read([]byte)`
  - `NextPacket()` (decoded `gopacket.Packet`)
  - `Iter()` channel iterator
- Utility helpers:
  - `GetSelfIP()`
  - `ToIPIterator(...)` for IP/cidr/range iteration and shuffling

## Requirements

- Go `1.25+`
- Raw socket permissions:
  - Linux/macOS: usually root or `CAP_NET_RAW`
  - Windows: administrator/Npcap privileges

## Installation

```bash
go get github.com/obeliskdev/rawsocket
```

## Quick Start

### 1) Build a TCP SYN packet

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
		rawsocket.WithTCPSequence(12345),
		rawsocket.WithTCPWindow(65535),
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("built %d bytes\n", len(packet))
}
```

### 2) Send it on a raw socket

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

### 3) Receive packets

```go
buf := make([]byte, 65535)
n, addr, err := sock.Read(buf)
if err != nil {
	panic(err)
}
fmt.Printf("read %d bytes from %s\n", n, addr.String())
```

Or use decoded packets:

```go
pkt, srcAddr, err := sock.NextPacket()
if err != nil {
	panic(err)
}
fmt.Println("from", srcAddr, "layers:", pkt.Layers())
```

## Packet Builders

All builders expose:

- `Build(...) []byte` (returns `nil` on error)
- `BuildWithError(...) ([]byte, error)`

For production code, prefer `BuildWithError`.

### TCP

Create via:

- `NewTCP(opts...)`
- `BuildTCPPacket(src, dst, opts...)`

Options include flags, sequence/ack/window, payload, and custom TCP options:

- `WithTCPSYN`, `WithTCPACK`, `WithTCPRST`, `WithTCPPSH`, `WithTCPFIN`, `WithTCPURG`, `WithTCPECE`, `WithTCPCWR`, `WithTCPNS`
- `WithTCPSequence`, `WithTCPAckNumber`, `WithTCPWindow`
- `WithTCPPayload`
- `WithTCPOptions`

### UDP

- `NewUDP(opts...)`
- `BuildUDPPacket(src, dst, opts...)`
- `WithUDPPayload`

### ICMP (IPv4)

- `NewICMP(opts...)`
- `BuildICMPPacket(src, dst, opts...)`
- `WithICMPType`, `WithICMPPayload`

Note: ICMP builder currently supports IPv4 addresses only.

### IGMP (IPv4)

- `NewIGMP(opts...)`
- `BuildIGMPPacket(src, dst, opts...)`
- `WithIGMPType`, `WithIGMPMaxResponseTime`, `WithIGMPGroupAddress`

Note: IGMP builder currently supports IPv4 addresses only.

### ESP

- `NewESP(opts...)`
- `BuildESPPacket(src, dst, opts...)`
- `WithESPSPI`, `WithESPSequence`, `WithESPPayload`

### Raw IP

- `NewRawIP(opts...)`
- `BuildRawIPPacket(src, dst, opts...)`
- `WithRawIPProtocol`, `WithRawIPPayload`

Use this when you want a custom IP protocol number and payload bytes.

## How It Works

### Build path

1. A builder prepares IPv4 or IPv6 header fields from source/destination addresses.
2. Transport/body layers are assembled (TCP/UDP/ICMP/etc.).
3. `gopacket.SerializeLayers` writes a packet with:
   - `FixLengths: true`
   - `ComputeChecksums: true`
4. The serialized bytes are returned as a standalone slice.

### Socket path

`OpenRawSocket(protocol)` returns a `RawSocket`:

- Unix-like: raw socket (`AF_INET`, `SOCK_RAW`, `IP_HDRINCL`)
- Windows: pcap capture/injection handle, protocol-filtered on read

The interface is:

```go
type RawSocket interface {
	Write([]byte, net.Addr) (int, error)
	Read([]byte) (int, net.Addr, error)
	NextPacket() (gopacket.Packet, *net.IPAddr, error)
	Iter() chan WrappedPacket
	Close() error
}
```

### IP helpers

`GetSelfIP()` caches and returns the host outbound/local interface IPv4.

`ToIPIterator(data...)` accepts:

- Single IP (`"1.1.1.1"`)
- CIDR (`"10.0.0.0/24"`)
- Range (`"192.168.1.10-192.168.1.20"`)

Iterator methods:

- `Next()`
- `HasNext()`
- `Shuffle()`
- `SetSkipLocal(true)`

## Example: Iterate Targets and Send UDP

```go
it := rawsocket.ToIPIterator("1.1.1.1", "8.8.8.0/30")
it.SetSkipLocal(true)
it.Shuffle()

sock, err := rawsocket.OpenRawSocket(rawsocket.IPPROTO_UDP)
if err != nil {
	panic(err)
}
defer sock.Close()

src := net.UDPAddr{IP: rawsocket.GetSelfIP(), Port: 53000}

for it.HasNext() {
	ip := it.Next()
	if ip == nil {
		break
	}

	dst := net.UDPAddr{IP: ip, Port: 53}
	pkt, err := rawsocket.BuildUDPPacket(src, dst, rawsocket.WithUDPPayload([]byte("hello")))
	if err != nil {
		continue
	}

	_, _ = sock.Write(pkt, &net.IPAddr{IP: ip})
}
```

## Notes and Caveats

- Sending raw packets can disrupt networks; use only in environments you control.
- Permissions are required to open raw sockets.
- `Build(...)` methods swallow errors; use `BuildWithError(...)` in non-trivial code.
- TCP "legit option" generation exists on the `TCP` struct (`LegitOptions`), but there is no dedicated option helper for it yet.

## Development

Run tests:

```bash
go test ./...
```

Some tests require raw socket privileges and may skip without permissions.
