# rawsocket

`rawsocket` is a Go library for crafting and sending raw IP packets.

It supports TCP, UDP, ICMP, IGMP, ESP, and custom raw IP payloads, with a cross-platform socket abstraction for sending and receiving packets.

## Safety and Permissions

Raw networking can affect live systems.

- Use only in environments you control.
- Linux/macOS usually require root or `CAP_NET_RAW`.
- Windows requires administrator privileges and packet-capture support.

## Installation

```bash
go get github.com/obeliskdev/rawsocket
```

## Quick Start

### 1. Build a TCP packet

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

## Packet Builders

Convenience helpers:
- `BuildTCPPacket`, `BuildUDPPacket`
- `BuildICMPPacket`, `BuildIGMPPacket`
- `BuildESPPacket`, `BuildRawIPPacket`

Builder constructors:
- `NewTCP`, `NewUDP`, `NewICMP`, `NewIGMP`, `NewESP`, `NewRawIP`

Each builder supports options (`WithTCP...`, `WithUDP...`, etc.) for protocol-specific fields and payloads.

## Socket API

`OpenRawSocket(protocol)` returns a `RawSocket` with:
- `Write([]byte, net.Addr)`
- `Read([]byte)`
- `NextPacket()` (decoded `gopacket.Packet`)
- `Iter()` (packet stream channel)
- `Close()`

## Utilities

- `GetSelfIP()` returns local outbound IPv4.
- `ToIPIterator(...)` accepts IPs, CIDRs, and ranges.

### Example: Iterate Targets

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

## Notes

- Prefer `Build...Packet(...)([]byte, error)` helpers in production so errors are explicit.
- ICMP/IGMP builders operate on IPv4 packet formats.

## Testing

```bash
go test ./...
```

Some tests may require elevated network permissions.

## License

MIT. See `LICENSE`.
