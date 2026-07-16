package rawsocket

import (
	"net"

	"github.com/google/gopacket"
	"github.com/obeliskdev/fastrand"
)

func validPort(port int) int {
	if port <= 0 {
		return fastrand.Int(1, 65535)
	}
	if port > 65535 {
		return 65535
	}
	return port
}

type packetFetcher func() (gopacket.Packet, *net.IPAddr, error)

// packetIter fetches packets via fetch and sends them on packets.
// It stops when fetch returns an error or when the caller closes or
// drains the channel (detected via a panic on send).
func packetIter(packets chan WrappedPacket, fetch packetFetcher) {
	for {
		packet, addr, err := fetch()
		if err != nil {
			return
		}

		if !sendPacket(packets, WrappedPacket{IPAddr: addr, Packet: packet}) {
			return
		}
	}
}

// sendPacket sends wp on ch. Returns false if ch was closed by the caller.
func sendPacket(ch chan WrappedPacket, wp WrappedPacket) (sent bool) {
	defer func() {
		if recover() != nil {
			sent = false
		}
	}()
	ch <- wp
	return true
}
