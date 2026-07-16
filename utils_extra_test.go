package rawsocket

import (
	"net"
	"testing"

	"github.com/google/gopacket"
)

func TestSendPacket_Success(t *testing.T) {
	ch := make(chan WrappedPacket, 1)
	wp := WrappedPacket{}
	if !sendPacket(ch, wp) {
		t.Fatal("expected sendPacket to return true on open channel")
	}
	select {
	case <-ch:
	default:
		t.Fatal("expected packet in channel")
	}
}

func TestSendPacket_ClosedChannel(t *testing.T) {
	ch := make(chan WrappedPacket, 1)
	close(ch)
	if sendPacket(ch, WrappedPacket{}) {
		t.Fatal("expected sendPacket to return false on closed channel")
	}
}

func TestPacketIter_StopsOnError(t *testing.T) {
	called := 0
	fetch := func() (gopacket.Packet, *net.IPAddr, error) {
		called++
		return nil, nil, errTestSentinel
	}
	ch := make(chan WrappedPacket, 1)
	packetIter(ch, fetch)
	if called != 1 {
		t.Fatalf("expected fetch called once, got %d", called)
	}
}

func TestPacketIter_SendsPackets(t *testing.T) {
	count := 0
	fetch := func() (gopacket.Packet, *net.IPAddr, error) {
		count++
		if count > 3 {
			return nil, nil, errTestSentinel
		}
		return nil, nil, nil
	}
	ch := make(chan WrappedPacket, 4)
	packetIter(ch, fetch)

	received := 0
loop:
	for {
		select {
		case <-ch:
			received++
		default:
			break loop
		}
	}
	if received != 3 {
		t.Fatalf("expected 3 packets, got %d", received)
	}
}

func TestPacketIter_StopsOnClosedChannel(t *testing.T) {
	fetch := func() (gopacket.Packet, *net.IPAddr, error) {
		return nil, nil, nil
	}
	ch := make(chan WrappedPacket, 1)
	done := make(chan struct{})
	go func() {
		close(ch)
		done <- struct{}{}
	}()
	<-done
	packetIter(ch, fetch)
}

var errTestSentinel = sentinelErr{}

type sentinelErr struct{}

func (sentinelErr) Error() string { return "sentinel" }
