package rawsocket

import (
	"net"
	"strings"
	"testing"
)

// TestWriteRawAndMACs opens a real socket and verifies the new
// interface methods work. Skips if the socket can't be opened
// (permissions, no network, etc.).
func TestWriteRawAndMACs(t *testing.T) {
	sock, err := OpenRawSocket(IPPROTO_UDP)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "permission") {
			t.Skip(err)
		}
		t.Skipf("cannot open raw socket: %v", err)
	}
	defer sock.Close()

	// IsRawMode should return a bool without panicking.
	_ = sock.IsRawMode()

	// MACs should return without panicking. In raw mode both are nil;
	// in non-raw mode they may or may not be populated depending on
	// whether ARP resolution succeeded.
	srcMac, dstMac := sock.MACs()
	if sock.IsRawMode() {
		if srcMac != nil || dstMac != nil {
			t.Errorf("raw mode: MACs should be nil, got src=%v dst=%v", srcMac, dstMac)
		}
	}
	// Non-raw mode: MACs may be nil if ARP hasn't resolved yet —
	// don't fail on that, just verify no panic.
}

// TestIsRawModeConsistent verifies IsRawMode returns the same value
// across multiple calls.
func TestIsRawModeConsistent(t *testing.T) {
	sock, err := OpenRawSocket(IPPROTO_UDP)
	if err != nil {
		t.Skipf("cannot open raw socket: %v", err)
	}
	defer sock.Close()

	a := sock.IsRawMode()
	b := sock.IsRawMode()
	if a != b {
		t.Errorf("IsRawMode inconsistent: %v vs %v", a, b)
	}
}

func TestExtractDstIP(t *testing.T) {
	// IPv4 packet — dst at offset 16-20
	pkt := make([]byte, 28) // 20 IP + 8 UDP
	pkt[0] = 0x45
	copy(pkt[16:20], net.IPv4(8, 8, 8, 8).To4())
	dst := extractDstIP(pkt)
	if dst == nil {
		t.Fatal("extractDstIP returned nil for valid IPv4 packet")
	}
	if !dst.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Errorf("extractDstIP = %s, want 8.8.8.8", dst)
	}

	// IPv6 packet — dst at offset 24-40
	pkt6 := make([]byte, 48) // 40 IP + 8 UDP
	pkt6[0] = 0x60
	want6 := net.ParseIP("2001:db8::1")
	copy(pkt6[24:40], want6)
	dst6 := extractDstIP(pkt6)
	if dst6 == nil {
		t.Fatal("extractDstIP returned nil for valid IPv6 packet")
	}
	if !dst6.Equal(want6) {
		t.Errorf("extractDstIP = %s, want %s", dst6, want6)
	}

	// Too short
	if dst := extractDstIP([]byte{0x45, 0x00}); dst != nil {
		t.Errorf("extractDstIP on short packet should return nil, got %v", dst)
	}

	// Unknown version
	pktBad := make([]byte, 20)
	pktBad[0] = 0x90 // version 9
	if dst := extractDstIP(pktBad); dst != nil {
		t.Errorf("extractDstIP on unknown version should return nil, got %v", dst)
	}

	// IPv6 too short
	pkt6Short := make([]byte, 30)
	pkt6Short[0] = 0x60
	if dst := extractDstIP(pkt6Short); dst != nil {
		t.Errorf("extractDstIP on short IPv6 packet should return nil, got %v", dst)
	}
}
