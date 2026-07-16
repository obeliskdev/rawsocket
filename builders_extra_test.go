package rawsocket

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestBuildTCP_IPv6(t *testing.T) {
	src := net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 12345}
	dst := net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443}

	packetBytes, err := BuildTCPPacket(src, dst, WithTCPSYN(true), WithTCPPayload([]byte("v6")))
	if err != nil {
		t.Fatalf("BuildTCPPacket IPv6 failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv6, gopacket.NoCopy)
	if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer == nil {
		t.Fatal("missing IPv6 layer")
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
		t.Fatal("missing TCP layer")
	}
}

func TestBuildUDP_IPv6(t *testing.T) {
	src := net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 12345}
	dst := net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 53}

	packetBytes, err := BuildUDPPacket(src, dst, WithUDPPayload([]byte("v6")))
	if err != nil {
		t.Fatalf("BuildUDPPacket IPv6 failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv6, gopacket.NoCopy)
	if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer == nil {
		t.Fatal("missing IPv6 layer")
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer == nil {
		t.Fatal("missing UDP layer")
	}
}

func TestBuildTCPPacket_NoPayload(t *testing.T) {
	src := net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	dst := net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443}

	packetBytes, err := BuildTCPPacket(src, dst, WithTCPSYN(true))
	if err != nil {
		t.Fatalf("BuildTCPPacket failed: %v", err)
	}
	if len(packetBytes) == 0 {
		t.Fatal("empty packet")
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.NoCopy)
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !tcp.SYN {
		t.Fatal("SYN flag not set")
	}
	if len(tcp.Payload) != 0 {
		t.Fatalf("expected empty payload, got %d bytes", len(tcp.Payload))
	}
}

func TestBuildTCPPacket_LegitOptionsSYN(t *testing.T) {
	src := net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	dst := net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443}

	tcp := NewTCP(WithTCPSYN(true), WithTCPLegitOptions(true))

	packetBytes, err := tcp.BuildWithError(src, dst)
	if err != nil {
		t.Fatalf("BuildWithError failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.NoCopy)
	tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if len(tcpLayer.Options) == 0 {
		t.Fatal("expected TCP options for SYN with LegitOptions")
	}

	hasMSS := false
	for _, opt := range tcpLayer.Options {
		if opt.OptionType == layers.TCPOptionKindMSS {
			hasMSS = true
			break
		}
	}
	if !hasMSS {
		t.Fatal("expected MSS option in SYN with LegitOptions")
	}
}

func TestBuildICMPPacket_NoPayload(t *testing.T) {
	src := net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}
	dst := net.IPAddr{IP: net.IPv4(8, 8, 8, 8)}

	packetBytes, err := BuildICMPPacket(src, dst)
	if err != nil {
		t.Fatalf("BuildICMPPacket failed: %v", err)
	}
	if len(packetBytes) == 0 {
		t.Fatal("empty packet")
	}
}

func TestBuildICMPPacket_IPv6_Rejects(t *testing.T) {
	src := net.IPAddr{IP: net.ParseIP("2001:db8::1")}
	dst := net.IPAddr{IP: net.ParseIP("2001:db8::2")}

	_, err := BuildICMPPacket(src, dst)
	if err == nil {
		t.Fatal("expected error for IPv6 ICMP (v4-only builder)")
	}
}

func TestBuildIGMPPacket_IPv6_Rejects(t *testing.T) {
	src := net.IPAddr{IP: net.ParseIP("2001:db8::1")}
	dst := net.IPAddr{IP: net.ParseIP("2001:db8::2")}

	_, err := BuildIGMPPacket(src, dst)
	if err == nil {
		t.Fatal("expected error for IPv6 IGMP (v4-only builder)")
	}
}

func TestBuildESPPacket_EmptyPayload(t *testing.T) {
	src := net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}
	dst := net.IPAddr{IP: net.IPv4(8, 8, 8, 8)}

	packetBytes, err := BuildESPPacket(src, dst, WithESPSPI(0x12345678), WithESPSequence(1))
	if err != nil {
		t.Fatalf("BuildESPPacket failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.NoCopy)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4.Protocol != layers.IPProtocolESP {
		t.Fatalf("expected ESP protocol, got %v", ip4.Protocol)
	}
	if len(ip4.Payload) != 8 {
		t.Fatalf("expected 8-byte ESP header (SPI+Seq), got %d", len(ip4.Payload))
	}
}

func TestBuildRawIPPacket_NoPayload(t *testing.T) {
	src := net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}
	dst := net.IPAddr{IP: net.IPv4(1, 1, 1, 1)}

	packetBytes, err := BuildRawIPPacket(src, dst, WithRawIPProtocol(layers.IPProtocol(253)))
	if err != nil {
		t.Fatalf("BuildRawIPPacket failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.NoCopy)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip4.Protocol != layers.IPProtocol(253) {
		t.Fatalf("expected protocol 253, got %v", ip4.Protocol)
	}
	if len(ip4.Payload) != 0 {
		t.Fatalf("expected empty payload, got %d", len(ip4.Payload))
	}
}

func TestBuildRawIPPacket_IPv6(t *testing.T) {
	src := net.IPAddr{IP: net.ParseIP("2001:db8::1")}
	dst := net.IPAddr{IP: net.ParseIP("2001:db8::2")}

	packetBytes, err := BuildRawIPPacket(src, dst, WithRawIPProtocol(layers.IPProtocol(253)), WithRawIPPayload([]byte{0xaa}))
	if err != nil {
		t.Fatalf("BuildRawIPPacket IPv6 failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv6, gopacket.NoCopy)
	ip6 := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if ip6.NextHeader != layers.IPProtocol(253) {
		t.Fatalf("expected NextHeader 253, got %v", ip6.NextHeader)
	}
}

func TestTCPBuildWithError_WindowDefault(t *testing.T) {
	src := net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	dst := net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443}

	tcp := NewTCP(WithTCPSYN(true))
	tcp.Window = 0

	packetBytes, err := tcp.BuildWithError(src, dst)
	if err != nil {
		t.Fatalf("BuildWithError failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.NoCopy)
	tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcpLayer.Window != 65535 {
		t.Fatalf("expected default window 65535, got %d", tcpLayer.Window)
	}
}

func TestPrepareIPLayers_Allocation(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(8, 8, 8, 8)
	var ip4 layers.IPv4
	var ip6 layers.IPv6

	allocs := testing.AllocsPerRun(100, func() {
		prepareIPLayers(src, dst, layers.IPProtocolTCP, &ip4, &ip6)
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocs for prepareIPLayers IPv4, got %v", allocs)
	}
}

func TestWithTCPLegitOptions(t *testing.T) {
	tcp := NewTCP(WithTCPSYN(true), WithTCPLegitOptions(true))
	if !tcp.LegitOptions {
		t.Fatal("expected LegitOptions true")
	}
	if !tcp.SYN {
		t.Fatal("expected SYN true")
	}
}

func TestWithTCPLegitOptions_Disabled(t *testing.T) {
	tcp := NewTCP(WithTCPSYN(true), WithTCPLegitOptions(false))
	if tcp.LegitOptions {
		t.Fatal("expected LegitOptions false")
	}
}

func TestBuildTCPPacket_AllFlags(t *testing.T) {
	src := net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	dst := net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443}

	packetBytes, err := BuildTCPPacket(src, dst,
		WithTCPSYN(true), WithTCPACK(true), WithTCPRST(true),
		WithTCPPSH(true), WithTCPFIN(true), WithTCPURG(true),
		WithTCPECE(true), WithTCPCWR(true), WithTCPNS(true),
	)
	if err != nil {
		t.Fatalf("BuildTCPPacket failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.NoCopy)
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !tcp.SYN || !tcp.ACK || !tcp.RST || !tcp.PSH || !tcp.FIN || !tcp.URG || !tcp.ECE || !tcp.CWR || !tcp.NS {
		t.Fatalf("expected all flags set: SYN=%v ACK=%v RST=%v PSH=%v FIN=%v URG=%v ECE=%v CWR=%v NS=%v",
			tcp.SYN, tcp.ACK, tcp.RST, tcp.PSH, tcp.FIN, tcp.URG, tcp.ECE, tcp.CWR, tcp.NS)
	}
}

func TestBuildUDPPacket_LargePayload(t *testing.T) {
	src := net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	dst := net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}

	packetBytes, err := BuildUDPPacket(src, dst, WithUDPPayload(payload))
	if err != nil {
		t.Fatalf("BuildUDPPacket failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.NoCopy)
	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if len(udp.Payload) != len(payload) {
		t.Fatalf("expected payload %d, got %d", len(payload), len(udp.Payload))
	}
}

func TestBuildESPPacket_LargePayload(t *testing.T) {
	src := net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}
	dst := net.IPAddr{IP: net.IPv4(8, 8, 8, 8)}
	payload := make([]byte, 200)

	packetBytes, err := BuildESPPacket(src, dst, WithESPPayload(payload))
	if err != nil {
		t.Fatalf("BuildESPPacket failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.NoCopy)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if len(ip4.Payload) != 8+len(payload) {
		t.Fatalf("expected ESP total %d, got %d", 8+len(payload), len(ip4.Payload))
	}
}

func TestBuildIGMPPacket_ChecksumValid(t *testing.T) {
	src := net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}
	dst := net.IPAddr{IP: net.IPv4(224, 0, 0, 1)}

	packetBytes, err := BuildIGMPPacket(src, dst,
		WithIGMPType(layers.IGMPMembershipQuery),
		WithIGMPMaxResponseTime(10*time.Second),
	)
	if err != nil {
		t.Fatalf("BuildIGMPPacket failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.NoCopy)
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	igmpData := ip4.Payload
	if len(igmpData) < 8 {
		t.Fatalf("IGMP data too short: %d", len(igmpData))
	}

	csum := checksum16(igmpData[:8])
	if csum != 0 {
		t.Fatalf("IGMP checksum invalid: expected 0 (checksum16 of valid checksum), got 0x%04x", csum)
	}
}