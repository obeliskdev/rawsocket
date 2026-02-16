package rawsocket

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestBuildTCPPacketOptions(t *testing.T) {
	src := net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 12345}
	dst := net.TCPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443}
	payload := []byte("hello")

	packetBytes, err := BuildTCPPacket(
		src,
		dst,
		WithTCPSYN(true),
		WithTCPACK(true),
		WithTCPSequence(7),
		WithTCPAckNumber(9),
		WithTCPWindow(1024),
		WithTCPPayload(payload),
	)
	if err != nil {
		t.Fatalf("BuildTCPPacket failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.NoCopy)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		t.Fatal("missing TCP layer")
	}
	tcp := tcpLayer.(*layers.TCP)
	if !tcp.SYN || !tcp.ACK {
		t.Fatalf("unexpected flags: SYN=%v ACK=%v", tcp.SYN, tcp.ACK)
	}
	if tcp.Seq != 7 || tcp.Ack != 9 {
		t.Fatalf("unexpected seq/ack: seq=%d ack=%d", tcp.Seq, tcp.Ack)
	}
	if int(tcp.SrcPort) != src.Port || int(tcp.DstPort) != dst.Port {
		t.Fatalf("unexpected ports: %d -> %d", tcp.SrcPort, tcp.DstPort)
	}
	if string(tcp.Payload) != string(payload) {
		t.Fatalf("unexpected payload: %q", string(tcp.Payload))
	}
}

func TestBuildUDPPacketOptions(t *testing.T) {
	src := net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 1111}
	dst := net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}
	payload := []byte{1, 2, 3, 4}

	packetBytes, err := BuildUDPPacket(src, dst, WithUDPPayload(payload))
	if err != nil {
		t.Fatalf("BuildUDPPacket failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.NoCopy)
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Fatal("missing UDP layer")
	}
	udp := udpLayer.(*layers.UDP)
	if int(udp.SrcPort) != src.Port || int(udp.DstPort) != dst.Port {
		t.Fatalf("unexpected ports: %d -> %d", udp.SrcPort, udp.DstPort)
	}
	if len(udp.Payload) != len(payload) {
		t.Fatalf("unexpected payload length: %d", len(udp.Payload))
	}
}

func TestBuildICMPPacketOptions(t *testing.T) {
	src := net.IPAddr{IP: net.IPv4(10, 0, 0, 3)}
	dst := net.IPAddr{IP: net.IPv4(8, 8, 4, 4)}
	payload := []byte("icmp")

	packetBytes, err := BuildICMPPacket(
		src,
		dst,
		WithICMPType(layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0)),
		WithICMPPayload(payload),
	)
	if err != nil {
		t.Fatalf("BuildICMPPacket failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.NoCopy)
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer == nil {
		t.Fatal("missing ICMPv4 layer")
	}
	icmp := icmpLayer.(*layers.ICMPv4)
	if icmp.TypeCode.Type() != layers.ICMPv4TypeEchoReply {
		t.Fatalf("unexpected icmp type: %v", icmp.TypeCode)
	}
	if len(icmp.Payload) != len(payload) {
		t.Fatalf("unexpected payload length: %d", len(icmp.Payload))
	}
}

func TestBuildIGMPPacketOptions(t *testing.T) {
	src := net.IPAddr{IP: net.IPv4(10, 0, 0, 4)}
	dst := net.IPAddr{IP: net.IPv4(224, 0, 0, 1)}
	group := net.IPv4(239, 1, 2, 3)

	packetBytes, err := BuildIGMPPacket(
		src,
		dst,
		WithIGMPType(layers.IGMPMembershipReportV2),
		WithIGMPMaxResponseTime(2*time.Second),
		WithIGMPGroupAddress(group),
	)
	if err != nil {
		t.Fatalf("BuildIGMPPacket failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.NoCopy)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		t.Fatal("missing IPv4 layer")
	}
	ip4 := ipLayer.(*layers.IPv4)
	if ip4.Protocol != layers.IPProtocolIGMP {
		t.Fatalf("unexpected protocol: %v", ip4.Protocol)
	}

	payload := ip4.Payload
	if len(payload) < 8 {
		t.Fatalf("igmp payload too short: %d", len(payload))
	}
	if payload[0] != byte(layers.IGMPMembershipReportV2) {
		t.Fatalf("unexpected igmp type: 0x%x", payload[0])
	}
	if !net.IP(payload[4:8]).Equal(group.To4()) {
		t.Fatalf("unexpected group address: %v", net.IP(payload[4:8]))
	}
}

func TestBuildESPPacketOptions(t *testing.T) {
	src := net.IPAddr{IP: net.IPv4(10, 0, 0, 5)}
	dst := net.IPAddr{IP: net.IPv4(8, 8, 8, 8)}
	payload := []byte{9, 8, 7, 6}

	packetBytes, err := BuildESPPacket(
		src,
		dst,
		WithESPSPI(0x01020304),
		WithESPSequence(0x0a0b0c0d),
		WithESPPayload(payload),
	)
	if err != nil {
		t.Fatalf("BuildESPPacket failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.NoCopy)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		t.Fatal("missing IPv4 layer")
	}
	ip4 := ipLayer.(*layers.IPv4)
	if ip4.Protocol != layers.IPProtocolESP {
		t.Fatalf("unexpected protocol: %v", ip4.Protocol)
	}
	if len(ip4.Payload) < 12 {
		t.Fatalf("esp payload too short: %d", len(ip4.Payload))
	}
	if got := binary.BigEndian.Uint32(ip4.Payload[0:4]); got != 0x01020304 {
		t.Fatalf("unexpected SPI: %#x", got)
	}
	if got := binary.BigEndian.Uint32(ip4.Payload[4:8]); got != 0x0a0b0c0d {
		t.Fatalf("unexpected sequence: %#x", got)
	}
	if got := ip4.Payload[8:12]; string(got) != string(payload) {
		t.Fatalf("unexpected payload: %v", got)
	}
}

func TestBuildRawIPPacketOptions(t *testing.T) {
	src := net.IPAddr{IP: net.IPv4(10, 0, 0, 6)}
	dst := net.IPAddr{IP: net.IPv4(1, 0, 0, 1)}
	payload := []byte{0xaa, 0xbb, 0xcc}

	packetBytes, err := BuildRawIPPacket(
		src,
		dst,
		WithRawIPProtocol(layers.IPProtocol(253)),
		WithRawIPPayload(payload),
	)
	if err != nil {
		t.Fatalf("BuildRawIPPacket failed: %v", err)
	}

	packet := gopacket.NewPacket(packetBytes, layers.LayerTypeIPv4, gopacket.NoCopy)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		t.Fatal("missing IPv4 layer")
	}
	ip4 := ipLayer.(*layers.IPv4)
	if ip4.Protocol != layers.IPProtocol(253) {
		t.Fatalf("unexpected protocol: %v", ip4.Protocol)
	}
	if string(ip4.Payload) != string(payload) {
		t.Fatalf("unexpected raw payload: %v", ip4.Payload)
	}
}
