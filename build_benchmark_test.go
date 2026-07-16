package rawsocket

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"
)

var benchPacket []byte

func BenchmarkUDPBuild(b *testing.B) {
	udp := NewUDP(WithUDPPayload(make([]byte, 64)))
	src := net.UDPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 12345}
	dst := net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 443}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchPacket = udp.Build(src, dst)
	}
}

func BenchmarkICMPBuild(b *testing.B) {
	icmp := NewICMP(
		WithICMPType(layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)),
		WithICMPPayload(make([]byte, 56)),
	)
	src := net.IPAddr{IP: net.IPv4(192, 168, 1, 10)}
	dst := net.IPAddr{IP: net.IPv4(8, 8, 8, 8)}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchPacket = icmp.Build(src, dst)
	}
}

func BenchmarkTCPBuildSYN(b *testing.B) {
	tcp := NewTCP(WithTCPSYN(true))
	src := net.TCPAddr{IP: net.IPv4(192, 168, 1, 10), Port: 49152}
	dst := net.TCPAddr{IP: net.IPv4(104, 16, 132, 229), Port: 443}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchPacket = tcp.Build(src, dst)
	}
}

func BenchmarkIGMPBuild(b *testing.B) {
	igmp := NewIGMP(
		WithIGMPType(layers.IGMPMembershipReportV2),
		WithIGMPGroupAddress(net.IPv4(239, 1, 2, 3)),
	)
	src := net.IPAddr{IP: net.IPv4(192, 168, 1, 10)}
	dst := net.IPAddr{IP: net.IPv4(224, 0, 0, 1)}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchPacket = igmp.Build(src, dst)
	}
}

func BenchmarkESPBuild(b *testing.B) {
	esp := NewESP(
		WithESPSPI(1),
		WithESPSequence(1),
		WithESPPayload(make([]byte, 64)),
	)
	src := net.IPAddr{IP: net.IPv4(192, 168, 1, 10)}
	dst := net.IPAddr{IP: net.IPv4(1, 1, 1, 1)}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchPacket = esp.Build(src, dst)
	}
}

func BenchmarkRawIPBuild(b *testing.B) {
	raw := NewRawIP(
		WithRawIPProtocol(layers.IPProtocol(253)),
		WithRawIPPayload(make([]byte, 64)),
	)
	src := net.IPAddr{IP: net.IPv4(192, 168, 1, 10)}
	dst := net.IPAddr{IP: net.IPv4(1, 1, 1, 1)}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchPacket = raw.Build(src, dst)
	}
}
