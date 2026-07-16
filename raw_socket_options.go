package rawsocket

import (
	"net"
	"time"
	
	"github.com/google/gopacket/layers"
)

// TCPOpt configures a TCP packet builder.
type TCPOpt func(*TCP)

// UDPOpt configures a UDP packet builder.
type UDPOpt func(*UDP)

// ICMPOpt configures an ICMP packet builder.
type ICMPOpt func(*ICMP)
type IGMPOpt func(*IGMP)
type ESPOpt func(*ESP)
type RawIPOpt func(*RawIP)

func NewTCP(opts ...TCPOpt) *TCP {
	tcp := &TCP{Window: 65535}
	for _, opt := range opts {
		if opt != nil {
			opt(tcp)
		}
	}
	return tcp
}

func NewUDP(opts ...UDPOpt) *UDP {
	udp := &UDP{}
	for _, opt := range opts {
		if opt != nil {
			opt(udp)
		}
	}
	return udp
}

func NewICMP(opts ...ICMPOpt) *ICMP {
	icmp := &ICMP{Type: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)}
	for _, opt := range opts {
		if opt != nil {
			opt(icmp)
		}
	}
	return icmp
}

func NewIGMP(opts ...IGMPOpt) *IGMP {
	igmp := &IGMP{
		Type:            layers.IGMPMembershipQuery,
		MaxResponseTime: 10 * time.Second,
		GroupAddress:    net.IPv4zero,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(igmp)
		}
	}
	return igmp
}

func NewESP(opts ...ESPOpt) *ESP {
	esp := &ESP{
		SPI:      1,
		Sequence: 1,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(esp)
		}
	}
	return esp
}

func NewRawIP(opts ...RawIPOpt) *RawIP {
	rawIP := &RawIP{
		Protocol: layers.IPProtocol(255),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(rawIP)
		}
	}
	return rawIP
}

func WithTCPSYN(enabled bool) TCPOpt { return func(t *TCP) { t.SYN = enabled } }
func WithTCPACK(enabled bool) TCPOpt { return func(t *TCP) { t.ACK = enabled } }
func WithTCPRST(enabled bool) TCPOpt { return func(t *TCP) { t.RST = enabled } }
func WithTCPPSH(enabled bool) TCPOpt { return func(t *TCP) { t.PSH = enabled } }
func WithTCPFIN(enabled bool) TCPOpt { return func(t *TCP) { t.FIN = enabled } }
func WithTCPURG(enabled bool) TCPOpt { return func(t *TCP) { t.URG = enabled } }
func WithTCPECE(enabled bool) TCPOpt { return func(t *TCP) { t.ECE = enabled } }
func WithTCPCWR(enabled bool) TCPOpt { return func(t *TCP) { t.CWR = enabled } }
func WithTCPNS(enabled bool) TCPOpt  { return func(t *TCP) { t.NS = enabled } }

func WithTCPSequence(seq uint32) TCPOpt {
	return func(t *TCP) { t.Sequence = seq }
}

func WithTCPAckNumber(ack uint32) TCPOpt {
	return func(t *TCP) { t.AckNum = ack }
}

func WithTCPWindow(window uint16) TCPOpt {
	return func(t *TCP) { t.Window = window }
}

func WithTCPPayload(payload []byte) TCPOpt {
	return func(t *TCP) { t.Payload = payload }
}

func WithTCPOptions(options ...layers.TCPOption) TCPOpt {
	return func(t *TCP) { t.Options = append(t.Options, options...) }
}

func WithTCPLegitOptions(enabled bool) TCPOpt {
	return func(t *TCP) { t.LegitOptions = enabled }
}

func WithUDPPayload(payload []byte) UDPOpt {
	return func(u *UDP) { u.Payload = payload }
}

func WithICMPType(typeCode layers.ICMPv4TypeCode) ICMPOpt {
	return func(i *ICMP) { i.Type = typeCode }
}

func WithICMPPayload(payload []byte) ICMPOpt {
	return func(i *ICMP) { i.Payload = payload }
}

func WithIGMPType(t layers.IGMPType) IGMPOpt {
	return func(i *IGMP) { i.Type = t }
}

func WithIGMPMaxResponseTime(d time.Duration) IGMPOpt {
	return func(i *IGMP) { i.MaxResponseTime = d }
}

func WithIGMPGroupAddress(group net.IP) IGMPOpt {
	return func(i *IGMP) { i.GroupAddress = group }
}

func WithESPSPI(spi uint32) ESPOpt {
	return func(e *ESP) { e.SPI = spi }
}

func WithESPSequence(seq uint32) ESPOpt {
	return func(e *ESP) { e.Sequence = seq }
}

func WithESPPayload(payload []byte) ESPOpt {
	return func(e *ESP) { e.Payload = payload }
}

func WithRawIPProtocol(protocol layers.IPProtocol) RawIPOpt {
	return func(r *RawIP) { r.Protocol = protocol }
}

func WithRawIPPayload(payload []byte) RawIPOpt {
	return func(r *RawIP) { r.Payload = payload }
}

func BuildTCPPacket(src, dest net.TCPAddr, opts ...TCPOpt) ([]byte, error) {
	return NewTCP(opts...).BuildWithError(src, dest)
}

func BuildUDPPacket(src, dest net.UDPAddr, opts ...UDPOpt) ([]byte, error) {
	return NewUDP(opts...).BuildWithError(src, dest)
}

func BuildICMPPacket(src, dest net.IPAddr, opts ...ICMPOpt) ([]byte, error) {
	return NewICMP(opts...).BuildWithError(src, dest)
}

func BuildIGMPPacket(src, dest net.IPAddr, opts ...IGMPOpt) ([]byte, error) {
	return NewIGMP(opts...).BuildWithError(src, dest)
}

func BuildESPPacket(src, dest net.IPAddr, opts ...ESPOpt) ([]byte, error) {
	return NewESP(opts...).BuildWithError(src, dest)
}

func BuildRawIPPacket(src, dest net.IPAddr, opts ...RawIPOpt) ([]byte, error) {
	return NewRawIP(opts...).BuildWithError(src, dest)
}
