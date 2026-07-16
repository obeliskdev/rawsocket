package rawsocket

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ProtocolType int

// LinkType returns the corresponding gopacket.Decoder for the given ProtocolType.
func (t ProtocolType) LinkType() gopacket.Decoder {
	switch t {
	case IPPROTO_UDP:
		return layers.LayerTypeUDP
	case IPPROTO_ICMP:
		if selfIPIsV4 {
			return layers.LayerTypeICMPv4
		}
		return layers.LayerTypeICMPv6
	case IPPROTO_IGMP:
		return layers.LayerTypeIGMP
	case IPPROTO_ESP:
		return layers.LayerTypeIPSecESP
	case IPPROTO_TCP:
		return layers.LayerTypeTCP
	case IPPROTO_IP, IPPROTO_RAW:
		if selfIPIsV4 {
			return layers.LayerTypeIPv4
		}
		return layers.LayerTypeIPv6
	default:
		return layers.LayerTypeEthernet
	}
}

type TCP struct {
	SYN, ACK, RST, PSH, FIN, URG, ECE, CWR, NS bool
	Payload                                    []byte
	LegitOptions                               bool
	Options                                    []layers.TCPOption
	Sequence                                   uint32
	Window                                     uint16
	AckNum                                     uint32
}

type UDP struct {
	Payload []byte
}

type ICMP struct {
	Type    layers.ICMPv4TypeCode
	Payload []byte
}

type IGMP struct {
	Type            layers.IGMPType
	MaxResponseTime time.Duration
	GroupAddress    net.IP
}

type ESP struct {
	SPI      uint32
	Sequence uint32
	Payload  []byte
}

type RawIP struct {
	Protocol layers.IPProtocol
	Payload  []byte
}

type WrappedPacket struct {
	*net.IPAddr
	gopacket.Packet
}

type RawSocket interface {
	Write([]byte, net.Addr) (int, error)
	Read([]byte) (int, net.Addr, error)
	// SetReadDeadline sets the deadline for future Read calls. A
	// zero value means no deadline. Returns an error if deadlines
	// are not supported. Lets callers break out of a blocking Read
	// on context cancellation without spawning a goroutine per
	// packet or closing the socket.
	SetReadDeadline(t time.Time) error
	NextPacket() (gopacket.Packet, *net.IPAddr, error)
	Iter() chan WrappedPacket
	Close() error
	// WriteRaw writes a pre-formatted frame directly to the wire
	// without any gopacket re-parsing or re-serialization. The
	// caller is responsible for including any required headers
	// (ethernet, IP, transport). Returns the number of bytes written.
	WriteRaw([]byte) (int, error)
	// IsRawMode returns true when the socket operates in IP-raw mode
	// (no ethernet framing needed). Returns false when ethernet
	// framing is required (e.g. Windows pcap non-raw mode).
	IsRawMode() bool
	// MACs returns the source and router MAC addresses used for
	// ethernet framing. Returns nil, nil in raw mode or when MACs
	// are not available.
	MACs() (src, dst net.HardwareAddr)
}
