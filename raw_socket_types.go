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
		ip := GetSelfIP()
		if ip.To4() != nil {
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
		ip := GetSelfIP()
		if ip.To4() != nil {
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
	NextPacket() (gopacket.Packet, *net.IPAddr, error)
	Iter() chan WrappedPacket
	Close() error
}
