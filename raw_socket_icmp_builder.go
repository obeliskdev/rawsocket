package rawsocket

import (
	"errors"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/obeliskdev/fastrand"
)

// Build constructs an ICMP packet with the given source and destination IP addresses.
func (icmp *ICMP) Build(src, dest net.IPAddr) []byte {
	packet, err := icmp.BuildWithError(src, dest)
	if err != nil {
		return nil
	}
	return packet
}

func (icmp *ICMP) BuildWithError(src, dest net.IPAddr) ([]byte, error) {
	if src.IP.To4() == nil || dest.IP.To4() == nil {
		return nil, errors.New("icmp builder currently supports ipv4 only")
	}

	scratch := icmpBuildScratchPool.Get().(*icmpBuildScratch)
	defer icmpBuildScratchPool.Put(scratch)

	scratch.buf.Clear()
	_, serializableIP := prepareIPLayers(src.IP, dest.IP, layers.IPProtocolICMPv4, &scratch.ip4, &scratch.ip6)

	scratch.icmp = layers.ICMPv4{
		TypeCode: icmp.Type,
		Id:       uint16(fastrand.Int(1, 65535)),
		Seq:      uint16(fastrand.Int(1, 65535)),
	}

	payload := icmp.Payload

	var layerBuf [3]gopacket.SerializableLayer
	layers := layerBuf[:2]
	layers[0] = serializableIP
	layers[1] = &scratch.icmp
	if len(payload) > 0 {
		layers = append(layers, gopacket.Payload(payload))
	}

	if err := gopacket.SerializeLayers(scratch.buf, serializeOptions, layers...); err != nil {
		return nil, err
	}

	return cloneSerializedBytes(scratch.buf), nil
}
