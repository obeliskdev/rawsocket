package rawsocket

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Build generates a UDP packet with the provided source and destination addresses.
func (udp *UDP) Build(src, dest net.UDPAddr) []byte {
	packet, err := udp.BuildWithError(src, dest)
	if err != nil {
		return nil
	}
	return packet
}

func (udp *UDP) BuildWithError(src, dest net.UDPAddr) ([]byte, error) {
	scratch := udpBuildScratchPool.Get().(*udpBuildScratch)
	defer udpBuildScratchPool.Put(scratch)

	scratch.buf.Clear()
	networkLayer, serializableIP := prepareIPLayers(src.IP, dest.IP, layers.IPProtocolUDP, &scratch.ip4, &scratch.ip6)

	scratch.udp = layers.UDP{
		SrcPort: layers.UDPPort(validPort(src.Port)),
		DstPort: layers.UDPPort(validPort(dest.Port)),
	}
	if err := scratch.udp.SetNetworkLayerForChecksum(networkLayer); err != nil {
		return nil, err
	}

	payload := udp.Payload

	var layerBuf [3]gopacket.SerializableLayer
	layers := layerBuf[:2]
	layers[0] = serializableIP
	layers[1] = &scratch.udp
	if len(payload) > 0 {
		layers = append(layers, gopacket.Payload(payload))
	}

	if err := gopacket.SerializeLayers(scratch.buf, serializeOptions, layers...); err != nil {
		return nil, err
	}

	return cloneSerializedBytes(scratch.buf), nil
}
