package rawsocket

import (
	"net"
	
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/obeliskdev/fastrand"
)

// Build creates a TCP packet with the given source and destination addresses.
func (tcp *TCP) Build(src, dest net.TCPAddr) []byte {
	packet, err := tcp.BuildWithError(src, dest)
	if err != nil {
		return nil
	}
	return packet
}

func (tcp *TCP) BuildWithError(src, dest net.TCPAddr) ([]byte, error) {
	scratch := tcpBuildScratchPool.Get().(*tcpBuildScratch)
	defer tcpBuildScratchPool.Put(scratch)
	
	scratch.buf.Clear()
	networkLayer, serializableIP := prepareIPLayers(src.IP, dest.IP, layers.IPProtocolTCP, &scratch.ip4, &scratch.ip6)
	
	scratch.tcp = layers.TCP{
		SrcPort: layers.TCPPort(validPort(src.Port)),
		DstPort: layers.TCPPort(validPort(dest.Port)),
		Seq:     tcp.Sequence,
		Window:  tcp.Window,
		Ack:     tcp.AckNum,
		FIN:     tcp.FIN,
		SYN:     tcp.SYN,
		RST:     tcp.RST,
		PSH:     tcp.PSH,
		ACK:     tcp.ACK,
		URG:     tcp.URG,
		ECE:     tcp.ECE,
		CWR:     tcp.CWR,
		NS:      tcp.NS,
	}
	if scratch.tcp.Window == 0 {
		scratch.tcp.Window = 65535
	}
	
	optionCap := len(tcp.Options)
	switch {
	case tcp.ACK && tcp.SYN:
		optionCap++
	case tcp.SYN:
		optionCap += 5
	case tcp.ACK:
		optionCap++
	case tcp.FIN:
		optionCap++
	}
	if optionCap <= cap(scratch.options) {
		scratch.tcp.Options = scratch.options[:0]
	} else {
		scratch.tcp.Options = make([]layers.TCPOption, 0, optionCap)
	}
	
	if tcp.LegitOptions {
		if tcp.ACK && tcp.SYN {
			scratch.tcp.Options = append(scratch.tcp.Options,
				layers.TCPOption{OptionType: layers.TCPOptionKindSACK},
			)
		} else if tcp.SYN {
			scratch.ws[0] = byte(fastrand.IntN(14))
			fillTimestamp(scratch.ts[:])
			scratch.tcp.Options = append(scratch.tcp.Options,
				layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: tcpOptionMSS1460},
				layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: scratch.ws[:]},
				layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: scratch.ts[:]},
				layers.TCPOption{OptionType: layers.TCPOptionKindNop},
				layers.TCPOption{OptionType: layers.TCPOptionKindCCEcho},
			)
		} else if tcp.ACK {
			scratch.ws[0] = byte(fastrand.Int(1, 14))
			scratch.tcp.Options = append(scratch.tcp.Options,
				layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: scratch.ws[:]},
			)
		} else if tcp.FIN {
			fillTimestamp(scratch.ts[:])
			scratch.tcp.Options = append(scratch.tcp.Options,
				layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: uint8(len(scratch.ts)), OptionData: scratch.ts[:]},
			)
		}
	}
	
	if len(tcp.Options) > 0 {
		scratch.tcp.Options = append(scratch.tcp.Options, tcp.Options...)
	}
	
	if err := scratch.tcp.SetNetworkLayerForChecksum(networkLayer); err != nil {
		return nil, err
	}
	
	payload := tcp.Payload

	var layerBuf [3]gopacket.SerializableLayer
	layers := layerBuf[:2]
	layers[0] = serializableIP
	layers[1] = &scratch.tcp
	if len(payload) > 0 {
		layers = append(layers, gopacket.Payload(payload))
	}

	if err := gopacket.SerializeLayers(scratch.buf, serializeOptions, layers...); err != nil {
		return nil, err
	}

	return cloneSerializedBytes(scratch.buf), nil
}
