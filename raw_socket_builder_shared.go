package rawsocket

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/obeliskdev/fastrand"
)

var serializeOptions = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

var decodeOptions = gopacket.DecodeOptions{
	NoCopy: true,
}

var tcpOptionMSS1460 = []byte{0x05, 0xb4}

type udpBuildScratch struct {
	buf gopacket.SerializeBuffer
	ip4 layers.IPv4
	ip6 layers.IPv6
	udp layers.UDP
}

type icmpBuildScratch struct {
	buf  gopacket.SerializeBuffer
	ip4  layers.IPv4
	ip6  layers.IPv6
	icmp layers.ICMPv4
}

type tcpBuildScratch struct {
	buf     gopacket.SerializeBuffer
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	options [8]layers.TCPOption
	ws      [1]byte
	ts      [8]byte
}

var udpBuildScratchPool = sync.Pool{
	New: func() any {
		return &udpBuildScratch{buf: gopacket.NewSerializeBuffer()}
	},
}

var icmpBuildScratchPool = sync.Pool{
	New: func() any {
		return &icmpBuildScratch{buf: gopacket.NewSerializeBuffer()}
	},
}

var tcpBuildScratchPool = sync.Pool{
	New: func() any {
		return &tcpBuildScratch{buf: gopacket.NewSerializeBuffer()}
	},
}

func cloneSerializedBytes(buf gopacket.SerializeBuffer) []byte {
	packet := buf.Bytes()
	out := make([]byte, len(packet))
	copy(out, packet)
	return out
}

func fillTimestamp(dst []byte) {
	binary.BigEndian.PutUint32(dst[:4], uint32(time.Now().UnixNano()))
	binary.BigEndian.PutUint32(dst[4:], fastrand.Number[uint32](0, ^uint32(0)))
}

func prepareIPLayers(src, dest net.IP, protocol layers.IPProtocol, ip4 *layers.IPv4, ip6 *layers.IPv6) (gopacket.NetworkLayer, gopacket.SerializableLayer, bool) {
	src4 := src.To4()
	dest4 := dest.To4()
	if src4 != nil && dest4 != nil {
		*ip4 = layers.IPv4{
			Version:  4,
			Id:       uint16(fastrand.Int(1, 65535)),
			Flags:    layers.IPv4DontFragment,
			TTL:      uint8(fastrand.Int(32, 255)),
			Protocol: protocol,
			SrcIP:    src4,
			DstIP:    dest4,
		}
		return ip4, ip4, true
	}

	*ip6 = layers.IPv6{
		Version:    6,
		NextHeader: protocol,
		SrcIP:      src,
		DstIP:      dest,
	}
	return ip6, ip6, false
}
