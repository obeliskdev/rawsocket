package rawsocket

import (
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Build creates an IGMP packet with the given source and destination addresses.
func (igmp *IGMP) Build(src, dest net.IPAddr) []byte {
	packet, err := igmp.BuildWithError(src, dest)
	if err != nil {
		return nil
	}
	return packet
}

func (igmp *IGMP) BuildWithError(src, dest net.IPAddr) ([]byte, error) {
	scratch := icmpBuildScratchPool.Get().(*icmpBuildScratch)
	defer icmpBuildScratchPool.Put(scratch)

	scratch.buf.Clear()
	_, serializableIP, isV4 := prepareIPLayers(src.IP, dest.IP, layers.IPProtocolIGMP, &scratch.ip4, &scratch.ip6)
	if !isV4 {
		return nil, errors.New("igmp builder currently supports ipv4 only")
	}

	var payload [8]byte
	payload[0] = byte(igmp.Type)
	payload[1] = encodeIGMPMaxResp(igmp.MaxResponseTime)

	group := igmp.GroupAddress.To4()
	if group == nil {
		group = net.IPv4zero
	}
	copy(payload[4:8], group)

	csum := checksum16(payload[:])
	binary.BigEndian.PutUint16(payload[2:4], csum)

	if err := gopacket.SerializeLayers(scratch.buf, serializeOptions, serializableIP, gopacket.Payload(payload[:])); err != nil {
		return nil, err
	}

	return cloneSerializedBytes(scratch.buf), nil
}

// Build creates an ESP packet with the given source and destination addresses.
func (esp *ESP) Build(src, dest net.IPAddr) []byte {
	packet, err := esp.BuildWithError(src, dest)
	if err != nil {
		return nil
	}
	return packet
}

func (esp *ESP) BuildWithError(src, dest net.IPAddr) ([]byte, error) {
	scratch := icmpBuildScratchPool.Get().(*icmpBuildScratch)
	defer icmpBuildScratchPool.Put(scratch)

	scratch.buf.Clear()
	_, serializableIP, _ := prepareIPLayers(src.IP, dest.IP, layers.IPProtocolESP, &scratch.ip4, &scratch.ip6)

	payload := esp.Payload
	totalLen := 8 + len(payload)

	var espBytes []byte
	var stackBuf [128]byte
	if totalLen <= len(stackBuf) {
		espBytes = stackBuf[:totalLen]
	} else {
		espBytes = make([]byte, totalLen)
	}

	binary.BigEndian.PutUint32(espBytes[0:4], esp.SPI)
	binary.BigEndian.PutUint32(espBytes[4:8], esp.Sequence)
	copy(espBytes[8:], payload)

	if err := gopacket.SerializeLayers(scratch.buf, serializeOptions, serializableIP, gopacket.Payload(espBytes)); err != nil {
		return nil, err
	}

	return cloneSerializedBytes(scratch.buf), nil
}

// Build creates a raw IP packet with the given source and destination addresses.
func (r *RawIP) Build(src, dest net.IPAddr) []byte {
	packet, err := r.BuildWithError(src, dest)
	if err != nil {
		return nil
	}
	return packet
}

func (r *RawIP) BuildWithError(src, dest net.IPAddr) ([]byte, error) {
	scratch := icmpBuildScratchPool.Get().(*icmpBuildScratch)
	defer icmpBuildScratchPool.Put(scratch)

	scratch.buf.Clear()
	_, serializableIP, _ := prepareIPLayers(src.IP, dest.IP, r.Protocol, &scratch.ip4, &scratch.ip6)

	var layerBuf [2]gopacket.SerializableLayer
	layers := layerBuf[:1]
	layers[0] = serializableIP
	if len(r.Payload) > 0 {
		layers = append(layers, gopacket.Payload(r.Payload))
	}

	if err := gopacket.SerializeLayers(scratch.buf, serializeOptions, layers...); err != nil {
		return nil, err
	}

	return cloneSerializedBytes(scratch.buf), nil
}

func encodeIGMPMaxResp(d time.Duration) byte {
	if d <= 0 {
		return 0
	}
	deciseconds := int(d / (100 * time.Millisecond))
	if deciseconds > 255 {
		return 255
	}
	return byte(deciseconds)
}

func checksum16(b []byte) uint16 {
	var sum uint32
	n := len(b) &^ 1
	for i := 0; i < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)&1 != 0 {
		sum += uint32(b[n]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
