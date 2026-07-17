package rawsocket

import "net"

// extractDstIP reads the destination IP from a raw IP packet and
// returns a copy. The copy is necessary because callers (especially
// packetBuilder in monoamp) reuse the packet buffer on the next call —
// an aliased slice into that buffer would become garbage before the
// returned net.IP is consumed by WriteTo.
//
// Handles both IPv4 (offset 16-20) and IPv6 (offset 24-40). Returns
// nil if the packet is too short or has an unknown version.
func extractDstIP(pkt []byte) net.IP {
	if len(pkt) < 20 {
		return nil
	}
	switch pkt[0] >> 4 {
	case 4:
		return net.IP{pkt[16], pkt[17], pkt[18], pkt[19]}.To4()
	case 6:
		if len(pkt) < 40 {
			return nil
		}
		dst := make(net.IP, 16)
		copy(dst, pkt[24:40])
		return dst
	default:
		return nil
	}
}
