package rawsocket

import "net"

// extractDstIP reads the destination IP from a raw IP packet.
// Handles both IPv4 (offset 16-20) and IPv6 (offset 24-40).
// Returns nil if the packet is too short or has an unknown version.
func extractDstIP(pkt []byte) net.IP {
	if len(pkt) < 20 {
		return nil
	}
	switch pkt[0] >> 4 {
	case 4:
		return pkt[16:20]
	case 6:
		if len(pkt) < 40 {
			return nil
		}
		return pkt[24:40]
	default:
		return nil
	}
}
