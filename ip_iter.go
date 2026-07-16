package rawsocket

import (
	"net"
	"strings"

	"github.com/obeliskdev/fastrand"
)

type netContainer struct {
	start, end net.IP
}

// IPIterator represents an iterator over a collection of IP addresses.
type IPIterator struct {
	containers []netContainer
	currentIdx int
	currentIP  net.IP
	skipLocal  bool
}

// ToIPIterator creates a new instance of IPIterator with the given data.
func ToIPIterator(data ...string) *IPIterator {
	if len(data) == 0 {
		panic("No data provided")
	}
	return &IPIterator{
		containers: parseData(data),
	}
}

// parseData parses a slice of strings and returns a slice of netContainers.
func parseData(data []string) []netContainer {
	containers := make([]netContainer, 0, len(data))

	for _, x := range data {
		if dashIdx := strings.IndexByte(x, '-'); dashIdx >= 0 {
			start := net.ParseIP(x[:dashIdx])
			end := net.ParseIP(x[dashIdx+1:])
			if start == nil || end == nil {
				continue
			}
			if !ipLessOrEqual(start, end) {
				continue
			}
			containers = append(containers, netContainer{start: start, end: end})
			continue
		}

		if slashIdx := strings.IndexByte(x, '/'); slashIdx >= 0 {
			start, end, err := cidrStartEnd(x)
			if err != nil {
				continue
			}
			containers = append(containers, netContainer{start: start, end: end})
			continue
		}

		if ip := net.ParseIP(x); ip != nil {
			containers = append(containers, netContainer{start: ip, end: ip})
		}
	}

	return containers
}

// cidrStartEnd returns the start and end IP addresses of a given CIDR range.
func cidrStartEnd(cidr string) (net.IP, net.IP, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}

	startIP := ipNet.IP.Mask(ipNet.Mask)

	endIP := make(net.IP, len(startIP))
	copy(endIP, startIP)

	for i := range endIP {
		endIP[i] |= ^ipNet.Mask[i]
	}

	return startIP, endIP, nil
}

// setCurrentIP copies ip into it.currentIP, reusing the backing slice when possible.
func (it *IPIterator) setCurrentIP(ip net.IP) {
	if cap(it.currentIP) >= len(ip) {
		it.currentIP = it.currentIP[:len(ip)]
	} else {
		it.currentIP = make(net.IP, len(ip))
	}
	copy(it.currentIP, ip)
}

// Next returns the next IP in the iterator.
func (it *IPIterator) Next() net.IP {
	// Exhausted: no more containers to iterate.
	if it.currentIdx >= len(it.containers) {
		return nil
	}

	// First call: position at the start of the first container.
	if it.currentIP == nil {
		return it.advanceToNextContainer(0)
	}

	container := it.currentContainer()

	// At end of current container: move to the next.
	if it.atEndOfContainer(container) {
		return it.advanceToNextContainer(it.currentIdx + 1)
	}

	// Still inside the container: increment and return.
	it.incrementIP()
	if it.skipLocal {
		return it.skipLocalAddresses(container)
	}
	return it.currentIP
}

// advanceToNextContainer positions the iterator at the start of containers[idx],
// skipping local addresses if skipLocal is set. Returns nil if idx is out of range.
func (it *IPIterator) advanceToNextContainer(idx int) net.IP {
	if idx >= len(it.containers) {
		return nil
	}
	it.currentIdx = idx
	cont := it.currentContainer()
	it.setCurrentIP(cont.start)
	if it.skipLocal && it.isLocalAddress() {
		return it.skipLocalAddresses(cont)
	}
	return it.currentIP
}

func (it *IPIterator) Shuffle() {
	fastrand.Shuffle(len(it.containers), func(i, j int) {
		it.containers[i], it.containers[j] = it.containers[j], it.containers[i]
	})
}

func (it *IPIterator) currentContainer() netContainer {
	return it.containers[it.currentIdx]
}

func (it *IPIterator) atEndOfContainer(cont netContainer) bool {
	return ipBytesEqual(it.currentIP, cont.end)
}

// incrementIP increments currentIP in place, avoiding allocation.
func (it *IPIterator) incrementIP() {
	incIPInPlace(it.currentIP)
}

// skipLocalAddresses skips any local addresses, crossing container boundaries if needed.
func (it *IPIterator) skipLocalAddresses(cont netContainer) net.IP {
	for it.isLocalAddress() {
		if it.atEndOfContainer(cont) {
			it.currentIdx++
			if it.currentIdx >= len(it.containers) {
				return nil
			}
			cont = it.currentContainer()
			it.setCurrentIP(cont.start)
			continue
		}
		it.incrementIP()
	}
	return it.currentIP
}

// isLocalAddress checks if the current IP address is a local address.
func (it *IPIterator) isLocalAddress() bool {
	ip := it.currentIP
	switch len(ip) {
	case 0:
		return false
	case 4:
		return isLocalV4(ip)
	case 16:
		if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
			ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
			ip[8] == 0 && ip[9] == 0 && ip[10] == 0xff && ip[11] == 0xff {
			return isLocalV4(ip[12:16])
		}
		return isLocalV6(ip)
	default:
		return false
	}
}

func isLocalV4(ip []byte) bool {
	return ip[0] == 0 ||
		ip[0] == 127 ||
		ip[0] == 10 ||
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168)
}

func isLocalV6(ip []byte) bool {
	nonZeroIdx := -1
	for i, b := range ip {
		if b != 0 {
			nonZeroIdx = i
			break
		}
	}
	if nonZeroIdx == -1 {
		return true
	}
	if nonZeroIdx == 15 && ip[15] == 1 {
		return true
	}
	return ip[0]&0xfe == 0xfc
}

// ipBytesEqual compares two net.IP values by raw bytes without To4() allocation.
func ipBytesEqual(a, b net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ipLessOrEqual checks if IP address ip is less than or equal to IP address ip2.
func ipLessOrEqual(ip, ip2 net.IP) bool {
	if len(ip) != len(ip2) {
		return len(ip) < len(ip2)
	}
	for i := range ip {
		if ip[i] < ip2[i] {
			return true
		} else if ip[i] > ip2[i] {
			return false
		}
	}
	return true
}

// HasNext returns true if there is a next IP address in the iterator.
func (it *IPIterator) HasNext() bool {
	if it.currentIdx >= len(it.containers) {
		return false
	}

	// Before the first Next() call, there is always a next IP (if containers exist).
	if it.currentIP == nil {
		return true
	}

	container := it.currentContainer()

	if ipBytesEqual(it.currentIP, container.end) {
		return it.currentIdx+1 < len(it.containers)
	}

	return true
}

// SetSkipLocal sets the skipLocal flag to the given value.
func (it *IPIterator) SetSkipLocal(b bool) {
	it.skipLocal = b
}

// incIPInPlace increments the given IP address by one in place.
func incIPInPlace(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
