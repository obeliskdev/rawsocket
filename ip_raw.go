package rawsocket

import (
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	selfIP     net.IP
	selfIPIsV4 bool
	selfOnce   sync.Once
)

// addrIP extracts the net.IP from a net.Addr, or nil if the type is unknown.
func addrIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPAddr:
		return v.IP
	case *net.IPNet:
		return v.IP
	}
	return nil
}

// getIfaceIP returns the IPv4 address of the first available network interface
// that is up and not loopback. Returns nil if none is found.
func getIfaceIP() net.IP {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := i.Addrs()
		if err != nil {
			continue
		}

		for _, a := range addrs {
			ip := addrIP(a)
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				return ip4
			}
		}
	}

	return nil
}

// requestIP discovers the local outbound IPv4 address by dialing a UDP socket.
// The dial target is not contacted; the kernel just picks a local source address.
func requestIP() net.IP {
	conn, err := net.DialTimeout("udp", "1.1.1.1:80", 5*time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	return addr.IP.To4()
}

// GetSelfIP returns the IPv4 address of the current machine.
// The result is computed once and cached for subsequent calls.
func GetSelfIP() net.IP {
	selfOnce.Do(func() {
		selfIP = requestIP()
		if selfIP == nil {
			selfIP = getIfaceIP()
		}
		if selfIP != nil {
			selfIPIsV4 = selfIP.To4() != nil
		}
	})
	return selfIP
}

// findIfaceForIP returns the first network interface whose address matches ip.
// The addr type-switch is shared by getInterfaceByIP and GetLocalMac.
func findIfaceForIP(ip net.IP) (*net.Interface, bool) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, false
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if addrIP(addr).Equal(ip) {
				return &iface, true
			}
		}
	}

	return nil, false
}

// getInterfaceByIP returns the network interface whose address matches ip.
func getInterfaceByIP(ip net.IP) (*net.Interface, error) {
	iface, ok := findIfaceForIP(ip)
	if !ok {
		return nil, fmt.Errorf("no interface found for IP address: %s", ip)
	}
	return iface, nil
}
