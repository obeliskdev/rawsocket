package rawsocket

import (
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	selfIP   net.IP
	selfOnce sync.Once
)

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
			var ip net.IP
			switch v := a.(type) {
			case *net.IPAddr:
				ip = v.IP
			case *net.IPNet:
				ip = v.IP
			}
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
	})
	return selfIP
}

// getInterfaceByIP returns the network interface whose address matches ip.
func getInterfaceByIP(ip net.IP) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.Equal(ip) {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("no interface found for IP address: %s", ip)
}