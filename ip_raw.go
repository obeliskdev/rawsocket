package rawsocket

import (
	"fmt"
	"net"
	"sync"
)

var (
	selfIP net.IP
	mx     sync.Mutex
)

// getIfaceIP returns the IP address of the first available network interface that is not loopback.
func getIfaceIP() net.IP {
	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	// Iterate through each network interface
	for _, i := range ifaces {
		// Skip interfaces that are down or loopback.
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Get the addresses of the current interface
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}

		// Iterate through each address
		for _, a := range addrs {
			switch v := a.(type) {
			// If the address is of type *net.IPAddr
			case *net.IPAddr:
				// Skip loopback addresses and addresses that are not IPv4
				if v.IP.IsLoopback() || v.IP.To4() == nil {
					continue
				}
				return v.IP

			// If the address is of type *net.IPNet
			case *net.IPNet:
				// Skip loopback addresses and addresses that are not IPv4
				if v.IP.IsLoopback() || v.IP.To4() == nil {
					continue
				}
				return v.IP
			}
		}
	}

	return nil
}

// requestIP requests the local outbound IP address using a UDP dial.
func requestIP() net.IP {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return nil
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	return addr.IP
}

// GetSelfIP returns the IP address of the current machine.
func GetSelfIP() net.IP {
	// Check if selfIP has already been set
	if selfIP != nil {
		// Return the previously set selfIP
		return selfIP
	}

	// Lock the mutex
	mx.Lock()
	defer mx.Unlock()

	// Another goroutine may have initialized selfIP while we were waiting.
	if selfIP != nil {
		return selfIP
	}

	// Get the IP address using the requestIP function
	selfIP = requestIP()

	// If the IP address is not available, get it using the getIfaceIP function
	if selfIP == nil {
		selfIP = getIfaceIP()
	}

	// Return the final selfIP
	return selfIP
}

func getInterfaceByIP(ip net.IP) (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.Equal(ip) {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("no interface found for IP address: %s", ip)
}
