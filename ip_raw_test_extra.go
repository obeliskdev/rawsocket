package rawsocket

import (
	"net"
	"testing"
)

func TestGetSelfIP_Cached(t *testing.T) {
	first := GetSelfIP()
	second := GetSelfIP()
	if first == nil {
		t.Skip("no self IP available in this environment")
	}
	if !first.Equal(second) {
		t.Fatalf("GetSelfIP returned different values: %s vs %s", first, second)
	}
}

func TestGetSelfIP_IsIPv4(t *testing.T) {
	ip := GetSelfIP()
	if ip == nil {
		t.Skip("no self IP available")
	}
	if ip.To4() == nil {
		t.Fatalf("expected IPv4 address, got %s", ip)
	}
}

func TestGetInterfaceByIP_NotFound(t *testing.T) {
	_, err := getInterfaceByIP(net.IPv4(240, 0, 0, 1))
	if err == nil {
		t.Fatal("expected error for non-existent interface IP")
	}
}

func TestGetInterfaceByIP_SelfIP(t *testing.T) {
	ip := GetSelfIP()
	if ip == nil {
		t.Skip("no self IP available")
	}
	iface, err := getInterfaceByIP(ip)
	if err != nil {
		t.Fatalf("expected to find interface for self IP %s: %v", ip, err)
	}
	if iface == nil {
		t.Fatal("expected non-nil interface")
	}
}
