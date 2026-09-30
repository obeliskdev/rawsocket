//go:build !windows

package rawsocket

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}

// AFPacketSocket is a Linux-only socket that receives packets at the
// link layer (AF_PACKET), before the kernel's TCP/IP stack processes
// them. This is essential for SYN scanning: when a SYN-ACK arrives for
// a connection the kernel doesn't know about (because the SYN was sent
// via a raw socket), the TCP stack sends a RST and "consumes" the
// packet before IPPROTO_TCP raw sockets can copy it. AF_PACKET
// delivers a copy at the link layer, before any protocol processing,
// so the SYN-ACK is always captured.
type AFPacketSocket struct {
	fd      int
	iface   string
	ifindex int
}

// OpenAFPacketSocket opens an AF_PACKET, SOCK_RAW socket that
// receives all IP frames on the specified interface (or all
// interfaces if iface is empty). The caller must be root or have
// CAP_NET_RAW.
func OpenAFPacketSocket(iface string) (*AFPacketSocket, error) {
	fd, err := syscall.Socket(
		syscall.AF_PACKET,
		syscall.SOCK_RAW,
		int(htons(syscall.ETH_P_IP)),
	)
	if err != nil {
		return nil, fmt.Errorf("afpacket: socket: %w (hint: run as root)", err)
	}

	idx := 0
	if iface != "" {
		ifObj, err := net.InterfaceByName(iface)
		if err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("afpacket: lookup iface %s: %w", iface, err)
		}
		idx = ifObj.Index
		sll := syscall.SockaddrLinklayer{
			Protocol: htons(syscall.ETH_P_IP),
			Ifindex:  idx,
		}
		if err := syscall.Bind(fd, &sll); err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("afpacket: bind: %w", err)
		}
	}

	return &AFPacketSocket{
		fd:      fd,
		iface:   iface,
		ifindex: idx,
	}, nil
}

// Read reads a single link-layer frame.
func (a *AFPacketSocket) Read(buf []byte) (int, error) {
	n, _, err := syscall.Recvfrom(a.fd, buf, 0)
	return n, err
}

// SetReadDeadline sets a deadline for future Read calls.
func (a *AFPacketSocket) SetReadDeadline(t time.Time) error {
	tv := syscall.NsecToTimeval(t.UnixNano())
	return syscall.SetsockoptTimeval(a.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
}

// Close closes the socket.
func (a *AFPacketSocket) Close() error {
	return syscall.Close(a.fd)
}

// NextPacket reads a single Ethernet frame, strips the Ethernet
// header, and returns a gopacket parsed as IPv4 so callers can
// access the TCP layer via packet.Layer(LayerTypeTCP).
func (a *AFPacketSocket) NextPacket() (gopacket.Packet, error) {
	buf := make([]byte, 65535)
	n, err := a.Read(buf)
	if err != nil || n <= 0 {
		return nil, err
	}
	pkt := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.Default)
	if eth := pkt.Layer(layers.LayerTypeEthernet); eth != nil {
		ipPayload := eth.(*layers.Ethernet).LayerPayload()
		if len(ipPayload) > 0 {
			return gopacket.NewPacket(ipPayload, layers.LayerTypeIPv4, gopacket.Default), nil
		}
	}
	return gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.Default), nil
}
