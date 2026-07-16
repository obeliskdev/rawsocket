//go:build !windows

package rawsocket

import (
	"math"

	"github.com/google/gopacket"

	"net"
	"os"
	"strconv"
	"syscall"
)

//goland:noinspection GoUnusedGlobalVariable,GoSnakeCaseUsage
var (
	IPPROTO_TCP  = ProtocolType(syscall.IPPROTO_TCP)
	IPPROTO_UDP  = ProtocolType(syscall.IPPROTO_UDP)
	IPPROTO_ICMP = ProtocolType(syscall.IPPROTO_ICMP)
	IPPROTO_IGMP = ProtocolType(syscall.IPPROTO_IGMP)
	IPPROTO_ESP  = ProtocolType(syscall.IPPROTO_ESP)
	IPPROTO_RAW  = ProtocolType(syscall.IPPROTO_RAW)
	IPPROTO_IP   = ProtocolType(syscall.IPPROTO_IP)
)

type UnixSocket struct {
	conn     net.PacketConn
	protocol ProtocolType
}

var mtu = math.MaxInt16

func init() {
	iface, err := getInterfaceByIP(GetSelfIP())
	if err != nil || iface == nil || iface.MTU <= 0 {
		mtu = math.MaxInt16
		return
	}

	mtu = iface.MTU + 1
}

// newUnixSocket creates a new UnixSocket instance with the given PacketConn.
func newUnixSocket(conn net.PacketConn, protocol ProtocolType) *UnixSocket {
	return &UnixSocket{conn: conn, protocol: protocol}
}

// Write writes the given bytes to the specified address using the UnixSocket connection.
// It returns the number of bytes written and any error that occurred.
func (u *UnixSocket) Write(bytes []byte, addr net.Addr) (int, error) {
	return u.conn.WriteTo(bytes, addr)
}

// Read reads data from the Unix socket connection.
// It reads up to len(bytes) bytes into the provided byte slice.
// It returns the number of bytes read, the network address of the remote socket,
// and any error encountered.
func (u *UnixSocket) Read(bytes []byte) (int, net.Addr, error) {
	return u.conn.ReadFrom(bytes)
}

// Close closes the UnixSocket connection.
// It returns an error if there was an issue closing the connection.
func (u *UnixSocket) Close() error {
	return u.conn.Close()
}

func (u *UnixSocket) NextPacket() (gopacket.Packet, *net.IPAddr, error) {
	packetData := make([]byte, mtu)

	n, addr, err := u.Read(packetData)
	if err != nil {
		return nil, nil, err
	}

	packet := gopacket.NewPacket(packetData[:n], u.protocol.LinkType(), gopacket.NoCopy)
	ipAddr, _ := addr.(*net.IPAddr)
	return packet, ipAddr, nil
}

func (u *UnixSocket) Iter() chan WrappedPacket {
	packets := make(chan WrappedPacket, 1024)
	go packetIter(packets, u.NextPacket)
	return packets
}

func closeOnErr(fd int, err error) (RawSocket, error) {
	_ = syscall.Close(fd)
	return nil, err
}

// OpenRawSocket opens a raw socket for the specified protocol.
// It returns a pointer to RawSocket and an error, if any.
func OpenRawSocket(protocol ProtocolType) (RawSocket, error) {
	// Create a new raw socket
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, int(protocol))
	if err != nil {
		return nil, err
	}

	// Set socket options
	if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return closeOnErr(sock, err)
	}

	if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.SO_REUSEADDR, 1); err != nil {
		return closeOnErr(sock, err)
	}

	// Convert the socket to a packet connection
	conn, err := net.FilePacketConn(os.NewFile(uintptr(sock), strconv.Itoa(sock)))
	if err != nil {
		return closeOnErr(sock, err)
	}

	// Create a RawSocket instance and return it
	return newUnixSocket(conn, protocol), nil
}
