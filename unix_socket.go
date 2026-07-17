//go:build !windows

package rawsocket

import (
	"errors"
	"sync"

	"github.com/google/gopacket"

	"net"
	"os"
	"strconv"
	"syscall"
	"time"
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

// maxIPPacketSize is the maximum size of an IP packet (IPv4 total
// length field is 16 bits). We use this as the read buffer size so we
// never truncate a valid packet, regardless of the interface MTU.
const maxIPPacketSize = 65535

// readBufPool reuses 65 KB buffers across NextPacket calls. Each
// buffer is returned to the pool after gopacket has parsed the packet
// and the caller is done with the data. This avoids a 65 KB heap
// allocation per packet in the hot read path.
var readBufPool = sync.Pool{
	New: func() any { return make([]byte, maxIPPacketSize) },
}

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
//
// On Linux, raw IP sockets (AF_INET / SOCK_RAW with IP_HDRINCL)
// deliver the full IP datagram — IP header + transport header +
// payload. Callers that expect transport-layer data (like monoamp's
// scanner) must strip the IP header themselves, or use NextPacket
// which uses gopacket to parse and strip it.
func (u *UnixSocket) Read(bytes []byte) (int, net.Addr, error) {
	return u.conn.ReadFrom(bytes)
}

// SetReadDeadline sets the deadline for future Read calls on the
// underlying net.PacketConn. A zero value means no deadline. This
// lets callers poll with a short deadline to break out of a blocking
// Read on context cancellation.
func (u *UnixSocket) SetReadDeadline(t time.Time) error {
	return u.conn.SetReadDeadline(t)
}

// Close closes the UnixSocket connection.
// It returns an error if there was an issue closing the connection.
func (u *UnixSocket) Close() error {
	return u.conn.Close()
}

// NextPacket reads a single packet from the socket and returns a
// gopacket.Parsed packet plus the source IP address. A pooled buffer
// is used for the raw read to avoid a 65 KB heap allocation per call.
// The packet data is copied out of the pooled buffer before parsing so
// the buffer can be immediately returned to the pool — this is safe
// and avoids the lifecycle ambiguity of NoCopy with pooled buffers.
//
// The copy adds one allocation per packet (the packet data slice),
// which is the same as the previous implementation. The difference is
// that the pooled read buffer is reused instead of being allocated
// and immediately becoming garbage.
func (u *UnixSocket) NextPacket() (gopacket.Packet, *net.IPAddr, error) {
	buf := readBufPool.Get().([]byte)
	n, addr, err := u.Read(buf)
	if err != nil || n <= 0 {
		readBufPool.Put(buf)
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, nil
	}

	// Copy the packet data into a fresh slice so the pooled buffer can
	// be returned immediately. gopacket will reference this copy, not
	// the pooled buffer, so there is no lifecycle coupling between the
	// returned packet and the pool.
	packetData := make([]byte, n)
	copy(packetData, buf)
	readBufPool.Put(buf)

	packet := gopacket.NewPacket(packetData, u.protocol.LinkType(), gopacket.NoCopy)
	ipAddr, _ := addr.(*net.IPAddr)
	return packet, ipAddr, nil
}

func (u *UnixSocket) Iter() chan WrappedPacket {
	packets := make(chan WrappedPacket, 1024)
	go packetIter(packets, u.NextPacket)
	return packets
}

// WriteRaw writes a pre-formatted IP packet directly to the wire.
// The destination address is extracted from the IP header in the
// packet so the kernel knows where to route it. extractDstIP returns
// a copy of the destination IP so it is safe even if the caller
// reuses the packet buffer after this call returns.
func (u *UnixSocket) WriteRaw(bytes []byte) (int, error) {
	dst := extractDstIP(bytes)
	if dst == nil {
		return 0, errors.New("rawsocket: cannot extract destination IP from packet")
	}
	return u.conn.WriteTo(bytes, &net.IPAddr{IP: dst})
}

// IsRawMode returns true — Unix raw sockets always operate in IP-raw
// mode (no ethernet framing needed).
func (u *UnixSocket) IsRawMode() bool {
	return true
}

// MACs returns nil, nil — Unix raw sockets do not use ethernet framing.
func (u *UnixSocket) MACs() (src, dst net.HardwareAddr) {
	return nil, nil
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
