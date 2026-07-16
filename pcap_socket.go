//go:build windows

package rawsocket

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

//goland:noinspection GoUnusedGlobalVariable,GoSnakeCaseUsage
var (
	IPPROTO_TCP  = ProtocolType(syscall.IPPROTO_TCP)
	IPPROTO_UDP  = ProtocolType(syscall.IPPROTO_UDP)
	IPPROTO_ICMP = ProtocolType(0x1)
	IPPROTO_IGMP = ProtocolType(0x2)
	IPPROTO_ESP  = ProtocolType(0x32)
	IPPROTO_RAW  = ProtocolType(0xFF)
	IPPROTO_IP   = ProtocolType(syscall.IPPROTO_IP)
)

var (
	NetworkDevice *pcap.Interface
	SysSrcMac     *net.HardwareAddr
	RouterMac     *net.HardwareAddr

	once      sync.Once
	mutex     sync.RWMutex
	ipRawMode bool
)

func init() {
	SrcIP := GetSelfIP()
	if SrcIP == nil {
		return
	}

	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	for _, dev := range devices {
		for _, address := range dev.Addresses {
			if address.IP.Equal(SrcIP) {
				mutex.Lock()
				NetworkDevice = &dev
				mutex.Unlock()
				return
			}
		}
	}
}

func waitForMac(packetSource *gopacket.PacketSource) {
	ip := GetSelfIP()

	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			return
		}

		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			mutex.RLock()
			routerSet := RouterMac != nil
			mutex.RUnlock()
			if routerSet {
				return
			}

			if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
				if ipLayer.(*layers.IPv4).SrcIP.Equal(ip) {
					ethernet := ethernetLayer.(*layers.Ethernet)

					srcMac := make(net.HardwareAddr, len(ethernet.SrcMAC))
					copy(srcMac, ethernet.SrcMAC)
					dstMac := make(net.HardwareAddr, len(ethernet.DstMAC))
					copy(dstMac, ethernet.DstMAC)

					mutex.Lock()
					SysSrcMac = &srcMac
					RouterMac = &dstMac
					mutex.Unlock()
					return
				}
			}
		}
	}
}

type PcapSocket struct {
	*pcap.Handle
	isRaw      bool
	protocol   ProtocolType
	source     *gopacket.PacketSource
	filterType gopacket.LayerType

	readDeadlineMu sync.Mutex
	readDeadline   time.Time // zero = no deadline (block until packet)
}

func newPcapSocket(isRaw bool, handle *pcap.Handle, protocol ProtocolType, source *gopacket.PacketSource) *PcapSocket {
	return &PcapSocket{
		isRaw:      isRaw,
		Handle:     handle,
		protocol:   protocol,
		source:     source,
		filterType: protocolFilterType(protocol),
	}
}

func protocolFilterType(p ProtocolType) gopacket.LayerType {
	switch p {
	case IPPROTO_TCP:
		return layers.LayerTypeTCP
	case IPPROTO_UDP:
		return layers.LayerTypeUDP
	case IPPROTO_IGMP:
		return layers.LayerTypeIGMP
	case IPPROTO_ESP:
		return layers.LayerTypeIPSecESP
	default:
		return gopacket.LayerTypeZero
	}
}

var writeBufPool = sync.Pool{
	New: func() any { return gopacket.NewSerializeBuffer() },
}

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func (p *PcapSocket) Write(bytes []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, errors.New("addr is nil")
	}

	if hasEthernet(bytes) && p.isRaw {
		return 0, errors.New("ethernet is not supported in IPRaw mode")
	}

	if hasEthernet(bytes) {
		if err := p.WritePacketData(bytes); err != nil {
			return 0, err
		}
		return len(bytes), nil
	}

	packet := createPacket(bytes)
	layer3, layer4, err := getNetworkAndTransportLayers(packet)
	if err != nil {
		return 0, err
	}

	if tcp, ok := layer4.(*layers.TCP); ok {
		if err := tcp.SetNetworkLayerForChecksum(packet.NetworkLayer()); err != nil {
			return 0, err
		}
	} else if udp, ok := layer4.(*layers.UDP); ok {
		if err := udp.SetNetworkLayerForChecksum(packet.NetworkLayer()); err != nil {
			return 0, err
		}
	}

	buffer := writeBufPool.Get().(gopacket.SerializeBuffer)
	defer writeBufPool.Put(buffer)
	buffer.Clear()

	if p.isRaw {
		if err := gopacket.SerializeLayers(buffer, serializeOptions, layer3, layer4); err != nil {
			return 0, err
		}
	} else {
		mutex.RLock()
		srcMac, routerMac := SysSrcMac, RouterMac
		mutex.RUnlock()
		if srcMac == nil || routerMac == nil {
			return 0, errors.New("missing source or router MAC address")
		}
		if err := gopacket.SerializeLayers(buffer, serializeOptions, &layers.Ethernet{
			SrcMAC:       *srcMac,
			DstMAC:       *routerMac,
			EthernetType: layers.EthernetTypeIPv4,
		}, layer3, layer4); err != nil {
			return 0, err
		}
	}

	if err := p.WritePacketData(buffer.Bytes()); err != nil {
		return 0, err
	}

	return len(bytes), nil
}

// WriteRaw writes a pre-formatted frame directly to the wire via
// WritePacketData, bypassing gopacket re-parsing and re-serialization.
// The caller must include any required headers (ethernet, IP, transport).
func (p *PcapSocket) WriteRaw(bytes []byte) (int, error) {
	if err := p.WritePacketData(bytes); err != nil {
		return 0, err
	}
	return len(bytes), nil
}

// IsRawMode returns true when the socket operates in IP-raw mode
// (no ethernet framing needed).
func (p *PcapSocket) IsRawMode() bool {
	return p.isRaw
}

// MACs returns the source and router MAC addresses used for ethernet
// framing. Returns nil, nil in raw mode or when MACs are unavailable.
func (p *PcapSocket) MACs() (src, dst net.HardwareAddr) {
	mutex.RLock()
	if SysSrcMac != nil {
		src = *SysSrcMac
	}
	if RouterMac != nil {
		dst = *RouterMac
	}
	mutex.RUnlock()
	return
}

func createPacket(bytes []byte) gopacket.Packet {
	if isIPv4(bytes) {
		return gopacket.NewPacket(bytes, layers.LayerTypeIPv4, decodeOptions)
	}
	return gopacket.NewPacket(bytes, layers.LayerTypeIPv6, decodeOptions)
}

func getNetworkAndTransportLayers(packet gopacket.Packet) (gopacket.SerializableLayer, gopacket.SerializableLayer, error) {
	network := packet.NetworkLayer()
	if network == nil {
		return nil, nil, errors.New("missing network layer")
	}
	layer3, ok := network.(gopacket.SerializableLayer)
	if !ok {
		return nil, nil, errors.New("network layer is not serializable")
	}

	transport := packet.TransportLayer()
	if transport == nil {
		return nil, nil, errors.New("missing transport layer")
	}
	layer4, ok := transport.(gopacket.SerializableLayer)
	if !ok {
		return nil, nil, errors.New("transport layer is not serializable")
	}

	return layer3, layer4, nil
}

func (p *PcapSocket) NextPacket() (gopacket.Packet, *net.IPAddr, error) {
	for {
		// Check the caller-imposed deadline. The handle's own read
		// timeout (250 ms) makes ReadPacketData return periodically;
		// we retry until the deadline expires or a packet arrives.
		p.readDeadlineMu.Lock()
		dl := p.readDeadline
		p.readDeadlineMu.Unlock()
		if !dl.IsZero() && time.Now().After(dl) {
			return nil, nil, errReadTimeout
		}

		packet, err := p.source.NextPacket()
		if err != nil {
			// A timeout from the handle's finite read timeout is
			// expected while polling; retry unless the caller's
			// deadline has passed.
			if isPcapTimeout(err) {
				if !dl.IsZero() && time.Now().After(dl) {
					return nil, nil, errReadTimeout
				}
				continue
			}
			return nil, nil, err
		}

		var ipAddr net.IP
		var isV4 bool

		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			ipAddr = ip4Layer.(*layers.IPv4).SrcIP
			isV4 = true
		} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			ipAddr = ip6Layer.(*layers.IPv6).SrcIP
		}

		switch p.protocol {
		case IPPROTO_TCP, IPPROTO_UDP, IPPROTO_IGMP, IPPROTO_ESP:
			if packet.Layer(p.filterType) == nil {
				continue
			}
		case IPPROTO_IP:
			if ipAddr == nil {
				continue
			}
		case IPPROTO_ICMP:
			if isV4 {
				if packet.Layer(layers.LayerTypeICMPv4) == nil {
					continue
				}
			} else {
				if packet.Layer(layers.LayerTypeICMPv6) == nil {
					continue
				}
			}
		default:
			if p.protocol != IPPROTO_RAW {
				continue
			}
		}

		return packet, &net.IPAddr{IP: ipAddr}, nil
	}
}

func (p *PcapSocket) Iter() chan WrappedPacket {
	packets := make(chan WrappedPacket, 1024)
	go packetIter(packets, p.NextPacket)
	return packets
}

// SetReadDeadline sets the deadline for future Read/NextPacket calls.
// A zero value means no deadline (block until a packet arrives).
// Since the underlying pcap handle has no native SetReadDeadline, the
// deadline is stored and checked in the NextPacket retry loop. The
// handle is opened with a 250 ms read timeout so the loop wakes up
// regularly to check the deadline.
func (p *PcapSocket) SetReadDeadline(t time.Time) error {
	p.readDeadlineMu.Lock()
	p.readDeadline = t
	p.readDeadlineMu.Unlock()
	return nil
}

var errReadTimeout = errors.New("rawsocket: read deadline exceeded")

// isPcapTimeout reports whether err is a pcap read timeout. gopacket
// returns NextErrorTimeoutExpired when the handle's read timeout
// elapses without a packet.
func isPcapTimeout(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "timeout") || strings.Contains(s, "Timeout")
}

func (p *PcapSocket) Read(bytes []byte) (int, net.Addr, error) {
	for {
		packet, addr, err := p.NextPacket()
		if err != nil {
			return 0, nil, err
		}

		switch p.protocol {
		case IPPROTO_UDP, IPPROTO_TCP:
			if transportLayer := packet.TransportLayer(); transportLayer != nil {
				return copyLayerData(bytes, transportLayer), addr, nil
			}
		case IPPROTO_IP, IPPROTO_ICMP:
			if networkLayer := packet.NetworkLayer(); networkLayer != nil {
				return copyLayerData(bytes, networkLayer), addr, nil
			}
		case IPPROTO_IGMP, IPPROTO_ESP:
			if layer := packet.Layer(p.filterType); layer != nil {
				return copyLayerData(bytes, layer), addr, nil
			}
		default:
			return copy(bytes, packet.Data()), addr, nil
		}
	}
}

func copyLayerData(dst []byte, layer gopacket.Layer) int {
	n := copy(dst, layer.LayerContents())
	n += copy(dst[n:], layer.LayerPayload())
	return n
}

func (p *PcapSocket) Close() error {
	p.Handle.Close()
	return nil
}

func OpenRawSocket(protocol ProtocolType) (RawSocket, error) {
	mutex.RLock()
	device := NetworkDevice
	mutex.RUnlock()
	if device == nil {
		return nil, errors.New("network device not found")
	}

	// Use a finite read timeout so SetReadDeadline polling works:
	// ReadPacketData returns a timeout error after this interval,
	// letting NextPacket/Read retry until the caller's deadline
	// expires or ctx is cancelled. BlockForever would never return,
	// making the socket uncancellable.
	handle, err := pcap.OpenLive(device.Name, 255, true, 250*time.Millisecond)
	if err != nil {
		return nil, err
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.NoCopy = true
	source.DecodeOptions = decodeOptions

	var onceErr error
	once.Do(func() {
		if err := updateMac(handle); err != nil {
			if strings.Contains(err.Error(), "mismatched hardware address sizes") {
				ipRawMode = true
				return
			}
			onceErr = err
			return
		}
		waitForMac(source)
	})
	if onceErr != nil {
		handle.Close()
		return nil, onceErr
	}

	return newPcapSocket(ipRawMode, handle, protocol, source), nil
}

func isIPv4(bytes []byte) bool {
	if len(bytes) == 0 {
		return false
	}
	return bytes[0]>>4 == 4
}

func updateMac(handle *pcap.Handle) error {
	mutex.RLock()
	srcSet := SysSrcMac != nil
	mutex.RUnlock()
	if srcSet {
		return nil
	}

	localMAC, err := GetLocalMac()
	if err != nil {
		return err
	}

	arpPacket := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   localMAC,
		SourceProtAddress: GetSelfIP(),
		DstHwAddress:      broadcastMAC,
		DstProtAddress:    GetSelfIP(),
	}

	ethernetPacket := &layers.Ethernet{
		SrcMAC:       localMAC,
		DstMAC:       broadcastMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	buffer := writeBufPool.Get().(gopacket.SerializeBuffer)
	defer writeBufPool.Put(buffer)
	buffer.Clear()
	if err := gopacket.SerializeLayers(buffer, serializeOptions, ethernetPacket, arpPacket); err != nil {
		return err
	}

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		return err
	}

	return nil
}

func GetLocalMac() (net.HardwareAddr, error) {
	selfIP := GetSelfIP()

	iface, ok := findIfaceForIP(selfIP)
	if !ok {
		return nil, fmt.Errorf("failed to retrieve local MAC address")
	}
	return iface.HardwareAddr, nil
}

func hasEthernet(bytes []byte) bool {
	return len(bytes) > 13 && bytes[12] == 0x08 && bytes[13] == 0x00
}
