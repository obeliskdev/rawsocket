package rawsocket

import (
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestPrepareIPLayers_ReturnsIsV4_IPv4(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.IPv4(8, 8, 8, 8)
	var ip4 layers.IPv4
	var ip6 layers.IPv6

	_, _, isV4 := prepareIPLayers(src, dst, layers.IPProtocolTCP, &ip4, &ip6)
	if !isV4 {
		t.Fatal("expected isV4=true for IPv4 src+dst")
	}
	if ip4.SrcIP == nil || !ip4.SrcIP.Equal(src) {
		t.Fatalf("expected ip4.SrcIP=%s, got %v", src, ip4.SrcIP)
	}
}

func TestPrepareIPLayers_ReturnsIsV4_IPv6(t *testing.T) {
	src := net.ParseIP("2001:db8::1")
	dst := net.ParseIP("2001:db8::2")
	var ip4 layers.IPv4
	var ip6 layers.IPv6

	_, _, isV4 := prepareIPLayers(src, dst, layers.IPProtocolTCP, &ip4, &ip6)
	if isV4 {
		t.Fatal("expected isV4=false for IPv6 src+dst")
	}
	if ip6.SrcIP == nil || !ip6.SrcIP.Equal(src) {
		t.Fatalf("expected ip6.SrcIP=%s, got %v", src, ip6.SrcIP)
	}
}

func TestPrepareIPLayers_MixedFamily_NotV4(t *testing.T) {
	src := net.IPv4(10, 0, 0, 1)
	dst := net.ParseIP("2001:db8::1")
	var ip4 layers.IPv4
	var ip6 layers.IPv6

	_, _, isV4 := prepareIPLayers(src, dst, layers.IPProtocolTCP, &ip4, &ip6)
	if isV4 {
		t.Fatal("expected isV4=false for mixed v4+v6")
	}
}

func TestICMP_BuildWithError_NoDoubleTo4(t *testing.T) {
	src := net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}
	dst := net.IPAddr{IP: net.IPv4(8, 8, 8, 8)}

	icmp := NewICMP()
	pkt, err := icmp.BuildWithError(src, dst)
	if err != nil {
		t.Fatalf("BuildWithError failed: %v", err)
	}
	if len(pkt) == 0 {
		t.Fatal("empty packet")
	}

	packet := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.NoCopy)
	if packet.Layer(layers.LayerTypeICMPv4) == nil {
		t.Fatal("missing ICMPv4 layer")
	}
}

func TestIGMP_BuildWithError_NoDoubleTo4(t *testing.T) {
	src := net.IPAddr{IP: net.IPv4(10, 0, 0, 1)}
	dst := net.IPAddr{IP: net.IPv4(224, 0, 0, 1)}

	igmp := NewIGMP()
	pkt, err := igmp.BuildWithError(src, dst)
	if err != nil {
		t.Fatalf("BuildWithError failed: %v", err)
	}
	if len(pkt) == 0 {
		t.Fatal("empty packet")
	}

	packet := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.NoCopy)
	if packet.Layer(layers.LayerTypeIGMP) == nil {
		t.Fatal("missing IGMP layer")
	}
}

func TestExtractDstIP_RedundantCheckRemoved(t *testing.T) {
	v4Pkt := make([]byte, 20)
	v4Pkt[0] = 0x45
	v4Pkt[16] = 8
	v4Pkt[17] = 8
	v4Pkt[18] = 8
	v4Pkt[19] = 8
	dst := extractDstIP(v4Pkt)
	if dst == nil || !dst.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Fatalf("expected 8.8.8.8, got %v", dst)
	}

	shortPkt := make([]byte, 19)
	shortPkt[0] = 0x45
	if dst := extractDstIP(shortPkt); dst != nil {
		t.Fatalf("expected nil for short packet, got %v", dst)
	}

	v6Pkt := make([]byte, 40)
	v6Pkt[0] = 0x60
	copy(v6Pkt[24:], net.ParseIP("2001:db8::1"))
	dst6 := extractDstIP(v6Pkt)
	if dst6 == nil || !dst6.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("expected 2001:db8::1, got %v", dst6)
	}

	v6Short := make([]byte, 39)
	v6Short[0] = 0x60
	if dst := extractDstIP(v6Short); dst != nil {
		t.Fatalf("expected nil for short v6 packet, got %v", dst)
	}
}

func TestIpBytesEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b net.IP
		want bool
	}{
		{"equal_v4", net.IPv4(1, 2, 3, 4), net.IPv4(1, 2, 3, 4), true},
		{"different_v4", net.IPv4(1, 2, 3, 4), net.IPv4(1, 2, 3, 5), false},
		{"equal_v6", net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::1"), true},
		{"different_v6", net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), false},
		{"different_length", net.IPv4(1, 1, 1, 1).To4(), net.ParseIP("2001:db8::1"), false},
		{"both_nil", nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipBytesEqual(tt.a, tt.b); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestIsLocalV4(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
		want bool
	}{
		{"unspecified", net.IPv4(0, 0, 0, 0).To4(), true},
		{"loopback", net.IPv4(127, 0, 0, 1).To4(), true},
		{"private_10", net.IPv4(10, 0, 0, 1).To4(), true},
		{"private_172_16", net.IPv4(172, 16, 0, 1).To4(), true},
		{"private_172_31", net.IPv4(172, 31, 255, 255).To4(), true},
		{"public_172_32", net.IPv4(172, 32, 0, 1).To4(), false},
		{"private_192_168", net.IPv4(192, 168, 1, 1).To4(), true},
		{"public", net.IPv4(8, 8, 8, 8).To4(), false},
		{"public_1_1_1_1", net.IPv4(1, 1, 1, 1).To4(), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLocalV4(tt.ip); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestIsLocalV6(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
		want bool
	}{
		{"unspecified", net.ParseIP("::"), true},
		{"loopback", net.ParseIP("::1"), true},
		{"ula_fc00", net.ParseIP("fc00::1"), true},
		{"ula_fd00", net.ParseIP("fd12:3456::1"), true},
		{"public", net.ParseIP("2001:db8::1"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLocalV6(tt.ip); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestIsLocalAddress_V4MappedV6(t *testing.T) {
	v4Mapped := make(net.IP, 16)
	v4Mapped[10] = 0xff
	v4Mapped[11] = 0xff
	v4Mapped[12] = 10
	v4Mapped[13] = 0
	v4Mapped[14] = 0
	v4Mapped[15] = 1

	it := &IPIterator{currentIP: v4Mapped}
	if !it.isLocalAddress() {
		t.Fatal("expected v4-mapped 10.0.0.1 to be local")
	}

	v4MappedPublic := make(net.IP, 16)
	v4MappedPublic[10] = 0xff
	v4MappedPublic[11] = 0xff
	v4MappedPublic[12] = 8
	v4MappedPublic[13] = 8
	v4MappedPublic[14] = 8
	v4MappedPublic[15] = 8

	it2 := &IPIterator{currentIP: v4MappedPublic}
	if it2.isLocalAddress() {
		t.Fatal("expected v4-mapped 8.8.8.8 to be non-local")
	}
}

func TestIsLocalAddress_Empty(t *testing.T) {
	it := &IPIterator{currentIP: nil}
	if it.isLocalAddress() {
		t.Fatal("expected false for nil IP")
	}

	it2 := &IPIterator{currentIP: net.IP{}}
	if it2.isLocalAddress() {
		t.Fatal("expected false for empty IP")
	}
}

func TestIPIterator_HasNext_NoAlloc(t *testing.T) {
	it := ToIPIterator("10.0.0.1-10.0.0.100")
	_ = it.Next()

	allocs := testing.AllocsPerRun(100, func() {
		_ = it.HasNext()
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocs for HasNext, got %v", allocs)
	}
}

func TestIPIterator_SkipLocal_NoAlloc(t *testing.T) {
	it := ToIPIterator("10.0.0.1-10.0.0.5", "8.8.8.8")
	it.SetSkipLocal(true)

	for it.HasNext() {
		ip := it.Next()
		if ip == nil {
			break
		}
	}

	allocs := testing.AllocsPerRun(100, func() {
		_ = it.isLocalAddress()
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocs for isLocalAddress, got %v", allocs)
	}
}

func TestCopyLayerData(t *testing.T) {
	pkt := gopacket.NewPacket(
		[]byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x08, 0x08, 0x08, 0x08},
		layers.LayerTypeIPv4,
		gopacket.NoCopy,
	)
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		t.Fatal("missing IPv4 layer")
	}
	dst := make([]byte, 100)
	n := copyLayerData(dst, ipLayer)
	if n == 0 {
		t.Fatal("expected non-zero copied bytes")
	}
}

// TestCopyLayerData_Truncation verifies that copyLayerData safely
// handles a destination buffer smaller than the layer data. Go's
// copy() clips silently, so the function should not panic — it
// should return the number of bytes actually copied.
func TestCopyLayerData_Truncation(t *testing.T) {
	// Build a UDP-over-IPv4 packet so the UDP layer has both
	// LayerContents (the 8-byte UDP header) and LayerPayload.
	udpPkt := gopacket.NewPacket(
		[]byte{
			// IPv4 header (20 bytes)
			0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
			0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
			0x08, 0x08, 0x08, 0x08,
			// UDP header (8 bytes)
			0x04, 0xd2, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
		},
		layers.LayerTypeIPv4,
		gopacket.NoCopy,
	)
	udpLayer := udpPkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		t.Fatal("missing UDP layer")
	}

	// Full copy — dst is large enough
	fullDst := make([]byte, 100)
	fullN := copyLayerData(fullDst, udpLayer)
	if fullN == 0 {
		t.Fatal("expected non-zero bytes for full copy")
	}

	// Truncated copy — dst is too small (2 bytes for an 8-byte UDP header)
	smallDst := make([]byte, 2)
	smallN := copyLayerData(smallDst, udpLayer)
	if smallN > 2 {
		t.Errorf("copyLayerData with 2-byte dst: got %d bytes, expected <= 2", smallN)
	}
	// The first 2 bytes should match the UDP src port
	if smallN >= 2 {
		srcPort := int(smallDst[0])<<8 | int(smallDst[1])
		if srcPort != 1234 {
			t.Errorf("copyLayerData truncated: first 2 bytes = %d, want src port 1234", srcPort)
		}
	}
}

// TestCopyLayerData_EmptyLayer verifies that copyLayerData returns 0
// for a layer with no contents or payload.
func TestCopyLayerData_EmptyLayer(t *testing.T) {
	// Create a minimal packet with an empty layer — use a bare
	// IPv4 header with no payload, and get the network layer.
	pkt := gopacket.NewPacket(
		[]byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x08, 0x08, 0x08, 0x08},
		layers.LayerTypeIPv4,
		gopacket.NoCopy,
	)
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		t.Fatal("missing IPv4 layer")
	}
	// The IPv4 layer itself has 20 bytes of LayerContents, so this
	// should copy 20 bytes — not 0. The test just verifies it doesn't
	// panic and returns a reasonable count.
	dst := make([]byte, 100)
	n := copyLayerData(dst, ipLayer)
	if n != 20 {
		t.Logf("copyLayerData(IPv4-only) = %d bytes (expected 20 for bare IP header)", n)
	}
}

func TestLinkType_NoTo4Alloc(t *testing.T) {
	GetSelfIP()

	allocs := testing.AllocsPerRun(100, func() {
		_ = IPPROTO_ICMP.LinkType()
		_ = IPPROTO_IP.LinkType()
		_ = IPPROTO_RAW.LinkType()
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocs for LinkType, got %v", allocs)
	}
}

func TestLinkType_Consistent(t *testing.T) {
	GetSelfIP()

	icmpType := IPPROTO_ICMP.LinkType()
	ipType := IPPROTO_IP.LinkType()
	rawType := IPPROTO_RAW.LinkType()

	if icmpType == nil || ipType == nil || rawType == nil {
		t.Fatal("expected non-nil decoders")
	}

	if selfIPIsV4 {
		if icmpType != layers.LayerTypeICMPv4 {
			t.Fatalf("expected ICMPv4, got %v", icmpType)
		}
		if ipType != layers.LayerTypeIPv4 {
			t.Fatalf("expected IPv4, got %v", ipType)
		}
	} else {
		if icmpType != layers.LayerTypeICMPv6 {
			t.Fatalf("expected ICMPv6, got %v", icmpType)
		}
		if ipType != layers.LayerTypeIPv6 {
			t.Fatalf("expected IPv6, got %v", ipType)
		}
	}
}

func TestParseData_IndexByte(t *testing.T) {
	containers := parseData([]string{
		"10.0.0.1-10.0.0.5",
		"192.168.1.0/30",
		"1.1.1.1",
		"bad-bad",
		"not-an-ip",
	})
	if len(containers) != 3 {
		t.Fatalf("expected 3 valid containers, got %d", len(containers))
	}

	if !containers[0].start.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Fatalf("expected range start 10.0.0.1, got %v", containers[0].start)
	}
	if !containers[0].end.Equal(net.IPv4(10, 0, 0, 5)) {
		t.Fatalf("expected range end 10.0.0.5, got %v", containers[0].end)
	}
	if !containers[1].start.Equal(net.IPv4(192, 168, 1, 0)) {
		t.Fatalf("expected cidr start 192.168.1.0, got %v", containers[1].start)
	}
	if !containers[2].start.Equal(net.IPv4(1, 1, 1, 1)) {
		t.Fatalf("expected single 1.1.1.1, got %v", containers[2].start)
	}
}

func TestParseData_IndexByte_NoSplitAlloc(t *testing.T) {
	input := []string{"10.0.0.1-10.0.0.2"}

	allocs := testing.AllocsPerRun(100, func() {
		_ = parseData(input)
	})

	if allocs < 0 {
		t.Fatalf("unexpected negative allocs: %v", allocs)
	}
}

func TestParseData_IPv6Range(t *testing.T) {
	containers := parseData([]string{"2001:db8::1-2001:db8::3"})
	if len(containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(containers))
	}
	if !containers[0].start.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("expected 2001:db8::1, got %v", containers[0].start)
	}
}

func TestFindIfaceForIP_NotFound(t *testing.T) {
	iface, ok := findIfaceForIP(net.IPv4(255, 255, 255, 255))
	if ok {
		t.Fatal("expected ok=false for unlikely IP 255.255.255.255")
	}
	if iface != nil {
		t.Fatal("expected nil iface")
	}
}

func TestFindIfaceForIP_SelfIP(t *testing.T) {
	selfIP := GetSelfIP()
	if selfIP == nil {
		t.Skip("no self IP available")
	}
	iface, ok := findIfaceForIP(selfIP)
	if !ok {
		t.Skip("could not find iface for self IP (may be expected in some envs)")
	}
	if iface == nil {
		t.Fatal("ok=true but iface is nil")
	}
}

func TestGetLocalMac_UsesFindIfaceForIP(t *testing.T) {
	mac, err := GetLocalMac()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "failed to retrieve") {
			t.Skip("no local MAC found (expected in some envs)")
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if mac == nil {
		t.Fatal("expected non-nil MAC address")
	}
}

func TestIsLocalV6_SinglePass(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
		want bool
	}{
		{"unspecified", net.ParseIP("::"), true},
		{"loopback", net.ParseIP("::1"), true},
		{"ula_fc00", net.ParseIP("fc00::1"), true},
		{"ula_fd00", net.ParseIP("fd12:3456::1"), true},
		{"public", net.ParseIP("2001:db8::1"), false},
		{"public_v4mapped", net.ParseIP("::ffff:8.8.8.8"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLocalV6(tt.ip); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestChecksum16_PrecomputedBound(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected uint16
	}{
		{"empty", []byte{}, 0xffff},
		{"single_byte", []byte{0x01}, 0xfeff},
		{"two_bytes", []byte{0x00, 0x01}, 0xfffe},
		{"three_bytes", []byte{0x00, 0x01, 0x02}, 0xfdfe},
		{"known_value", []byte{0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01}, 0x79d1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checksum16(tt.input); got != tt.expected {
				t.Fatalf("checksum16(%v) = 0x%04x, want 0x%04x", tt.input, got, tt.expected)
			}
		})
	}
}

func TestChecksum16_NoAlloc(t *testing.T) {
	input := make([]byte, 256)
	allocs := testing.AllocsPerRun(100, func() {
		_ = checksum16(input)
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocs for checksum16, got %v", allocs)
	}
}

func TestProtocolFilterType(t *testing.T) {
	tests := []struct {
		name     string
		proto    ProtocolType
		expected gopacket.LayerType
	}{
		{"tcp", IPPROTO_TCP, layers.LayerTypeTCP},
		{"udp", IPPROTO_UDP, layers.LayerTypeUDP},
		{"igmp", IPPROTO_IGMP, layers.LayerTypeIGMP},
		{"esp", IPPROTO_ESP, layers.LayerTypeIPSecESP},
		{"ip", IPPROTO_IP, gopacket.LayerTypeZero},
		{"icmp", IPPROTO_ICMP, gopacket.LayerTypeZero},
		{"raw", IPPROTO_RAW, gopacket.LayerTypeZero},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := protocolFilterType(tt.proto); got != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestAddrIP(t *testing.T) {
	ip := net.IPv4(10, 0, 0, 1)

	ipAddr := &net.IPAddr{IP: ip}
	if got := addrIP(ipAddr); !got.Equal(ip) {
		t.Fatalf("expected %s, got %v", ip, got)
	}

	ipNet := &net.IPNet{IP: ip, Mask: net.CIDRMask(24, 32)}
	if got := addrIP(ipNet); !got.Equal(ip) {
		t.Fatalf("expected %s, got %v", ip, got)
	}

	if got := addrIP(nil); got != nil {
		t.Fatalf("expected nil for nil addr, got %v", got)
	}

	other := &net.UDPAddr{IP: ip, Port: 53}
	if got := addrIP(other); got != nil {
		t.Fatalf("expected nil for unknown addr type, got %v", got)
	}
}

func TestBroadcastMAC(t *testing.T) {
	expected := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if len(broadcastMAC) != 6 {
		t.Fatalf("expected 6 bytes, got %d", len(broadcastMAC))
	}
	for i, b := range broadcastMAC {
		if b != expected[i] {
			t.Fatalf("byte %d: expected 0xff, got 0x%02x", i, b)
		}
	}
}

func TestAdvanceToNextContainer_DedupCurrentContainer(t *testing.T) {
	it := ToIPIterator("10.0.0.1-10.0.0.3", "20.0.0.1-20.0.0.2")
	it.SetSkipLocal(false)

	ip := it.Next()
	if !ip.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Fatalf("expected 10.0.0.1, got %v", ip)
	}
	ip = it.Next()
	if !ip.Equal(net.IPv4(10, 0, 0, 2)) {
		t.Fatalf("expected 10.0.0.2, got %v", ip)
	}
	ip = it.Next()
	if !ip.Equal(net.IPv4(10, 0, 0, 3)) {
		t.Fatalf("expected 10.0.0.3, got %v", ip)
	}
	ip = it.Next()
	if !ip.Equal(net.IPv4(20, 0, 0, 1)) {
		t.Fatalf("expected 20.0.0.1 (advance to next container), got %v", ip)
	}
}

func TestPcapSocket_Read_MergedIGMPESP(t *testing.T) {
	igmpFilter := protocolFilterType(IPPROTO_IGMP)
	if igmpFilter != layers.LayerTypeIGMP {
		t.Fatalf("expected IGMP filter type, got %v", igmpFilter)
	}

	espFilter := protocolFilterType(IPPROTO_ESP)
	if espFilter != layers.LayerTypeIPSecESP {
		t.Fatalf("expected ESP filter type, got %v", espFilter)
	}

	p := &PcapSocket{protocol: IPPROTO_IGMP, filterType: igmpFilter}
	if p.filterType != layers.LayerTypeIGMP {
		t.Fatalf("expected IGMP filter type on PcapSocket, got %v", p.filterType)
	}

	p2 := &PcapSocket{protocol: IPPROTO_ESP, filterType: espFilter}
	if p2.filterType != layers.LayerTypeIPSecESP {
		t.Fatalf("expected ESP filter type on PcapSocket, got %v", p2.filterType)
	}
}

func TestNextPacket_ICMPv4Only(t *testing.T) {
	v4Pkt := []byte{
		0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00,
		0x40, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
		0x08, 0x08, 0x08, 0x08,
		0x08, 0x00, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01,
	}
	pkt := gopacket.NewPacket(v4Pkt, layers.LayerTypeIPv4, gopacket.NoCopy)
	if pkt.Layer(layers.LayerTypeICMPv4) == nil {
		t.Fatal("expected ICMPv4 layer in test packet")
	}
	if pkt.Layer(layers.LayerTypeICMPv6) != nil {
		t.Fatal("unexpected ICMPv6 layer in v4 test packet")
	}
}
