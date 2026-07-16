package rawsocket

import (
	"net"
	"testing"
)

func TestIPIterator_SingleIP(t *testing.T) {
	it := ToIPIterator("192.168.1.1")
	if !it.HasNext() {
		t.Fatal("expected HasNext true for single IP")
	}
	first := it.Next()
	if !first.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Fatalf("expected 192.168.1.1, got %s", first)
	}
	if it.HasNext() {
		t.Fatal("expected HasNext false after single IP consumed")
	}
	if got := it.Next(); got != nil {
		t.Fatalf("expected nil after exhaustion, got %s", got)
	}
}

func TestIPIterator_Range(t *testing.T) {
	it := ToIPIterator("10.0.0.1-10.0.0.5")
	expected := []string{
		"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
	}
	var got []string
	for it.HasNext() {
		ip := it.Next()
		if ip == nil {
			t.Fatal("unexpected nil within range")
		}
		got = append(got, ip.String())
	}
	if len(got) != len(expected) {
		t.Fatalf("expected %d IPs, got %d (%v)", len(expected), len(got), got)
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("index %d: expected %s, got %s", i, expected[i], got[i])
		}
	}
}

func TestIPIterator_CIDR(t *testing.T) {
	it := ToIPIterator("192.168.1.0/30")
	expected := []string{
		"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3",
	}
	var count int
	for it.HasNext() {
		ip := it.Next()
		if ip == nil {
			t.Fatal("unexpected nil")
		}
		if count >= len(expected) {
			t.Fatalf("too many IPs, got %s at index %d", ip, count)
		}
		if ip.String() != expected[count] {
			t.Fatalf("index %d: expected %s, got %s", count, expected[count], ip.String())
		}
		count++
	}
	if count != len(expected) {
		t.Fatalf("expected %d IPs, got %d", len(expected), count)
	}
}

func TestIPIterator_MultipleContainers(t *testing.T) {
	it := ToIPIterator("1.1.1.1-1.1.1.2", "2.2.2.2-2.2.2.3")
	expected := []string{
		"1.1.1.1", "1.1.1.2", "2.2.2.2", "2.2.2.3",
	}
	var got []string
	for it.HasNext() {
		ip := it.Next()
		if ip == nil {
			t.Fatal("unexpected nil")
		}
		got = append(got, ip.String())
	}
	if len(got) != len(expected) {
		t.Fatalf("expected %d, got %d (%v)", len(expected), len(got), got)
	}
}

func TestIPIterator_SkipLocal(t *testing.T) {
	it := ToIPIterator("127.0.0.1-127.0.0.3", "8.8.8.8")
	it.SetSkipLocal(true)

	var got []string
	for it.HasNext() {
		ip := it.Next()
		if ip == nil {
			break
		}
		got = append(got, ip.String())
	}

	for _, s := range got {
		ip := net.ParseIP(s)
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() {
			t.Fatalf("skipLocal leaked local address: %s", s)
		}
	}
	if len(got) == 0 {
		t.Fatal("expected at least one non-local IP (8.8.8.8)")
	}
	if got[0] != "8.8.8.8" {
		t.Fatalf("expected first non-local IP 8.8.8.8, got %s", got[0])
	}
}

func TestIPIterator_EmptyRange(t *testing.T) {
	it := ToIPIterator("not-an-ip", "also-bad")
	if it.HasNext() {
		t.Fatal("expected HasNext false for all-invalid input")
	}
	if got := it.Next(); got != nil {
		t.Fatalf("expected nil, got %s", got)
	}
}

func TestIPIterator_ShufflePreservesAll(t *testing.T) {
	input := "10.0.0.1-10.0.0.20"
	it := ToIPIterator(input)
	it.Shuffle()

	seen := make(map[string]bool)
	for it.HasNext() {
		ip := it.Next()
		if ip == nil {
			t.Fatal("unexpected nil")
		}
		seen[ip.String()] = true
	}
	if len(seen) != 20 {
		t.Fatalf("expected 20 unique IPs after shuffle, got %d", len(seen))
	}
}

func TestIPIterator_NoDataPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for no data")
		}
	}()
	_ = ToIPIterator()
}

func TestIncIPInPlace(t *testing.T) {
	tests := []struct {
		name     string
		input    net.IP
		expected net.IP
	}{
		{"simple", net.IPv4(1, 2, 3, 4).To4(), net.IPv4(1, 2, 3, 5).To4()},
		{"carry_byte", net.IPv4(1, 2, 3, 255).To4(), net.IPv4(1, 2, 4, 0).To4()},
		{"carry_word", net.IPv4(1, 2, 255, 255).To4(), net.IPv4(1, 3, 0, 0).To4()},
		{"all_carry", net.IPv4(255, 255, 255, 255).To4(), net.IPv4(0, 0, 0, 0).To4()},
		{"ipv6", net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := make(net.IP, len(tt.input))
			copy(ip, tt.input)
			incIPInPlace(ip)
			if !ip.Equal(tt.expected) {
				t.Fatalf("expected %s, got %s", tt.expected, ip)
			}
		})
	}
}

func TestIncIP_Allocation(t *testing.T) {
	ip := net.IPv4(1, 2, 3, 4)
	allocs := testing.AllocsPerRun(100, func() {
		incIPInPlace(ip)
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocs for incIPInPlace, got %v", allocs)
	}
}

func TestIpLessOrEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b net.IP
		want bool
	}{
		{"equal", net.IPv4(1, 2, 3, 4), net.IPv4(1, 2, 3, 4), true},
		{"less", net.IPv4(1, 2, 3, 4), net.IPv4(1, 2, 3, 5), true},
		{"greater", net.IPv4(1, 2, 3, 5), net.IPv4(1, 2, 3, 4), false},
		{"first_octet", net.IPv4(1, 255, 255, 255), net.IPv4(2, 0, 0, 0), true},
		{"ipv4_vs_ipv6", net.IPv4(1, 1, 1, 1).To4(), net.ParseIP("::1"), true},
		{"ipv6_vs_ipv4", net.ParseIP("::1"), net.IPv4(1, 1, 1, 1).To4(), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipLessOrEqual(tt.a, tt.b); got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestCIDRStartEnd(t *testing.T) {
	start, end, err := cidrStartEnd("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if !start.Equal(net.IPv4(10, 0, 0, 0)) {
		t.Fatalf("expected start 10.0.0.0, got %s", start)
	}
	if !end.Equal(net.IPv4(10, 0, 0, 255)) {
		t.Fatalf("expected end 10.0.0.255, got %s", end)
	}
}

func TestCIDRStartEnd_Invalid(t *testing.T) {
	if _, _, err := cidrStartEnd("not-a-cidr"); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestIPIterator_HasNext_BeforeFirstNext(t *testing.T) {
	it := ToIPIterator("1.1.1.1-1.1.1.3")
	if !it.HasNext() {
		t.Fatal("HasNext must be true before first Next() call (currentIP is nil)")
	}
}

func TestIPIterator_AllContainersLocal_SkipLocal(t *testing.T) {
	it := ToIPIterator("127.0.0.1", "10.0.0.1")
	it.SetSkipLocal(true)

	var got []string
	for it.HasNext() {
		ip := it.Next()
		if ip == nil {
			break
		}
		got = append(got, ip.String())
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 non-local IPs, got %v", got)
	}
}

func TestIPIterator_SkipLocal_FollowedByNonLocal(t *testing.T) {
	it := ToIPIterator("10.0.0.1-10.0.0.3", "172.217.0.0-172.217.0.2")
	it.SetSkipLocal(true)

	var got []string
	for it.HasNext() {
		ip := it.Next()
		if ip == nil {
			break
		}
		got = append(got, ip.String())
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 non-local IPs (172.217.x is public), got %d: %v", len(got), got)
	}
	for _, s := range got {
		if s != "172.217.0.0" && s != "172.217.0.1" && s != "172.217.0.2" {
			t.Fatalf("unexpected non-local IP: %s", s)
		}
	}
}

func TestIPIterator_Next_AfterExhaustion(t *testing.T) {
	it := ToIPIterator("1.1.1.1")
	_ = it.Next()
	if it.HasNext() {
		t.Fatal("expected HasNext false after exhaustion")
	}
	if got := it.Next(); got != nil {
		t.Fatalf("expected nil after exhaustion, got %s", got)
	}
}

func TestIPIterator_IPv6Range(t *testing.T) {
	it := ToIPIterator("2001:db8::1-2001:db8::3")
	expected := []string{"2001:db8::1", "2001:db8::2", "2001:db8::3"}
	var got []string
	for it.HasNext() {
		ip := it.Next()
		if ip == nil {
			t.Fatal("unexpected nil")
		}
		got = append(got, ip.String())
	}
	if len(got) != len(expected) {
		t.Fatalf("expected %d IPv6 addresses, got %d (%v)", len(expected), len(got), got)
	}
}

func TestIPIterator_InvalidRangeEntry(t *testing.T) {
	it := ToIPIterator("bad-bad", "1.1.1.1")
	if !it.HasNext() {
		t.Fatal("expected HasNext true for valid entry after invalid one")
	}
	ip := it.Next()
	if !ip.Equal(net.IPv4(1, 1, 1, 1)) {
		t.Fatalf("expected 1.1.1.1, got %s", ip)
	}
}

func TestIPIterator_Next_Allocation(t *testing.T) {
	it := ToIPIterator("10.0.0.1-10.0.0.100")
	_ = it.Next()

	allocs := testing.AllocsPerRun(100, func() {
		_ = it.Next()
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocs for Next() after warmup, got %v", allocs)
	}
}

func TestIPIterator_NextAfterExhaustion_NoPanic(t *testing.T) {
	it := ToIPIterator("1.1.1.1")
	_ = it.Next()
	// Exhausted: currentIdx == len(containers)
	if it.HasNext() {
		t.Fatal("expected HasNext false")
	}
	// Calling Next() again must not panic
	for i := 0; i < 5; i++ {
		if got := it.Next(); got != nil {
			t.Fatalf("expected nil after exhaustion, got %s on call %d", got, i)
		}
	}
}

func TestIPIterator_NextAfterSkipLocalExhaustion_NoPanic(t *testing.T) {
	it := ToIPIterator("127.0.0.1", "10.0.0.1")
	it.SetSkipLocal(true)
	// All containers are local → skipLocalAddresses exhausts everything
	for i := 0; i < 10; i++ {
		ip := it.Next()
		if ip != nil {
			t.Fatalf("expected nil (all local), got %s on call %d", ip, i)
		}
	}
}

func TestIPIterator_ReversedRangeSkipped(t *testing.T) {
	it := ToIPIterator("10.0.0.5-10.0.0.1", "1.1.1.1")
	// The reversed range should be skipped; only 1.1.1.1 should be yielded
	ip := it.Next()
	if ip == nil {
		t.Fatal("expected non-nil IP")
	}
	if !ip.Equal(net.IPv4(1, 1, 1, 1)) {
		t.Fatalf("expected 1.1.1.1, got %s", ip)
	}
	if it.HasNext() {
		t.Fatal("expected no more IPs after 1.1.1.1")
	}
}
