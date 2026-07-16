package rawsocket

import (
	"testing"
	"time"
)

func TestValidPort(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		min, max int
	}{
		{"zero", 0, 1, 65535},
		{"negative", -5, 1, 65535},
		{"normal", 443, 443, 443},
		{"overflow", 70000, 65535, 65535},
		{"max", 65535, 65535, 65535},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validPort(tt.input)
			if got < tt.min || got > tt.max {
				t.Fatalf("validPort(%d) = %d, want in [%d, %d]", tt.input, got, tt.min, tt.max)
			}
		})
	}
}

func TestValidPort_RandomInRange(t *testing.T) {
	for i := 0; i < 100; i++ {
		got := validPort(0)
		if got < 1 || got > 65535 {
			t.Fatalf("random port %d out of range", got)
		}
	}
}

func TestChecksum16(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected uint16
	}{
		{"empty", []byte{}, 0xffff},
		{"single_byte", []byte{0x01}, 0xfeff},
		{"two_bytes", []byte{0x00, 0x01}, 0xfffe},
		{"known_value", []byte{0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01}, 0x79d1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checksum16(tt.input)
			if got != tt.expected {
				t.Fatalf("checksum16(%v) = 0x%04x, want 0x%04x", tt.input, got, tt.expected)
			}
		})
	}
}

func TestChecksum16_Allocation(t *testing.T) {
	input := make([]byte, 256)
	allocs := testing.AllocsPerRun(100, func() {
		_ = checksum16(input)
	})
	if allocs != 0 {
		t.Fatalf("expected 0 allocs for checksum16, got %v", allocs)
	}
}

func TestEncodeIGMPMaxResp(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Duration
		expected byte
	}{
		{"zero", 0, 0},
		{"negative", -1 * time.Second, 0},
		{"100ms", 100 * time.Millisecond, 1},
		{"1s", 1 * time.Second, 10},
		{"10s", 10 * time.Second, 100},
		{"overflow", 30 * time.Second, 255},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encodeIGMPMaxResp(tt.input); got != tt.expected {
				t.Fatalf("encodeIGMPMaxResp(%v) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsIPv4(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{"empty", []byte{}, false},
		{"ipv4", []byte{0x45, 0x00}, true},
		{"ipv6", []byte{0x60, 0x00}, false},
		{"single_ipv4", []byte{0x40}, true},
		{"full_ipv4", []byte{0x4f, 0xff}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isIPv4(tt.input); got != tt.expected {
				t.Fatalf("isIPv4(%v) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestHasEthernet(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{"empty", []byte{}, false},
		{"too_short", make([]byte, 10), false},
		{"ethernet", append(make([]byte, 12), 0x08, 0x00, 0x00), true},
		{"not_ethernet", append(make([]byte, 12), 0x86, 0xdd, 0x00), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasEthernet(tt.input); got != tt.expected {
				t.Fatalf("hasEthernet(%v) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}
