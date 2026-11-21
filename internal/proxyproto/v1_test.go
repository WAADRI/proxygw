package proxyproto

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

func TestParseV1TCP4(t *testing.T) {
	payload := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	buf := bytes.NewBufferString("PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n" + payload)
	h, err := ParseV1(buf)
	if err != nil {
		t.Fatalf("ParseV1: %v", err)
	}
	if h.Version != Version1 {
		t.Errorf("Version = %d, want 1", h.Version)
	}
	if h.Command != CommandProxy {
		t.Errorf("Command = %q, want PROXY", h.Command)
	}
	if h.Family != FamilyTCP4 {
		t.Errorf("Family = %q, want TCP4", h.Family)
	}
	if got := h.SrcIP.String(); got != "192.168.0.1" {
		t.Errorf("SrcIP = %q, want 192.168.0.1", got)
	}
	if got := h.DstIP.String(); got != "192.168.0.11" {
		t.Errorf("DstIP = %q, want 192.168.0.11", got)
	}
	if h.SrcPort != 56324 || h.DstPort != 443 {
		t.Errorf("ports = %d/%d, want 56324/443", h.SrcPort, h.DstPort)
	}
	if h.TLVs != nil {
		t.Errorf("TLVs = %v, want nil for v1", h.TLVs)
	}
	if !h.IsProxy() {
		t.Error("IsProxy() = false, want true")
	}
	if got, want := h.SourceAddr().String(), "192.168.0.1:56324"; got != want {
		t.Errorf("SourceAddr = %q, want %q", got, want)
	}
	if got, want := h.DestinationAddr().String(), "192.168.0.11:443"; got != want {
		t.Errorf("DestinationAddr = %q, want %q", got, want)
	}
	// No byte beyond the CRLF may be consumed.
	rest, err := io.ReadAll(buf)
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if string(rest) != payload {
		t.Errorf("payload after header = %q, want %q", rest, payload)
	}
}

func TestParseV1TCP6(t *testing.T) {
	line := "PROXY TCP6 2001:db8::1 2001:db8::2 1234 443\r\n"
	h, err := ParseV1(strings.NewReader(line))
	if err != nil {
		t.Fatalf("ParseV1: %v", err)
	}
	if h.Family != FamilyTCP6 {
		t.Errorf("Family = %q, want TCP6", h.Family)
	}
	if got := h.SrcIP.String(); got != "2001:db8::1" {
		t.Errorf("SrcIP = %q, want 2001:db8::1", got)
	}
	if got := h.DstIP.String(); got != "2001:db8::2" {
		t.Errorf("DstIP = %q, want 2001:db8::2", got)
	}
	if h.SrcPort != 1234 || h.DstPort != 443 {
		t.Errorf("ports = %d/%d, want 1234/443", h.SrcPort, h.DstPort)
	}
	if got, want := h.SourceAddr().String(), "[2001:db8::1]:1234"; got != want {
		t.Errorf("SourceAddr = %q, want %q", got, want)
	}
}

func TestParseV1Unknown(t *testing.T) {
	for _, line := range []string{
		"PROXY UNKNOWN\r\n",
		// Historical long form: the receiver must ignore whatever follows
		// UNKNOWN up to the CRLF.
		"PROXY UNKNOWN ffff::1 ffff::2 0 0\r\n",
	} {
		h, err := ParseV1(strings.NewReader(line + "payload"))
		if err != nil {
			t.Fatalf("ParseV1(%q): %v", line, err)
		}
		if h.Version != Version1 {
			t.Errorf("Version = %d, want 1", h.Version)
		}
		if h.Command != CommandLocal {
			t.Errorf("Command = %q, want LOCAL for UNKNOWN", h.Command)
		}
		if h.Family != FamilyUNSPEC {
			t.Errorf("Family = %q, want UNSPEC for UNKNOWN", h.Family)
		}
		if h.IsProxy() {
			t.Error("IsProxy() = true, want false for UNKNOWN")
		}
		if h.SourceAddr() != nil || h.DestinationAddr() != nil {
			t.Error("SourceAddr/DestinationAddr must be nil for UNKNOWN")
		}
	}
}

func TestParseV1MaxLineLength(t *testing.T) {
	// 104 bytes: the longest legal TCP6 line.
	src := "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
	line := "PROXY TCP6 " + src + " " + src + " 65535 65535\r\n"
	if len(line) != 104 {
		t.Fatalf("test line length = %d, want 104", len(line))
	}
	h, err := ParseV1(strings.NewReader(line))
	if err != nil {
		t.Fatalf("ParseV1(max line): %v", err)
	}
	if h.SrcPort != 65535 || h.DstPort != 65535 {
		t.Errorf("ports = %d/%d", h.SrcPort, h.DstPort)
	}

	// 107 bytes is the documented worst case (long UNKNOWN form with two full
	// IPv6 addresses and ports) and is accepted by the reader.
	long := "PROXY UNKNOWN " + src + " " + src + " 65535 65535\r\n"
	if len(long) != 107 {
		t.Fatalf("long UNKNOWN line length = %d, want 107", len(long))
	}
	if _, err := ParseV1(strings.NewReader(long)); err != nil {
		t.Fatalf("ParseV1(107 bytes): %v", err)
	}

	// Any line whose CRLF does not fit in 107 bytes must be rejected.
	tooLong := "PROXY UNKNOWN " + strings.Repeat("x", 100) + "\r\n"
	if _, err := ParseV1(strings.NewReader(tooLong)); !errors.Is(err, ErrHeaderTooLong) {
		t.Errorf("ParseV1(too long) error = %v, want ErrHeaderTooLong", err)
	}
}

func TestParseV1Errors(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"no magic", "GET / HTTP/1.1\r\n"},
		{"wrong magic", "PROXZ TCP4 1.2.3.4 5.6.7.8 1 2\r\n"},
		{"bare LF", "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n"},
		{"no terminator", "PROXY TCP4 1.2.3.4 5.6.7.8 1 2"},
		{"bad protocol", "PROXY UDP4 1.2.3.4 5.6.7.8 1 2\r\n"},
		{"too few fields", "PROXY TCP4 1.2.3.4 5.6.7.8 1\r\n"},
		{"too many fields", "PROXY TCP4 1.2.3.4 5.6.7.8 1 2 3\r\n"},
		{"double space", "PROXY TCP4  1.2.3.4 5.6.7.8 1 2\r\n"},
		{"bad src ip", "PROXY TCP4 1.2.3 5.6.7.8 1 2\r\n"},
		{"ipv6 in tcp4", "PROXY TCP4 2001:db8::1 5.6.7.8 1 2\r\n"},
		{"ipv4 in tcp6", "PROXY TCP6 1.2.3.4 ::1 1 2\r\n"},
		{"bad port", "PROXY TCP4 1.2.3.4 5.6.7.8 1 65536\r\n"},
		{"negative port", "PROXY TCP4 1.2.3.4 5.6.7.8 1 -2\r\n"},
		{"control byte", "PROXY TCP4 1.2.3.4 5.6.7.8 1 2\rX\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseV1(strings.NewReader(tc.in)); err == nil {
				t.Fatalf("ParseV1(%q) = nil error, want error", tc.in)
			}
		})
	}
}

func TestParseV1NilReader(t *testing.T) {
	if _, err := ParseV1(nil); err == nil {
		t.Fatal("ParseV1(nil) = nil error, want error")
	}
	if _, err := ParseV2(nil); err == nil {
		t.Fatal("ParseV2(nil) = nil error, want error")
	}
	if _, err := Parse(nil); err == nil {
		t.Fatal("Parse(nil) = nil error, want error")
	}
}

func TestV1IPNormalizedToFourBytes(t *testing.T) {
	h, err := ParseV1(strings.NewReader("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"))
	if err != nil {
		t.Fatalf("ParseV1: %v", err)
	}
	if len(h.SrcIP) != net.IPv4len {
		t.Errorf("len(SrcIP) = %d, want %d", len(h.SrcIP), net.IPv4len)
	}
	if len(h.DstIP) != net.IPv4len {
		t.Errorf("len(DstIP) = %d, want %d", len(h.DstIP), net.IPv4len)
	}
}

func TestAddr(t *testing.T) {
	var nilAddr *Addr
	if got := nilAddr.String(); got != "" {
		t.Errorf("nil Addr.String() = %q, want empty", got)
	}
	a := &Addr{IP: net.ParseIP("203.0.113.9").To4(), Port: 8080}
	if got := a.Network(); got != "tcp" {
		t.Errorf("Network() = %q, want tcp", got)
	}
	if got := a.String(); got != "203.0.113.9:8080" {
		t.Errorf("String() = %q, want 203.0.113.9:8080", got)
	}
}
