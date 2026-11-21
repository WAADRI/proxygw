package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
	"strings"
	"testing"
)

// testV2TCP4Addr builds a 12-byte IPv4 address block.
func testV2TCP4Addr(src, dst string, srcPort, dstPort int) []byte {
	s := net.ParseIP(src).To4()
	d := net.ParseIP(dst).To4()
	if s == nil || d == nil {
		panic("test: invalid IPv4 address")
	}
	b := make([]byte, 0, v2AddrLenIPv4)
	b = append(b, s...)
	b = append(b, d...)
	b = append(b, byte(srcPort>>8), byte(srcPort), byte(dstPort>>8), byte(dstPort))
	return b
}

// testV2TCP6Addr builds a 36-byte IPv6 address block.
func testV2TCP6Addr(src, dst string, srcPort, dstPort int) []byte {
	s := net.ParseIP(src).To16()
	d := net.ParseIP(dst).To16()
	if s == nil || d == nil {
		panic("test: invalid IPv6 address")
	}
	b := make([]byte, 0, v2AddrLenIPv6)
	b = append(b, s...)
	b = append(b, d...)
	b = append(b, byte(srcPort>>8), byte(srcPort), byte(dstPort>>8), byte(dstPort))
	return b
}

// testV2TLV builds one TLV element.
func testV2TLV(typ byte, value []byte) []byte {
	b := make([]byte, 0, 3+len(value))
	b = append(b, typ, byte(len(value)>>8), byte(len(value)))
	return append(b, value...)
}

// testBuildV2 assembles a complete v2 header with an explicit verCmd/family
// byte and payload.
func testBuildV2(verCmd, famProto byte, payload []byte) []byte {
	buf := make([]byte, 0, v2FixedLen+len(payload))
	buf = append(buf, v2Signature...)
	buf = append(buf, verCmd, famProto, byte(len(payload)>>8), byte(len(payload)))
	return append(buf, payload...)
}

// testV2WithZeroCRC returns a v2 header whose payload is addr followed by the
// given TLVs plus a CRC32C TLV whose value is still zero.
func testV2WithZeroCRC(famProto byte, addr, tlvs []byte) (hdr []byte, crcValueOffset int) {
	payload := append([]byte(nil), addr...)
	payload = append(payload, tlvs...)
	payload = append(payload, testV2TLV(TLVTypeCRC32C, []byte{0, 0, 0, 0})...)
	hdr = testBuildV2(0x21, famProto, payload)
	return hdr, v2FixedLen + len(addr) + len(tlvs) + 3
}

// testComputeCRC32C computes the CRC32C of hdr with the checksum field zeroed.
func testComputeCRC32C(hdr []byte, crcValueOffset int) uint32 {
	cp := append([]byte(nil), hdr...)
	for i := crcValueOffset; i < crcValueOffset+4; i++ {
		cp[i] = 0
	}
	return crc32.Checksum(cp, crc32.MakeTable(crc32.Castagnoli))
}

// testSealCRC fills in the CRC32C value of a header produced by
// testV2WithZeroCRC.
func testSealCRC(hdr []byte, crcValueOffset int) []byte {
	binary.BigEndian.PutUint32(hdr[crcValueOffset:crcValueOffset+4], testComputeCRC32C(hdr, crcValueOffset))
	return hdr
}

func TestParseV2TCP4(t *testing.T) {
	addr := testV2TCP4Addr("198.51.100.7", "10.1.2.3", 54321, 443)
	buf := bytes.NewBuffer(append(testBuildV2(0x21, 0x11, addr), []byte("stream data")...))
	h, err := ParseV2(buf)
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	if h.Version != Version2 || h.Command != CommandProxy || h.Family != FamilyTCP4 {
		t.Errorf("header = %+v, want version 2 PROXY TCP4", h)
	}
	if got := h.SrcIP.String(); got != "198.51.100.7" {
		t.Errorf("SrcIP = %q", got)
	}
	if got := h.DstIP.String(); got != "10.1.2.3" {
		t.Errorf("DstIP = %q", got)
	}
	if h.SrcPort != 54321 || h.DstPort != 443 {
		t.Errorf("ports = %d/%d, want 54321/443", h.SrcPort, h.DstPort)
	}
	if h.TLVs != nil {
		t.Errorf("TLVs = %v, want nil", h.TLVs)
	}
	if rest := buf.String(); rest != "stream data" {
		t.Errorf("leftover = %q, want %q", rest, "stream data")
	}
}

func TestParseV2TCP6(t *testing.T) {
	addr := testV2TCP6Addr("2001:db8::7", "2001:db8::9", 1111, 443)
	h, err := ParseV2(bytes.NewReader(testBuildV2(0x21, 0x21, addr)))
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	if h.Family != FamilyTCP6 {
		t.Errorf("Family = %q, want TCP6", h.Family)
	}
	if got := h.SrcIP.String(); got != "2001:db8::7" {
		t.Errorf("SrcIP = %q", got)
	}
	if got := h.DstIP.String(); got != "2001:db8::9" {
		t.Errorf("DstIP = %q", got)
	}
	if h.SrcPort != 1111 || h.DstPort != 443 {
		t.Errorf("ports = %d/%d", h.SrcPort, h.DstPort)
	}
}

func TestParseV2Local(t *testing.T) {
	tests := []struct {
		name    string
		fam     byte
		payload []byte
	}{
		{"empty", 0x00, nil},
		// The receiver must consume exactly len bytes and ignore them, even
		// when the family claims an address block.
		{"garbage address block", 0x11, bytes.Repeat([]byte{0xAB}, 12)},
		{"arbitrary payload", 0x00, []byte("health-check-metadata")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := ParseV2(bytes.NewReader(testBuildV2(0x20, tc.fam, tc.payload)))
			if err != nil {
				t.Fatalf("ParseV2: %v", err)
			}
			if h.Command != CommandLocal {
				t.Errorf("Command = %q, want LOCAL", h.Command)
			}
			if h.Family != FamilyUNSPEC {
				t.Errorf("Family = %q, want UNSPEC for LOCAL", h.Family)
			}
			if h.IsProxy() {
				t.Error("IsProxy() = true, want false for LOCAL")
			}
			if h.SourceAddr() != nil || h.DestinationAddr() != nil {
				t.Error("LOCAL header must not report proxy endpoints")
			}
		})
	}
}

func TestParseV2Unspec(t *testing.T) {
	for _, tlvs := range [][]byte{
		nil,
		append(testV2TLV(0x01, []byte("h2")), testV2TLV(0x04, []byte("noop"))...),
	} {
		h, err := ParseV2(bytes.NewReader(testBuildV2(0x21, 0x00, tlvs)))
		if err != nil {
			t.Fatalf("ParseV2: %v", err)
		}
		if h.Command != CommandProxy {
			t.Errorf("Command = %q, want PROXY", h.Command)
		}
		if h.Family != FamilyUNSPEC {
			t.Errorf("Family = %q, want UNSPEC", h.Family)
		}
		if h.SrcIP != nil || h.DstIP != nil {
			t.Error("UNSPEC header must not expose addresses")
		}
	}
}

func TestParseV2UnsupportedFamiliesFallbackToUnspec(t *testing.T) {
	tests := []struct {
		name     string
		fam      byte
		addrLen  int
		wantTLVs bool
	}{
		{"udp4", 0x12, v2AddrLenIPv4, true},
		{"udp6", 0x22, v2AddrLenIPv6, true},
		{"unix stream", 0x31, v2AddrLenUnix, true},
		{"unix datagram", 0x32, v2AddrLenUnix, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := bytes.Repeat([]byte{0x11}, tc.addrLen)
			payload = append(payload, testV2TLV(0x01, []byte("h2"))...)
			h, err := ParseV2(bytes.NewReader(testBuildV2(0x21, tc.fam, payload)))
			if err != nil {
				t.Fatalf("ParseV2: %v", err)
			}
			if h.Family != FamilyUNSPEC {
				t.Errorf("Family = %q, want UNSPEC fallback", h.Family)
			}
			if h.SrcIP != nil || h.DstIP != nil {
				t.Error("fallback header must not expose addresses")
			}
			if got := string(h.TLVs[0x01]); got != "h2" {
				t.Errorf("TLV ALPN = %q, want h2", got)
			}
		})
	}
}

func TestParseV2TLVs(t *testing.T) {
	addr := testV2TCP4Addr("192.0.2.1", "192.0.2.2", 1, 2)
	tlvs := append(testV2TLV(0x01, []byte("h2")), testV2TLV(0x05, []byte("req-123"))...)
	tlvs = append(tlvs, testV2TLV(0x04, []byte("first"))...)
	tlvs = append(tlvs, testV2TLV(0x04, []byte("second"))...)
	h, err := ParseV2(bytes.NewReader(testBuildV2(0x21, 0x11, append(addr, tlvs...))))
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	if got := string(h.TLVs[0x01]); got != "h2" {
		t.Errorf("TLV 0x01 = %q, want h2", got)
	}
	if got := string(h.TLVs[0x05]); got != "req-123" {
		t.Errorf("TLV 0x05 = %q, want req-123", got)
	}
	if got := string(h.TLVs[0x04]); got != "second" {
		t.Errorf("duplicate TLV 0x04 = %q, want last value %q", got, "second")
	}
}

func TestParseV2CRC32CValid(t *testing.T) {
	addr := testV2TCP4Addr("203.0.113.5", "198.51.100.1", 4444, 443)
	hdr, off := testV2WithZeroCRC(0x11, addr, testV2TLV(0x01, []byte("h2")))
	want := testComputeCRC32C(hdr, off)
	testSealCRC(hdr, off)

	h, err := ParseV2(bytes.NewReader(hdr))
	if err != nil {
		t.Fatalf("ParseV2 with valid CRC32C: %v", err)
	}
	if got := binary.BigEndian.Uint32(h.TLVs[TLVTypeCRC32C]); got != want {
		t.Errorf("TLV CRC32C = %08x, want %08x", got, want)
	}
}

func TestParseV2CRC32CInvalid(t *testing.T) {
	addr := testV2TCP4Addr("203.0.113.5", "198.51.100.1", 4444, 443)
	hdr, off := testV2WithZeroCRC(0x11, addr, nil)
	testSealCRC(hdr, off)
	hdr[off+3] ^= 0xFF // corrupt the stored checksum

	if _, err := ParseV2(bytes.NewReader(hdr)); err == nil || !strings.Contains(err.Error(), "CRC32C") {
		t.Fatalf("ParseV2(corrupt CRC32C) error = %v, want CRC32C mismatch", err)
	}
}

func TestParseV2CRC32CCoversWholeHeader(t *testing.T) {
	addr := testV2TCP4Addr("203.0.113.5", "198.51.100.1", 4444, 443)
	hdr, off := testV2WithZeroCRC(0x11, addr, nil)
	testSealCRC(hdr, off)
	// Change a byte inside the address block: the stored checksum no longer
	// matches because the checksum covers the whole header, not just the TLV.
	hdr[v2FixedLen] ^= 0x01
	if _, err := ParseV2(bytes.NewReader(hdr)); err == nil || !strings.Contains(err.Error(), "CRC32C") {
		t.Fatalf("ParseV2(tampered address) error = %v, want CRC32C mismatch", err)
	}
}

func TestParseV2CRC32CWrongLength(t *testing.T) {
	addr := testV2TCP4Addr("203.0.113.5", "198.51.100.1", 4444, 443)
	payload := append(addr, testV2TLV(TLVTypeCRC32C, []byte{0, 0})...)
	if _, err := ParseV2(bytes.NewReader(testBuildV2(0x21, 0x11, payload))); err == nil {
		t.Fatal("ParseV2(short CRC32C TLV) = nil error, want error")
	}
}

func TestParseV2Errors(t *testing.T) {
	validAddr := testV2TCP4Addr("192.0.2.1", "192.0.2.2", 1, 2)
	sig := []byte(v2Signature)

	tests := []struct {
		name    string
		hdr     []byte
		wantErr error
	}{
		{
			name:    "bad signature",
			hdr:     append([]byte("\r\n\r\n\x00\r\nQUITX"), 0x21, 0x11, 0, 0),
			wantErr: ErrNoProxyHeader,
		},
		{name: "truncated signature", hdr: sig[:5]},
		{name: "truncated fixed header", hdr: append(append([]byte(nil), sig...), 0x21, 0x11)},
		{
			name: "bad version",
			hdr:  testBuildV2(0x11, 0x11, validAddr), // version 1
		},
		{
			name: "bad command",
			hdr:  testBuildV2(0x22, 0x11, validAddr), // version 2, command 2
		},
		{
			name: "bad family",
			hdr:  testBuildV2(0x21, 0x13, validAddr),
		},
		{
			name: "reserved family",
			hdr:  testBuildV2(0x21, 0x40, validAddr),
		},
		{
			name: "payload too large",
			hdr:  testBuildV2(0x21, 0x00, make([]byte, maxV2PayloadLen+1)),
		},
		{
			name: "truncated payload",
			hdr:  testBuildV2(0x21, 0x11, validAddr[:5]),
		},
		{
			name: "address block too short for family",
			hdr:  testBuildV2(0x21, 0x11, make([]byte, 4)),
		},
		{
			name: "truncated tlv header",
			hdr:  testBuildV2(0x21, 0x11, append(append([]byte(nil), validAddr...), 0x01, 0x00)),
		},
		{
			name: "tlv value exceeds payload",
			hdr:  testBuildV2(0x21, 0x11, append(append([]byte(nil), validAddr...), 0x01, 0x00, 0x10, 'a')),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseV2(bytes.NewReader(tc.hdr))
			if err == nil {
				t.Fatalf("ParseV2(%s) = nil error, want error", tc.name)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseV2PayloadTooLargeSentinel(t *testing.T) {
	// A hostile length field must be rejected from the fixed header alone,
	// without allocating or reading the announced payload.
	hdr := testBuildV2(0x21, 0x00, nil)
	hdr[14], hdr[15] = 0xFF, 0xFF // len = 65535
	_, err := ParseV2(bytes.NewReader(hdr))
	if !errors.Is(err, ErrHeaderTooLong) {
		t.Fatalf("ParseV2(65535 payload) error = %v, want ErrHeaderTooLong", err)
	}
}

func TestParseV2NoOverRead(t *testing.T) {
	addr := testV2TCP4Addr("192.0.2.1", "192.0.2.2", 1, 2)
	trailing := []byte("payload-bytes")
	buf := bytes.NewBuffer(append(testBuildV2(0x21, 0x11, addr), trailing...))
	if _, err := ParseV2(buf); err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	if got := buf.Bytes(); !bytes.Equal(got, trailing) {
		t.Errorf("leftover = %q, want %q", got, trailing)
	}
}
