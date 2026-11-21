package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
)

// oneByteWriter writes at most one byte per Write call to exercise short-write
// handling.
type oneByteWriter struct {
	buf bytes.Buffer
}

func (w *oneByteWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.buf.WriteByte(p[0])
	return 1, nil
}

// failingWriter always fails after a fixed number of bytes.
type failingWriter struct {
	remaining int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, errors.New("write failed")
	}
	if len(p) > w.remaining {
		n := w.remaining
		w.remaining = 0
		return n, errors.New("write failed")
	}
	w.remaining -= len(p)
	return len(p), nil
}

func TestWriteV2RoundTripTCP4(t *testing.T) {
	in := Header{
		Version: Version2,
		Command: CommandProxy,
		Family:  FamilyTCP4,
		SrcIP:   []byte{203, 0, 113, 7},
		DstIP:   []byte{10, 0, 0, 1},
		SrcPort: 40000,
		DstPort: 443,
	}
	var buf bytes.Buffer
	if err := WriteV2(&buf, in); err != nil {
		t.Fatalf("WriteV2: %v", err)
	}
	out, err := ParseV2(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ParseV2 round trip: %v", err)
	}
	if out.Family != FamilyTCP4 || out.Command != CommandProxy {
		t.Errorf("round trip header = %+v", out)
	}
	if got := out.SrcIP.String(); got != "203.0.113.7" {
		t.Errorf("SrcIP = %q", got)
	}
	if got := out.DstIP.String(); got != "10.0.0.1" {
		t.Errorf("DstIP = %q", got)
	}
	if out.SrcPort != 40000 || out.DstPort != 443 {
		t.Errorf("ports = %d/%d", out.SrcPort, out.DstPort)
	}
}

func TestWriteV2RoundTripTCP6(t *testing.T) {
	in := Header{
		Version: Version2,
		Command: CommandProxy,
		Family:  FamilyTCP6,
		SrcIP:   mustIP(t, "2001:db8::1"),
		DstIP:   mustIP(t, "2001:db8::2"),
		SrcPort: 1234,
		DstPort: 443,
	}
	var buf bytes.Buffer
	if err := WriteV2(&buf, in); err != nil {
		t.Fatalf("WriteV2: %v", err)
	}
	out, err := ParseV2(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ParseV2 round trip: %v", err)
	}
	if out.Family != FamilyTCP6 {
		t.Errorf("Family = %q, want TCP6", out.Family)
	}
	if got := out.SrcIP.String(); got != "2001:db8::1" {
		t.Errorf("SrcIP = %q", got)
	}
}

func TestWriteV2RoundTripUNSPEC(t *testing.T) {
	in := Header{Version: Version2, Command: CommandProxy, Family: FamilyUNSPEC}
	var buf bytes.Buffer
	if err := WriteV2(&buf, in); err != nil {
		t.Fatalf("WriteV2: %v", err)
	}
	out, err := ParseV2(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ParseV2 round trip: %v", err)
	}
	if out.Command != CommandProxy || out.Family != FamilyUNSPEC {
		t.Errorf("round trip header = %+v", out)
	}
}

func TestWriteV2RoundTripLocal(t *testing.T) {
	in := Header{Version: Version2, Command: CommandLocal}
	var buf bytes.Buffer
	if err := WriteV2(&buf, in); err != nil {
		t.Fatalf("WriteV2: %v", err)
	}
	out, err := ParseV2(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ParseV2 round trip: %v", err)
	}
	if out.Command != CommandLocal || out.Family != FamilyUNSPEC {
		t.Errorf("round trip header = %+v", out)
	}
}

func TestWriteV2InfersFamily(t *testing.T) {
	in := Header{
		Version: Version2,
		SrcIP:   mustIP(t, "192.0.2.10"),
		DstIP:   mustIP(t, "192.0.2.20"),
		SrcPort: 1,
		DstPort: 2,
	}
	var buf bytes.Buffer
	if err := WriteV2(&buf, in); err != nil {
		t.Fatalf("WriteV2: %v", err)
	}
	out, err := ParseV2(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	if out.Family != FamilyTCP4 || out.Command != CommandProxy {
		t.Errorf("header = %+v, want inferred TCP4 PROXY", out)
	}
}

func TestWriteV2TLVsAndCRC32C(t *testing.T) {
	in := Header{
		Version: Version2,
		Command: CommandProxy,
		Family:  FamilyTCP4,
		SrcIP:   mustIP(t, "203.0.113.5"),
		DstIP:   mustIP(t, "198.51.100.1"),
		SrcPort: 4444,
		DstPort: 443,
		TLVs: map[byte][]byte{
			TLVTypeCRC32C: {}, // value is computed by WriteV2
			0x01:          []byte("h2"),
			0x05:          []byte("unique-id"),
		},
	}
	var buf bytes.Buffer
	if err := WriteV2(&buf, in); err != nil {
		t.Fatalf("WriteV2: %v", err)
	}
	raw := buf.Bytes()

	// Independently verify the checksum: whole header, checksum field zeroed,
	// stored in network byte order.
	crcOff := findTLVValueOffset(t, raw, v2AddrLenIPv4, TLVTypeCRC32C)
	want := testComputeCRC32C(raw, crcOff)
	if got := binary.BigEndian.Uint32(raw[crcOff : crcOff+4]); got != want {
		t.Errorf("stored CRC32C = %08x, want %08x", got, want)
	}
	if got := binary.BigEndian.Uint32(raw[crcOff : crcOff+4]); got == 0 {
		t.Error("CRC32C value must not stay zero")
	}

	out, err := ParseV2(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseV2 of generated header: %v", err)
	}
	if got := string(out.TLVs[0x01]); got != "h2" {
		t.Errorf("TLV ALPN = %q, want h2", got)
	}
	if got := string(out.TLVs[0x05]); got != "unique-id" {
		t.Errorf("TLV unique id = %q", got)
	}
	if len(out.TLVs[TLVTypeCRC32C]) != 4 {
		t.Errorf("CRC32C TLV length = %d, want 4", len(out.TLVs[TLVTypeCRC32C]))
	}
}

// findTLVValueOffset walks the TLV vector of a v2 header and returns the byte
// offset of the value of the first TLV with the given type.
func findTLVValueOffset(t *testing.T, raw []byte, addrLen int, wantType byte) int {
	t.Helper()
	payload := raw[v2FixedLen:]
	for i := addrLen; i < len(payload); {
		if len(payload)-i < 3 {
			t.Fatalf("truncated TLV at payload offset %d", i)
		}
		typ := payload[i]
		l := int(binary.BigEndian.Uint16(payload[i+1 : i+3]))
		if typ == wantType {
			return v2FixedLen + i + 3
		}
		i += 3 + l
	}
	t.Fatalf("TLV type 0x%02x not found", wantType)
	return 0
}

func TestWriteV2ShortWrites(t *testing.T) {
	in := Header{
		Version: Version2,
		Command: CommandProxy,
		Family:  FamilyTCP4,
		SrcIP:   mustIP(t, "192.0.2.1"),
		DstIP:   mustIP(t, "192.0.2.2"),
		SrcPort: 1,
		DstPort: 2,
	}
	w := &oneByteWriter{}
	if err := WriteV2(w, in); err != nil {
		t.Fatalf("WriteV2(short writer): %v", err)
	}
	if _, err := ParseV2(bytes.NewReader(w.buf.Bytes())); err != nil {
		t.Fatalf("ParseV2 of short-written header: %v", err)
	}
}

func TestWriteV2Errors(t *testing.T) {
	valid := Header{
		Version: Version2,
		Command: CommandProxy,
		Family:  FamilyTCP4,
		SrcIP:   mustIP(t, "192.0.2.1"),
		DstIP:   mustIP(t, "192.0.2.2"),
		SrcPort: 1,
		DstPort: 2,
	}
	hugeTLV := make([]byte, 0x10000)
	tests := []struct {
		name string
		h    Header
	}{
		{"bad command", Header{Command: "FORWARD"}},
		{"bad family", Header{Command: CommandProxy, Family: "TCP5", SrcIP: mustIP(t, "192.0.2.1"), DstIP: mustIP(t, "192.0.2.2")}},
		{"tcp4 without addresses", Header{Command: CommandProxy, Family: FamilyTCP4}},
		{"tcp4 with ipv6", Header{Command: CommandProxy, Family: FamilyTCP4, SrcIP: mustIP(t, "2001:db8::1"), DstIP: mustIP(t, "192.0.2.2")}},
		{"tcp6 with ipv4", Header{Command: CommandProxy, Family: FamilyTCP6, SrcIP: mustIP(t, "192.0.2.1"), DstIP: mustIP(t, "192.0.2.2")}},
		{"port out of range", Header{Command: CommandProxy, Family: FamilyTCP4, SrcIP: mustIP(t, "192.0.2.1"), DstIP: mustIP(t, "192.0.2.2"), SrcPort: 70000, DstPort: 2}},
		{"tlv too long", Header{Command: CommandProxy, Family: FamilyTCP4, SrcIP: mustIP(t, "192.0.2.1"), DstIP: mustIP(t, "192.0.2.2"), SrcPort: 1, DstPort: 2, TLVs: map[byte][]byte{0x01: hugeTLV}}},
		{"payload too long", Header{Command: CommandProxy, Family: FamilyTCP4, SrcIP: mustIP(t, "192.0.2.1"), DstIP: mustIP(t, "192.0.2.2"), SrcPort: 1, DstPort: 2, TLVs: map[byte][]byte{0x01: make([]byte, maxV2PayloadLen)}}},
	}
	var buf bytes.Buffer
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf.Reset()
			if err := WriteV2(&buf, tc.h); err == nil {
				t.Fatalf("WriteV2(%s) = nil error, want error", tc.name)
			}
		})
	}
	// Sanity: the reference header must still be writable.
	if err := WriteV2(&buf, valid); err != nil {
		t.Fatalf("WriteV2(valid): %v", err)
	}
}

func TestWriteV2NilWriterAndWriteFailure(t *testing.T) {
	h := Header{Command: CommandLocal}
	if err := WriteV2(nil, h); err == nil {
		t.Fatal("WriteV2(nil writer) = nil error, want error")
	}
	if err := WriteV2(&failingWriter{remaining: 3}, h); err == nil {
		t.Fatal("WriteV2(failing writer) = nil error, want error")
	}
}

func TestWriteV2CommandDefaultsToProxy(t *testing.T) {
	in := Header{
		Version: Version2,
		Family:  FamilyTCP4,
		SrcIP:   mustIP(t, "192.0.2.1"),
		DstIP:   mustIP(t, "192.0.2.2"),
		SrcPort: 1,
		DstPort: 2,
	}
	var buf bytes.Buffer
	if err := WriteV2(&buf, in); err != nil {
		t.Fatalf("WriteV2: %v", err)
	}
	out, err := ParseV2(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ParseV2: %v", err)
	}
	if out.Command != CommandProxy {
		t.Errorf("Command = %q, want PROXY", out.Command)
	}
}

func TestWriteV2RejectsOversizedTLVName(t *testing.T) {
	// A TLV value longer than the 16-bit length field cannot be encoded.
	h := Header{
		Command: CommandProxy,
		Family:  FamilyTCP4,
		SrcIP:   mustIP(t, "192.0.2.1"),
		DstIP:   mustIP(t, "192.0.2.2"),
		TLVs:    map[byte][]byte{0xE0: make([]byte, 0x10000)},
	}
	var buf bytes.Buffer
	err := WriteV2(&buf, h)
	if err == nil || !strings.Contains(err.Error(), "TLV type 0xe0") {
		t.Fatalf("WriteV2(oversized TLV) error = %v", err)
	}
}

func mustIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("invalid test IP %q", s)
	}
	return ip
}
