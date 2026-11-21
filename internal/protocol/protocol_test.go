package protocol

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello world")
	if err := WriteFrame(&buf, FrameData, 7, payload); err != nil {
		t.Fatal(err)
	}
	f, err := ReadFrame(&buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != FrameData || f.StreamID != 7 || string(f.Payload) != string(payload) {
		t.Fatalf("unexpected frame: %+v", f)
	}
}

func TestFrameEmptyPayloadAndHeaderOnly(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, FrameFin, 42, nil); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != FrameHeaderLen {
		t.Fatalf("encoded length = %d, want %d", buf.Len(), FrameHeaderLen)
	}
	typ, sid, length, err := ReadFrameHeader(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if typ != FrameFin || sid != 42 || length != 0 {
		t.Fatalf("header = %v %d %d", typ, sid, length)
	}
}

func TestFrameOversizeRejected(t *testing.T) {
	// Announce a 100 KiB payload with a tiny limit; must fail before reading.
	var hdr [FrameHeaderLen]byte
	hdr[0] = byte(FrameData)
	binary.BigEndian.PutUint32(hdr[1:5], 1)
	binary.BigEndian.PutUint32(hdr[5:9], 100*1024)
	if _, err := ReadFrame(bytes.NewReader(hdr[:]), 64*1024); err == nil {
		t.Fatal("expected oversize error")
	}
	if _, err := AppendFrame(nil, FrameData, 1, make([]byte, MaxFramePayload+1)); err == nil {
		t.Fatal("expected encode oversize error")
	}
}

func TestFrameTruncated(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, FrameData, 1, []byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	if _, err := ReadFrame(bytes.NewReader(data[:len(data)-2]), 0); err == nil {
		t.Fatal("expected truncated frame error")
	}
	if _, err := ReadFrame(bytes.NewReader(data[:4]), 0); err == nil {
		t.Fatal("expected truncated header error")
	}
}

func TestOpenRoundTripIPAndDomain(t *testing.T) {
	var trace [TraceIDLen]byte
	for i := range trace {
		trace[i] = byte(i)
	}
	cases := []struct {
		host string
		port uint16
	}{
		{"example.com", 443},
		{"1.2.3.4", 80},
		{"2001:db8::1", 8443},
	}
	for _, tc := range cases {
		req := TargetToOpen(tc.host, int(tc.port), trace, true)
		enc, err := req.Encode()
		if err != nil {
			t.Fatalf("%s encode: %v", tc.host, err)
		}
		dec, err := DecodeOpen(enc)
		if err != nil {
			t.Fatalf("%s decode: %v", tc.host, err)
		}
		if dec.Host != tc.host || dec.Port != tc.port || dec.TraceID != trace || !dec.Compressed() {
			t.Fatalf("%s round trip mismatch: %+v", tc.host, dec)
		}
	}
}

func TestOpenRejectsBadInput(t *testing.T) {
	good, err := TargetToOpen("example.com", 443, [TraceIDLen]byte{}, false).Encode()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":         {},
		"short":         {1, 1, 3},
		"bad version":   append([]byte{9}, good[1:]...),
		"bad proto":     append([]byte{good[0], 9}, good[2:]...),
		"bad addr type": append(append([]byte{}, good[:2]...), append([]byte{9}, good[3:]...)...),
		"trailing":      append(append([]byte{}, good...), 0x00),
	}
	for name, in := range cases {
		if _, err := DecodeOpen(in); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
	// Port zero is rejected.
	portZero := append([]byte{}, good...)
	// Domain length byte is at offset 3, host starts at 4; port follows host.
	pos := 4 + int(good[3])
	portZero[pos], portZero[pos+1] = 0, 0
	if _, err := DecodeOpen(portZero); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("port zero: got %v", err)
	}
	// Reserved flag bits are rejected.
	req := TargetToOpen("a.com", 80, [TraceIDLen]byte{}, false)
	enc, _ := req.Encode()
	enc[len(enc)-1] = 0x80
	if _, err := DecodeOpen(enc); err == nil {
		t.Fatal("reserved flags must be rejected")
	}
}

func TestStreamIDPacking(t *testing.T) {
	id := MakeStreamID(0xABC, 0x12345)
	epoch, seq := SplitStreamID(id)
	if epoch != 0xABC || seq != 0x12345 {
		t.Fatalf("split = %x %x", epoch, seq)
	}
	if id == MakeStreamID(0xABD, 0x12345) {
		t.Fatal("different epochs must produce different ids")
	}
}

func TestOpenResultRoundTrip(t *testing.T) {
	enc := EncodeOpenResult(byte(CodeConnRefused), "dial tcp: connection refused")
	code, msg, err := DecodeOpenResult(enc)
	if err != nil {
		t.Fatal(err)
	}
	if OpenErrorCode(code) != CodeConnRefused || msg != "dial tcp: connection refused" {
		t.Fatalf("decoded %d %q", code, msg)
	}
	code, msg, err = DecodeOpenResult(EncodeOpenResult(0, ""))
	if err != nil || code != 0 || msg != "" {
		t.Fatalf("ok result: %d %q %v", code, msg, err)
	}
	if _, _, err := DecodeOpenResult(nil); err == nil {
		t.Fatal("empty result must fail")
	}
}

func TestErrorCodeMappings(t *testing.T) {
	cases := []struct {
		code  OpenErrorCode
		http  int
		socks byte
	}{
		{CodeDNS, 502, 0x04},
		{CodeConnRefused, 502, 0x05},
		{CodeTimeout, 504, 0x06},
		{CodePolicy, 403, 0x02},
		{CodeOverloaded, 503, 0x01},
		{CodeProtoUnsupported, 405, 0x07},
		{CodeInternal, 502, 0x01},
	}
	for _, tc := range cases {
		if got := tc.code.HTTPStatus(); got != tc.http {
			t.Fatalf("%v http = %d want %d", tc.code, got, tc.http)
		}
		if got := tc.code.SOCKS5Reply(); got != tc.socks {
			t.Fatalf("%v socks = 0x%02x want 0x%02x", tc.code, got, tc.socks)
		}
		if !tc.code.Valid() {
			t.Fatalf("%v should be valid", tc.code)
		}
	}
	if OpenErrorCode(200).Valid() {
		t.Fatal("undefined code must be invalid")
	}
	if !FrameOpen.IsControl() == false {
		t.Fatal("OPEN must not be a control frame")
	}
	if !FrameHello.IsControl() || !FramePing.IsControl() {
		t.Fatal("HELLO/PING must be control frames")
	}
}

func TestWindowEncoding(t *testing.T) {
	enc := EncodeWindow(256 * 1024)
	got, err := DecodeWindow(enc)
	if err != nil || got != 256*1024 {
		t.Fatalf("window = %d, %v", got, err)
	}
	if _, err := DecodeWindow([]byte{1, 2}); err == nil {
		t.Fatal("bad window payload must fail")
	}
}

func TestControlMessageRoundTrip(t *testing.T) {
	h := Hello{Ver: Version1, Token: "x", ClientID: "node-1", Transport: "quic", Capabilities: []string{CapZstd}}
	b, err := Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	var back Hello
	if err := Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.ClientID != h.ClientID || back.Transport != "quic" || len(back.Capabilities) != 1 {
		t.Fatalf("round trip = %+v", back)
	}
	ack := HelloAck{OK: true, Epoch: 7, Settings: HelloSettings{MaxStreams: 1000}}
	b, err = Marshal(ack)
	if err != nil {
		t.Fatal(err)
	}
	var ackBack HelloAck
	if err := Unmarshal(b, &ackBack); err != nil {
		t.Fatal(err)
	}
	if !ackBack.OK || ackBack.Epoch != 7 || ackBack.Settings.MaxStreams != 1000 {
		t.Fatalf("ack round trip = %+v", ackBack)
	}
}
