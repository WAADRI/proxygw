package proxyproto

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestIsProxyHeaderPrefix(t *testing.T) {
	longV1 := []byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n")
	v2sig := []byte(v2Signature)
	tests := []struct {
		name string
		in   []byte
		want bool
	}{
		{"empty", nil, false},
		{"v1 P", []byte("P"), true},
		{"v1 prefix partial", []byte("PROX"), true},
		{"v1 magic", []byte("PROXY "), true},
		{"v1 full line", longV1, true},
		{"http POST", []byte("PO"), false},
		{"http GET", []byte("GET "), false},
		{"v1 wrong fourth byte", []byte("PROZ"), false},
		{"v2 first byte", []byte("\r"), true},
		{"v2 four bytes", []byte("\r\n\r\n"), true},
		{"v2 eleven bytes", v2sig[:11], true},
		{"v2 full signature", v2sig, true},
		{"v2 signature plus data", append(append([]byte(nil), v2sig...), 0x21), true},
		{"v2 wrong byte", []byte("\r\n\r\nX"), false},
		{"tls client hello", []byte{0x16, 0x03, 0x01, 0x00, 0x2f}, false},
		{"https request", []byte("GET / HTTP/1.1\r\n"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsProxyHeaderPrefix(tc.in); got != tc.want {
				t.Errorf("IsProxyHeaderPrefix(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseAutoDetect(t *testing.T) {
	t.Run("v1", func(t *testing.T) {
		buf := bytes.NewBufferString("PROXY TCP4 192.0.2.1 192.0.2.2 1111 443\r\nstream")
		h, err := Parse(buf)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if h.Version != Version1 || h.Family != FamilyTCP4 {
			t.Errorf("header = %+v, want v1 TCP4", h)
		}
		if got := buf.String(); got != "stream" {
			t.Errorf("leftover = %q, want stream", got)
		}
	})
	t.Run("v2", func(t *testing.T) {
		addr := testV2TCP4Addr("192.0.2.1", "192.0.2.2", 1111, 443)
		buf := bytes.NewBuffer(append(testBuildV2(0x21, 0x11, addr), []byte("stream")...))
		h, err := Parse(buf)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if h.Version != Version2 || h.Family != FamilyTCP4 {
			t.Errorf("header = %+v, want v2 TCP4", h)
		}
		if got := buf.String(); got != "stream" {
			t.Errorf("leftover = %q, want stream", got)
		}
	})
}

func TestParseNoHeader(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"tls", []byte{0x16, 0x03, 0x01, 0x00, 0x2f, 0x01}},
		{"http", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")},
		{"http post", []byte("POST / HTTP/1.1\r\n")},
		{"v1 magic mismatch", []byte("PROXYX ...")},
		{"v2 magic mismatch", []byte("\r\n\r\nX.........")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(bytes.NewReader(tc.in)); !errors.Is(err, ErrNoProxyHeader) {
				t.Errorf("Parse(%q) error = %v, want ErrNoProxyHeader", tc.in, err)
			}
		})
	}
}

func TestParseTruncatedOrInvalidCommittedHeader(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"v1 truncated", "PROXY TCP4 192.0.2.1"},
		{"v1 truncated before ports", "PROXY TCP4 192.0.2.1 192.0.2.2 1\r\n"},
		{"v2 truncated fixed", v2Signature + "\x21\x11"},
		{"v2 truncated payload", v2Signature + "\x21\x11\x00\x0c\x01\x02"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(tc.in)); err == nil {
				t.Fatalf("Parse(%q) = nil error, want error", tc.in)
			}
		})
	}
}

func TestParseEmptyInput(t *testing.T) {
	if _, err := Parse(strings.NewReader("")); !errors.Is(err, io.EOF) {
		t.Errorf("Parse(empty) error = %v, want io.EOF", err)
	}
	if _, err := ParseV2(strings.NewReader("")); !errors.Is(err, io.EOF) {
		t.Errorf("ParseV2(empty) error = %v, want io.EOF", err)
	}
}
