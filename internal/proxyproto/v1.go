package proxyproto

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const (
	// maxV1LineLen is the longest legal v1 line, including the trailing CRLF
	// (worst case: "PROXY UNKNOWN" with two full IPv6 addresses and ports).
	maxV1LineLen = 107
	// v1Prefix is the only legal start of a v1 header.
	v1Prefix = "PROXY "
)

// ParseV1 parses a version 1 (human readable) PROXY protocol header from r.
// Exactly one header line is consumed, including its CRLF; no byte after the
// CRLF is read, so a following payload stays in r.
//
// The line must be at most 107 bytes long including CRLF. A bare LF terminator
// is rejected, and so is anything that does not exactly match the grammar.
// A "PROXY UNKNOWN" line is mapped to Command=CommandLocal and
// Family=FamilyUNSPEC: the real socket endpoints must be used, as required by
// the specification.
func ParseV1(r io.Reader) (Header, error) {
	if r == nil {
		return Header{}, fmt.Errorf("proxyproto: v1: nil reader")
	}
	return parseV1Line(r, nil)
}

// parseV1Line reads the remainder of a v1 header line from r. prefix holds the
// bytes that were already consumed while sniffing the "PROXY " signature; they
// are prepended to the line but are not read from r again.
func parseV1Line(r io.Reader, prefix []byte) (Header, error) {
	line := make([]byte, len(prefix), maxV1LineLen)
	copy(line, prefix)
	for len(line) < maxV1LineLen {
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return Header{}, fmt.Errorf("proxyproto: v1: read header line: %w", err)
		}
		line = append(line, b[0])
		if b[0] == '\n' {
			return decodeV1Line(line)
		}
	}
	return Header{}, fmt.Errorf("%w: v1 line longer than %d bytes", ErrHeaderTooLong, maxV1LineLen)
}

// decodeV1Line validates and decodes one complete v1 line including its CRLF.
func decodeV1Line(line []byte) (Header, error) {
	if len(line) < 2 || line[len(line)-1] != '\n' {
		return Header{}, fmt.Errorf("proxyproto: v1: header line is not terminated by CRLF")
	}
	if line[len(line)-2] != '\r' {
		return Header{}, fmt.Errorf("proxyproto: v1: header line is terminated by a bare LF")
	}
	body := line[:len(line)-2]
	// The grammar is US-ASCII and every field is printable; this also rejects
	// embedded CR/LF/NUL bytes before the terminator.
	for i, b := range body {
		if b < 0x20 || b > 0x7e {
			return Header{}, fmt.Errorf("proxyproto: v1: invalid byte 0x%02x at line offset %d", b, i)
		}
	}
	fields := strings.Split(string(body), " ")
	if len(fields) < 2 || fields[0] != "PROXY" {
		return Header{}, fmt.Errorf("%w: v1: line does not start with %q", ErrNoProxyHeader, v1Prefix)
	}
	h := Header{Version: Version1}
	switch fields[1] {
	case "UNKNOWN":
		// The specification says the receiver must ignore anything presented
		// after UNKNOWN up to the CRLF. Accept both the short form and the
		// historical long form with dummy addresses.
		h.Command = CommandLocal
		h.Family = FamilyUNSPEC
		return h, nil
	case "TCP4", "TCP6":
		if len(fields) != 6 {
			return Header{}, fmt.Errorf("proxyproto: v1: %s line must have 6 space separated fields, got %d", fields[1], len(fields))
		}
		srcIP, err := parseV1IP(fields[2], fields[1])
		if err != nil {
			return Header{}, err
		}
		dstIP, err := parseV1IP(fields[3], fields[1])
		if err != nil {
			return Header{}, err
		}
		srcPort, err := parseV1Port(fields[4])
		if err != nil {
			return Header{}, err
		}
		dstPort, err := parseV1Port(fields[5])
		if err != nil {
			return Header{}, err
		}
		h.Command = CommandProxy
		h.Family = fields[1]
		h.SrcIP = srcIP
		h.DstIP = dstIP
		h.SrcPort = srcPort
		h.DstPort = dstPort
		return h, nil
	default:
		return Header{}, fmt.Errorf("proxyproto: v1: unsupported transport protocol %q (want TCP4, TCP6 or UNKNOWN)", fields[1])
	}
}

// parseV1IP parses one v1 address and enforces that its representation matches
// the announced family: TCP4 rejects IPv6 and TCP6 rejects IPv4 (including
// IPv4-mapped IPv6 literals).
func parseV1IP(s, family string) (net.IP, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("proxyproto: v1: invalid %s address %q", family, s)
	}
	if family == "TCP4" {
		v4 := ip.To4()
		if v4 == nil {
			return nil, fmt.Errorf("proxyproto: v1: address %q is not an IPv4 address (family TCP4)", s)
		}
		return v4, nil
	}
	if ip.To4() != nil {
		return nil, fmt.Errorf("proxyproto: v1: address %q is not an IPv6 address (family TCP6)", s)
	}
	v6 := ip.To16()
	if v6 == nil {
		return nil, fmt.Errorf("proxyproto: v1: invalid IPv6 address %q", s)
	}
	return v6, nil
}

// parseV1Port parses a decimal port in the range [0,65535].
func parseV1Port(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("proxyproto: v1: empty port")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("proxyproto: v1: invalid port %q: not a decimal number", s)
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("proxyproto: v1: port %q out of range [0,65535]", s)
	}
	return n, nil
}
