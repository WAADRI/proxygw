package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
)

// OPEN protocol (identical on both transports):
//
//	ver(1) | proto(1) | addr_type(1) | addr(v) | port(2) | trace_id(16) | flags(1)

// OPEN header constants.
const (
	OpenVersion1 = 1

	ProtoTCP = 1

	AddrIPv4   = 1
	AddrIPv6   = 2
	AddrDomain = 3

	FlagCompressed = 0x01
	// flagsMask is the set of flags defined by this protocol version; any other
	// bit is a protocol error.
	flagsMask = FlagCompressed

	openFixedLen = 1 + 1 + 1 + 2 + TraceIDLen + 1
)

// OpenRequest is the parsed OPEN header.
type OpenRequest struct {
	Version uint8
	Proto   uint8
	Host    string // IP literal or hostname
	Port    uint16
	TraceID [TraceIDLen]byte
	Flags   uint8
}

// Compressed reports whether the compressed flag is set.
func (r OpenRequest) Compressed() bool { return r.Flags&FlagCompressed != 0 }

// Target returns the canonical host:port string.
func (r OpenRequest) Target() string {
	return net.JoinHostPort(r.Host, strconv.Itoa(int(r.Port)))
}

// Encode serializes the OPEN header.
func (r OpenRequest) Encode() ([]byte, error) {
	if r.Version != OpenVersion1 {
		return nil, fmt.Errorf("protocol: unsupported OPEN version %d", r.Version)
	}
	if r.Proto != ProtoTCP {
		return nil, fmt.Errorf("protocol: unsupported OPEN proto %d", r.Proto)
	}
	if r.Port == 0 {
		return nil, errors.New("protocol: OPEN port must be non-zero")
	}
	if r.Flags&^flagsMask != 0 {
		return nil, fmt.Errorf("protocol: unsupported OPEN flags 0x%02x", r.Flags)
	}
	out := make([]byte, 0, openFixedLen+MaxDomainLen)
	out = append(out, r.Version, r.Proto)
	if ip := net.ParseIP(r.Host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, AddrIPv4)
			out = append(out, v4...)
		} else {
			out = append(out, AddrIPv6)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(r.Host) == 0 || len(r.Host) > MaxDomainLen {
			return nil, fmt.Errorf("protocol: OPEN hostname length %d out of range 1..%d", len(r.Host), MaxDomainLen)
		}
		out = append(out, AddrDomain, byte(len(r.Host)))
		out = append(out, r.Host...)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], r.Port)
	out = append(out, port[:]...)
	out = append(out, r.TraceID[:]...)
	out = append(out, r.Flags)
	return out, nil
}

// DecodeOpen parses an OPEN header payload.
func DecodeOpen(b []byte) (OpenRequest, error) {
	var r OpenRequest
	if len(b) < 4 {
		return r, fmt.Errorf("protocol: OPEN header too short (%d bytes)", len(b))
	}
	r.Version = b[0]
	r.Proto = b[1]
	if r.Version != OpenVersion1 {
		return r, fmt.Errorf("protocol: unsupported OPEN version %d (this build speaks version %d)", r.Version, OpenVersion1)
	}
	if r.Proto != ProtoTCP {
		return r, fmt.Errorf("protocol: unsupported OPEN proto %d", r.Proto)
	}
	addrType := b[2]
	pos := 3
	switch addrType {
	case AddrIPv4:
		if len(b) < pos+4 {
			return r, errors.New("protocol: truncated IPv4 address in OPEN header")
		}
		r.Host = net.IP(b[pos : pos+4]).String()
		pos += 4
	case AddrIPv6:
		if len(b) < pos+16 {
			return r, errors.New("protocol: truncated IPv6 address in OPEN header")
		}
		r.Host = net.IP(b[pos : pos+16]).String()
		pos += 16
	case AddrDomain:
		if len(b) < pos+1 {
			return r, errors.New("protocol: truncated domain length in OPEN header")
		}
		n := int(b[pos])
		pos++
		if n == 0 || n > MaxDomainLen {
			return r, fmt.Errorf("protocol: invalid domain length %d in OPEN header", n)
		}
		if len(b) < pos+n {
			return r, errors.New("protocol: truncated domain in OPEN header")
		}
		r.Host = string(b[pos : pos+n])
		pos += n
	default:
		return r, fmt.Errorf("protocol: unsupported OPEN address type %d", addrType)
	}
	if len(b) < pos+2+TraceIDLen+1 {
		return r, errors.New("protocol: truncated OPEN header tail")
	}
	r.Port = binary.BigEndian.Uint16(b[pos : pos+2])
	pos += 2
	if r.Port == 0 {
		return r, errors.New("protocol: OPEN port must be non-zero")
	}
	copy(r.TraceID[:], b[pos:pos+TraceIDLen])
	pos += TraceIDLen
	r.Flags = b[pos]
	if r.Flags&^flagsMask != 0 {
		return r, fmt.Errorf("protocol: unsupported OPEN flags 0x%02x", r.Flags)
	}
	if pos+1 != len(b) {
		return r, fmt.Errorf("protocol: trailing %d bytes after OPEN header", len(b)-(pos+1))
	}
	return r, nil
}

// TargetToOpen builds an OPEN request for a TCP target.
func TargetToOpen(host string, port int, traceID [TraceIDLen]byte, compressed bool) OpenRequest {
	r := OpenRequest{Version: OpenVersion1, Proto: ProtoTCP, Host: host, Port: uint16(port), TraceID: traceID}
	if compressed {
		r.Flags |= FlagCompressed
	}
	return r
}
