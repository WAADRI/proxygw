package proxyproto

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"net"
)

const (
	// v2Signature is the fixed 12-byte signature that starts every v2 header.
	// It contains a NUL byte at offset 4, so it is compared as binary data.
	v2Signature = "\r\n\r\n\x00\r\nQUIT\n"
	// v2SignatureLen is the length of v2Signature.
	v2SignatureLen = 12
	// v2FixedLen is the length of the fixed part of a v2 header: signature
	// (12 bytes) + version/command + family/protocol + 2-byte length.
	v2FixedLen = 16
	// maxV2PayloadLen is the defensive upper bound for the length field of a
	// v2 header (addresses plus TLVs). The specification allows up to 65535
	// bytes, but a real PROXY header fits in the minimum TCP segment (536
	// bytes); 16 KiB leaves ample room for large SSL-client-certificate TLVs
	// while bounding what an untrusted sender can make us allocate.
	maxV2PayloadLen = 16*1024 - v2FixedLen
)

// v2 address block lengths for the valid family/protocol combinations.
const (
	v2AddrLenIPv4 = 12 // 4+4 addresses + 2+2 ports
	v2AddrLenIPv6 = 36 // 16+16 addresses + 2+2 ports
	v2AddrLenUnix = 216
)

// crc32cTable is the Castagnoli polynomial table used by the PP2_TYPE_CRC32C
// TLV (RFC 4960 appendix B).
var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// ParseV2 parses a version 2 (binary) PROXY protocol header from r. The whole
// header (fixed 16 bytes plus the announced payload) is consumed; no byte after
// the header is read, so a following payload stays in r.
//
// Supported commands are LOCAL and PROXY. For PROXY, TCP over IPv4/IPv6 is
// decoded into addresses and ports, UNSPEC yields FamilyUNSPEC, and the valid
// but unsupported combinations (UDP over IPv4/IPv6 and UNIX sockets) are
// skipped and reported as FamilyUNSPEC with their TLVs still parsed, as the
// specification recommends for receivers that do not implement them. Unknown
// family/protocol bytes are rejected. TLVs are returned raw in Header.TLVs and
// a CRC32C TLV, when present, is verified.
func ParseV2(r io.Reader) (Header, error) {
	if r == nil {
		return Header{}, fmt.Errorf("proxyproto: v2: nil reader")
	}
	sig := make([]byte, v2SignatureLen)
	if _, err := io.ReadFull(r, sig); err != nil {
		return Header{}, fmt.Errorf("proxyproto: v2: read signature: %w", err)
	}
	if string(sig) != v2Signature {
		return Header{}, fmt.Errorf("%w: v2: invalid signature", ErrNoProxyHeader)
	}
	return readV2Body(r, sig)
}

// readV2Body reads the fixed header remainder and the payload from r. sig holds
// the already consumed 12-byte signature and is kept so the CRC32C checksum can
// be computed over the whole header.
func readV2Body(r io.Reader, sig []byte) (Header, error) {
	var fixed [4]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return Header{}, fmt.Errorf("proxyproto: v2: read version/command/family/length: %w", err)
	}
	verCmd, famProto := fixed[0], fixed[1]
	version := int(verCmd >> 4)
	if version != Version2 {
		return Header{}, fmt.Errorf("proxyproto: v2: unsupported version %d (want 2)", version)
	}
	h := Header{Version: Version2}
	switch verCmd & 0x0f {
	case 0x00:
		h.Command = CommandLocal
	case 0x01:
		h.Command = CommandProxy
	default:
		return Header{}, fmt.Errorf("proxyproto: v2: unsupported command 0x%x", verCmd&0x0f)
	}
	payloadLen := int(binary.BigEndian.Uint16(fixed[2:4]))
	if payloadLen > maxV2PayloadLen {
		return Header{}, fmt.Errorf("%w: v2 payload length %d exceeds limit %d", ErrHeaderTooLong, payloadLen, maxV2PayloadLen)
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Header{}, fmt.Errorf("proxyproto: v2: read header payload: %w", err)
	}
	raw := make([]byte, 0, v2FixedLen+payloadLen)
	raw = append(raw, sig...)
	raw = append(raw, fixed[:]...)
	raw = append(raw, payload...)

	// For LOCAL the specification says to accept the connection, use the real
	// socket endpoints and discard the protocol block (family included). We
	// still consume exactly len bytes, which the sender may use for anything.
	if h.Command == CommandLocal {
		h.Family = FamilyUNSPEC
		return h, nil
	}

	family, addrLen, err := v2Family(famProto)
	if err != nil {
		return Header{}, err
	}
	h.Family = family
	if payloadLen < addrLen {
		return Header{}, fmt.Errorf("proxyproto: v2: payload length %d is too short for a %s address block (%d bytes)", payloadLen, family, addrLen)
	}
	if addrLen > 0 && (h.Family == FamilyTCP4 || h.Family == FamilyTCP6) {
		if err := decodeV2Addrs(&h, payload[:addrLen]); err != nil {
			return Header{}, err
		}
	}
	tlvs, crcRawOffset, haveCRC, crcExpected, err := parseV2TLVs(payload[addrLen:], v2FixedLen+addrLen)
	if err != nil {
		return Header{}, err
	}
	h.TLVs = tlvs
	if haveCRC {
		// Section 2.2.3: set the checksum field to zero, then compute the
		// CRC32C of the whole header (signature through the last TLV). The
		// checksum is stored in network byte order.
		if crcRawOffset < 0 || crcRawOffset+4 > len(raw) {
			return Header{}, fmt.Errorf("proxyproto: v2: internal CRC32C offset %d out of range", crcRawOffset)
		}
		for i := crcRawOffset; i < crcRawOffset+4; i++ {
			raw[i] = 0
		}
		got := crc32.Checksum(raw, crc32cTable)
		if got != crcExpected {
			return Header{}, fmt.Errorf("proxyproto: v2: CRC32C mismatch: header has %08x, computed %08x", crcExpected, got)
		}
	}
	return h, nil
}

// v2Family maps the v2 family/protocol byte to a Header.Family and to the
// length of the address block that follows it. Valid combinations that this
// package does not decode (UDP over IPv4/IPv6, UNIX stream/datagram) are
// reported as UNSPEC with the address block length so it can be skipped; they
// are accepted because the specification recommends that fallback instead of
// rejecting connections. Every other byte is invalid.
func v2Family(famProto byte) (family string, addrLen int, err error) {
	switch famProto {
	case 0x00: // AF_UNSPEC / UNSPEC
		return FamilyUNSPEC, 0, nil
	case 0x11: // AF_INET / STREAM
		return FamilyTCP4, v2AddrLenIPv4, nil
	case 0x21: // AF_INET6 / STREAM
		return FamilyTCP6, v2AddrLenIPv6, nil
	case 0x12: // AF_INET / DGRAM
		return FamilyUNSPEC, v2AddrLenIPv4, nil
	case 0x22: // AF_INET6 / DGRAM
		return FamilyUNSPEC, v2AddrLenIPv6, nil
	case 0x31, 0x32: // AF_UNIX STREAM/DGRAM
		return FamilyUNSPEC, v2AddrLenUnix, nil
	default:
		return "", 0, fmt.Errorf("proxyproto: v2: unsupported address family/protocol 0x%02x", famProto)
	}
}

// decodeV2Addrs decodes the IPv4 or IPv6 address block into h.
func decodeV2Addrs(h *Header, addr []byte) error {
	switch h.Family {
	case FamilyTCP4:
		h.SrcIP = net.IP(append([]byte(nil), addr[0:4]...))
		h.DstIP = net.IP(append([]byte(nil), addr[4:8]...))
		h.SrcPort = int(binary.BigEndian.Uint16(addr[8:10]))
		h.DstPort = int(binary.BigEndian.Uint16(addr[10:12]))
	case FamilyTCP6:
		h.SrcIP = net.IP(append([]byte(nil), addr[0:16]...))
		h.DstIP = net.IP(append([]byte(nil), addr[16:32]...))
		h.SrcPort = int(binary.BigEndian.Uint16(addr[32:34]))
		h.DstPort = int(binary.BigEndian.Uint16(addr[34:36]))
	default:
		return fmt.Errorf("proxyproto: v2: cannot decode addresses for family %s", h.Family)
	}
	return nil
}

// parseV2TLVs parses a TLV vector. rawBase is the offset of b inside the whole
// header (used to locate the CRC32C value for checksumming). It returns the
// decoded values, the absolute offset of the CRC32C value (a 4-byte field whose
// value is big endian), whether a CRC32C TLV was present and its expected
// value. A malformed vector (truncated element, value larger than the remaining
// payload, CRC32C not exactly 4 bytes) is an error.
func parseV2TLVs(b []byte, rawBase int) (tlvs map[byte][]byte, crcRawOffset int, haveCRC bool, crcExpected uint32, err error) {
	crcRawOffset = -1
	for i := 0; i < len(b); {
		if len(b)-i < 3 {
			return nil, 0, false, 0, fmt.Errorf("proxyproto: v2: truncated TLV header at payload offset %d", i)
		}
		typ := b[i]
		valueLen := int(binary.BigEndian.Uint16(b[i+1 : i+3]))
		if valueLen > len(b)-i-3 {
			return nil, 0, false, 0, fmt.Errorf("proxyproto: v2: TLV type 0x%02x length %d exceeds remaining payload %d", typ, valueLen, len(b)-i-3)
		}
		value := b[i+3 : i+3+valueLen]
		if typ == TLVTypeCRC32C {
			if valueLen != 4 {
				return nil, 0, false, 0, fmt.Errorf("proxyproto: v2: CRC32C TLV must be 4 bytes, got %d", valueLen)
			}
			crcRawOffset = rawBase + i + 3
			crcExpected = binary.BigEndian.Uint32(value)
			haveCRC = true
		}
		if tlvs == nil {
			tlvs = make(map[byte][]byte)
		}
		tlvs[typ] = append([]byte(nil), value...)
		i += 3 + valueLen
	}
	return tlvs, crcRawOffset, haveCRC, crcExpected, nil
}
