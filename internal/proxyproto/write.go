package proxyproto

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
)

// WriteV2 serializes h as a version 2 (binary) PROXY protocol header and writes
// it to w. It is intended for panel diagnostics and for tests that need to
// produce a header (for example to exercise a CDN/LB configuration); the
// gateway itself receives headers rather than sending them.
//
// The emitted command is taken from h.Command ("PROXY" by default, or "LOCAL").
// For PROXY the family is taken from h.Family and may be "TCP4", "TCP6" or
// "UNSPEC"; when h.Family is empty it is inferred from the addresses. TLVs are
// written in ascending type order for deterministic output. When a CRC32C TLV
// is requested its value is computed (the caller-provided value is ignored and
// replaced by the 4-byte checksum in network byte order). LOCAL headers carry
// no address block; TLVs, if any, are still written and included in the length
// field.
//
// h.Version is informational: WriteV2 always emits a v2 header.
func WriteV2(w io.Writer, h Header) error {
	if w == nil {
		return fmt.Errorf("proxyproto: v2: nil writer")
	}
	var verCmd, famProto byte
	var addr []byte
	switch h.Command {
	case "", CommandProxy:
		verCmd = 0x21
		var err error
		famProto, addr, err = encodeV2Addrs(h)
		if err != nil {
			return err
		}
	case CommandLocal:
		verCmd = 0x20
		famProto = 0x00
	default:
		return fmt.Errorf("proxyproto: v2: unsupported command %q (want PROXY or LOCAL)", h.Command)
	}

	tlvBytes, crcOffset, err := encodeV2TLVs(h.TLVs)
	if err != nil {
		return err
	}
	payloadLen := len(addr) + len(tlvBytes)
	if payloadLen > maxV2PayloadLen {
		return fmt.Errorf("%w: v2 payload length %d exceeds limit %d", ErrHeaderTooLong, payloadLen, maxV2PayloadLen)
	}
	if payloadLen > 0xffff {
		return fmt.Errorf("%w: v2 payload length %d does not fit the 16-bit length field", ErrHeaderTooLong, payloadLen)
	}

	buf := make([]byte, 0, v2FixedLen+payloadLen)
	buf = append(buf, v2Signature...)
	buf = append(buf, verCmd, famProto, byte(payloadLen>>8), byte(payloadLen))
	buf = append(buf, addr...)
	tlvStart := len(buf)
	buf = append(buf, tlvBytes...)

	if crcOffset >= 0 {
		crcRawOffset := tlvStart + crcOffset
		if crcRawOffset+4 > len(buf) {
			return fmt.Errorf("proxyproto: v2: internal CRC32C offset %d out of range", crcRawOffset)
		}
		// The placeholder is already zeroed by encodeV2TLVs, so the checksum
		// covers the whole header with the checksum field itself set to 0.
		sum := crc32.Checksum(buf, crc32cTable)
		binary.BigEndian.PutUint32(buf[crcRawOffset:crcRawOffset+4], sum)
	}
	return writeAll(w, buf)
}

// encodeV2Addrs returns the family/protocol byte and the address block for h.
func encodeV2Addrs(h Header) (famProto byte, addr []byte, err error) {
	family := h.Family
	if family == "" {
		switch {
		case h.SrcIP == nil && h.DstIP == nil:
			family = FamilyUNSPEC
		case h.SrcIP != nil && h.SrcIP.To4() != nil &&
			h.DstIP != nil && h.DstIP.To4() != nil:
			family = FamilyTCP4
		case h.SrcIP != nil && h.SrcIP.To4() == nil &&
			h.DstIP != nil && h.DstIP.To4() == nil:
			family = FamilyTCP6
		default:
			return 0, nil, fmt.Errorf("proxyproto: v2: cannot infer address family from source/destination addresses")
		}
	}
	switch family {
	case FamilyTCP4:
		src, dst := h.SrcIP.To4(), h.DstIP.To4()
		if src == nil || dst == nil {
			return 0, nil, fmt.Errorf("proxyproto: v2: TCP4 requires two IPv4 addresses")
		}
		if err := validatePort(h.SrcPort); err != nil {
			return 0, nil, err
		}
		if err := validatePort(h.DstPort); err != nil {
			return 0, nil, err
		}
		addr = make([]byte, 0, v2AddrLenIPv4)
		addr = append(addr, src...)
		addr = append(addr, dst...)
		addr = append(addr, byte(h.SrcPort>>8), byte(h.SrcPort), byte(h.DstPort>>8), byte(h.DstPort))
		return 0x11, addr, nil
	case FamilyTCP6:
		src, dst := h.SrcIP.To16(), h.DstIP.To16()
		if src == nil || dst == nil || h.SrcIP.To4() != nil || h.DstIP.To4() != nil {
			return 0, nil, fmt.Errorf("proxyproto: v2: TCP6 requires two IPv6 addresses")
		}
		if err := validatePort(h.SrcPort); err != nil {
			return 0, nil, err
		}
		if err := validatePort(h.DstPort); err != nil {
			return 0, nil, err
		}
		addr = make([]byte, 0, v2AddrLenIPv6)
		addr = append(addr, src...)
		addr = append(addr, dst...)
		addr = append(addr, byte(h.SrcPort>>8), byte(h.SrcPort), byte(h.DstPort>>8), byte(h.DstPort))
		return 0x21, addr, nil
	case FamilyUNSPEC:
		return 0x00, nil, nil
	default:
		return 0, nil, fmt.Errorf("proxyproto: v2: unsupported family %q (want TCP4, TCP6 or UNSPEC)", family)
	}
}

// validatePort checks that a port fits in the 16-bit field used by v2.
func validatePort(port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("proxyproto: v2: port %d out of range [0,65535]", port)
	}
	return nil
}

// encodeV2TLVs serializes the TLV vector in ascending type order. It returns the
// byte offset of the CRC32C value inside the vector when a CRC32C TLV is
// present, with the value bytes left zeroed for the caller to fill in.
func encodeV2TLVs(tlvs map[byte][]byte) (out []byte, crcOffset int, err error) {
	crcOffset = -1
	if len(tlvs) == 0 {
		return nil, -1, nil
	}
	types := make([]int, 0, len(tlvs))
	for typ := range tlvs {
		types = append(types, int(typ))
	}
	sort.Ints(types)
	for _, it := range types {
		typ := byte(it)
		value := tlvs[typ]
		if typ == TLVTypeCRC32C {
			if crcOffset >= 0 {
				// A map cannot hold the same key twice, this is unreachable.
				return nil, -1, fmt.Errorf("proxyproto: v2: duplicate CRC32C TLV")
			}
			crcOffset = len(out) + 3
			out = append(out, typ, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00)
			continue
		}
		if len(value) > 0xffff {
			return nil, -1, fmt.Errorf("proxyproto: v2: TLV type 0x%02x value length %d exceeds 65535", typ, len(value))
		}
		out = append(out, typ, byte(len(value)>>8), byte(len(value)))
		out = append(out, value...)
	}
	return out, crcOffset, nil
}

// writeAll writes all of b to w, handling short writes.
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return fmt.Errorf("proxyproto: v2: write header: %w", err)
		}
		if n <= 0 || n > len(b) {
			return fmt.Errorf("proxyproto: v2: invalid write count %d", n)
		}
		b = b[n:]
	}
	return nil
}
