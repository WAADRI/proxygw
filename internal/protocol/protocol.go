// Package protocol implements the wire protocol shared by both transports:
// the WebSocket frame framing, the OPEN header, the OPEN build result format
// and the JSON control messages. QUIC data streams reuse the OPEN header and
// result format while relying on QUIC's native stream framing.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Protocol constants.
const (
	// Version1 is the current protocol version.
	Version1 = 1
	// ALPN is the application protocol negotiated over QUIC.
	ALPN = "proxygw/1"
	// FrameHeaderLen is type(1) + streamID(4) + length(4).
	FrameHeaderLen = 9
	// MaxFramePayload is the hard limit for a single frame payload (64 KiB).
	MaxFramePayload = 64 * 1024
	// TraceIDLen is the fixed trace id length inside the OPEN header.
	TraceIDLen = 16
	// MaxDomainLen is the maximum hostname length accepted in OPEN.
	MaxDomainLen = 255
	// ControlStreamID is the reserved stream id for connection level frames.
	ControlStreamID uint32 = 0

	// StreamID epoch packing: upper 12 bits epoch, lower 20 bits sequence.
	StreamIDEpochShift = 20
	MaxEpoch           = 0xFFF
	MaxStreamSequence  = 0xFFFFF
)

// FrameType identifies a multiplexed frame on the WebSocket path and on
// connection level control streams.
type FrameType uint8

// Frame types. Values 0x01-0x0A are the ones mandated by the tunnel state
// machine attachment; 0x10+ are control extensions that ride on control
// streams.
const (
	FrameOpen     FrameType = 0x01
	FrameOpenOK   FrameType = 0x02
	FrameOpenErr  FrameType = 0x03
	FrameData     FrameType = 0x04
	FrameFin      FrameType = 0x05
	FrameWindow   FrameType = 0x06
	FramePing     FrameType = 0x07
	FramePong     FrameType = 0x08
	FrameStats    FrameType = 0x09
	FrameRST      FrameType = 0x0A
	FrameHello    FrameType = 0x10
	FrameHelloAck FrameType = 0x11
	FrameKick     FrameType = 0x12
	FrameStatsReq FrameType = 0x13
	FrameProbe    FrameType = 0x14
	FrameProbeRes FrameType = 0x15
	FrameUpdate   FrameType = 0x16
	FrameUpdateSt FrameType = 0x17
)

var frameNames = map[FrameType]string{
	FrameOpen: "OPEN", FrameOpenOK: "OPEN_OK", FrameOpenErr: "OPEN_ERR",
	FrameData: "DATA", FrameFin: "FIN", FrameWindow: "WINDOW",
	FramePing: "PING", FramePong: "PONG", FrameStats: "STATS", FrameRST: "RST",
	FrameHello: "HELLO", FrameHelloAck: "HELLO_ACK", FrameKick: "KICK",
	FrameStatsReq: "STATS_REQ", FrameProbe: "PROBE", FrameProbeRes: "PROBE_RESULT",
	FrameUpdate: "UPDATE", FrameUpdateSt: "UPDATE_STATUS",
}

// String implements fmt.Stringer.
func (t FrameType) String() string {
	if s, ok := frameNames[t]; ok {
		return s
	}
	return fmt.Sprintf("0x%02x", uint8(t))
}

// IsControl reports whether the frame is a connection level control frame.
// Connection level means "not tied to a data stream" and is always delivered
// on control streams (QUIC) or with stream id 0 (WS).
func (t FrameType) IsControl() bool {
	switch t {
	case FrameHello, FrameHelloAck, FrameKick, FrameStats, FrameStatsReq, FrameProbe, FrameProbeRes, FramePing, FramePong, FrameUpdate, FrameUpdateSt:
		return true
	}
	return false
}

// Frame is one decoded wire frame.
type Frame struct {
	Type     FrameType
	StreamID uint32
	Payload  []byte
}

// ErrFrameTooLarge is returned when a peer announces a payload above the limit.
var ErrFrameTooLarge = errors.New("protocol: frame payload exceeds limit")

// ReadFrame reads exactly one frame from r. It validates the declared length
// against maxPayload (zero means MaxFramePayload) and rejects unknown types,
// unknown control frames on a data stream are the caller's concern.
func ReadFrame(r io.Reader, maxPayload int) (Frame, error) {
	if maxPayload <= 0 || maxPayload > MaxFramePayload {
		maxPayload = MaxFramePayload
	}
	var hdr [FrameHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	typ := FrameType(hdr[0])
	sid := binary.BigEndian.Uint32(hdr[1:5])
	length := binary.BigEndian.Uint32(hdr[5:9])
	if length > uint32(maxPayload) {
		return Frame{}, fmt.Errorf("%w: type=%s length=%d limit=%d", ErrFrameTooLarge, typ, length, maxPayload)
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, err
		}
	}
	return Frame{Type: typ, StreamID: sid, Payload: payload}, nil
}

// ReadFrameHeader parses a 9 byte frame header.
func ReadFrameHeader(b []byte) (FrameType, uint32, uint32, error) {
	if len(b) < FrameHeaderLen {
		return 0, 0, 0, fmt.Errorf("protocol: short frame header: %d bytes", len(b))
	}
	return FrameType(b[0]), binary.BigEndian.Uint32(b[1:5]), binary.BigEndian.Uint32(b[5:9]), nil
}

// AppendFrame appends an encoded frame to dst (useful to batch frames before a
// single write).
func AppendFrame(dst []byte, typ FrameType, streamID uint32, payload []byte) ([]byte, error) {
	if len(payload) > MaxFramePayload {
		return dst, ErrFrameTooLarge
	}
	var hdr [FrameHeaderLen]byte
	hdr[0] = byte(typ)
	binary.BigEndian.PutUint32(hdr[1:5], streamID)
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(payload)))
	dst = append(dst, hdr[:]...)
	dst = append(dst, payload...)
	return dst, nil
}

// WriteFrame writes one frame to w with a single Write call.
func WriteFrame(w io.Writer, typ FrameType, streamID uint32, payload []byte) error {
	if len(payload) > MaxFramePayload {
		return ErrFrameTooLarge
	}
	buf := make([]byte, 0, FrameHeaderLen+len(payload))
	buf, err := AppendFrame(buf, typ, streamID, payload)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// EncodeWindow encodes a WINDOW increment payload (uint32 big endian).
func EncodeWindow(delta uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], delta)
	return b[:]
}

// DecodeWindow decodes a WINDOW increment payload.
func DecodeWindow(payload []byte) (uint32, error) {
	if len(payload) != 4 {
		return 0, fmt.Errorf("protocol: WINDOW payload must be 4 bytes, got %d", len(payload))
	}
	return binary.BigEndian.Uint32(payload), nil
}

// MakeStreamID packs epoch and sequence into a WS stream id.
func MakeStreamID(epoch, seq uint32) uint32 {
	return (epoch&MaxEpoch)<<StreamIDEpochShift | (seq & MaxStreamSequence)
}

// SplitStreamID splits a WS stream id into epoch and sequence.
func SplitStreamID(id uint32) (epoch, seq uint32) {
	return (id >> StreamIDEpochShift) & MaxEpoch, id & MaxStreamSequence
}

// EncodeOpenResult encodes the stream build result written back by the node.
// Layout: code(1) + message length(2) + message.
func EncodeOpenResult(code byte, message string) []byte {
	if len(message) > 0xFFFF {
		message = message[:0xFFFF]
	}
	out := make([]byte, 3+len(message))
	out[0] = code
	binary.BigEndian.PutUint16(out[1:3], uint16(len(message)))
	copy(out[3:], message)
	return out
}

// DecodeOpenResult decodes the stream build result.
func DecodeOpenResult(b []byte) (code byte, message string, err error) {
	if len(b) < 1 {
		return 0, "", errors.New("protocol: empty OPEN result")
	}
	if len(b) < 3 {
		return b[0], "", nil
	}
	n := int(binary.BigEndian.Uint16(b[1:3]))
	if len(b) < 3+n {
		return 0, "", fmt.Errorf("protocol: truncated OPEN result: have %d want %d", len(b), 3+n)
	}
	return b[0], string(b[3 : 3+n]), nil
}
