package compress

import (
	"io"
	"time"
)

// Stream is the compressed stream adapter returned by WrapStream.
//
// It is a full duplex stream view of an underlying io.ReadWriteCloser: Read
// decompresses the peer's payload, Write compresses the local payload and Close
// finalizes both directions, closes the underlying stream and releases the
// pooled codecs.
//
// Unlike WrapReadWrite, which returns the io.ReadWriteCloser interface, Stream
// exposes the optional tunnel transport capabilities directly on its method set:
//
//   - CloseWrite() error: flush and terminate the zstd stream, then half-close
//     the underlying write direction (TCP FIN semantics).
//   - CloseRead() error: cancel the local read direction.
//   - Reset(code uint64) error: reset the underlying stream abnormally.
//   - SetDeadline(t time.Time) error, SetReadDeadline(time.Time) error,
//     SetWriteDeadline(time.Time) error: forwarded to the underlying stream.
//
// Tunnel relay layers can therefore keep their half-close, timeout, reset and
// cleanup semantics without probing for interfaces with type assertions. Close
// is idempotent and always flushes the final zstd frame before closing the
// underlying stream; the codecs return to DefaultPool so the next stream can
// reuse them.
//
// A Stream is bound to one tunnel stream. Read and Write may be called
// concurrently (one reader, one writer), matching a net.Conn; Close may run
// concurrently with a blocked Read.
type Stream struct {
	*wrappedConn
}

// WrapStream wraps rw into a compressed Stream. level is clamped into
// [MinLevel, MaxLevel]; use DefaultLevel for the latency oriented default.
//
// The same wrapper must be applied on both ends of the stream after the OPEN
// header negotiated protocol.FlagCompressed: the initiator's Write is decoded by
// the peer's Read and vice versa. The OPEN header and the stream build result
// are never passed through the wrapper.
func WrapStream(rw io.ReadWriteCloser, level int) (*Stream, error) {
	c, err := wrapReadWrite(rw, level)
	if err != nil {
		return nil, err
	}
	return &Stream{wrappedConn: c}, nil
}

// Compile time guarantees: the proxy and node relay layers rely on these exact
// capabilities without type assertions.
var (
	_ io.ReadWriteCloser = (*Stream)(nil)

	_ interface{ CloseWrite() error }           = (*Stream)(nil)
	_ interface{ CloseRead() error }            = (*Stream)(nil)
	_ interface{ Reset(uint64) error }          = (*Stream)(nil)
	_ interface{ SetDeadline(time.Time) error } = (*Stream)(nil)
	_ interface {
		SetReadDeadline(time.Time) error
	} = (*Stream)(nil)
	_ interface {
		SetWriteDeadline(time.Time) error
	} = (*Stream)(nil)
)
