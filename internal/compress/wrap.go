package compress

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// WrapReadWrite returns a compressed view of rw: Read decompresses bytes coming
// from the peer, Write compresses bytes towards the peer, and Close finalizes
// both directions, closes rw and returns the encoder/decoder to the default
// pool. Calling the same wrap on both ends of a stream (after the OPEN header
// negotiated protocol.FlagCompressed) yields a transparent compressed tunnel.
//
// The underlying rw is used full duplex: Read and Write may be called
// concurrently, exactly like a net.Conn. Close is safe to call concurrently
// with a blocked Read: it closes the underlying stream before releasing the
// decoder, which unblocks the pending read for net.Conn-like transports. The
// underlying codecs are serialized internally, so one concurrent reader and one
// concurrent writer are supported; Close blocks until an in-flight Write (and
// its final flush) completes.
//
// The concrete value also forwards optional transport capabilities of rw when
// it implements them, so a tunnel relay can keep its half-close, timeout and
// reset semantics on the wrapped stream:
//
//   - CloseWrite() error: flush + terminate the zstd stream (the peer decoder
//     sees io.EOF) and half-close the underlying write direction.
//   - CloseRead() error: cancel the local read direction.
//   - Reset(code uint64) error: reset the underlying stream abnormally.
//   - SetDeadline(time.Time) error, SetReadDeadline(time.Time) error,
//     SetWriteDeadline(time.Time) error: forwarded to rw.
func WrapReadWrite(rw io.ReadWriteCloser, level int) (io.ReadWriteCloser, error) {
	return wrapReadWrite(rw, level)
}

// wrapReadWrite is the shared constructor behind WrapReadWrite and WrapStream.
func wrapReadWrite(rw io.ReadWriteCloser, level int) (*wrappedConn, error) {
	if rw == nil {
		return nil, fmt.Errorf("compress: wrap: %w", errNilStream)
	}
	pool := DefaultPool()
	enc, err := pool.GetEncoder(rw, level)
	if err != nil {
		return nil, fmt.Errorf("compress: wrap: %w", err)
	}
	dec, err := pool.GetDecoder(rw)
	if err != nil {
		pool.PutEncoder(enc)
		return nil, fmt.Errorf("compress: wrap: %w", err)
	}
	return &wrappedConn{rw: rw, enc: enc, dec: dec, pool: pool}, nil
}

// wrappedConn is the io.ReadWriteCloser returned by WrapReadWrite.
type wrappedConn struct {
	rw   io.ReadWriteCloser
	enc  *Encoder
	dec  *Decoder
	pool *Pool

	closeOnce sync.Once
	closeErr  error
	writeOnce sync.Once
	writeErr  error
	readOnce  sync.Once
	readErr   error
}

// Read decompresses the peer's payload.
func (c *wrappedConn) Read(p []byte) (int, error) { return c.dec.Read(p) }

// Write compresses the local payload.
func (c *wrappedConn) Write(p []byte) (int, error) { return c.enc.Write(p) }

// Close finalizes the compression streams, closes the underlying stream and
// releases the pooled codecs. It is idempotent and returns the same result on
// repeated calls. Errors are joined with errors.Join and remain matchable with
// errors.Is.
func (c *wrappedConn) Close() error {
	c.closeOnce.Do(func() {
		var errs []error
		// Flush the tail first, while the underlying stream is still open, so
		// the peer receives the final zstd frame.
		if err := c.enc.Close(); err != nil {
			errs = append(errs, err)
		}
		// Closing the underlying stream unblocks a decoder read that may be in
		// flight; only then can the decoder be released without waiting for the
		// peer to send more data.
		if err := c.rw.Close(); err != nil {
			errs = append(errs, fmt.Errorf("compress: close underlying stream: %w", err))
		}
		if err := c.dec.Close(); err != nil {
			errs = append(errs, err)
		}
		c.pool.PutEncoder(c.enc)
		c.pool.PutDecoder(c.dec)
		c.closeErr = errors.Join(errs...)
	})
	return c.closeErr
}

// CloseWrite half-closes the local write direction: it flushes and terminates
// the zstd stream, then forwards the half close to the underlying stream when it
// supports it. The read direction stays usable, which preserves TCP FIN
// semantics through the tunnel. It is idempotent; further Writes fail with
// ErrClosed.
//
// zstd allows concatenated frames on one stream, so the peer's decoder reports
// io.EOF only once the transport signals the end of the byte stream as well
// (FIN). transport.Stream implements CloseWrite on both QUIC and WS, so a
// wrapped tunnel stream gets clean half-close semantics; on a plain
// io.ReadWriteCloser without a write half-close the peer sees EOF only when the
// stream is closed.
func (c *wrappedConn) CloseWrite() error {
	c.writeOnce.Do(func() {
		var err error
		if cerr := c.enc.Close(); cerr != nil {
			err = fmt.Errorf("compress: close write: %w", cerr)
		}
		if cw, ok := c.rw.(interface{ CloseWrite() error }); ok {
			if cerr := cw.CloseWrite(); cerr != nil && err == nil {
				err = fmt.Errorf("compress: underlying close write: %w", cerr)
			}
		}
		c.writeErr = err
	})
	return c.writeErr
}

// CloseRead cancels the local read direction. The underlying half close is
// invoked first so that a blocked decoder read is unblocked before the decoder
// is released. It is idempotent.
func (c *wrappedConn) CloseRead() error {
	c.readOnce.Do(func() {
		var err error
		if cr, ok := c.rw.(interface{ CloseRead() error }); ok {
			if cerr := cr.CloseRead(); cerr != nil {
				err = fmt.Errorf("compress: underlying close read: %w", cerr)
			}
		}
		if cerr := c.dec.Close(); cerr != nil && err == nil {
			err = cerr
		}
		c.readErr = err
	})
	return c.readErr
}

// Reset forwards an abnormal stream reset to the underlying stream. The
// compressed stream itself is released by Close.
func (c *wrappedConn) Reset(code uint64) error {
	if r, ok := c.rw.(interface{ Reset(uint64) error }); ok {
		return r.Reset(code)
	}
	return errors.New("compress: underlying stream does not support Reset")
}

// SetDeadline forwards to the underlying stream.
func (c *wrappedConn) SetDeadline(t time.Time) error {
	if d, ok := c.rw.(interface{ SetDeadline(time.Time) error }); ok {
		return d.SetDeadline(t)
	}
	return errors.New("compress: underlying stream does not support deadlines")
}

// SetReadDeadline forwards to the underlying stream.
func (c *wrappedConn) SetReadDeadline(t time.Time) error {
	if d, ok := c.rw.(interface{ SetReadDeadline(time.Time) error }); ok {
		return d.SetReadDeadline(t)
	}
	return errors.New("compress: underlying stream does not support read deadlines")
}

// SetWriteDeadline forwards to the underlying stream.
func (c *wrappedConn) SetWriteDeadline(t time.Time) error {
	if d, ok := c.rw.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return d.SetWriteDeadline(t)
	}
	return errors.New("compress: underlying stream does not support write deadlines")
}
