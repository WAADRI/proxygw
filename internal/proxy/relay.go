package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
)

// relayBufferSize is the copy buffer size shared by every relay and HTTP body
// copy. Buffers are recycled through relayBufPool.
const relayBufferSize = 32 * 1024

var relayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, relayBufferSize)
		return &b
	},
}

func getRelayBuf() *[]byte  { return relayBufPool.Get().(*[]byte) }
func putRelayBuf(b *[]byte) { relayBufPool.Put(b) }

// writeFull writes p completely.
func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// copyMode selects the framing applied by copyBody.
type copyMode int

const (
	// copyRaw forwards bytes until EOF.
	copyRaw copyMode = iota
	// copyExact forwards exactly n bytes and fails on a short stream.
	copyExact
	// copyChunked re-encodes the stream with HTTP chunked framing.
	copyChunked
)

// copyBody streams src into dst with the given framing. lim applies read side
// backpressure (nil = unlimited). beforeRead / beforeWrite refresh the read and
// write deadlines and may be nil.
func copyBody(ctx context.Context, dst io.Writer, src io.Reader, mode copyMode, n int64, lim ByteLimiter, beforeRead, beforeWrite func()) (int64, error) {
	bp := getRelayBuf()
	defer putRelayBuf(bp)
	buf := *bp
	var total int64
	for {
		readBuf := buf
		if mode == copyExact {
			remaining := n - total
			if remaining <= 0 {
				return total, nil
			}
			if remaining < int64(len(readBuf)) {
				readBuf = readBuf[:remaining]
			}
		}
		if beforeRead != nil {
			beforeRead()
		}
		nr, rerr := src.Read(readBuf)
		if nr > 0 {
			if lim != nil {
				if werr := lim.WaitN(ctx, nr); werr != nil {
					return total, fmt.Errorf("proxy: bandwidth limiter: %w", werr)
				}
			}
			if beforeWrite != nil {
				beforeWrite()
			}
			var werr error
			if mode == copyChunked {
				werr = writeChunk(dst, readBuf[:nr], beforeWrite)
			} else {
				werr = writeFull(dst, readBuf[:nr])
			}
			if werr != nil {
				return total, werr
			}
			total += int64(nr)
		}
		if rerr != nil {
			switch {
			case rerr == io.EOF:
				if mode == copyExact && total >= n {
					return total, nil
				}
				if mode == copyChunked {
					if beforeWrite != nil {
						beforeWrite()
					}
					if werr := writeFull(dst, []byte("0\r\n\r\n")); werr != nil {
						return total, werr
					}
				}
				if mode == copyExact {
					return total, io.ErrUnexpectedEOF
				}
				return total, nil
			case mode == copyExact:
				return total, rerr
			default:
				return total, rerr
			}
		}
	}
}

// writeChunk writes one HTTP chunk (size line, data, trailing CRLF).
func writeChunk(dst io.Writer, data []byte, beforeWrite func()) error {
	var hexbuf [18]byte
	line := hexbuf[:0]
	line = strconv.AppendInt(line, int64(len(data)), 16)
	line = append(line, '\r', '\n')
	head := make([]byte, 0, len(line)+len(data)+2)
	head = append(head, line...)
	head = append(head, data...)
	head = append(head, '\r', '\n')
	if beforeWrite != nil {
		beforeWrite()
	}
	return writeFull(dst, head)
}

// readDeadliner / writeDeadliner are the optional deadline capabilities of a
// connection. The StreamConn interface is intentionally minimal, so the relay
// layer applies deadlines only when the concrete connection supports them.
type readDeadliner interface{ SetReadDeadline(time.Time) error }

type writeDeadliner interface{ SetWriteDeadline(time.Time) error }

// halfConn is one direction capable endpoint of a relay.
type halfConn struct {
	r                io.Reader
	w                io.Writer
	closeWrite       func() error
	closeFn          func() error
	setReadDeadline  func(time.Time) error
	setWriteDeadline func(time.Time) error
}

// clientHalf builds the client side endpoint. br may already hold bytes that
// were buffered while parsing the request head (for example the first TLS bytes
// after a CONNECT), so it must be used as the read side instead of the raw conn.
func clientHalf(conn io.ReadWriteCloser, br io.Reader) halfConn {
	h := halfConn{
		r:       io.Reader(conn),
		w:       conn,
		closeFn: conn.Close,
	}
	if br != nil {
		h.r = br
	}
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		h.closeWrite = cw.CloseWrite
	}
	if d, ok := conn.(readDeadliner); ok {
		h.setReadDeadline = d.SetReadDeadline
	}
	if d, ok := conn.(writeDeadliner); ok {
		h.setWriteDeadline = d.SetWriteDeadline
	}
	return h
}

// streamHalf builds the tunnel stream side endpoint. br must be the buffered
// reader used to parse the upstream response; bytes after the response head may
// already be buffered there.
func streamHalf(conn StreamConn, br io.Reader) halfConn {
	h := halfConn{
		r:          io.Reader(conn),
		w:          conn,
		closeWrite: conn.CloseWrite,
		closeFn:    conn.Close,
	}
	if br != nil {
		h.r = br
	}
	if d, ok := conn.(readDeadliner); ok {
		h.setReadDeadline = d.SetReadDeadline
	}
	if d, ok := conn.(writeDeadliner); ok {
		h.setWriteDeadline = d.SetWriteDeadline
	}
	return h
}

// relayConfig configures one bidirectional copy.
type relayConfig struct {
	idle        time.Duration
	writeBlock  time.Duration
	linger      time.Duration
	upLimiter   ByteLimiter // client -> node
	downLimiter ByteLimiter // node -> client
}

// relayDuplex copies bytes in both directions until both directions finish or
// the linger bound is reached. It implements the half close / linger timing of
// the attachment (chapter 3.4 / 3.6): a read EOF or read error half-closes the
// write direction of the peer and the remaining direction is allowed to drain
// for at most cfg.linger.
func relayDuplex(ctx context.Context, client, upstream halfConn, cfg relayConfig) (up, down int64, err error) {
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			if upstream.closeFn != nil {
				_ = upstream.closeFn()
			}
			if client.closeFn != nil {
				_ = client.closeFn()
			}
		})
	}
	defer closeAll()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			closeAll()
		case <-stop:
		}
	}()

	type halfResult struct {
		n   int64
		err error
	}
	upCh := make(chan halfResult, 1)
	downCh := make(chan halfResult, 1)
	go func() {
		n, e := copyHalf(ctx, upstream, client, cfg.idle, cfg.writeBlock, cfg.upLimiter)
		upCh <- halfResult{n: n, err: e}
	}()
	go func() {
		n, e := copyHalf(ctx, client, upstream, cfg.idle, cfg.writeBlock, cfg.downLimiter)
		downCh <- halfResult{n: n, err: e}
	}()

	var upRes, downRes halfResult
	firstUp := false
	select {
	case upRes = <-upCh:
		firstUp = true
	case downRes = <-downCh:
	}

	timer := time.NewTimer(cfg.linger)
	defer timer.Stop()
	waitOther := func(ch chan halfResult, dst *halfResult) {
		select {
		case *dst = <-ch:
		case <-timer.C:
			// Linger budget exhausted: force both sides closed so the
			// remaining copy loop cannot keep the connection alive.
			closeAll()
			*dst = <-ch
		case <-ctx.Done():
			closeAll()
			*dst = <-ch
		}
	}
	if firstUp {
		waitOther(downCh, &downRes)
	} else {
		waitOther(upCh, &upRes)
	}
	up, down = upRes.n, downRes.n
	switch {
	case upRes.err != nil:
		err = upRes.err
	case downRes.err != nil:
		err = downRes.err
	}
	return up, down, err
}

// copyHalf copies one direction. On EOF or a read error it half-closes the
// write direction of the peer so the peer sees a clean FIN, then returns.
func copyHalf(ctx context.Context, dst, src halfConn, idle, writeBlock time.Duration, lim ByteLimiter) (int64, error) {
	bp := getRelayBuf()
	defer putRelayBuf(bp)
	buf := *bp
	var total int64
	for {
		if src.setReadDeadline != nil {
			_ = src.setReadDeadline(time.Now().Add(idle))
		}
		nr, rerr := src.r.Read(buf)
		if nr > 0 {
			if lim != nil {
				if werr := lim.WaitN(ctx, nr); werr != nil {
					if dst.closeWrite != nil {
						_ = dst.closeWrite()
					}
					return total, fmt.Errorf("proxy: bandwidth limiter: %w", werr)
				}
			}
			if dst.setWriteDeadline != nil {
				_ = dst.setWriteDeadline(time.Now().Add(writeBlock))
			}
			if werr := writeFull(dst.w, buf[:nr]); werr != nil {
				return total, werr
			}
			total += int64(nr)
		}
		if rerr != nil {
			if dst.closeWrite != nil {
				_ = dst.closeWrite()
			}
			if errors.Is(rerr, io.EOF) {
				return total, nil
			}
			return total, rerr
		}
	}
}
