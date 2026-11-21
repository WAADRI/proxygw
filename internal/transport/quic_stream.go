package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"proxygw/internal/protocol"
)

// maxOpenMetaLen bounds the length prefix used by the QUIC OPEN metadata and
// OPEN result encoding (2 byte big endian length).
const maxOpenMetaLen = 0xFFFF

// quicStream adapts a native quic.Stream to the transport Stream contract.
//
// The OPEN metadata and the build result travel as 2 byte length prefixed
// payloads at the start of each direction; plain data follows the metadata on
// the write direction.
type quicStream struct {
	conn   *quicConn
	stream quic.Stream

	// writeMu serializes all writes on this stream (Write, WriteOpen,
	// WriteOpenResult, CloseWrite): quic-go requires one writer per stream and
	// the length prefixed OPEN header must not interleave with data.
	writeMu sync.Mutex
	// readMu serializes framed metadata reads (ReadOpen, ReadOpenResult).
	readMu sync.Mutex
	// stateMu guards the local half-close and reset state.
	stateMu     sync.Mutex
	writeClosed bool
	readClosed  bool
	reset       bool
	resetCode   uint64
	// dmu guards the deadlines reported by Set*Deadline.
	dmu     sync.Mutex
	readDL  time.Time
	writeDL time.Time
}

func newQUICStream(conn *quicConn, st quic.Stream) *quicStream {
	return &quicStream{conn: conn, stream: st}
}

// Kind returns the transport kind.
func (s *quicStream) Kind() Kind { return KindQUIC }

// Write implements io.Writer on the raw stream data direction. Writes are
// serialized with WriteOpen/WriteOpenResult/CloseWrite so the OPEN header and
// the data can never interleave.
func (s *quicStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.localErr("write"); err != nil {
		return 0, err
	}
	n, err := s.stream.Write(p)
	if err != nil {
		return n, s.mapStreamErr("write", err)
	}
	return n, nil
}

// Read implements io.Reader on the raw stream data direction.
func (s *quicStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := s.localErr("read"); err != nil {
		return 0, err
	}
	n, err := s.stream.Read(p)
	if err != nil {
		return n, s.mapStreamErr("read", err)
	}
	return n, nil
}

// WriteOpen writes the length prefixed OPEN metadata.
func (s *quicStream) WriteOpen(meta []byte) error {
	return s.writeLenPrefixed("write open metadata", meta)
}

// ReadOpen reads the length prefixed peer OPEN metadata.
func (s *quicStream) ReadOpen(ctx context.Context) ([]byte, error) {
	return s.readLenPrefixed(ctx, "read open metadata")
}

// WriteOpenResult writes the length prefixed OPEN build result.
func (s *quicStream) WriteOpenResult(result []byte) error {
	return s.writeLenPrefixed("write open result", result)
}

// ReadOpenResult reads the length prefixed OPEN build result.
func (s *quicStream) ReadOpenResult(ctx context.Context) ([]byte, error) {
	return s.readLenPrefixed(ctx, "read open result")
}

// CloseWrite half-closes the write direction with a QUIC FIN. It is
// idempotent.
func (s *quicStream) CloseWrite() error {
	if cerr := s.conn.doneErr(); cerr != nil {
		return cerr
	}
	s.stateMu.Lock()
	if s.writeClosed {
		s.stateMu.Unlock()
		return nil
	}
	if s.reset {
		code := s.resetCode
		s.stateMu.Unlock()
		return &StreamResetError{Code: code}
	}
	s.stateMu.Unlock()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.stateMu.Lock()
	already := s.writeClosed
	reset := s.reset
	s.writeClosed = true
	s.stateMu.Unlock()
	if already || reset {
		return nil
	}
	if err := s.stream.Close(); err != nil {
		return s.mapStreamErr("close write", err)
	}
	return nil
}

// CloseRead cancels the read direction (QUIC STOP_SENDING).
func (s *quicStream) CloseRead() error {
	s.stateMu.Lock()
	already := s.readClosed
	s.readClosed = true
	s.stateMu.Unlock()
	if already {
		return nil
	}
	s.stream.CancelRead(quic.StreamErrorCode(0))
	return nil
}

// Reset aborts both directions with the given application code.
func (s *quicStream) Reset(code uint64) error {
	s.stateMu.Lock()
	if s.reset {
		s.stateMu.Unlock()
		return nil
	}
	s.reset = true
	s.resetCode = code
	s.stateMu.Unlock()
	s.stream.CancelRead(quic.StreamErrorCode(code))
	s.stream.CancelWrite(quic.StreamErrorCode(code))
	return nil
}

// SetDeadline implements Stream.
func (s *quicStream) SetDeadline(t time.Time) error {
	s.dmu.Lock()
	s.readDL, s.writeDL = t, t
	s.dmu.Unlock()
	if err := s.stream.SetDeadline(t); err != nil {
		return s.mapStreamErr("set deadline", err)
	}
	return nil
}

// SetReadDeadline implements Stream.
func (s *quicStream) SetReadDeadline(t time.Time) error {
	s.dmu.Lock()
	s.readDL = t
	s.dmu.Unlock()
	if err := s.stream.SetReadDeadline(t); err != nil {
		return s.mapStreamErr("set read deadline", err)
	}
	return nil
}

// SetWriteDeadline implements Stream.
func (s *quicStream) SetWriteDeadline(t time.Time) error {
	s.dmu.Lock()
	s.writeDL = t
	s.dmu.Unlock()
	if err := s.stream.SetWriteDeadline(t); err != nil {
		return s.mapStreamErr("set write deadline", err)
	}
	return nil
}

// localErr reports local state errors for one operation direction.
func (s *quicStream) localErr(op string) error {
	if cerr := s.conn.doneErr(); cerr != nil {
		return cerr
	}
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.reset {
		return &StreamResetError{Code: s.resetCode}
	}
	if op == "write" && s.writeClosed {
		return fmt.Errorf("%w: write direction closed", ErrStreamClosed)
	}
	if op == "read" && s.readClosed {
		return fmt.Errorf("%w: read direction closed", ErrStreamClosed)
	}
	return nil
}

// mapStreamErr normalises native quic stream errors.
func (s *quicStream) mapStreamErr(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	if cerr := s.conn.doneErr(); cerr != nil {
		return cerr
	}
	// A peer closing the whole connection aborts every stream; surface that as
	// the transport level connection error so callers can classify it.
	if cerr := s.conn.conn.Context().Err(); cerr != nil {
		s.conn.markClosed(cerr)
		return s.conn.lastErr()
	}
	var qerr *quic.StreamError
	if errors.As(err, &qerr) {
		return &StreamResetError{Code: uint64(qerr.ErrorCode), Remote: qerr.Remote}
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return deadlineError(op)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("transport: quic stream %s: %w", op, err)
}

func (s *quicStream) readDeadline() time.Time {
	s.dmu.Lock()
	defer s.dmu.Unlock()
	return s.readDL
}

func (s *quicStream) writeDeadlineValue() time.Time {
	s.dmu.Lock()
	defer s.dmu.Unlock()
	return s.writeDL
}

// writeLenPrefixed writes a 2 byte length prefixed payload.
func (s *quicStream) writeLenPrefixed(op string, payload []byte) error {
	if len(payload) > maxOpenMetaLen {
		return fmt.Errorf("transport: quic %s: payload %d bytes exceeds limit %d", op, len(payload), maxOpenMetaLen)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.localErr("write"); err != nil {
		return err
	}
	buf := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(payload)))
	copy(buf[2:], payload)
	if _, err := s.stream.Write(buf); err != nil {
		return s.mapStreamErr(op, err)
	}
	return nil
}

// readLenPrefixed reads a 2 byte length prefixed payload, honouring the
// context deadline and cancellation.
func (s *quicStream) readLenPrefixed(ctx context.Context, op string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.localErr("read"); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	restore := withCtxDeadline(ctx, func(t time.Time) error { return s.stream.SetReadDeadline(t) }, s.readDeadline())
	defer restore()
	var hdr [2]byte
	if _, err := io.ReadFull(s.stream, hdr[:]); err != nil {
		return nil, s.ctxReadErr(ctx, op, err)
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return nil, nil
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(s.stream, payload); err != nil {
		return nil, s.ctxReadErr(ctx, op, err)
	}
	return payload, nil
}

// ctxReadErr maps a metadata read error, preferring the context error when the
// operation was interrupted by cancellation rather than by peer activity.
func (s *quicStream) ctxReadErr(ctx context.Context, op string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return deadlineError(op)
	}
	return s.mapStreamErr(op, err)
}

// withCtxDeadline applies the earlier of the context deadline and the deadline
// already configured on the stream, unblocks the in-flight operation when the
// context is cancelled, and restores the configured deadline on return.
func withCtxDeadline(ctx context.Context, setDeadline func(time.Time) error, current time.Time) func() {
	effective := current
	if dl, ok := ctx.Deadline(); ok {
		effective = minDeadline(effective, dl)
	}
	_ = setDeadline(effective)
	if ctx.Done() == nil {
		return func() { _ = setDeadline(current) }
	}
	var mu sync.Mutex
	finished := false
	stop := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			mu.Lock()
			alreadyFinished := finished
			mu.Unlock()
			if alreadyFinished {
				return
			}
			_ = setDeadline(time.Now())
		case <-stop:
		}
	}()
	return func() {
		mu.Lock()
		finished = true
		mu.Unlock()
		close(stop)
		<-watcherDone
		_ = setDeadline(current)
	}
}

// quicControl is the connection level control stream.
type quicControl struct {
	conn   *quicConn
	stream quic.Stream

	wmu sync.Mutex
	rmu sync.Mutex
	dmu sync.Mutex
	rd  time.Time
	wr  time.Time

	closeOnce sync.Once
	closed    atomic.Bool
}

func newQUICControl(conn *quicConn, st quic.Stream) *quicControl {
	return &quicControl{conn: conn, stream: st}
}

// Send writes one control frame. It is safe for concurrent use; writes are
// serialized so frames never interleave.
func (c *quicControl) Send(ctx context.Context, typ protocol.FrameType, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(payload) > protocol.MaxFramePayload {
		return fmt.Errorf("%w: control payload %d exceeds limit %d", ErrProtocol, len(payload), protocol.MaxFramePayload)
	}
	if err := c.usable(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	buf, err := protocol.AppendFrame(nil, typ, protocol.ControlStreamID, payload)
	if err != nil {
		return fmt.Errorf("transport: quic control send: %w", err)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if err := c.usable(); err != nil {
		return err
	}
	c.dmu.Lock()
	current := c.wr
	c.dmu.Unlock()
	restore := withCtxDeadline(ctx, func(t time.Time) error { return c.stream.SetWriteDeadline(t) }, current)
	defer restore()
	if _, err := c.stream.Write(buf); err != nil {
		return c.mapControlErr(ctx, "send", err)
	}
	return nil
}

// Recv reads the next control frame, blocking until one is available, the
// context is cancelled or the control stream/connection is closed.
func (c *quicControl) Recv(ctx context.Context) (protocol.FrameType, []byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := c.usable(); err != nil {
		return 0, nil, err
	}
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if err := c.usable(); err != nil {
		return 0, nil, err
	}
	c.dmu.Lock()
	current := c.rd
	c.dmu.Unlock()
	restore := withCtxDeadline(ctx, func(t time.Time) error { return c.stream.SetReadDeadline(t) }, current)
	defer restore()
	frame, err := protocol.ReadFrame(c.stream, protocol.MaxFramePayload)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return 0, nil, ctxErr
		}
		return 0, nil, c.mapControlErr(ctx, "recv", err)
	}
	if frame.StreamID != protocol.ControlStreamID {
		return 0, nil, fmt.Errorf("%w: control frame %s carries stream id %d", ErrProtocol, frame.Type, frame.StreamID)
	}
	return frame.Type, frame.Payload, nil
}

// Close closes the local control channel. It is idempotent; a pending Recv is
// unblocked immediately.
func (c *quicControl) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.stream.CancelRead(quic.StreamErrorCode(0))
		_ = c.stream.Close()
	})
	return nil
}

func (c *quicControl) usable() error {
	if c.closed.Load() {
		return ErrControlClosed
	}
	if cerr := c.conn.doneErr(); cerr != nil {
		return cerr
	}
	return nil
}

func (c *quicControl) mapControlErr(ctx context.Context, op string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if cerr := c.conn.doneErr(); cerr != nil {
		return cerr
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return deadlineError("control " + op)
	}
	if errors.Is(err, io.EOF) {
		return ErrControlClosed
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("transport: quic control %s: %w", op, err)
}
