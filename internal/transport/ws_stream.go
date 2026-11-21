package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"proxygw/internal/protocol"
)

// wsStream is one logical bidirectional stream multiplexed over a wsConn.
//
// Receive side: the connection reader appends DATA payloads to buf and enforces
// the per stream and connection receive windows. Read consumes buf and hands
// WINDOW credit back. Write side: Write reserves flow control credit and
// queues DATA frames on the connection's single writer.
type wsStream struct {
	conn       *wsConn
	id         uint32
	peerOpened bool

	// rmu guards buf, readNotify, remoteFin and local wake-ups.
	rmu        sync.Mutex
	buf        bytes.Buffer
	readNotify chan struct{}
	remoteFin  bool
	readClosed atomic.Bool

	// openMeta carries the OPEN payload for peer opened streams; openResult
	// carries OPEN_OK/OPEN_ERR for locally opened streams.
	openMeta   chan []byte
	openResult chan []byte

	rst atomic.Pointer[StreamResetError]
	// released is set once the stream left the connection stream table; no
	// frames or window updates may be sent for it afterwards.
	released atomic.Bool

	// writeMu serializes the local writer: OPEN, DATA, FIN and CloseWrite must
	// keep their program order on the wire.
	writeMu     sync.Mutex
	writeClosed atomic.Bool

	// dmu guards deadlines; the notify channels wake blocked operations when a
	// deadline is changed from another goroutine.
	dmu       sync.Mutex
	rdl, wdl  time.Time
	rdlNotify chan struct{}
	wdlNotify chan struct{}

	// Guarded by conn.windowMu:
	sendWindow  int64
	recvWindow  int64
	recvPending int64

	releaseOnce sync.Once
}

// newWSPeerStream creates a stream from an incoming OPEN frame.
func newWSPeerStream(c *wsConn, id uint32, meta []byte) *wsStream {
	s := &wsStream{
		conn:       c,
		id:         id,
		peerOpened: true,
		readNotify: make(chan struct{}),
		openMeta:   make(chan []byte, 1),
		rdlNotify:  make(chan struct{}),
		wdlNotify:  make(chan struct{}),
	}
	if meta == nil {
		meta = []byte{}
	}
	s.openMeta <- meta
	c.windowMu.Lock()
	s.sendWindow = DefaultStreamWindow
	s.recvWindow = DefaultStreamWindow
	c.windowMu.Unlock()
	return s
}

// newWSLocalStream creates a locally initiated stream.
func newWSLocalStream(c *wsConn, id uint32) *wsStream {
	s := &wsStream{
		conn:       c,
		id:         id,
		readNotify: make(chan struct{}),
		openResult: make(chan []byte, 1),
		rdlNotify:  make(chan struct{}),
		wdlNotify:  make(chan struct{}),
	}
	c.windowMu.Lock()
	s.sendWindow = DefaultStreamWindow
	s.recvWindow = DefaultStreamWindow
	c.windowMu.Unlock()
	return s
}

// ID returns the wire stream id (useful for diagnostics and tests).
func (s *wsStream) ID() uint32 { return s.id }

// Read implements io.Reader.
func (s *wsStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if err := s.conn.doneErr(); err != nil {
			return 0, err
		}
		if rerr := s.rst.Load(); rerr != nil {
			return 0, rerr
		}
		if s.readClosed.Load() {
			return 0, fmt.Errorf("%w: read direction closed", ErrStreamClosed)
		}
		rdl, rdlNotify := s.readDeadline()
		s.rmu.Lock()
		if s.buf.Len() > 0 {
			n, err := s.buf.Read(p)
			s.rmu.Unlock()
			if n > 0 {
				s.conn.consumeReceive(s, int64(n))
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return n, err
			}
			return n, nil
		}
		if s.remoteFin {
			s.rmu.Unlock()
			return 0, io.EOF
		}
		notify := s.readNotify
		s.rmu.Unlock()
		if err := s.conn.waitAny(notify, rdlNotify, rdl, "read"); err != nil {
			return 0, err
		}
	}
}

// Write implements io.Writer. Large writes are split into frame sized chunks;
// each chunk requires stream and connection send credit.
func (s *wsStream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for total < len(p) {
		n := len(p) - total
		if n > protocol.MaxFramePayload {
			n = protocol.MaxFramePayload
		}
		s.writeMu.Lock()
		if err := s.writeStateErr(); err != nil {
			s.writeMu.Unlock()
			return total, err
		}
		wdl, wdlNotify := s.writeDeadline()
		if err := s.conn.acquireSendCredit(s, int64(n), wdl, wdlNotify); err != nil {
			s.writeMu.Unlock()
			return total, err
		}
		err := s.conn.enqueueDataFrame(protocol.FrameData, s.id, p[total:total+n], wdl)
		if err != nil {
			s.conn.refundSendCredit(s, int64(n))
			s.writeMu.Unlock()
			return total, err
		}
		s.writeMu.Unlock()
		total += n
	}
	return total, nil
}

// WriteOpen sends the OPEN frame that creates this stream on the peer.
func (s *wsStream) WriteOpen(meta []byte) error {
	if s.peerOpened {
		return fmt.Errorf("transport: ws: stream 0x%08x was opened by the peer", s.id)
	}
	if len(meta) > protocol.MaxFramePayload {
		return fmt.Errorf("transport: ws: OPEN metadata %d bytes exceeds frame payload limit %d", len(meta), protocol.MaxFramePayload)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.writeStateErr(); err != nil {
		return err
	}
	wdl, _ := s.writeDeadline()
	return s.conn.enqueueDataFrame(protocol.FrameOpen, s.id, meta, wdl)
}

// ReadOpen returns the OPEN metadata sent by the peer.
func (s *wsStream) ReadOpen(ctx context.Context) ([]byte, error) {
	if s.openMeta == nil {
		return nil, fmt.Errorf("%w: stream 0x%08x carries no peer OPEN metadata", ErrOpenUnavailable, s.id)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case meta := <-s.openMeta:
		if meta == nil {
			meta = []byte{}
		}
		return meta, nil
	case <-s.conn.done:
		return nil, s.conn.lastErr()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// WriteOpenResult sends the OPEN_OK/OPEN_ERR result back to the opener.
func (s *wsStream) WriteOpenResult(result []byte) error {
	if !s.peerOpened {
		return fmt.Errorf("transport: ws: only the stream receiver writes the OPEN result")
	}
	if len(result) == 0 {
		return errors.New("transport: ws: empty OPEN result")
	}
	if err := s.conn.doneErr(); err != nil {
		return err
	}
	if rerr := s.rst.Load(); rerr != nil {
		return rerr
	}
	typ := protocol.FrameOpenOK
	if result[0] != 0 {
		typ = protocol.FrameOpenErr
	}
	// Result frames ride the high priority queue; the opener buffers any data
	// that arrives before the result.
	return s.conn.enqueueCtrlFrame(context.Background(), typ, s.id, result)
}

// ReadOpenResult waits for the OPEN build result from the stream receiver.
func (s *wsStream) ReadOpenResult(ctx context.Context) ([]byte, error) {
	if s.openResult == nil {
		return nil, fmt.Errorf("%w: stream 0x%08x was opened by the peer", ErrOpenUnavailable, s.id)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if rerr := s.rst.Load(); rerr != nil {
			return nil, rerr
		}
		if err := s.conn.doneErr(); err != nil {
			return nil, err
		}
		s.rmu.Lock()
		notify := s.readNotify
		s.rmu.Unlock()
		select {
		case result := <-s.openResult:
			if result == nil {
				result = []byte{}
			}
			return result, nil
		case <-notify:
			continue
		case <-s.conn.done:
			return nil, s.conn.lastErr()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// CloseWrite sends FIN: the local write direction is half-closed, reads stay
// possible until the peer FIN arrives. It is idempotent.
func (s *wsStream) CloseWrite() error {
	if s.writeClosed.Load() {
		return nil
	}
	if err := s.conn.doneErr(); err != nil {
		return err
	}
	if rerr := s.rst.Load(); rerr != nil {
		return rerr
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.writeClosed.Load() {
		return nil
	}
	if err := s.writeStateErr(); err != nil {
		return err
	}
	s.writeClosed.Store(true)
	wdl, _ := s.writeDeadline()
	if err := s.conn.enqueueDataFrame(protocol.FrameFin, s.id, nil, wdl); err != nil {
		// The FIN could not be queued (connection closed or write deadline):
		// reset the stream so both sides release it instead of leaving a half
		// closed stream dangling until the connection dies.
		s.writeClosed.Store(false)
		s.markReset(&StreamResetError{Code: 1})
		return err
	}
	s.maybeRelease()
	return nil
}

// CloseRead cancels the local read direction. Buffered bytes are discarded and
// their window credit is returned so the peer is not stalled; a later FIN still
// releases the stream. The wire protocol has no "stop sending" frame that keeps
// the write direction alive, so unlike QUIC's STOP_SENDING the peer is not
// signalled: it can keep sending until it FINs and the transport discards and
// credits those bytes.
func (s *wsStream) CloseRead() error {
	if err := s.conn.doneErr(); err != nil {
		return err
	}
	if s.released.Load() {
		return nil
	}
	if s.readClosed.Swap(true) {
		return nil
	}
	s.rmu.Lock()
	pending := int64(s.buf.Len())
	s.buf.Reset()
	s.wakeReadLocked()
	s.rmu.Unlock()
	if pending > 0 {
		s.conn.consumeReceive(s, pending)
	}
	s.maybeRelease()
	return nil
}

// Reset terminates the stream abnormally and tells the peer with an RST frame.
func (s *wsStream) Reset(code uint64) error {
	if err := s.conn.doneErr(); err != nil {
		return err
	}
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, code)
	if !s.markReset(&StreamResetError{Code: code}) {
		return nil
	}
	_ = s.conn.enqueueCtrlFrame(context.Background(), protocol.FrameRST, s.id, payload)
	return nil
}

// SetDeadline implements Stream.
func (s *wsStream) SetDeadline(t time.Time) error {
	s.dmu.Lock()
	s.rdl, s.wdl = t, t
	close(s.rdlNotify)
	s.rdlNotify = make(chan struct{})
	close(s.wdlNotify)
	s.wdlNotify = make(chan struct{})
	s.dmu.Unlock()
	return nil
}

// SetReadDeadline implements Stream.
func (s *wsStream) SetReadDeadline(t time.Time) error {
	s.dmu.Lock()
	s.rdl = t
	close(s.rdlNotify)
	s.rdlNotify = make(chan struct{})
	s.dmu.Unlock()
	return nil
}

// SetWriteDeadline implements Stream.
func (s *wsStream) SetWriteDeadline(t time.Time) error {
	s.dmu.Lock()
	s.wdl = t
	close(s.wdlNotify)
	s.wdlNotify = make(chan struct{})
	s.dmu.Unlock()
	return nil
}

// readDeadline returns the value and wake channel of the read deadline.
func (s *wsStream) readDeadline() (time.Time, <-chan struct{}) {
	s.dmu.Lock()
	defer s.dmu.Unlock()
	return s.rdl, s.rdlNotify
}

// writeDeadline returns the value and wake channel of the write deadline.
func (s *wsStream) writeDeadline() (time.Time, <-chan struct{}) {
	s.dmu.Lock()
	defer s.dmu.Unlock()
	return s.wdl, s.wdlNotify
}

// writeStateErr reports why the write direction cannot be used.
func (s *wsStream) writeStateErr() error {
	if err := s.conn.doneErr(); err != nil {
		return err
	}
	if rerr := s.rst.Load(); rerr != nil {
		return rerr
	}
	if s.writeClosed.Load() {
		return fmt.Errorf("%w: write direction closed", ErrStreamClosed)
	}
	return nil
}

// wakeReadLocked notifies blocked readers. The caller must hold rmu.
func (s *wsStream) wakeReadLocked() {
	close(s.readNotify)
	s.readNotify = make(chan struct{})
}

// markReset records the first reset cause and tears the stream down.
func (s *wsStream) markReset(rerr *StreamResetError) bool {
	if !s.rst.CompareAndSwap(nil, rerr) {
		return false
	}
	s.conn.broadcastSendWindow()
	s.rmu.Lock()
	s.wakeReadLocked()
	s.rmu.Unlock()
	s.release()
	return true
}

// maybeRelease frees the stream once both directions are closed.
func (s *wsStream) maybeRelease() {
	if s.rst.Load() != nil {
		s.release()
		return
	}
	s.rmu.Lock()
	remoteFin := s.remoteFin
	s.rmu.Unlock()
	if remoteFin && s.writeClosed.Load() {
		s.release()
	}
}

// release unregisters the stream exactly once.
func (s *wsStream) release() {
	s.releaseOnce.Do(func() {
		s.released.Store(true)
		s.conn.releaseBufferedCredit(s)
		s.conn.removeStream(s)
		s.conn.broadcastSendWindow()
		s.rmu.Lock()
		s.wakeReadLocked()
		s.rmu.Unlock()
		s.conn.flushConnRecvPending()
	})
}
