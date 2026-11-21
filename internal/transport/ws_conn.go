package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"proxygw/internal/protocol"
)

// wsWriteRequest is one encoded protocol frame queued for the single writer
// goroutine. deadline is the writer goroutine's websocket write deadline.
type wsWriteRequest struct {
	buf      []byte
	deadline time.Time
}

// wsConn implements Conn over a single multiplexed WebSocket connection.
//
// Concurrency model (attachment chapter 8):
//   - exactly one goroutine reads from the websocket and dispatches frames;
//   - exactly one goroutine writes frames, fed by a high priority control queue
//     and a bounded data queue (callers are backpressured when full);
//   - streams never write to the websocket directly.
type wsConn struct {
	role     wsRole
	ws       *websocket.Conn
	opts     WSOptions
	maxFrame int
	// windowStall is the per stream send window stall budget (0 disables it).
	windowStall time.Duration
	closeHook   func(*wsConn)

	done      chan struct{}
	closeOnce sync.Once
	errMu     sync.Mutex
	err       error

	wg sync.WaitGroup

	ctrlCh      chan wsWriteRequest
	dataCh      chan wsWriteRequest
	inboundCtrl chan protocol.Frame
	acceptCh    chan *wsStream

	streamsMu sync.Mutex
	streams   map[uint32]*wsStream
	// recentlyClosed remembers stream ids released within the last few seconds
	// so late DATA/FIN/WINDOW/RST frames produced by a normal reset are dropped
	// silently instead of being counted as protocol violations (a busy
	// connection with periodic client cancellations would otherwise kill itself
	// after wsMaxLateFrames frames).
	recentMu       sync.Mutex
	recentlyClosed map[uint32]time.Time

	epoch    atomic.Uint32
	epochSet atomic.Bool
	nextSeq  atomic.Uint32
	late     atomic.Int32

	windowMu        sync.Mutex
	connSendWindow  int64
	connRecvWindow  int64
	connRecvPending int64
	connRecvMax     int64
	sendNotify      chan struct{}

	control *wsControl
}

// newWSConn wires a websocket connection into the mux and starts the I/O
// goroutines. The caller must not use ws after this call.
func newWSConn(ws *websocket.Conn, role wsRole, opts WSOptions, closeHook func(*wsConn)) *wsConn {
	maxFrame := opts.MaxFrameBytes
	if maxFrame <= 0 || maxFrame > protocol.MaxFramePayload {
		maxFrame = protocol.MaxFramePayload
	}
	ws.SetReadLimit(wsReadLimit(opts, maxFrame))
	_ = ws.SetReadDeadline(time.Time{})

	ctrlQueue := opts.WriteQueueFrames
	if ctrlQueue <= 0 {
		ctrlQueue = wsDefaultWriteQueueFrames
	}
	c := &wsConn{
		role:           role,
		ws:             ws,
		opts:           opts,
		maxFrame:       maxFrame,
		windowStall:    opts.WindowStall,
		closeHook:      closeHook,
		done:           make(chan struct{}),
		ctrlCh:         make(chan wsWriteRequest, wsDefaultControlQueueFrames),
		dataCh:         make(chan wsWriteRequest, ctrlQueue),
		inboundCtrl:    make(chan protocol.Frame, wsDefaultControlQueueFrames),
		acceptCh:       make(chan *wsStream, wsDefaultStreamAcceptQueue),
		streams:        make(map[uint32]*wsStream),
		recentlyClosed: make(map[uint32]time.Time),
		sendNotify:     make(chan struct{}),
	}
	c.connSendWindow = DefaultConnWindow
	c.connRecvWindow = DefaultConnWindow
	c.connRecvMax = DefaultConnWindow
	if role == wsRoleClient {
		// Dialer initiated stream ids are odd.
		c.nextSeq.Store(1)
	} else {
		// Listener initiated stream ids are even.
		c.nextSeq.Store(2)
	}
	c.control = newWSControl(c)
	c.wg.Add(2)
	go c.readLoop()
	go c.writeLoop()
	return c
}

// wsReadLimit returns the gorilla per message read limit.
func wsReadLimit(opts WSOptions, maxFrame int) int64 {
	if opts.ReadLimit > 0 {
		return opts.ReadLimit
	}
	return int64(maxFrame + protocol.FrameHeaderLen)
}

// Kind implements Conn.
func (c *wsConn) Kind() Kind { return KindWS }

// LocalAddr implements Conn.
func (c *wsConn) LocalAddr() net.Addr { return c.ws.LocalAddr() }

// RemoteAddr implements Conn.
func (c *wsConn) RemoteAddr() net.Addr { return c.ws.RemoteAddr() }

// HandshakeComplete reports whether the websocket upgrade finished. DialWS and
// the listener handler only return after a successful upgrade, so this is
// always true for a usable wsConn.
func (c *wsConn) HandshakeComplete() bool { return true }

// SetEpoch implements EpochSetter: stream ids created from now on embed epoch.
// Incoming data frames are checked against the epoch once SetEpoch has been
// called; before that any epoch is accepted so that streams opened immediately
// after HELLO_ACK cannot be dropped by the epoch race between the session FSM
// and the transport reader goroutine.
func (c *wsConn) SetEpoch(epoch uint32) {
	c.epoch.Store(epoch & protocol.MaxEpoch)
	c.epochSet.Store(true)
}

// doneErr returns the connection error when the connection is already closed.
func (c *wsConn) doneErr() error {
	select {
	case <-c.done:
		return c.lastErr()
	default:
		return nil
	}
}

// lastErr returns the terminal connection error.
func (c *wsConn) lastErr() error {
	c.errMu.Lock()
	err := c.err
	c.errMu.Unlock()
	if err == nil {
		return ErrConnClosed
	}
	return err
}

// OpenStream opens a locally initiated logical stream. It only allocates the
// stream id; the OPEN frame is emitted by WriteOpen.
func (c *wsConn) OpenStream(ctx context.Context) (Stream, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if err := c.doneErr(); err != nil {
		return nil, err
	}
	id, err := c.allocStreamID()
	if err != nil {
		return nil, err
	}
	s := newWSLocalStream(c, id)
	c.streamsMu.Lock()
	c.streams[id] = s
	c.streamsMu.Unlock()
	return s, nil
}

// allocStreamID allocates the next unused stream id for this side.
func (c *wsConn) allocStreamID() (uint32, error) {
	// nextSeq starts at 1 (dialer) or 2 (listener) and advances by two, so
	// both endpoints can open streams concurrently without colliding.
	seq := c.nextSeq.Add(2) - 2
	if seq > protocol.MaxStreamSequence {
		return 0, fmt.Errorf("transport: ws: stream id space exhausted")
	}
	return protocol.MakeStreamID(c.epoch.Load(), seq), nil
}

// AcceptStream waits for a peer initiated logical stream.
func (c *wsConn) AcceptStream(ctx context.Context) (Stream, error) {
	if err := c.doneErr(); err != nil {
		return nil, err
	}
	select {
	case s := <-c.acceptCh:
		if err := c.doneErr(); err != nil {
			return nil, err
		}
		return s, nil
	case <-c.done:
		return nil, c.lastErr()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Control returns the implicit connection level control channel.
func (c *wsConn) Control(ctx context.Context) (ControlStream, error) {
	if err := c.doneErr(); err != nil {
		return nil, err
	}
	return c.control, nil
}

// CloseWithError closes the connection. It is idempotent.
func (c *wsConn) CloseWithError(code uint64, reason string) error {
	c.closeWithError(fmt.Errorf("%w (ws code %d: %s)", ErrConnClosed, code, reason))
	return nil
}

// closeWithError tears the connection down once. It unblocks all stream and
// control waiters by closing c.done and closing the underlying websocket.
func (c *wsConn) closeWithError(err error) {
	if err == nil {
		err = ErrConnClosed
	}
	c.closeOnce.Do(func() {
		c.errMu.Lock()
		c.err = err
		c.errMu.Unlock()
		close(c.done)
		c.control.closeInternal()
		if c.closeHook != nil {
			c.closeHook(c)
		}
		// Best effort close message, then tear down the TCP connection which
		// unblocks the reader and writer goroutines.
		_ = c.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(wsCloseDeadline))
		_ = c.ws.Close()
	})
}

// waitGoroutines blocks until the reader and writer goroutines exited. Package
// tests use it to assert cleanup; it is not part of the Conn contract.
func (c *wsConn) waitGoroutines(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

// readLoop is the only reader of the websocket. It validates each binary
// message as exactly one protocol frame and dispatches it.
func (c *wsConn) readLoop() {
	defer c.wg.Done()
	for {
		mt, msg, err := c.ws.ReadMessage()
		if err != nil {
			c.failRead(err)
			return
		}
		if mt != websocket.BinaryMessage {
			c.closeWithError(fmt.Errorf("%w: unexpected websocket message type %d", ErrProtocol, mt))
			return
		}
		r := bytes.NewReader(msg)
		frame, err := protocol.ReadFrame(r, c.maxFrame)
		if err != nil {
			c.closeWithError(fmt.Errorf("%w: websocket frame: %w", ErrProtocol, err))
			return
		}
		if r.Len() != 0 {
			c.closeWithError(fmt.Errorf("%w: websocket message carries %d trailing bytes", ErrProtocol, r.Len()))
			return
		}
		if err := c.dispatch(frame); err != nil {
			c.closeWithError(err)
			return
		}
	}
}

// failRead normalises a websocket read failure.
func (c *wsConn) failRead(err error) {
	if c.doneErr() != nil {
		return
	}
	if errors.Is(err, websocket.ErrReadLimit) {
		c.closeWithError(fmt.Errorf("%w: websocket message exceeds read limit", ErrProtocol))
		return
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		c.closeWithError(fmt.Errorf("%w: websocket read deadline exceeded", ErrConnClosed))
		return
	}
	c.closeWithError(fmt.Errorf("%w: websocket read: %w", ErrConnClosed, err))
}

// writeLoop is the only data writer of the websocket. Control frames are
// served first; a frame is never split and frames are never interleaved.
func (c *wsConn) writeLoop() {
	defer c.wg.Done()
	for {
		// Drain control frames first to keep heartbeats and window updates
		// responsive under a data flood.
		select {
		case <-c.done:
			return
		case req := <-c.ctrlCh:
			if !c.writeFrame(req) {
				return
			}
			continue
		default:
		}
		select {
		case <-c.done:
			return
		case req := <-c.ctrlCh:
			if !c.writeFrame(req) {
				return
			}
		case req := <-c.dataCh:
			if !c.writeFrame(req) {
				return
			}
		}
	}
}

// writeFrame writes one websocket binary message.
func (c *wsConn) writeFrame(req wsWriteRequest) bool {
	if err := c.ws.SetWriteDeadline(req.deadline); err != nil {
		c.failWrite(err)
		return false
	}
	if err := c.ws.WriteMessage(websocket.BinaryMessage, req.buf); err != nil {
		c.failWrite(err)
		return false
	}
	return true
}

// failWrite normalises a websocket write failure. A partially written message
// corrupts the frame stream, so the connection is always torn down.
func (c *wsConn) failWrite(err error) {
	if c.doneErr() != nil {
		return
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		c.closeWithError(fmt.Errorf("%w: websocket write deadline exceeded", ErrConnClosed))
		return
	}
	c.closeWithError(fmt.Errorf("%w: websocket write: %w", ErrConnClosed, err))
}

// dispatch routes one decoded frame.
func (c *wsConn) dispatch(f protocol.Frame) error {
	if f.StreamID == protocol.ControlStreamID {
		switch {
		case f.Type.IsControl():
			select {
			case c.inboundCtrl <- f:
				return nil
			case <-c.control.closed:
				// The upper layer closed its control consumer; drop frames
				// instead of stalling the data path.
				return nil
			case <-c.done:
				return c.lastErr()
			}
		case f.Type == protocol.FrameWindow:
			// Connection level flow control credit.
			return c.onWindow(f)
		default:
			return fmt.Errorf("%w: frame %s is not allowed on the control channel", ErrProtocol, f.Type)
		}
	}
	epoch, seq := protocol.SplitStreamID(f.StreamID)
	if seq == 0 {
		return fmt.Errorf("%w: frame %s uses reserved stream id 0x%08x", ErrProtocol, f.Type, f.StreamID)
	}
	if c.epochSet.Load() && epoch != c.epoch.Load() {
		return c.dropUnknown(f)
	}
	switch f.Type {
	case protocol.FrameOpen:
		return c.onOpen(f)
	case protocol.FrameOpenOK, protocol.FrameOpenErr:
		return c.onOpenResult(f)
	case protocol.FrameData:
		return c.onData(f)
	case protocol.FrameFin:
		return c.onFin(f)
	case protocol.FrameWindow:
		return c.onWindow(f)
	case protocol.FrameRST:
		return c.onReset(f)
	default:
		return fmt.Errorf("%w: unexpected frame %s on data stream %d", ErrProtocol, f.Type, f.StreamID)
	}
}

// dropLate counts a stale frame (old epoch or unknown stream) and fails the
// connection once the peer exceeds the tolerated amount.
func (c *wsConn) dropLate(kind string) error {
	if n := c.late.Add(1); n > wsMaxLateFrames {
		return fmt.Errorf("%w: peer sent %d late %s frames", ErrProtocol, n, kind)
	}
	return nil
}

// lookupStream returns a live stream by id.
func (c *wsConn) lookupStream(id uint32) *wsStream {
	c.streamsMu.Lock()
	s := c.streams[id]
	c.streamsMu.Unlock()
	return s
}

// removeStream unregisters a released stream.
func (c *wsConn) removeStream(s *wsStream) {
	c.streamsMu.Lock()
	if cur, ok := c.streams[s.id]; ok && cur == s {
		delete(c.streams, s.id)
	}
	c.streamsMu.Unlock()
	c.rememberClosed(s.id)
}

// closedStreamGrace is how long a released stream id is remembered. Frames
// queued before a reset can take a few RTTs to arrive; a late frame for an id
// released within this window is a normal race, not an attack.
const closedStreamGrace = 10 * time.Second

func (c *wsConn) rememberClosed(id uint32) {
	now := time.Now()
	c.recentMu.Lock()
	c.recentlyClosed[id] = now
	if len(c.recentlyClosed) > 2048 {
		for k, ts := range c.recentlyClosed {
			if now.Sub(ts) > closedStreamGrace {
				delete(c.recentlyClosed, k)
			}
		}
	}
	c.recentMu.Unlock()
}

func (c *wsConn) isRecentlyClosed(id uint32) bool {
	c.recentMu.Lock()
	ts, ok := c.recentlyClosed[id]
	c.recentMu.Unlock()
	return ok && time.Since(ts) <= closedStreamGrace
}

// dropUnknown handles a frame for a stream id that is not in the stream table:
// recently released ids are silent (normal late frames), truly unknown or
// future-epoch ids feed the late-frame budget.
func (c *wsConn) dropUnknown(f protocol.Frame) error {
	if c.isRecentlyClosed(f.StreamID) {
		return nil
	}
	return c.dropLate(string(f.Type))
}

// onOpen handles a peer OPEN frame and queues the new stream for AcceptStream.
func (c *wsConn) onOpen(f protocol.Frame) error {
	_, seq := protocol.SplitStreamID(f.StreamID)
	if !c.isPeerSeq(seq) {
		return fmt.Errorf("%w: peer used locally owned stream id 0x%08x for OPEN", ErrProtocol, f.StreamID)
	}
	meta := make([]byte, len(f.Payload))
	copy(meta, f.Payload)
	c.streamsMu.Lock()
	if _, ok := c.streams[f.StreamID]; ok {
		c.streamsMu.Unlock()
		return fmt.Errorf("%w: duplicate OPEN for stream 0x%08x", ErrProtocol, f.StreamID)
	}
	s := newWSPeerStream(c, f.StreamID, meta)
	c.streams[f.StreamID] = s
	c.streamsMu.Unlock()
	select {
	case c.acceptCh <- s:
		return nil
	case <-c.done:
		return c.lastErr()
	}
}

// onOpenResult handles the stream build result sent back to the opener.
func (c *wsConn) onOpenResult(f protocol.Frame) error {
	_, seq := protocol.SplitStreamID(f.StreamID)
	if !c.isLocalSeq(seq) {
		return fmt.Errorf("%w: %s for peer owned stream 0x%08x", ErrProtocol, f.Type, f.StreamID)
	}
	if len(f.Payload) == 0 {
		return fmt.Errorf("%w: empty %s payload for stream 0x%08x", ErrProtocol, f.Type, f.StreamID)
	}
	s := c.lookupStream(f.StreamID)
	if s == nil {
		return c.dropUnknown(f)
	}
	if s.openResult == nil {
		return fmt.Errorf("%w: unexpected %s for stream 0x%08x", ErrProtocol, f.Type, f.StreamID)
	}
	payload := make([]byte, len(f.Payload))
	copy(payload, f.Payload)
	select {
	case s.openResult <- payload:
		return nil
	default:
		return fmt.Errorf("%w: duplicate %s for stream 0x%08x", ErrProtocol, f.Type, f.StreamID)
	}
}

// onData delivers stream payload bytes.
func (c *wsConn) onData(f protocol.Frame) error {
	s := c.lookupStream(f.StreamID)
	if s == nil {
		return c.dropUnknown(f)
	}
	return c.deliverData(s, f.Payload)
}

// onFin handles the peer half-close.
func (c *wsConn) onFin(f protocol.Frame) error {
	s := c.lookupStream(f.StreamID)
	if s == nil {
		return c.dropUnknown(f)
	}
	s.rmu.Lock()
	if s.remoteFin {
		s.rmu.Unlock()
		return fmt.Errorf("%w: duplicate FIN for stream 0x%08x", ErrProtocol, f.StreamID)
	}
	s.remoteFin = true
	s.wakeReadLocked()
	s.rmu.Unlock()
	s.maybeRelease()
	return nil
}

// onWindow grants send credit to this connection or to one stream.
func (c *wsConn) onWindow(f protocol.Frame) error {
	delta, err := protocol.DecodeWindow(f.Payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	if delta == 0 {
		return nil
	}
	if f.StreamID == protocol.ControlStreamID {
		c.grantConnSendCredit(int64(delta))
		return nil
	}
	s := c.lookupStream(f.StreamID)
	if s == nil {
		return c.dropUnknown(f)
	}
	c.grantStreamSendCredit(s, int64(delta))
	return nil
}

// onReset aborts a stream because the peer reset it.
func (c *wsConn) onReset(f protocol.Frame) error {
	var code uint64
	switch len(f.Payload) {
	case 0:
	case 8:
		code = binary.BigEndian.Uint64(f.Payload)
	default:
		return fmt.Errorf("%w: invalid RST payload of %d bytes", ErrProtocol, len(f.Payload))
	}
	s := c.lookupStream(f.StreamID)
	if s == nil {
		return c.dropUnknown(f)
	}
	s.markReset(&StreamResetError{Code: code, Remote: true})
	return nil
}

// deliverData buffers stream payload and enforces the receive windows.
func (c *wsConn) deliverData(s *wsStream, payload []byte) error {
	n := int64(len(payload))
	c.windowMu.Lock()
	if n > s.recvWindow || n > c.connRecvWindow {
		streamRemaining, connRemaining := s.recvWindow, c.connRecvWindow
		c.windowMu.Unlock()
		return fmt.Errorf("%w: peer exceeded receive window for stream 0x%08x (data %d, stream credit %d, connection credit %d)",
			ErrProtocol, s.id, n, streamRemaining, connRemaining)
	}
	s.recvWindow -= n
	c.connRecvWindow -= n
	c.windowMu.Unlock()
	if n == 0 {
		return nil
	}
	s.rmu.Lock()
	if s.remoteFin {
		s.rmu.Unlock()
		return fmt.Errorf("%w: DATA after FIN for stream 0x%08x", ErrProtocol, s.id)
	}
	if s.readClosed.Load() || s.rst.Load() != nil {
		s.rmu.Unlock()
		// Nobody will consume these bytes; hand the credit back immediately so
		// the peer is not stalled by a locally closed read direction.
		c.consumeReceive(s, n)
		return nil
	}
	s.buf.Write(payload)
	s.wakeReadLocked()
	s.rmu.Unlock()
	return nil
}

// isLocalSeq reports whether seq belongs to this endpoint's id space.
func (c *wsConn) isLocalSeq(seq uint32) bool {
	if c.role == wsRoleClient {
		return seq%2 == 1
	}
	return seq%2 == 0
}

// isPeerSeq reports whether seq belongs to the peer's id space.
func (c *wsConn) isPeerSeq(seq uint32) bool { return !c.isLocalSeq(seq) }

// enqueueDataFrame encodes and queues a frame on the bounded data queue.
func (c *wsConn) enqueueDataFrame(typ protocol.FrameType, streamID uint32, payload []byte, deadline time.Time) error {
	buf, err := protocol.AppendFrame(nil, typ, streamID, payload)
	if err != nil {
		return fmt.Errorf("transport: ws encode %s frame: %w", typ, err)
	}
	return c.enqueue(c.dataCh, wsWriteRequest{buf: buf, deadline: deadline}, context.Background())
}

// enqueueCtrlFrame encodes and queues a frame on the high priority queue.
func (c *wsConn) enqueueCtrlFrame(ctx context.Context, typ protocol.FrameType, streamID uint32, payload []byte) error {
	buf, err := protocol.AppendFrame(nil, typ, streamID, payload)
	if err != nil {
		return fmt.Errorf("transport: ws encode %s frame: %w", typ, err)
	}
	req := wsWriteRequest{buf: buf}
	if ctx == nil {
		ctx = context.Background()
	}
	if dl, ok := ctx.Deadline(); ok {
		req.deadline = dl
	}
	return c.enqueue(c.ctrlCh, req, ctx)
}

// enqueue pushes a frame to a writer queue, applying backpressure with the
// request deadline and unblocking when the connection closes.
func (c *wsConn) enqueue(ch chan wsWriteRequest, req wsWriteRequest, ctx context.Context) error {
	if err := c.doneErr(); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Fast path: never allocate a timer when the queue has room.
	select {
	case ch <- req:
		return nil
	default:
	}
	if !req.deadline.IsZero() {
		d := time.Until(req.deadline)
		if d <= 0 {
			return deadlineError("enqueue")
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case ch <- req:
			return nil
		case <-c.done:
			return c.lastErr()
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return deadlineError("enqueue")
		}
	}
	select {
	case ch <- req:
		return nil
	case <-c.done:
		return c.lastErr()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// acquireSendCredit reserves n bytes of stream and connection send credit,
// waiting for WINDOW frames with the given deadline. When the connection has a
// window stall budget configured, a stream that waits longer than that budget
// is reset (the peer stopped consuming its receive window) instead of blocking
// the writer forever.
func (c *wsConn) acquireSendCredit(s *wsStream, n int64, deadline time.Time, deadlineNotify <-chan struct{}) error {
	var waitStart time.Time
	for {
		if err := s.writeStateErr(); err != nil {
			return err
		}
		if cerr := c.doneErr(); cerr != nil {
			return cerr
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return deadlineError("write")
		}
		c.windowMu.Lock()
		if c.connSendWindow >= n && s.sendWindow >= n {
			c.connSendWindow -= n
			s.sendWindow -= n
			c.windowMu.Unlock()
			return nil
		}
		notify := c.sendNotify
		c.windowMu.Unlock()
		if waitStart.IsZero() {
			waitStart = time.Now()
		}
		waitDeadline := deadline
		if c.windowStall > 0 {
			stallDeadline := waitStart.Add(c.windowStall)
			if waitDeadline.IsZero() || stallDeadline.Before(waitDeadline) {
				waitDeadline = stallDeadline
			}
		}
		if err := c.waitAny(notify, deadlineNotify, waitDeadline, "write"); err != nil {
			if c.windowStall > 0 && !waitStart.IsZero() && time.Since(waitStart) >= c.windowStall {
				s.markReset(&StreamResetError{Code: 2})
				return fmt.Errorf("%w: stream 0x%08x waited %s for WINDOW credit", ErrWindowStall, s.id, time.Since(waitStart).Round(time.Millisecond))
			}
			return err
		}
	}
}

// refundSendCredit returns credit reserved for a frame that could not be
// queued (deadline or connection close).
func (c *wsConn) refundSendCredit(s *wsStream, n int64) {
	c.windowMu.Lock()
	c.connSendWindow = satAdd(c.connSendWindow, n)
	s.sendWindow = satAdd(s.sendWindow, n)
	c.windowMu.Unlock()
}

// grantConnSendCredit adds connection level send credit.
func (c *wsConn) grantConnSendCredit(delta int64) {
	c.windowMu.Lock()
	c.connSendWindow = satAdd(c.connSendWindow, delta)
	c.broadcastSendWindowLocked()
	c.windowMu.Unlock()
}

// grantStreamSendCredit adds per stream send credit.
func (c *wsConn) grantStreamSendCredit(s *wsStream, delta int64) {
	c.windowMu.Lock()
	s.sendWindow = satAdd(s.sendWindow, delta)
	c.broadcastSendWindowLocked()
	c.windowMu.Unlock()
}

// broadcastSendWindowLocked wakes every writer waiting for send credit. The
// caller must hold windowMu.
func (c *wsConn) broadcastSendWindowLocked() {
	close(c.sendNotify)
	c.sendNotify = make(chan struct{})
}

// broadcastSendWindow wakes writers waiting for credit.
func (c *wsConn) broadcastSendWindow() {
	c.windowMu.Lock()
	c.broadcastSendWindowLocked()
	c.windowMu.Unlock()
}

// consumeReceive accounts n consumed receive bytes and returns WINDOW credit to
// the peer once the configured threshold has been reached.
func (c *wsConn) consumeReceive(s *wsStream, n int64) {
	if n <= 0 {
		return
	}
	if s.released.Load() {
		// The release path already returned the buffered connection credit; a
		// per-stream WINDOW frame for a released stream would be a late frame on
		// the peer side.
		return
	}
	c.windowMu.Lock()
	s.recvWindow += n
	s.recvPending += n
	c.connRecvWindow += n
	c.connRecvPending += n
	var streamDelta, connDelta int64
	if s.recvPending >= WindowUpdateThreshold {
		streamDelta = s.recvPending
		s.recvPending = 0
	}
	if c.connRecvPending >= WindowUpdateThreshold {
		connDelta = c.connRecvPending
		c.connRecvPending = 0
	}
	c.windowMu.Unlock()
	if streamDelta > 0 {
		_ = c.enqueueCtrlFrame(context.Background(), protocol.FrameWindow, s.id, encodeWindowDelta(streamDelta))
	}
	if connDelta > 0 {
		_ = c.enqueueCtrlFrame(context.Background(), protocol.FrameWindow, protocol.ControlStreamID, encodeWindowDelta(connDelta))
	}
}

// releaseBufferedCredit returns the connection level receive credit of bytes
// that were buffered by a stream which is now being released without the
// application consuming them. Without this the connection window would leak
// on every cancelled download.
func (c *wsConn) releaseBufferedCredit(s *wsStream) {
	s.rmu.Lock()
	buffered := int64(s.buf.Len())
	s.rmu.Unlock()
	if buffered <= 0 {
		return
	}
	// The stream was released (both directions closed). Any still buffered
	// payload stays readable for a caller that has not drained it yet, but its
	// connection level credit must be returned now so the peer is not stalled.
	c.windowMu.Lock()
	s.recvWindow += buffered
	c.connRecvWindow += buffered
	c.connRecvPending += buffered
	var delta int64
	if c.connRecvPending >= WindowUpdateThreshold {
		delta = c.connRecvPending
		c.connRecvPending = 0
	}
	c.windowMu.Unlock()
	if delta > 0 {
		_ = c.enqueueCtrlFrame(context.Background(), protocol.FrameWindow, protocol.ControlStreamID, encodeWindowDelta(delta))
	}
}

// flushConnRecvPending announces pending connection level credit, e.g. when a
// stream is released so its consumed bytes do not stay locked.
func (c *wsConn) flushConnRecvPending() {
	c.windowMu.Lock()
	delta := c.connRecvPending
	c.connRecvPending = 0
	c.windowMu.Unlock()
	if delta > 0 {
		_ = c.enqueueCtrlFrame(context.Background(), protocol.FrameWindow, protocol.ControlStreamID, encodeWindowDelta(delta))
	}
}

// encodeWindowDelta clamps a byte delta to the uint32 wire encoding.
func encodeWindowDelta(delta int64) []byte {
	if delta > math.MaxUint32 {
		delta = math.MaxUint32
	}
	return protocol.EncodeWindow(uint32(delta))
}

// waitAny blocks until either notify channel fires, the deadline passes or the
// connection closes. Nil channels are ignored.
func (c *wsConn) waitAny(a, b <-chan struct{}, deadline time.Time, op string) error {
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return deadlineError(op)
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-a:
			return nil
		case <-b:
			return nil
		case <-timer.C:
			return deadlineError(op)
		case <-c.done:
			return c.lastErr()
		}
	}
	select {
	case <-a:
		return nil
	case <-b:
		return nil
	case <-c.done:
		return c.lastErr()
	}
}
