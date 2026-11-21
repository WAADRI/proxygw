package tunnel

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxygw/internal/fsm"
	"proxygw/internal/protocol"
	"proxygw/internal/transport"
)

// Stream is one proxied connection carried by a tunnel plane. It implements
// io.ReadWriteCloser plus half-close and byte accounting helpers.
type Stream struct {
	id        uint64
	nodeID    string
	plane     int
	epoch     uint32
	transport string
	raw       transport.Stream
	sess      *session
	srv       *Server
	fsm       *fsm.StreamFSM
	opensAt   time.Time

	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
	failed   atomic.Bool

	failOnce sync.Once
	failMu   sync.Mutex
	failErr  error

	closeOnce sync.Once
	closedCh  chan struct{}
}

func newStream(srv *Server, sess *session, raw transport.Stream) *Stream {
	st := &Stream{
		srv:       srv,
		sess:      sess,
		raw:       raw,
		id:        srv.streamSeq.Add(1),
		nodeID:    sess.node(),
		plane:     sess.planeIndex(),
		epoch:     sess.epoch.Load(),
		transport: sess.transport,
		closedCh:  make(chan struct{}),
	}
	st.fsm = fsm.NewStreamFSM(st.onStateChange)
	return st
}

func (st *Stream) onStateChange(from, to fsm.StreamState, event fsm.StreamEvent) {
	st.srv.logger.Debug("stream state transition",
		"event", "stream_state",
		"stream_id", st.id,
		"node_id", st.nodeID,
		"plane_index", st.plane,
		"epoch", st.epoch,
		"from", string(from),
		"to", string(to),
		"transition", string(event),
		"duration_ms", time.Since(st.opensAt).Milliseconds())
}

// NodeID returns the node the stream is routed through.
func (st *Stream) NodeID() string { return st.nodeID }

// PlaneIndex returns the transport plane index the stream is routed through.
func (st *Stream) PlaneIndex() int { return st.plane }

// Epoch returns the session registration epoch that created the stream.
func (st *Stream) Epoch() uint32 { return st.epoch }

// ID returns the server local stream sequence number (debugging only).
func (st *Stream) ID() uint64 { return st.id }

// BytesIn returns the number of bytes read from the node.
func (st *Stream) BytesIn() uint64 { return st.bytesIn.Load() }

// BytesOut returns the number of bytes written to the node.
func (st *Stream) BytesOut() uint64 { return st.bytesOut.Load() }

// SetDeadline sets a combined read/write deadline on the underlying stream.
func (st *Stream) SetDeadline(t time.Time) error { return st.raw.SetDeadline(t) }

// SetReadDeadline sets the read deadline on the underlying stream.
func (st *Stream) SetReadDeadline(t time.Time) error { return st.raw.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline on the underlying stream.
func (st *Stream) SetWriteDeadline(t time.Time) error { return st.raw.SetWriteDeadline(t) }

// Done is closed once the stream resources are released.
func (st *Stream) Done() <-chan struct{} { return st.closedCh }

// Read implements io.Reader. A session failure is reported as an error, never as
// a clean io.EOF, so the proxy layer can tell "normal end" from "tunnel died".
func (st *Stream) Read(p []byte) (int, error) {
	if st.failed.Load() {
		return 0, st.failure()
	}
	n, err := st.raw.Read(p)
	if n > 0 {
		st.bytesIn.Add(uint64(n))
	}
	if err != nil {
		if st.failed.Load() {
			return n, st.failure()
		}
		if errors.Is(err, io.EOF) {
			// Half close: the node finished sending but the read side of the
			// local stream is not an error.
			_, _ = st.fsm.Fire(fsm.StreamEvRemoteFIN)
			return n, io.EOF
		}
		return n, err
	}
	return n, nil
}

// Write implements io.Writer.
func (st *Stream) Write(p []byte) (int, error) {
	if st.failed.Load() {
		return 0, st.failure()
	}
	n, err := st.raw.Write(p)
	if n > 0 {
		st.bytesOut.Add(uint64(n))
	}
	if err != nil {
		if st.failed.Load() {
			return n, st.failure()
		}
		st.setFailure(fmt.Errorf("tunnel: stream %d write: %w", st.id, err))
		return n, err
	}
	return n, nil
}

// CloseWrite half-closes the local write direction (FIN) and keeps the read
// direction open so the response tail can still arrive.
func (st *Stream) CloseWrite() error {
	if st.failed.Load() {
		return st.failure()
	}
	_, _ = st.fsm.Fire(fsm.StreamEvLocalEOF)
	return st.raw.CloseWrite()
}

// Close releases the stream exactly once.
func (st *Stream) Close() error {
	var err error
	st.closeOnce.Do(func() {
		if st.failed.Load() {
			err = st.raw.Reset(0)
		} else {
			_ = st.raw.CloseWrite()
			err = st.raw.CloseRead()
		}
		st.srv.detachStream(st)
	})
	return err
}

// fail marks the stream as failed (session lost, protocol error) and releases
// it. Reads and writes return the recorded error instead of io.EOF.
func (st *Stream) fail(err error) {
	st.setFailure(err)
	_ = st.Close()
}

func (st *Stream) setFailure(err error) {
	st.failOnce.Do(func() {
		if err == nil {
			err = ErrSessionClosed
		}
		st.failMu.Lock()
		st.failErr = err
		st.failMu.Unlock()
		st.failed.Store(true)
		if errors.Is(err, transport.ErrWindowStall) && st.srv.metrics != nil {
			st.srv.metrics.TunnelWindowStalls.WithLabelValues(st.srv.nodeLabel(st.nodeID)).Inc()
			st.srv.logger.Warn("tunnel stream window stall",
				"event", "stream.window_stall", "stream_id", st.id,
				"node_id", st.nodeID, "plane_index", st.plane)
		}
	})
}

func (st *Stream) failure() error {
	st.failMu.Lock()
	defer st.failMu.Unlock()
	if st.failErr != nil {
		return st.failErr
	}
	return ErrSessionClosed
}

// driveClosed walks the stream FSM to closed using the legal transitions from
// the attachment, so every stream ends in exactly one terminal state.
func (st *Stream) driveClosed() {
	for i := 0; i < 4; i++ {
		cur := st.fsm.State()
		if cur == fsm.StreamClosed {
			return
		}
		var ev fsm.StreamEvent
		switch cur {
		case fsm.StreamNew, fsm.StreamOpening:
			ev = fsm.StreamEvRST
		case fsm.StreamOpen:
			ev = fsm.StreamEvLocalEOF
		case fsm.StreamHalfLocal:
			ev = fsm.StreamEvRemoteFIN
		case fsm.StreamHalfRemote:
			ev = fsm.StreamEvLocalEOF
		case fsm.StreamDraining:
			ev = fsm.StreamEvCleanup
		default:
			return
		}
		if _, err := st.fsm.Fire(ev); err != nil {
			if cur == fsm.StreamDraining {
				return
			}
			if _, rerr := st.fsm.Fire(fsm.StreamEvRST); rerr != nil {
				return
			}
		}
	}
}

// detachStream removes a stream from the server tables exactly once and updates
// counters, metrics and the stream FSM.
func (s *Server) detachStream(st *Stream) {
	st.driveClosed()
	s.streamMu.Lock()
	delete(s.streams, st.id)
	if n := s.nodeStreams[st.nodeID]; n > 0 {
		if n == 1 {
			delete(s.nodeStreams, st.nodeID)
		} else {
			s.nodeStreams[st.nodeID] = n - 1
		}
	}
	s.streamMu.Unlock()
	s.activeStream.Add(-1)
	if st.sess != nil {
		st.sess.removeStream(st)
	}
	if s.metrics != nil {
		label := s.nodeLabel(st.nodeID)
		s.metrics.TunnelStreams.WithLabelValues(label, "open").Dec()
		if in := st.bytesIn.Load(); in > 0 {
			s.metrics.TunnelBytesTotal.WithLabelValues("in", label).Add(float64(in))
		}
		if out := st.bytesOut.Load(); out > 0 {
			s.metrics.TunnelBytesTotal.WithLabelValues("out", label).Add(float64(out))
		}
	}
	s.logger.Debug("stream closed",
		"event", "stream_closed",
		"stream_id", st.id,
		"node_id", st.nodeID,
		"plane_index", st.plane,
		"epoch", st.epoch,
		"bytes_in", st.bytesIn.Load(),
		"bytes_out", st.bytesOut.Load(),
		"duration_ms", time.Since(st.opensAt).Milliseconds())
	close(st.closedCh)
}

// DialStream opens one proxied connection through nodeID. The node must be
// online, enabled and have at least one ready or degraded plane. OPEN failures
// are mapped to *protocol.Error with the attachment chapter 7 codes.
func (s *Server) DialStream(ctx context.Context, nodeID string, req protocol.OpenRequest) (*Stream, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return nil, protocol.NewError(protocol.CodePolicy, "tunnel: empty node id")
	}
	if s.isClosing() {
		return nil, protocol.NewError(protocol.CodeOverloaded, "tunnel: server is shutting down")
	}
	node, ok := s.reg.Get(nodeID)
	if !ok {
		// The node disappeared between scheduling and dialing: this is an
		// infrastructure shortage, not an authorization decision, so return the
		// "no available resource" code (HTTP 503) instead of policy (403).
		return nil, protocol.NewError(protocol.CodeOverloaded, "tunnel: unknown node %q", nodeID)
	}
	if !node.Enabled {
		return nil, protocol.NewError(protocol.CodeOverloaded, "tunnel: node %q is disabled", nodeID)
	}
	if !node.Online {
		return nil, protocol.NewError(protocol.CodeOverloaded, "tunnel: node %q is offline", nodeID)
	}
	sess := s.pickSession(nodeID, req.TraceID)
	if sess == nil {
		s.countOpenError(nodeID, protocol.NewError(protocol.CodeOverloaded, ""))
		return nil, protocol.NewError(protocol.CodeOverloaded, "tunnel: node %q has no ready transport plane", nodeID)
	}
	st, err := s.openStream(ctx, sess, req)
	if err != nil {
		s.countOpenError(nodeID, err)
		return nil, err
	}
	return st, nil
}

func (s *Server) openStream(ctx context.Context, sess *session, req protocol.OpenRequest) (*Stream, error) {
	settings := s.settingsSnapshot()
	limit := settings.Limits.MaxStreamsPerNode
	if err := s.reserveStream(sess.node(), limit); err != nil {
		return nil, err
	}
	reserved := true
	defer func() {
		if reserved {
			s.releaseStreamReservation(sess.node())
		}
	}()
	// 0-RTT: control messages may travel in early data, but data streams must
	// wait for the handshake to be confirmed (replay safety, attachment A.11).
	// Wait for the handshake instead of failing the request with a 502.
	if !sess.conn.HandshakeComplete() {
		waitCtx, waitCancel := context.WithTimeout(ctx, s.times.openTimeout(settings))
		confirmed := false
		for !confirmed {
			if sess.conn.HandshakeComplete() {
				confirmed = true
				break
			}
			select {
			case <-waitCtx.Done():
				waitCancel()
				return nil, protocol.NewError(protocol.CodeTimeout, "tunnel: transport handshake not confirmed in time for node %q", sess.node())
			case <-time.After(10 * time.Millisecond):
			}
		}
		waitCancel()
	}
	openTimeout := s.times.openTimeout(settings)
	started := time.Now()
	openCtx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	raw, err := sess.conn.OpenStream(openCtx)
	if err != nil {
		if ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ctx.Err()
		}
		if openCtx.Err() != nil {
			return nil, protocol.NewError(protocol.CodeTimeout, "tunnel: node %q did not open a transport stream within %s", sess.node(), openTimeout)
		}
		return nil, protocol.NewError(protocol.CodeInternal, "tunnel: open transport stream on node %q: %v", sess.node(), err)
	}
	req = normalizeOpenRequest(req)
	meta, err := req.Encode()
	if err != nil {
		_ = raw.Reset(0)
		return nil, protocol.NewError(protocol.CodeInternal, "tunnel: encode OPEN header: %v", err)
	}
	if err := raw.WriteOpen(meta); err != nil {
		_ = raw.Reset(0)
		return nil, protocol.NewError(protocol.CodeInternal, "tunnel: write OPEN header to node %q: %v", sess.node(), err)
	}
	result, err := raw.ReadOpenResult(openCtx)
	if err != nil {
		_ = raw.Reset(0)
		if ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, ctx.Err()
		}
		if openCtx.Err() != nil {
			return nil, protocol.NewError(protocol.CodeTimeout, "tunnel: node %q did not answer OPEN within %s", sess.node(), openTimeout)
		}
		return nil, protocol.NewError(protocol.CodeInternal, "tunnel: read OPEN result from node %q: %v", sess.node(), err)
	}
	code, message, err := protocol.DecodeOpenResult(result)
	if err != nil {
		_ = raw.Reset(0)
		return nil, protocol.NewError(protocol.CodeInternal, "tunnel: decode OPEN result from node %q: %v", sess.node(), err)
	}
	openCode := protocol.OpenErrorCode(code)
	if openCode != protocol.CodeOK {
		_ = raw.Reset(0)
		return nil, mapOpenError(openCode, message)
	}

	st := newStream(s, sess, raw)
	st.opensAt = started
	_, _ = st.fsm.Fire(fsm.StreamEvSentOpen)
	_, _ = st.fsm.Fire(fsm.StreamEvAckOK)
	s.registerStream(st)
	reserved = false
	if s.metrics != nil {
		label := s.nodeLabel(sess.node())
		s.metrics.TunnelOpenSeconds.WithLabelValues(label, sess.transport).Observe(time.Since(started).Seconds())
		s.metrics.TunnelStreams.WithLabelValues(label, "open").Inc()
	}
	return st, nil
}

// mapOpenError converts a node reported OPEN_ERR code into the protocol error the
// proxy entry points translate into HTTP/SOCKS5 failures.
func mapOpenError(code protocol.OpenErrorCode, message string) *protocol.Error {
	text := strings.TrimSpace(message)
	if !code.Valid() {
		return protocol.NewError(protocol.CodeInternal, "tunnel: node returned unknown OPEN error code %d: %s", uint8(code), text)
	}
	if text == "" {
		text = "node reported " + code.String()
	}
	return &protocol.Error{Code: code, Message: text}
}

func normalizeOpenRequest(req protocol.OpenRequest) protocol.OpenRequest {
	if req.Version == 0 {
		req.Version = protocol.OpenVersion1
	}
	if req.Proto == 0 {
		req.Proto = protocol.ProtoTCP
	}
	return req
}

// reserveStream accounts one stream slot before the OPEN round trip so N
// concurrent DialStream calls cannot exceed the node limit.
func (s *Server) reserveStream(nodeID string, limit int) error {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	if s.isClosing() {
		return protocol.NewError(protocol.CodeOverloaded, "tunnel: server is shutting down")
	}
	if limit > 0 && s.nodeStreams[nodeID] >= limit {
		return protocol.NewError(protocol.CodeOverloaded, "tunnel: node %q already carries %d active streams (limit %d)", nodeID, s.nodeStreams[nodeID], limit)
	}
	s.nodeStreams[nodeID]++
	s.activeStream.Add(1)
	return nil
}

func (s *Server) releaseStreamReservation(nodeID string) {
	s.streamMu.Lock()
	if n := s.nodeStreams[nodeID]; n > 0 {
		if n == 1 {
			delete(s.nodeStreams, nodeID)
		} else {
			s.nodeStreams[nodeID] = n - 1
		}
	}
	s.streamMu.Unlock()
	s.activeStream.Add(-1)
}

func (s *Server) registerStream(st *Stream) {
	s.streamMu.Lock()
	s.streams[st.id] = st
	s.streamMu.Unlock()
	if st.sess != nil {
		st.sess.addStream(st)
	}
}

func (s *Server) countOpenError(nodeID string, err error) {
	if s.metrics == nil {
		return
	}
	code := "internal"
	if pe := protocol.AsError(err); pe != nil {
		code = pe.Code.String()
	}
	s.metrics.TunnelOpenErrors.WithLabelValues(s.nodeLabel(nodeID), code).Inc()
}

// pickSession selects a plane for a new stream. A non-zero trace id pins the
// stream to one plane so related requests reuse the same congestion window; the
// zero trace id falls back to round robin.
func (s *Server) pickSession(nodeID string, trace [protocol.TraceIDLen]byte) *session {
	s.mu.Lock()
	list := make([]*session, 0, 2)
	for key, sess := range s.sessions {
		if key.nodeID != nodeID {
			continue
		}
		if sess.isDraining() || !sess.state().CanHoldNewStreams() {
			continue
		}
		list = append(list, sess)
	}
	s.mu.Unlock()
	if len(list) == 0 {
		return nil
	}
	sort.Slice(list, func(i, j int) bool { return list[i].planeIndex() < list[j].planeIndex() })
	zero := true
	for _, b := range trace {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		n := s.rr.Add(1)
		return list[int(n)%len(list)]
	}
	h := fnv.New32a()
	_, _ = h.Write(trace[:])
	return list[int(h.Sum32()%uint32(len(list)))]
}
