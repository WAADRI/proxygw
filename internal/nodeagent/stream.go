package nodeagent

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"proxygw/internal/compress"
	"proxygw/internal/protocol"
	"proxygw/internal/transport"
)

// acceptLoop accepts server initiated data streams. Streams arriving before the
// session is registered or while it is draining are logged as a security event
// and reset instead of being proxied.
func (s *session) acceptLoop() {
	for {
		st, err := s.conn.AcceptStream(s.ctx)
		if err != nil {
			if s.ctx.Err() == nil {
				s.reportError(fmt.Errorf("接受服务端数据流失败: %w", err))
			}
			return
		}
		if st == nil {
			continue
		}
		state := s.fsm.State()
		if s.drainStarted.Load() || !state.CanHoldNewStreams() {
			s.rejectNotReady(st, fmt.Sprintf("会话状态 %s 不接受新流", state))
			continue
		}
		s.handlers.Add(1)
		go func(stream transport.Stream) {
			defer s.handlers.Add(-1)
			s.handleStream(stream)
		}(st)
	}
}

// rejectNotReady consumes the OPEN header (to keep the transport stream
// consistent) and then resets the stream.
func (s *session) rejectNotReady(st transport.Stream, reason string) {
	ctx, cancel := context.WithTimeout(s.ctx, time.Second)
	_, _ = st.ReadOpen(ctx)
	cancel()
	s.log.Warn("注册前或排空期收到数据流，记录安全日志并拒绝",
		"event", "stream.rejected_not_ready",
		"reason", reason)
	_ = st.Reset(1)
}

// handleStream proxies exactly one server initiated stream: it reads and
// validates the OPEN header, dials the target with the fixed 10s budget, writes
// the OPEN result and relays bytes both ways until both directions finish.
func (s *session) handleStream(st transport.Stream) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("数据流处理发生 panic，已复位", "event", "stream.panic", "panic", fmt.Sprint(r))
			_ = st.Reset(1)
		}
	}()

	openCtx, cancel := context.WithTimeout(s.ctx, s.a.timings.openDialTimeout)
	meta, err := st.ReadOpen(openCtx)
	cancel()
	if err != nil {
		if s.ctx.Err() == nil {
			s.log.Warn("读取 OPEN 头失败，复位数据流", "event", "stream.open_read_fail", "error", err)
		}
		_ = st.Reset(1)
		return
	}
	req, err := protocol.DecodeOpen(meta)
	if err != nil {
		s.log.Warn("非法 OPEN 头，复位数据流", "event", "stream.open_invalid", "error", err)
		_ = st.Reset(1)
		s.a.recordOpenError(protocol.CodeProtoUnsupported)
		return
	}
	if state := s.fsm.State(); !state.CanHoldNewStreams() {
		s.log.Warn("非 ready 状态收到数据流，记录安全日志并拒绝",
			"event", "stream.rejected_not_ready",
			"state", string(state),
			"target", req.Target(),
			"trace_id", traceHex(req.TraceID))
		_ = st.Reset(1)
		return
	}

	s.streamsMu.Lock()
	full := len(s.streams) >= s.maxStreams
	s.streamsMu.Unlock()
	if full {
		s.log.Warn("流表已满，拒绝新流", "event", "stream.overloaded", "target", req.Target())
		_ = s.writeOpenResult(st, protocol.EncodeOpenResult(byte(protocol.CodeOverloaded), "节点流表已满"))
		_ = st.CloseWrite()
		_ = st.CloseRead()
		s.a.recordOpenError(protocol.CodeOverloaded)
		return
	}

	sid := s.nextStreamID.Add(1)
	streamCtx, streamCancel := context.WithCancel(s.ctx)
	e := &streamEntry{id: sid, st: st, cancel: streamCancel}
	if !s.addStream(e) {
		streamCancel()
		s.log.Warn("会话已排空，拒绝新流", "event", "stream.rejected_draining", "target", req.Target())
		_ = s.writeOpenResult(st, protocol.EncodeOpenResult(byte(protocol.CodeOverloaded), "会话正在排空"))
		_ = st.CloseWrite()
		_ = st.CloseRead()
		return
	}
	defer func() {
		s.removeStream(sid)
		streamCancel()
		e.closeTarget()
	}()

	s.a.inflight.Add(1)
	dialCtx, dialCancel := context.WithTimeout(streamCtx, s.a.timings.openDialTimeout)
	dialStart := time.Now()
	target, dialErr := s.a.dialTarget(dialCtx, "tcp", req.Target())
	dialCancel()
	elapsed := time.Since(dialStart)
	s.a.inflight.Add(-1)
	s.a.noteLatency(elapsed)

	if dialErr != nil {
		code := openErrorCode(dialErr)
		s.a.recordOpenError(code)
		_ = s.writeOpenResult(st, protocol.EncodeOpenResult(byte(code), truncateMsg(dialErr.Error(), 256)))
		_ = st.CloseWrite()
		_ = st.CloseRead()
		s.log.Warn("目标拨号失败",
			"event", "stream.target_dial_fail",
			"target", req.Target(),
			"code", code.String(),
			"duration_ms", elapsed.Milliseconds(),
			"trace_id", traceHex(req.TraceID),
			"error", dialErr)
		return
	}
	e.setTarget(target)
	defer func() { _ = target.Close() }()

	if err := s.writeOpenResult(st, protocol.EncodeOpenResult(byte(protocol.CodeOK), "")); err != nil {
		s.log.Debug("回写 OPEN 成功结果失败", "event", "stream.open_result_fail", "error", err)
		return
	}
	s.log.Info("数据流建立",
		"event", "stream.open",
		"target", req.Target(),
		"compressed", req.Compressed(),
		"duration_ms", elapsed.Milliseconds(),
		"trace_id", traceHex(req.TraceID))
	pipe, perr := s.dataPipe(st, req)
	if perr != nil {
		s.log.Error("压缩流初始化失败，复位数据流",
			"event", "stream.compress_init_fail",
			"target", req.Target(),
			"trace_id", traceHex(req.TraceID),
			"error", perr)
		_ = st.Reset(1)
		return
	}
	if err := s.relay(pipe, target); err != nil {
		s.log.Debug("数据流转发异常结束",
			"event", "stream.relay_error",
			"target", req.Target(),
			"trace_id", traceHex(req.TraceID),
			"error", err)
	}
}

// dataPipe returns the tunnel side byte pipe for one data stream. It is the raw
// transport stream by default; when the server set protocol.FlagCompressed in
// the OPEN header the node wraps it symmetrically: bytes read from the tunnel are
// zstd decoded before they reach the target and bytes read from the target are
// zstd encoded before they reach the tunnel. The OPEN header and the build result
// are exchanged before this point and are never compressed.
//
// A compression setup failure after OPEN_OK is fatal for the stream: it returns an
// error so the caller resets the stream. The server must never receive plaintext
// where it expects a zstd frame.
func (s *session) dataPipe(st transport.Stream, req protocol.OpenRequest) (relayStream, error) {
	raw := rawRelayStream{Stream: st}
	if !req.Compressed() {
		return raw, nil
	}
	pipe, err := compress.WrapStream(raw, compress.DefaultLevel)
	if err != nil {
		return nil, fmt.Errorf("nodeagent: wrap tunnel stream with zstd: %w", err)
	}
	return pipe, nil
}

// relayStream is the tunnel side pipe the relay pumps bytes through. It is the
// raw transport stream by default and a compress.Stream wrapper when OPEN
// negotiated compression, so the pumps stay identical for both modes.
type relayStream interface {
	io.Reader
	io.Writer
	CloseWrite() error
	CloseRead() error
	Reset(code uint64) error
	SetWriteDeadline(t time.Time) error
	// Close releases the stream once both directions finish. For a compressed
	// pipe it flushes the final zstd frame and returns the codecs to the pool;
	// for a raw stream it is a no-op because the relay owns the transport
	// stream lifetime and closes it via CloseWrite + CloseRead.
	Close() error
}

// rawRelayStream adapts a transport.Stream to relayStream. transport.Stream has
// no Close; the relay releases the stream explicitly through CloseWrite and
// CloseRead, so Close only exists to satisfy the compressed wrapper's
// io.ReadWriteCloser contract and must not touch the transport stream.
type rawRelayStream struct {
	transport.Stream
}

// Close implements io.Closer without closing the transport stream (see
// rawRelayStream).
func (rawRelayStream) Close() error { return nil }

// writeOpenResult writes the OPEN result with the configured write-block
// timeout (default 30s).
func (s *session) writeOpenResult(st transport.Stream, result []byte) error {
	_ = st.SetWriteDeadline(time.Now().Add(s.a.timings.writeBlock))
	err := st.WriteOpenResult(result)
	_ = st.SetWriteDeadline(time.Time{})
	return err
}

// relay pumps bytes in both directions. EOF on one side half-closes the other
// side and keeps the stream alive (linger is controlled by the server); only
// when both directions finish are the resources released. Any real error resets
// the stream (RST semantics) and closes the target to unblock the peer pump.
//
// pipe is either the raw transport stream or a compressed wrapper; the pumps do
// not care which one, so half-close, reset and write-timeout semantics are
// identical in both modes.
func (s *session) relay(pipe relayStream, target net.Conn) error {
	var (
		wg        sync.WaitGroup
		abortOnce sync.Once
	)
	errCh := make(chan error, 2)
	abort := func() {
		abortOnce.Do(func() {
			_ = target.Close()
			_ = pipe.Reset(1)
		})
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		errCh <- s.pumpToTarget(pipe, target, abort)
	}()
	go func() {
		defer wg.Done()
		errCh <- s.pumpToStream(target, pipe, abort)
	}()
	wg.Wait()
	var firstErr error
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		abort()
	}
	// Both directions are done. Sending FIN again is harmless, CloseRead
	// releases the transport receive half and Close flushes/releases a
	// compressed pipe (a no-op for the raw stream).
	_ = pipe.SetWriteDeadline(time.Now().Add(time.Second))
	_ = pipe.CloseWrite()
	_ = pipe.CloseRead()
	_ = pipe.Close()
	_ = target.Close()
	return firstErr
}

// pumpToTarget copies tunnel -> target (upload direction, counted as BytesIn).
func (s *session) pumpToTarget(pipe relayStream, target net.Conn, abort func()) error {
	buf := getRelayBuf()
	defer putRelayBuf(buf)
	b := *buf
	writeBlock := s.a.timings.writeBlock
	for {
		n, rerr := pipe.Read(b)
		if n > 0 {
			if writeBlock > 0 {
				_ = target.SetWriteDeadline(time.Now().Add(writeBlock))
			}
			w, werr := target.Write(b[:n])
			if w > 0 {
				s.a.bytesIn.Add(uint64(w))
			}
			if werr != nil {
				abort()
				return fmt.Errorf("写入目标失败: %w", werr)
			}
			if w != n {
				abort()
				return fmt.Errorf("写入目标不完整: %w", io.ErrShortWrite)
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				_ = closeWrite(target)
				return nil
			}
			abort()
			return fmt.Errorf("读取隧道流失败: %w", rerr)
		}
	}
}

// pumpToStream copies target -> tunnel (download direction, BytesOut).
func (s *session) pumpToStream(target net.Conn, pipe relayStream, abort func()) error {
	buf := getRelayBuf()
	defer putRelayBuf(buf)
	b := *buf
	writeBlock := s.a.timings.writeBlock
	for {
		n, rerr := target.Read(b)
		if n > 0 {
			if writeBlock > 0 {
				_ = pipe.SetWriteDeadline(time.Now().Add(writeBlock))
			}
			w, werr := pipe.Write(b[:n])
			if w > 0 {
				s.a.bytesOut.Add(uint64(w))
			}
			if werr != nil {
				abort()
				return fmt.Errorf("写入隧道流失败: %w", werr)
			}
			if w != n {
				abort()
				return fmt.Errorf("写入隧道流不完整: %w", io.ErrShortWrite)
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				// A compressed pipe flushes its final zstd frame here, so a
				// flush failure means the tail was lost: report it instead of
				// quietly truncating the download.
				if cerr := pipe.CloseWrite(); cerr != nil {
					abort()
					return fmt.Errorf("关闭隧道流写方向失败: %w", cerr)
				}
				return nil
			}
			abort()
			return fmt.Errorf("读取目标失败: %w", rerr)
		}
	}
}

// streamEntry is one entry of the per session stream table. It allows the
// session teardown to cancel the stream context and close the target from
// another goroutine.
type streamEntry struct {
	id     uint64
	st     transport.Stream
	cancel context.CancelFunc

	mu        sync.Mutex
	target    net.Conn
	aborted   bool
	abortOnce sync.Once
}

func (e *streamEntry) setTarget(c net.Conn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.aborted {
		_ = c.Close()
		return
	}
	e.target = c
}

func (e *streamEntry) closeTarget() {
	e.mu.Lock()
	target := e.target
	e.mu.Unlock()
	if target != nil {
		_ = target.Close()
	}
}

// abort cancels the stream and closes its target exactly once.
func (e *streamEntry) abort() {
	e.abortOnce.Do(func() {
		e.mu.Lock()
		e.aborted = true
		target := e.target
		e.mu.Unlock()
		e.cancel()
		if target != nil {
			_ = target.Close()
		}
		if e.st != nil {
			_ = e.st.Reset(1)
		}
	})
}

// dialTarget dials the real target from the node network with the fixed 10s
// budget (tests inject a dialer through TestHooks).
func (a *Agent) dialTarget(ctx context.Context, network, addr string) (net.Conn, error) {
	if a.opts.TestHooks != nil && a.opts.TestHooks.DialTarget != nil {
		return a.opts.TestHooks.DialTarget(ctx, network, addr)
	}
	dialer := &net.Dialer{Timeout: a.timings.openDialTimeout}
	return dialer.DialContext(ctx, network, addr)
}

// openErrorCode maps a node -> target dial error to the OPEN_ERR code table of
// tunnel-state-machine.md chapter 7.
func openErrorCode(err error) protocol.OpenErrorCode {
	if err == nil {
		return protocol.CodeOK
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return protocol.CodeDNS
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return protocol.CodeConnRefused
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || isTimeoutErr(err) {
		return protocol.CodeTimeout
	}
	lower := asciiLower(err.Error())
	switch {
	case containsFold(lower, "refused"):
		return protocol.CodeConnRefused
	case containsFold(lower, "no such host"), containsFold(lower, "name resolution"), containsFold(lower, "dns"):
		return protocol.CodeDNS
	case containsFold(lower, "timeout"), containsFold(lower, "timed out"):
		return protocol.CodeTimeout
	}
	return protocol.CodeInternal
}

// traceHex renders the 16 byte trace id for logs.
func traceHex(id [protocol.TraceIDLen]byte) string {
	return hex.EncodeToString(id[:8])
}
