package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
)

// ErrClosed is returned by Serve when the entry point is already shut down.
var ErrClosed = errors.New("proxy: entry point is closed")

// drainHardCap bounds how long Close waits for handlers after the socket level
// force close; it only triggers when a handler ignores closed connections.
const drainHardCap = 5 * time.Second

// entryServer owns everything shared by the HTTP and SOCKS5 entry points: the
// listener lifecycle, connection tracking for forced shutdown, graceful drain
// and panic recovery.
type entryServer struct {
	pipeline *pipeline

	baseCtx    context.Context
	baseCancel context.CancelFunc

	closing   atomic.Bool
	closeOnce sync.Once
	forceOnce sync.Once

	mu        sync.Mutex
	listeners map[net.Listener]struct{}
	conns     map[net.Conn]context.CancelFunc

	loopsMu   sync.Mutex
	loops     int
	loopsDone chan struct{}

	wg sync.WaitGroup
}

// newEntryServer builds the shared server state.
func newEntryServer(p *pipeline) *entryServer {
	baseCtx, cancel := context.WithCancel(context.Background())
	return &entryServer{
		pipeline:   p,
		baseCtx:    baseCtx,
		baseCancel: cancel,
		listeners:  make(map[net.Listener]struct{}),
		conns:      make(map[net.Conn]context.CancelFunc),
	}
}

// isClosing reports whether the server stopped accepting new connections.
func (s *entryServer) isClosing() bool { return s.closing.Load() }

// serve accepts connections on ln until the listener is closed, shutting the
// entry point down when ctx is cancelled.
func (s *entryServer) serve(ctx context.Context, ln net.Listener, handle func(context.Context, net.Conn)) error {
	if ln == nil {
		return errors.New("proxy: nil listener")
	}
	if !s.addListener(ln) {
		_ = ln.Close()
		return ErrClosed
	}
	defer s.removeListener(ln)
	s.beginLoop()
	loopEnded := false
	defer func() {
		if !loopEnded {
			s.endLoop()
		}
	}()

	stop := make(chan struct{})
	defer close(stop)
	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				s.initiateClose()
			case <-stop:
			}
		}()
	}

	var acceptErr error
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.isClosing() || (ctx != nil && ctx.Err() != nil) {
				acceptErr = nil
			} else {
				acceptErr = fmt.Errorf("proxy: accept: %w", err)
			}
			break
		}
		connCtx, cancel := context.WithCancel(s.baseCtx)
		if !s.trackConn(conn, cancel) {
			cancel()
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.runConn(connCtx, conn, cancel, handle)
		}()
	}
	s.endLoop()
	loopEnded = true
	if s.isClosing() {
		s.drain(context.Background())
		return nil
	}
	return acceptErr
}

// runConn executes one connection handler with panic recovery and exact-once
// cleanup.
func (s *entryServer) runConn(ctx context.Context, conn net.Conn, cancel context.CancelFunc, handle func(context.Context, net.Conn)) {
	p := s.pipeline
	p.activeConn(1)
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("proxy connection panicked",
				"event", "proxy_panic",
				"remote", remoteIP(conn.RemoteAddr()),
				"panic", fmt.Sprint(r),
				"stack", string(debug.Stack()))
		}
		cancel()
		s.untrackConn(conn)
		_ = conn.Close()
		p.activeConn(-1)
	}()
	handle(ctx, conn)
}

// addListener registers a listener unless the server is already closing.
func (s *entryServer) addListener(ln net.Listener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing.Load() {
		return false
	}
	s.listeners[ln] = struct{}{}
	return true
}

// removeListener unregisters a listener.
func (s *entryServer) removeListener(ln net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.listeners, ln)
}

// trackConn registers an accepted connection unless the server is closing.
func (s *entryServer) trackConn(conn net.Conn, cancel context.CancelFunc) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing.Load() {
		return false
	}
	s.conns[conn] = cancel
	return true
}

// untrackConn unregisters a connection.
func (s *entryServer) untrackConn(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
}

// beginLoop registers one running Serve loop.
func (s *entryServer) beginLoop() {
	s.loopsMu.Lock()
	defer s.loopsMu.Unlock()
	if s.loops == 0 {
		s.loopsDone = make(chan struct{})
	}
	s.loops++
}

// endLoop unregisters one running Serve loop.
func (s *entryServer) endLoop() {
	s.loopsMu.Lock()
	defer s.loopsMu.Unlock()
	s.loops--
	if s.loops == 0 && s.loopsDone != nil {
		close(s.loopsDone)
		s.loopsDone = nil
	}
}

// waitLoops waits until every Serve loop stopped accepting, or ctx expires.
func (s *entryServer) waitLoops(ctx context.Context) {
	s.loopsMu.Lock()
	done := s.loopsDone
	s.loopsMu.Unlock()
	if done == nil {
		return
	}
	if ctx == nil {
		<-done
		return
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// initiateClose stops accepting connections. It is idempotent.
func (s *entryServer) initiateClose() {
	s.closeOnce.Do(func() {
		s.closing.Store(true)
		s.mu.Lock()
		listeners := make([]net.Listener, 0, len(s.listeners))
		for ln := range s.listeners {
			listeners = append(listeners, ln)
		}
		s.mu.Unlock()
		for _, ln := range listeners {
			_ = ln.Close()
		}
	})
}

// close gracefully drains the entry point: stop accepting, wait for in-flight
// requests up to the configured drain timeout (or the caller deadline), then
// force close the remaining connections. It is idempotent.
func (s *entryServer) close(ctx context.Context) error {
	s.initiateClose()
	s.drain(ctx)
	return nil
}

// drain waits for the in-flight connections to finish.
func (s *entryServer) drain(ctx context.Context) {
	// Accept loops must be gone before Wait: a still running loop may call
	// wg.Add after Wait started, which is not allowed by sync.WaitGroup.
	waitCtx := ctx
	if waitCtx == nil {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(context.Background(), s.pipeline.timeouts().drain)
		defer cancel()
	}
	s.waitLoops(waitCtx)

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	timeout := s.pipeline.timeouts().drain
	if ctx != nil {
		if deadline, ok := ctx.Deadline(); ok {
			if remaining := time.Until(deadline); remaining < timeout {
				timeout = remaining
			}
		}
	}
	if timeout <= 0 {
		s.forceClose()
		<-done
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
		s.forceClose()
	}
	hard := time.NewTimer(drainHardCap)
	defer hard.Stop()
	select {
	case <-done:
	case <-hard.C:
		s.pipeline.logger.Warn("proxy drain hard cap reached",
			"event", "proxy_drain_timeout")
	}
}

// forceClose cancels every in-flight connection context and closes the sockets.
func (s *entryServer) forceClose() {
	s.forceOnce.Do(func() {
		s.baseCancel()
		s.mu.Lock()
		conns := make([]net.Conn, 0, len(s.conns))
		cancels := make([]context.CancelFunc, 0, len(s.conns))
		for conn, cancel := range s.conns {
			conns = append(conns, conn)
			cancels = append(cancels, cancel)
		}
		s.mu.Unlock()
		for _, cancel := range cancels {
			cancel()
		}
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
}
