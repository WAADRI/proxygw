package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"proxygw/internal/protocol"
)

// Defaults for the QUIC transport.
const (
	// defaultMaxIncomingStreams is the peer initiated bidirectional stream
	// limit. quic-go defaults to 100 which is far too small for a gateway:
	// every proxied connection occupies one stream. The same value is applied
	// on both ends because the node also accepts server initiated data streams.
	defaultMaxIncomingStreams = 4096
)

// ListenQUIC starts a QUIC listener on opts.Addr (host:port, UDP).
//
// The TLS config in opts.TLS is cloned and its ALPN list is forced to
// opts.ALPN (or protocol.ALPN when empty); the caller's config is never
// mutated. 0-RTT support is enabled via quic.Config.Allow0RTT when requested.
func ListenQUIC(opts QUICOptions) (Listener, error) {
	if opts.Addr == "" {
		return nil, errors.New("transport: quic: listen address is required")
	}
	tlsConf, err := quicTLSConfig(opts, true)
	if err != nil {
		return nil, err
	}
	conf := quicConfig(opts)
	ln, err := quic.ListenAddr(opts.Addr, tlsConf, conf)
	if err != nil {
		return nil, fmt.Errorf("transport: quic listen %q: %w", opts.Addr, err)
	}
	return &quicListener{ln: ln}, nil
}

// DialQUIC dials a QUIC server.
//
// When opts.Allow0RTT is set the dialer uses quic.DialAddrEarly so the
// control stream can be carried in 0-RTT data; Conn.HandshakeComplete then
// reports the actual TLS handshake state and the caller is responsible for not
// opening data streams before the handshake completed. With 0-RTT disabled the
// returned Conn has already completed the handshake. The handshake timeout is
// taken from the context deadline (falling back to opts.HandshakeTimeout via
// quic.Config.HandshakeIdleTimeout).
func DialQUIC(ctx context.Context, opts QUICOptions) (Conn, error) {
	if opts.Addr == "" {
		return nil, errors.New("transport: quic: dial address is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tlsConf, err := quicTLSConfig(opts, false)
	if err != nil {
		return nil, err
	}
	conf := quicConfig(opts)
	if opts.Allow0RTT {
		early, err := quic.DialAddrEarly(ctx, opts.Addr, tlsConf, conf)
		if err != nil {
			return nil, quicDialError(ctx, opts.Addr, err)
		}
		return newQUICConn(early, true), nil
	}
	qc, err := quic.DialAddr(ctx, opts.Addr, tlsConf, conf)
	if err != nil {
		return nil, quicDialError(ctx, opts.Addr, err)
	}
	return newQUICConn(qc, true), nil
}

// quicDialError makes context cancellation visible to the fallback controller:
// a handshake that exceeded the 2s QUIC fallback budget must surface as
// context.DeadlineExceeded, not as an opaque QUIC transport error.
func quicDialError(ctx context.Context, addr string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("transport: quic dial %q: %w", addr, ctxErr)
	}
	return fmt.Errorf("transport: quic dial %q: %w", addr, err)
}

// quicTLSConfig clones the caller TLS config and applies the transport ALPN.
func quicTLSConfig(opts QUICOptions, server bool) (*tls.Config, error) {
	if opts.TLS == nil {
		return nil, errors.New("transport: quic: TLS config is required")
	}
	conf := opts.TLS.Clone()
	alpn := opts.ALPN
	if alpn == "" {
		alpn = protocol.ALPN
	}
	conf.NextProtos = []string{alpn}
	if server && len(conf.Certificates) == 0 && conf.GetCertificate == nil && conf.GetConfigForClient == nil {
		return nil, errors.New("transport: quic: server TLS config carries no certificate")
	}
	return conf, nil
}

// quicConfig translates QUICOptions into a quic.Config.
//
// Notes for quic-go v0.48.2:
//   - congestion control is no longer selectable through the public API (the
//     Config.CongestionControl field was removed), so opts.CongestionControl is
//     accepted for configuration compatibility but cannot be applied here.
//   - DPLPMTUD is enabled by default; the only switch is
//     Config.DisablePathMTUDiscovery, which is left enabled.
//   - qlog is wired through Config.Tracer (see qlog.go).
func quicConfig(opts QUICOptions) *quic.Config {
	conf := &quic.Config{
		MaxIdleTimeout:  opts.MaxIdleTimeout,
		KeepAlivePeriod: opts.KeepAlivePeriod,
		EnableDatagrams: opts.EnableDatagrams,
		Allow0RTT:       opts.Allow0RTT,
	}
	if opts.HandshakeTimeout > 0 {
		conf.HandshakeIdleTimeout = opts.HandshakeTimeout
	}
	if opts.InitialPacketSize >= 1200 {
		conf.InitialPacketSize = opts.InitialPacketSize
	}
	maxIncoming := opts.MaxIncomingStreams
	if maxIncoming <= 0 {
		maxIncoming = defaultMaxIncomingStreams
	}
	conf.MaxIncomingStreams = maxIncoming
	if opts.QLogDir != "" {
		conf.Tracer = newQLogTracer(opts.QLogDir)
	}
	return conf
}

// quicListener implements Listener on top of quic.Listener.
type quicListener struct {
	ln *quic.Listener
}

// Accept waits for the next completed QUIC handshake.
func (l *quicListener) Accept(ctx context.Context) (Conn, error) {
	qc, err := l.ln.Accept(ctx)
	if err != nil {
		if errors.Is(err, quic.ErrServerClosed) {
			return nil, ErrListenerClosed
		}
		return nil, fmt.Errorf("transport: quic accept: %w", err)
	}
	return newQUICConn(qc, false), nil
}

// Close stops the listener. It is idempotent.
func (l *quicListener) Close() error {
	if err := l.ln.Close(); err != nil {
		return fmt.Errorf("transport: quic listener close: %w", err)
	}
	return nil
}

// Addr returns the bound UDP address.
func (l *quicListener) Addr() net.Addr { return l.ln.Addr() }

// Kind implements Listener.
func (l *quicListener) Kind() Kind { return KindQUIC }

// quicConn implements Conn on top of a quic.Connection.
type quicConn struct {
	conn   quic.Connection
	client bool

	done      chan struct{}
	closeOnce sync.Once
	errMu     sync.Mutex
	err       error

	ctrlOnce sync.Once
	ctrl     *quicControl
	ctrlErr  error

	wg sync.WaitGroup
}

func newQUICConn(qc quic.Connection, client bool) *quicConn {
	c := &quicConn{
		conn:   qc,
		client: client,
		done:   make(chan struct{}),
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		<-qc.Context().Done()
		c.markClosed(qc.Context().Err())
	}()
	return c
}

// markClosed records the terminal connection error and unblocks waiters. Only
// the first caller wins so a local CloseWithError reason is preserved.
func (c *quicConn) markClosed(err error) {
	c.closeOnce.Do(func() {
		if err == nil {
			err = ErrConnClosed
		}
		c.errMu.Lock()
		c.err = err
		c.errMu.Unlock()
		close(c.done)
	})
}

// lastErr returns the terminal error, blocking free. It is safe to call
// before the connection is closed (it then reports ErrConnClosed).
func (c *quicConn) lastErr() error {
	c.errMu.Lock()
	err := c.err
	c.errMu.Unlock()
	if err == nil {
		return ErrConnClosed
	}
	return err
}

// doneErr returns the terminal error if the connection is already closed.
func (c *quicConn) doneErr() error {
	select {
	case <-c.done:
		return c.lastErr()
	default:
		return nil
	}
}

// checkUsable rejects new stream operations on a closed connection.
func (c *quicConn) checkUsable() error {
	if err := c.doneErr(); err != nil {
		return err
	}
	if err := c.conn.Context().Err(); err != nil {
		c.markClosed(err)
		return c.lastErr()
	}
	return nil
}

// wrapCall maps errors of connection level operations to the transport error
// vocabulary.
func (c *quicConn) wrapCall(op string, err error) error {
	if err == nil {
		return nil
	}
	if cerr := c.doneErr(); cerr != nil {
		return cerr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("transport: quic %s: %w", op, err)
}

// Kind implements Conn.
func (c *quicConn) Kind() Kind { return KindQUIC }

// OpenStream opens a locally initiated bidirectional stream. The control
// stream is always established first so the peer can correlate stream order.
func (c *quicConn) OpenStream(ctx context.Context) (Stream, error) {
	if err := c.checkUsable(); err != nil {
		return nil, err
	}
	if _, err := c.ensureControl(ctx); err != nil {
		return nil, err
	}
	st, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, c.wrapCall("open stream", err)
	}
	return newQUICStream(c, st), nil
}

// AcceptStream accepts a peer initiated bidirectional stream.
func (c *quicConn) AcceptStream(ctx context.Context) (Stream, error) {
	if err := c.checkUsable(); err != nil {
		return nil, err
	}
	if _, err := c.ensureControl(ctx); err != nil {
		return nil, err
	}
	st, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, c.wrapCall("accept stream", err)
	}
	return newQUICStream(c, st), nil
}

// Control returns the connection level control stream.
//
// The client opens the first bidirectional stream; the server treats the first
// accepted bidirectional stream as the control stream. The stream is created
// lazily exactly once (sync.Once) and is also ensured by OpenStream and
// AcceptStream so the control stream is always the first stream on the wire.
func (c *quicConn) Control(ctx context.Context) (ControlStream, error) {
	ctrl, err := c.ensureControl(ctx)
	if err != nil {
		return nil, err
	}
	return ctrl, nil
}

func (c *quicConn) ensureControl(ctx context.Context) (*quicControl, error) {
	c.ctrlOnce.Do(func() {
		if err := c.doneErr(); err != nil {
			c.ctrlErr = err
			return
		}
		var (
			st  quic.Stream
			err error
		)
		if c.client {
			st, err = c.conn.OpenStreamSync(ctx)
		} else {
			st, err = c.conn.AcceptStream(ctx)
		}
		if err != nil {
			if cerr := c.doneErr(); cerr != nil {
				c.ctrlErr = cerr
			} else {
				c.ctrlErr = fmt.Errorf("transport: quic control stream: %w", err)
			}
			return
		}
		c.ctrl = newQUICControl(c, st)
	})
	if c.ctrlErr != nil {
		return nil, c.ctrlErr
	}
	return c.ctrl, nil
}

// CloseWithError closes the QUIC connection. It is idempotent.
func (c *quicConn) CloseWithError(code uint64, reason string) error {
	cerr := fmt.Errorf("%w (quic application code %d: %s)", ErrConnClosed, code, reason)
	alreadyClosed := c.doneErr() != nil
	c.markClosed(cerr)
	if alreadyClosed {
		return nil
	}
	_ = c.conn.CloseWithError(quic.ApplicationErrorCode(code), reason)
	return nil
}

// LocalAddr implements Conn.
func (c *quicConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// RemoteAddr implements Conn.
func (c *quicConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// HandshakeComplete reports whether the TLS handshake finished. Server side
// connections returned by quic.Listener.Accept always have completed their
// handshake; client side connections may be handshaking when 0-RTT is enabled.
func (c *quicConn) HandshakeComplete() bool {
	return c.conn.ConnectionState().TLS.HandshakeComplete
}

// waitGoroutines blocks until the connection watcher goroutine exited. Used by
// package tests to assert cleanup; not part of the Conn contract.
func (c *quicConn) waitGoroutines(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}
