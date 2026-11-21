package transport

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocket transport defaults.
const (
	// defaultWSPath is the HTTP path the upgrade handler answers on.
	defaultWSPath = "/tunnel"
	// wsDefaultWriteQueueFrames bounds the per connection data frame queue.
	wsDefaultWriteQueueFrames = 64
	// wsDefaultControlQueueFrames bounds the high priority control frame queue.
	wsDefaultControlQueueFrames = 64
	// wsDefaultAcceptQueue bounds the listener level connection accept queue.
	wsDefaultAcceptQueue = 256
	// wsDefaultStreamAcceptQueue bounds the per connection logical stream
	// accept queue.
	wsDefaultStreamAcceptQueue = 256
	// wsMaxLateFrames is the number of stale (old epoch / unknown stream)
	// frames tolerated before the peer is treated as broken.
	wsMaxLateFrames = 100
	// wsCloseDeadline bounds the best effort websocket close message.
	wsCloseDeadline = 250 * time.Millisecond
)

// wsRole identifies which side of the connection this endpoint is. It decides
// the stream id parity: the dialer allocates odd sequence numbers, the listener
// even ones, so both sides can open streams without id collisions.
type wsRole uint8

const (
	wsRoleClient wsRole = iota
	wsRoleServer
)

// WSListener is the server side WebSocket transport.
//
// It does not own a TCP listener: mount Handler on the HTTP server that
// terminates wss:// (or ws:// for local development) and call Accept to
// receive upgraded connections.
type WSListener struct {
	opts     WSOptions
	path     string
	upgrader websocket.Upgrader

	acceptCh chan *wsConn
	done     chan struct{}
	once     sync.Once

	mu    sync.Mutex
	conns map[*wsConn]struct{}
	addr  atomic.Value // net.Addr
}

// NewWSListener creates a WebSocket tunnel listener.
//
// WSOptions.Path selects the HTTP path served by Handler (default /tunnel);
// WSOptions.MaxFrameBytes bounds a single inner frame payload (default 64 KiB);
// WSOptions.WriteQueueFrames bounds the data frame queue; WSOptions.ReadLimit
// bounds a single WebSocket message (default MaxFrameBytes+protocol.FrameHeaderLen).
func NewWSListener(opts WSOptions) *WSListener {
	path := opts.Path
	if path == "" {
		path = defaultWSPath
	}
	if path[0] != '/' {
		path = "/" + path
	}
	l := &WSListener{
		opts:     opts,
		path:     path,
		acceptCh: make(chan *wsConn, wsDefaultAcceptQueue),
		done:     make(chan struct{}),
		conns:    make(map[*wsConn]struct{}),
	}
	l.upgrader = websocket.Upgrader{
		HandshakeTimeout:  opts.HandshakeTimeout,
		CheckOrigin:       func(*http.Request) bool { return true }, // non browser clients do not send Origin
		EnableCompression: false,
	}
	return l
}

// Handler returns the HTTP handler that upgrades tunnel WebSocket clients. It
// must be mounted by the embedding HTTP server; the listener never serves HTTP
// itself.
func (l *WSListener) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != l.path {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		select {
		case <-l.done:
			http.Error(w, "tunnel listener closed", http.StatusServiceUnavailable)
			return
		default:
		}
		ws, err := l.upgrader.Upgrade(w, r, nil)
		if err != nil {
			// Upgrade already wrote an HTTP error response.
			return
		}
		c := newWSConn(ws, wsRoleServer, l.opts, l.unregister)
		if !l.register(c) {
			c.closeWithError(ErrListenerClosed)
			return
		}
		select {
		case <-l.done:
			c.closeWithError(ErrListenerClosed)
		case l.acceptCh <- c:
		default:
			// The accept queue is full: refuse this connection instead of
			// blocking the HTTP handler goroutine.
			c.closeWithError(ErrAcceptQueueFull)
		}
	})
}

// register tracks a connection; it fails when the listener is already closed.
func (l *WSListener) register(c *wsConn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.done:
		return false
	default:
	}
	l.conns[c] = struct{}{}
	return true
}

// unregister is the close hook of every accepted connection.
func (l *WSListener) unregister(c *wsConn) {
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
}

// Accept returns the next upgraded tunnel connection.
func (l *WSListener) Accept(ctx context.Context) (Conn, error) {
	select {
	case <-l.done:
		return nil, ErrListenerClosed
	default:
	}
	select {
	case <-l.done:
		return nil, ErrListenerClosed
	case c := <-l.acceptCh:
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close stops the listener, closes queued connections and every live
// connection it accepted. It is idempotent.
func (l *WSListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		for {
			select {
			case c := <-l.acceptCh:
				c.closeWithError(ErrListenerClosed)
			default:
				goto drained
			}
		}
	drained:
		l.mu.Lock()
		conns := make([]*wsConn, 0, len(l.conns))
		for c := range l.conns {
			conns = append(conns, c)
		}
		l.mu.Unlock()
		for _, c := range conns {
			c.closeWithError(ErrListenerClosed)
		}
	})
	return nil
}

// Addr returns the address the listener is served on. SetAddr can be used by
// the embedding HTTP server to publish the real address; otherwise the local
// address of the most recently accepted connection is used.
func (l *WSListener) Addr() net.Addr {
	if a, ok := l.addr.Load().(net.Addr); ok && a != nil {
		return a
	}
	l.mu.Lock()
	for c := range l.conns {
		if a := c.LocalAddr(); a != nil {
			l.mu.Unlock()
			return a
		}
		break
	}
	l.mu.Unlock()
	return wsAddr{network: "ws"}
}

// SetAddr records the TCP address this listener's HTTP server is bound to.
func (l *WSListener) SetAddr(addr net.Addr) {
	if addr != nil {
		l.addr.Store(addr)
	}
}

// Kind implements Listener.
func (l *WSListener) Kind() Kind { return KindWS }

// DialWS dials a WebSocket tunnel server.
//
// opts.URL must be a ws:// or wss:// URL. The dialer is a clone of
// websocket.DefaultDialer with the configured TLS config, handshake timeout and
// message size limit applied. The tunnel protocol is identical on ws:// and
// wss://; the TLS decision is made by the URL scheme (the caller is responsible
// for only allowing plain ws:// on loopback or in development).
func DialWS(ctx context.Context, opts WSOptions) (Conn, error) {
	u, err := url.Parse(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("transport: ws: parse URL %q: %w", opts.URL, err)
	}
	switch u.Scheme {
	case "ws", "wss":
	default:
		return nil, fmt.Errorf("transport: ws: unsupported URL scheme %q (want ws or wss)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("transport: ws: URL %q has no host", opts.URL)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	dialer := *websocket.DefaultDialer
	dialer.EnableCompression = false
	if opts.HandshakeTimeout > 0 {
		dialer.HandshakeTimeout = opts.HandshakeTimeout
	}
	if opts.TLS != nil {
		dialer.TLSClientConfig = opts.TLS.Clone()
	}
	ws, resp, err := dialer.DialContext(ctx, opts.URL, opts.Header)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("transport: ws dial %q: %w", opts.URL, ctxErr)
		}
		return nil, fmt.Errorf("transport: ws dial %q: %w", opts.URL, err)
	}
	c := newWSConn(ws, wsRoleClient, opts, nil)
	return c, nil
}

// wsAddr is a synthetic net.Addr used when the listener address is unknown.
type wsAddr struct {
	network string
	addr    string
}

func (a wsAddr) Network() string { return a.network }

func (a wsAddr) String() string {
	if a.addr == "" {
		return "ws"
	}
	return a.addr
}

// Compile time interface assertions.
var (
	_ Listener      = (*WSListener)(nil)
	_ Listener      = (*quicListener)(nil)
	_ Conn          = (*wsConn)(nil)
	_ Conn          = (*quicConn)(nil)
	_ Stream        = (*wsStream)(nil)
	_ Stream        = (*quicStream)(nil)
	_ ControlStream = (*wsControl)(nil)
	_ ControlStream = (*quicControl)(nil)
	_ EpochSetter   = (*wsConn)(nil)
)
