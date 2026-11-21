package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"proxygw/internal/metrics"
	"proxygw/internal/model"
	"proxygw/internal/protocol"
)

// discardLogger keeps test output clean.
var discardLogger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

// testSettings returns fast timeouts suitable for unit tests.
func testSettings() model.Settings {
	s := model.DefaultSettings()
	s.Timeouts.Open = model.D(2 * time.Second)
	s.Timeouts.ReadHeader = model.D(2 * time.Second)
	s.Timeouts.Idle = model.D(5 * time.Second)
	s.Timeouts.WriteBlock = model.D(2 * time.Second)
	s.Timeouts.Linger = model.D(300 * time.Millisecond)
	s.Timeouts.Drain = model.D(2 * time.Second)
	return s
}

// settingsBox is a hot settings provider with a mutable override hook.
type settingsBox struct {
	mu  sync.Mutex
	cur model.Settings
}

func newSettingsBox() *settingsBox {
	return &settingsBox{cur: testSettings()}
}

func (b *settingsBox) get() model.Settings {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cur
}

func (b *settingsBox) set(fn func(*model.Settings)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	fn(&b.cur)
}

// baseOptions returns options for an open (auth none) proxy with fakes.
func baseOptions() Options {
	return Options{
		Logger:   discardLogger,
		Settings: testSettings,
		AuthMode: model.AuthNone,
	}
}

// mustNode returns an enabled and online node.
func mustNode(id string) *model.Node {
	return &model.Node{ID: id, Alias: id, Enabled: true, Online: true}
}

// testCredential returns an enabled credential.
func testCredential(id, username string) *model.Credential {
	return &model.Credential{ID: id, Username: username, Enabled: true}
}

// fakeAuthenticator verifies username/password pairs against a fixed table.
type fakeAuthenticator struct {
	mu          sync.Mutex
	users       map[string]string
	creds       map[string]*model.Credential
	verifyCalls int
	panicNow    bool
}

func newFakeAuthenticator() *fakeAuthenticator {
	return &fakeAuthenticator{users: map[string]string{}, creds: map[string]*model.Credential{}}
}

// add registers one username/password/credential triple.
func (f *fakeAuthenticator) add(username, password string, cred *model.Credential) *fakeAuthenticator {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[username] = password
	f.creds[username] = cred
	return f
}

// Verify implements Authenticator.
func (f *fakeAuthenticator) Verify(username, password string) (*model.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifyCalls++
	if f.panicNow {
		panic("fake authenticator panic")
	}
	cred, ok := f.creds[username]
	if !ok {
		return nil, errors.New("unknown user")
	}
	if f.users[username] != password {
		return nil, errors.New("bad password")
	}
	return cred, nil
}

// fakeCandidates returns a fixed candidate set.
type fakeCandidates struct {
	mu     sync.Mutex
	nodes  []*model.Node
	err    error
	calls  int
	groups [][]string
}

func newFakeCandidates(nodes ...*model.Node) *fakeCandidates {
	return &fakeCandidates{nodes: nodes}
}

func (f *fakeCandidates) setNodes(nodes ...*model.Node) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodes = nodes
}

func (f *fakeCandidates) setError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeCandidates) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// Candidates implements CandidateResolver.
func (f *fakeCandidates) Candidates(groups []string) ([]*model.Node, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.groups = append(f.groups, append([]string(nil), groups...))
	if f.err != nil {
		return nil, f.err
	}
	return append([]*model.Node(nil), f.nodes...), nil
}

// selectorResult records one RecordResult call.
type selectorResult struct {
	nodeID string
	err    error
}

// fakeSelector selects the first candidate unless a hook is set.
type fakeSelector struct {
	mu            sync.Mutex
	pick          func(req SelectRequest, candidates []*model.Node) (*model.Node, SelectionInfo, error)
	calls         int
	requests      []SelectRequest
	results       []selectorResult
	panicOnSelect bool
}

func (f *fakeSelector) setPick(fn func(req SelectRequest, candidates []*model.Node) (*model.Node, SelectionInfo, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pick = fn
}

func (f *fakeSelector) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeSelector) lastRequest() SelectRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		return SelectRequest{}
	}
	return f.requests[len(f.requests)-1]
}

func (f *fakeSelector) resultCalls() []selectorResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]selectorResult(nil), f.results...)
}

func (f *fakeSelector) setPanic(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.panicOnSelect = v
}

// Select implements Selector.
func (f *fakeSelector) Select(ctx context.Context, req SelectRequest, candidates []*model.Node) (*model.Node, SelectionInfo, error) {
	f.mu.Lock()
	f.calls++
	f.requests = append(f.requests, req)
	pick := f.pick
	panicNow := f.panicOnSelect
	f.mu.Unlock()
	if panicNow {
		panic("fake selector panic")
	}
	if pick != nil {
		return pick(req, candidates)
	}
	select {
	case <-ctx.Done():
		return nil, SelectionInfo{}, ctx.Err()
	default:
	}
	if len(candidates) == 0 {
		return nil, SelectionInfo{}, errors.New("no candidates")
	}
	return candidates[0], SelectionInfo{Strategy: model.StrategyRandom, Reason: "strategy"}, nil
}

// RecordResult implements Selector.
func (f *fakeSelector) RecordResult(nodeID string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, selectorResult{nodeID: nodeID, err: err})
}

// fakeACL is a programmable ACL checker.
type fakeACL struct {
	mu          sync.Mutex
	check       func(t model.RequestTarget) error
	calls       int
	panicOnDeny bool
}

func (f *fakeACL) setCheck(fn func(t model.RequestTarget) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.check = fn
}

func (f *fakeACL) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeACL) setPanic(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.panicOnDeny = v
}

// Check implements ACLChecker.
func (f *fakeACL) Check(t model.RequestTarget) error {
	f.mu.Lock()
	f.calls++
	panicNow := f.panicOnDeny
	check := f.check
	f.mu.Unlock()
	if panicNow {
		panic("fake acl panic")
	}
	if check != nil {
		return check(t)
	}
	return nil
}

// fakeDialer opens real TCP connections to the requested target, simulating a
// node that dials the target from its own network. A handler may replace that
// behaviour.
type fakeDialer struct {
	mu      sync.Mutex
	calls   int
	opens   []dialCall
	handler func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error)
}

// dialCall records one OpenStream invocation.
type dialCall struct {
	nodeID string
	host   string
	port   int
	trace  [protocol.TraceIDLen]byte
	flags  uint8
}

func (f *fakeDialer) setHandler(fn func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handler = fn
}

func (f *fakeDialer) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeDialer) openCalls() []dialCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]dialCall(nil), f.opens...)
}

// OpenStream implements StreamDialer.
func (f *fakeDialer) OpenStream(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
	f.mu.Lock()
	f.calls++
	f.opens = append(f.opens, dialCall{nodeID: nodeID, host: req.Host, port: int(req.Port), trace: req.TraceID, flags: req.Flags})
	handler := f.handler
	f.mu.Unlock()
	if handler != nil {
		return handler(ctx, nodeID, req)
	}
	return dialTarget(ctx, req.Host, int(req.Port))
}

// tcpStream wraps a TCP connection and implements StreamConn.
type tcpStream struct {
	*net.TCPConn
}

// CloseWrite implements StreamConn.
func (t *tcpStream) CloseWrite() error { return t.TCPConn.CloseWrite() }

// dialTarget dials the requested target like a node would.
func dialTarget(ctx context.Context, host string, port int) (StreamConn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, classifyDialError(err)
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, protocol.NewError(protocol.CodeInternal, "unexpected connection type %T", conn)
	}
	return &tcpStream{TCPConn: tcp}, nil
}

// classifyDialError converts a dial error into the OPEN error code of the
// attachment.
func classifyDialError(err error) error {
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr):
		return protocol.NewError(protocol.CodeDNS, "%v", err)
	case errors.Is(err, syscall.ECONNREFUSED):
		return protocol.NewError(protocol.CodeConnRefused, "%v", err)
	case isTimeout(err):
		return protocol.NewError(protocol.CodeTimeout, "%v", err)
	default:
		return protocol.NewError(protocol.CodeInternal, "%v", err)
	}
}

// memStream is an in-memory StreamConn backed by two io.Pipe instances with
// working half-close semantics.
type memStream struct {
	r *io.PipeReader
	w *io.PipeWriter
}

// Read implements io.Reader.
func (m *memStream) Read(p []byte) (int, error) { return m.r.Read(p) }

// Write implements io.Writer.
func (m *memStream) Write(p []byte) (int, error) { return m.w.Write(p) }

// Close releases both directions.
func (m *memStream) Close() error {
	_ = m.r.Close()
	return m.w.Close()
}

// CloseWrite releases the write direction only.
func (m *memStream) CloseWrite() error { return m.w.Close() }

// memPipePair returns two connected in-memory streams.
func memPipePair() (*memStream, *memStream) {
	a2bReader, a2bWriter := io.Pipe()
	b2aReader, b2aWriter := io.Pipe()
	return &memStream{r: b2aReader, w: a2bWriter}, &memStream{r: a2bReader, w: b2aWriter}
}

// echoServer is a local TCP echo server with half-close support.
type echoServer struct {
	ln     net.Listener
	wg     sync.WaitGroup
	closed chan struct{}
}

// newEchoServer starts an echo server on the given network/"host:port".
func newEchoServer(t *testing.T, network, address string) *echoServer {
	t.Helper()
	ln, err := net.Listen(network, address)
	if err != nil {
		t.Skipf("listen %s %s: %v", network, address, err)
	}
	server := &echoServer{ln: ln, closed: make(chan struct{})}
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			server.wg.Add(1)
			go func() {
				defer server.wg.Done()
				echoConn(conn)
			}()
		}
	}()
	t.Cleanup(server.close)
	return server
}

// echoConn echoes bytes until the peer closes its write direction.
func echoConn(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 16*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
			return
		}
	}
}

// addr returns the listener address.
func (e *echoServer) addr() string { return e.ln.Addr().String() }

// hostPort returns the listener host and port.
func (e *echoServer) hostPort(t *testing.T) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(e.ln.Addr().String())
	if err != nil {
		t.Fatalf("split echo address: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("echo port: %v", err)
	}
	return host, port
}

// close stops the echo server.
func (e *echoServer) close() {
	select {
	case <-e.closed:
	default:
		close(e.closed)
		_ = e.ln.Close()
		e.wg.Wait()
	}
}

// startHTTPProxy starts an HTTP proxy on a loopback listener.
func startHTTPProxy(t *testing.T, opts Options) (string, *HTTPProxy) {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = discardLogger
	}
	if opts.Settings == nil {
		opts.Settings = testSettings
	}
	if opts.Candidates == nil {
		opts.Candidates = newFakeCandidates(mustNode("node-1"))
	}
	if opts.Selector == nil {
		opts.Selector = &fakeSelector{}
	}
	if opts.Dialer == nil {
		opts.Dialer = &fakeDialer{}
	}
	proxy, err := NewHTTPProxy(opts)
	if err != nil {
		t.Fatalf("NewHTTPProxy: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- proxy.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		_ = proxy.Close(context.Background())
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("HTTP proxy Serve returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("HTTP proxy did not stop in time")
		}
	})
	return ln.Addr().String(), proxy
}

// startSOCKS5Proxy starts a SOCKS5 proxy on a loopback listener.
func startSOCKS5Proxy(t *testing.T, opts Options) (string, *SOCKS5Proxy) {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = discardLogger
	}
	if opts.Settings == nil {
		opts.Settings = testSettings
	}
	if opts.Candidates == nil {
		opts.Candidates = newFakeCandidates(mustNode("node-1"))
	}
	if opts.Selector == nil {
		opts.Selector = &fakeSelector{}
	}
	if opts.Dialer == nil {
		opts.Dialer = &fakeDialer{}
	}
	proxy, err := NewSOCKS5Proxy(opts)
	if err != nil {
		t.Fatalf("NewSOCKS5Proxy: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- proxy.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		_ = proxy.Close(context.Background())
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("SOCKS5 proxy Serve returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("SOCKS5 proxy did not stop in time")
		}
	})
	return ln.Addr().String(), proxy
}

// proxyURL builds a proxy URL, optionally with credentials.
func proxyURL(t *testing.T, addr, username, password string) *url.URL {
	t.Helper()
	raw := "http://"
	if username != "" || password != "" {
		raw += url.UserPassword(username, password).String() + "@"
	}
	raw += addr
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	return u
}

// httpClientViaProxy returns a keep-alive capable HTTP client routed through the
// proxy described by rawProxyURL.
func httpClientViaProxy(t *testing.T, rawProxyURL string) *http.Client {
	t.Helper()
	u, err := url.Parse(rawProxyURL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyURL(u),
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		ExpectContinueTimeout: 200 * time.Millisecond,
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

// dialTCP dials addr and registers the close with the test cleanup.
func dialTCP(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// readHTTPResponse reads one response from br.
func readHTTPResponse(t *testing.T, br *bufio.Reader, method string) *http.Response {
	t.Helper()
	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

// connectTunnel issues a CONNECT request and returns the raw connection plus the
// buffered reader that must be used for tunnel bytes.
func connectTunnel(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn := dialTCP(t, proxyAddr)
	br := bufio.NewReader(conn)
	request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp := readHTTPResponse(t, br, http.MethodConnect)
	return conn, br, resp
}

// tcpTarget formats host and port as host:port.
func tcpTarget(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// newTestMetrics returns an isolated metrics set.
func newTestMetrics() *metrics.Metrics { return metrics.New() }

// metricValue returns the value of the counter, gauge or histogram sample count
// with the given metric name and label subset.
func metricValue(t *testing.T, registry *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			matched := 0
			for _, pair := range metric.GetLabel() {
				if want, ok := labels[pair.GetName()]; ok && want == pair.GetValue() {
					matched++
				}
			}
			if matched != len(labels) {
				continue
			}
			if counter := metric.GetCounter(); counter != nil {
				return counter.GetValue()
			}
			if gauge := metric.GetGauge(); gauge != nil {
				return gauge.GetValue()
			}
			if histogram := metric.GetHistogram(); histogram != nil {
				return float64(histogram.GetSampleCount())
			}
		}
	}
	return 0
}

// newLocalHTTPServer starts a local HTTP server for upstream tests.
func newLocalHTTPServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

// serverTarget returns the host and port of an httptest server.
func serverTarget(t *testing.T, server *httptest.Server) (string, int) {
	t.Helper()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("server port: %v", err)
	}
	return u.Hostname(), port
}
