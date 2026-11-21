package proxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// TestHTTPForwardAbsoluteForm verifies absolute-form forwarding, origin-form
// rewriting and hop-by-hop header stripping.
func TestHTTPForwardAbsoluteForm(t *testing.T) {
	type seenRequest struct {
		method    string
		uri       string
		host      string
		proxyAuth string
		proxyConn string
		keepAlive string
		te        string
		xCustom   string
		body      string
	}
	seen := make(chan seenRequest, 1)
	upstream := newLocalHTTPServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen <- seenRequest{
			method:    r.Method,
			uri:       r.URL.RequestURI(),
			host:      r.Host,
			proxyAuth: r.Header.Get("Proxy-Authorization"),
			proxyConn: r.Header.Get("Proxy-Connection"),
			keepAlive: r.Header.Get("Keep-Alive"),
			te:        r.Header.Get("TE"),
			xCustom:   r.Header.Get("X-Custom"),
			body:      string(body),
		}
		w.Header().Set("X-Origin", "proxygw-test")
		_, _ = io.WriteString(w, "hello-proxy")
	})
	host, port := serverTarget(t, upstream)
	proxyAddr, _ := startHTTPProxy(t, baseOptions())
	client := httpClientViaProxy(t, "http://"+proxyAddr)

	rawConn := dialTCP(t, proxyAddr)
	br := bufio.NewReader(rawConn)
	fmt.Fprintf(rawConn, "GET http://%s:%d/path?q=1 HTTP/1.1\r\nHost: %s:%d\r\n"+
		"Proxy-Connection: keep-alive\r\nKeep-Alive: timeout=5\r\nTE: trailers\r\n"+
		"X-Custom: drop-me\r\nConnection: x-custom\r\nProxy-Authorization: Basic Zm9vOmJhcg==\r\n\r\n",
		host, port, host, port)
	resp := readHTTPResponse(t, br, http.MethodGet)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "hello-proxy" {
		t.Fatalf("body = %q, want hello-proxy", body)
	}
	if got := resp.Header.Get("X-Origin"); got != "proxygw-test" {
		t.Fatalf("X-Origin = %q", got)
	}
	got := <-seen
	if got.method != http.MethodGet {
		t.Errorf("method = %q", got.method)
	}
	if got.uri != "/path?q=1" {
		t.Errorf("request URI = %q, want origin form /path?q=1", got.uri)
	}
	if got.host != tcpTarget(host, port) {
		t.Errorf("host header = %q", got.host)
	}
	for name, value := range map[string]string{
		"Proxy-Authorization": got.proxyAuth,
		"Proxy-Connection":    got.proxyConn,
		"Keep-Alive":          got.keepAlive,
		"TE":                  got.te,
		"X-Custom":            got.xCustom,
	} {
		if value != "" {
			t.Errorf("hop-by-hop header %s leaked upstream: %q", name, value)
		}
	}
	_ = client // the keep-alive client is exercised in a dedicated test
}

// TestHTTPForwardChunkedResponse verifies a chunked origin response is streamed
// back to the client.
func TestHTTPForwardChunkedResponse(t *testing.T) {
	upstream := newLocalHTTPServer(t, func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("response writer is not a flusher")
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "part-one")
		flusher.Flush()
		_, _ = io.WriteString(w, "part-two")
	})
	host, port := serverTarget(t, upstream)
	proxyAddr, _ := startHTTPProxy(t, baseOptions())
	client := httpClientViaProxy(t, "http://"+proxyAddr)
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/chunked", host, port))
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read chunked body: %v", err)
	}
	if string(body) != "part-onepart-two" {
		t.Fatalf("body = %q", body)
	}
	if len(resp.TransferEncoding) == 0 || resp.TransferEncoding[0] != "chunked" {
		t.Logf("warning: client did not observe chunked framing: %v", resp.TransferEncoding)
	}
}

// unknownLengthBody hides its length so the client Transport uses chunked
// request encoding.
type unknownLengthBody struct {
	data []byte
	off  int
}

func (b *unknownLengthBody) Read(p []byte) (int, error) {
	if b.off >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.off:])
	b.off += n
	return n, nil
}

func (b *unknownLengthBody) Close() error { return nil }

// TestHTTPForwardRequestBodies verifies Content-Length and chunked request
// bodies are streamed to the origin.
func TestHTTPForwardRequestBodies(t *testing.T) {
	upstream := newLocalHTTPServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Body-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	})
	host, port := serverTarget(t, upstream)
	proxyAddr, _ := startHTTPProxy(t, baseOptions())
	client := httpClientViaProxy(t, "http://"+proxyAddr)
	target := fmt.Sprintf("http://%s:%d/echo", host, port)

	t.Run("content-length", func(t *testing.T) {
		resp, err := client.Post(target, "text/plain", strings.NewReader("fixed-length-body"))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "fixed-length-body" {
			t.Fatalf("echoed body = %q", body)
		}
	})

	t.Run("chunked", func(t *testing.T) {
		payload := bytes.Repeat([]byte("chunk-data-"), 1000)
		req, err := http.NewRequest(http.MethodPost, target, &unknownLengthBody{data: payload})
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST chunked: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if !bytes.Equal(body, payload) {
			t.Fatalf("chunked echo mismatch: got %d bytes want %d", len(body), len(payload))
		}
	})
}

// TestHTTPKeepAliveUpstreamReuse verifies consecutive requests on one client
// connection reuse the same upstream stream.
func TestHTTPKeepAliveUpstreamReuse(t *testing.T) {
	var hits atomic.Int32
	upstream := newLocalHTTPServer(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	})
	host, port := serverTarget(t, upstream)
	dialer := &fakeDialer{}
	opts := baseOptions()
	opts.Dialer = dialer
	proxyAddr, _ := startHTTPProxy(t, opts)
	client := httpClientViaProxy(t, "http://"+proxyAddr)
	for i := 0; i < 2; i++ {
		resp, err := client.Get(fmt.Sprintf("http://%s:%d/keepalive", host, port))
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "ok" {
			t.Fatalf("GET %d body = %q", i, body)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("origin hits = %d, want 2", hits.Load())
	}
	if calls := dialer.callCount(); calls != 1 {
		t.Fatalf("upstream stream opens = %d, want 1 (keep-alive reuse)", calls)
	}
}

// TestHTTPNoBodyStatus verifies 204 responses without a body.
func TestHTTPNoBodyStatus(t *testing.T) {
	upstream := newLocalHTTPServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-No-Body", "yes")
		w.WriteHeader(http.StatusNoContent)
	})
	host, port := serverTarget(t, upstream)
	proxyAddr, _ := startHTTPProxy(t, baseOptions())
	client := httpClientViaProxy(t, "http://"+proxyAddr)
	resp, err := client.Get(fmt.Sprintf("http://%s:%d/nobody", host, port))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Fatalf("204 body = %q", body)
	}
	if resp.Header.Get("X-No-Body") != "yes" {
		t.Fatalf("origin header lost")
	}
}

// TestHTTPInformationalResponse verifies 1xx responses are forwarded before the
// final response.
func TestHTTPInformationalResponse(t *testing.T) {
	upstream := newLocalHTTPServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</style.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("X-Final", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "final-body")
	})
	host, port := serverTarget(t, upstream)
	proxyAddr, _ := startHTTPProxy(t, baseOptions())
	conn := dialTCP(t, proxyAddr)
	br := bufio.NewReader(conn)
	fmt.Fprintf(conn, "GET http://%s:%d/hints HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port)
	early := readHTTPResponse(t, br, http.MethodGet)
	if early.StatusCode != http.StatusEarlyHints {
		t.Fatalf("first status = %d, want 103", early.StatusCode)
	}
	if early.Header.Get("Link") == "" {
		t.Fatalf("early hints headers lost")
	}
	final := readHTTPResponse(t, br, http.MethodGet)
	if final.StatusCode != http.StatusOK {
		t.Fatalf("final status = %d", final.StatusCode)
	}
	body, _ := io.ReadAll(final.Body)
	final.Body.Close()
	if string(body) != "final-body" {
		t.Fatalf("final body = %q", body)
	}
}

// TestHTTPUpgrade101 verifies a 101 Switching Protocols response switches the
// proxy to raw byte forwarding.
func TestHTTPUpgrade101(t *testing.T) {
	upstream := newLocalHTTPServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "testproto" {
			http.Error(w, "missing upgrade", http.StatusBadRequest)
			return
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("hijacker unavailable")
			return
		}
		conn, rw, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: testproto\r\n\r\n")
		buf := make([]byte, 4096)
		for {
			n, rerr := rw.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	})
	host, port := serverTarget(t, upstream)
	proxyAddr, _ := startHTTPProxy(t, baseOptions())
	conn, br := dialUpgradeClient(t, proxyAddr, tcpTarget(host, port), "testproto")
	if _, err := conn.Write([]byte("ping-through-upgrade")); err != nil {
		t.Fatalf("write tunnel bytes: %v", err)
	}
	echoed := make([]byte, len("ping-through-upgrade"))
	if _, err := io.ReadFull(br, echoed); err != nil {
		t.Fatalf("read echoed bytes: %v", err)
	}
	if string(echoed) != "ping-through-upgrade" {
		t.Fatalf("echoed = %q", echoed)
	}
}

// dialUpgradeClient sends an upgrade request and returns the raw tunnel.
func dialUpgradeClient(t *testing.T, proxyAddr, target, protocol string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn := dialTCP(t, proxyAddr)
	br := bufio.NewReader(conn)
	request := fmt.Sprintf("GET http://%s/upgrade HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: %s\r\n\r\n",
		target, target, protocol)
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}
	resp := readHTTPResponse(t, br, http.MethodGet)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d, want 101", resp.StatusCode)
	}
	if got := resp.Header.Get("Upgrade"); got != protocol {
		t.Fatalf("upgrade header = %q", got)
	}
	return conn, br
}

// TestHTTPInvalidTargets verifies malformed absolute targets are rejected with
// an explicit 400.
func TestHTTPInvalidTargets(t *testing.T) {
	proxyAddr, _ := startHTTPProxy(t, baseOptions())
	longHost := strings.Repeat("a", 300)
	cases := []struct {
		name    string
		request string
	}{
		{"connect-empty-host", "CONNECT :80 HTTP/1.1\r\nHost: :80\r\n\r\n"},
		{"connect-bad-port", "CONNECT example.com:notaport HTTP/1.1\r\nHost: example.com:notaport\r\n\r\n"},
		{"connect-long-host", "CONNECT " + longHost + ":80 HTTP/1.1\r\nHost: x\r\n\r\n"},
		{"origin-form", "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"},
		{"https-absolute-form", "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := dialTCP(t, proxyAddr)
			br := bufio.NewReader(conn)
			if _, err := io.WriteString(conn, tc.request); err != nil {
				t.Fatalf("write request: %v", err)
			}
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", resp.StatusCode)
			}
		})
	}
}

// TestHTTPConnectEcho verifies the CONNECT tunnel and byte transparency.
func TestHTTPConnectEcho(t *testing.T) {
	echo := newEchoServer(t, "tcp", "127.0.0.1:0")
	host, port := echo.hostPort(t)
	proxyAddr, _ := startHTTPProxy(t, baseOptions())
	conn, br, resp := connectTunnel(t, proxyAddr, tcpTarget(host, port))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	payload := []byte("hello-connect-tunnel")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(br, echoed); err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("echoed = %q", echoed)
	}
}

// TestHTTPConnectHalfClose verifies the half-close semantics of a CONNECT
// tunnel: the client can finish its write direction and still receive the tail.
func TestHTTPConnectHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("half")); err != nil {
			return
		}
		buf := make([]byte, 16)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				_, _ = conn.Write(buf[:n])
			}
			if rerr != nil {
				break
			}
		}
		_, _ = conn.Write([]byte("tail"))
	}()
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	portNum, _ := parsePort(port)
	proxyAddr, _ := startHTTPProxy(t, baseOptions())
	conn, br, resp := connectTunnel(t, proxyAddr, tcpTarget(host, portNum))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	firstHalf := make([]byte, 4)
	if _, err := io.ReadFull(br, firstHalf); err != nil {
		t.Fatalf("read first half: %v", err)
	}
	if string(firstHalf) != "half" {
		t.Fatalf("first half = %q", firstHalf)
	}
	// Half close the client write direction, the tunnel must stay open for the
	// target's remaining response bytes.
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			t.Fatalf("close write: %v", err)
		}
	} else {
		t.Fatalf("client is not a TCP connection")
	}
	tail := make([]byte, 4)
	if _, err := io.ReadFull(br, tail); err != nil {
		t.Fatalf("read tail after half close: %v", err)
	}
	if string(tail) != "tail" {
		t.Fatalf("tail = %q", tail)
	}
}
