package integration

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"testing"
	"time"

	"proxygw/internal/config"
	"proxygw/internal/metrics"
	"proxygw/internal/model"
)

// TestZstdCompressedProxy proves end-to-end zstd stream compression over a real
// QUIC tunnel with two planes: a 100 KiB random POST roundtrips byte for byte,
// keep-alive HTTP and CONNECT keep working, and the tunnel byte counters show
// that compressible bodies really travel compressed on the wire.
func TestZstdCompressedProxy(t *testing.T) {
	// The ACL forced deny list blocks loopback targets; the documented test-only
	// escape hatch lets this in-process test reach a local origin server.
	t.Setenv("NP_ACL_ALLOW_LOOPBACK_TARGETS", "1")

	originAddr, stopOrigin := startCompressionOrigin(t)
	defer stopOrigin()

	ts := startServer(t, func(c *config.ServerConfig) {
		c.Proxy.AuthMode = model.AuthNone
		c.Settings.Compression = true
	})
	tc := startClient(t, ts, ts.pin, func(c *config.ClientConfig) {
		c.Compression = true
		c.Planes = 2
	})
	node := waitNodeOnline(t, ts)
	// Two QUIC planes are the precondition for a fully populated plane session.
	waitFor(t, 20*time.Second, "two QUIC planes", func() bool {
		n, ok := ts.app.Registry().Get(node.ID)
		return ok && n.Planes >= 2
	})
	// The negotiated zstd capability is what makes the server flag OPEN headers
	// as compressed.
	waitFor(t, 10*time.Second, "negotiated zstd compression", func() bool {
		n, ok := ts.app.Registry().Get(node.ID)
		return ok && n.Compression
	})
	negotiated, ok := ts.app.Registry().Get(node.ID)
	if !ok {
		t.Fatal("registry lost the node")
	}
	if !negotiated.Compression {
		t.Fatalf("node compression not negotiated: %+v", negotiated)
	}
	hasZstd := false
	for _, cap := range negotiated.Capabilities {
		if cap == "zstd" {
			hasZstd = true
		}
	}
	if !hasZstd {
		t.Fatalf("node capabilities %v do not include zstd", negotiated.Capabilities)
	}
	if !ts.app.Settings().Current().Compression {
		t.Fatal("server settings compression_enabled is not enabled")
	}
	if got := tc.client.Status().Transport; got != "quic" {
		t.Fatalf("expected QUIC transport, got %q", got)
	}
	if ts.app.Registry().OnlineCount() != 1 {
		t.Fatalf("online nodes = %d, want 1", ts.app.Registry().OnlineCount())
	}

	httpAddr, _ := ts.app.ProxyAddrs()
	if httpAddr == "" {
		t.Fatal("HTTP proxy listener is not bound")
	}
	proxyURL, err := url.Parse("http://" + httpAddr)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}
	transport := &http.Transport{
		Proxy:               http.ProxyURL(proxyURL),
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 60 * time.Second}

	baseOut := tunnelBytes(t, ts.app.Metrics(), "out")
	baseIn := tunnelBytes(t, ts.app.Metrics(), "in")

	// 1) 100 KiB of random (incompressible) data must survive the compressed
	// tunnel unchanged in both directions.
	randomBody := make([]byte, 100<<10)
	if _, err := rand.Read(randomBody); err != nil {
		t.Fatalf("generate random body: %v", err)
	}
	gotRandom := postEcho(t, client, "http://"+originAddr+"/echo", randomBody)
	if !bytes.Equal(gotRandom, randomBody) {
		t.Fatalf("random echo mismatch: got %d bytes, want %d", len(gotRandom), len(randomBody))
	}

	// 2) The same connection is reused for a compressible body (keep-alive over
	// one compressed tunnel stream).
	compressible := bytes.Repeat([]byte("compressible-http-body-"), 12<<10) // ~288 KiB
	reused := make(chan bool, 1)
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			select {
			case reused <- info.Reused:
			default:
			}
		},
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+originAddr+"/echo", bytes.NewReader(compressible))
	if err != nil {
		t.Fatalf("build keep-alive request: %v", err)
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("compressible POST: %v", err)
	}
	gotCompressible, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatalf("read compressible response: %v", err)
	}
	if resp.StatusCode != http.StatusOK || !bytes.Equal(gotCompressible, compressible) {
		t.Fatalf("compressible echo mismatch: status=%d got=%d want=%d", resp.StatusCode, len(gotCompressible), len(compressible))
	}
	select {
	case wasReused := <-reused:
		if !wasReused {
			t.Fatal("second HTTP request did not reuse the keep-alive connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no httptrace GotConn event")
	}

	// 3) CONNECT over the compressed tunnel must still carry a plain HTTP
	// exchange to the origin.
	assertCompressedConnect(t, httpAddr, originAddr)

	// Closing the idle client connections tears the tunnel streams down; the
	// tunnel layer then accounts the raw (compressed) bytes it carried.
	transport.CloseIdleConnections()
	plaintextOut := int64(len(randomBody) + len(compressible))
	plaintextIn := plaintextOut
	waitFor(t, 15*time.Second, "tunnel byte accounting", func() bool {
		return tunnelBytes(t, ts.app.Metrics(), "out")-baseOut >= float64(len(compressible)/8)
	})
	outDelta := tunnelBytes(t, ts.app.Metrics(), "out") - baseOut
	inDelta := tunnelBytes(t, ts.app.Metrics(), "in") - baseIn
	if outDelta >= float64(plaintextOut)/2 {
		t.Fatalf("compressed upload bytes = %.0f, plaintext = %d: stream was not compressed", outDelta, plaintextOut)
	}
	if inDelta >= float64(plaintextIn)/2 {
		t.Fatalf("compressed download bytes = %.0f, plaintext = %d: stream was not compressed", inDelta, plaintextIn)
	}
	t.Logf("tunnel wire upload=%.0f download=%.0f vs plaintext %d/%d", outDelta, inDelta, plaintextOut, plaintextIn)
}

// startCompressionOrigin starts a local HTTP origin server: /echo echoes the
// request body and /hello returns a fixed text body. Both use an explicit
// Content-Length so HTTP/1.1 keep-alive stays usable.
func startCompressionOrigin(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen origin: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		const body = "compressed-connect-ok"
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = io.WriteString(w, body)
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(ln) }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		_ = server.Close()
	}
	t.Cleanup(stop)
	return ln.Addr().String(), stop
}

// postEcho POSTs body to rawURL through the proxy and returns the echoed bytes.
func postEcho(t *testing.T, client *http.Client, rawURL string, body []byte) []byte {
	t.Helper()
	resp, err := client.Post(rawURL, "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s status = %d", rawURL, resp.StatusCode)
	}
	echoed, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read POST response: %v", err)
	}
	return echoed
}

// assertCompressedConnect performs a raw HTTP CONNECT through the proxy and then
// a plain HTTP/1.1 request inside the tunnel.
func assertCompressedConnect(t *testing.T, proxyAddr, originAddr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	br := bufio.NewReader(conn)
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", originAddr, originAddr)
	if _, err := io.WriteString(conn, connectReq); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	connectResp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer connectResp.Body.Close()
	if connectResp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", connectResp.StatusCode)
	}
	getReq := fmt.Sprintf("GET /hello HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", originAddr)
	if _, err := io.WriteString(conn, getReq); err != nil {
		t.Fatalf("write tunneled GET: %v", err)
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read tunneled response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read tunneled body: %v", err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "compressed-connect-ok" {
		t.Fatalf("tunneled CONNECT response = %d %q", resp.StatusCode, body)
	}
}

// tunnelBytes sums the tunnel_bytes_total counter for one direction across all
// node labels.
func tunnelBytes(t *testing.T, m *metrics.Metrics, direction string) float64 {
	t.Helper()
	families, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	var total float64
	for _, family := range families {
		if family.GetName() != "tunnel_bytes_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			matched := false
			for _, label := range metric.GetLabel() {
				if label.GetName() == "direction" && label.GetValue() == direction {
					matched = true
				}
			}
			if matched && metric.GetCounter() != nil {
				total += metric.GetCounter().GetValue()
			}
		}
	}
	return total
}
