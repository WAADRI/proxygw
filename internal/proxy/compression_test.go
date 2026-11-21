package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"proxygw/internal/compress"
	"proxygw/internal/model"
	"proxygw/internal/protocol"
)

// zstdMagic is the little endian magic number of a zstd frame.
var zstdMagic = []byte{0x28, 0xB5, 0x2F, 0xFD}

// compressionNode returns an enabled, online node with the negotiated
// compression capability.
func compressionNode(id string, compression bool) *model.Node {
	n := mustNode(id)
	n.Compression = compression
	return n
}

// compressionEnabledOptions returns proxy options with the operator compression
// switch enabled.
func compressionEnabledOptions() Options {
	opts := baseOptions()
	box := newSettingsBox()
	box.set(func(s *model.Settings) { s.Compression = true })
	opts.Settings = box.get
	return opts
}

// recordingConn records the raw bytes written to the underlying conn. It is used
// to inspect what really travels on the tunnel wire.
type recordingConn struct {
	net.Conn

	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.buf.Write(p)
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func (c *recordingConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

// halfClosePipe adapts one end of a net.Pipe to StreamConn.
type halfClosePipe struct{ net.Conn }

// CloseWrite implements StreamConn. net.Pipe has no half close, so it releases
// the whole pipe, which is enough for the proxy relay to finish.
func (h *halfClosePipe) CloseWrite() error { return h.Conn.Close() }

// newFakeTunnelPair returns one fake tunnel stream: the proxy side (a StreamConn
// returned by the fake dialer), the node side used by the test and a recorder
// that captures every raw byte the proxy writes towards the node.
func newFakeTunnelPair() (StreamConn, net.Conn, *recordingConn) {
	proxySide, nodeSide := net.Pipe()
	rec := &recordingConn{Conn: proxySide}
	return &halfClosePipe{Conn: rec}, nodeSide, rec
}

// compressedPeer plays the node side of a compressed tunnel stream: it decodes
// what the proxy sends and encodes what the test replies.
type compressedPeer struct {
	conn net.Conn
	dec  *compress.Decoder
	enc  *compress.Encoder
}

// newCompressedPeer wraps the test side of a tunnel stream with zstd, exactly
// like the node agent does for an OPEN flagged as compressed.
func newCompressedPeer(t *testing.T, conn net.Conn) *compressedPeer {
	t.Helper()
	dec, err := compress.NewDecoder()
	if err != nil {
		t.Fatalf("compress.NewDecoder: %v", err)
	}
	if err := dec.Reset(conn); err != nil {
		_ = dec.Close()
		t.Fatalf("decoder Reset: %v", err)
	}
	enc, err := compress.NewEncoder(compress.DefaultLevel)
	if err != nil {
		_ = dec.Close()
		t.Fatalf("compress.NewEncoder: %v", err)
	}
	if err := enc.Reset(conn); err != nil {
		_ = dec.Close()
		t.Fatalf("encoder Reset: %v", err)
	}
	p := &compressedPeer{conn: conn, dec: dec, enc: enc}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = dec.Close()
		_ = enc.Close()
	})
	return p
}

// Read decompresses the proxy payload (upload direction).
func (p *compressedPeer) Read(b []byte) (int, error) { return p.dec.Read(b) }

// Write compresses the test payload and flushes it immediately so the proxy
// sees it without waiting for the background flush interval.
func (p *compressedPeer) Write(b []byte) (int, error) {
	n, err := p.enc.Write(b)
	if err != nil {
		return n, err
	}
	if ferr := p.enc.Flush(); ferr != nil {
		return n, ferr
	}
	return n, nil
}

// Close closes the underlying pipe.
func (p *compressedPeer) Close() error { return p.conn.Close() }

// readExactly reads exactly n plaintext bytes from the compressed peer.
func (p *compressedPeer) readExactly(t *testing.T, n int) []byte {
	t.Helper()
	out := make([]byte, n)
	if _, err := io.ReadFull(p, out); err != nil {
		t.Fatalf("read %d compressed bytes: %v", n, err)
	}
	return out
}

// TestCompressionCONNECTRoundTrip verifies a compressed CONNECT tunnel: the OPEN
// header carries protocol.FlagCompressed, the proxy really writes zstd frames
// towards the node and the payload roundtrips byte for byte.
func TestCompressionCONNECTRoundTrip(t *testing.T) {
	proxySide, nodeSide, rec := newFakeTunnelPair()
	dialer := &fakeDialer{}
	dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
		return proxySide, nil
	})
	opts := compressionEnabledOptions()
	opts.Candidates = newFakeCandidates(compressionNode("node-1", true))
	opts.Dialer = dialer
	proxyAddr, _ := startHTTPProxy(t, opts)

	client, br, resp := connectTunnel(t, proxyAddr, "origin.example:443")
	defer client.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	opens := dialer.openCalls()
	if len(opens) != 1 {
		t.Fatalf("dialer calls = %d, want 1", len(opens))
	}
	if opens[0].flags&protocol.FlagCompressed == 0 {
		t.Fatalf("OPEN flags = 0x%02x, want FlagCompressed set", opens[0].flags)
	}

	payload := bytes.Repeat([]byte("compressed-connect-payload-"), 2048) // ~55 KiB
	writeCh := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		writeCh <- err
	}()
	peer := newCompressedPeer(t, nodeSide)
	if got := peer.readExactly(t, len(payload)); !bytes.Equal(got, payload) {
		t.Fatalf("uploaded payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	if err := <-writeCh; err != nil {
		t.Fatalf("client write: %v", err)
	}
	wire := rec.bytes()
	if !bytes.HasPrefix(wire, zstdMagic) {
		t.Fatalf("tunnel wire is not a zstd frame, first bytes = %x", wire[:min(8, len(wire))])
	}
	if len(wire) >= len(payload) {
		t.Fatalf("compressed wire is %d bytes, plaintext was %d (not compressed)", len(wire), len(payload))
	}

	reply := bytes.Repeat([]byte("compressed-response-"), 256)
	replyCh := make(chan error, 1)
	go func() {
		_, err := peer.Write(reply)
		replyCh <- err
	}()
	gotReply := make([]byte, len(reply))
	if _, err := io.ReadFull(br, gotReply); err != nil {
		t.Fatalf("read compressed reply: %v", err)
	}
	if !bytes.Equal(gotReply, reply) {
		t.Fatalf("reply mismatch: got %d bytes, want %d", len(gotReply), len(reply))
	}
	if err := <-replyCh; err != nil {
		t.Fatalf("peer reply write: %v", err)
	}
}

// TestCompressionSOCKS5RoundTrip verifies the SOCKS5 entry uses the same
// negotiated compression path as CONNECT.
func TestCompressionSOCKS5RoundTrip(t *testing.T) {
	proxySide, nodeSide, rec := newFakeTunnelPair()
	dialer := &fakeDialer{}
	dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
		return proxySide, nil
	})
	opts := compressionEnabledOptions()
	opts.Candidates = newFakeCandidates(compressionNode("node-1", true))
	opts.Dialer = dialer
	proxyAddr, _ := startSOCKS5Proxy(t, opts)

	conn, br, rep := dialSOCKS5Connect(t, proxyAddr, "origin.example", 443, false, "", "")
	defer conn.Close()
	if rep != socks5ReplySucceeded {
		t.Fatalf("SOCKS5 reply = 0x%02x, want success", rep)
	}
	opens := dialer.openCalls()
	if len(opens) != 1 || opens[0].flags&protocol.FlagCompressed == 0 {
		t.Fatalf("SOCKS5 OPEN not compressed: %+v", opens)
	}
	payload := bytes.Repeat([]byte("socks5-compressed-"), 1024)
	writeCh := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeCh <- err
	}()
	peer := newCompressedPeer(t, nodeSide)
	if got := peer.readExactly(t, len(payload)); !bytes.Equal(got, payload) {
		t.Fatalf("SOCKS5 upload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
	if err := <-writeCh; err != nil {
		t.Fatalf("SOCKS5 client write: %v", err)
	}
	if wire := rec.bytes(); !bytes.HasPrefix(wire, zstdMagic) {
		t.Fatalf("SOCKS5 wire is not zstd: %x", wire[:min(8, len(wire))])
	}
	reply := []byte("socks5-compressed-reply")
	go func() { _, _ = peer.Write(reply) }()
	got := make([]byte, len(reply))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("SOCKS5 reply read: %v", err)
	}
	if !bytes.Equal(got, reply) {
		t.Fatalf("SOCKS5 reply = %q, want %q", got, reply)
	}
}

// TestCompressionAbsoluteHTTPKeepAlive verifies absolute-form HTTP forwarding and
// connection reuse (keep-alive) over one compressed tunnel stream: two requests
// share a single OPEN with the compressed flag and both responses stay intact.
func TestCompressionAbsoluteHTTPKeepAlive(t *testing.T) {
	proxySide, nodeSide, rec := newFakeTunnelPair()
	dialer := &fakeDialer{}
	dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
		return proxySide, nil
	})
	opts := compressionEnabledOptions()
	opts.Candidates = newFakeCandidates(compressionNode("node-1", true))
	opts.Dialer = dialer
	proxyAddr, _ := startHTTPProxy(t, opts)

	peer := newCompressedPeer(t, nodeSide)
	originErr := make(chan error, 1)
	go func() {
		br := bufio.NewReader(peer)
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				originErr <- err
				return
			}
			body, _ := io.ReadAll(req.Body)
			_ = req.Body.Close()
			payload := fmt.Sprintf("origin path=%s body=%s", req.URL.Path, body)
			header := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n", len(payload))
			if _, werr := peer.Write(append([]byte(header), payload...)); werr != nil {
				originErr <- werr
				return
			}
		}
	}()

	client := httpClientViaProxy(t, "http://"+proxyAddr)
	for i := 1; i <= 2; i++ {
		resp, err := client.Get(fmt.Sprintf("http://origin.example/item-%d", i))
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("request %d body: %v", i, err)
		}
		want := fmt.Sprintf("origin path=/item-%d body=", i)
		if resp.StatusCode != http.StatusOK || string(body) != want {
			t.Fatalf("request %d = %d %q, want 200 %q", i, resp.StatusCode, body, want)
		}
	}
	opens := dialer.openCalls()
	if len(opens) != 1 {
		t.Fatalf("keep-alive opened %d streams, want 1", len(opens))
	}
	if opens[0].flags&protocol.FlagCompressed == 0 {
		t.Fatalf("HTTP OPEN flags = 0x%02x, want FlagCompressed", opens[0].flags)
	}
	if wire := rec.bytes(); !bytes.HasPrefix(wire, zstdMagic) {
		t.Fatalf("HTTP request wire is not zstd: %x", wire[:min(8, len(wire))])
	}
	// Closing the idle client connection lets the origin loop finish.
	client.CloseIdleConnections()
	select {
	case err := <-originErr:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			// A closed pipe after the client went away is expected here.
			t.Logf("origin loop ended with: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Log("origin loop did not finish before the test completed")
	}
}

// TestCompressionGate verifies compression is a three way intersection: the
// OPEN flag is set only when the operator switch and the node capability agree,
// and a disabled decision keeps the raw byte stream untouched.
func TestCompressionGate(t *testing.T) {
	cases := []struct {
		name        string
		settingsOn  bool
		nodeCapable bool
		wantFlag    bool
	}{
		{name: "both-enabled", settingsOn: true, nodeCapable: true, wantFlag: true},
		{name: "node-without-capability", settingsOn: true, nodeCapable: false, wantFlag: false},
		{name: "operator-disabled", settingsOn: false, nodeCapable: true, wantFlag: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxySide, nodeSide, _ := newFakeTunnelPair()
			dialer := &fakeDialer{}
			dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
				return proxySide, nil
			})
			opts := baseOptions()
			if tc.settingsOn {
				opts = compressionEnabledOptions()
			}
			opts.Candidates = newFakeCandidates(compressionNode("node-1", tc.nodeCapable))
			opts.Dialer = dialer
			proxyAddr, _ := startHTTPProxy(t, opts)

			client, br, resp := connectTunnel(t, proxyAddr, "origin.example:443")
			defer client.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("CONNECT status = %d", resp.StatusCode)
			}
			opens := dialer.openCalls()
			if len(opens) != 1 {
				t.Fatalf("dialer calls = %d", len(opens))
			}
			gotFlag := opens[0].flags&protocol.FlagCompressed != 0
			if gotFlag != tc.wantFlag {
				t.Fatalf("FlagCompressed = %v, want %v (flags 0x%02x)", gotFlag, tc.wantFlag, opens[0].flags)
			}
			if tc.wantFlag {
				return
			}
			// Disabled: the payload must reach the node as plain bytes.
			payload := []byte("plaintext-when-compression-is-off")
			writeCh := make(chan error, 1)
			go func() {
				_, err := client.Write(payload)
				writeCh <- err
			}()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(nodeSide, got); err != nil {
				t.Fatalf("read raw node bytes: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("node received %q, want plaintext %q", got, payload)
			}
			if err := <-writeCh; err != nil {
				t.Fatalf("client write: %v", err)
			}
			reply := []byte("plaintext-reply")
			go func() { _, _ = nodeSide.Write(reply) }()
			gotReply := make([]byte, len(reply))
			if _, err := io.ReadFull(br, gotReply); err != nil {
				t.Fatalf("read reply: %v", err)
			}
			if !bytes.Equal(gotReply, reply) {
				t.Fatalf("reply = %q, want %q", gotReply, reply)
			}
		})
	}
}

// TestCompressionTransparentRetry verifies every stream build attempt uses the
// same negotiated flags: the failed attempt and the retried attempt both carry
// FlagCompressed when compression is enabled.
func TestCompressionTransparentRetry(t *testing.T) {
	proxySide, nodeSide, _ := newFakeTunnelPair()
	var mu sync.Mutex
	attempts := 0
	dialer := &fakeDialer{}
	dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n == 1 {
			return nil, protocol.NewError(protocol.CodeConnRefused, "node refused the target")
		}
		return proxySide, nil
	})
	opts := compressionEnabledOptions()
	opts.Candidates = newFakeCandidates(
		compressionNode("node-1", true),
		compressionNode("node-2", true),
	)
	opts.Dialer = dialer
	proxyAddr, _ := startHTTPProxy(t, opts)

	client, _, resp := connectTunnel(t, proxyAddr, "origin.example:443")
	defer client.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT after retry = %d, want 200", resp.StatusCode)
	}
	opens := dialer.openCalls()
	if len(opens) != 2 {
		t.Fatalf("dialer calls = %d, want 2 (one retry)", len(opens))
	}
	for i, call := range opens {
		if call.flags&protocol.FlagCompressed == 0 {
			t.Fatalf("attempt %d OPEN flags = 0x%02x, want FlagCompressed on every attempt", i+1, call.flags)
		}
	}
	if opens[0].nodeID == opens[1].nodeID {
		t.Fatalf("retry reused the failing node %q", opens[0].nodeID)
	}
	// The retried stream must still be a working compressed tunnel.
	peer := newCompressedPeer(t, nodeSide)
	payload := []byte("retried-compressed-payload")
	writeCh := make(chan error, 1)
	go func() {
		_, err := client.Write(payload)
		writeCh <- err
	}()
	if got := peer.readExactly(t, len(payload)); !bytes.Equal(got, payload) {
		t.Fatalf("retried tunnel payload = %q, want %q", got, payload)
	}
	if err := <-writeCh; err != nil {
		t.Fatalf("client write: %v", err)
	}
}
