package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"proxygw/internal/model"
	"proxygw/internal/protocol"
)

// TestRelayHalfClose verifies that a client half-close keeps the tunnel open
// for the target's remaining bytes (attachment 3.4 / 3.6).
func TestRelayHalfClose(t *testing.T) {
	nodeCh := make(chan *memStream, 1)
	dialer := &fakeDialer{}
	dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
		client, peer := memPipePair()
		nodeCh <- peer
		return client, nil
	})
	opts := baseOptions()
	opts.Dialer = dialer
	proxyAddr, _ := startHTTPProxy(t, opts)
	conn, br, resp := connectTunnel(t, proxyAddr, "half-close.test:80")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	node := <-nodeCh
	if _, err := node.Write([]byte("half")); err != nil {
		t.Fatalf("node write: %v", err)
	}
	half := make([]byte, 4)
	if _, err := io.ReadFull(br, half); err != nil {
		t.Fatalf("client read half: %v", err)
	}
	if string(half) != "half" {
		t.Fatalf("half = %q", half)
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			t.Fatalf("client half close: %v", err)
		}
	}
	// The target must observe the client EOF through the half close.
	if _, err := io.ReadAll(node); err != nil {
		t.Fatalf("node read after client half close: %v", err)
	}
	if _, err := node.Write([]byte("tail")); err != nil {
		t.Fatalf("node write tail: %v", err)
	}
	if err := node.CloseWrite(); err != nil {
		t.Fatalf("node half close: %v", err)
	}
	tail := make([]byte, 4)
	if _, err := io.ReadFull(br, tail); err != nil {
		t.Fatalf("client read tail after half close: %v", err)
	}
	if string(tail) != "tail" {
		t.Fatalf("tail = %q", tail)
	}
}

// TestRelayLingerBoundsHalfClose verifies the drain direction is force closed
// after the linger timeout instead of staying forever.
func TestRelayLingerBoundsHalfClose(t *testing.T) {
	box := newSettingsBox()
	box.set(func(s *model.Settings) { s.Timeouts.Linger = model.D(200 * time.Millisecond) })
	nodeCh := make(chan *memStream, 1)
	dialer := &fakeDialer{}
	dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
		client, peer := memPipePair()
		nodeCh <- peer
		return client, nil
	})
	opts := baseOptions()
	opts.Settings = box.get
	opts.Dialer = dialer
	proxyAddr, _ := startHTTPProxy(t, opts)
	conn, br, resp := connectTunnel(t, proxyAddr, "linger.test:80")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	node := <-nodeCh
	nodeEOF := make(chan struct{})
	go func() {
		_, _ = io.ReadAll(node)
		close(nodeEOF)
	}()
	start := time.Now()
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	select {
	case <-nodeEOF:
	case <-time.After(2 * time.Second):
		t.Fatalf("node never observed the client EOF")
	}
	// The target stays silent; the proxy must force close the tunnel after the
	// linger budget instead of waiting for the idle timeout.
	buf := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := br.Read(buf); err == nil {
		t.Fatalf("expected the tunnel to be closed after linger")
	}
	elapsed := time.Since(start)
	if elapsed < 150*time.Millisecond {
		t.Fatalf("tunnel closed after %v, before the linger budget", elapsed)
	}
	if elapsed > 2500*time.Millisecond {
		t.Fatalf("tunnel closed after %v, linger did not bound the drain", elapsed)
	}
}

// TestConcurrentConnectEcho verifies 50 concurrent CONNECT tunnels under -race.
func TestConcurrentConnectEcho(t *testing.T) {
	echo := newEchoServer(t, "tcp", "127.0.0.1:0")
	host, port := echo.hostPort(t)
	opts := baseOptions()
	proxyAddr, _ := startHTTPProxy(t, opts)
	const workers = 50
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			conn, br, resp := connectTunnel(t, proxyAddr, tcpTarget(host, port))
			if resp.StatusCode != http.StatusOK {
				errCh <- fmt.Errorf("worker %d CONNECT status %d", index, resp.StatusCode)
				return
			}
			payload := []byte(fmt.Sprintf("payload-%03d", index))
			if _, err := conn.Write(payload); err != nil {
				errCh <- fmt.Errorf("worker %d write: %w", index, err)
				return
			}
			echoed := make([]byte, len(payload))
			if _, err := io.ReadFull(br, echoed); err != nil {
				errCh <- fmt.Errorf("worker %d read: %w", index, err)
				return
			}
			if !bytes.Equal(echoed, payload) {
				errCh <- fmt.Errorf("worker %d echo mismatch", index)
				return
			}
			_ = conn.Close()
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestGracefulCloseWaitsForInflight verifies Close drains active tunnels before
// returning and stops accepting new connections.
func TestGracefulCloseWaitsForInflight(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	nodeCh := make(chan *memStream, 1)
	dialer := &fakeDialer{}
	dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
		client, peer := memPipePair()
		nodeCh <- peer
		return client, nil
	})
	opts := baseOptions()
	opts.Dialer = dialer
	opts.Candidates = newFakeCandidates(mustNode("node-1"))
	opts.Selector = &fakeSelector{}
	proxy, err := NewHTTPProxy(opts)
	if err != nil {
		t.Fatalf("NewHTTPProxy: %v", err)
	}
	serveCtx, cancelServe := context.WithCancel(context.Background())
	defer cancelServe()
	serveDone := make(chan error, 1)
	go func() { serveDone <- proxy.Serve(serveCtx, ln) }()
	addr := ln.Addr().String()

	conn, br, resp := connectTunnel(t, addr, "drain.test:80")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	node := <-nodeCh
	// Echo one payload through the live tunnel.
	go func() {
		buf := make([]byte, 32)
		for {
			n, rerr := node.Read(buf)
			if n > 0 {
				if _, werr := node.Write(buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()
	if _, err := conn.Write([]byte("drain-me")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echoed := make([]byte, len("drain-me"))
	if _, err := io.ReadFull(br, echoed); err != nil {
		t.Fatalf("read: %v", err)
	}
	closeStart := time.Now()
	closed := make(chan error, 1)
	go func() { closed <- proxy.Close(context.Background()) }()
	// Give Close a moment to stop accepting, then terminate the in-flight tunnel.
	time.Sleep(50 * time.Millisecond)
	_ = conn.Close()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Close did not finish")
	}
	if elapsed := time.Since(closeStart); elapsed > 4*time.Second {
		t.Fatalf("Close took %v", elapsed)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Serve did not return after Close")
	}
	if _, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		t.Fatalf("listener still accepts connections after Close")
	}
	if err := proxy.Close(context.Background()); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
