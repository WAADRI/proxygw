package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"proxygw/internal/model"
	"proxygw/internal/protocol"
)

// startEvent captures one OnRequestStart callback.
type startEvent struct {
	credentialID string
	protocol     string
	target       string
	nodeID       string
}

// endEvent captures one OnRequestEnd callback.
type endEvent struct {
	credentialID string
	protocol     string
	target       string
	nodeID       string
	bytesIn      int64
	bytesOut     int64
	err          error
}

// callbackRecorder records the optional request observer callbacks.
type callbackRecorder struct {
	mu     sync.Mutex
	starts []startEvent
	ends   []endEvent
}

func (r *callbackRecorder) start(credentialID, protocol, target, nodeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.starts = append(r.starts, startEvent{credentialID: credentialID, protocol: protocol, target: target, nodeID: nodeID})
}

func (r *callbackRecorder) end(credentialID, protocol, target, nodeID string, bytesIn, bytesOut int64, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ends = append(r.ends, endEvent{
		credentialID: credentialID, protocol: protocol, target: target, nodeID: nodeID,
		bytesIn: bytesIn, bytesOut: bytesOut, err: err,
	})
}

func (r *callbackRecorder) snapshot() ([]startEvent, []endEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]startEvent(nil), r.starts...), append([]endEvent(nil), r.ends...)
}

func (r *callbackRecorder) waitEnds(t *testing.T, want int) []endEvent {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, ends := r.snapshot()
		if len(ends) >= want {
			return ends
		}
		if time.Now().After(deadline) {
			t.Fatalf("got %d OnRequestEnd callbacks, want %d", len(ends), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestRequestCallbacksHTTP verifies the callbacks fire once per plain HTTP
// request, including keep-alive requests on one client connection.
func TestRequestCallbacksHTTP(t *testing.T) {
	var targetHost string
	var targetPort int
	upstream := newLocalHTTPServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "callback-body")
	})
	targetHost, targetPort = serverTarget(t, upstream)
	recorder := &callbackRecorder{}
	opts := baseOptions()
	opts.OnRequestStart = recorder.start
	opts.OnRequestEnd = recorder.end
	proxyAddr, _ := startHTTPProxy(t, opts)
	client := httpClientViaProxy(t, "http://"+proxyAddr)
	target := fmt.Sprintf("http://%s:%d/", targetHost, targetPort)
	for i := 0; i < 2; i++ {
		resp, err := client.Get(target)
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		if _, err := io.ReadAll(resp.Body); err != nil {
			t.Fatalf("read body: %v", err)
		}
		resp.Body.Close()
	}
	ends := recorder.waitEnds(t, 2)
	starts, _ := recorder.snapshot()
	if len(starts) != 2 {
		t.Fatalf("OnRequestStart calls = %d, want 2 (one per keep-alive request)", len(starts))
	}
	if len(ends) != 2 {
		t.Fatalf("OnRequestEnd calls = %d, want 2", len(ends))
	}
	wantTarget := tcpTarget(targetHost, targetPort)
	for i, event := range ends {
		if event.protocol != model.ProtoHTTP {
			t.Fatalf("event %d protocol = %q", i, event.protocol)
		}
		if event.target != wantTarget {
			t.Fatalf("event %d target = %q, want %q", i, event.target, wantTarget)
		}
		if event.nodeID != "node-1" {
			t.Fatalf("event %d node = %q", i, event.nodeID)
		}
		if event.credentialID != "" {
			t.Fatalf("event %d credential = %q, want anonymous", i, event.credentialID)
		}
		if event.err != nil {
			t.Fatalf("event %d err = %v", i, event.err)
		}
		if event.bytesOut <= 0 {
			t.Fatalf("event %d bytesOut = %d, want the response body bytes", i, event.bytesOut)
		}
	}
}

// TestRequestCallbacksCONNECT verifies callbacks and byte counts for CONNECT.
func TestRequestCallbacksCONNECT(t *testing.T) {
	echo := newEchoServer(t, "tcp", "127.0.0.1:0")
	host, port := echo.hostPort(t)
	recorder := &callbackRecorder{}
	opts := baseOptions()
	opts.OnRequestStart = recorder.start
	opts.OnRequestEnd = recorder.end
	proxyAddr, _ := startHTTPProxy(t, opts)
	conn, br, resp := connectTunnel(t, proxyAddr, tcpTarget(host, port))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	payload := []byte("callback-tunnel-payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(br, echoed); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = conn.Close()
	ends := recorder.waitEnds(t, 1)
	starts, _ := recorder.snapshot()
	if len(starts) != 1 {
		t.Fatalf("OnRequestStart calls = %d, want 1", len(starts))
	}
	event := ends[0]
	if event.protocol != model.ProtoConnect || event.nodeID != "node-1" {
		t.Fatalf("event = %+v", event)
	}
	if event.target != tcpTarget(host, port) {
		t.Fatalf("target = %q", event.target)
	}
	if event.err != nil {
		t.Fatalf("err = %v", event.err)
	}
	if event.bytesIn < int64(len(payload)) {
		t.Fatalf("bytesIn = %d, want >= %d", event.bytesIn, len(payload))
	}
	if event.bytesOut < int64(len(payload)) {
		t.Fatalf("bytesOut = %d, want >= %d", event.bytesOut, len(payload))
	}
}

// TestRequestCallbacksFailure verifies a failed request still reports exactly
// one start and one end callback with the final error.
func TestRequestCallbacksFailure(t *testing.T) {
	dialer := &fakeDialer{}
	dialer.setHandler(func(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error) {
		return nil, protocol.NewError(protocol.CodeConnRefused, "injected failure")
	})
	recorder := &callbackRecorder{}
	opts := baseOptions()
	opts.Dialer = dialer
	opts.OnRequestStart = recorder.start
	opts.OnRequestEnd = recorder.end
	proxyAddr, _ := startHTTPProxy(t, opts)
	_, _, resp := connectTunnel(t, proxyAddr, "127.0.0.1:1")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	ends := recorder.waitEnds(t, 1)
	starts, _ := recorder.snapshot()
	if len(starts) != 1 {
		t.Fatalf("OnRequestStart calls = %d, want 1", len(starts))
	}
	if len(ends) != 1 {
		t.Fatalf("OnRequestEnd calls = %d, want 1", len(ends))
	}
	if ends[0].err == nil {
		t.Fatalf("OnRequestEnd error is nil on a failed request")
	}
	if ends[0].protocol != model.ProtoConnect || ends[0].nodeID != "node-1" {
		t.Fatalf("event = %+v", ends[0])
	}
}

// TestRequestCallbacksSOCKS5 verifies the callbacks for the SOCKS5 entry.
func TestRequestCallbacksSOCKS5(t *testing.T) {
	echo := newEchoServer(t, "tcp", "127.0.0.1:0")
	host, port := echo.hostPort(t)
	recorder := &callbackRecorder{}
	opts := baseOptions()
	opts.OnRequestStart = recorder.start
	opts.OnRequestEnd = recorder.end
	proxyAddr, _ := startSOCKS5Proxy(t, opts)
	conn, br, rep := dialSOCKS5Connect(t, proxyAddr, host, port, false, "", "")
	if rep != socks5ReplySucceeded {
		t.Fatalf("reply = 0x%02x", rep)
	}
	if _, err := conn.Write([]byte("socks-callback")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len("socks-callback"))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	_ = conn.Close()
	ends := recorder.waitEnds(t, 1)
	starts, _ := recorder.snapshot()
	if len(starts) != 1 || len(ends) != 1 {
		t.Fatalf("callbacks = %d starts, %d ends", len(starts), len(ends))
	}
	event := ends[0]
	if event.protocol != model.ProtoSOCKS5 {
		t.Fatalf("protocol = %q", event.protocol)
	}
	if event.bytesIn <= 0 || event.bytesOut <= 0 {
		t.Fatalf("byte counters = %d/%d", event.bytesIn, event.bytesOut)
	}
	if event.err != nil {
		t.Fatalf("err = %v", event.err)
	}
}
