package nodeagent

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"proxygw/internal/protocol"
)

func TestProbes(t *testing.T) {
	srv := newFakeServer(t)
	h := startAgent(t, srv, nil)
	waitConnected(t, h)

	// ping: answered immediately with the EMA latency and "pong" detail.
	srv.pushJSON(protocol.FrameProbe, protocol.Probe{ID: "p-ping", Kind: protocol.ProbePing})
	res := srv.waitProbeResult(t, 3*time.Second)
	if res.ID != "p-ping" {
		t.Fatalf("PROBE_RESULT 丢失 ID: %q", res.ID)
	}
	if !res.OK || res.Detail != "pong" {
		t.Fatalf("ping probe = %+v", res)
	}

	// tcping: real local TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	srv.pushJSON(protocol.FrameProbe, protocol.Probe{ID: "p-tcp", Kind: protocol.ProbeTCPing, Target: ln.Addr().String()})
	res = srv.waitProbeResult(t, 3*time.Second)
	if !res.OK || res.ID != "p-tcp" {
		t.Fatalf("tcping probe = %+v", res)
	}

	// http: local httptest server, target without scheme must be completed.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.Close)
	target := strings.TrimPrefix(ts.URL, "http://")
	srv.pushJSON(protocol.FrameProbe, protocol.Probe{ID: "p-http", Kind: protocol.ProbeHTTP, Target: target})
	res = srv.waitProbeResult(t, 3*time.Second)
	if !res.OK || res.ID != "p-http" || res.Detail != "status=204" {
		t.Fatalf("http probe = %+v", res)
	}

	// dns: local UDP echo server returns the query bytes.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	query := []byte{0xde, 0xad, 0xbe, 0xef}
	srv.pushJSON(protocol.FrameProbe, protocol.Probe{
		ID: "p-dns", Kind: protocol.ProbeDNS, Target: pc.LocalAddr().String(), Payload: query,
	})
	res = srv.waitProbeResult(t, 3*time.Second)
	if !res.OK || res.ID != "p-dns" {
		t.Fatalf("dns probe = %+v", res)
	}
	if !bytes.Equal(res.Result, query) {
		t.Fatalf("dns probe result = %v, want %v", res.Result, query)
	}

	// unknown kind: error result must still carry the ID.
	srv.pushJSON(protocol.FrameProbe, protocol.Probe{ID: "p-bogus", Kind: "bogus"})
	res = srv.waitProbeResult(t, 3*time.Second)
	if res.ID != "p-bogus" || res.OK {
		t.Fatalf("unknown probe = %+v", res)
	}
}
