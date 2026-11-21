package geo

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestExtractIP(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"plain ipv4", "203.0.113.7\n", "203.0.113.7"},
		{"plain ipv6", "2001:db8::42\n", "2001:db8::42"},
		{"json ip field", `{"ip":"198.51.100.9"}`, "198.51.100.9"},
		{"json ip field prefers ip key", `{"other":"192.0.2.1","ip":"198.51.100.9"}`, "198.51.100.9"},
		{"cloudflare trace", "fl=abcdef\nip=192.0.2.44\nloc=JP\ntls=TLSv1.3\n", "192.0.2.44"},
		{"first of multiple", "8.8.8.8 and 1.1.1.1", "8.8.8.8"},
		{"ipv6 in brackets", "[2001:db8::1]", "2001:db8::1"},
		{"surrounding whitespace", "\n  203.0.113.9  \n", "203.0.113.9"},
		{"no address", "no address here", ""},
		{"empty", "   \n\t", ""},
		{"version like numbers", "build 1.2.3 ts=17.5", ""},
		{"unspecified address", "0.0.0.0", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractIP([]byte(tc.body)); got != tc.want {
				t.Fatalf("ExtractIP(%q) = %q, want %q", tc.body, got, tc.want)
			}
		})
	}
}

func TestEgressManualWins(t *testing.T) {
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "203.0.113.5")
	})
	resolver := NewEgressResolver(EgressOptions{
		ManualV4:   "203.0.113.1",
		ManualV6:   "2001:db8::1",
		EchoURLsV4: []string{srv.URL},
		EchoURLsV6: []string{srv.URL},
		Timeout:    200 * time.Millisecond,
		Logger:     testLogger(),
		HTTPClient: srv.Client(),
	})
	egress, err := resolver.Detect(context.Background(), net.ParseIP("198.51.100.7"))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if egress.V4 != "203.0.113.1" || egress.V6 != "2001:db8::1" {
		t.Fatalf("manual egress not used: %+v", egress)
	}
	if egress.Source != EgressSourceManual {
		t.Fatalf("Source = %q, want %q", egress.Source, EgressSourceManual)
	}
	if egress.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt must be set")
	}
	if srv.hits.Load() != 0 {
		t.Fatalf("echo endpoint must not be probed when manual IPs win, hits=%d", srv.hits.Load())
	}
}

func TestEgressPeerBeforeEcho(t *testing.T) {
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "203.0.113.5")
	})
	resolver := NewEgressResolver(EgressOptions{
		EchoURLsV4: []string{srv.URL},
		Timeout:    200 * time.Millisecond,
		Logger:     testLogger(),
		HTTPClient: srv.Client(),
	})
	egress, err := resolver.Detect(context.Background(), net.ParseIP("198.51.100.7"))
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if egress.V4 != "198.51.100.7" {
		t.Fatalf("V4 = %q, want peer address", egress.V4)
	}
	if egress.Source != EgressSourcePeer {
		t.Fatalf("Source = %q, want %q", egress.Source, EgressSourcePeer)
	}
	if srv.hits.Load() != 0 {
		t.Fatalf("echo endpoint must not be probed when the peer address wins, hits=%d", srv.hits.Load())
	}
}

func TestEgressEchoPlainAndJSON(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"plain text", "203.0.113.10\n", "203.0.113.10"},
		{"json", `{"ip":"198.51.100.10"}`, "198.51.100.10"},
		{"cloudflare trace", "fl=x\nip=192.0.2.10\nloc=DE\n", "192.0.2.10"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, tc.body)
			})
			resolver := NewEgressResolver(EgressOptions{
				EchoURLsV4: []string{srv.URL},
				Timeout:    200 * time.Millisecond,
				Logger:     testLogger(),
				HTTPClient: srv.Client(),
			})
			egress, err := resolver.Detect(context.Background(), nil)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if egress.V4 != tc.want {
				t.Fatalf("V4 = %q, want %q", egress.V4, tc.want)
			}
			if egress.Source != EgressSourceEcho {
				t.Fatalf("Source = %q, want %q", egress.Source, EgressSourceEcho)
			}
		})
	}
}

func TestEgressSeparateV4V6Probes(t *testing.T) {
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v4":
			_, _ = io.WriteString(w, "203.0.113.11")
		case "/v6":
			_, _ = io.WriteString(w, "2001:db8::11")
		default:
			http.NotFound(w, r)
		}
	})
	resolver := NewEgressResolver(EgressOptions{
		EchoURLsV4: []string{srv.URL + "/v4"},
		EchoURLsV6: []string{srv.URL + "/v6"},
		Timeout:    500 * time.Millisecond,
		Logger:     testLogger(),
		HTTPClient: srv.Client(),
	})
	egress, err := resolver.Detect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if egress.V4 != "203.0.113.11" || egress.V6 != "2001:db8::11" {
		t.Fatalf("unexpected egress: %+v", egress)
	}
	if egress.Source != EgressSourceEcho {
		t.Fatalf("Source = %q, want echo", egress.Source)
	}
}

func TestEgressTimeoutFallsBackToPrivatePeer(t *testing.T) {
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		_, _ = io.WriteString(w, "203.0.113.5")
	})
	resolver := NewEgressResolver(EgressOptions{
		EchoURLsV4: []string{srv.URL},
		Timeout:    20 * time.Millisecond,
		Logger:     testLogger(),
		HTTPClient: srv.Client(),
	})
	start := time.Now()
	egress, err := resolver.Detect(context.Background(), net.ParseIP("10.0.0.5"))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Detect must degrade gracefully, got error: %v", err)
	}
	if egress.V4 != "10.0.0.5" {
		t.Fatalf("V4 = %q, want the non-public peer address as last resort", egress.V4)
	}
	if egress.Source != EgressSourcePeer {
		t.Fatalf("Source = %q, want peer", egress.Source)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("timeout degradation took too long: %v", elapsed)
	}
}

func TestEgressEchoFailureWithoutPeer(t *testing.T) {
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	resolver := NewEgressResolver(EgressOptions{
		EchoURLsV4: []string{srv.URL},
		Timeout:    200 * time.Millisecond,
		Logger:     testLogger(),
		HTTPClient: srv.Client(),
	})
	egress, err := resolver.Detect(context.Background(), nil)
	if err == nil {
		t.Fatalf("Detect must fail when nothing can be detected, got %+v", egress)
	}
	if egress.V4 != "" {
		t.Fatalf("V4 = %q, want empty", egress.V4)
	}
	if !strings.Contains(err.Error(), "egress IP detection failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServerEgress(t *testing.T) {
	srv := newCountingTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v4":
			_, _ = io.WriteString(w, "203.0.113.7")
		case "/v6":
			_, _ = io.WriteString(w, "2001:db8::7")
		default:
			http.NotFound(w, r)
		}
	})
	resolver := NewEgressResolver(EgressOptions{
		EchoURLsV4: []string{srv.URL + "/v4"},
		EchoURLsV6: []string{srv.URL + "/v6"},
		Timeout:    500 * time.Millisecond,
		Logger:     testLogger(),
		HTTPClient: srv.Client(),
	})
	got, err := resolver.ServerEgress(context.Background())
	if err != nil {
		t.Fatalf("ServerEgress: %v", err)
	}
	if got != "203.0.113.7" {
		t.Fatalf("ServerEgress = %q, want the IPv4 address", got)
	}

	empty := NewEgressResolver(EgressOptions{Logger: testLogger()})
	if _, err := empty.ServerEgress(context.Background()); err == nil {
		t.Fatal("ServerEgress must fail without echo URLs")
	}
}
