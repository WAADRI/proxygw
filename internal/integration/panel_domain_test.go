package integration

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"proxygw/internal/config"
	"proxygw/internal/model"
)

// rawPanelHTTPS sends one HTTP/1.1 request over TLS and returns the raw bytes
// read back. It deliberately does not use http.Client: a rejected panel request
// must be closed without any HTTP response at all.
func rawPanelHTTPS(t *testing.T, port int, host, path string) []byte {
	t.Helper()
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- test server uses a self-signed pin-mode certificate
	})
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	data, err := io.ReadAll(conn)
	if err != nil && err != io.EOF {
		t.Fatalf("read response: %v", err)
	}
	return data
}

func TestPanelDomainRestriction(t *testing.T) {
	const domain = "panel.example.test"
	srv := startE2EServer(t, func(cfg *config.ServerConfig) {
		cfg.Server.PanelDomain = domain
	})

	// Matching Host (with or without an explicit port) reaches the panel.
	for _, host := range []string{domain, domain + ":443"} {
		data := rawPanelHTTPS(t, srv.port, host, "/api/v1/session")
		if !strings.HasPrefix(string(data), "HTTP/1.1 401") {
			t.Fatalf("panel request Host %q: expected 401, got %q", host, truncateForLog(data))
		}
	}

	// Wrong Host and direct-IP access get no HTTP bytes at all.
	for _, host := range []string{"other.example.test", fmt.Sprintf("127.0.0.1:%d", srv.port)} {
		data := rawPanelHTTPS(t, srv.port, host, "/api/v1/session")
		if len(data) != 0 {
			t.Fatalf("panel request Host %q returned %d bytes, want silent close: %q", host, len(data), truncateForLog(data))
		}
	}

	// Operational endpoints and the tunnel route stay reachable regardless of
	// the panel domain (they are intentionally outside the panel restriction).
	data := rawPanelHTTPS(t, srv.port, "other.example.test", "/healthz")
	if !strings.HasPrefix(string(data), "HTTP/1.1 200") {
		t.Fatalf("GET /healthz with wrong Host: expected 200, got %q", truncateForLog(data))
	}
}

func TestPanelDomainDoesNotBlockWSTunnel(t *testing.T) {
	srv := startE2EServer(t, func(cfg *config.ServerConfig) {
		cfg.Server.PanelDomain = "panel.example.test"
	})
	// A WS-transport node dials 127.0.0.1, so its HTTP Host does not match the
	// panel domain. The /tunnel route must still work.
	startE2EClient(t, srv, "panel-domain-node", nil, func(cfg *config.ClientConfig) {
		cfg.Transport = model.TransportWS
		cfg.Planes = 1
	})
	e2eWaitNodeOnline(t, srv, "panel-domain-node")
}
