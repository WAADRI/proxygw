package integration

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"proxygw/internal/config"
)

// proxyV2Header builds a PROXY protocol v2 header for TCP4 with the given
// source address/port.
func proxyV2Header(srcIP net.IP, srcPort, dstPort uint16) []byte {
	hdr := make([]byte, 0, 16+12)
	hdr = append(hdr, []byte("\r\n\r\n\x00\r\nQUIT\n")...)
	hdr = append(hdr, 0x21) // version 2, PROXY command
	hdr = append(hdr, 0x11) // AF_INET + STREAM
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, 12)
	hdr = append(hdr, length...)
	hdr = append(hdr, srcIP.To4()...)
	hdr = append(hdr, net.IPv4(127, 0, 0, 1).To4()...)
	ports := make([]byte, 4)
	binary.BigEndian.PutUint16(ports[0:2], srcPort)
	binary.BigEndian.PutUint16(ports[2:4], dstPort)
	hdr = append(hdr, ports...)
	return hdr
}

// readHead reads the HTTP response head (up to the blank line).
func readHead(t *testing.T, conn net.Conn) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var sb strings.Builder
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
			if strings.Contains(sb.String(), "\r\n\r\n") {
				return sb.String()
			}
		}
		if err != nil {
			return sb.String()
		}
	}
}

func dialTLS(addr string, rawHeader []byte) (*tls.Conn, error) {
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if len(rawHeader) > 0 {
		if _, err := raw.Write(rawHeader); err != nil {
			_ = raw.Close()
			return nil, err
		}
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "127.0.0.1", NextProtos: []string{"http/1.1"}})
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := conn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// TestProxyProtocolV2Listeners proves the documented PROXY protocol v2 support
// is actually wired: the optional header is consumed on the shared TLS listener
// and on the HTTP proxy entry, connections without a header still work, and the
// spoofed source address is used in the audit trail.
func TestProxyProtocolV2Listeners(t *testing.T) {
	ts := startServer(t, func(cfg *config.ServerConfig) {
		cfg.Server.ProxyProtocol = true
	})

	// Wait until the TLS listener serves /healthz without any PROXY header
	// (optional header pass-through must keep direct access working).
	panelAddr := net.JoinHostPort("127.0.0.1", itoa(ts.port))
	var ready bool
	for i := 0; i < 50; i++ {
		conn, err := dialTLS(panelAddr, nil)
		if err == nil {
			_, _ = conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"))
			head := readHead(t, conn)
			_ = conn.Close()
			if strings.Contains(head, " 200 ") {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("shared TLS listener did not serve /healthz without PROXY header")
	}

	// With PROXY v2 in front of TLS: the optional header is consumed before the
	// TLS handshake and the request is served normally.
	conn, err := dialTLS(panelAddr, proxyV2Header(net.ParseIP("203.0.113.9"), 45678, uint16(ts.port)))
	if err != nil {
		t.Fatalf("TLS handshake after PROXY v2 header: %v", err)
	}
	_, _ = conn.Write([]byte("GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"))
	head := readHead(t, conn)
	_ = conn.Close()
	if !strings.Contains(head, " 200 ") {
		t.Fatalf("shared TLS listener with PROXY v2 header: response head %q", head)
	}

	// HTTP proxy entry: a request without credentials must be rejected with 407,
	// both with and without a PROXY header (the header must not be parsed as
	// HTTP request bytes). The spoofed source address must reach the audit log.
	proxyAddr := ts.cfg.Proxy.HTTPListen
	sendNotify := func(header []byte) string {
		raw, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial HTTP proxy: %v", err)
		}
		defer raw.Close()
		if len(header) > 0 {
			_, _ = raw.Write(header)
		}
		_, _ = raw.Write([]byte("GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"))
		return readHead(t, raw)
	}
	if head := sendNotify(nil); !strings.Contains(head, " 407 ") {
		t.Fatalf("HTTP proxy without PROXY header: response head %q", head)
	}
	if head := sendNotify(proxyV2Header(net.ParseIP("203.0.113.77"), 45679, 0)); !strings.Contains(head, " 407 ") {
		t.Fatalf("HTTP proxy with PROXY v2 header: response head %q", head)
	}

	// The audit trail must attribute the authentication failure to the address
	// supplied by the PROXY header (not the TCP peer 127.0.0.1).
	auditPath := ts.cfg.AuditPath()
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, err := os.ReadFile(auditPath)
		if err == nil {
			text := string(data)
			if strings.Contains(text, "203.0.113.77") && strings.Contains(text, "proxy.auth_failed") {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit log %s does not contain proxy.auth_failed with PROXY source 203.0.113.77", auditPath)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
