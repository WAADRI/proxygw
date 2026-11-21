package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// socks5Handshake performs the SOCKS5 greeting and returns the selected method.
func socks5Handshake(t *testing.T, conn net.Conn, br *bufio.Reader, methods []byte) byte {
	t.Helper()
	if _, err := conn.Write(append([]byte{socks5Version, byte(len(methods))}, methods...)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(br, reply[:]); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	if reply[0] != socks5Version {
		t.Fatalf("method reply version = %d", reply[0])
	}
	return reply[1]
}

// socks5UserPass performs the RFC 1929 sub-negotiation and returns the status.
func socks5UserPass(t *testing.T, conn net.Conn, br *bufio.Reader, username, password string) byte {
	t.Helper()
	request := []byte{socks5AuthVersion, byte(len(username))}
	request = append(request, username...)
	request = append(request, byte(len(password)))
	request = append(request, password...)
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("write userpass: %v", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(br, reply[:]); err != nil {
		t.Fatalf("read userpass reply: %v", err)
	}
	return reply[1]
}

// socks5Address encodes a target address for a SOCKS5 request.
func socks5Address(t *testing.T, host string, port int) []byte {
	t.Helper()
	out := []byte{0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append([]byte{socks5AtypIPv4}, v4...)
		} else {
			out = append([]byte{socks5AtypIPv6}, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			t.Fatalf("invalid domain target %q", host)
		}
		out = append([]byte{socks5AtypDomain, byte(len(host))}, host...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	return append(out, portBytes[:]...)
}

// socks5Connect sends a CONNECT request and returns the reply code.
func socks5Connect(t *testing.T, conn net.Conn, br *bufio.Reader, host string, port int, cmd byte) byte {
	t.Helper()
	request := append([]byte{socks5Version, cmd, 0x00}, socks5Address(t, host, port)...)
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	var header [4]byte
	if _, err := io.ReadFull(br, header[:]); err != nil {
		t.Fatalf("read request reply: %v", err)
	}
	if header[0] != socks5Version {
		t.Fatalf("reply version = %d", header[0])
	}
	switch header[3] {
	case socks5AtypIPv4:
		var skip [6]byte
		if _, err := io.ReadFull(br, skip[:]); err != nil {
			t.Fatalf("read IPv4 bind address: %v", err)
		}
	case socks5AtypIPv6:
		var skip [18]byte
		if _, err := io.ReadFull(br, skip[:]); err != nil {
			t.Fatalf("read IPv6 bind address: %v", err)
		}
	case socks5AtypDomain:
		length, err := br.ReadByte()
		if err != nil {
			t.Fatalf("read domain bind length: %v", err)
		}
		skip := make([]byte, int(length)+2)
		if _, err := io.ReadFull(br, skip); err != nil {
			t.Fatalf("read domain bind address: %v", err)
		}
	default:
		t.Fatalf("unexpected reply address type %d", header[3])
	}
	return header[1]
}

// dialSOCKSCONNECT dials the proxy, performs greeting with method, optionally
// authenticates and issues CONNECT. It returns the connection and reply code.
func dialSOCKS5Connect(t *testing.T, proxyAddr, host string, port int, useAuth bool, username, password string) (net.Conn, *bufio.Reader, byte) {
	t.Helper()
	conn := dialTCP(t, proxyAddr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	methods := []byte{socks5MethodNoAuth}
	if useAuth {
		methods = []byte{socks5MethodUserPass}
	}
	method := socks5Handshake(t, conn, br, methods)
	if method == socks5MethodNone {
		return conn, br, socks5MethodNone
	}
	if useAuth {
		if status := socks5UserPass(t, conn, br, username, password); status != 0 {
			return conn, br, status
		}
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	rep := socks5Connect(t, conn, br, host, port, socks5CmdConnect)
	return conn, br, rep
}

// TestSOCKS5ConnectEcho verifies the no-auth handshake and CONNECT tunneling.
func TestSOCKS5ConnectEcho(t *testing.T) {
	echo := newEchoServer(t, "tcp", "127.0.0.1:0")
	host, port := echo.hostPort(t)
	proxyAddr, _ := startSOCKS5Proxy(t, baseOptions())
	conn, br, rep := dialSOCKS5Connect(t, proxyAddr, host, port, false, "", "")
	if rep != socks5ReplySucceeded {
		t.Fatalf("reply = 0x%02x, want success", rep)
	}
	payload := []byte("hello-socks5")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(br, echoed); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("echoed = %q", echoed)
	}
}

// TestSOCKS5UserPassConnect verifies RFC 1929 auth and a domain target.
func TestSOCKS5UserPassConnect(t *testing.T) {
	echo := newEchoServer(t, "tcp", "127.0.0.1:0")
	_, port := echo.hostPort(t)
	auth := newFakeAuthenticator().add("alice", "s3cret", testCredential("cred-1", "alice"))
	opts := baseOptions()
	opts.AuthMode = modelAuthRequired()
	opts.Authenticator = auth
	proxyAddr, _ := startSOCKS5Proxy(t, opts)
	conn, br, rep := dialSOCKS5Connect(t, proxyAddr, "localhost", port, true, "alice", "s3cret")
	if rep != socks5ReplySucceeded {
		t.Fatalf("reply = 0x%02x, want success", rep)
	}
	if _, err := conn.Write([]byte("auth-tunnel")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echoed := make([]byte, len("auth-tunnel"))
	if _, err := io.ReadFull(br, echoed); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echoed) != "auth-tunnel" {
		t.Fatalf("echoed = %q", echoed)
	}
}

// TestSOCKS5IPv6Target verifies IPv6 address type requests.
func TestSOCKS5IPv6Target(t *testing.T) {
	echo := newEchoServer(t, "tcp6", "[::1]:0")
	host, port := echo.hostPort(t)
	proxyAddr, _ := startSOCKS5Proxy(t, baseOptions())
	conn, br, rep := dialSOCKS5Connect(t, proxyAddr, host, port, false, "", "")
	if rep != socks5ReplySucceeded {
		t.Fatalf("reply = 0x%02x, want success (host %s)", rep, host)
	}
	if _, err := conn.Write([]byte("v6")); err != nil {
		t.Fatalf("write: %v", err)
	}
	var echoed [2]byte
	if _, err := io.ReadFull(br, echoed[:]); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echoed[:]) != "v6" {
		t.Fatalf("echoed = %q", echoed)
	}
}

// TestSOCKS5UnsupportedCommand verifies non-CONNECT commands are rejected.
func TestSOCKS5UnsupportedCommand(t *testing.T) {
	echo := newEchoServer(t, "tcp", "127.0.0.1:0")
	host, port := echo.hostPort(t)
	proxyAddr, _ := startSOCKS5Proxy(t, baseOptions())
	for _, cmd := range []byte{socks5CmdBind, socks5CmdUDP, 0x09} {
		conn := dialTCP(t, proxyAddr)
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(conn)
		if method := socks5Handshake(t, conn, br, []byte{socks5MethodNoAuth}); method != socks5MethodNoAuth {
			t.Fatalf("method = 0x%02x", method)
		}
		if rep := socks5Connect(t, conn, br, host, port, cmd); rep != socks5ReplyCmdNotSupported {
			t.Fatalf("command 0x%02x reply = 0x%02x, want 0x07", cmd, rep)
		}
	}
}

// TestSOCKS5UnsupportedAddressType verifies unknown ATYP values are rejected.
func TestSOCKS5UnsupportedAddressType(t *testing.T) {
	proxyAddr, _ := startSOCKS5Proxy(t, baseOptions())
	conn := dialTCP(t, proxyAddr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	if method := socks5Handshake(t, conn, br, []byte{socks5MethodNoAuth}); method != socks5MethodNoAuth {
		t.Fatalf("method = 0x%02x", method)
	}
	if _, err := conn.Write([]byte{socks5Version, socks5CmdConnect, 0x00, 0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write request: %v", err)
	}
	var header [4]byte
	if _, err := io.ReadFull(br, header[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if header[1] != socks5ReplyAtypNotSupported {
		t.Fatalf("reply = 0x%02x, want 0x08", header[1])
	}
}

// TestSOCKS5BadPassword verifies RFC 1929 failures are reported.
func TestSOCKS5BadPassword(t *testing.T) {
	auth := newFakeAuthenticator().add("alice", "s3cret", testCredential("cred-1", "alice"))
	opts := baseOptions()
	opts.AuthMode = modelAuthRequired()
	opts.Authenticator = auth
	proxyAddr, _ := startSOCKS5Proxy(t, opts)
	conn := dialTCP(t, proxyAddr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	if method := socks5Handshake(t, conn, br, []byte{socks5MethodUserPass}); method != socks5MethodUserPass {
		t.Fatalf("method = 0x%02x", method)
	}
	if status := socks5UserPass(t, conn, br, "alice", "wrong"); status == 0 {
		t.Fatalf("bad password reported success")
	}
}

// TestSOCKS5RequiredNoUserPassMethod verifies the no-acceptable-method reply.
func TestSOCKS5RequiredNoUserPassMethod(t *testing.T) {
	auth := newFakeAuthenticator().add("alice", "s3cret", testCredential("cred-1", "alice"))
	opts := baseOptions()
	opts.AuthMode = modelAuthRequired()
	opts.Authenticator = auth
	proxyAddr, _ := startSOCKS5Proxy(t, opts)
	conn := dialTCP(t, proxyAddr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	if method := socks5Handshake(t, conn, br, []byte{socks5MethodNoAuth}); method != socks5MethodNone {
		t.Fatalf("method = 0x%02x, want 0xff", method)
	}
}

// TestSOCKS5OptionalAnonymous verifies anonymous connections in optional mode.
func TestSOCKS5OptionalAnonymous(t *testing.T) {
	echo := newEchoServer(t, "tcp", "127.0.0.1:0")
	host, port := echo.hostPort(t)
	auth := newFakeAuthenticator().add("alice", "s3cret", testCredential("cred-1", "alice"))
	opts := baseOptions()
	opts.AuthMode = modelAuthOptional()
	opts.Authenticator = auth
	proxyAddr, _ := startSOCKS5Proxy(t, opts)
	conn, br, rep := dialSOCKS5Connect(t, proxyAddr, host, port, false, "", "")
	if rep != socks5ReplySucceeded {
		t.Fatalf("reply = 0x%02x", rep)
	}
	if _, err := conn.Write([]byte("anon")); err != nil {
		t.Fatalf("write: %v", err)
	}
	var echoed [4]byte
	if _, err := io.ReadFull(br, echoed[:]); err != nil {
		t.Fatalf("read: %v", err)
	}
}

// TestSOCKS5BadVersion verifies the handshake closes on a wrong version.
func TestSOCKS5BadVersion(t *testing.T) {
	proxyAddr, _ := startSOCKS5Proxy(t, baseOptions())
	conn := dialTCP(t, proxyAddr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{0x04, 0x01, 0x00}); err != nil {
		t.Fatalf("write: %v", err)
	}
	var buf [1]byte
	if _, err := conn.Read(buf[:]); err == nil {
		t.Fatalf("expected the connection to be closed")
	}
}

// TestSOCKS5DisabledCredential verifies credential authorization failures map
// to "connection not allowed" after authentication.
func TestSOCKS5DisabledCredential(t *testing.T) {
	echo := newEchoServer(t, "tcp", "127.0.0.1:0")
	host, port := echo.hostPort(t)
	cred := testCredential("cred-1", "alice")
	cred.Enabled = false
	auth := newFakeAuthenticator().add("alice", "s3cret", cred)
	opts := baseOptions()
	opts.AuthMode = modelAuthRequired()
	opts.Authenticator = auth
	proxyAddr, _ := startSOCKS5Proxy(t, opts)
	_, _, rep := dialSOCKS5Connect(t, proxyAddr, host, port, true, "alice", "s3cret")
	if rep != socks5ReplyNotAllowed {
		t.Fatalf("reply = 0x%02x, want 0x02", rep)
	}
}

func modelAuthRequired() string { return "required" }
func modelAuthOptional() string { return "optional" }

// socks5Target is a tiny helper for readable failure messages.
func socks5Target(host string, port int) string {
	return net.JoinHostPort(host, fmt.Sprint(port))
}
