package proxyproto

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// pipeConn returns a connected (client, server) pipe and registers cleanup.
func pipeConn(t *testing.T) (client, server net.Conn) {
	t.Helper()
	client, server = net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

// writeAsync writes data to c in the background and closes the write side.
func writeAsync(client net.Conn, data []byte) {
	go func() {
		_, _ = client.Write(data)
		_ = client.Close()
	}()
}

func TestNewConnValidation(t *testing.T) {
	if _, err := NewConn(nil, time.Second); err == nil {
		t.Fatal("NewConn(nil) = nil error, want error")
	}
	client, server := pipeConn(t)
	_ = client
	if _, err := NewConn(server, -time.Second); err == nil {
		t.Fatal("NewConn(negative timeout) = nil error, want error")
	}
}

func TestConnPassThroughNoHeader(t *testing.T) {
	client, server := pipeConn(t)
	c, err := NewConn(server, 2*time.Second)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	// A TLS ClientHello starts with 0x16; the sniffer must not misdetect it
	// and must not lose a single byte.
	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b}
	underlyingRemote := server.RemoteAddr().String()
	writeAsync(client, payload)

	if c.Flushed() {
		t.Error("Flushed() = true before first use")
	}
	if got := c.RemoteAddr().String(); got != underlyingRemote {
		t.Errorf("RemoteAddr() = %q, want underlying %q", got, underlyingRemote)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("read %x, want %x", got, payload)
	}
	if !c.Flushed() {
		t.Error("Flushed() = false after read")
	}
}

func TestConnV1Header(t *testing.T) {
	client, server := pipeConn(t)
	c, err := NewConn(server, 2*time.Second)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	header := "PROXY TCP4 203.0.113.7 10.0.0.1 40000 443\r\n"
	payload := []byte("hello proxy")
	writeAsync(client, append([]byte(header), payload...))

	if got := c.RemoteAddr().String(); got != "203.0.113.7:40000" {
		t.Errorf("RemoteAddr() = %q, want 203.0.113.7:40000", got)
	}
	if got := c.LocalAddr().String(); got != "10.0.0.1:443" {
		t.Errorf("LocalAddr() = %q, want 10.0.0.1:443", got)
	}
	h, ok := c.Header()
	if !ok {
		t.Fatal("Header() = false, want parsed header")
	}
	if h.Family != FamilyTCP4 || h.SrcPort != 40000 {
		t.Errorf("Header() = %+v", h)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
	if !c.Flushed() {
		t.Error("Flushed() = false after header parse")
	}
}

func TestConnV2Header(t *testing.T) {
	client, server := pipeConn(t)
	c, err := NewConn(server, 2*time.Second)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	addr := testV2TCP6Addr("2001:db8::7", "2001:db8::1", 1234, 443)
	payload := []byte("payload")
	writeAsync(client, append(testBuildV2(0x21, 0x21, addr), payload...))

	if got := c.RemoteAddr().String(); got != "[2001:db8::7]:1234" {
		t.Errorf("RemoteAddr() = %q", got)
	}
	if got := c.LocalAddr().String(); got != "[2001:db8::1]:443" {
		t.Errorf("LocalAddr() = %q", got)
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

func TestConnLocalHeaderFallsBackToSocketAddrs(t *testing.T) {
	client, server := pipeConn(t)
	c, err := NewConn(server, 2*time.Second)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	writeAsync(client, append(testBuildV2(0x20, 0x00, nil), []byte("local")...))

	underlyingRemote := server.RemoteAddr().String()
	if got := c.RemoteAddr().String(); got != underlyingRemote {
		t.Errorf("RemoteAddr() = %q, want underlying %q for LOCAL", got, underlyingRemote)
	}
	if _, ok := c.RemoteAddr().(*Addr); ok {
		t.Error("RemoteAddr() returned a PROXY protocol address for LOCAL header")
	}
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "local" {
		t.Errorf("payload = %q, want local", got)
	}
}

func TestConnPartialMagicPrefixPreserved(t *testing.T) {
	client, server := pipeConn(t)
	c, err := NewConn(server, 2*time.Second)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	writeAsync(client, []byte("P"))

	buf := make([]byte, 8)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 1 || buf[0] != 'P' {
		t.Errorf("Read = (%d, %q), want (1, P)", n, buf[:n])
	}
	if _, err := c.Read(buf); !errors.Is(err, io.EOF) {
		t.Errorf("second Read error = %v, want EOF", err)
	}
}

func TestConnInvalidHeader(t *testing.T) {
	client, server := pipeConn(t)
	c, err := NewConn(server, 2*time.Second)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	writeAsync(client, []byte("PROXY UDP4 203.0.113.7 10.0.0.1 40000 443\r\npayload"))

	if _, err := c.Read(make([]byte, 4)); err == nil {
		t.Fatal("Read with invalid header = nil error, want error")
	}
	if !c.Flushed() {
		t.Error("Flushed() = false after failed parse")
	}
	// Address access must stay safe and fall back to the socket addresses.
	if c.RemoteAddr() == nil {
		t.Error("RemoteAddr() = nil after parse error")
	}
}

func TestConnHeaderReadTimeout(t *testing.T) {
	client, server := pipeConn(t)
	_ = client // never written
	c, err := NewConn(server, 40*time.Millisecond)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	start := time.Now()
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read = nil error, want header read timeout")
	}
	elapsed := time.Since(start)
	if elapsed < 20*time.Millisecond || elapsed > 2*time.Second {
		t.Errorf("timeout took %v, want about 40ms", elapsed)
	}
	if !c.Flushed() {
		t.Error("Flushed() = false after timeout")
	}
}

func TestConnZeroLengthReadDoesNotParse(t *testing.T) {
	client, server := pipeConn(t)
	_ = client
	c, err := NewConn(server, time.Second)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	if n, err := c.Read(nil); n != 0 || err != nil {
		t.Errorf("Read(nil) = (%d, %v), want (0, nil)", n, err)
	}
	if c.Flushed() {
		t.Error("Read(nil) triggered parsing")
	}
}

func TestConnForwardsHalfClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("PROXY TCP4 203.0.113.7 10.0.0.1 40000 443\r\nx"))
	}()
	raw, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	c, err := NewConn(raw, time.Second)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	defer c.Close()
	if _, err := c.Read(make([]byte, 1)); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Errorf("CloseWrite() on a TCP connection = %v, want nil", err)
	}

	// A pipe does not support half-close; the wrapper must report that instead
	// of silently succeeding.
	client, server := net.Pipe()
	_ = client
	pc, err := NewConn(server, time.Second)
	if err != nil {
		t.Fatalf("NewConn(pipe): %v", err)
	}
	if err := pc.CloseWrite(); err == nil {
		t.Error("CloseWrite() on a pipe = nil error, want unsupported error")
	}
	if err := pc.CloseRead(); err == nil {
		t.Error("CloseRead() on a pipe = nil error, want unsupported error")
	}
}

func TestConnRestoresCallerReadDeadline(t *testing.T) {
	client, server := pipeConn(t)
	c, err := NewConn(server, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	// A consumer deadline (e.g. net/http's TLS handshake deadline) must survive
	// the header parse instead of being cleared or replaced by the header
	// timeout.
	const callerDeadline = 300 * time.Millisecond
	if err := c.SetReadDeadline(time.Now().Add(callerDeadline)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	go func() {
		_, _ = client.Write([]byte("PROXY TCP4 203.0.113.7 10.0.0.1 40000 443\r\n"))
		// Do not send any payload: the caller deadline must fire.
	}()
	start := time.Now()
	_, err = c.Read(make([]byte, 4))
	elapsed := time.Since(start)
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("Read error = %v, want timeout from the caller deadline", err)
	}
	if elapsed < 200*time.Millisecond || elapsed > 2*time.Second {
		t.Errorf("Read timed out after %v, want about %v (caller deadline restored)", elapsed, callerDeadline)
	}
}

func TestConnConcurrentRemoteAddr(t *testing.T) {
	client, server := pipeConn(t)
	c, err := NewConn(server, 2*time.Second)
	if err != nil {
		t.Fatalf("NewConn: %v", err)
	}
	writeAsync(client, []byte("PROXY TCP4 203.0.113.7 10.0.0.1 40000 443\r\nbody"))

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if got := c.RemoteAddr().String(); got != "203.0.113.7:40000" {
					t.Errorf("RemoteAddr() = %q", got)
					return
				}
				_ = c.Flushed()
			}
		}()
	}
	wg.Wait()
	if !strings.HasPrefix(c.LocalAddr().String(), "10.0.0.1:") {
		t.Errorf("LocalAddr() = %q", c.LocalAddr())
	}
}
