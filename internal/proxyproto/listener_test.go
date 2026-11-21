package proxyproto

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestNewListenerValidation(t *testing.T) {
	if _, err := NewListener(nil, time.Second); err == nil {
		t.Fatal("NewListener(nil) = nil error, want error")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	if _, err := NewListener(ln, -time.Second); err == nil {
		t.Fatal("NewListener(negative timeout) = nil error, want error")
	}
}

func TestListenerWrapsAcceptedConn(t *testing.T) {
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln, err := NewListener(rawLn, 2*time.Second)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()
	if ln.Unwrap() != rawLn {
		t.Error("Unwrap() did not return the underlying listener")
	}

	payload := []byte("after-header")
	go func() {
		c, err := net.Dial("tcp", rawLn.Addr().String())
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write(append([]byte("PROXY TCP4 203.0.113.7 10.0.0.1 40000 443\r\n"), payload...))
	}()

	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().String(); got != "203.0.113.7:40000" {
		t.Errorf("RemoteAddr() = %q, want 203.0.113.7:40000", got)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}
