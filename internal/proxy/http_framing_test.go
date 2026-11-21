package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestHTTPUpstreamSingleContentLength is a regression test for a duplicated
// Content-Length header: the proxy forwards the parsed body framing and must not
// also copy the client's Content-Length header, otherwise strict origin servers
// (Node.js, Go) reject the request with 400 Bad Request.
func TestHTTPUpstreamSingleContentLength(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer ln.Close()
	host, port, _ := net.SplitHostPort(ln.Addr().String())

	headCh := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			headCh <- ""
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		var head strings.Builder
		for {
			line, err := br.ReadString('\n')
			head.WriteString(line)
			if err == nil && line == "\r\n" {
				break
			}
			if err != nil {
				break
			}
		}
		headCh <- head.String()
		// Drain the request body then answer.
		_, _ = io.CopyN(io.Discard, br, 10)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"))
	}()

	proxyAddr, _ := startHTTPProxy(t, baseOptions())
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "POST http://" + net.JoinHostPort(host, port) + "/upload HTTP/1.1\r\n" +
		"Host: " + net.JoinHostPort(host, port) + "\r\n" +
		"Content-Length: 10\r\n" +
		"Content-Type: text/plain\r\n\r\n"
	if _, err := conn.Write([]byte(req + "hello12345")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	head := <-headCh
	if head == "" {
		t.Fatal("upstream did not receive a request")
	}
	if n := strings.Count(strings.ToLower(head), "content-length:"); n != 1 {
		t.Fatalf("upstream request contains %d Content-Length headers, want 1:\n%s", n, head)
	}
	if !strings.Contains(head, "Content-Length: 10") {
		t.Fatalf("upstream request Content-Length mismatch:\n%s", head)
	}
}
