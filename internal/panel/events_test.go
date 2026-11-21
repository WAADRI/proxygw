package panel

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// readSSEData reads lines until one carries a `data:` payload.
func readSSEData(t *testing.T, lines <-chan string, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("SSE stream closed before a data line arrived")
			}
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "data: ") {
				return []byte(strings.TrimPrefix(trimmed, "data: "))
			}
		case <-deadline:
			t.Fatalf("timeout waiting for an SSE data line")
		}
	}
}

// TestEventsSSE connects to /api/v1/events, verifies the immediate snapshot,
// triggers a mutation for an early tick and finally closes the connection.
func TestEventsSSE(t *testing.T) {
	env := newTestEnv(t)
	seedNodes(t, env)
	client := env.loginClient(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, env.url("/api/v1/events"), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.http.Do(req)
	if err != nil {
		t.Fatalf("events request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events status=%d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type=%q", ct)
	}
	if got := resp.Header.Get("X-Accel-Buffering"); got != "no" {
		t.Fatalf("X-Accel-Buffering=%q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("Cache-Control=%q", got)
	}

	reader := bufio.NewReader(resp.Body)
	lines := make(chan string, 32)
	go func() {
		defer close(lines)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil {
				return
			}
			lines <- line
		}
	}()

	// The very first data frame must be a snapshot with the overview and nodes.
	snapshot := readSSEData(t, lines, time.Second)
	var event eventPayload
	if err := jsonUnmarshal(snapshot, &event); err != nil {
		t.Fatalf("decode snapshot %q: %v", snapshot, err)
	}
	if event.Type != "snapshot" {
		t.Fatalf("first event type=%q want snapshot", event.Type)
	}
	if event.Overview.OnlineNodes != 2 || event.Overview.NodesTotal != 3 {
		t.Fatalf("snapshot overview=%+v", event.Overview)
	}
	if len(event.Nodes) != 3 {
		t.Fatalf("snapshot nodes=%d want 3", len(event.Nodes))
	}
	if event.TS <= 0 {
		t.Fatalf("snapshot ts=%d", event.TS)
	}

	waitFor(t, time.Second, "SSE subscriber registration", func() bool {
		return env.srv.hub.subscriberCount() >= 1
	})

	// A mutation wakes the hub and produces an early tick.
	client.mustStatus(http.MethodPatch, "/api/v1/nodes/node-a", map[string]any{"weight": 3}, http.StatusOK)
	tick := readSSEData(t, lines, 2*time.Second)
	if err := jsonUnmarshal(tick, &event); err != nil {
		t.Fatalf("decode tick %q: %v", tick, err)
	}
	if event.Type != "tick" {
		t.Fatalf("event type=%q want tick", event.Type)
	}

	// Closing the client must terminate the handler and unsubscribe it.
	cancel()
	waitFor(t, 2*time.Second, "SSE unsubscribe", func() bool {
		return env.srv.hub.subscriberCount() == 0
	})
}

// TestEventsRequiresAuth checks SSE uses the normal cookie authentication.
func TestEventsRequiresAuth(t *testing.T) {
	env := newTestEnv(t)
	client := env.newAPIClient(t)
	resp, data := client.do(http.MethodGet, "/api/v1/events", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("events without cookie status=%d want 401 body=%s", resp.StatusCode, data)
	}
}
