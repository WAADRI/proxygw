package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"proxygw/internal/model"
)

// groupRouteACL exercises the optional route extension without changing the
// plain ACLChecker fake used by the existing tests.
type groupRouteACL struct {
	fakeACL
	groups []string
}

func (a *groupRouteACL) ForcedGroups(model.RequestTarget) ([]string, error) {
	return append([]string(nil), a.groups...), nil
}

func TestRouteForcedGroupsOverrideCredentialGroups(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "routed-ok")
	}))
	defer upstream.Close()

	opts := baseOptions()
	candidates := newFakeCandidates(mustNode("node-cn"))
	opts.Candidates = candidates
	opts.ACL = &groupRouteACL{groups: []string{"cn-edge", "cn-home"}}
	proxyAddr, _ := startHTTPProxy(t, opts)

	conn := dialTCP(t, proxyAddr)
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.URL, upstream.URL[len("http://"):]); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "routed-ok" {
		t.Fatalf("response status=%d body=%q", resp.StatusCode, body)
	}

	candidates.mu.Lock()
	defer candidates.mu.Unlock()
	if len(candidates.groups) != 1 {
		t.Fatalf("candidate calls = %d, want 1", len(candidates.groups))
	}
	got := candidates.groups[0]
	if len(got) != 2 || got[0] != "cn-edge" || got[1] != "cn-home" {
		t.Fatalf("forced candidate groups = %v", got)
	}
}

var _ ACLGroupRouter = (*groupRouteACL)(nil)
