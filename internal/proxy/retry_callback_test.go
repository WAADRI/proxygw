package proxy

import (
	"testing"

	"proxygw/internal/model"
)

// TestOnRetryCallback verifies the pipeline reports every transparent retry to
// the optional OnRetry hook (the panel uses it for an exact overview retry
// counter instead of inferring retries from failed requests).
func TestOnRetryCallback(t *testing.T) {
	calls := 0
	opts := baseOptions()
	opts.Candidates = newFakeCandidates(mustNode("node-1"))
	opts.Selector = &fakeSelector{}
	opts.Dialer = &fakeDialer{}
	opts.OnRetry = func() { calls++ }
	p, err := newPipeline(opts)
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}
	target := model.RequestTarget{Protocol: model.ProtoHTTP, Host: "example.com", Port: 80}
	p.retry("node-1", "tracehex", model.ProtoHTTP, target, nil)
	p.retry("node-1", "tracehex", model.ProtoHTTP, target, nil)
	if calls != 2 {
		t.Fatalf("OnRetry calls = %d, want 2", calls)
	}
}
