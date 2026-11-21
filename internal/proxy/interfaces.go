// Package proxy implements the three proxy entry points of the gateway: plain
// HTTP forwarding (absolute-form), HTTP CONNECT and SOCKS5 (RFC 1928/1929).
//
// The entry points are deliberately decoupled from the rest of the server. They
// depend only on the small interfaces below; the assembly layer adapts the
// credential store, the scheduler, the ACL engine and the tunnel dialer to them.
// That keeps the protocol code testable with fakes and avoids import cycles.
package proxy

import (
	"context"
	"io"

	"proxygw/internal/model"
	"proxygw/internal/protocol"
)

// Authenticator validates proxy credentials and returns the matching
// credential. A non-nil error (or a nil credential and nil error) means the
// user name / password pair is not valid.
type Authenticator interface {
	Verify(username, password string) (*model.Credential, error)
}

// CandidateResolver returns the nodes visible to a credential. An empty groups
// slice means "all nodes". Implementations must return only nodes that are
// enabled and online; the proxy layer treats an empty result as a hard
// fail-closed condition and never falls back to the whole fleet.
type CandidateResolver interface {
	Candidates(groups []string) ([]*model.Node, error)
}

// SelectRequest is one scheduling request. It mirrors the scheduler input but is
// owned by this package so the scheduler does not have to be imported.
type SelectRequest struct {
	CredentialID string
	Username     string
	SourceIP     string
	Protocol     string // http | connect | socks5
	Target       model.RequestTarget
	Exclude      []string // node ids that already failed in this request
}

// SelectionInfo describes why a node was selected. It is filled by the
// Selector adapter and is used for logging, metrics and audits.
type SelectionInfo struct {
	Strategy       string
	StickyHit      bool
	StickyMigrated bool
	Blacklisted    bool
	BlacklistRule  string
	Reason         string
}

// Selector chooses one node for a request. It receives a deadline budget: the
// proxy layer calls it with a 5ms context and degrades to a random candidate
// when the budget is exhausted.
type Selector interface {
	Select(ctx context.Context, req SelectRequest, candidates []*model.Node) (*model.Node, SelectionInfo, error)
	// RecordResult records a node-side result for circuit breaking. A nil error
	// means success. Target side 4xx/5xx responses and ACL decisions are never
	// reported here.
	RecordResult(nodeID string, err error)
}

// ACLChecker decides whether a target is allowed. A nil checker means no ACL.
type ACLChecker interface {
	Check(t model.RequestTarget) error
}

// StreamDialer opens one tunnel stream through a node. The returned stream is a
// bidirectional byte pipe with half-close support.
type StreamDialer interface {
	OpenStream(ctx context.Context, nodeID string, req protocol.OpenRequest) (StreamConn, error)
}

// StreamConn is one established tunnel stream.
type StreamConn interface {
	io.ReadWriteCloser
	// CloseWrite sends FIN for the local write direction only. Reads continue
	// until the peer closes its own direction.
	CloseWrite() error
}

// ByteLimiter is a token bucket. WaitN blocks until n bytes may pass; it must
// apply backpressure instead of dropping data.
type ByteLimiter interface {
	WaitN(ctx context.Context, n int) error
}

// Bandwidth returns the byte limiters for one stream direction. Down is the
// node to client direction, Up is the client to node direction.
type Bandwidth interface {
	Down(credentialID, nodeID string) ByteLimiter
	Up(credentialID, nodeID string) ByteLimiter
}
