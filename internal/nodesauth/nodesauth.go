// Package nodesauth authenticates tunnel nodes. A node proves its identity with
// a per-node bearer token (either static from the configuration file or issued
// dynamically from the panel and persisted in the state directory) or, when
// nodes.mtls is enabled, with a client certificate validated by the TLS layer.
//
// Tokens are never stored or logged in clear text: the authenticator keeps a
// SHA-256 digest in memory and persists only that digest. Comparison uses
// crypto/subtle so a token cannot be recovered through timing.
package nodesauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"proxygw/internal/config"
	"proxygw/internal/model"
	"proxygw/internal/store"
)

// NodeIDWildcard is the node id that matches every node when no per-node token
// exists. It is the escape hatch for shared-secret deployments.
const NodeIDWildcard = "*"

// TokenBytes is the entropy of an issued token before base64 encoding.
const TokenBytes = 32

// Errors returned by the authenticator. They are intentionally generic so a
// probing peer cannot distinguish "unknown node" from "wrong token".
var (
	// ErrUnauthorized is returned for any authentication failure.
	ErrUnauthorized = errors.New("nodesauth: authentication failed")
	// ErrClosed is returned after Close.
	ErrClosed = errors.New("nodesauth: authenticator closed")
	// ErrInvalidNodeID is returned when the node id is empty or malformed.
	ErrInvalidNodeID = errors.New("nodesauth: invalid node id")
)

// tokenEntry is one accepted credential.
type tokenEntry struct {
	nodeID    string
	hash      [sha256.Size]byte
	note      string
	createdAt time.Time
}

// persisted is the on-disk document. Only digests are stored, never tokens.
type persisted struct {
	// Tokens holds dynamically issued credentials (digest only).
	Tokens []model.NodeToken `json:"tokens"`
	// RevokedNodes lists node ids whose tokens (static or dynamic) are revoked.
	RevokedNodes []string `json:"revoked_nodes,omitempty"`
	// Bindings maps a wildcard token digest (hex) to the first node id that used
	// it. A wildcard/shared token is thereby turned into a per-node credential
	// after the first successful registration, preventing one shared secret from
	// impersonating every node forever.
	Bindings map[string]string `json:"bindings,omitempty"`
}

// Authenticator validates node tunnel credentials.
type Authenticator struct {
	logger    *slog.Logger
	statePath string
	doc       *store.JSON[persisted]
	mtls      bool

	mu       sync.RWMutex
	static   map[string][]tokenEntry // nodeID -> static tokens
	dynamic  map[string][]tokenEntry // nodeID -> dynamic tokens
	revoked  map[string]bool
	bindings map[string]string // wildcard token digest (hex) -> bound node id
	closed   bool
}

// New builds an authenticator from the configuration. statePath is the JSON file
// used to persist dynamically issued tokens and revocations; an empty path
// disables persistence (development and tests).
func New(cfg config.NodesAuthConfig, statePath string, logger *slog.Logger) (*Authenticator, error) {
	if logger == nil {
		logger = slog.Default()
	}
	a := &Authenticator{
		logger:    logger,
		statePath: statePath,
		mtls:      cfg.MTLS,
		static:    make(map[string][]tokenEntry),
		dynamic:   make(map[string][]tokenEntry),
		revoked:   make(map[string]bool),
		bindings:  make(map[string]string),
	}
	seen := make(map[string]struct{}, len(cfg.Tokens))
	for i, tok := range cfg.Tokens {
		nodeID := strings.TrimSpace(tok.NodeID)
		token := tok.Token
		if nodeID == "" {
			return nil, fmt.Errorf("nodesauth: nodes.tokens[%d].node_id must not be empty", i)
		}
		if strings.TrimSpace(token) == "" {
			return nil, fmt.Errorf("nodesauth: nodes.tokens[%d].token (node %s) must not be empty", i, nodeID)
		}
		if nodeID != NodeIDWildcard {
			if _, dup := seen[nodeID]; dup {
				return nil, fmt.Errorf("nodesauth: duplicate token for node %q", nodeID)
			}
			seen[nodeID] = struct{}{}
		}
		a.static[nodeID] = append(a.static[nodeID], tokenEntry{
			nodeID:    nodeID,
			hash:      sha256.Sum256([]byte(token)),
			note:      tok.Note,
			createdAt: a.now(),
		})
	}
	if statePath != "" {
		a.doc = store.New[persisted](statePath)
		doc, warnings, err := a.doc.Load(persisted{})
		for _, w := range warnings {
			logger.Warn("nodes auth state recovered", "warning", w)
		}
		if err != nil {
			return nil, fmt.Errorf("nodesauth: load %s: %w", statePath, err)
		}
		for _, nd := range doc.RevokedNodes {
			a.revoked[nd] = true
		}
		for digestHex, bound := range doc.Bindings {
			if digestHex == "" || strings.TrimSpace(bound) == "" {
				continue
			}
			a.bindings[digestHex] = bound
		}
		for _, tok := range doc.Tokens {
			nodeID := strings.TrimSpace(tok.NodeID)
			if nodeID == "" || tok.TokenHash == "" {
				logger.Warn("nodes auth state: skipping malformed token record", "node_id", tok.NodeID)
				continue
			}
			var digest [sha256.Size]byte
			raw, err := hex.DecodeString(tok.TokenHash)
			if err != nil || len(raw) != sha256.Size {
				logger.Warn("nodes auth state: skipping token with invalid digest", "node_id", nodeID)
				continue
			}
			copy(digest[:], raw)
			a.dynamic[nodeID] = append(a.dynamic[nodeID], tokenEntry{
				nodeID:    nodeID,
				hash:      digest,
				note:      tok.Note,
				createdAt: tok.CreatedAt,
			})
		}
	}
	logger.Info("node authenticator ready",
		"static_tokens", a.staticCount(),
		"dynamic_tokens", a.dynamicCount(),
		"revoked_nodes", len(a.revoked),
		"mtls", a.mtls,
		"persistent", statePath != "")
	return a, nil
}

// now is replaceable in tests to keep timestamps deterministic.
func (a *Authenticator) now() time.Time { return time.Now() }

// MTLSEnabled reports whether mTLS alone is an accepted node credential.
func (a *Authenticator) MTLSEnabled() bool { return a.mtls }

// Authenticate validates nodeID against token.
func (a *Authenticator) Authenticate(nodeID, token string) error {
	return a.AuthenticateWithMTLS(nodeID, token, false)
}

// AuthenticateWithMTLS validates nodeID against token. When the authenticator is
// configured for mTLS and mtls reports that the transport proved the peer
// identity with a client certificate, the token may be empty only when no token
// is configured at all. Revocation always wins over both mechanisms.
//
// Wildcard/shared tokens are bound to the first node id that authenticates with
// them (persisted), so a shared enrollment token cannot be replayed by a second
// node id after the first registration.
func (a *Authenticator) AuthenticateWithMTLS(nodeID, token string, mtls bool) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || len(nodeID) > 256 {
		return ErrInvalidNodeID
	}
	a.mu.RLock()
	if a.closed {
		a.mu.RUnlock()
		return ErrClosed
	}
	if a.revoked[nodeID] {
		a.mu.RUnlock()
		a.logger.Warn("node authentication rejected: node revoked", "node_id", nodeID)
		return ErrUnauthorized
	}
	hasTokens := a.staticCount()+a.dynamicCount() > 0
	if a.mtls && mtls {
		if !hasTokens {
			a.mu.RUnlock()
			a.logger.Debug("node authenticated via mTLS (no node tokens configured)", "node_id", nodeID)
			return nil
		}
		// mTLS plus per-node tokens: both must prove the same identity.
		if token == "" {
			a.mu.RUnlock()
			a.logger.Debug("node authentication rejected: mTLS node missing token", "node_id", nodeID)
			return ErrUnauthorized
		}
	}
	if token == "" {
		a.mu.RUnlock()
		a.logger.Debug("node authentication rejected: empty token", "node_id", nodeID)
		return ErrUnauthorized
	}
	digest := sha256.Sum256([]byte(token))
	// Compare against every candidate without early exit so the number of
	// compared entries does not depend on which one matches.
	direct := 0
	var wildcardStatic [][sha256.Size]byte
	var wildcardDynamic [][sha256.Size]byte
	for _, e := range a.static[nodeID] {
		direct |= subtle.ConstantTimeCompare(digest[:], e.hash[:])
	}
	for _, e := range a.dynamic[nodeID] {
		direct |= subtle.ConstantTimeCompare(digest[:], e.hash[:])
	}
	if nodeID != NodeIDWildcard {
		// Explicitly configured wildcard tokens are an opt-in shared-secret mode
		// (documented, strong random token required). Auto issued bootstrap tokens
		// are bound to the first node that uses them.
		for _, e := range a.static[NodeIDWildcard] {
			wildcardStatic = append(wildcardStatic, e.hash)
		}
		for _, e := range a.dynamic[NodeIDWildcard] {
			wildcardDynamic = append(wildcardDynamic, e.hash)
		}
	}
	a.mu.RUnlock()
	if direct == 1 {
		return nil
	}
	for _, h := range wildcardStatic {
		if subtle.ConstantTimeCompare(digest[:], h[:]) == 1 {
			return nil
		}
	}
	if len(wildcardDynamic) == 0 {
		a.logger.Debug("node authentication rejected: bad token", "node_id", nodeID)
		return ErrUnauthorized
	}
	return a.bindWildcardToken(nodeID, digest, wildcardDynamic)
}

// bindWildcardToken validates a shared token and binds it to nodeID on first
// use. Persisted so a restart cannot re-bind the same token to another node.
func (a *Authenticator) bindWildcardToken(nodeID string, digest [sha256.Size]byte, candidates [][sha256.Size]byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	if a.revoked[nodeID] {
		return ErrUnauthorized
	}
	for _, h := range candidates {
		if subtle.ConstantTimeCompare(digest[:], h[:]) != 1 {
			continue
		}
		key := hex.EncodeToString(h[:])
		if bound, ok := a.bindings[key]; ok {
			if bound != nodeID {
				a.logger.Warn("node authentication rejected: shared token already bound to another node",
					"node_id", nodeID, "bound_node", bound)
				return ErrUnauthorized
			}
			return nil
		}
		a.bindings[key] = nodeID
		if err := a.saveLocked(); err != nil {
			delete(a.bindings, key)
			return err
		}
		a.logger.Warn("共享接入令牌已绑定到首个使用节点（后续仅该 node_id 可用）",
			"node_id", nodeID, "hint", "生产环境请为每个节点签发独立令牌或启用 mTLS")
		return nil
	}
	a.logger.Debug("node authentication rejected: bad token", "node_id", nodeID)
	return ErrUnauthorized
}

// Issue creates a fresh random token for nodeID, persists its digest and returns
// the clear text token exactly once. Issuing a token also lifts a previous
// revocation of that node.
func (a *Authenticator) Issue(nodeID string, note string) (string, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || len(nodeID) > 256 {
		return "", ErrInvalidNodeID
	}
	raw := make([]byte, TokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("nodesauth: generate token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(token))
	entry := tokenEntry{nodeID: nodeID, hash: digest, note: note, createdAt: a.now()}

	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return "", ErrClosed
	}
	prevTokens := a.dynamic[nodeID]
	a.dynamic[nodeID] = []tokenEntry{entry}
	wasRevoked := a.revoked[nodeID]
	delete(a.revoked, nodeID)
	err := a.saveLocked()
	if err != nil {
		// Roll back so a token that could not be persisted never works.
		if prevTokens == nil {
			delete(a.dynamic, nodeID)
		} else {
			a.dynamic[nodeID] = prevTokens
		}
		if wasRevoked {
			a.revoked[nodeID] = true
		}
		a.mu.Unlock()
		return "", err
	}
	a.mu.Unlock()
	a.logger.Info("node token issued", "node_id", nodeID, "note", note)
	return token, nil
}

// Revoke invalidates every token of nodeID. Existing sessions are closed by the
// tunnel layer (kick) after a successful revoke.
func (a *Authenticator) Revoke(nodeID string) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return ErrInvalidNodeID
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	wasRevoked := a.revoked[nodeID]
	a.revoked[nodeID] = true
	if err := a.saveLocked(); err != nil {
		if !wasRevoked {
			delete(a.revoked, nodeID)
		}
		return err
	}
	a.logger.Info("node token revoked", "node_id", nodeID)
	return nil
}

// List returns every configured credential without exposing token digests.
func (a *Authenticator) List() []model.NodeToken {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]model.NodeToken, 0, a.staticCount()+a.dynamicCount())
	appendEntries := func(m map[string][]tokenEntry) {
		for _, list := range m {
			for _, e := range list {
				tok := model.NodeToken{
					NodeID:    e.nodeID,
					Note:      e.note,
					Revoked:   a.revoked[e.nodeID],
					CreatedAt: e.createdAt,
					UpdatedAt: e.createdAt,
				}
				out = append(out, tok)
			}
		}
	}
	appendEntries(a.static)
	appendEntries(a.dynamic)
	sort.Slice(out, func(i, j int) bool {
		if out[i].NodeID != out[j].NodeID {
			return out[i].NodeID < out[j].NodeID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

// Close releases the authenticator. It is idempotent.
func (a *Authenticator) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	return nil
}

// NodeIDs returns the node ids that currently have at least one credential.
func (a *Authenticator) NodeIDs() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	set := make(map[string]struct{}, len(a.static)+len(a.dynamic))
	for id := range a.static {
		set[id] = struct{}{}
	}
	for id := range a.dynamic {
		set[id] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// saveLocked persists the dynamic state. Caller holds a.mu.
func (a *Authenticator) saveLocked() error {
	if a.doc == nil {
		return nil
	}
	doc := persisted{
		Tokens:       make([]model.NodeToken, 0, a.dynamicCount()),
		RevokedNodes: make([]string, 0, len(a.revoked)),
		Bindings:     make(map[string]string, len(a.bindings)),
	}
	for digestHex, bound := range a.bindings {
		doc.Bindings[digestHex] = bound
	}
	now := a.now()
	for nodeID, list := range a.dynamic {
		for _, e := range list {
			doc.Tokens = append(doc.Tokens, model.NodeToken{
				NodeID:    nodeID,
				TokenHash: hex.EncodeToString(e.hash[:]),
				Note:      e.note,
				Revoked:   a.revoked[nodeID],
				CreatedAt: e.createdAt,
				UpdatedAt: now,
			})
		}
	}
	sort.Slice(doc.Tokens, func(i, j int) bool {
		if doc.Tokens[i].NodeID != doc.Tokens[j].NodeID {
			return doc.Tokens[i].NodeID < doc.Tokens[j].NodeID
		}
		return doc.Tokens[i].CreatedAt.Before(doc.Tokens[j].CreatedAt)
	})
	for id := range a.revoked {
		doc.RevokedNodes = append(doc.RevokedNodes, id)
	}
	sort.Strings(doc.RevokedNodes)
	if err := a.doc.Save(doc); err != nil {
		return fmt.Errorf("nodesauth: persist %s: %w", a.statePath, err)
	}
	return nil
}

func (a *Authenticator) staticCount() int {
	n := 0
	for _, l := range a.static {
		n += len(l)
	}
	return n
}

func (a *Authenticator) dynamicCount() int {
	n := 0
	for _, l := range a.dynamic {
		n += len(l)
	}
	return n
}
