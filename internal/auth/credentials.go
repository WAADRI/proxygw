package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"proxygw/internal/logx"
	"proxygw/internal/model"
	"proxygw/internal/store"
)

// VerifyErrorKind classifies a failed proxy credential verification. Callers
// map it to protocol specific responses and audit records; the Error() text is
// deliberately generic for the first two kinds so that responses do not reveal
// whether the username exists.
type VerifyErrorKind int

// Verification failure kinds.
const (
	VerifyNoCredential VerifyErrorKind = iota // no credential with this username
	VerifyBadPassword                         // credential exists but the password is wrong
	VerifyDisabled                            // credential is disabled
	VerifyExpired                             // credential is past its expiry time
)

// VerifyError is returned by CredentialStore.Verify for any authentication
// failure. Username is the attempted (not necessarily existing) username and is
// intended for logs/audit, never for password or hash material.
type VerifyError struct {
	Kind     VerifyErrorKind
	Username string
}

// Error implements the error interface with an operator facing Chinese message.
func (e *VerifyError) Error() string {
	switch e.Kind {
	case VerifyNoCredential, VerifyBadPassword:
		return "代理认证失败：用户名或密码错误"
	case VerifyDisabled:
		return "代理认证失败：凭据已被禁用"
	case VerifyExpired:
		return "代理认证失败：凭据已过期"
	default:
		return "代理认证失败"
	}
}

var (
	usernameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	// allowedCredentialProtocols mirrors the entry points; tcp covers generic
	// tunnel authorization so an operator can restrict a credential to raw TCP.
	allowedCredentialProtocols = map[string]bool{
		model.ProtoHTTP:    true,
		model.ProtoConnect: true,
		model.ProtoSOCKS5:  true,
		model.ProtoTCP:     true,
	}
)

// CredentialStore keeps the proxy accounts in memory and persists them as a
// JSON array. It is safe for concurrent use. Reads take a read lock only; writes
// mutate memory under the writer lock and perform disk I/O outside of it,
// serialized by opMu so that file snapshots can never be written out of order.
// Argon2id verification is intentionally memory-hard (64 MiB per call). Without
// throttling, a burst of proxy connections can exhaust the host before the
// password check completes. Successful checks are therefore cached briefly and
// cold verifications run with a small concurrency limit; both bounds are
// independent of the number of client connections.
const (
	credentialVerifyCacheTTL    = 5 * time.Minute
	credentialVerifyCacheLimit  = 4096
	credentialVerifyConcurrency = 4
)

// verifyCacheKey identifies one successful (username, password) pair without
// keeping the plaintext password in memory.
type verifyCacheKey struct {
	username string
	digest   [sha256.Size]byte
}

// verifyCacheEntry is tied to the credential's current password hash so that a
// password rotation invalidates the cached result without a global flush.
type verifyCacheEntry struct {
	credentialID string
	passwordHash string
	expiresAt    time.Time
}

type CredentialStore struct {
	mu       sync.RWMutex
	opMu     sync.Mutex // serializes disk writers (never held while waiting for mu)
	items    []model.Credential
	idxByID  map[string]int
	idxByUsr map[string]int // lower-cased username -> index

	// verifyMu guards verifyCache; verifySem bounds concurrent Argon2 calls and
	// verifySecret keys the password digests used as cache keys.
	verifyMu     sync.Mutex
	verifyCache  map[verifyCacheKey]verifyCacheEntry
	verifySem    chan struct{}
	verifySecret [32]byte

	path string
	doc  *store.JSON[[]model.Credential]
	log  *slog.Logger
	now  func() time.Time

	// MarkUsed throttling: usage updates are accumulated in memory and flushed
	// at most once per flushInterval, or on Flush/Close.
	flushInterval time.Duration
	lastFlush     time.Time
	dirty         bool
	flushing      bool
	closed        bool
}

// NewCredentialStore loads the credential table from path. An empty path creates
// a purely in-memory store (tests, ephemeral deployments); nothing is written to
// disk. A corrupted main file is recovered from "<path>.bak" and reported
// through the logger.
func NewCredentialStore(path string, logger *slog.Logger) (*CredentialStore, error) {
	s := &CredentialStore{
		path:          strings.TrimSpace(path),
		log:           logger,
		now:           time.Now,
		flushInterval: time.Second,
		idxByID:       make(map[string]int),
		idxByUsr:      make(map[string]int),
		verifyCache:   make(map[verifyCacheKey]verifyCacheEntry),
		verifySem:     make(chan struct{}, credentialVerifyConcurrency),
	}
	secret, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("初始化凭据校验缓存失败: %w", err)
	}
	copy(s.verifySecret[:], secret)
	if s.path == "" {
		s.lastFlush = s.now()
		return s, nil
	}
	s.doc = store.New[[]model.Credential](s.path)
	items, warnings, err := s.doc.Load(nil)
	if err != nil {
		return nil, fmt.Errorf("加载代理凭据失败: %w", err)
	}
	for _, w := range warnings {
		s.logger().Warn(w)
	}
	if err := s.loadItems(items); err != nil {
		return nil, err
	}
	s.lastFlush = s.now()
	return s, nil
}

// loadItems validates and installs the persisted table.
func (s *CredentialStore) loadItems(items []model.Credential) error {
	out := make([]model.Credential, 0, len(items))
	seenUsers := make(map[string]struct{}, len(items))
	for i, raw := range items {
		c, err := s.prepareStored(raw)
		if err != nil {
			return fmt.Errorf("凭据文件 %s 第 %d 条记录非法: %w", s.path, i+1, err)
		}
		key := strings.ToLower(c.Username)
		if _, ok := seenUsers[key]; ok {
			return fmt.Errorf("凭据文件 %s 存在重复用户名 %q", s.path, c.Username)
		}
		seenUsers[key] = struct{}{}
		out = append(out, c)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = out
	s.rebuildIndexLocked()
	return nil
}

// prepareStored validates one credential read from disk without rewriting it.
func (s *CredentialStore) prepareStored(raw model.Credential) (model.Credential, error) {
	c := raw
	username, err := normalizeUsername(c.Username)
	if err != nil {
		return model.Credential{}, err
	}
	c.Username = username
	if c.ID == "" {
		return model.Credential{}, fmt.Errorf("缺少 id")
	}
	c.ID = strings.TrimSpace(c.ID)
	if c.PasswordHash == "" {
		return model.Credential{}, fmt.Errorf("缺少 password_hash")
	}
	if !PasswordHashSupported(c.PasswordHash) {
		return model.Credential{}, fmt.Errorf("password_hash 格式不受支持")
	}
	if err := normalizeCredentialLists(&c); err != nil {
		return model.Credential{}, err
	}
	if c.MaxConcurrent < 0 {
		return model.Credential{}, fmt.Errorf("max_concurrent 不能为负数")
	}
	if c.BandwidthKbps < 0 {
		return model.Credential{}, fmt.Errorf("bandwidth_kbps 不能为负数")
	}
	return cloneCredential(c), nil
}

// rebuildIndexLocked rebuilds the id/username lookup maps. Callers must hold the
// write lock.
func (s *CredentialStore) rebuildIndexLocked() {
	s.idxByID = make(map[string]int, len(s.items))
	s.idxByUsr = make(map[string]int, len(s.items))
	for i := range s.items {
		s.idxByID[s.items[i].ID] = i
		s.idxByUsr[strings.ToLower(s.items[i].Username)] = i
	}
}

// logger returns a never-nil logger.
func (s *CredentialStore) logger() *slog.Logger { return logx.WithFields(s.log, "component", "auth") }

// List returns every credential with PasswordHash cleared, safe for panel API
// responses and logs. Slice fields are copied so callers can mutate the result.
func (s *CredentialStore) List() []model.Credential {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Credential, 0, len(s.items))
	for _, c := range s.items {
		c = cloneCredential(c)
		c.PasswordHash = ""
		out = append(out, c)
	}
	return out
}

// Get returns the raw credential (including its password hash) by id. The hash
// is only needed by internal callers such as the panel password-rotation flow
// and is never included in API responses.
func (s *CredentialStore) Get(id string) (model.Credential, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.idxByID[id]
	if !ok {
		return model.Credential{}, false
	}
	return cloneCredential(s.items[idx]), true
}

// GetByUsername returns the raw credential by username. The lookup is trimmed
// and case-insensitive (usernames are unique case-insensitively) while the
// stored spelling is preserved.
func (s *CredentialStore) GetByUsername(username string) (model.Credential, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.idxByUsr[strings.ToLower(strings.TrimSpace(username))]
	if !ok {
		return model.Credential{}, false
	}
	return cloneCredential(s.items[idx]), true
}

// Create validates c and appends it to the table. When c.ID is empty a random id
// is generated. c.PasswordHash must already be hashed (HashPassword); the plain
// password is never accepted here. An empty ID/username/hash is rejected, as are
// duplicate usernames (case-insensitive) and malformed list fields.
func (s *CredentialStore) Create(c model.Credential) (model.Credential, error) {
	now := s.now()
	c, err := prepareCreate(c, now)
	if err != nil {
		return model.Credential{}, err
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return model.Credential{}, fmt.Errorf("凭据存储已关闭")
	}
	if _, ok := s.idxByUsr[strings.ToLower(c.Username)]; ok {
		s.mu.Unlock()
		return model.Credential{}, fmt.Errorf("用户名 %q 已存在", c.Username)
	}
	if _, ok := s.idxByID[c.ID]; ok {
		s.mu.Unlock()
		return model.Credential{}, fmt.Errorf("凭据 id %q 已存在", c.ID)
	}
	s.items = append(s.items, c)
	s.rebuildIndexLocked()
	s.mu.Unlock()

	if err := s.persistCurrent(); err != nil {
		// Keep memory and disk consistent: undo the insertion.
		s.mu.Lock()
		if idx, ok := s.idxByID[c.ID]; ok {
			s.removeIndexLocked(idx)
		}
		s.mu.Unlock()
		return model.Credential{}, err
	}
	return cloneCredential(c), nil
}

// prepareCreate validates a new credential and fills in generated id/timestamps.
func prepareCreate(c model.Credential, now time.Time) (model.Credential, error) {
	username, err := normalizeUsername(c.Username)
	if err != nil {
		return model.Credential{}, err
	}
	c.Username = username
	if c.PasswordHash == "" {
		return model.Credential{}, fmt.Errorf("密码哈希不能为空：请先生成随机密码并通过 HashPassword 生成哈希")
	}
	if !PasswordHashSupported(c.PasswordHash) {
		return model.Credential{}, fmt.Errorf("密码哈希格式不受支持（仅支持 argon2id 或 bcrypt）")
	}
	id := strings.TrimSpace(c.ID)
	if id == "" {
		generated, err := newCredentialID()
		if err != nil {
			return model.Credential{}, err
		}
		id = generated
	} else if len(id) > 128 {
		return model.Credential{}, fmt.Errorf("凭据 id 过长（最多 128 字符）")
	}
	c.ID = id
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	// Usage counters are runtime state owned by MarkUsed; a freshly created
	// credential always starts from zero.
	c.LastUsedAt = nil
	c.BytesIn = 0
	c.BytesOut = 0
	if err := normalizeCredentialLists(&c); err != nil {
		return model.Credential{}, err
	}
	if c.MaxConcurrent < 0 {
		return model.Credential{}, fmt.Errorf("max_concurrent 不能为负数")
	}
	if c.MaxConcurrent > 1_000_000 {
		return model.Credential{}, fmt.Errorf("max_concurrent 过大（最多 1000000）")
	}
	if c.BandwidthKbps < 0 {
		return model.Credential{}, fmt.Errorf("bandwidth_kbps 不能为负数")
	}
	if c.BandwidthKbps > 100_000_000 {
		return model.Credential{}, fmt.Errorf("bandwidth_kbps 过大（最多 100000000）")
	}
	if len(c.Note) > 1024 {
		return model.Credential{}, fmt.Errorf("备注过长（最多 1024 字符）")
	}
	return cloneCredential(c), nil
}

// Update replaces the mutable fields of an existing credential identified by
// c.ID. CreatedAt, usage counters and LastUsedAt are preserved from the stored
// object; an empty PasswordHash keeps the existing hash (so panels can edit
// metadata without re-sending the hash). The username is validated and kept
// unique; an empty username keeps the existing one.
func (s *CredentialStore) Update(c model.Credential) (model.Credential, error) {
	id := strings.TrimSpace(c.ID)
	if id == "" {
		return model.Credential{}, fmt.Errorf("更新凭据缺少 id")
	}
	now := s.now()

	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return model.Credential{}, fmt.Errorf("凭据存储已关闭")
	}
	idx, ok := s.idxByID[id]
	if !ok {
		s.mu.Unlock()
		return model.Credential{}, fmt.Errorf("凭据不存在: %s", id)
	}
	prev := s.items[idx]
	next, err := prepareUpdate(prev, c, now)
	if err != nil {
		s.mu.Unlock()
		return model.Credential{}, err
	}
	if next.Username != prev.Username {
		if other, ok := s.idxByUsr[strings.ToLower(next.Username)]; ok && other != idx {
			s.mu.Unlock()
			return model.Credential{}, fmt.Errorf("用户名 %q 已存在", next.Username)
		}
	}
	s.items[idx] = next
	s.rebuildIndexLocked()
	s.mu.Unlock()

	if err := s.persistCurrent(); err != nil {
		s.mu.Lock()
		if idx, ok := s.idxByID[prev.ID]; ok {
			s.items[idx] = prev
			s.rebuildIndexLocked()
		}
		s.mu.Unlock()
		return model.Credential{}, err
	}
	return cloneCredential(next), nil
}

// prepareUpdate builds the next state of a credential from prev and incoming.
func prepareUpdate(prev, incoming model.Credential, now time.Time) (model.Credential, error) {
	next := incoming
	next.ID = prev.ID

	username := strings.TrimSpace(incoming.Username)
	if username == "" {
		username = prev.Username
	}
	username, err := normalizeUsername(username)
	if err != nil {
		return model.Credential{}, err
	}
	next.Username = username

	hash := incoming.PasswordHash
	if hash == "" {
		hash = prev.PasswordHash
	}
	if !PasswordHashSupported(hash) {
		return model.Credential{}, fmt.Errorf("密码哈希格式不受支持（仅支持 argon2id 或 bcrypt）")
	}
	next.PasswordHash = hash

	if err := normalizeCredentialLists(&next); err != nil {
		return model.Credential{}, err
	}
	if next.MaxConcurrent < 0 {
		return model.Credential{}, fmt.Errorf("max_concurrent 不能为负数")
	}
	if next.MaxConcurrent > 1_000_000 {
		return model.Credential{}, fmt.Errorf("max_concurrent 过大（最多 1000000）")
	}
	if next.BandwidthKbps < 0 {
		return model.Credential{}, fmt.Errorf("bandwidth_kbps 不能为负数")
	}
	if next.BandwidthKbps > 100_000_000 {
		return model.Credential{}, fmt.Errorf("bandwidth_kbps 过大（最多 100000000）")
	}
	if len(next.Note) > 1024 {
		return model.Credential{}, fmt.Errorf("备注过长（最多 1024 字符）")
	}

	// Runtime-state fields are owned by the store, not by the panel form.
	next.CreatedAt = prev.CreatedAt
	next.UpdatedAt = now
	next.LastUsedAt = cloneTimePtr(prev.LastUsedAt)
	next.BytesIn = prev.BytesIn
	next.BytesOut = prev.BytesOut
	return cloneCredential(next), nil
}

// Delete removes a credential by id.
func (s *CredentialStore) Delete(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("删除凭据缺少 id")
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("凭据存储已关闭")
	}
	idx, ok := s.idxByID[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("凭据不存在: %s", id)
	}
	removed := s.items[idx]
	s.removeIndexLocked(idx)
	s.mu.Unlock()

	if err := s.persistCurrent(); err != nil {
		// Restore the removed credential on persistence failure.
		s.mu.Lock()
		if _, exists := s.idxByID[removed.ID]; !exists {
			s.items = append(s.items, removed)
			s.rebuildIndexLocked()
		}
		s.mu.Unlock()
		return err
	}
	return nil
}

// removeIndexLocked deletes items[idx] keeping the backing array compact. Callers
// must hold the write lock.
func (s *CredentialStore) removeIndexLocked(idx int) {
	copy(s.items[idx:], s.items[idx+1:])
	s.items[len(s.items)-1] = model.Credential{}
	s.items = s.items[:len(s.items)-1]
	s.rebuildIndexLocked()
}

// Verify authenticates a proxy client. Checks run in a fixed order: credential
// exists -> enabled -> not expired (UTC) -> password. Any failure returns a
// *VerifyError carrying the classification; success returns the full credential
// (including hash) for internal use and never writes to disk.
//
// Successful password checks are cached for a short time because Argon2id is
// deliberately expensive (64 MiB, t=3) and proxy clients reconnect frequently.
// Cold checks are additionally serialized by verifySem so that a connection
// burst cannot allocate one 64 MiB Argon2 buffer per connection concurrently.
func (s *CredentialStore) Verify(username, password string) (model.Credential, error) {
	name := strings.TrimSpace(username)
	c, ok := s.GetByUsername(name)
	if !ok {
		return model.Credential{}, &VerifyError{Kind: VerifyNoCredential, Username: name}
	}
	if verr := s.credentialUsable(c); verr != nil {
		s.logVerifyFailure(c, verr)
		return model.Credential{}, verr
	}
	if s.verifyCacheHit(c, password) {
		return c, nil
	}

	// Bound the number of simultaneous Argon2 buffers. A queued caller may have
	// to wait, so re-read the credential afterwards: it may have been disabled,
	// rotated or deleted while waiting.
	release := s.acquireVerifySlot()
	defer release()
	c, ok = s.GetByUsername(name)
	if !ok {
		return model.Credential{}, &VerifyError{Kind: VerifyNoCredential, Username: name}
	}
	if verr := s.credentialUsable(c); verr != nil {
		s.logVerifyFailure(c, verr)
		return model.Credential{}, verr
	}
	if s.verifyCacheHit(c, password) {
		return c, nil
	}

	matched, err := VerifyPassword(c.PasswordHash, password)
	if err != nil {
		// Corrupted stored hash: log the cause (never the hash) and fail closed.
		s.logger().Error("代理凭据密码哈希校验异常", "credential", c.Username, "credential_id", c.ID, "error", err)
		return model.Credential{}, &VerifyError{Kind: VerifyBadPassword, Username: c.Username}
	}
	if !matched {
		s.logger().Debug("代理凭据密码错误", "credential", c.Username, "credential_id", c.ID)
		return model.Credential{}, &VerifyError{Kind: VerifyBadPassword, Username: c.Username}
	}
	s.storeVerifyCache(c, password)
	return c, nil
}

// credentialUsable applies the non-password checks shared by the cache and cold
// verification paths.
func (s *CredentialStore) credentialUsable(c model.Credential) *VerifyError {
	if !c.Enabled {
		return &VerifyError{Kind: VerifyDisabled, Username: c.Username}
	}
	now := s.now()
	if now.IsZero() {
		now = time.Now()
	}
	if c.ExpiresAt != nil && !c.ExpiresAt.After(now.UTC()) {
		return &VerifyError{Kind: VerifyExpired, Username: c.Username}
	}
	return nil
}

func (s *CredentialStore) logVerifyFailure(c model.Credential, verr *VerifyError) {
	switch verr.Kind {
	case VerifyDisabled:
		s.logger().Debug("代理凭据已禁用", "credential", c.Username, "credential_id", c.ID)
	case VerifyExpired:
		s.logger().Debug("代理凭据已过期", "credential", c.Username, "credential_id", c.ID)
	}
}

// verifyDigest turns the presented password into a cache key without retaining
// the plaintext.
func (s *CredentialStore) verifyDigest(password string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, s.verifySecret[:])
	_, _ = mac.Write([]byte(password))
	var out [sha256.Size]byte
	copy(out[:], mac.Sum(nil))
	return out
}

// verifyCacheHit reports whether this credential and password already passed an
// Argon2 check recently. The cached entry is rejected as soon as the credential
// id or stored password hash differs.
func (s *CredentialStore) verifyCacheHit(c model.Credential, password string) bool {
	if s.verifyCache == nil {
		return false
	}
	key := verifyCacheKey{username: strings.ToLower(c.Username), digest: s.verifyDigest(password)}
	now := s.now()
	if now.IsZero() {
		now = time.Now()
	}
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()
	entry, ok := s.verifyCache[key]
	if !ok {
		return false
	}
	if !now.Before(entry.expiresAt) || entry.credentialID != c.ID || entry.passwordHash != c.PasswordHash {
		delete(s.verifyCache, key)
		return false
	}
	return true
}

// storeVerifyCache records a successful check. The cache is bounded so a large
// credential table cannot pin unbounded memory.
func (s *CredentialStore) storeVerifyCache(c model.Credential, password string) {
	if s.verifyCache == nil {
		return
	}
	now := s.now()
	if now.IsZero() {
		now = time.Now()
	}
	key := verifyCacheKey{username: strings.ToLower(c.Username), digest: s.verifyDigest(password)}
	s.verifyMu.Lock()
	defer s.verifyMu.Unlock()
	if len(s.verifyCache) >= credentialVerifyCacheLimit {
		for k, entry := range s.verifyCache {
			if !now.Before(entry.expiresAt) {
				delete(s.verifyCache, k)
			}
		}
		for k := range s.verifyCache {
			if len(s.verifyCache) < credentialVerifyCacheLimit {
				break
			}
			delete(s.verifyCache, k)
		}
	}
	s.verifyCache[key] = verifyCacheEntry{
		credentialID: c.ID,
		passwordHash: c.PasswordHash,
		expiresAt:    now.Add(credentialVerifyCacheTTL),
	}
}

// acquireVerifySlot blocks until one of the bounded Argon2 verification slots is
// free. It never returns nil so callers can always defer the release function.
func (s *CredentialStore) acquireVerifySlot() func() {
	if s.verifySem == nil {
		return func() {}
	}
	s.verifySem <- struct{}{}
	return func() { <-s.verifySem }
}

// MarkUsed records a successful use: LastUsedAt is set and the traffic counters
// are incremented by the supplied deltas. To keep the request path from writing
// a file on every connection, persistence is throttled: the in-memory state is
// flushed at most once per second and on Flush/Close. An unknown id (credential
// deleted concurrently) is a silent no-op.
func (s *CredentialStore) MarkUsed(id string, bytesIn, bytesOut uint64) error {
	now := s.now()
	flush := false
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	idx, ok := s.idxByID[id]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	c := &s.items[idx]
	used := now
	c.LastUsedAt = &used
	c.BytesIn += bytesIn
	c.BytesOut += bytesOut
	s.dirty = true
	if !s.flushing && now.Sub(s.lastFlush) >= s.flushInterval {
		s.flushing = true
		flush = true
	}
	s.mu.Unlock()

	if !flush {
		return nil
	}
	defer func() {
		s.mu.Lock()
		s.flushing = false
		s.mu.Unlock()
	}()
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.persistCurrent()
}

// Flush persists any accumulated usage updates (if dirty).
func (s *CredentialStore) Flush() error {
	s.mu.RLock()
	dirty := s.dirty
	closed := s.closed
	s.mu.RUnlock()
	if closed || !dirty {
		return nil
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.persistCurrent()
}

// Close flushes pending usage updates and marks the store closed. It is safe to
// call more than once.
func (s *CredentialStore) Close() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	return s.persistCurrent()
}

// persistCurrent atomically writes the latest in-memory table. Callers must hold
// opMu; the data lock is only taken around the snapshot and the bookkeeping so
// that readers never block on disk I/O.
func (s *CredentialStore) persistCurrent() error {
	s.mu.Lock()
	snapshot := make([]model.Credential, len(s.items))
	for i := range s.items {
		snapshot[i] = cloneCredential(s.items[i])
	}
	path := s.path
	doc := s.doc
	s.dirty = false
	s.lastFlush = s.now()
	s.mu.Unlock()

	if path == "" || doc == nil {
		return nil
	}
	if err := doc.Save(snapshot); err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return fmt.Errorf("保存代理凭据失败: %w", err)
	}
	return nil
}

// EnsureBootstrap creates one random credential when the table is empty, as
// required for the first start with auth_mode=required. It returns the plain
// password only for this call; the caller prints it once to the console. On a
// non-empty table it returns ("", "", false, nil). Concurrent callers are safe:
// at most one credential is created.
func (s *CredentialStore) EnsureBootstrap() (username, password string, generated bool, err error) {
	s.mu.RLock()
	empty := len(s.items) == 0
	closed := s.closed
	s.mu.RUnlock()
	if !empty || closed {
		return "", "", false, nil
	}

	// Generate and hash outside the locks: argon2id takes tens of milliseconds.
	uname, err := randomUsername()
	if err != nil {
		return "", "", false, err
	}
	pw, err := GeneratePassword(24)
	if err != nil {
		return "", "", false, err
	}
	hash, err := HashPassword(pw)
	if err != nil {
		return "", "", false, fmt.Errorf("生成首启凭据密码哈希失败: %w", err)
	}
	now := s.now()
	cred := model.Credential{
		ID:           "",
		Username:     uname,
		PasswordHash: hash,
		Enabled:      true,
		Note:         "首启自动生成；密码仅在首次启动时于控制台打印一次，请在面板中及时更换",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	cred, err = prepareCreate(cred, now)
	if err != nil {
		return "", "", false, fmt.Errorf("生成首启凭据失败: %w", err)
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.Lock()
	if s.closed || len(s.items) > 0 {
		s.mu.Unlock()
		return "", "", false, nil
	}
	s.items = append(s.items, cred)
	s.rebuildIndexLocked()
	s.mu.Unlock()

	if err := s.persistCurrent(); err != nil {
		s.mu.Lock()
		if idx, ok := s.idxByID[cred.ID]; ok {
			s.removeIndexLocked(idx)
		}
		s.mu.Unlock()
		return "", "", false, err
	}
	s.logger().Warn("已生成首启代理凭据，密码仅在本次启动的控制台输出中出现一次",
		"credential", cred.Username, "credential_id", cred.ID)
	return cred.Username, pw, true, nil
}

// normalizeCredentialLists trims and validates the list-valued credential
// fields in place, normalizing source networks to canonical CIDR form.
func normalizeCredentialLists(c *model.Credential) error {
	if len(c.Groups) > 64 {
		return fmt.Errorf("groups 数量过多（最多 64 个）")
	}
	groups := make([]string, 0, len(c.Groups))
	for _, g := range c.Groups {
		g = strings.TrimSpace(g)
		if g == "" {
			return fmt.Errorf("groups 中存在空值")
		}
		groups = append(groups, g)
	}
	if len(groups) == 0 {
		c.Groups = nil
	} else {
		c.Groups = groups
	}

	if len(c.AllowedProtocols) > 8 {
		return fmt.Errorf("allowed_protocols 数量过多（最多 8 个）")
	}
	protocols := make([]string, 0, len(c.AllowedProtocols))
	seenProto := make(map[string]struct{}, len(c.AllowedProtocols))
	for _, p := range c.AllowedProtocols {
		p = strings.ToLower(strings.TrimSpace(p))
		if !allowedCredentialProtocols[p] {
			return fmt.Errorf("allowed_protocols 含不支持的值 %q（支持 http/connect/socks5/tcp）", p)
		}
		if _, ok := seenProto[p]; ok {
			continue
		}
		seenProto[p] = struct{}{}
		protocols = append(protocols, p)
	}
	if len(protocols) == 0 {
		c.AllowedProtocols = nil
	} else {
		c.AllowedProtocols = protocols
	}

	if len(c.SourceCIDRs) > 256 {
		return fmt.Errorf("source_cidrs 数量过多（最多 256 个）")
	}
	cidrs := make([]string, 0, len(c.SourceCIDRs))
	seenCIDR := make(map[string]struct{}, len(c.SourceCIDRs))
	for _, raw := range c.SourceCIDRs {
		cidr, err := normalizeCIDR(raw)
		if err != nil {
			return err
		}
		if _, ok := seenCIDR[cidr]; ok {
			continue
		}
		seenCIDR[cidr] = struct{}{}
		cidrs = append(cidrs, cidr)
	}
	if len(cidrs) == 0 {
		c.SourceCIDRs = nil
	} else {
		c.SourceCIDRs = cidrs
	}
	return nil
}

// normalizeUsername trims and validates a credential username.
func normalizeUsername(raw string) (string, error) {
	u := strings.TrimSpace(raw)
	if u == "" {
		return "", fmt.Errorf("用户名不能为空")
	}
	if !usernameRe.MatchString(u) {
		return "", fmt.Errorf("用户名 %q 非法：仅允许 1-64 个字母、数字、下划线、点或横线", raw)
	}
	return u, nil
}

// normalizeCIDR accepts a CIDR or a bare IP and returns canonical CIDR text.
func normalizeCIDR(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", fmt.Errorf("来源网段不能为空")
	}
	if _, ipnet, err := net.ParseCIDR(v); err == nil {
		return ipnet.String(), nil
	}
	if ip := net.ParseIP(v); ip != nil {
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		return fmt.Sprintf("%s/%d", ip.String(), bits), nil
	}
	return "", fmt.Errorf("来源网段 %q 非法（期望 CIDR 或 IP）", raw)
}

// newCredentialID returns a random credential id.
func newCredentialID() (string, error) {
	b, err := randomBytes(8)
	if err != nil {
		return "", fmt.Errorf("生成凭据 id 失败: %w", err)
	}
	return "cred-" + hex.EncodeToString(b), nil
}

func cloneCredential(c model.Credential) model.Credential {
	c.Groups = cloneStrings(c.Groups)
	c.AllowedProtocols = cloneStrings(c.AllowedProtocols)
	c.SourceCIDRs = cloneStrings(c.SourceCIDRs)
	c.ExpiresAt = cloneTimePtr(c.ExpiresAt)
	c.LastUsedAt = cloneTimePtr(c.LastUsedAt)
	return c
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneTimePtr(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}
