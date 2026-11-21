package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"proxygw/internal/model"
)

// testClock is an injectable clock for expiry/lock-window tests.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock(t time.Time) *testClock { return &testClock{t: t} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestAdmin(t *testing.T, opts AdminOptions) *AdminManager {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = testLogger()
	}
	mgr, err := NewAdminManager(opts)
	if err != nil {
		t.Fatalf("NewAdminManager: %v", err)
	}
	return mgr
}

func readAdminState(t *testing.T, path string) model.AdminUser {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read admin state: %v", err)
	}
	var user model.AdminUser
	if err := json.Unmarshal(data, &user); err != nil {
		t.Fatalf("unmarshal admin state: %v", err)
	}
	return user
}

func TestAdminConfiguredHashLogin(t *testing.T) {
	clock := newTestClock(time.Unix(1700000000, 0))
	hash, err := HashPassword("panel-pass")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	mgr := newTestAdmin(t, AdminOptions{
		Username:        "root",
		PasswordHash:    hash,
		SessionTTL:      time.Hour,
		LoginRatePerMin: 10,
		LockThreshold:   5,
		LockWindow:      5 * time.Minute,
		Now:             clock.Now,
	})
	if got := mgr.BootstrapPassword(); got != "" {
		t.Fatalf("BootstrapPassword = %q, want empty for configured hash", got)
	}
	if got := mgr.CurrentUser().Username; got != "root" {
		t.Fatalf("CurrentUser().Username = %q", got)
	}
	if mgr.TOTPEnabled() {
		t.Fatal("TOTP unexpectedly enabled")
	}

	user, err := mgr.Authenticate("root", "panel-pass", "", "203.0.113.9")
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if user.Username != "root" {
		t.Fatalf("authenticated user = %q", user.Username)
	}

	if _, err := mgr.Authenticate("root", "wrong", "", "203.0.113.9"); !errors.Is(err, ErrInvalidLogin) {
		t.Fatalf("wrong password error = %v, want ErrInvalidLogin", err)
	}
	if _, err := mgr.Authenticate("nobody", "panel-pass", "", "203.0.113.9"); !errors.Is(err, ErrInvalidLogin) {
		t.Fatalf("unknown user error = %v, want ErrInvalidLogin", err)
	}

	token, expires, err := mgr.IssueToken(*user)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	const wantExpiry = int64(1700000000 + 3600)
	if expires.Unix() != wantExpiry {
		t.Fatalf("expires = %d, want %d", expires.Unix(), wantExpiry)
	}
	claims, err := mgr.VerifyToken(token)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.Username != "root" || !claims.Expires.Equal(expires) {
		t.Fatalf("claims = %+v, want root/%v", claims, expires)
	}
	mustRejectJWT(t, mgr, token, ErrInvalidToken)

	if _, _, err := mgr.IssueToken(model.AdminUser{}); err == nil {
		t.Fatal("IssueToken with empty user succeeded")
	}
	if _, err := mgr.VerifyToken(""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyToken(empty) = %v", err)
	}
}

// mustRejectJWT verifies that VerifyToken rejects a malformed token.
func mustRejectJWT(t *testing.T, mgr *AdminManager, token string, want error) {
	t.Helper()
	last := token[len(token)-1]
	replacement := byte('A')
	if last == 'A' {
		replacement = 'B'
	}
	tampered := token[:len(token)-1] + string(replacement)
	if tampered == token {
		t.Fatal("failed to tamper with token")
	}
	if _, err := mgr.VerifyToken(tampered); !errors.Is(err, want) {
		t.Fatalf("VerifyToken(tampered) = %v, want %v", err, want)
	}
}

func TestAdminJWTClaimsAndRejectedAlgorithms(t *testing.T) {
	clock := newTestClock(time.Unix(1700000000, 0))
	mgr := newTestAdmin(t, AdminOptions{
		Username:     "root",
		PasswordHash: mustCheapHash(t, "pw"),
		SessionTTL:   time.Hour,
		Now:          clock.Now,
	})
	now := clock.Now()
	baseClaims := func() jwt.MapClaims {
		return jwt.MapClaims{
			"sub": "root",
			"iat": now.Unix(),
			"exp": now.Add(time.Hour).Unix(),
			"jti": "test-jti",
		}
	}

	// HS256 token works.
	valid := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims())
	signed, err := valid.SignedString(mgr.secret)
	if err != nil {
		t.Fatalf("sign HS256: %v", err)
	}
	if _, err := mgr.VerifyToken(signed); err != nil {
		t.Fatalf("VerifyToken(HS256): %v", err)
	}

	// HS384 with the correct secret must be rejected (algorithm confusion).
	hs384 := jwt.NewWithClaims(jwt.SigningMethodHS384, baseClaims())
	signed384, err := hs384.SignedString(mgr.secret)
	if err != nil {
		t.Fatalf("sign HS384: %v", err)
	}
	if _, err := mgr.VerifyToken(signed384); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyToken(HS384) = %v, want ErrInvalidToken", err)
	}

	// "alg: none" must be rejected.
	none := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims())
	unsigned, err := none.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := mgr.VerifyToken(unsigned); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyToken(none) = %v, want ErrInvalidToken", err)
	}

	// A token signed by a different manager (different key) is invalid.
	other := newTestAdmin(t, AdminOptions{Username: "root", PasswordHash: mustCheapHash(t, "pw"), Now: clock.Now})
	if _, err := other.VerifyToken(signed); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("VerifyToken(other key) = %v, want ErrInvalidToken", err)
	}

	// Expiry is enforced against the injected clock.
	clock.Advance(61 * time.Minute)
	if _, err := mgr.VerifyToken(signed); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("VerifyToken(expired) = %v, want ErrExpiredToken", err)
	}
}

func TestAdminFirstStartAndRestart(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "admin.json")
	jwtPath := filepath.Join(dir, "jwt.secret")
	clock := newTestClock(time.Unix(1700000000, 0))
	opts := AdminOptions{
		StatePath:     statePath,
		JWTSecretPath: jwtPath,
		SessionTTL:    time.Hour,
		Now:           clock.Now,
	}

	mgr := newTestAdmin(t, opts)
	bootstrap := mgr.BootstrapPassword()
	if len(bootstrap) != 20 {
		t.Fatalf("bootstrap password length = %d, want 20", len(bootstrap))
	}
	user, err := mgr.Authenticate("admin", bootstrap, "", "192.0.2.10")
	if err != nil {
		t.Fatalf("Authenticate with bootstrap password: %v", err)
	}
	token, _, err := mgr.IssueToken(*user)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	// The state file must contain a hash and never the plain password.
	rawState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read admin state: %v", err)
	}
	if bytes.Contains(rawState, []byte(bootstrap)) {
		t.Fatal("admin.json contains the plain bootstrap password")
	}
	if !bytes.Contains(rawState, []byte("$argon2id$")) {
		t.Fatalf("admin.json does not contain an argon2id hash: %s", rawState)
	}
	stored := readAdminState(t, statePath)
	if !PasswordHashSupported(stored.PasswordHash) {
		t.Fatalf("persisted hash unsupported: %q", stored.PasswordHash)
	}
	if stored.Username != "admin" || stored.CreatedAt.IsZero() || stored.UpdatedAt.IsZero() {
		t.Fatalf("persisted admin user incomplete: %+v", stored)
	}

	secretBytes, err := os.ReadFile(jwtPath)
	if err != nil {
		t.Fatalf("read jwt secret: %v", err)
	}
	if len(secretBytes) != 32 {
		t.Fatalf("jwt.secret length = %d, want 32", len(secretBytes))
	}

	// Restart: same password still authenticates, no new bootstrap password and
	// old tokens stay valid because the signing key was persisted.
	mgr2 := newTestAdmin(t, opts)
	if got := mgr2.BootstrapPassword(); got != "" {
		t.Fatalf("restart BootstrapPassword = %q, want empty", got)
	}
	if _, err := mgr2.Authenticate("admin", bootstrap, "", "192.0.2.10"); err != nil {
		t.Fatalf("Authenticate after restart: %v", err)
	}
	claims, err := mgr2.VerifyToken(token)
	if err != nil || claims.Username != "admin" {
		t.Fatalf("VerifyToken after restart: %+v, %v", claims, err)
	}
}

func TestAdminConfigHashOverridesState(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "admin.json")
	jwtPath := filepath.Join(dir, "jwt.secret")
	clock := newTestClock(time.Unix(59, 0)) // RFC 6238 vector time step 1
	secret := totpTestSecret()

	mgr := newTestAdmin(t, AdminOptions{StatePath: statePath, JWTSecretPath: jwtPath, Now: clock.Now})
	oldPassword := mgr.BootstrapPassword()
	if oldPassword == "" {
		t.Fatal("first start did not generate a bootstrap password")
	}

	configuredHash, err := HashPassword("configured-pass")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	mgr2 := newTestAdmin(t, AdminOptions{
		StatePath:     statePath,
		JWTSecretPath: jwtPath,
		PasswordHash:  configuredHash,
		TOTPSecret:    secret,
		Now:           clock.Now,
	})
	if got := mgr2.BootstrapPassword(); got != "" {
		t.Fatalf("configured-hash start BootstrapPassword = %q, want empty", got)
	}
	if _, err := mgr2.Authenticate("admin", "configured-pass", "287082", "192.0.2.20"); err != nil {
		t.Fatalf("Authenticate with configured password + TOTP: %v", err)
	}
	if _, err := mgr2.Authenticate("admin", oldPassword, "287082", "192.0.2.20"); !errors.Is(err, ErrInvalidLogin) {
		t.Fatalf("old generated password error = %v, want ErrInvalidLogin", err)
	}

	// The configured hash and TOTP secret are written back to the state file.
	stored := readAdminState(t, statePath)
	if stored.PasswordHash != configuredHash {
		t.Fatalf("state hash was not updated: %q", stored.PasswordHash)
	}
	if stored.TOTPSecret != secret {
		t.Fatalf("state TOTP secret = %q, want %q", stored.TOTPSecret, secret)
	}

	// A restart with defaults loads the persisted identity.
	mgr3 := newTestAdmin(t, AdminOptions{StatePath: statePath, JWTSecretPath: jwtPath, Now: clock.Now})
	if !mgr3.TOTPEnabled() {
		t.Fatal("persisted TOTP secret was not loaded")
	}
	if _, err := mgr3.Authenticate("admin", "configured-pass", "", "192.0.2.21"); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("missing TOTP error = %v, want ErrTOTPRequired", err)
	}
	if _, err := mgr3.Authenticate("admin", "configured-pass", "287082", "192.0.2.21"); err != nil {
		t.Fatalf("Authenticate after restart with TOTP: %v", err)
	}
}

func TestAdminLockout(t *testing.T) {
	clock := newTestClock(time.Unix(1700000100, 0))
	mgr := newTestAdmin(t, AdminOptions{
		Username:        "admin",
		PasswordHash:    mustCheapHash(t, "lock-pass"),
		LoginRatePerMin: 10,
		LockThreshold:   5,
		LockWindow:      5 * time.Minute,
		Now:             clock.Now,
	})
	const ip = "198.51.100.7"
	for i := 1; i <= 4; i++ {
		if _, err := mgr.Authenticate("admin", "wrong", "", ip); !errors.Is(err, ErrInvalidLogin) {
			t.Fatalf("attempt %d error = %v, want ErrInvalidLogin", i, err)
		}
	}
	if _, err := mgr.Authenticate("admin", "wrong", "", ip); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("threshold attempt error = %v, want ErrLockedOut", err)
	}
	// Correct credentials are rejected while the lock is active.
	if _, err := mgr.Authenticate("admin", "lock-pass", "", ip); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("locked-out login error = %v, want ErrLockedOut", err)
	}
	// Lockout is per source IP.
	if _, err := mgr.Authenticate("admin", "lock-pass", "", "198.51.100.8"); err != nil {
		t.Fatalf("other IP login rejected: %v", err)
	}
	// After the window the IP can log in again.
	clock.Advance(5*time.Minute + time.Second)
	if _, err := mgr.Authenticate("admin", "lock-pass", "", ip); err != nil {
		t.Fatalf("login after lock window: %v", err)
	}
}

func TestAdminLoginRateLimit(t *testing.T) {
	clock := newTestClock(time.Unix(1700000100, 0))
	mgr := newTestAdmin(t, AdminOptions{
		Username:        "admin",
		PasswordHash:    mustCheapHash(t, "rate-pass"),
		LoginRatePerMin: 3,
		LockThreshold:   10,
		LockWindow:      5 * time.Minute,
		Now:             clock.Now,
	})
	const ip = "203.0.113.30"
	for i := 0; i < 3; i++ {
		if _, err := mgr.Authenticate("admin", "wrong", "", ip); !errors.Is(err, ErrInvalidLogin) {
			t.Fatalf("attempt %d error = %v, want ErrInvalidLogin", i, err)
		}
	}
	// The per-minute budget is exhausted even for correct credentials.
	if _, err := mgr.Authenticate("admin", "rate-pass", "", ip); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("rate-limited login error = %v, want ErrLockedOut", err)
	}
	if _, err := mgr.Authenticate("admin", "rate-pass", "", "203.0.113.31"); err != nil {
		t.Fatalf("other IP login rejected: %v", err)
	}
	// After the sliding window slides past the attempts, login is allowed again.
	clock.Advance(61 * time.Second)
	if _, err := mgr.Authenticate("admin", "rate-pass", "", ip); err != nil {
		t.Fatalf("login after rate window: %v", err)
	}
}

func TestAdminTOTP(t *testing.T) {
	clock := newTestClock(time.Unix(59, 0))
	secret := totpTestSecret()
	mgr := newTestAdmin(t, AdminOptions{
		Username:        "admin",
		PasswordHash:    mustCheapHash(t, "totp-pass"),
		TOTPSecret:      secret,
		LoginRatePerMin: 10,
		LockThreshold:   5,
		Now:             clock.Now,
	})
	if !mgr.TOTPEnabled() {
		t.Fatal("TOTPEnabled = false with a configured secret")
	}
	if _, err := mgr.Authenticate("admin", "totp-pass", "", "192.0.2.40"); !errors.Is(err, ErrTOTPRequired) {
		t.Fatalf("missing TOTP error = %v, want ErrTOTPRequired", err)
	}
	if _, err := mgr.Authenticate("admin", "totp-pass", "000000", "192.0.2.40"); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("wrong TOTP error = %v, want ErrTOTPInvalid", err)
	}
	if _, err := mgr.Authenticate("admin", "totp-pass", "287082", "192.0.2.40"); err != nil {
		t.Fatalf("Authenticate with valid TOTP: %v", err)
	}

	if err := mgr.VerifyTOTP("287082"); err != nil {
		t.Fatalf("VerifyTOTP(valid): %v", err)
	}
	if err := mgr.VerifyTOTP(""); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("VerifyTOTP(empty) = %v, want ErrTOTPInvalid", err)
	}
	if err := mgr.VerifyTOTP("123456"); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("VerifyTOTP(wrong) = %v, want ErrTOTPInvalid", err)
	}

	// A code from two time steps ago is outside the +/- 1 window.
	clock.Advance(60 * time.Second) // now T=119, time step 3
	if err := mgr.VerifyTOTP("287082"); !errors.Is(err, ErrTOTPInvalid) {
		t.Fatalf("VerifyTOTP(old code) = %v, want ErrTOTPInvalid", err)
	}

	// Invalid configuration is rejected at construction time.
	if _, err := NewAdminManager(AdminOptions{TOTPSecret: "not base32!", Logger: testLogger()}); err == nil {
		t.Fatal("NewAdminManager accepted an invalid TOTP secret")
	}
	// Unconfigured managers report TOTP as unavailable.
	plain := newTestAdmin(t, AdminOptions{Username: "admin", PasswordHash: mustCheapHash(t, "pw"), Logger: testLogger()})
	if plain.TOTPEnabled() {
		t.Fatal("TOTPEnabled = true without a secret")
	}
	if err := plain.VerifyTOTP("123456"); !errors.Is(err, ErrTOTPNotConfigured) {
		t.Fatalf("VerifyTOTP without secret = %v, want ErrTOTPNotConfigured", err)
	}
}

func TestAdminSetPasswordHash(t *testing.T) {
	clock := newTestClock(time.Unix(1700000000, 0))
	mgr := newTestAdmin(t, AdminOptions{
		Username:     "admin",
		PasswordHash: mustCheapHash(t, "old-pass"),
		Now:          clock.Now,
	})
	if _, err := mgr.Authenticate("admin", "old-pass", "", "192.0.2.50"); err != nil {
		t.Fatalf("Authenticate old password: %v", err)
	}
	if err := mgr.SetPasswordHash(mustCheapHash(t, "new-pass")); err != nil {
		t.Fatalf("SetPasswordHash: %v", err)
	}
	if _, err := mgr.Authenticate("admin", "old-pass", "", "192.0.2.50"); !errors.Is(err, ErrInvalidLogin) {
		t.Fatalf("old password after rotation = %v, want ErrInvalidLogin", err)
	}
	if _, err := mgr.Authenticate("admin", "new-pass", "", "192.0.2.50"); err != nil {
		t.Fatalf("new password after rotation: %v", err)
	}
	if err := mgr.SetPasswordHash("not-a-hash"); err == nil {
		t.Fatal("SetPasswordHash accepted a plaintext value")
	}

	// A persistent manager writes the new hash through and its bootstrap password
	// is invalidated once the operator sets a password.
	dir := t.TempDir()
	statePath := filepath.Join(dir, "admin.json")
	jwtPath := filepath.Join(dir, "jwt.secret")
	persistent := newTestAdmin(t, AdminOptions{StatePath: statePath, JWTSecretPath: jwtPath, Now: clock.Now})
	if persistent.BootstrapPassword() == "" {
		t.Fatal("persistent first start did not generate a bootstrap password")
	}
	if err := persistent.SetPasswordHash(mustCheapHash(t, "rotated-pass")); err != nil {
		t.Fatalf("SetPasswordHash(persistent): %v", err)
	}
	if got := persistent.BootstrapPassword(); got != "" {
		t.Fatalf("BootstrapPassword after SetPasswordHash = %q, want empty", got)
	}
	restarted := newTestAdmin(t, AdminOptions{StatePath: statePath, JWTSecretPath: jwtPath, Now: clock.Now})
	if _, err := restarted.Authenticate("admin", "rotated-pass", "", "192.0.2.51"); err != nil {
		t.Fatalf("rotated password after restart: %v", err)
	}
	if !PasswordHashSupported(readAdminState(t, statePath).PasswordHash) {
		t.Fatal("persisted rotated hash is unsupported")
	}
}

func TestAdminCorruptStateFailsClosed(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "admin.json")
	if err := os.WriteFile(statePath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("write corrupt state: %v", err)
	}
	if _, err := NewAdminManager(AdminOptions{
		StatePath:     statePath,
		JWTSecretPath: filepath.Join(dir, "jwt.secret"),
		Logger:        testLogger(),
	}); err == nil {
		t.Fatal("NewAdminManager accepted a corrupt admin.json")
	}
}

func TestAdminJWTSecretValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jwt.secret")
	if err := os.WriteFile(path, []byte("too-short"), 0o600); err != nil {
		t.Fatalf("write short secret: %v", err)
	}
	if _, err := NewAdminManager(AdminOptions{
		JWTSecretPath: path,
		Logger:        testLogger(),
	}); err == nil {
		t.Fatal("NewAdminManager accepted a short jwt.secret")
	}
}
