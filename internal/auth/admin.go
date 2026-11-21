package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"proxygw/internal/logx"
	"proxygw/internal/model"
	"proxygw/internal/store"
)

// Admin authentication errors. Authenticate returns these sentinel values
// directly (not wrapped) so callers can classify the failure with errors.Is and
// write audit records / protocol responses accordingly.
var (
	// ErrInvalidLogin means the administrator username or password is wrong.
	ErrInvalidLogin = errors.New("用户名或密码错误")
	// ErrLockedOut means the source IP exceeded the login rate or is inside a
	// lockout window after too many consecutive failures.
	ErrLockedOut = errors.New("登录尝试过于频繁或已被临时锁定，请稍后再试")
	// ErrTOTPRequired means TOTP is enabled and the request did not supply a code.
	ErrTOTPRequired = errors.New("需要输入动态验证码")
	// ErrTOTPInvalid means the supplied TOTP code is not valid for the current time.
	ErrTOTPInvalid = errors.New("动态验证码错误")
	// ErrTOTPNotConfigured is returned by VerifyTOTP when no TOTP secret is set.
	ErrTOTPNotConfigured = errors.New("未启用 TOTP 二次验证")
)

// AdminOptions configures the panel administrator manager.
type AdminOptions struct {
	Username        string        // administrator login name (default "admin")
	PasswordHash    string        // argon2id/bcrypt hash from config; empty = load state or generate on first start
	TOTPSecret      string        // base32 TOTP secret; empty = TOTP disabled
	StatePath       string        // admin.json persistence path; empty = memory only
	JWTSecretPath   string        // jwt.secret path (32 random bytes); empty = process random
	SessionTTL      time.Duration // JWT lifetime (default 12h)
	LoginRatePerMin int           // sliding-window login attempts per minute per source IP (default 10)
	LockThreshold   int           // consecutive failures before a temporary lock (default 5)
	LockWindow      time.Duration // temporary lock duration (default 5m)
	Logger          *slog.Logger
	// Now overrides the clock; tests use it to exercise expiry and lock windows.
	Now func() time.Time
}

// AdminManager owns the panel administrator identity, the JWT signing key, the
// per-IP login limiter and the TOTP verifier. All methods are safe for
// concurrent use.
type AdminManager struct {
	mu     sync.RWMutex
	saveMu sync.Mutex // serializes state writes so stale snapshots cannot clobber newer ones
	user   model.AdminUser
	state  *store.JSON[model.AdminUser]

	secret     []byte
	sessionTTL time.Duration
	bootstrap  string // generated plain password for this startup only
	now        func() time.Time
	logger     *slog.Logger
	limiter    *loginLimiter
}

// NewAdminManager resolves the administrator identity with the documented
// precedence (config password hash > persisted admin.json > generated on first
// start), loads or creates the JWT signing secret and persists the result.
func NewAdminManager(opts AdminOptions) (*AdminManager, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	logger := logx.WithFields(opts.Logger, "component", "auth")

	sessionTTL := opts.SessionTTL
	if sessionTTL <= 0 {
		sessionTTL = 12 * time.Hour
	}

	secret, err := loadOrCreateJWTSecret(opts.JWTSecretPath)
	if err != nil {
		return nil, err
	}

	var (
		state      *store.JSON[model.AdminUser]
		stored     model.AdminUser
		haveStored bool
	)
	if statePath := strings.TrimSpace(opts.StatePath); statePath != "" {
		state = store.New[model.AdminUser](statePath)
		loaded, warnings, err := state.Load(model.AdminUser{})
		if err != nil {
			return nil, fmt.Errorf("加载面板管理员状态失败: %w", err)
		}
		for _, w := range warnings {
			logger.Warn(w)
		}
		if loaded.Username != "" || loaded.PasswordHash != "" {
			stored = loaded
			haveStored = true
		}
	}

	username := strings.TrimSpace(opts.Username)
	if username == "" && haveStored {
		username = stored.Username
	}
	if username == "" {
		username = "admin"
	}

	totpRaw := opts.TOTPSecret
	if strings.TrimSpace(totpRaw) == "" && haveStored {
		totpRaw = stored.TOTPSecret
	}
	totpSecret, err := normalizeTOTPSecret(totpRaw)
	if err != nil {
		return nil, err
	}

	var (
		hash      string
		bootstrap string
	)
	switch {
	case opts.PasswordHash != "":
		// Configuration wins over the persisted state and is written back.
		if !PasswordHashSupported(opts.PasswordHash) {
			return nil, fmt.Errorf("admin.password_hash 格式不受支持（仅支持 argon2id 或 bcrypt）")
		}
		hash = opts.PasswordHash
	case haveStored && stored.PasswordHash != "":
		if !PasswordHashSupported(stored.PasswordHash) {
			return nil, fmt.Errorf("面板管理员状态文件中的密码哈希格式不受支持")
		}
		hash = stored.PasswordHash
	default:
		pw, err := GeneratePassword(20)
		if err != nil {
			return nil, fmt.Errorf("生成首启管理员密码失败: %w", err)
		}
		h, err := HashPassword(pw)
		if err != nil {
			return nil, fmt.Errorf("生成首启管理员密码哈希失败: %w", err)
		}
		hash = h
		bootstrap = pw
	}

	createdAt := stored.CreatedAt
	if createdAt.IsZero() {
		createdAt = now()
	}
	user := model.AdminUser{
		Username:     username,
		PasswordHash: hash,
		TOTPSecret:   totpSecret,
		CreatedAt:    createdAt,
		UpdatedAt:    now(),
	}

	a := &AdminManager{
		user:       user,
		state:      state,
		secret:     secret,
		sessionTTL: sessionTTL,
		bootstrap:  bootstrap,
		now:        now,
		logger:     logger,
		limiter:    newLoginLimiter(opts.LoginRatePerMin, opts.LockThreshold, opts.LockWindow),
	}
	if state != nil {
		if err := state.Save(user); err != nil {
			return nil, fmt.Errorf("保存面板管理员状态失败: %w", err)
		}
	}
	if bootstrap != "" {
		logger.Warn("已生成首启面板管理员密码：明文仅在本次启动的控制台输出一次，请登录后立即修改",
			"username", username)
	}
	return a, nil
}

// BootstrapPassword returns the generated plain administrator password when this
// startup created one, otherwise an empty string. main prints it once.
func (a *AdminManager) BootstrapPassword() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.bootstrap
}

// Authenticate verifies username + password and, when configured, the TOTP code
// for a login attempt from sourceIP. Failures are counted per source IP: too
// many attempts inside one minute or too many consecutive failures trigger
// ErrLockedOut. A successful login resets the counters.
func (a *AdminManager) Authenticate(username, password, totpCode, sourceIP string) (*model.AdminUser, error) {
	src := normalizeSourceIP(sourceIP)
	now := a.now()
	if err := a.limiter.begin(src, now); err != nil {
		a.logFailure(src, username, "rate_or_lock")
		return nil, err
	}

	a.mu.RLock()
	user := a.user
	a.mu.RUnlock()

	if subtle.ConstantTimeCompare([]byte(username), []byte(user.Username)) != 1 {
		a.logFailure(src, username, "invalid_credentials")
		return nil, a.limiter.fail(src, now, ErrInvalidLogin)
	}
	matched, err := VerifyPassword(user.PasswordHash, password)
	if err != nil {
		// A corrupted stored hash must not panic and must not leak: fail closed.
		a.logger.Error("面板管理员密码哈希校验异常", "error", err, "source_ip", src)
		a.logFailure(src, username, "invalid_credentials")
		return nil, a.limiter.fail(src, now, ErrInvalidLogin)
	}
	if !matched {
		a.logFailure(src, username, "invalid_credentials")
		return nil, a.limiter.fail(src, now, ErrInvalidLogin)
	}

	if user.TOTPSecret != "" {
		code := strings.TrimSpace(totpCode)
		switch {
		case code == "":
			a.logFailure(src, username, "totp_required")
			return nil, a.limiter.fail(src, now, ErrTOTPRequired)
		case !validTOTP(user.TOTPSecret, code, now):
			a.logFailure(src, username, "totp_invalid")
			return nil, a.limiter.fail(src, now, ErrTOTPInvalid)
		}
	}

	a.limiter.success(src, now)
	a.logger.Info("面板管理员登录成功", "username", user.Username, "source_ip", src)
	out := user
	return &out, nil
}

// logFailure emits a structured warning. Username/source IP are not secrets; the
// password, its hash and TOTP codes are never passed here.
func (a *AdminManager) logFailure(sourceIP, username, reason string) {
	a.logger.Warn("面板管理员认证失败", "source_ip", sourceIP, "username", username, "reason", reason)
}

// IssueToken is implemented in jwt.go.

// SetPasswordHash replaces the administrator password hash (the caller produces
// it with HashPassword) and persists it. The bootstrap password is invalidated
// from memory once a new password is set.
func (a *AdminManager) SetPasswordHash(hash string) error {
	if !PasswordHashSupported(hash) {
		return fmt.Errorf("不支持的密码哈希格式（仅支持 argon2id 或 bcrypt）")
	}
	a.mu.Lock()
	a.user.PasswordHash = hash
	a.user.UpdatedAt = a.now()
	a.bootstrap = ""
	a.mu.Unlock()
	return a.persist()
}

// VerifyTOTP validates code against the configured TOTP secret using the
// manager clock and a +/- one time-step window.
func (a *AdminManager) VerifyTOTP(code string) error {
	a.mu.RLock()
	secret := a.user.TOTPSecret
	a.mu.RUnlock()
	if secret == "" {
		return ErrTOTPNotConfigured
	}
	if !validTOTP(secret, code, a.now()) {
		return ErrTOTPInvalid
	}
	return nil
}

// TOTPEnabled reports whether a TOTP secret is configured.
func (a *AdminManager) TOTPEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.user.TOTPSecret != ""
}

// CurrentUser returns a copy of the administrator identity (including the
// password hash; never send it to the browser unredacted).
func (a *AdminManager) CurrentUser() model.AdminUser {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.user
}

// persist writes the latest administrator state. Callers must not hold a.mu.
func (a *AdminManager) persist() error {
	if a.state == nil {
		return nil
	}
	a.saveMu.Lock()
	defer a.saveMu.Unlock()
	a.mu.RLock()
	user := a.user
	a.mu.RUnlock()
	if err := a.state.Save(user); err != nil {
		return fmt.Errorf("保存面板管理员状态失败: %w", err)
	}
	return nil
}

// loadOrCreateJWTSecret loads the HS256 signing key from path, or generates a
// random 32-byte key and persists it with 0600. An empty path keeps the key
// process-local (sessions do not survive a restart).
func loadOrCreateJWTSecret(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return randomBytes(32)
	}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(data) != 32 {
			return nil, fmt.Errorf("JWT 密钥文件 %s 长度非法（期望 32 字节，实际 %d）；如确认可删除该文件后重启以重新生成", path, len(data))
		}
		secret := make([]byte, 32)
		copy(secret, data)
		return secret, nil
	case errors.Is(err, os.ErrNotExist):
		secret, genErr := randomBytes(32)
		if genErr != nil {
			return nil, fmt.Errorf("生成 JWT 密钥失败: %w", genErr)
		}
		if writeErr := store.WriteFileAtomic(path, secret, 0o600); writeErr != nil {
			return nil, fmt.Errorf("写入 JWT 密钥失败: %w", writeErr)
		}
		return secret, nil
	default:
		return nil, fmt.Errorf("读取 JWT 密钥失败: %w", err)
	}
}

// normalizeSourceIP trims a login source address for use as a limiter key.
func normalizeSourceIP(raw string) string {
	ip := strings.TrimSpace(raw)
	if ip == "" {
		return "unknown"
	}
	return ip
}
