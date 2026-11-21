package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"proxygw/internal/model"
)

// JWT session token errors. They are wrapped with details, so callers should use
// errors.Is rather than string comparison.
var (
	// ErrInvalidToken means the token is malformed, signed with the wrong key or
	// algorithm, or otherwise not usable.
	ErrInvalidToken = errors.New("面板令牌无效")
	// ErrExpiredToken means the token signature is valid but the token expired.
	ErrExpiredToken = errors.New("面板令牌已过期")
)

// AdminClaims is the verified content of a panel session token.
type AdminClaims struct {
	Username string
	Expires  time.Time
}

// IssueToken signs a new HS256 panel session token for user. The token carries
// sub (username), iat, exp (now + SessionTTL) and a random jti. The returned
// expiry is exactly the exp claim and can be used for the session cookie.
func (a *AdminManager) IssueToken(user model.AdminUser) (token string, expires time.Time, err error) {
	username := strings.TrimSpace(user.Username)
	if username == "" {
		return "", time.Time{}, fmt.Errorf("签发面板令牌失败：用户名为空")
	}
	now := a.now()
	expires = time.Unix(now.Add(a.sessionTTL).Unix(), 0).UTC()
	jti, err := GeneratePassword(24)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("签发面板令牌失败: %w", err)
	}
	claims := jwt.MapClaims{
		"sub": username,
		"iat": now.Unix(),
		"exp": expires.Unix(),
		"jti": jti,
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("签发面板令牌失败: %w", err)
	}
	return signed, expires, nil
}

// VerifyToken validates the signature, algorithm and expiry of a panel session
// token and returns its claims. Only HS256 is accepted: "none" and any other
// algorithm are rejected. Time validation uses the manager clock.
func (a *AdminManager) VerifyToken(token string) (*AdminClaims, error) {
	raw := strings.TrimSpace(token)
	if raw == "" {
		return nil, fmt.Errorf("%w: 令牌为空", ErrInvalidToken)
	}
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithTimeFunc(a.now),
	)
	parsed, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("不支持的签名算法 %q", t.Method.Alg())
		}
		return a.secret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("%w: %v", ErrExpiredToken, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if parsed == nil || !parsed.Valid {
		return nil, fmt.Errorf("%w: 令牌校验失败", ErrInvalidToken)
	}
	subject, err := claims.GetSubject()
	if err != nil || strings.TrimSpace(subject) == "" {
		return nil, fmt.Errorf("%w: 缺少 sub 声明", ErrInvalidToken)
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return nil, fmt.Errorf("%w: 缺少 exp 声明", ErrInvalidToken)
	}
	if !exp.After(a.now()) {
		return nil, fmt.Errorf("%w: 令牌已过期", ErrExpiredToken)
	}
	return &AdminClaims{Username: subject, Expires: exp.Time.UTC()}, nil
}
