package panel

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"proxygw/internal/auth"
)

// loginRequest is the POST /api/v1/login body.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTP     string `json:"totp"`
}

// sessionResponse is returned by login and GET /session.
type sessionResponse struct {
	Username    string `json:"username"`
	Expires     string `json:"expires"`
	CSRF        string `json:"csrf"`
	TOTPEnabled bool   `json:"totp_enabled"`
}

// loginDefaultRetrySeconds is the retry hint returned with 429. The auth
// manager owns the real lock window but does not expose the remaining time;
// 60 seconds is a conservative hint for the UI countdown.
const loginDefaultRetrySeconds = 60

// handleLogin authenticates the administrator and issues the JWT + CSRF
// cookies. Login is the only unauthenticated API endpoint.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !s.readJSON(w, r, &req, true, false) {
		return
	}
	username := strings.TrimSpace(req.Username)
	sourceIP := remoteIP(r)

	user, err := s.opts.Admin.Authenticate(username, req.Password, req.TOTP, sourceIP)
	if err != nil {
		s.audit("login", username, username, sourceIP, "failure", map[string]string{
			"reason": loginReason(err),
		})
		switch {
		case errors.Is(err, auth.ErrLockedOut):
			w.Header().Set("Retry-After", "60")
			s.writeJSON(w, http.StatusTooManyRequests, lockedOutResponse{
				Error:             "locked_out",
				Message:           "登录尝试过于频繁或已被临时锁定，请稍后再试",
				RetryAfterSeconds: loginDefaultRetrySeconds,
			})
		case errors.Is(err, auth.ErrTOTPRequired):
			s.writeError(w, http.StatusUnauthorized, "totp_required", "需要输入动态验证码", nil)
		case errors.Is(err, auth.ErrTOTPInvalid):
			s.writeError(w, http.StatusUnauthorized, "invalid_credentials", "动态验证码错误", nil)
		default:
			// ErrInvalidLogin / ErrTOTPInvalid / unexpected: keep the response
			// generic so it does not reveal which factor failed.
			s.writeError(w, http.StatusUnauthorized, "invalid_credentials", "用户名或密码错误", nil)
		}
		s.log.Warn("面板登录失败", "username", username, "source_ip", sourceIP, "reason", loginReason(err))
		return
	}

	token, expires, err := s.opts.Admin.IssueToken(*user)
	if err != nil {
		s.writeInternalError(w, err, "签发登录令牌失败")
		return
	}
	csrf, err := randomToken(32)
	if err != nil {
		s.writeInternalError(w, err, "生成 CSRF 令牌失败")
		return
	}
	s.setAuthCookies(w, r, token, expires, csrf)
	s.audit("login", user.Username, user.Username, sourceIP, "ok", nil)
	s.log.Info("面板登录成功", "username", user.Username, "source_ip", sourceIP)

	s.writeJSON(w, http.StatusOK, sessionResponse{
		Username:    user.Username,
		Expires:     expires.UTC().Format(time.RFC3339),
		CSRF:        csrf,
		TOTPEnabled: s.opts.Admin.TOTPEnabled(),
	})
}

// loginReason maps an authentication error to a machine readable audit reason.
func loginReason(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, auth.ErrLockedOut):
		return "locked_out"
	case errors.Is(err, auth.ErrTOTPRequired):
		return "totp_required"
	case errors.Is(err, auth.ErrTOTPInvalid):
		return "totp_invalid"
	case errors.Is(err, auth.ErrInvalidLogin):
		return "invalid_credentials"
	default:
		return "error"
	}
}

// handleLogout clears both panel cookies.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearAuthCookies(w, r)
	s.auditRequest(r, "logout", "", "ok", nil)
	s.log.Info("面板退出登录", "username", sessionUsername(r), "source_ip", remoteIP(r))
	s.writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleSession returns the current administrator session. It also re-issues
// the CSRF cookie when the browser lost it (for example after a restart).
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromRequest(r)
	if sess == nil {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "未登录或登录已过期", nil)
		return
	}
	csrf := ""
	if cookie, err := r.Cookie(s.csrfCookie); err == nil {
		csrf = cookie.Value
	}
	if csrf == "" {
		fresh, genErr := randomToken(32)
		if genErr != nil {
			s.writeInternalError(w, genErr, "生成 CSRF 令牌失败")
			return
		}
		csrf = fresh
		ttl := s.sessionCookieTTL(sess.Expires)
		http.SetCookie(w, &http.Cookie{
			Name:     s.csrfCookie,
			Value:    csrf,
			Path:     "/",
			MaxAge:   ttl,
			Expires:  sess.Expires.UTC(),
			HttpOnly: false,
			Secure:   cookieSecure(r),
			SameSite: http.SameSiteStrictMode,
		})
	}
	s.writeJSON(w, http.StatusOK, sessionResponse{
		Username:    sess.Username,
		Expires:     sess.Expires.UTC().Format(time.RFC3339),
		CSRF:        csrf,
		TOTPEnabled: s.opts.Admin.TOTPEnabled(),
	})
}

// sessionUsername returns the session username or an empty string.
func sessionUsername(r *http.Request) string {
	if sess := sessionFromRequest(r); sess != nil {
		return sess.Username
	}
	return ""
}
