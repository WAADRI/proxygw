package panel

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestLoginSetsCookiesAndCSRF checks the login response body and both cookies.
func TestLoginSetsCookiesAndCSRF(t *testing.T) {
	env := newTestEnv(t)
	// Raw client without a cookie jar so the Set-Cookie headers can be inspected.
	raw := env.newAPIClient(t)
	raw.http.Jar = nil

	resp, data := raw.do(http.MethodPost, "/api/v1/login", map[string]string{
		"username": "admin",
		"password": testPassword,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", resp.StatusCode, data)
	}
	var session sessionResponse
	if err := json.Unmarshal(data, &session); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if session.Username != "admin" {
		t.Fatalf("username=%q", session.Username)
	}
	if session.CSRF == "" || len(session.CSRF) < 20 {
		t.Fatalf("csrf token looks invalid: %q", session.CSRF)
	}
	if session.TOTPEnabled {
		t.Fatalf("TOTP should be disabled in the default test env")
	}
	if _, err := time.Parse(time.RFC3339, session.Expires); err != nil {
		t.Fatalf("expires=%q: %v", session.Expires, err)
	}

	cookies := map[string]*http.Cookie{}
	for _, cookie := range resp.Cookies() {
		cookies[cookie.Name] = cookie
	}
	sessionCookie, ok := cookies[defaultSessionCookie]
	if !ok {
		t.Fatalf("missing %s cookie, got %v", defaultSessionCookie, resp.Cookies())
	}
	if !sessionCookie.HttpOnly {
		t.Fatalf("session cookie must be HttpOnly")
	}
	if sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie SameSite=%v want Strict", sessionCookie.SameSite)
	}
	if sessionCookie.Path != "/" {
		t.Fatalf("session cookie Path=%q", sessionCookie.Path)
	}
	if sessionCookie.MaxAge <= 0 {
		t.Fatalf("session cookie MaxAge=%d", sessionCookie.MaxAge)
	}
	if strings.TrimSpace(sessionCookie.Value) == "" {
		t.Fatalf("empty session cookie value")
	}
	csrfCookie, ok := cookies[defaultCSRFCookie]
	if !ok {
		t.Fatalf("missing %s cookie", defaultCSRFCookie)
	}
	if csrfCookie.HttpOnly {
		t.Fatalf("CSRF cookie must not be HttpOnly")
	}
	if csrfCookie.Value != session.CSRF {
		t.Fatalf("csrf cookie=%q response=%q", csrfCookie.Value, session.CSRF)
	}
	if csrfCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("csrf cookie SameSite=%v", csrfCookie.SameSite)
	}
}

// TestLoginWrongPassword checks the generic 401 response.
func TestLoginWrongPassword(t *testing.T) {
	env := newTestEnv(t)
	client := env.newAPIClient(t)
	resp, data := client.do(http.MethodPost, "/api/v1/login", map[string]string{
		"username": "admin",
		"password": "definitely-wrong",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, data)
	}
	if code := errorCode(t, data); code != "invalid_credentials" {
		t.Fatalf("error=%q want invalid_credentials (%s)", code, data)
	}
}

// TestLoginLockedOut checks the 429 mapping after the failure threshold.
func TestLoginLockedOut(t *testing.T) {
	env := newTestEnvWith(t, testEnvOptions{lockThreshold: 2})
	client := env.newAPIClient(t)
	bad := map[string]string{"username": "admin", "password": "nope"}

	resp, data := client.do(http.MethodPost, "/api/v1/login", bad)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("first failure status=%d body=%s", resp.StatusCode, data)
	}
	resp, data = client.do(http.MethodPost, "/api/v1/login", bad)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second failure status=%d want 429 body=%s", resp.StatusCode, data)
	}
	var locked lockedOutResponse
	if err := json.Unmarshal(data, &locked); err != nil {
		t.Fatalf("decode locked_out: %v", err)
	}
	if locked.Error != "locked_out" {
		t.Fatalf("error=%q want locked_out", locked.Error)
	}
	if locked.RetryAfterSeconds <= 0 {
		t.Fatalf("retry_after_seconds=%d", locked.RetryAfterSeconds)
	}
	if got := resp.Header.Get("Retry-After"); got == "" {
		t.Fatalf("missing Retry-After header")
	}
}

// TestLoginTOTPRequired checks the TOTP challenge branch.
func TestLoginTOTPRequired(t *testing.T) {
	env := newTestEnvWith(t, testEnvOptions{totpSecret: "JBSWY3DPEHPK3PXP"})
	client := env.newAPIClient(t)

	resp, data := client.do(http.MethodPost, "/api/v1/login", map[string]string{
		"username": "admin", "password": testPassword,
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, data)
	}
	if code := errorCode(t, data); code != "totp_required" {
		t.Fatalf("error=%q want totp_required (%s)", code, data)
	}

	// A wrong TOTP code must stay a generic credential failure.
	resp, data = client.do(http.MethodPost, "/api/v1/login", map[string]string{
		"username": "admin", "password": testPassword, "totp": "000000",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad totp status=%d want 401 body=%s", resp.StatusCode, data)
	}
	if code := errorCode(t, data); code != "invalid_credentials" {
		t.Fatalf("bad totp error=%q want invalid_credentials (%s)", code, data)
	}
}

// TestUnauthorizedAPI checks that missing/invalid session cookies get 401 JSON.
func TestUnauthorizedAPI(t *testing.T) {
	env := newTestEnv(t)
	client := env.newAPIClient(t)

	resp, data := client.do(http.MethodGet, "/api/v1/overview", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, data)
	}
	if code := errorCode(t, data); code != "unauthorized" {
		t.Fatalf("error=%q want unauthorized", code)
	}

	// A forged cookie value must also be rejected.
	req, _ := http.NewRequest(http.MethodGet, env.url("/api/v1/session"), nil)
	req.AddCookie(&http.Cookie{Name: defaultSessionCookie, Value: "not-a-jwt"})
	client2 := &http.Client{Timeout: 5 * time.Second}
	resp, err := client2.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged cookie status=%d want 401", resp.StatusCode)
	}
}

// TestSessionEndpoint checks GET /session returns the current identity and CSRF.
func TestSessionEndpoint(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	var session sessionResponse
	if status := client.doJSON(http.MethodGet, "/api/v1/session", nil, &session); status != http.StatusOK {
		t.Fatalf("session status=%d", status)
	}
	if session.Username != "admin" {
		t.Fatalf("username=%q", session.Username)
	}
	if session.CSRF != client.csrf {
		t.Fatalf("session csrf=%q want %q", session.CSRF, client.csrf)
	}
	if _, err := time.Parse(time.RFC3339, session.Expires); err != nil {
		t.Fatalf("expires=%q: %v", session.Expires, err)
	}
}

// TestLogoutClearsCookies checks logout clears both cookies and invalidates the
// session.
func TestLogoutClearsCookies(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	resp, data := client.do(http.MethodPost, "/api/v1/logout", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status=%d body=%s", resp.StatusCode, data)
	}
	var ok map[string]bool
	if err := json.Unmarshal(data, &ok); err != nil || !ok["ok"] {
		t.Fatalf("logout body=%s err=%v", data, err)
	}
	cleared := map[string]bool{}
	for _, cookie := range resp.Cookies() {
		if cookie.MaxAge < 0 || cookie.Value == "" {
			cleared[cookie.Name] = true
		}
	}
	if !cleared[defaultSessionCookie] || !cleared[defaultCSRFCookie] {
		t.Fatalf("cookies not cleared: %v", resp.Cookies())
	}

	// The cookie jar dropped the session; the API must be unauthorized now.
	status := client.doJSON(http.MethodGet, "/api/v1/session", nil, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("session after logout status=%d want 401", status)
	}
}

// TestCSRFProtection checks the double-submit validation on write requests.
func TestCSRFProtection(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)
	group := map[string]string{"name": "csrf-group"}

	validCSRF := client.csrf

	client.csrf = ""
	resp, data := client.do(http.MethodPost, "/api/v1/groups", group)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing csrf header status=%d want 403 body=%s", resp.StatusCode, data)
	}
	if code := errorCode(t, data); code != "csrf_invalid" {
		t.Fatalf("error=%q want csrf_invalid", code)
	}

	client.csrf = "wrong-token"
	resp, data = client.do(http.MethodPost, "/api/v1/groups", group)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong csrf header status=%d want 403 body=%s", resp.StatusCode, data)
	}

	client.csrf = validCSRF
	client.mustStatus(http.MethodPost, "/api/v1/groups", group, http.StatusOK)

	// GET requests don't need a CSRF token.
	client.csrf = ""
	client.mustStatus(http.MethodGet, "/api/v1/groups", nil, http.StatusOK)
}
