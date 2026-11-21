package panel

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestSecurityHeaders checks the panel security headers required by the API
// contract.
func TestSecurityHeaders(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	resp, data := client.do(http.MethodGet, "/api/v1/overview", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", resp.StatusCode, data)
	}
	wantHeaders := map[string]string{
		"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Cache-Control":           "no-store",
	}
	for name, want := range wantHeaders {
		if got := resp.Header.Get(name); got != want {
			t.Fatalf("%s=%q want %q", name, got, want)
		}
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type=%q", ct)
	}

	// Static responses also carry the security headers (Cache-Control differs).
	resp, data = client.do(http.MethodGet, "/static/app.js", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("asset status=%d body=%s", resp.StatusCode, data)
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("asset X-Frame-Options=%q", got)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got != cspPolicy {
		t.Fatalf("asset CSP=%q", got)
	}
}

// TestStaticAssetsAndSPAFallback checks asset serving and the index fallback.
func TestStaticAssetsAndSPAFallback(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)

	resp, data := client.do(http.MethodGet, "/static/app.js", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("app.js status=%d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Fatalf("app.js Content-Type=%q", ct)
	}
	if !strings.Contains(string(data), "console.log") {
		t.Fatalf("app.js body=%q", data)
	}

	resp, data = client.do(http.MethodGet, "/static/style.css", nil)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/css") {
		t.Fatalf("style.css status=%d ct=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	for _, path := range []string{"/", "/dashboard/nodes", "/some/spa/route?x=1"} {
		resp, data = client.do(http.MethodGet, path, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status=%d", path, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("%s Content-Type=%q", path, ct)
		}
		if !strings.Contains(string(data), "panel") {
			t.Fatalf("%s not index.html: %q", path, data)
		}
	}

	for _, path := range []string{"/static/missing.js", "/static/", "/static", "/static/../index.html"} {
		resp, _ = client.do(http.MethodGet, path, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s status=%d want 404", path, resp.StatusCode)
		}
	}
}

// TestStaticNilWebFS checks the 503 placeholder when no assets are embedded.
func TestStaticNilWebFS(t *testing.T) {
	env := newTestEnvWith(t, testEnvOptions{noWebFS: true})
	client := env.loginClient(t)

	resp, data := client.do(http.MethodGet, "/", nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("index status=%d want 503 body=%s", resp.StatusCode, data)
	}
	resp, data = client.do(http.MethodGet, "/static/app.js", nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("asset status=%d want 503 body=%s", resp.StatusCode, data)
	}
}

// TestUnknownAPIRoutes checks strict 404/405 handling with JSON bodies.
func TestUnknownAPIRoutes(t *testing.T) {
	env := newTestEnv(t)
	client := env.loginClient(t)
	env.addNode("node-a", "alpha", true, nil)

	resp, data := client.do(http.MethodGet, "/api/v1/nodes/node-a/kick", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("kick GET status=%d want 405 body=%s", resp.StatusCode, data)
	}
	if allow := resp.Header.Get("Allow"); !strings.Contains(allow, http.MethodPost) {
		t.Fatalf("Allow header=%q", allow)
	}

	resp, data = client.do(http.MethodGet, "/api/v1/does-not-exist", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown API status=%d want 404 body=%s", resp.StatusCode, data)
	}
	if code := errorCode(t, data); code != "not_found" {
		t.Fatalf("error=%q want not_found", code)
	}

	// Malformed JSON bodies are rejected with 422.
	resp, data = client.do(http.MethodPost, "/api/v1/login", "not-an-object")
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("bad json status=%d want 422 body=%s", resp.StatusCode, data)
	}
	var envelope errorResponse
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if envelope.Error != "validation_failed" || len(envelope.FieldErrors) == 0 {
		t.Fatalf("error envelope=%+v", envelope)
	}

	// A non-API write method is rejected too.
	resp, _ = client.do(http.MethodPost, "/dashboard", nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST /dashboard status=%d want 405", resp.StatusCode)
	}
}
