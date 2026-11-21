package geo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Limits and defaults for server initiated HTTP requests (SSRF chapter E.6).
const (
	maxRemoteURLLength       = 2048
	maxProviderResponseBytes = 64 << 10
	maxRedirects             = 2
	defaultProviderTimeout   = 3 * time.Second
	defaultEgressTimeout     = 2 * time.Second
	defaultDialTimeout       = 5 * time.Second
	defaultUserAgent         = "proxygw-geo/1"
	maxSnippetBytes          = 512
)

// remoteURLPolicy describes how strict URL validation must be. The relaxed
// policy is only ever used when the caller injects an *http.Client, which is a
// test/self-check facility: real deployments always build the secure client
// (https only, no loopback/private targets).
type remoteURLPolicy struct {
	allowHTTP     bool // accept http:// in addition to https://
	allowLoopback bool // accept loopback targets (httptest TLS servers)
}

// cgnatBlock is the RFC 6598 shared address space 100.64.0.0/10, which is not
// flagged as private by net.IP but is also not a public egress target.
var cgnatBlock = &net.IPNet{IP: net.IPv4(100, 64, 0, 0).To4(), Mask: net.CIDRMask(10, 32)}

// blockedIP reports whether a server initiated request must never reach ip:
// loopback, private, link-local (includes the 169.254.169.254 cloud metadata
// endpoint), unspecified, multicast and CGNAT addresses are all rejected.
func blockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4.IsLoopback(), ip4.IsPrivate(), ip4.IsUnspecified(),
			ip4.IsLinkLocalUnicast(), ip4.IsLinkLocalMulticast(),
			ip4.IsMulticast(), ip4.IsInterfaceLocalMulticast():
			return true
		}
		return cgnatBlock.Contains(ip4)
	}
	switch {
	case ip.IsLoopback(), ip.IsPrivate(), ip.IsUnspecified(),
		ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(),
		ip.IsMulticast(), ip.IsInterfaceLocalMulticast():
		return true
	}
	// Cloud metadata IPv6 endpoints live in the ULA space blocked above; keep
	// this explicit check for readability and defence in depth.
	if ip.Equal(net.ParseIP("fd00:ec2::254")) || ip.Equal(net.ParseIP("169.254.169.254")) {
		return true
	}
	return false
}

// newHTTPClient returns the HTTP client used for server initiated requests and
// whether the caller injected it. A nil injected client selects the built-in
// hardened client: no proxy, TLS verification on and an SSRF-checking dialer.
func newHTTPClient(injected *http.Client) (*http.Client, bool) {
	if injected != nil {
		return injected, true
	}
	transport := &http.Transport{
		Proxy:                 nil, // never route server initiated lookups through a proxy
		DialContext:           safeDialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: time.Second,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       90 * time.Second,
	}
	return &http.Client{Transport: transport}, false
}

// safeDialContext resolves the target itself and only dials validated addresses.
// This is the second SSRF layer (after the pre-request check) and also defeats
// DNS rebinding, because the address that was validated is the one dialed.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("ssrf: invalid dial address %q: %w", addr, err)
	}
	ips, err := resolveHostIPs(ctx, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ip := range ips {
		if blockedIP(ip) {
			lastErr = fmt.Errorf("ssrf: blocked dial address %s", ip)
			continue
		}
		dialer := &net.Dialer{Timeout: defaultDialTimeout}
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("ssrf: no usable address for host %q", host)
	}
	return nil, lastErr
}

// resolveHostIPs resolves host to IPs without any SSRF filtering. IP literals
// are returned as-is; hostnames use the system resolver (tests inject their
// resolution results through a custom DialContext / loopback httptest server).
func resolveHostIPs(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("ssrf: resolve host %q: %w", host, err)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP != nil {
			ips = append(ips, addr.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("ssrf: host %q resolved to no usable address", host)
	}
	return ips, nil
}

// validateRemoteURL checks the static rules for a server initiated URL: length
// limit, absolute host, no userinfo, no IPv6 zone, scheme restriction.
func validateRemoteURL(raw string, policy remoteURLPolicy) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("ssrf: empty URL")
	}
	if len(raw) > maxRemoteURLLength {
		return nil, fmt.Errorf("ssrf: URL longer than %d bytes", maxRemoteURLLength)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("ssrf: invalid URL: %w", err)
	}
	if u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("ssrf: URL must contain a host")
	}
	if u.User != nil {
		return nil, errors.New("ssrf: URL must not contain userinfo")
	}
	if strings.Contains(u.Hostname(), "%") {
		return nil, errors.New("ssrf: URL must not contain an IPv6 zone identifier")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !policy.allowHTTP {
			return nil, fmt.Errorf("ssrf: only https URLs are allowed for server initiated requests, got scheme %q", u.Scheme)
		}
	default:
		return nil, fmt.Errorf("ssrf: unsupported URL scheme %q (only https is allowed)", u.Scheme)
	}
	return u, nil
}

// validateResolvedHost resolves the URL host and rejects blocked addresses. The
// check is repeated for every redirect hop so a public URL cannot bounce the
// server into an internal network.
func validateResolvedHost(ctx context.Context, u *url.URL, policy remoteURLPolicy) error {
	if u == nil {
		return errors.New("ssrf: missing URL")
	}
	host := u.Hostname()
	ips, err := resolveHostIPs(ctx, host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if !blockedIP(ip) {
			continue
		}
		if policy.allowLoopback && ip.IsLoopback() {
			continue
		}
		return fmt.Errorf("ssrf: target host %q resolves to blocked address %s (loopback/private/link-local/metadata targets are not allowed)", host, ip)
	}
	return nil
}

// clientWithRedirectGuard returns a shallow copy of base whose redirect policy
// re-runs the full URL + address validation for every hop and enforces the
// maximum of two redirects. The copy is per request, so the shared client is
// never mutated concurrently.
func clientWithRedirectGuard(base *http.Client, policy remoteURLPolicy) *http.Client {
	guarded := *base
	guarded.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return fmt.Errorf("ssrf: too many redirects (maximum %d)", maxRedirects)
		}
		if _, err := validateRemoteURL(req.URL.String(), policy); err != nil {
			return fmt.Errorf("unsafe redirect target: %w", err)
		}
		if err := validateResolvedHost(req.Context(), req.URL, policy); err != nil {
			return fmt.Errorf("unsafe redirect target: %w", err)
		}
		return nil
	}
	return &guarded
}

// readLimitedBody reads at most maxProviderResponseBytes from r and fails when
// the response exceeds the limit (chapter E.6: response cap 64 KiB).
func readLimitedBody(r io.Reader) ([]byte, error) {
	limited := io.LimitReader(r, maxProviderResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if len(data) > maxProviderResponseBytes {
		return nil, fmt.Errorf("response body exceeds the %d byte limit", maxProviderResponseBytes)
	}
	return data, nil
}

// redactURL strips credentials and the query string from a URL before it is put
// into a log line or an error message. Provider tokens only ever live in the
// query string, so this guarantees they never leak.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<invalid-url>"
	}
	u.User = nil
	u.Fragment = ""
	if u.RawQuery != "" || u.ForceQuery {
		u.RawQuery = "redacted=1"
		u.ForceQuery = false
	}
	return u.String()
}

// sanitizeHTTPError renders an HTTP client error without the request URL query
// string (which may contain a provider token).
func sanitizeHTTPError(err error) string {
	if err == nil {
		return ""
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		inner := urlErr.Err
		if inner == nil {
			inner = errors.New("unknown error")
		}
		return fmt.Sprintf("%s %s: %v", urlErr.Op, redactURL(urlErr.URL), inner)
	}
	return err.Error()
}

// scrubSecret removes a secret (for example a provider token) from text before
// it can reach a log line or an operator visible error.
func scrubSecret(text, secret string) string {
	if text == "" || secret == "" {
		return text
	}
	return strings.ReplaceAll(text, secret, "***")
}

// responseSnippet returns at most maxSnippetBytes of a response body for the
// panel "test provider" view, always valid UTF-8.
func responseSnippet(body []byte) string {
	return truncateSnippet(body, maxSnippetBytes)
}

// truncateSnippet returns at most limit bytes of body without splitting a UTF-8
// rune.
func truncateSnippet(body []byte, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(body) > limit {
		body = body[:limit]
	}
	return strings.ToValidUTF8(string(body), "\uFFFD")
}
