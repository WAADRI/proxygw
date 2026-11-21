package geo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// EgressIP is one egress IP resolution result: the IPv4 and/or IPv6 address,
// which source produced it (manual, peer or echo) and when it was observed.
type EgressIP struct {
	V4        string    `json:"v4,omitempty"`
	V6        string    `json:"v6,omitempty"`
	Source    string    `json:"source,omitempty"` // manual | peer | echo
	UpdatedAt time.Time `json:"updated_at"`
}

// Egress source names as recorded in EgressIP.Source.
const (
	EgressSourceManual = "manual"
	EgressSourcePeer   = "peer"
	EgressSourceEcho   = "echo"
)

// EgressOptions configures an EgressResolver.
type EgressOptions struct {
	// ManualV4 / ManualV6 are the operator configured egress addresses. They
	// always win over detected addresses.
	ManualV4, ManualV6 string
	// EchoURLsV4 / EchoURLsV6 are probed in order for the respective address
	// family; the first URL that yields a valid address of that family wins.
	EchoURLsV4, EchoURLsV6 []string
	// Timeout bounds each individual echo request. Defaults to 2s.
	Timeout time.Duration
	Logger  *slog.Logger
	// HTTPClient is a test injection hook. nil builds the hardened client (no
	// proxy, TLS verification on, SSRF guarded).
	HTTPClient *http.Client
}

// EgressResolver detects node egress IP addresses. It performs no network I/O
// in the constructor and is safe for concurrent use.
type EgressResolver struct {
	manualV4, manualV6 net.IP
	echoV4, echoV6     []string
	timeout            time.Duration
	logger             *slog.Logger
	client             *http.Client
	policy             remoteURLPolicy
	now                func() time.Time
}

// NewEgressResolver builds an egress resolver. Invalid manual addresses are
// logged and ignored (registration must not fail because of a typo); echo
// entries that are not valid URLs are logged and skipped.
func NewEgressResolver(opts EgressOptions) *EgressResolver {
	res := &EgressResolver{
		timeout: opts.Timeout,
		logger:  opts.Logger,
		now:     time.Now,
	}
	if res.timeout <= 0 {
		res.timeout = defaultEgressTimeout
	}
	if res.logger == nil {
		res.logger = slog.Default()
	}
	var injected bool
	res.client, injected = newHTTPClient(opts.HTTPClient)
	if injected {
		// The injected client is only used by tests and panel self-checks; the
		// httptest TLS servers it talks to live on loopback.
		res.policy = remoteURLPolicy{allowHTTP: true, allowLoopback: true}
	}
	if v := strings.TrimSpace(opts.ManualV4); v != "" {
		if ip := net.ParseIP(v); ip != nil && ip.To4() != nil {
			res.manualV4 = ip.To4()
		} else {
			res.logger.Warn("geo: 忽略无效的 manual_v4 出口 IP", "value", v)
		}
	}
	if v := strings.TrimSpace(opts.ManualV6); v != "" {
		if ip := net.ParseIP(v); ip != nil && ip.To4() == nil {
			res.manualV6 = ip
		} else {
			res.logger.Warn("geo: 忽略无效的 manual_v6 出口 IP", "value", v)
		}
	}
	res.echoV4 = res.validEchoURLs(opts.EchoURLsV4, "v4")
	res.echoV6 = res.validEchoURLs(opts.EchoURLsV6, "v6")
	return res
}

// validEchoURLs removes entries that can never be requested under the active
// policy so that misconfiguration is reported once instead of on every node
// registration.
func (e *EgressResolver) validEchoURLs(urls []string, family string) []string {
	out := make([]string, 0, len(urls))
	for _, raw := range urls {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, err := validateRemoteURL(raw, e.policy); err != nil {
			e.logger.Warn("geo: 忽略无效的出口 IP 回声端点", "family", family, "url", redactURL(raw), "error", err)
			continue
		}
		out = append(out, raw)
	}
	return out
}

// Detect resolves the egress IPs with the documented priority
// manual > peer > echo. peerIP must be the real peer address observed by the
// tunnel layer; when the server sits behind a CDN/load balancer the caller is
// responsible for extracting it through PROXY protocol v2 first. Echo probes
// only run for a family that is still unknown after the manual/peer layers, so
// the common case costs no network I/O.
//
// A failure to detect anything returns an error and an empty result; callers
// should register the node anyway (the specification forbids blocking node
// registration on egress detection). Partial detection (only IPv4 or only IPv6)
// is not an error.
func (e *EgressResolver) Detect(ctx context.Context, peerIP net.IP) (EgressIP, error) {
	res := EgressIP{UpdatedAt: e.now().UTC()}
	manualUsed := false
	if e.manualV4 != nil {
		res.V4 = e.manualV4.String()
		manualUsed = true
	}
	if e.manualV6 != nil {
		res.V6 = e.manualV6.String()
		manualUsed = true
	}

	// Peer addresses are used before echo endpoints. A private/loopback peer is
	// not a public egress address (server and node on the same LAN, or a
	// misconfigured PROXY protocol hop); it is kept as a last-resort fallback
	// after the echo layer instead of shadowing a real public address.
	peerUsed := false
	var pendingPeerV4, pendingPeerV6 net.IP
	peer := canonicalIP(peerIP)
	if peer != nil {
		if blockedIP(peer) {
			e.logger.Debug("geo: 隧道对端地址不是公网出口，将在回声失败后作为兜底", "peer_ip", peer.String())
			if peer.To4() != nil {
				if res.V4 == "" {
					pendingPeerV4 = peer
				}
			} else if res.V6 == "" {
				pendingPeerV6 = peer
			}
		} else if peer.To4() != nil {
			if res.V4 == "" {
				res.V4 = peer.String()
				peerUsed = true
			}
		} else if res.V6 == "" {
			res.V6 = peer.String()
			peerUsed = true
		}
	}

	var (
		echoUsed bool
		errs     []error
		mu       sync.Mutex
		wg       sync.WaitGroup
	)
	probe := func(urls []string, wantV6 bool, apply func(string)) {
		defer wg.Done()
		addr, err := e.probeFamily(ctx, urls, wantV6)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, err)
			return
		}
		apply(addr)
		echoUsed = true
	}
	if res.V4 == "" && len(e.echoV4) > 0 {
		wg.Add(1)
		go probe(e.echoV4, false, func(addr string) { res.V4 = addr })
	}
	if res.V6 == "" && len(e.echoV6) > 0 {
		wg.Add(1)
		go probe(e.echoV6, true, func(addr string) { res.V6 = addr })
	}
	wg.Wait()

	// Last resort: fall back to a non-public peer address rather than reporting
	// nothing at all when the node is behind a shared LAN.
	if res.V4 == "" && pendingPeerV4 != nil {
		res.V4 = pendingPeerV4.String()
		peerUsed = true
	}
	if res.V6 == "" && pendingPeerV6 != nil {
		res.V6 = pendingPeerV6.String()
		peerUsed = true
	}

	switch {
	case manualUsed:
		res.Source = EgressSourceManual
	case peerUsed:
		res.Source = EgressSourcePeer
	case echoUsed:
		res.Source = EgressSourceEcho
	}

	if res.V4 == "" && res.V6 == "" {
		if len(errs) > 0 {
			return res, fmt.Errorf("geo: egress IP detection failed: %w", errors.Join(errs...))
		}
		return res, errors.New("geo: egress IP detection failed: no manual IP, no usable peer address and no echo URL configured")
	}
	return res, nil
}

// ServerEgress returns the server's own primary egress IP by probing the echo
// endpoints; the panel "test provider" button uses it when no node IP is given.
// IPv4 is preferred because most geolocation providers only accept IPv4.
func (e *EgressResolver) ServerEgress(ctx context.Context) (string, error) {
	if len(e.echoV4) == 0 && len(e.echoV6) == 0 {
		return "", errors.New("geo: no echo URL configured, cannot determine the server egress IP")
	}
	var (
		v4, v6 string
		errs   []error
		mu     sync.Mutex
		wg     sync.WaitGroup
	)
	if len(e.echoV4) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr, err := e.probeFamily(ctx, e.echoV4, false)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			v4 = addr
		}()
	}
	if len(e.echoV6) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr, err := e.probeFamily(ctx, e.echoV6, true)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			v6 = addr
		}()
	}
	wg.Wait()
	if v4 != "" {
		return v4, nil
	}
	if v6 != "" {
		return v6, nil
	}
	return "", fmt.Errorf("geo: server egress IP detection failed: %w", errors.Join(errs...))
}

// probeFamily walks the URL list in order and returns the first valid address of
// the requested family.
func (e *EgressResolver) probeFamily(ctx context.Context, urls []string, wantV6 bool) (string, error) {
	var errs []error
	for _, raw := range urls {
		ip, err := e.probeOnce(ctx, raw)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if isV6 := ip.To4() == nil; isV6 == wantV6 {
			return ip.String(), nil
		}
		errs = append(errs, fmt.Errorf("%s: returned an address of the unexpected family (%s)", redactURL(raw), ip))
	}
	if len(errs) == 0 {
		return "", errors.New("no echo URL configured")
	}
	return "", errors.Join(errs...)
}

// probeOnce performs one echo request and extracts the first valid IP.
func (e *EgressResolver) probeOnce(ctx context.Context, rawURL string) (net.IP, error) {
	u, err := validateRemoteURL(rawURL, e.policy)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", redactURL(rawURL), err)
	}
	if err := validateResolvedHost(ctx, u, e.policy); err != nil {
		return nil, fmt.Errorf("%s: %w", redactURL(rawURL), err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%s: build request: %w", redactURL(rawURL), err)
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Accept", "text/plain, application/json")
	resp, err := clientWithRedirectGuard(e.client, e.policy).Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", redactURL(rawURL), sanitizeHTTPError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: unexpected HTTP status %d", redactURL(rawURL), resp.StatusCode)
	}
	body, err := readLimitedBody(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", redactURL(rawURL), err)
	}
	text := ExtractIP(body)
	if text == "" {
		return nil, fmt.Errorf("%s: response does not contain a valid IP address", redactURL(rawURL))
	}
	ip := net.ParseIP(text)
	if ip == nil {
		return nil, fmt.Errorf("%s: response contains an invalid IP address", redactURL(rawURL))
	}
	return ip, nil
}

// ExtractIP extracts the first valid IPv4/IPv6 address from an echo response.
// Both documented response shapes are supported without sniffing geolocation
// formats: a JSON object carrying an "ip" field wins, otherwise the first valid
// address in the raw text is used (this also covers the cloudflare trace
// "ip=..." line and plain text endpoints such as icanhazip.com).
func ExtractIP(body []byte) string {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return ""
	}
	if strings.HasPrefix(text, "{") {
		var doc map[string]any
		if err := json.Unmarshal([]byte(text), &doc); err == nil {
			if v, ok := doc["ip"]; ok {
				if s, ok := v.(string); ok {
					if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil && !ip.IsUnspecified() {
						return ip.String()
					}
				}
			}
		}
	}
	return firstIPInText(text)
}

// firstIPInText scans text in order and returns the first token that parses as
// an IP address. IP characters form tokens, so "ip=1.2.3.4" and
// "2001:db8::1" are both found while unrelated numbers are skipped.
func firstIPInText(text string) string {
	start := -1
	for i := 0; i <= len(text); i++ {
		var isTokenChar bool
		if i < len(text) {
			isTokenChar = isIPChar(text[i])
		}
		if isTokenChar && start < 0 {
			start = i
			continue
		}
		if isTokenChar || start < 0 {
			continue
		}
		token := strings.Trim(text[start:i], ".:")
		if token != "" {
			if ip := net.ParseIP(token); ip != nil && !ip.IsUnspecified() {
				return ip.String()
			}
		}
		start = -1
	}
	return ""
}

func isIPChar(c byte) bool {
	switch {
	case c >= '0' && c <= '9':
		return true
	case c >= 'a' && c <= 'f':
		return true
	case c >= 'A' && c <= 'F':
		return true
	case c == ':' || c == '.':
		return true
	}
	return false
}

// canonicalIP normalizes an IP for lookups: nil stays nil, IPv4-mapped IPv6
// addresses become IPv4.
func canonicalIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	if len(ip) == net.IPv6len {
		return ip
	}
	return nil
}
