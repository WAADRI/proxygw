package geo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"proxygw/internal/config"
	"proxygw/internal/model"
)

// Supported preset adapter names (chapter E.3). The response format of every
// preset is fixed and parsed by dedicated code; formats are never sniffed.
const (
	presetIPInfo     = "ipinfo"
	presetIPAPI      = "ip-api"
	presetIPWhois    = "ipwho.is"
	presetCloudflare = "cloudflare"
	presetMMDB       = "mmdb"
)

// Default preset endpoints. Users may override the URL (and token) in the
// provider configuration; "{ip}" is substituted with the node egress IP.
const (
	defaultIPInfoURL            = "https://ipinfo.io/{ip}/json"
	defaultIPAPIURL             = "https://ip-api.com/json/{ip}?fields=status,countryCode,regionName,city,as,isp,query"
	defaultIPWhoisURL           = "https://ipwho.is/{ip}"
	defaultCloudflareTraceURL   = "https://cloudflare.com/cdn-cgi/trace"
	providerFailureThreshold    = 5
	providerMinTimeout          = time.Second
	providerMaxTimeout          = 10 * time.Second
	providerTokenQueryParam     = "token"
	ipAPIKeyQueryParam          = "key"
	maxProviderErrorBodySnippet = 160
)

// supportedRemotePresets lists the built-in adapters usable as online
// providers. "mmdb" is a local layer and handled separately.
var supportedRemotePresets = map[string]bool{
	presetIPInfo:     true,
	presetIPAPI:      true,
	presetIPWhois:    true,
	presetCloudflare: true,
}

// providerKind distinguishes the three provider types.
type providerKind int

const (
	providerKindPreset providerKind = iota
	providerKindTemplate
	providerKindSchema
)

// provider is one online geolocation provider plus its runtime health state.
// mu only protects the small state fields; HTTP I/O is always lock free.
type provider struct {
	cfg       config.ProviderConfig
	kind      providerKind
	preset    string
	order     int
	timeout   time.Duration
	consentOK bool

	mu       sync.Mutex
	enabled  bool
	healthy  bool
	failures int
	lastErr  string
}

// usable reports whether the resolver may call this provider right now.
func (p *provider) usable() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.enabled && p.consentOK && p.healthy
}

// statusSnapshot returns the externally visible provider state.
func (p *provider) statusSnapshot() (enabled, healthy bool, failures int, lastErr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.enabled && p.consentOK, p.healthy, p.failures, p.lastErr
}

// recordSuccess resets the consecutive failure counter.
func (p *provider) recordSuccess() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures = 0
	p.healthy = true
	p.lastErr = ""
}

// recordFailure increments the consecutive failure counter and reports whether
// the configured threshold was crossed on this call (so the caller invokes the
// OnProviderDown hook exactly once).
func (p *provider) recordFailure(err error) (tripped bool, failures int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failures++
	if err != nil {
		p.lastErr = err.Error()
	}
	if p.failures >= providerFailureThreshold && p.healthy {
		p.healthy = false
		return true, p.failures
	}
	return false, p.failures
}

// setEnabled applies an operator decision. Enabling clears the failure counter
// and the auto-removal state; remote providers can never be enabled without
// geo.remote_consent (privacy guarantee).
func (p *provider) setEnabled(enabled bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if enabled {
		if !p.consentOK {
			return fmt.Errorf("geo: provider %q cannot be enabled: geo.remote_consent=false (remote lookups send node IPs to third parties and require explicit consent)", p.cfg.Name)
		}
		p.enabled = true
		p.healthy = true
		p.failures = 0
		p.lastErr = ""
		return nil
	}
	p.enabled = false
	return nil
}

// newRemoteProviders validates and builds the online providers ordered by
// Priority (ascending; the MMDB layer always runs before them regardless of
// prio). Configuration is validated again here defensively so that programmatic
// callers get the same clear errors as the config loader.
func newRemoteProviders(cfg config.GeoConfig, policy remoteURLPolicy, logger *slog.Logger) ([]*provider, error) {
	if logger == nil {
		logger = slog.Default()
	}
	out := make([]*provider, 0, len(cfg.Providers))
	names := make(map[string]int, len(cfg.Providers))
	for i := range cfg.Providers {
		pc := cfg.Providers[i]
		if pc.Type == "preset" && pc.Preset == presetMMDB {
			continue // owned by the local MMDB layer
		}
		if previous, exists := names[pc.Name]; exists {
			return nil, fmt.Errorf("geo.providers[%d].name: duplicate provider name %q (already used by geo.providers[%d])", i, pc.Name, previous)
		}
		p, err := buildRemoteProvider(pc, i, cfg.RemoteConsent, policy, logger)
		if err != nil {
			return nil, err
		}
		names[p.cfg.Name] = i
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].cfg.Priority != out[j].cfg.Priority {
			return out[i].cfg.Priority < out[j].cfg.Priority
		}
		return out[i].order < out[j].order
	})
	return out, nil
}

// buildRemoteProvider validates one provider configuration and prepares its
// runtime state.
func buildRemoteProvider(pc config.ProviderConfig, order int, consent bool, policy remoteURLPolicy, logger *slog.Logger) (*provider, error) {
	prefix := fmt.Sprintf("geo.providers[%d]", order)
	if strings.TrimSpace(pc.Name) == "" {
		return nil, fmt.Errorf("%s.name: must not be empty", prefix)
	}
	prefix = fmt.Sprintf("%s (%q)", prefix, pc.Name)
	p := &provider{
		cfg:       pc,
		order:     order,
		timeout:   defaultProviderTimeout,
		consentOK: consent,
		enabled:   pc.Enabled && consent,
		healthy:   true,
	}
	if !consent && pc.Enabled {
		p.lastErr = "remote provider is configured but geo.remote_consent=false; it will never be called"
	}
	if pc.Timeout != 0 {
		p.timeout = pc.Timeout.Std()
		if p.timeout < providerMinTimeout {
			logger.Warn("geo: provider 超时小于下限，已按 1s 处理", "provider", pc.Name)
			p.timeout = providerMinTimeout
		} else if p.timeout > providerMaxTimeout {
			logger.Warn("geo: provider 超时大于上限，已按 10s 处理", "provider", pc.Name)
			p.timeout = providerMaxTimeout
		}
	}
	switch pc.Type {
	case "preset":
		if !supportedRemotePresets[pc.Preset] {
			return nil, fmt.Errorf("%s.preset: unknown preset %q (supported online presets: ipinfo, ip-api, ipwho.is, cloudflare)", prefix, pc.Preset)
		}
		p.kind = providerKindPreset
		p.preset = pc.Preset
		raw := strings.TrimSpace(pc.URL)
		if raw == "" {
			raw = presetDefaultURL(pc.Preset)
		}
		if err := validateProviderURL(raw, policy); err != nil {
			return nil, fmt.Errorf("%s.url: %w", prefix, err)
		}
	case "template":
		p.kind = providerKindTemplate
		if strings.TrimSpace(pc.URL) == "" {
			return nil, fmt.Errorf("%s.url: template provider requires a URL", prefix)
		}
		if len(pc.Fields) == 0 {
			return nil, fmt.Errorf("%s.fields: template provider requires at least one field mapping", prefix)
		}
		fields := make(map[string]string, len(pc.Fields))
		for field, mapping := range pc.Fields {
			if !validGeoFieldName(field) {
				return nil, fmt.Errorf("%s.fields: unsupported field %q (supported: country, region, city, asn, asn_org, isp)", prefix, field)
			}
			mapping = strings.TrimSpace(mapping)
			switch {
			case mapping == "":
				return nil, fmt.Errorf("%s.fields.%s: mapping must not be empty", prefix, field)
			case strings.HasPrefix(mapping, "regex:"):
				pattern := strings.TrimPrefix(mapping, "regex:")
				if pattern == "" {
					return nil, fmt.Errorf("%s.fields.%s: empty regex pattern", prefix, field)
				}
				if _, err := regexp.Compile(pattern); err != nil {
					return nil, fmt.Errorf("%s.fields.%s: invalid regex: %w", prefix, field, err)
				}
			case strings.HasPrefix(mapping, "$."):
			default:
				// Bare paths ("data.country") are accepted for convenience; the
				// config validator normally requires the "$." prefix.
				mapping = "$." + mapping
			}
			fields[field] = mapping
		}
		p.cfg.Fields = fields
		if err := validateProviderURL(pc.URL, policy); err != nil {
			return nil, fmt.Errorf("%s.url: %w", prefix, err)
		}
	case "schema":
		p.kind = providerKindSchema
		if strings.TrimSpace(pc.URL) == "" {
			return nil, fmt.Errorf("%s.url: schema provider requires a URL", prefix)
		}
		if err := validateProviderURL(pc.URL, policy); err != nil {
			return nil, fmt.Errorf("%s.url: %w", prefix, err)
		}
	default:
		return nil, fmt.Errorf("%s.type: must be preset, template or schema, got %q", prefix, pc.Type)
	}
	if len(p.cfg.Headers) > 0 {
		headers := make(map[string]string, len(p.cfg.Headers))
		for k, v := range p.cfg.Headers {
			if strings.TrimSpace(k) == "" {
				return nil, fmt.Errorf("%s.headers: empty header name", prefix)
			}
			headers[k] = v
		}
		p.cfg.Headers = headers
	}
	return p, nil
}

// validateProviderURL statically validates a provider URL template. Placeholders
// are substituted with sample values first so the URL parser sees a real URL.
func validateProviderURL(raw string, policy remoteURLPolicy) error {
	sample := strings.ReplaceAll(raw, "{ip}", "198.51.100.7")
	sample = strings.ReplaceAll(sample, "{token}", "sample-token")
	_, err := validateRemoteURL(sample, policy)
	return err
}

// presetDefaultURL returns the documented default endpoint of a preset.
func presetDefaultURL(preset string) string {
	switch preset {
	case presetIPInfo:
		return defaultIPInfoURL
	case presetIPAPI:
		return defaultIPAPIURL
	case presetIPWhois:
		return defaultIPWhoisURL
	case presetCloudflare:
		return defaultCloudflareTraceURL
	}
	return ""
}

// buildProviderTargetURL renders the final request URL for one provider and IP,
// substituting {ip}/{token} and appending the token as a query parameter when
// needed. Tokens only ever appear in the query string, never in logs.
func buildProviderTargetURL(p *provider, ip net.IP) (string, error) {
	ipText := ip.String()
	raw := strings.TrimSpace(p.cfg.URL)
	if raw == "" {
		raw = presetDefaultURL(p.preset)
	}
	if raw == "" {
		return "", errors.New("no URL configured")
	}
	if strings.Contains(raw, "{ip}") {
		raw = strings.ReplaceAll(raw, "{ip}", ipText)
	} else if p.kind == providerKindPreset {
		withIP, err := appendIPPath(raw, p.preset, ipText)
		if err != nil {
			return "", err
		}
		raw = withIP
	}
	token := strings.TrimSpace(p.cfg.Token)
	if token != "" {
		if strings.Contains(raw, "{token}") {
			raw = strings.ReplaceAll(raw, "{token}", url.QueryEscape(token))
		} else {
			u, err := url.Parse(raw)
			if err != nil {
				// Sanitize: the raw URL may already carry a token in its query.
				return "", fmt.Errorf("invalid provider URL: %s", sanitizeHTTPError(err))
			}
			param := providerTokenParam(p)
			query := u.Query()
			if query.Get(param) == "" {
				query.Set(param, token)
				u.RawQuery = query.Encode()
			}
			raw = u.String()
		}
	}
	return raw, nil
}

// appendIPPath implements the documented "URL without {ip}" behavior of the
// preset adapters: ipinfo gets "/{ip}/json", the other adapters get "/{ip}".
func appendIPPath(raw, preset, ipText string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid provider URL: %s", sanitizeHTTPError(err))
	}
	if u.Host == "" {
		return "", errors.New("provider URL must contain a host")
	}
	base := strings.TrimRight(u.Path, "/")
	switch preset {
	case presetIPInfo:
		u.Path = base + "/" + ipText + "/json"
	case presetIPAPI, presetIPWhois:
		u.Path = base + "/" + ipText
	default:
		return raw, nil
	}
	u.RawPath = ""
	return u.String(), nil
}

// providerTokenParam selects the query parameter carrying the provider token.
func providerTokenParam(p *provider) string {
	if p.kind == providerKindPreset && p.preset == presetIPAPI {
		return ipAPIKeyQueryParam
	}
	return providerTokenQueryParam
}

// fetchProvider performs one guarded HTTP GET for a provider and returns the
// response body (<=64 KiB) plus the measured duration. All SSRF checks are
// applied before the request and repeated for redirect hops.
func (r *Resolver) fetchProvider(ctx context.Context, p *provider, ip net.IP) ([]byte, time.Duration, error) {
	target, err := buildProviderTargetURL(p, ip)
	if err != nil {
		return nil, 0, fmt.Errorf("geo: provider %q: %w", p.cfg.Name, err)
	}
	u, err := validateRemoteURL(target, r.policy)
	if err != nil {
		return nil, 0, fmt.Errorf("geo: provider %q: %w", p.cfg.Name, err)
	}
	if err := validateResolvedHost(ctx, u, r.policy); err != nil {
		return nil, 0, fmt.Errorf("geo: provider %q: %w", p.cfg.Name, err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("geo: provider %q: build request: %w", p.cfg.Name, err)
	}
	req.Header.Set("User-Agent", defaultUserAgent)
	req.Header.Set("Accept", "application/json, text/plain;q=0.9, */*;q=0.1")
	for name, value := range p.cfg.Headers {
		req.Header.Set(name, value)
	}
	start := time.Now()
	resp, err := clientWithRedirectGuard(r.client, r.policy).Do(req)
	duration := time.Since(start)
	if err != nil {
		return nil, duration, fmt.Errorf("geo: provider %q: request failed: %s", p.cfg.Name, sanitizeHTTPError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Return the (limited) error body as well so the panel test view can show
		// the raw response snippet of a misbehaving endpoint.
		body, readErr := readLimitedBody(resp.Body)
		if readErr != nil {
			body = nil
		}
		snippet := ""
		if len(body) > 0 {
			// A misbehaving endpoint may echo the request URL (and therefore the
			// token) in its error body; scrub it before it reaches the log.
			snippet = scrubSecret(truncateSnippet(body, maxProviderErrorBodySnippet), p.cfg.Token)
		}
		if snippet != "" {
			return body, duration, fmt.Errorf("geo: provider %q: unexpected HTTP status %d: %s", p.cfg.Name, resp.StatusCode, snippet)
		}
		return body, duration, fmt.Errorf("geo: provider %q: unexpected HTTP status %d", p.cfg.Name, resp.StatusCode)
	}
	body, err := readLimitedBody(resp.Body)
	if err != nil {
		return nil, duration, fmt.Errorf("geo: provider %q: %w", p.cfg.Name, err)
	}
	return body, duration, nil
}

// parseProviderBody dispatches to the fixed parser of the provider type. The
// returned hit paths are recorded per field for the panel test button.
func (p *provider) parseProviderBody(body []byte) (model.Geo, map[string]string, error) {
	var (
		geo      model.Geo
		hitPaths map[string]string
		err      error
	)
	switch p.kind {
	case providerKindPreset:
		geo, hitPaths, err = parsePresetBody(p.preset, body)
	case providerKindTemplate:
		geo, hitPaths, err = ApplyTemplateFields(body, p.cfg.Fields)
	case providerKindSchema:
		geo, hitPaths, err = parseSchemaProviderBody(body)
	default:
		return model.Geo{}, nil, fmt.Errorf("unsupported provider kind")
	}
	if err != nil {
		return model.Geo{}, nil, fmt.Errorf("geo: provider %q: %w", p.cfg.Name, err)
	}
	geo = normalizeGeoFields(geo)
	if err := validateGeoFields(geo); err != nil {
		return model.Geo{}, nil, fmt.Errorf("geo: provider %q: %w", p.cfg.Name, err)
	}
	return geo, hitPaths, nil
}

// parseSchemaProviderBody wraps ParseSchema and derives the hit paths from the
// populated fields.
func parseSchemaProviderBody(body []byte) (model.Geo, map[string]string, error) {
	geo, err := ParseSchema(body)
	if err != nil {
		return model.Geo{}, nil, err
	}
	hitPaths := map[string]string{}
	if geo.Country != "" {
		hitPaths[geoFieldCountry] = "$." + geoFieldCountry
	}
	if geo.Region != "" {
		hitPaths[geoFieldRegion] = "$." + geoFieldRegion
	}
	if geo.City != "" {
		hitPaths[geoFieldCity] = "$." + geoFieldCity
	}
	if geo.ASN > 0 {
		hitPaths[geoFieldASN] = "$." + geoFieldASN
	}
	if geo.ASNOrg != "" {
		hitPaths[geoFieldASNOrg] = "$." + geoFieldASNOrg
	}
	if geo.ISP != "" {
		hitPaths[geoFieldISP] = "$." + geoFieldISP
	}
	return geo, hitPaths, nil
}

// finishProviderGeo normalizes and validates a parsed provider result so every
// adapter rejects clearly wrong values (for example a country name in the
// two-letter country field) instead of showing bad geolocation data.
func finishProviderGeo(providerName string, geo model.Geo, hitPaths map[string]string) (model.Geo, map[string]string, error) {
	geo = normalizeGeoFields(geo)
	if err := validateGeoFields(geo); err != nil {
		return model.Geo{}, nil, fmt.Errorf("%s: %w", providerName, err)
	}
	return geo, hitPaths, nil
}

// parsePresetBody dispatches to the fixed parser of a preset adapter.
func parsePresetBody(preset string, body []byte) (model.Geo, map[string]string, error) {
	switch preset {
	case presetIPInfo:
		return parseIPInfoBody(body)
	case presetIPAPI:
		return parseIPAPIBody(body)
	case presetIPWhois:
		return parseIPWhoisBody(body)
	case presetCloudflare:
		return parseCloudflareTrace(body)
	default:
		return model.Geo{}, nil, fmt.Errorf("unsupported preset %q", preset)
	}
}

// ipinfoResponse is the fixed response shape of ipinfo.io/.../json (unknown
// fields are ignored by the decoder).
type ipinfoResponse struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
	Org     string `json:"org"`
	Bogon   bool   `json:"bogon"`
	Error   *struct {
		Title   string `json:"title"`
		Message string `json:"message"`
	} `json:"error"`
}

func parseIPInfoBody(body []byte) (model.Geo, map[string]string, error) {
	var wire ipinfoResponse
	if err := json.Unmarshal(body, &wire); err != nil {
		return model.Geo{}, nil, fmt.Errorf("ipinfo: response is not valid JSON (unexpected format): %w", err)
	}
	if wire.Error != nil {
		return model.Geo{}, nil, fmt.Errorf("ipinfo: API error: %s: %s", wire.Error.Title, wire.Error.Message)
	}
	if wire.Bogon {
		return model.Geo{}, nil, errors.New("ipinfo: address is a bogon (reserved/private) address")
	}
	geo := model.Geo{Country: wire.Country, Region: wire.Region, City: wire.City}
	hitPaths := map[string]string{}
	if geo.Country != "" {
		hitPaths[geoFieldCountry] = "country"
	}
	if geo.Region != "" {
		hitPaths[geoFieldRegion] = "region"
	}
	if geo.City != "" {
		hitPaths[geoFieldCity] = "city"
	}
	if org := strings.TrimSpace(wire.Org); org != "" {
		asn, orgName := splitASNOrg(org)
		if asn > 0 {
			geo.ASN = asn
			hitPaths[geoFieldASN] = "org"
		}
		if orgName != "" {
			geo.ASNOrg = orgName
			hitPaths[geoFieldASNOrg] = "org"
		}
	}
	if geo.IsZero() {
		return model.Geo{}, nil, errors.New("ipinfo: response did not contain any known field (unexpected response format)")
	}
	return finishProviderGeo("ipinfo", geo, hitPaths)
}

// ipAPIResponse is the fixed response shape of ip-api.com with the documented
// fields query parameter.
type ipAPIResponse struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	CountryCode string `json:"countryCode"`
	RegionName  string `json:"regionName"`
	City        string `json:"city"`
	AS          string `json:"as"`
	ISP         string `json:"isp"`
	Query       string `json:"query"`
}

func parseIPAPIBody(body []byte) (model.Geo, map[string]string, error) {
	var wire ipAPIResponse
	if err := json.Unmarshal(body, &wire); err != nil {
		return model.Geo{}, nil, fmt.Errorf("ip-api: response is not valid JSON (unexpected format): %w", err)
	}
	if wire.Status == "" {
		return model.Geo{}, nil, errors.New("ip-api: response does not contain a status field (unexpected response format)")
	}
	if wire.Status != "success" {
		return model.Geo{}, nil, fmt.Errorf("ip-api: API status is %q: %s", wire.Status, wire.Message)
	}
	geo := model.Geo{Country: wire.CountryCode, Region: wire.RegionName, City: wire.City, ISP: wire.ISP}
	hitPaths := map[string]string{}
	if geo.Country != "" {
		hitPaths[geoFieldCountry] = "countryCode"
	}
	if geo.Region != "" {
		hitPaths[geoFieldRegion] = "regionName"
	}
	if geo.City != "" {
		hitPaths[geoFieldCity] = "city"
	}
	if geo.ISP != "" {
		hitPaths[geoFieldISP] = "isp"
	}
	if asText := strings.TrimSpace(wire.AS); asText != "" {
		asn, orgName := splitASNOrg(asText)
		if asn > 0 {
			geo.ASN = asn
			hitPaths[geoFieldASN] = "as"
		}
		if orgName != "" {
			geo.ASNOrg = orgName
			hitPaths[geoFieldASNOrg] = "as"
		}
	}
	if geo.IsZero() {
		return model.Geo{}, nil, errors.New("ip-api: response did not contain any known field (unexpected response format)")
	}
	return finishProviderGeo("ip-api", geo, hitPaths)
}

// ipWhoisResponse is the fixed response shape of ipwho.is/{ip}.
type ipWhoisResponse struct {
	Success     bool   `json:"success"`
	Message     string `json:"message"`
	CountryCode string `json:"country_code"`
	Region      string `json:"region"`
	City        string `json:"city"`
	Connection  struct {
		ASN json.RawMessage `json:"asn"`
		Org string          `json:"org"`
		ISP string          `json:"isp"`
	} `json:"connection"`
}

func parseIPWhoisBody(body []byte) (model.Geo, map[string]string, error) {
	var wire ipWhoisResponse
	if err := json.Unmarshal(body, &wire); err != nil {
		return model.Geo{}, nil, fmt.Errorf("ipwho.is: response is not valid JSON (unexpected format): %w", err)
	}
	if !wire.Success {
		message := strings.TrimSpace(wire.Message)
		if message == "" {
			message = "response does not contain success=true (unexpected response format)"
		}
		return model.Geo{}, nil, fmt.Errorf("ipwho.is: API returned success=false: %s", message)
	}
	geo := model.Geo{
		Country: wire.CountryCode,
		Region:  wire.Region,
		City:    wire.City,
		ASNOrg:  wire.Connection.Org,
		ISP:     wire.Connection.ISP,
	}
	hitPaths := map[string]string{}
	if geo.Country != "" {
		hitPaths[geoFieldCountry] = "country_code"
	}
	if geo.Region != "" {
		hitPaths[geoFieldRegion] = "region"
	}
	if geo.City != "" {
		hitPaths[geoFieldCity] = "city"
	}
	if geo.ASNOrg != "" {
		hitPaths[geoFieldASNOrg] = "connection.org"
	}
	if geo.ISP != "" {
		hitPaths[geoFieldISP] = "connection.isp"
	}
	if asnRaw := strings.TrimSpace(string(wire.Connection.ASN)); asnRaw != "" && asnRaw != "null" {
		var asnValue any
		dec := json.NewDecoder(strings.NewReader(asnRaw))
		dec.UseNumber()
		if err := dec.Decode(&asnValue); err != nil {
			return model.Geo{}, nil, fmt.Errorf("ipwho.is: invalid connection.asn: %w", err)
		}
		asn, err := asnFromAny(asnValue)
		if err != nil {
			return model.Geo{}, nil, fmt.Errorf("ipwho.is: invalid connection.asn: %w", err)
		}
		geo.ASN = asn
		hitPaths[geoFieldASN] = "connection.asn"
	}
	if geo.IsZero() {
		return model.Geo{}, nil, errors.New("ipwho.is: response did not contain any known field (unexpected response format)")
	}
	return finishProviderGeo("ipwho.is", geo, hitPaths)
}

// parseCloudflareTrace parses the cloudflare /cdn-cgi/trace text response. The
// trace endpoint does not geolocate a passed IP (it reports the caller), so
// only the country field is derived from the "loc=" line; this limitation is
// intentional and documented.
func parseCloudflareTrace(body []byte) (model.Geo, map[string]string, error) {
	values := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	loc := model.NormalizeCountry(values["loc"])
	if loc == "" {
		return model.Geo{}, nil, errors.New("cloudflare trace: response does not contain a loc= line (unexpected response format)")
	}
	return finishProviderGeo("cloudflare trace", model.Geo{Country: loc}, map[string]string{geoFieldCountry: "loc"})
}
