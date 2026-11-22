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
	"sync/atomic"
	"time"

	"proxygw/internal/config"
	"proxygw/internal/metrics"
	"proxygw/internal/model"
)

// Options configures a Resolver.
type Options struct {
	// Config is the geo section of the server configuration. It has already
	// been validated by the config layer; the resolver repeats the important
	// checks defensively.
	Config config.GeoConfig
	Logger *slog.Logger
	// Metrics is optional (nil disables metric collection).
	Metrics *metrics.Metrics
	// HTTPClient is a test injection hook. nil builds the hardened client used
	// in production (https only, no proxy, TLS verification, SSRF guarded).
	HTTPClient *http.Client
	// Now is a clock injection hook; nil uses time.Now.
	Now func() time.Time
	// OnProviderDown is called exactly once when an online provider is removed
	// from rotation after providerFailureThreshold consecutive failures. It is
	// meant for alerting/webhooks and must not block.
	OnProviderDown func(name, reason string)
}

// ProviderStatus is the panel visible runtime state of one provider. Preset and
// Priority are additive fields used by the panel provider table
// (GET /geo/providers) even though the core resolution contract only needs the
// other fields.
type ProviderStatus struct {
	Name      string `json:"name"`
	Type      string `json:"type"`   // preset | template | schema
	Preset    string `json:"preset"` // preset adapter name (preset providers, including the local mmdb)
	Enabled   bool   `json:"enabled"`
	Healthy   bool   `json:"healthy"`
	Failures  int    `json:"failures"`
	LastError string `json:"last_error,omitempty"`
	Priority  int    `json:"priority"` // configured priority; the local MMDB always runs first regardless
}

// ProviderTest is the result of a panel "test provider" invocation.
type ProviderTest struct {
	Provider   string            `json:"provider"`
	IP         string            `json:"ip"`
	RawSnippet string            `json:"raw_snippet"`
	Result     model.Geo         `json:"result"`
	DurationMS float64           `json:"duration_ms"`
	HitPaths   map[string]string `json:"hit_paths,omitempty"`
	Error      string            `json:"error,omitempty"`
}

// Resolver enriches IP addresses with geolocation/ASN metadata. The local MMDB
// is the primary layer; online providers (opt-in via Config.RemoteConsent) only
// fill missing fields. Results are cached for Config.CacheTTL (24h default) and
// concurrent lookups of the same IP are coalesced. The resolver never runs on
// the proxy request hot path: callers invoke it on node registration or when an
// egress IP changes.
//
// The Resolver is safe for concurrent use.
type Resolver struct {
	cfg            config.GeoConfig
	log            *slog.Logger
	metrics        *metrics.Metrics
	now            func() time.Time
	onProviderDown func(name, reason string)

	client   *http.Client
	injected bool
	policy   remoteURLPolicy

	mmdb      *mmdbLayer
	providers []*provider

	cache   *geoCache
	flights *flightGroup
	rate    *tokenBucket
	slots   chan struct{}

	egress *EgressResolver

	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
}

// New builds a geolocation Resolver.
//
// A missing/corrupt MMDB file is NOT fatal: a warning is logged, the provider
// status shows MMDB unavailable and Resolve falls back to online providers or
// returns an empty Geo (the panel renders "unknown") with a nil error, so node
// registration is never blocked by geolocation. Remote provider configuration is
// validated again defensively even though the config layer already did it.
func New(opts Options) (*Resolver, error) {
	r := &Resolver{
		cfg:            opts.Config,
		log:            opts.Logger,
		metrics:        opts.Metrics,
		now:            opts.Now,
		onProviderDown: opts.OnProviderDown,
	}
	if r.log == nil {
		r.log = slog.Default()
	}
	if r.now == nil {
		r.now = time.Now
	}
	r.client, r.injected = newHTTPClient(opts.HTTPClient)
	if r.injected {
		// Injected clients only exist in tests / panel self-checks: loopback
		// httptest servers must be reachable while private/metadata targets stay
		// blocked (the SSRF tests rely on that).
		r.policy = remoteURLPolicy{allowHTTP: true, allowLoopback: true}
	}
	r.cache = newGeoCache(defaultCacheEntries, r.cacheTTL(), r.now)
	r.flights = newFlightGroup()
	r.egress = NewEgressResolver(EgressOptions{
		EchoURLsV4: r.cfg.Egress.EchoURLsV4,
		EchoURLsV6: r.cfg.Egress.EchoURLsV6,
		Timeout:    r.cfg.Egress.Timeout.Std(),
		Logger:     r.log,
		HTTPClient: opts.HTTPClient,
	})
	if !r.cfg.Enabled {
		r.log.Info("geo: 归属地解析已禁用（geo.enabled=false）")
		return r, nil
	}
	// The local MMDB provider entries are handled by initMMDB, so validate their
	// names here (the remote provider builder validates the rest defensively).
	for i, pc := range r.cfg.Providers {
		if pc.Type == "preset" && pc.Preset == presetMMDB && strings.TrimSpace(pc.Name) == "" {
			return nil, fmt.Errorf("geo.providers[%d].name: must not be empty", i)
		}
	}
	r.initMMDB()
	providers, err := newRemoteProviders(r.cfg, r.policy, r.log)
	if err != nil {
		_ = r.mmdb.close()
		return nil, err
	}
	if r.mmdb != nil {
		for _, p := range providers {
			if r.mmdb.hasName(p.cfg.Name) {
				_ = r.mmdb.close()
				return nil, fmt.Errorf("geo: provider name %q conflicts with the local MMDB provider", p.cfg.Name)
			}
		}
	}
	r.providers = providers
	maxConcurrent := r.cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrent
	}
	r.slots = make(chan struct{}, maxConcurrent)
	r.rate = newTokenBucket(r.cfg.RatePerMin)
	if len(providers) > 0 && !r.cfg.RemoteConsent {
		r.log.Warn("geo: 已配置在线 provider 但 geo.remote_consent=false，远程查询被禁用（节点 IP 不会发送给第三方）")
	}
	return r, nil
}

// cacheTTL returns the effective cache lifetime.
func (r *Resolver) cacheTTL() time.Duration {
	if ttl := r.cfg.CacheTTL.Std(); ttl > 0 {
		return ttl
	}
	return defaultCacheTTL
}

// initMMDB opens the local MMDB when configured. Failures only warn; the layer
// stays in the status list as unhealthy.
func (r *Resolver) initMMDB() {
	path := strings.TrimSpace(r.cfg.MMDBPath)
	var names []string
	priority := 0
	for _, pc := range r.cfg.Providers {
		if pc.Type == "preset" && pc.Preset == presetMMDB {
			if len(names) == 0 {
				priority = pc.Priority
			}
			names = append(names, pc.Name)
		}
	}
	if path == "" && len(names) == 0 {
		return
	}
	if path == "" {
		r.log.Warn("geo: 配置了 preset=mmdb 但 geo.mmdb_path 为空，MMDB 主层不可用")
	}
	if len(names) == 0 {
		names = []string{presetMMDB}
	}
	layer := newMMDBLayer(path, names, priority, r.cfg.MMDBNameLanguage)
	r.mmdb = layer
	if _, healthy, _, lastErr := layer.statusSnapshot(); !healthy {
		r.log.Warn("geo: MMDB 不可用，归属地将回退到在线 provider 或显示 unknown（服务继续启动）", "path", path, "error", lastErr)
	}
}

// Resolve enriches one node egress IP. It returns a Geo with per-field sources;
// fields that no provider could supply are left empty (the panel shows
// "unknown"). Provider failures do not fail Resolve: they are counted, logged,
// exposed through ProviderStatuses and may remove the provider from rotation
// after providerFailureThreshold consecutive failures. A nil Geo with a nil
// error therefore means "no geolocation data available", not failure.
func (r *Resolver) Resolve(ctx context.Context, ip net.IP) (model.Geo, error) {
	if r == nil {
		return model.Geo{}, errors.New("geo: nil resolver")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	canonical := canonicalIP(ip)
	if canonical == nil {
		return model.Geo{}, fmt.Errorf("geo: invalid IP address %v", ip)
	}
	if r.closed.Load() {
		return model.Geo{}, errResolverClosed
	}
	if !r.cfg.Enabled {
		return model.Geo{}, nil
	}
	key := canonical.String()
	if geo, ok := r.cache.get(key); ok {
		r.observeMetrics("cache", resultHit, 0)
		return geo, nil
	}
	return r.flights.do(ctx, key, func() (model.Geo, error) {
		if geo, ok := r.cache.get(key); ok {
			return geo, nil
		}
		return r.lookup(ctx, canonical)
	})
}

// ResolveBatch resolves a set of IPs concurrently (bounded by the provider
// concurrency limit, so it does not stampede a remote endpoint). The result map
// is keyed by the canonical IP string.
func (r *Resolver) ResolveBatch(ctx context.Context, ips []net.IP) map[string]model.Geo {
	out := make(map[string]model.Geo, len(ips))
	if r == nil || len(ips) == 0 {
		return out
	}
	if ctx == nil {
		ctx = context.Background()
	}
	unique := make(map[string]net.IP, len(ips))
	for _, ip := range ips {
		if canonical := canonicalIP(ip); canonical != nil {
			unique[canonical.String()] = canonical
		}
	}
	if len(unique) == 0 {
		return out
	}
	workers := len(unique)
	if workers > 8 {
		workers = 8
	}
	jobs := make(chan net.IP)
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				geo, err := r.Resolve(ctx, ip)
				if err != nil {
					continue
				}
				mu.Lock()
				out[ip.String()] = geo
				mu.Unlock()
			}
		}()
	}
feed:
	for _, ip := range unique {
		select {
		case jobs <- ip:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	return out
}

// lookup performs the layered resolution for one IP: MMDB first, then online
// providers in Priority order filling only missing fields.
func (r *Resolver) lookup(ctx context.Context, ip net.IP) (model.Geo, error) {
	now := r.now().UTC()
	result := model.Geo{Sources: make(map[string]model.FieldSource), UpdatedAt: now}

	if r.mmdb != nil && r.mmdb.isEnabled() {
		start := time.Now()
		geo, _, err := r.mmdb.lookup(ip)
		duration := time.Since(start)
		if err != nil {
			// The local layer is not counted as a provider failure (only a
			// missing/corrupt file can cause this and that is reported through
			// ProviderStatuses); log once per lookup at debug level.
			r.log.Debug("geo: MMDB 查询未命中或不可用", "ip", ip.String(), "error", err)
			r.observeMetrics(r.mmdb.primaryName(), resultError, duration)
		} else {
			r.observeMetrics(r.mmdb.primaryName(), resultSuccess, duration)
			if !geo.IsZero() {
				r.merge(&result, geo, r.mmdb.primaryName(), now)
			}
		}
	}

	providerErrors := 0
	for _, p := range r.providers {
		if ctx.Err() != nil {
			break
		}
		if !hasMissingFields(&result) {
			break
		}
		if !p.usable() {
			continue
		}
		if err := r.rate.wait(ctx); err != nil {
			r.log.Debug("geo: rate limiter stopped provider lookups", "error", err)
			break
		}
		if err := r.acquireProviderSlot(ctx); err != nil {
			r.log.Debug("geo: concurrency limiter stopped provider lookups", "error", err)
			break
		}
		call, callErr := r.callProvider(ctx, p, ip)
		r.releaseProviderSlot()
		duration := call.duration
		if callErr != nil {
			providerErrors++
			r.observeMetrics(p.cfg.Name, resultError, duration)
			r.log.Warn("geo: 在线 provider 查询失败", "provider", p.cfg.Name, "error", callErr)
			if tripped, failures := p.recordFailure(callErr); tripped {
				reason := fmt.Sprintf("连续失败 %d 次后自动摘除: %v", failures, callErr)
				r.log.Error("geo: 在线 provider 连续失败，已自动摘除并告警", "provider", p.cfg.Name, "failures", failures)
				if r.onProviderDown != nil {
					r.onProviderDown(p.cfg.Name, reason)
				}
			}
			continue
		}
		p.recordSuccess()
		r.observeMetrics(p.cfg.Name, resultSuccess, duration)
		r.merge(&result, call.geo, p.cfg.Name, now)
	}

	if result.IsZero() {
		// Unknown region: not an error for node registration. The panel shows
		// "unknown" and ProviderStatuses explains why (MMDB missing, consent
		// off, providers unhealthy, ...).
		r.log.Debug("geo: 无归属地数据", "ip", ip.String(), "provider_errors", providerErrors)
		return model.Geo{}, nil
	}
	result.UpdatedAt = now
	r.cache.set(ip.String(), result)
	return result, nil
}

// callProvider fetches and parses one provider response. The raw body is kept
// for the panel test button; the resolver itself only uses the parsed Geo.
func (r *Resolver) callProvider(ctx context.Context, p *provider, ip net.IP) (providerCallResult, error) {
	body, duration, err := r.fetchProvider(ctx, p, ip)
	call := providerCallResult{raw: body, duration: duration}
	if err != nil {
		return call, err
	}
	geo, hitPaths, err := p.parseProviderBody(body)
	if err != nil {
		return call, err
	}
	call.geo = geo
	call.hitPaths = hitPaths
	return call, nil
}

// providerCallResult is the outcome of one provider request.
type providerCallResult struct {
	geo      model.Geo
	hitPaths map[string]string
	raw      []byte
	duration time.Duration
}

// merge fills every still-missing field of dst from src. Fields already provided
// by a higher-priority source are never overwritten (partial fill). The last
// provider that contributed is recorded in Geo.Provider and every filled field
// records its source and fetch time.
func (r *Resolver) merge(dst *model.Geo, src model.Geo, source string, now time.Time) bool {
	src = normalizeGeoFields(src)
	if dst.Sources == nil {
		dst.Sources = make(map[string]model.FieldSource)
	}
	contributed := false
	record := func(field string) {
		dst.Sources[field] = model.FieldSource{Source: source, FetchedAt: now}
		contributed = true
	}
	if dst.Country == "" && src.Country != "" {
		dst.Country = src.Country
		record(geoFieldCountry)
	}
	if dst.Region == "" && src.Region != "" {
		dst.Region = src.Region
		record(geoFieldRegion)
	}
	if dst.City == "" && src.City != "" {
		dst.City = src.City
		record(geoFieldCity)
	}
	if dst.ASN == 0 && src.ASN > 0 {
		dst.ASN = src.ASN
		record(geoFieldASN)
	}
	if dst.ASNOrg == "" && src.ASNOrg != "" {
		dst.ASNOrg = src.ASNOrg
		record(geoFieldASNOrg)
	}
	if dst.ISP == "" && src.ISP != "" {
		dst.ISP = src.ISP
		record(geoFieldISP)
	}
	if !contributed {
		return false
	}
	dst.Provider = source
	return true
}

// hasMissingFields reports whether any geolocation field is still empty.
func hasMissingFields(geo *model.Geo) bool {
	return geo.Country == "" || geo.Region == "" || geo.City == "" ||
		geo.ASN == 0 || geo.ASNOrg == "" || geo.ISP == ""
}

// ProviderStatuses returns a snapshot of every provider (local MMDB first, then
// online providers in Priority order).
func (r *Resolver) ProviderStatuses() []ProviderStatus {
	if r == nil {
		return nil
	}
	var out []ProviderStatus
	if r.mmdb != nil {
		enabled, healthy, failures, lastErr := r.mmdb.statusSnapshot()
		for _, name := range r.mmdb.names {
			out = append(out, ProviderStatus{
				Name:      name,
				Type:      "preset",
				Preset:    presetMMDB,
				Enabled:   enabled,
				Healthy:   healthy,
				Failures:  failures,
				LastError: lastErr,
				Priority:  r.mmdb.priority,
			})
		}
	}
	// providers is immutable after New, so iterating it without a lock is fine.
	for _, p := range r.providers {
		enabled, healthy, failures, lastErr := p.statusSnapshot()
		out = append(out, ProviderStatus{
			Name:      p.cfg.Name,
			Type:      providerTypeName(p),
			Preset:    providerPresetName(p),
			Enabled:   enabled,
			Healthy:   healthy,
			Failures:  failures,
			LastError: lastErr,
			Priority:  p.cfg.Priority,
		})
	}
	return out
}

// providerPresetName returns the preset adapter name for preset providers.
func providerPresetName(p *provider) string {
	if p.kind == providerKindPreset {
		return p.preset
	}
	return ""
}

// providerTypeName renders the configured provider type.
func providerTypeName(p *provider) string {
	switch p.kind {
	case providerKindPreset:
		return "preset"
	case providerKindTemplate:
		return "template"
	case providerKindSchema:
		return "schema"
	default:
		return "unknown"
	}
}

// SetProviderEnabled applies an operator decision to one provider. Enabling a
// provider that was automatically removed clears its failure counter and health
// state; a remote provider can never be enabled while geo.remote_consent=false.
func (r *Resolver) SetProviderEnabled(name string, enabled bool) error {
	if r == nil {
		return errors.New("geo: nil resolver")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("geo: provider name must not be empty")
	}
	if r.mmdb != nil && r.mmdb.hasName(name) {
		return r.mmdb.setEnabled(enabled)
	}
	for _, p := range r.providers {
		if p.cfg.Name == name {
			return p.setEnabled(enabled)
		}
	}
	return fmt.Errorf("geo: unknown provider %q", name)
}

// findProvider looks up an online provider by name.
func (r *Resolver) findProvider(name string) *provider {
	for _, p := range r.providers {
		if p.cfg.Name == name {
			return p
		}
	}
	return nil
}

// TestProvider performs one real lookup for the panel "test provider" button and
// returns the raw response snippet (<=512 bytes), the parsed result, the duration
// in milliseconds, the field paths that produced values and a clear error. It
// reports an error only for an unknown/empty provider name or invalid input; DNS,
// SSRF, HTTP and parse failures are reported in ProviderTest.Error so the panel
// can show them. The automatic failure counter is intentionally not touched: a
// manual test must neither trip nor reset the breaker.
func (r *Resolver) TestProvider(ctx context.Context, name string, ip net.IP) (result *ProviderTest, err error) {
	if r == nil {
		return nil, errors.New("geo: nil resolver")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("geo: provider name must not be empty")
	}
	// Last line of defence: the panel endpoint must never panic because of this
	// package.
	defer func() {
		if recovered := recover(); recovered != nil {
			result = &ProviderTest{Provider: name, Error: fmt.Sprintf("internal panic: %v", recovered)}
			err = nil
		}
	}()

	test := &ProviderTest{Provider: name, HitPaths: make(map[string]string)}
	if canonical := canonicalIP(ip); canonical != nil {
		ip = canonical
		test.IP = canonical.String()
	} else {
		// No node IP given: use a server egress echo lookup, as the panel does.
		serverIP, egressErr := r.serverEgress(ctx)
		if egressErr != nil {
			test.Error = "cannot determine a test IP: " + egressErr.Error()
			return test, nil
		}
		ip = net.ParseIP(serverIP)
		test.IP = serverIP
	}

	if r.mmdb != nil && r.mmdb.hasName(name) {
		start := time.Now()
		geo, hitPaths, lookupErr := r.mmdb.lookup(ip)
		test.DurationMS = durationMS(time.Since(start))
		if len(hitPaths) > 0 {
			test.HitPaths = hitPaths
		}
		if lookupErr != nil {
			test.Error = lookupErr.Error()
			return test, nil
		}
		test.Result = NormalizeGeo(geo, name)
		if !geo.IsZero() {
			test.RawSnippet = compactJSONSnippet(geo)
		}
		return test, nil
	}

	p := r.findProvider(name)
	if p == nil {
		return nil, fmt.Errorf("geo: unknown provider %q", name)
	}
	if !p.consentOK {
		test.Error = "在线 provider 未启用：geo.remote_consent=false 时不会向第三方发送节点 IP；请先显式启用远程查询"
		return test, nil
	}
	if err := r.rate.wait(ctx); err != nil {
		test.Error = "rate limiter: " + err.Error()
		return test, nil
	}
	if err := r.acquireProviderSlot(ctx); err != nil {
		test.Error = "concurrency limiter: " + err.Error()
		return test, nil
	}
	call, callErr := r.callProvider(ctx, p, ip)
	r.releaseProviderSlot()
	test.DurationMS = durationMS(call.duration)
	test.RawSnippet = responseSnippet(call.raw)
	if len(call.hitPaths) > 0 {
		test.HitPaths = call.hitPaths
	}
	test.Result = NormalizeGeo(call.geo, name)
	if callErr != nil {
		test.Error = callErr.Error()
	}
	return test, nil
}

// serverEgress returns the server's own egress IP via the echo endpoints.
func (r *Resolver) serverEgress(ctx context.Context) (string, error) {
	if r.egress == nil {
		return "", errors.New("server egress resolver is not configured")
	}
	return r.egress.ServerEgress(ctx)
}

// Close releases the MMDB handle. It is idempotent and safe to call while
// lookups are in flight (they fail with errResolverClosed afterwards).
func (r *Resolver) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.closed.Store(true)
		if r.mmdb != nil {
			r.closeErr = r.mmdb.close()
		}
	})
	return r.closeErr
}

// observeMetrics records one provider lookup (nil-safe: the metrics package is
// optional).
func (r *Resolver) observeMetrics(provider, result string, duration time.Duration) {
	if r == nil || r.metrics == nil {
		return
	}
	if r.metrics.GeoLookupsTotal != nil {
		r.metrics.GeoLookupsTotal.WithLabelValues(provider, result).Inc()
	}
	if r.metrics.GeoLookupDuration != nil && duration > 0 {
		r.metrics.GeoLookupDuration.WithLabelValues(provider).Observe(duration.Seconds())
	}
}

// durationMS renders a duration as floating point milliseconds.
func durationMS(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000.0
}

// compactJSONSnippet renders a Geo as compact JSON for the local MMDB test view
// (the MMDB has no raw HTTP response).
func compactJSONSnippet(geo model.Geo) string {
	encoded, err := json.Marshal(geo)
	if err != nil {
		return ""
	}
	return responseSnippet(encoded)
}

// Metric result label values.
const (
	resultSuccess = "success"
	resultError   = "error"
	resultHit     = "hit"
)
