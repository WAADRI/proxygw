// Package model holds the data structures shared by the server, the node
// client, the panel and the persistence layer. All persisted objects carry
// id/created_at/updated_at as required by the specification.
package model

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that marshals as a human friendly string such as
// "10m" in YAML and JSON. Both encodings also accept integer nanoseconds.
type Duration time.Duration

// D is a shorthand constructor.
func D(d time.Duration) Duration { return Duration(d) }

// Std returns the standard library representation.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// String implements fmt.Stringer.
func (d Duration) String() string { return time.Duration(d).String() }

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		return d.parse(s)
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("duration: expected string or integer, got %s", string(b))
	}
	*d = Duration(time.Duration(n))
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		return d.parse(s)
	}
	var n int64
	if err := unmarshal(&n); err != nil {
		return fmt.Errorf("duration: expected string or integer")
	}
	*d = Duration(time.Duration(n))
	return nil
}

// UnmarshalText implements encoding.TextUnmarshaler (environment variables).
func (d *Duration) UnmarshalText(b []byte) error { return d.parse(string(b)) }

func (d *Duration) parse(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// Protocol names used by the proxy entry points and ACL matching.
const (
	ProtoHTTP    = "http"    // plain HTTP proxy request
	ProtoConnect = "connect" // HTTP CONNECT
	ProtoSOCKS5  = "socks5"
	ProtoTCP     = "tcp"
)

// ACL actions.
const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

// Breaker states (与状态机设计第 5 章一致).
const (
	BreakerClosed   = "closed"
	BreakerOpen     = "open"
	BreakerHalfOpen = "half_open"
)

// Route strategies.
const (
	StrategyRandom        = "random"
	StrategyLeastInflight = "least_inflight"
	StrategyFastest       = "fastest"
	StrategyWeighted      = "weighted"
)

// Auth modes for the proxy entry points.
const (
	AuthNone     = "none"
	AuthOptional = "optional"
	AuthRequired = "required"
)

// Transport selection values.
const (
	TransportAuto = "auto"
	TransportQUIC = "quic"
	TransportWS   = "ws"
)

// FieldSource records where one geolocation field came from.
type FieldSource struct {
	Source    string    `json:"source"`
	FetchedAt time.Time `json:"fetched_at"`
}

// EgressIP holds the node egress addresses and where they came from
// (peer, echo or manual).
type EgressIP struct {
	V4        string    `json:"v4,omitempty" yaml:"v4"`
	V6        string    `json:"v6,omitempty" yaml:"v6"`
	Source    string    `json:"source,omitempty" yaml:"source"`
	UpdatedAt time.Time `json:"updated_at,omitempty" yaml:"updated_at"`
}

// Geo is the normalized geolocation/ASN metadata of a node egress address.
type Geo struct {
	Country   string                 `json:"country,omitempty"` // ISO 3166-1 alpha-2, upper case
	Region    string                 `json:"region,omitempty"`
	City      string                 `json:"city,omitempty"`
	ASN       int                    `json:"asn,omitempty"` // integer, "AS15169" -> 15169
	ASNOrg    string                 `json:"asn_org,omitempty"`
	ISP       string                 `json:"isp,omitempty"`
	Provider  string                 `json:"provider,omitempty"` // last provider that contributed
	UpdatedAt time.Time              `json:"updated_at,omitempty"`
	Sources   map[string]FieldSource `json:"sources,omitempty"` // key: country|region|city|asn|asn_org|isp
}

// IsZero reports whether no geolocation field is populated.
func (g Geo) IsZero() bool {
	return g.Country == "" && g.Region == "" && g.City == "" && g.ASN == 0 && g.ASNOrg == "" && g.ISP == ""
}

// Node is the runtime view of one node, aggregated over its transport planes.
type Node struct {
	ID            string    `json:"id"`
	Alias         string    `json:"alias,omitempty"`
	Region        string    `json:"region,omitempty"`    // manual label overrides detected region
	ISPLabel      string    `json:"isp_label,omitempty"` // manual label overrides detected ISP
	Tags          []string  `json:"tags,omitempty"`
	Weight        int       `json:"weight"`
	Enabled       bool      `json:"enabled"`
	Online        bool      `json:"online"`
	EgressIP      EgressIP  `json:"egress_ip"`
	Geo           Geo       `json:"geo"`
	Inflight      int64     `json:"inflight"`
	BytesIn       uint64    `json:"bytes_in"`
	BytesOut      uint64    `json:"bytes_out"`
	LatencyEWMA   float64   `json:"latency_ewma_ms"`
	BreakerState  string    `json:"breaker_state"`
	LastHeartbeat time.Time `json:"last_heartbeat,omitempty"`
	FirstSeen     time.Time `json:"first_seen,omitempty"`
	Version       string    `json:"version,omitempty"`
	Groups        []string  `json:"groups,omitempty"`
	Transport     string    `json:"transport,omitempty"`
	Planes        int       `json:"planes"`
	// Capabilities are the protocol capabilities advertised by the node in
	// HELLO (for example "zstd", "dns", "probe").
	Capabilities []string `json:"capabilities,omitempty"`
	// Compression reports whether the node agreed to zstd stream compression.
	Compression bool      `json:"compression,omitempty"`
	DuplicateOf string    `json:"duplicate_of,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// EffectiveRegion returns the manual region label when set.
func (n *Node) EffectiveRegion() string {
	if n.Region != "" {
		return n.Region
	}
	return n.Geo.Region
}

// EffectiveISP returns the manual ISP label when set.
func (n *Node) EffectiveISP() string {
	if n.ISPLabel != "" {
		return n.ISPLabel
	}
	return n.Geo.ISP
}

// NodeOverride is the persisted subset of node fields that operators can edit.
type NodeOverride struct {
	ID        string    `json:"id"`
	Alias     string    `json:"alias,omitempty"`
	Region    string    `json:"region,omitempty"`
	ISPLabel  string    `json:"isp_label,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	Weight    int       `json:"weight"`
	Enabled   bool      `json:"enabled"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GroupMatch selects nodes by tags and/or regions.
type GroupMatch struct {
	TagsAny    []string `json:"tags_any,omitempty" yaml:"tags_any"`
	RegionsAny []string `json:"regions_any,omitempty" yaml:"regions_any"`
}

// Group is a node pool. Membership = (selector ∪ nodes_add) − nodes_remove.
type Group struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Match       GroupMatch `json:"match"`
	NodesAdd    []string   `json:"nodes_add,omitempty"`
	NodesRemove []string   `json:"nodes_remove,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Matches reports whether the node is selected by the group selector. An empty
// selector matches nothing: groups built only from explicit node lists must not
// silently include every node.
func (g *Group) Matches(n *Node) bool {
	if len(g.Match.TagsAny) == 0 && len(g.Match.RegionsAny) == 0 {
		return false
	}
	if len(g.Match.TagsAny) > 0 {
		hit := false
		for _, want := range g.Match.TagsAny {
			for _, have := range n.Tags {
				if strings.EqualFold(strings.TrimSpace(have), strings.TrimSpace(want)) {
					hit = true
					break
				}
			}
			if hit {
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(g.Match.RegionsAny) > 0 {
		hit := false
		region := strings.ToUpper(n.EffectiveRegion())
		country := strings.ToUpper(n.Geo.Country)
		for _, want := range g.Match.RegionsAny {
			w := strings.ToUpper(strings.TrimSpace(want))
			if w == region || w == country || w == strings.ToUpper(n.Region) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// Contains reports whether the group explicitly lists the node.
func (g *Group) Contains(nodeID string) bool {
	for _, id := range g.NodesAdd {
		if id == nodeID {
			return true
		}
	}
	return false
}

// Excluded reports whether the group explicitly removes the node.
func (g *Group) Excluded(nodeID string) bool {
	for _, id := range g.NodesRemove {
		if id == nodeID {
			return true
		}
	}
	return false
}

// Credential is one proxy account. PasswordHash is never exposed by the API.
type Credential struct {
	ID               string     `json:"id"`
	Username         string     `json:"username"`
	PasswordHash     string     `json:"password_hash"`
	Groups           []string   `json:"groups,omitempty"` // empty = all groups
	Enabled          bool       `json:"enabled"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	MaxConcurrent    int        `json:"max_concurrent"` // 0 = unlimited
	BandwidthKbps    int        `json:"bandwidth_kbps"` // 0 = unlimited
	AllowedProtocols []string   `json:"allowed_protocols,omitempty"`
	SourceCIDRs      []string   `json:"source_cidrs,omitempty"`
	Note             string     `json:"note,omitempty"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	BytesIn          uint64     `json:"bytes_in"`
	BytesOut         uint64     `json:"bytes_out"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// Redacted returns a copy safe for API responses and logs.
func (c Credential) Redacted() Credential {
	c.PasswordHash = ""
	return c
}

// TargetSpec describes destination selectors for sticky rules: any match hits.
type TargetSpec struct {
	CIDRs   []string `json:"cidrs,omitempty"`
	Domains []string `json:"domains,omitempty"` // exact, suffix (*.bank.com) or wildcard
}

// StickyRule keeps a target out of session stickiness. Any dimension match
// (target, node group or explicit node) disables pinning for the request.
type StickyRule struct {
	ID         string     `json:"id"`
	Enabled    bool       `json:"enabled"`
	Note       string     `json:"note,omitempty"`
	Target     TargetSpec `json:"target"`
	NodeGroups []string   `json:"node_groups,omitempty"`
	NodeIDs    []string   `json:"node_ids,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// ACLRule is one ordered access control rule.
type ACLRule struct {
	ID        string    `json:"id"`
	Order     int       `json:"order"`
	SrcCIDRs  []string  `json:"src_cidrs,omitempty"`
	Domains   []string  `json:"domains,omitempty"`
	Ports     []string  `json:"ports,omitempty"` // single ports and ranges, e.g. "443", "8000-9000"
	Protocols []string  `json:"protocols,omitempty"`
	Action    string    `json:"action"` // allow | deny
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BreakerSettings configures the per-node circuit breaker.
type BreakerSettings struct {
	FailureThreshold int      `json:"failure_threshold" yaml:"failure_threshold"` // consecutive failures to open
	FailureRate      float64  `json:"failure_rate" yaml:"failure_rate"`           // 0-1, opens at/above rate
	MinSamples       int      `json:"min_samples" yaml:"min_samples"`             // minimum samples for rate rule
	OpenTimeout      Duration `json:"open_timeout" yaml:"open_timeout"`
}

// StickySettings configures session affinity.
type StickySettings struct {
	Enabled        bool     `json:"enabled" yaml:"enabled"`
	TTL            Duration `json:"ttl" yaml:"ttl"`
	MaxKeysPerNode int      `json:"max_keys_per_node" yaml:"max_keys_per_node"`
}

// RetrySettings configures transparent retry before the response commit point.
type RetrySettings struct {
	Enabled     bool `json:"enabled" yaml:"enabled"`
	MaxAttempts int  `json:"max_attempts" yaml:"max_attempts"` // total attempts including the first
}

// SchedulerSettings bundles routing knobs.
type SchedulerSettings struct {
	Strategy string          `json:"strategy" yaml:"strategy"`
	Sticky   StickySettings  `json:"sticky" yaml:"sticky"`
	Breaker  BreakerSettings `json:"breaker" yaml:"breaker"`
	Retry    RetrySettings   `json:"retry" yaml:"retry"`
}

// LimitsSettings configures bandwidth and concurrency caps.
type LimitsSettings struct {
	GlobalDownKbps        int `json:"global_down_kbps" yaml:"global_down_kbps"` // 0 = unlimited
	PerNodeDownKbps       int `json:"per_node_down_kbps" yaml:"per_node_down_kbps"`
	PerCredentialDownKbps int `json:"per_credential_down_kbps" yaml:"per_credential_down_kbps"`
	MaxStreamsPerNode     int `json:"max_streams_per_node" yaml:"max_streams_per_node"`
}

// TimeoutSettings contains every entry of the timeout table that is operator
// configurable (fixed entries live in code constants).
type TimeoutSettings struct {
	Open        Duration `json:"open" yaml:"open"`
	ReadHeader  Duration `json:"read_header" yaml:"read_header"`
	Idle        Duration `json:"idle" yaml:"idle"`
	WriteBlock  Duration `json:"write_block" yaml:"write_block"`
	Linger      Duration `json:"linger" yaml:"linger"`
	Drain       Duration `json:"drain" yaml:"drain"`
	WindowStall Duration `json:"window_stall" yaml:"window_stall"`
	DialTarget  Duration `json:"dial_target" yaml:"dial_target"` // node -> target TCP dial
}

// Settings is the hot-reloadable runtime configuration that is persisted to
// runtime-overrides.json and can be changed from the panel.
type Settings struct {
	Scheduler        SchedulerSettings `json:"scheduler" yaml:"scheduler"`
	Limits           LimitsSettings    `json:"limits" yaml:"limits"`
	Timeouts         TimeoutSettings   `json:"timeouts" yaml:"timeouts"`
	Compression      bool              `json:"compression_enabled" yaml:"compression_enabled"`
	DefaultACLAction string            `json:"default_acl_action" yaml:"default_acl_action"` // allow | deny
}

// DefaultSettings returns the specification defaults.
func DefaultSettings() Settings {
	return Settings{
		Scheduler: SchedulerSettings{
			Strategy: StrategyFastest,
			Sticky: StickySettings{
				Enabled:        true,
				TTL:            D(10 * time.Minute),
				MaxKeysPerNode: 1000,
			},
			Breaker: BreakerSettings{
				FailureThreshold: 5,
				FailureRate:      0.5,
				MinSamples:       20,
				OpenTimeout:      D(30 * time.Second),
			},
			Retry: RetrySettings{Enabled: true, MaxAttempts: 2},
		},
		Limits: LimitsSettings{
			MaxStreamsPerNode: 1000,
		},
		Timeouts: TimeoutSettings{
			Open:        D(10 * time.Second),
			ReadHeader:  D(10 * time.Second),
			Idle:        D(30 * time.Minute),
			WriteBlock:  D(30 * time.Second),
			Linger:      D(30 * time.Second),
			Drain:       D(10 * time.Second),
			WindowStall: D(30 * time.Second),
			DialTarget:  D(10 * time.Second),
		},
		Compression:      false,
		DefaultACLAction: ActionAllow,
	}
}

// Validate checks the runtime settings for internal consistency.
func (s Settings) Validate() error {
	switch s.Scheduler.Strategy {
	case StrategyRandom, StrategyLeastInflight, StrategyFastest, StrategyWeighted:
	default:
		return fmt.Errorf("scheduler.strategy: unsupported strategy %q", s.Scheduler.Strategy)
	}
	if s.Scheduler.Sticky.TTL <= 0 {
		return fmt.Errorf("scheduler.sticky.ttl: must be > 0")
	}
	if s.Scheduler.Sticky.MaxKeysPerNode <= 0 {
		return fmt.Errorf("scheduler.sticky.max_keys_per_node: must be > 0")
	}
	b := s.Scheduler.Breaker
	if b.FailureThreshold <= 0 || b.OpenTimeout <= 0 {
		return fmt.Errorf("scheduler.breaker: failure_threshold and open_timeout must be > 0")
	}
	if b.FailureRate <= 0 || b.FailureRate > 1 {
		return fmt.Errorf("scheduler.breaker.failure_rate: must be in (0,1]")
	}
	if b.MinSamples <= 0 {
		return fmt.Errorf("scheduler.breaker.min_samples: must be > 0")
	}
	r := s.Scheduler.Retry
	if r.MaxAttempts < 1 || r.MaxAttempts > 3 {
		return fmt.Errorf("scheduler.retry.max_attempts: must be 1..3")
	}
	if s.Limits.MaxStreamsPerNode <= 0 {
		return fmt.Errorf("limits.max_streams_per_node: must be > 0")
	}
	for name, d := range map[string]Duration{
		"timeouts.open": s.Timeouts.Open, "timeouts.read_header": s.Timeouts.ReadHeader,
		"timeouts.idle": s.Timeouts.Idle, "timeouts.write_block": s.Timeouts.WriteBlock,
		"timeouts.linger": s.Timeouts.Linger, "timeouts.drain": s.Timeouts.Drain,
		"timeouts.window_stall": s.Timeouts.WindowStall, "timeouts.dial_target": s.Timeouts.DialTarget,
	} {
		if d <= 0 {
			return fmt.Errorf("%s: must be > 0", name)
		}
	}
	switch s.DefaultACLAction {
	case ActionAllow, ActionDeny:
	default:
		return fmt.Errorf("default_acl_action: must be allow or deny")
	}
	return nil
}

// RequestTarget describes one proxy request after parsing the entry protocol.
type RequestTarget struct {
	Protocol   string `json:"protocol"` // http | connect | socks5
	Host       string `json:"host"`     // hostname or IP literal
	Port       int    `json:"port"`
	SourceIP   string `json:"source_ip,omitempty"`
	Credential string `json:"credential,omitempty"` // credential id (empty for anonymous)
	Username   string `json:"username,omitempty"`
	TraceID    string `json:"trace_id,omitempty"`
}

// String renders host:port.
func (t RequestTarget) String() string { return t.Host + ":" + strconv.Itoa(t.Port) }

// AuditEvent is one JSONL audit record. Detail values must already be
// redacted by the caller.
type AuditEvent struct {
	ID       string            `json:"id"`
	Time     time.Time         `json:"time"`
	Actor    string            `json:"actor,omitempty"`
	SourceIP string            `json:"source_ip,omitempty"`
	Action   string            `json:"action"`
	Object   string            `json:"object,omitempty"`
	Result   string            `json:"result,omitempty"`
	Detail   map[string]string `json:"detail,omitempty"`
}

// AdminUser is the panel administrator, persisted with a password hash.
type AdminUser struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	TOTPSecret   string    `json:"totp_secret,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// NodeToken is a per-node tunnel credential.
type NodeToken struct {
	NodeID    string    `json:"node_id"`
	TokenHash string    `json:"token_hash"` // sha256 hex of the token
	Note      string    `json:"note,omitempty"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NormalizeCountry uppercases and trims an ISO 3166-1 alpha-2 code.
func NormalizeCountry(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

// NormalizeASN parses "AS15169", "as15169" or "15169" into an integer.
func NormalizeASN(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty ASN")
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "AS"), "as")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "As"), "aS")
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid ASN %q: %w", s, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("invalid ASN %q: must be positive", s)
	}
	return n, nil
}
