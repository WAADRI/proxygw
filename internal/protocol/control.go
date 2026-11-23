package protocol

import (
	"encoding/json"
	"fmt"
	"time"
)

// Capability names advertised in HELLO.
const (
	CapZstd   = "zstd"
	CapDNS    = "dns"
	CapProbe  = "probe"
	CapUpdate = "update"
)

// Update states reported by a node to the panel.
const (
	UpdateIdle           = "idle"
	UpdateChecking       = "checking"
	UpdateDownloading    = "downloading"
	UpdateVerified       = "verified"
	UpdateWaitingRestart = "waiting_restart"
	UpdateReplacing      = "replacing"
	UpdateRestarting     = "restarting"
	UpdateSuccess        = "success"
	UpdateFailed         = "failed"
	UpdateRolledBack     = "rolled_back"
)

// Kick reasons.
const (
	KickShutdown  = "shutdown"
	KickReplaced  = "replaced"
	KickRevoked   = "revoked"
	KickDisabled  = "disabled"
	KickDuplicate = "duplicate_client_id"
	KickCooldown  = "takeover_cooldown"
)

// Probe kinds used by the panel dial test and DNS passthrough.
const (
	ProbePing   = "ping"
	ProbeTCPing = "tcping"
	ProbeHTTP   = "http"
	ProbeDNS    = "dns"
)

// Hello is the registration message sent by a node on its control stream.
type Hello struct {
	Ver           uint8    `json:"ver"`
	Token         string   `json:"token,omitempty"`
	ClientID      string   `json:"client_id"`
	Alias         string   `json:"alias,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Region        string   `json:"region,omitempty"`
	ISPLabel      string   `json:"isp_label,omitempty"`
	Weight        int      `json:"weight,omitempty"`
	Transport     string   `json:"transport"`
	Planes        int      `json:"planes,omitempty"`
	PlaneIndex    int      `json:"plane_index,omitempty"`
	EgressV4      string   `json:"egress_v4,omitempty"`
	EgressV6      string   `json:"egress_v6,omitempty"`
	Version       string   `json:"version,omitempty"`
	Runtime       string   `json:"runtime,omitempty"`
	UpdateCapable bool     `json:"update_capable,omitempty"`
	Capabilities  []string `json:"caps,omitempty"`
	Compression   bool     `json:"compression,omitempty"`
	TS            int64    `json:"ts,omitempty"`
}

// HelloSettings is the runtime policy returned to a node in HELLO_ACK.
type HelloSettings struct {
	MaxStreams    int   `json:"max_streams"`
	MaxFrameBytes int   `json:"max_frame_bytes"`
	Compression   bool  `json:"compression"`
	HeartbeatMS   int64 `json:"heartbeat_ms"`
}

// HelloAck acknowledges registration (or rejects it).
type HelloAck struct {
	Ver        uint8         `json:"ver"`
	OK         bool          `json:"ok"`
	Error      string        `json:"error,omitempty"`
	Epoch      uint32        `json:"epoch"`
	Transport  string        `json:"transport"`
	Settings   HelloSettings `json:"settings"`
	PinNext    string        `json:"pin_next,omitempty"`
	ServerTime int64         `json:"server_time"`
}

// Stats is the periodic node statistics message.
type Stats struct {
	Inflight      int64         `json:"inflight"`
	ActiveStreams int64         `json:"active_streams"`
	BytesIn       uint64        `json:"bytes_in"`
	BytesOut      uint64        `json:"bytes_out"`
	LatencyMS     float64       `json:"latency_ms"`
	Transport     string        `json:"transport"`
	Version       string        `json:"version,omitempty"`
	Runtime       string        `json:"runtime,omitempty"`
	Update        *UpdateStatus `json:"update,omitempty"`
	EgressV4      string        `json:"egress_v4,omitempty"`
	EgressV6      string        `json:"egress_v6,omitempty"`
	TS            int64         `json:"ts,omitempty"`
}

// UpdateCommand asks a node to self-update to the latest release. The node
// still downloads from the configured GitHub repository and verifies the
// release SHA-256; the command never carries an arbitrary executable URL.
type UpdateCommand struct {
	CommandID  string `json:"command_id,omitempty"`
	Version    string `json:"version,omitempty"`
	Repository string `json:"repository,omitempty"`
}

// UpdateStatus is the node's update progress, also exposed through STATS and
// the panel node list.
type UpdateStatus struct {
	State          string `json:"state"`
	CurrentVersion string `json:"current_version,omitempty"`
	TargetVersion  string `json:"target_version,omitempty"`
	Progress       int    `json:"progress,omitempty"`
	Message        string `json:"message,omitempty"`
	Error          string `json:"error,omitempty"`
	UpdatedAt      int64  `json:"updated_at,omitempty"`
}

// Kick tells a node to stop accepting new streams and drain.
type Kick struct {
	Reason  string `json:"reason"`
	Message string `json:"message,omitempty"`
}

// Probe requests the node to run a dial test or a DNS lookup.
type Probe struct {
	ID      string `json:"id,omitempty"`
	Kind    string `json:"kind"`
	Target  string `json:"target"`
	Payload []byte `json:"payload,omitempty"`
}

// ProbeResult carries the outcome of a probe.
type ProbeResult struct {
	ID        string  `json:"id,omitempty"`
	OK        bool    `json:"ok"`
	Error     string  `json:"error,omitempty"`
	LatencyMS float64 `json:"latency_ms"`
	Result    []byte  `json:"result,omitempty"`
	Detail    string  `json:"detail,omitempty"`
}

// Marshal encodes a control message.
func Marshal(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("protocol: marshal control message: %w", err)
	}
	return b, nil
}

// Unmarshal decodes a control message.
func Unmarshal(b []byte, v any) error {
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("protocol: unmarshal control message: %w", err)
	}
	return nil
}

// NowMillis returns the current unix time in milliseconds.
func NowMillis() int64 { return time.Now().UnixMilli() }

// ControlStreamFrame is a convenience pair used when buffering control frames.
type ControlStreamFrame struct {
	Type    FrameType
	Payload []byte
}
