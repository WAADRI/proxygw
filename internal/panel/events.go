package panel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"proxygw/internal/model"
)

// sseHub fans mutation notifications out to the connected /events clients. Each
// subscriber owns a buffered channel; broadcasts never block on a slow client.
type sseHub struct {
	mu          sync.Mutex
	subscribers map[chan struct{}]struct{}
}

// newSSEHub creates an empty hub.
func newSSEHub() *sseHub {
	return &sseHub{subscribers: make(map[chan struct{}]struct{})}
}

// subscribe registers a new subscriber and returns its wake-up channel plus the
// unsubscribe function.
func (h *sseHub) subscribe() chan struct{} {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	h.subscribers[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

// unsubscribe removes a subscriber channel.
func (h *sseHub) unsubscribe(ch chan struct{}) {
	h.mu.Lock()
	delete(h.subscribers, ch)
	h.mu.Unlock()
}

// broadcast wakes every subscriber without blocking.
func (h *sseHub) broadcast() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// subscriberCount reports the number of connected SSE clients (tests/metrics).
func (h *sseHub) subscriberCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subscribers)
}

// eventNode is the per-node summary embedded in the SSE snapshot/tick payload.
type eventNode struct {
	ID            string         `json:"id"`
	Alias         string         `json:"alias,omitempty"`
	Online        bool           `json:"online"`
	Enabled       bool           `json:"enabled"`
	Weight        int            `json:"weight"`
	Transport     string         `json:"transport,omitempty"`
	Planes        int            `json:"planes"`
	Inflight      int64          `json:"inflight"`
	LatencyEWMA   float64        `json:"latency_ewma_ms"`
	BytesIn       uint64         `json:"bytes_in"`
	BytesOut      uint64         `json:"bytes_out"`
	BreakerState  string         `json:"breaker_state,omitempty"`
	EgressIP      model.EgressIP `json:"egress_ip"`
	Geo           model.Geo      `json:"geo"`
	Groups        []string       `json:"groups,omitempty"`
	LastHeartbeat time.Time      `json:"last_heartbeat,omitempty"`
}

// eventPayload is the JSON object carried by every `data:` line.
type eventPayload struct {
	Type     string           `json:"type"` // snapshot | tick
	TS       int64            `json:"ts"`   // Unix milliseconds
	Overview overviewResponse `json:"overview"`
	Nodes    []eventNode      `json:"nodes"`
}

// maxEventNodes bounds the SSE node payload; the full list stays available via
// GET /nodes pagination.
const maxEventNodes = 1000

// handleEvents serves GET /api/v1/events (Server-Sent Events). It sends an
// immediate snapshot, ticks every 3 seconds, wakes early after mutations and
// keeps the connection alive with `: ping` comments.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeError(w, http.StatusInternalServerError, "internal_error", "当前连接不支持 SSE 推送", nil)
		return
	}
	header := w.Header()
	header.Set("Content-Type", "text/event-stream; charset=utf-8")
	header.Set("Cache-Control", "no-cache")
	header.Set("Connection", "keep-alive")
	header.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	// Ask EventSource to reconnect after 3s; harmless for other clients.
	if _, err := fmt.Fprint(w, "retry: 3000\n\n"); err != nil {
		return
	}
	flusher.Flush()

	wake := s.hub.subscribe()
	defer s.hub.unsubscribe(wake)

	if !s.writeEvent(w, flusher, r, "snapshot") {
		return
	}

	ticker := time.NewTicker(sseTickInterval)
	defer ticker.Stop()
	heartbeat := time.NewTicker(sseHeartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !s.writeEvent(w, flusher, r, "tick") {
				return
			}
		case <-wake:
			if !s.writeEvent(w, flusher, r, "tick") {
				return
			}
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// writeEvent builds and writes one SSE data frame. It returns false when the
// client is gone.
func (s *Server) writeEvent(w http.ResponseWriter, flusher http.Flusher, r *http.Request, kind string) bool {
	payload, err := json.Marshal(s.buildEventPayload(r, kind))
	if err != nil {
		s.log.Error("构造 SSE 事件失败", "type", kind, "error", err)
		payload = []byte(`{"type":"error","message":"构造事件失败"}`)
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", payload); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

// buildEventPayload assembles the snapshot/tick payload from live state.
func (s *Server) buildEventPayload(r *http.Request, kind string) eventPayload {
	overview := s.buildOverview(r.Context())
	nodeList := s.opts.Registry.List()
	sortNodes(nodeList)
	if len(nodeList) > maxEventNodes {
		nodeList = nodeList[:maxEventNodes]
	}
	nodes := make([]eventNode, 0, len(nodeList))
	for i := range nodeList {
		node := &nodeList[i]
		nodes = append(nodes, eventNode{
			ID:            node.ID,
			Alias:         node.Alias,
			Online:        node.Online,
			Enabled:       node.Enabled,
			Weight:        node.Weight,
			Transport:     node.Transport,
			Planes:        node.Planes,
			Inflight:      node.Inflight,
			LatencyEWMA:   node.LatencyEWMA,
			BytesIn:       node.BytesIn,
			BytesOut:      node.BytesOut,
			BreakerState:  node.BreakerState,
			EgressIP:      node.EgressIP,
			Geo:           node.Geo,
			Groups:        node.Groups,
			LastHeartbeat: node.LastHeartbeat,
		})
	}
	return eventPayload{
		Type:     kind,
		TS:       s.now().UnixMilli(),
		Overview: overview,
		Nodes:    nodes,
	}
}
