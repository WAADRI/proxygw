package tunnel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"proxygw/internal/fsm"
	"proxygw/internal/protocol"
)

// KickNode sends KICK to every plane of nodeID and drains them. The node is
// removed from the schedulable pool immediately; in-flight streams may finish
// within the drain budget. reason must be one of protocol.Kick* values.
func (s *Server) KickNode(nodeID, reason, message string) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return errors.New("tunnel: empty node id")
	}
	if reason == "" {
		reason = protocol.KickDisabled
	}
	sessions := s.liveSessionsFor(nodeID)
	if len(sessions) == 0 {
		return fmt.Errorf("tunnel: node %q has no active sessions", nodeID)
	}
	for _, sess := range sessions {
		s.detachSession(sess)
		sess.beginDrain(reason, message)
	}
	s.logger.Info("node kicked",
		"event", "node_kick", "node_id", nodeID, "reason", reason,
		"message", message, "planes", len(sessions))
	return nil
}

// ResetNodeTakeover clears the takeover history and cooldown of one node. It is
// used by the panel force-offline action: an operator explicitly asked the node
// to disconnect, so its immediate reconnect must not be rejected by a cooldown
// accumulated before the kick.
func (s *Server) ResetNodeTakeover(nodeID string) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return
	}
	s.mu.Lock()
	delete(s.cooldown, nodeID)
	delete(s.takeovers, nodeID)
	s.mu.Unlock()
	s.logger.Info("node takeover state reset", "event", "node_takeover_reset", "node_id", nodeID)
}

// UpdateNode sends a self-update command to one live plane of nodeID. The node
// downloads the release itself and reports progress over UPDATE_STATUS/STATS.
func (s *Server) UpdateNode(nodeID string, cmd protocol.UpdateCommand) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return errors.New("tunnel: empty node id")
	}
	sessions := s.liveSessionsFor(nodeID)
	if len(sessions) == 0 {
		return fmt.Errorf("tunnel: node %q has no active sessions", nodeID)
	}
	var lastErr error
	for _, sess := range sessions {
		if err := sess.sendJSON(protocol.FrameUpdate, cmd); err != nil {
			lastErr = err
			continue
		}
		s.logger.Info("node update dispatched",
			"event", "node_update", "node_id", nodeID, "version", cmd.Version,
			"command_id", cmd.CommandID)
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no reachable plane")
	}
	return fmt.Errorf("tunnel: send UPDATE to node %q: %w", nodeID, lastErr)
}

// DrainNode stops assigning new streams to nodeID but lets the node close
// naturally after its in-flight streams finish.
func (s *Server) DrainNode(nodeID string) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return errors.New("tunnel: empty node id")
	}
	sessions := s.liveSessionsFor(nodeID)
	if len(sessions) == 0 {
		return fmt.Errorf("tunnel: node %q has no active sessions", nodeID)
	}
	for _, sess := range sessions {
		s.detachSession(sess)
		sess.beginDrain(reasonDrain, "operator requested drain")
	}
	s.logger.Info("node drained",
		"event", "node_drain", "node_id", nodeID, "planes", len(sessions))
	return nil
}

// detachSession removes sess from the schedulable owner map.
func (s *Server) detachSession(sess *session) bool {
	key := sess.key()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions[key] == sess {
		delete(s.sessions, key)
		return true
	}
	return false
}

// liveSessionsFor returns a snapshot of every live session of nodeID.
func (s *Server) liveSessionsFor(nodeID string) []*session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*session, 0, 2)
	for sess := range s.live {
		if sess.node() == nodeID {
			out = append(out, sess)
		}
	}
	return out
}

// readySessionsFor returns a snapshot of the schedulable owner sessions of
// nodeID (ready/degraded only), sorted by plane index.
func (s *Server) readySessionsFor(nodeID string) []*session {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*session, 0, 2)
	for key, sess := range s.sessions {
		if key.nodeID != nodeID {
			continue
		}
		if sess.isDraining() || !sess.state().CanHoldNewStreams() {
			continue
		}
		out = append(out, sess)
	}
	return out
}

// pickAnySession chooses a ready plane for control operations (PING/PROBE).
func (s *Server) pickAnySession(nodeID string) *session {
	list := s.readySessionsFor(nodeID)
	if len(list) == 0 {
		return nil
	}
	n := s.rr.Add(1)
	return list[int(n%uint64(len(list)))]
}

// PingNode measures the control-stream RTT to a node with PING/PONG.
func (s *Server) PingNode(ctx context.Context, nodeID string) (time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return 0, errors.New("tunnel: empty node id")
	}
	sess := s.pickAnySession(nodeID)
	if sess == nil {
		return 0, protocol.NewError(protocol.CodePolicy, "tunnel: node %q is not connected", nodeID)
	}
	nonce := randNonce()
	ch := make(chan time.Duration, 1)
	entry := &pingEntry{sentAt: time.Now(), rttCh: ch}
	sess.mu.Lock()
	sess.pings[nonce] = entry
	sess.mu.Unlock()
	payload := make([]byte, 8)
	payload[0] = byte(nonce >> 56)
	payload[1] = byte(nonce >> 48)
	payload[2] = byte(nonce >> 40)
	payload[3] = byte(nonce >> 32)
	payload[4] = byte(nonce >> 24)
	payload[5] = byte(nonce >> 16)
	payload[6] = byte(nonce >> 8)
	payload[7] = byte(nonce)
	if err := sess.sendFrame(protocol.FramePing, payload); err != nil {
		sess.removePing(nonce)
		return 0, fmt.Errorf("tunnel: send PING to node %q: %w", nodeID, err)
	}
	timeout := s.times.Ping
	if timeout <= 0 {
		timeout = DefaultPingTimeout
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case rtt := <-ch:
		return rtt, nil
	case <-sess.closedCh:
		sess.removePing(nonce)
		return 0, fmt.Errorf("tunnel: session for node %q closed while waiting for PONG", nodeID)
	case <-tctx.Done():
		sess.removePing(nonce)
		return 0, fmt.Errorf("tunnel: PING to node %q timed out: %w", nodeID, tctx.Err())
	}
}

// ProbeNode forwards a dial test (ping/tcping/http/dns) to a node and waits for
// its PROBE_RESULT. The ID field correlates the response with the request.
func (s *Server) ProbeNode(ctx context.Context, nodeID, kind, target string, payload []byte) (*protocol.ProbeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return nil, errors.New("tunnel: empty node id")
	}
	sess := s.pickAnySession(nodeID)
	if sess == nil {
		return nil, protocol.NewError(protocol.CodePolicy, "tunnel: node %q is not connected", nodeID)
	}
	id := randomHex(8)
	ch := make(chan *protocol.ProbeResult, 1)
	sess.mu.Lock()
	sess.probes[id] = ch
	sess.mu.Unlock()
	defer func() {
		sess.mu.Lock()
		delete(sess.probes, id)
		sess.mu.Unlock()
	}()
	probe := protocol.Probe{ID: id, Kind: kind, Target: target, Payload: payload}
	if err := sess.sendJSON(protocol.FrameProbe, probe); err != nil {
		return nil, fmt.Errorf("tunnel: send PROBE to node %q: %w", nodeID, err)
	}
	timeout := s.times.Probe
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case res := <-ch:
		if res == nil {
			return nil, errors.New("tunnel: empty PROBE_RESULT")
		}
		return res, nil
	case <-sess.closedCh:
		return nil, fmt.Errorf("tunnel: session for node %q closed while waiting for PROBE_RESULT", nodeID)
	case <-tctx.Done():
		return nil, fmt.Errorf("tunnel: PROBE to node %q timed out: %w", nodeID, tctx.Err())
	}
}

// NodePlaneCount returns the number of ready/degraded planes of a node.
func (s *Server) NodePlaneCount(nodeID string) int {
	return len(s.readySessionsFor(strings.TrimSpace(nodeID)))
}

// ActiveStreams returns the number of active tunnel streams (including streams
// whose OPEN is still in flight).
func (s *Server) ActiveStreams() int64 { return s.activeStream.Load() }

// SessionState returns the aggregated session state and transport of a node for
// the panel. Precedence: ready > degraded > draining > handshaking.
func (s *Server) SessionState(nodeID string) (state string, transport string, ok bool) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return "", "", false
	}
	sessions := s.liveSessionsFor(nodeID)
	if len(sessions) == 0 {
		return "", "", false
	}
	best := -1
	var bestSess *session
	for _, sess := range sessions {
		rank := sessionStateRank(sess.state())
		if rank > best {
			best = rank
			bestSess = sess
		}
	}
	if bestSess == nil {
		return "", "", false
	}
	return string(bestSess.state()), bestSess.transport, true
}

func sessionStateRank(st fsm.SessionState) int {
	switch st {
	case fsm.SessionReady:
		return 5
	case fsm.SessionDegraded:
		return 4
	case fsm.SessionDraining:
		return 3
	case fsm.SessionHandshaking:
		return 2
	case fsm.SessionDialing:
		return 1
	default:
		return 0
	}
}

// NodeLastError returns the last node level error recorded by the tunnel.
func (s *Server) NodeLastError(nodeID string) string {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nodeErrs[nodeID]
}
