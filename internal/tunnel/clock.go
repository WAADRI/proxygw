package tunnel

// Clock offset observation helpers. The server samples HELLO/STATS timestamps
// per session and exposes the median offset (local - remote) for the panel and
// alerting. The server never adjusts its own clock.

// ClockSkew returns the current clock offset estimate (local - remote) for one
// node, in milliseconds. When multiple planes exist the largest absolute offset
// is reported. Zero means either no samples yet or a perfectly aligned clock.
func (s *Server) ClockSkew(nodeID string) int64 {
	s.mu.Lock()
	sessions := make([]*session, 0, len(s.live))
	for sess := range s.live {
		if sess.node() == nodeID {
			sessions = append(sessions, sess)
		}
	}
	s.mu.Unlock()
	var best int64
	found := false
	for _, sess := range sessions {
		if sess.clock == nil {
			continue
		}
		off := int64(sess.clock.Offset() / 1e6)
		if !found || abs64Int(off) > abs64Int(best) {
			best = off
			found = true
		}
	}
	return best
}

// MaxClockSkew returns the largest absolute clock offset across all live
// sessions in milliseconds (0 when no samples exist).
func (s *Server) MaxClockSkew() int64 {
	s.mu.Lock()
	sessions := make([]*session, 0, len(s.live))
	for sess := range s.live {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	var best int64
	for _, sess := range sessions {
		if sess.clock == nil {
			continue
		}
		off := int64(sess.clock.Offset() / 1e6)
		if abs64Int(off) > abs64Int(best) {
			best = off
		}
	}
	return best
}

func abs64Int(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
