package tunnel

import (
	"proxygw/internal/fsm"
)

// rejectPeerStreams consumes peer initiated streams and rejects them. Per the
// tunnel state machine attachment, before registration any data stream is a
// security violation (and after registration the protocol is strictly server
// initiated), so a node that opens streams unilaterally is either buggy or
// hostile. Draining the accept queue also prevents queue exhaustion from
// blocking the transport read loop.
func (s *Server) rejectPeerStreams(sess *session) {
	for {
		st, err := sess.conn.AcceptStream(sess.ctx)
		if err != nil {
			return
		}
		state := sess.state()
		s.logger.Warn("security: peer initiated tunnel stream rejected",
			"event", "security.peer_stream",
			"session_id", sess.id,
			"node_id", sess.node(),
			"plane_index", sess.planeIndex(),
			"transport", sess.transport,
			"state", string(state),
			"handshaking", state == fsm.SessionHandshaking,
			"remote", addrString(sess.conn.RemoteAddr()))
		s.auditEvent("tunnel.peer_stream_rejected", map[string]string{
			"node_id": sess.node(), "session_id": sess.id, "transport": sess.transport,
			"state": string(state),
		})
		_ = st.Reset(1)
	}
}
