package tunnel

import (
	"strings"
	"testing"
	"time"

	"proxygw/internal/protocol"
)

// TestKickDeliversControlFrameBeforeClose guards the KICK delivery grace: a
// kick with no in-flight streams must keep the transport open long enough for
// the peer to read the KICK control frame. Without the grace, nodes only see a
// closed connection and enter the generic 1-minute reconnect backoff instead of
// the intended 1s KICK retry.
func TestKickDeliversControlFrameBeforeClose(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{times: &Timeouts{Drain: 2 * time.Second}})
	conn, tap, _ := env.registerNode("node-kick-grace", 0)

	start := time.Now()
	if err := env.srv.KickNode("node-kick-grace", protocol.KickRevoked, "grace test"); err != nil {
		t.Fatalf("KickNode: %v", err)
	}
	frame := tap.nextOfType(t, protocol.FrameKick, 3*time.Second)
	if frame.typ != protocol.FrameKick {
		t.Fatalf("expected KICK, got %s", frame.typ)
	}
	if err := conn.waitClosed(3 * time.Second); err != nil {
		t.Fatalf("kicked session did not close: %v", err)
	}
	if elapsed := time.Since(start); elapsed < kickDeliveryGrace/2 {
		t.Fatalf("session closed %s after kick; KICK delivery grace (%s) not applied", elapsed, kickDeliveryGrace)
	}
}

// TestHelloRejectionDeliversAckBeforeClose guards the HELLO_ACK rejection grace:
// a node with a bad token must receive HELLO_ACK(ok=false) with the rejection
// reason before the transport closes, so it can fail fast instead of retrying
// forever (nodeagent treats a lost rejection as a transport error).
func TestHelloRejectionDeliversAckBeforeClose(t *testing.T) {
	env := newTestEnv(t, testEnvOptions{})
	conn := env.pushHelloConn("node-bad-token", 0, "definitely-wrong-token")

	start := time.Now()
	ack := readHelloAck(t, conn.ctrl, 3*time.Second)
	if ack.OK {
		t.Fatal("HELLO_ACK unexpectedly OK for a bad token")
	}
	if !strings.Contains(ack.Error, "authentication failed") {
		t.Fatalf("HELLO_ACK error = %q, want authentication failed", ack.Error)
	}
	if err := conn.waitClosed(3 * time.Second); err != nil {
		t.Fatalf("rejected session did not close: %v", err)
	}
	if elapsed := time.Since(start); elapsed < helloRejectGrace/2 {
		t.Fatalf("session closed %s after rejection; HELLO_ACK delivery grace (%s) not applied", elapsed, helloRejectGrace)
	}
}
