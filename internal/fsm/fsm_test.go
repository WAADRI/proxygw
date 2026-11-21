package fsm

import "testing"

func TestSessionHappyPath(t *testing.T) {
	var seen []string
	f := NewSessionFSM(SessionDialing, func(from, to SessionState, ev SessionEvent) {
		seen = append(seen, string(from)+"->"+string(to))
	})
	steps := []struct {
		ev   SessionEvent
		want SessionState
	}{
		{SessEvConnected, SessionHandshaking},
		{SessEvHelloOK, SessionReady},
		{SessEvHeartbeatMiss, SessionDegraded},
		{SessEvHeartbeatOK, SessionReady},
		{SessEvKick, SessionDraining},
		{SessEvDrainDone, SessionClosed},
	}
	for _, s := range steps {
		got, err := f.Fire(s.ev)
		if err != nil {
			t.Fatalf("fire %s: %v", s.ev, err)
		}
		if got != s.want {
			t.Fatalf("fire %s = %s want %s", s.ev, got, s.want)
		}
	}
	if len(seen) != len(steps) {
		t.Fatalf("hook calls = %d want %d", len(seen), len(steps))
	}
	if _, err := f.Fire(SessEvHelloOK); err == nil {
		t.Fatal("event after closed must fail")
	}
}

func TestSessionToClosedFromAnyFailure(t *testing.T) {
	states := []SessionState{SessionDialing, SessionHandshaking, SessionReady, SessionDegraded, SessionDraining}
	for _, st := range states {
		f := NewSessionFSM(st, nil)
		if _, err := f.Fire(SessEvTransportErr); err != nil {
			t.Fatalf("state %s: transport error must close: %v", st, err)
		}
		if f.State() != SessionClosed {
			t.Fatalf("state %s did not close", st)
		}
	}
}

func TestSessionIllegalTransitions(t *testing.T) {
	f := NewSessionFSM(SessionDialing, nil)
	if _, err := f.Fire(SessEvHelloOK); err == nil {
		t.Fatal("dialing + hello_ok must be illegal")
	}
	if f.State() != SessionDialing {
		t.Fatal("illegal transition must not change state")
	}
	if _, err := f.Fire(SessEvHeartbeatLost); err == nil {
		t.Fatal("dialing + heartbeat_lost must be illegal")
	}
}

func TestSessionHandshakeAuthFailure(t *testing.T) {
	f := NewSessionFSM(SessionHandshaking, nil)
	if _, err := f.Fire(SessEvHelloFail); err != nil {
		t.Fatal(err)
	}
	if f.State() != SessionClosed {
		t.Fatal("auth failure must close")
	}
}

func TestStreamHappyPath(t *testing.T) {
	f := NewStreamFSM(nil)
	steps := []struct {
		ev   StreamEvent
		want StreamState
	}{
		{StreamEvSentOpen, StreamOpening},
		{StreamEvAckOK, StreamOpen},
		{StreamEvLocalEOF, StreamHalfLocal},
		{StreamEvRemoteFIN, StreamClosed},
	}
	for _, s := range steps {
		got, err := f.Fire(s.ev)
		if err != nil {
			t.Fatalf("fire %s: %v", s.ev, err)
		}
		if got != s.want {
			t.Fatalf("fire %s = %s want %s", s.ev, got, s.want)
		}
	}
}

func TestStreamRemoteFINFirst(t *testing.T) {
	f := NewStreamFSM(nil)
	for _, ev := range []StreamEvent{StreamEvSentOpen, StreamEvAckOK, StreamEvRemoteFIN} {
		if _, err := f.Fire(ev); err != nil {
			t.Fatalf("fire %s: %v", ev, err)
		}
	}
	if f.State() != StreamHalfRemote {
		t.Fatalf("state = %s", f.State())
	}
	if _, err := f.Fire(StreamEvLocalEOF); err != nil {
		t.Fatal(err)
	}
	if f.State() != StreamClosed {
		t.Fatalf("state = %s", f.State())
	}
}

func TestStreamErrors(t *testing.T) {
	f := NewStreamFSM(nil)
	if _, err := f.Fire(StreamEvAckOK); err == nil {
		t.Fatal("new + ack_ok must be illegal")
	}
	if _, err := f.Fire(StreamEvSentOpen); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Fire(StreamEvAckErr); err != nil {
		t.Fatal(err)
	}
	if f.State() != StreamClosed || !f.State().Terminal() {
		t.Fatalf("ack error must close, got %s", f.State())
	}
	// RST path goes through draining then closed.
	g := NewStreamFSM(nil)
	for _, ev := range []StreamEvent{StreamEvSentOpen, StreamEvAckOK, StreamEvRST} {
		if _, err := g.Fire(ev); err != nil {
			t.Fatalf("fire %s: %v", ev, err)
		}
	}
	if g.State() != StreamDraining {
		t.Fatalf("rst state = %s", g.State())
	}
	if _, err := g.Fire(StreamEvCleanup); err != nil {
		t.Fatal(err)
	}
	if g.State() != StreamClosed {
		t.Fatalf("cleanup state = %s", g.State())
	}
}

func TestStreamOpenTimeout(t *testing.T) {
	f := NewStreamFSM(nil)
	if _, err := f.Fire(StreamEvSentOpen); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Fire(StreamEvOpenTO); err != nil {
		t.Fatal(err)
	}
	if f.State() != StreamDraining {
		t.Fatalf("open timeout state = %s", f.State())
	}
}
