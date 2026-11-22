// Package fsm implements the session and stream state machines defined by the
// tunnel design attachment. Both the server and the node agent use these types
// so the transition tables have exactly one implementation.
package fsm

import (
	"fmt"
	"sync"
)

// SessionState is the transport connection lifecycle state.
type SessionState string

// Session states (状态机设计第 2 章).
const (
	SessionDialing     SessionState = "dialing"
	SessionHandshaking SessionState = "handshaking"
	SessionReady       SessionState = "ready"
	SessionDegraded    SessionState = "degraded"
	SessionDraining    SessionState = "draining"
	SessionClosed      SessionState = "closed"
)

// SessionEvent is an input to the session state machine.
type SessionEvent string

// Session events.
const (
	SessEvConnected     SessionEvent = "connected"
	SessEvHelloOK       SessionEvent = "hello_ok"
	SessEvHelloFail     SessionEvent = "hello_fail"
	SessEvHandshakeTO   SessionEvent = "handshake_timeout"
	SessEvHeartbeatMiss SessionEvent = "heartbeat_miss"
	SessEvHeartbeatOK   SessionEvent = "heartbeat_ok"
	SessEvHeartbeatLost SessionEvent = "heartbeat_lost"
	SessEvKick          SessionEvent = "kick"
	SessEvDrainDone     SessionEvent = "drain_done"
	SessEvTransportErr  SessionEvent = "transport_error"
)

// Transition describes one allowed state change.
type Transition struct {
	From  SessionState
	Event SessionEvent
	To    SessionState
}

// SessionTransitions is the authoritative session transition table.
var SessionTransitions = []Transition{
	{SessionDialing, SessEvConnected, SessionHandshaking},
	{SessionHandshaking, SessEvHelloOK, SessionReady},
	{SessionHandshaking, SessEvHelloFail, SessionClosed},
	{SessionHandshaking, SessEvHandshakeTO, SessionClosed},
	{SessionReady, SessEvHeartbeatMiss, SessionDegraded},
	{SessionDegraded, SessEvHeartbeatOK, SessionReady},
	{SessionDegraded, SessEvHeartbeatLost, SessionClosed},
	{SessionReady, SessEvKick, SessionDraining},
	{SessionDegraded, SessEvKick, SessionDraining},
	{SessionDraining, SessEvDrainDone, SessionClosed},
	// Any state can fail closed on a transport error.
	{SessionDialing, SessEvTransportErr, SessionClosed},
	{SessionHandshaking, SessEvTransportErr, SessionClosed},
	{SessionReady, SessEvTransportErr, SessionClosed},
	{SessionDegraded, SessEvTransportErr, SessionClosed},
	{SessionDraining, SessEvTransportErr, SessionClosed},
}

// TransitionFunc is invoked after every successful transition.
type TransitionFunc func(from, to fmt.Stringer, event fmt.Stringer)

// SessionFSM is a thread safe session state machine.
type SessionFSM struct {
	mu     sync.Mutex
	state  SessionState
	hook   func(from, to SessionState, event SessionEvent)
	closed bool
}

// NewSessionFSM creates a session machine starting in initial.
func NewSessionFSM(initial SessionState, hook func(from, to SessionState, event SessionEvent)) *SessionFSM {
	if initial == "" {
		initial = SessionDialing
	}
	return &SessionFSM{state: initial, hook: hook}
}

// State returns the current state.
func (f *SessionFSM) State() SessionState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

// Fire applies event e. Illegal transitions return an error and leave the state
// unchanged; a closed machine stays closed.
func (f *SessionFSM) Fire(e SessionEvent) (SessionState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state == SessionClosed {
		if e == SessEvTransportErr || e == SessEvDrainDone {
			return f.state, nil
		}
		return f.state, fmt.Errorf("fsm: session already closed, event %s", e)
	}
	to, ok := sessionNext(f.state, e)
	if !ok {
		return f.state, fmt.Errorf("fsm: illegal session transition %s --%s--> ?", f.state, e)
	}
	from := f.state
	f.state = to
	if to == SessionClosed {
		f.closed = true
	}
	if f.hook != nil {
		f.hook(from, to, e)
	}
	return to, nil
}

func sessionNext(from SessionState, e SessionEvent) (SessionState, bool) {
	for _, t := range SessionTransitions {
		if t.From == from && t.Event == e {
			return t.To, true
		}
	}
	return "", false
}

// CanHoldNewStreams reports whether the state accepts new OPEN requests.
func (s SessionState) CanHoldNewStreams() bool { return s == SessionReady || s == SessionDegraded }

// StreamState is the lifecycle of one proxied connection.
type StreamState string

// Stream states (状态机设计第 3 章).
const (
	StreamNew        StreamState = "new"
	StreamOpening    StreamState = "opening"
	StreamOpen       StreamState = "open"
	StreamHalfLocal  StreamState = "half_local"
	StreamHalfRemote StreamState = "half_remote"
	StreamDraining   StreamState = "draining"
	StreamClosed     StreamState = "closed"
)

// StreamEvent is an input to the stream state machine.
type StreamEvent string

// Stream events.
const (
	StreamEvSentOpen    StreamEvent = "sent_open"
	StreamEvAckOK       StreamEvent = "ack_ok"
	StreamEvAckErr      StreamEvent = "ack_err"
	StreamEvOpenTO      StreamEvent = "open_timeout"
	StreamEvLocalEOF    StreamEvent = "local_eof"
	StreamEvRemoteFIN   StreamEvent = "remote_fin"
	StreamEvRST         StreamEvent = "rst"
	StreamEvSessionLost StreamEvent = "session_lost"
	StreamEvCleanup     StreamEvent = "cleanup_done"
)

// StreamTransition describes one allowed stream state change.
type StreamTransition struct {
	From  StreamState
	Event StreamEvent
	To    StreamState
}

// StreamTransitions is the authoritative stream transition table.
var StreamTransitions = []StreamTransition{
	{StreamNew, StreamEvSentOpen, StreamOpening},
	{StreamOpening, StreamEvAckOK, StreamOpen},
	{StreamOpening, StreamEvAckErr, StreamClosed},
	{StreamOpening, StreamEvOpenTO, StreamDraining},
	{StreamOpen, StreamEvLocalEOF, StreamHalfLocal},
	{StreamOpen, StreamEvRemoteFIN, StreamHalfRemote},
	{StreamOpen, StreamEvRST, StreamDraining},
	{StreamOpen, StreamEvSessionLost, StreamDraining},
	{StreamHalfLocal, StreamEvRemoteFIN, StreamClosed},
	{StreamHalfLocal, StreamEvRST, StreamDraining},
	{StreamHalfLocal, StreamEvSessionLost, StreamDraining},
	{StreamHalfRemote, StreamEvLocalEOF, StreamClosed},
	{StreamHalfRemote, StreamEvRST, StreamDraining},
	{StreamHalfRemote, StreamEvSessionLost, StreamDraining},
	{StreamOpening, StreamEvRST, StreamDraining},
	{StreamOpening, StreamEvSessionLost, StreamDraining},
	{StreamDraining, StreamEvCleanup, StreamClosed},
	// A remote FIN arriving on an already half-closed local side is benign and
	// handled by the relay; the state machine records it idempotently.
	{StreamHalfLocal, StreamEvRemoteFIN, StreamClosed},
}

// StreamFSM is a thread safe stream state machine.
type StreamFSM struct {
	mu    sync.Mutex
	state StreamState
	hook  func(from, to StreamState, event StreamEvent)
}

// NewStreamFSM creates a stream machine starting at new.
func NewStreamFSM(hook func(from, to StreamState, event StreamEvent)) *StreamFSM {
	return &StreamFSM{state: StreamNew, hook: hook}
}

// State returns the current state.
func (f *StreamFSM) State() StreamState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

// Fire applies event e.
func (f *StreamFSM) Fire(e StreamEvent) (StreamState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state == StreamClosed {
		return f.state, nil
	}
	to, ok := streamNext(f.state, e)
	if !ok {
		return f.state, fmt.Errorf("fsm: illegal stream transition %s --%s--> ?", f.state, e)
	}
	from := f.state
	f.state = to
	if f.hook != nil {
		f.hook(from, to, e)
	}
	return to, nil
}

func streamNext(from StreamState, e StreamEvent) (StreamState, bool) {
	for _, t := range StreamTransitions {
		if t.From == from && t.Event == e {
			return t.To, true
		}
	}
	return "", false
}

// Terminal reports whether no further transitions are possible.
func (s StreamState) Terminal() bool { return s == StreamClosed }
