package transport

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"proxygw/internal/protocol"
)

// wsControl is the implicit connection level control channel of the WebSocket
// transport. Control frames are protocol frames whose stream id is 0; they ride
// the high priority writer queue and are demultiplexed by the connection reader.
type wsControl struct {
	conn   *wsConn
	in     chan protocol.Frame
	closed chan struct{}
	once   sync.Once
	done   atomic.Bool
}

func newWSControl(c *wsConn) *wsControl {
	return &wsControl{conn: c, in: c.inboundCtrl, closed: make(chan struct{})}
}

// Send queues one control frame.
func (c *wsControl) Send(ctx context.Context, typ protocol.FrameType, payload []byte) error {
	if err := c.usable(); err != nil {
		return err
	}
	if len(payload) > protocol.MaxFramePayload {
		return fmt.Errorf("%w: control payload %d exceeds frame payload limit %d", ErrProtocol, len(payload), protocol.MaxFramePayload)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.conn.enqueueCtrlFrame(ctx, typ, protocol.ControlStreamID, payload)
}

// Recv returns the next control frame, blocking until one is available, the
// context is cancelled, or the control channel/connection is closed.
func (c *wsControl) Recv(ctx context.Context) (protocol.FrameType, []byte, error) {
	if err := c.usable(); err != nil {
		return 0, nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case f := <-c.in:
		return f.Type, f.Payload, nil
	case <-c.closed:
		return 0, nil, ErrControlClosed
	case <-c.conn.done:
		return 0, nil, c.conn.lastErr()
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	}
}

// Close closes the local control channel. It is idempotent and does not close
// the transport connection; a pending Recv returns ErrControlClosed.
func (c *wsControl) Close() error {
	c.shutdown()
	return nil
}

// shutdown closes the control channel once.
func (c *wsControl) shutdown() {
	c.once.Do(func() {
		c.done.Store(true)
		close(c.closed)
	})
}

// closeInternal is used by the connection teardown path.
func (c *wsControl) closeInternal() { c.shutdown() }

// usable reports whether control operations may proceed.
func (c *wsControl) usable() error {
	if c.done.Load() {
		return ErrControlClosed
	}
	if err := c.conn.doneErr(); err != nil {
		return err
	}
	return nil
}
