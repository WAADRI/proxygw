package transport

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
)

// newQLogTracer builds a quic-go per-connection tracer that writes one .sqlog
// file per connection into dir.
//
// quic-go v0.48.2 exposes qlog through quic.Config.Tracer (a factory called
// per connection); the helper qlog.DefaultConnectionTracer only reads the
// QLOGDIR environment variable, so QUICOptions.QLogDir is implemented with
// this small custom factory instead. Directory creation and file errors are
// non-fatal: tracing is best effort and must never break the transport.
func newQLogTracer(dir string) func(context.Context, logging.Perspective, quic.ConnectionID) *logging.ConnectionTracer {
	_ = os.MkdirAll(dir, 0o755)
	return func(_ context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
		name := fmt.Sprintf("%s_%s.sqlog", connID, p)
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return nil
		}
		return qlog.NewConnectionTracer(f, p, connID)
	}
}
