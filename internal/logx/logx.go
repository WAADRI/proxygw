// Package logx configures structured logging for both binaries.
package logx

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Format selects the log encoding.
const (
	FormatJSON = "json"
	FormatText = "text"
)

// Config controls logger construction.
type Config struct {
	Level  string `json:"level" yaml:"level"`
	Format string `json:"format" yaml:"format"`
}

// Validate checks the log configuration.
func (c Config) Validate() error {
	if _, err := ParseLevel(c.Level); err != nil {
		return err
	}
	switch strings.ToLower(c.Format) {
	case "", FormatJSON, FormatText:
		return nil
	default:
		return fmt.Errorf("log.format: unsupported format %q (want json or text)", c.Format)
	}
}

// ParseLevel maps a textual level to slog.Level.
func ParseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("log.level: unsupported level %q (want debug/info/warn/error)", level)
	}
}

// New builds a slog.Logger writing to w. A nil writer means os.Stderr.
func New(cfg Config, w io.Writer) (*slog.Logger, error) {
	lvl, err := ParseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}
	if w == nil {
		w = os.Stderr
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if strings.ToLower(cfg.Format) == FormatText {
		h = slog.NewTextHandler(w, opts)
	} else {
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(h).With("app", "proxygw"), nil
}

// WithFields is a convenience wrapper returning a logger with key/value pairs.
func WithFields(l *slog.Logger, kv ...any) *slog.Logger {
	if l == nil {
		return slog.Default().With(kv...)
	}
	return l.With(kv...)
}

// FromContext returns the logger stored in ctx, or the fallback logger.
func FromContext(ctx context.Context, fallback *slog.Logger) *slog.Logger {
	if ctx != nil {
		if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && l != nil {
			return l
		}
	}
	if fallback == nil {
		return slog.Default()
	}
	return fallback
}

type loggerKey struct{}

// IntoContext stores a logger in the context.
func IntoContext(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, l)
}

// Redacted reports whether a log key must be redacted. It is a last line of
// defence: call sites should simply never pass secrets.
func Redacted(key string) bool {
	switch strings.ToLower(key) {
	case "token", "password", "password_hash", "secret", "authorization", "proxy-authorization",
		"cookie", "set-cookie", "tls_key", "private_key", "totp_secret", "jwt":
		return true
	}
	return false
}
