// Package settings implements hot-reloadable runtime settings with validation,
// atomic persistence to runtime-overrides.json and a one-step undo history.
package settings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"proxygw/internal/model"
	"proxygw/internal/store"
)

// Snapshot is one persisted settings version.
type Snapshot struct {
	Version   int            `json:"version"`
	Settings  model.Settings `json:"settings"`
	UpdatedAt time.Time      `json:"updated_at"`
	UpdatedBy string         `json:"updated_by,omitempty"`
}

// HistoryEntry is the metadata returned by History.
type HistoryEntry struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by,omitempty"`
}

// fileData is the on-disk representation of runtime-overrides.json.
type fileData struct {
	Version int             `json:"version"`
	Current *model.Settings `json:"current,omitempty"`
	History []Snapshot      `json:"history,omitempty"`
}

// Manager owns the current runtime settings.
type Manager struct {
	mu       sync.RWMutex
	path     string
	defaults model.Settings
	current  model.Settings
	version  int
	history  []Snapshot
	logger   interface {
		Warn(msg string, args ...any)
		Info(msg string, args ...any)
	}
}

// ErrNoUndo is returned when there is no previous version to restore.
var ErrNoUndo = errors.New("settings: no previous version to undo")

// NewManager loads runtime-overrides.json if present, falling back to defaults.
func NewManager(path string, defaults model.Settings, logger interface {
	Warn(msg string, args ...any)
	Info(msg string, args ...any)
}) (*Manager, error) {
	if err := defaults.Validate(); err != nil {
		return nil, fmt.Errorf("settings: invalid defaults: %w", err)
	}
	m := &Manager{path: path, defaults: defaults, current: defaults, logger: logger}
	if path == "" {
		return m, nil
	}
	file := store.New[fileData](path)
	loaded, warnings, err := file.Load(fileData{})
	if err != nil {
		return nil, err
	}
	for _, w := range warnings {
		if m.logger != nil {
			m.logger.Warn(w)
		}
	}
	if loaded.Current != nil {
		if verr := loaded.Current.Validate(); verr != nil {
			if m.logger != nil {
				m.logger.Warn("runtime-overrides.json 校验失败，已回退到配置文件默认值", "error", verr)
			}
		} else {
			m.current = *loaded.Current
			m.version = loaded.Version
			m.history = loaded.History
		}
	}
	return m, nil
}

// Current returns the effective settings.
func (m *Manager) Current() model.Settings {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// Version returns the current settings version (0 = built-in defaults).
func (m *Manager) Version() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version
}

// Apply validates and persists new settings. On validation failure the previous
// settings stay in effect and the error is returned (the panel shows it).
func (m *Manager) Apply(next model.Settings, actor string) error {
	if err := next.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prev := m.current
	m.history = append(m.history, Snapshot{
		Version: m.version, Settings: prev, UpdatedAt: time.Now().UTC(), UpdatedBy: actor,
	})
	// Keep a small bounded history (undo + audit trail).
	if len(m.history) > 20 {
		m.history = m.history[len(m.history)-20:]
	}
	m.current = next
	m.version++
	if err := m.persistLocked(); err != nil {
		// Roll back in memory so the panel never shows an unpersisted config.
		m.current = prev
		m.version--
		m.history = m.history[:len(m.history)-1]
		return err
	}
	if m.logger != nil {
		m.logger.Info("运行设置已更新", "actor", actor, "version", m.version, "strategy", next.Scheduler.Strategy)
	}
	return nil
}

// Undo restores the previous settings version.
func (m *Manager) Undo(actor string) (model.Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.history) == 0 {
		return m.current, ErrNoUndo
	}
	last := m.history[len(m.history)-1]
	m.history = m.history[:len(m.history)-1]
	previous := m.current
	m.current = last.Settings
	m.version++
	if err := m.persistLocked(); err != nil {
		m.current = previous
		m.version--
		m.history = append(m.history, last)
		return previous, err
	}
	if m.logger != nil {
		m.logger.Info("运行设置已撤销到上一版本", "actor", actor, "version", m.version)
	}
	return m.current, nil
}

// History returns a copy of the retained history (oldest first).
func (m *Manager) History() []HistoryEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]HistoryEntry, 0, len(m.history))
	for _, s := range m.history {
		out = append(out, HistoryEntry{Version: s.Version, UpdatedAt: s.UpdatedAt, UpdatedBy: s.UpdatedBy})
	}
	return out
}

// ResetToDefaults clears overrides and restores the configured defaults.
func (m *Manager) ResetToDefaults(actor string) error {
	return m.Apply(m.defaults, actor)
}

func (m *Manager) persistLocked() error {
	if m.path == "" {
		return nil
	}
	data := fileData{Version: m.version, Current: &m.current, History: m.history}
	file := store.New[fileData](m.path)
	if err := file.Save(data); err != nil {
		return fmt.Errorf("settings: persist: %w", err)
	}
	return nil
}

// Merge overlays runtime settings onto a freshly loaded config file. This is
// used at startup so persisted overrides win over config.server.yaml.
func Merge(base, override model.Settings) model.Settings { return override }

// Exported for tests and the panel preview endpoint.
func (m *Manager) Defaults() model.Settings { return m.defaults }

// DecodeOverride parses and validates a JSON settings object (full settings
// object, not a patch, to keep semantics simple and auditable).
func DecodeOverride(data []byte) (model.Settings, error) {
	var s model.Settings
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return model.Settings{}, fmt.Errorf("settings: invalid JSON: %w", err)
	}
	if err := s.Validate(); err != nil {
		return model.Settings{}, err
	}
	return s, nil
}
