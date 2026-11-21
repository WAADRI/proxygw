// Package store persists runtime objects as JSON files. Writes are crash safe
// (temp file + fsync + atomic rename) and the previous good version is kept as
// "<path>.bak" so a corrupted file falls back to the last known good copy.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// JSON is a concurrency safe JSON document at a fixed path.
type JSON[T any] struct {
	mu   sync.Mutex
	path string
}

// New returns a store for the given path.
func New[T any](path string) *JSON[T] { return &JSON[T]{path: path} }

// Path returns the backing file path.
func (s *JSON[T]) Path() string { return s.path }

// BackupPath returns the backup file path.
func (s *JSON[T]) BackupPath() string { return s.path + ".bak" }

// Load reads the document. Missing files return def (and no error). A corrupted
// main file falls back to the .bak copy and reports a warning. When both copies
// are unusable the error is returned so the caller can decide to fail closed.
func (s *JSON[T]) Load(def T) (value T, warnings []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked(def)
}

func (s *JSON[T]) loadLocked(def T) (T, []string, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			bakData, bakErr := os.ReadFile(s.BackupPath())
			if bakErr != nil {
				return def, nil, nil
			}
			var v T
			if jsonErr := json.Unmarshal(bakData, &v); jsonErr != nil {
				return def, nil, fmt.Errorf("store: %s missing and backup %s unreadable: %w", s.path, s.BackupPath(), jsonErr)
			}
			return v, []string{fmt.Sprintf("存储告警：主文件 %s 缺失，已从备份恢复", s.path)}, nil
		}
		return def, nil, fmt.Errorf("store: read %s: %w", s.path, err)
	}
	var v T
	if jsonErr := json.Unmarshal(data, &v); jsonErr != nil {
		bakData, bakErr := os.ReadFile(s.BackupPath())
		if bakErr == nil {
			var bv T
			if bakJSONErr := json.Unmarshal(bakData, &bv); bakJSONErr == nil {
				return bv, []string{fmt.Sprintf("存储告警：%s 解析失败(%v)，已回退到备份 %s", s.path, jsonErr, s.BackupPath())}, nil
			}
		}
		return def, nil, fmt.Errorf("store: parse %s: %w", s.path, jsonErr)
	}
	return v, nil, nil
}

// Save atomically writes v and preserves the previous file as .bak.
func (s *JSON[T]) Save(v T) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode %s: %w", s.path, err)
	}
	data = append(data, '\n')
	// Snapshot the previous good copy first. If this step fails we refuse to
	// overwrite the main file: a failed backup must not destroy the only copy.
	if prev, err := os.ReadFile(s.path); err == nil {
		if err := WriteFileAtomic(s.BackupPath(), prev, 0o600); err != nil {
			return fmt.Errorf("store: write backup for %s: %w", s.path, err)
		}
	}
	if err := WriteFileAtomic(s.path, data, 0o600); err != nil {
		return err
	}
	return nil
}

// Update applies fn to the current document and stores the result atomically.
func (s *JSON[T]) Update(def T, fn func(*T) error) (T, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, warnings, err := s.loadLocked(def)
	if err != nil {
		return def, warnings, err
	}
	if err := fn(&v); err != nil {
		return def, warnings, err
	}
	if err := s.saveLocked(v); err != nil {
		return def, warnings, err
	}
	return v, warnings, nil
}

func (s *JSON[T]) saveLocked(v T) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode %s: %w", s.path, err)
	}
	data = append(data, '\n')
	if prev, err := os.ReadFile(s.path); err == nil {
		if err := WriteFileAtomic(s.BackupPath(), prev, 0o600); err != nil {
			return fmt.Errorf("store: write backup for %s: %w", s.path, err)
		}
	}
	return WriteFileAtomic(s.path, data, 0o600)
}

// WriteFileAtomic writes data to path through a temporary file in the same
// directory, fsyncs it, then renames it over the destination.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("store: create dir %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("store: create temp for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("store: write temp for %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("store: fsync temp for %s: %w", path, err)
	}
	if err := tmp.Chmod(perm); err != nil {
		cleanup()
		return fmt.Errorf("store: chmod temp for %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("store: close temp for %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("store: rename %s: %w", path, err)
	}
	syncDir(dir)
	return nil
}

// syncDir best-effort fsyncs a directory entry. Windows does not support
// fsync on directories; errors are ignored by design.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}

// AppendLine appends one JSON encoded record plus '\n' to path. It fsyncs the
// file so audit records survive a crash.
func AppendLine(path string, record any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("store: create dir %s: %w", dir, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("store: open %s: %w", path, err)
	}
	defer f.Close()
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("store: encode record: %w", err)
	}
	data = append(data, '\n')
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("store: append %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("store: fsync %s: %w", path, err)
	}
	return nil
}
