// Package groups manages node group definitions and membership resolution.
// Membership is (selector match ∪ nodes_add) − nodes_remove as required by the
// specification, and it is the only place where group semantics live.
package groups

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"proxygw/internal/model"
	"proxygw/internal/store"
)

// ErrNotFound is returned when a group id does not exist.
var ErrNotFound = errors.New("groups: not found")

// Store is a concurrency safe group registry persisted as JSON.
type Store struct {
	mu     sync.RWMutex
	path   string
	groups []model.Group
	logger interface {
		Warn(msg string, args ...any)
	}
}

// NewStore loads (or initialises) the group store at path. Empty path means
// memory only (tests).
func NewStore(path string, logger interface {
	Warn(msg string, args ...any)
}) (*Store, error) {
	s := &Store{path: path, logger: logger}
	if path != "" {
		file := store.New[[]model.Group](path)
		groups, warnings, err := file.Load([]model.Group{})
		if err != nil {
			return nil, err
		}
		if s.logger != nil {
			for _, w := range warnings {
				s.logger.Warn(w)
			}
		}
		s.groups = groups
	}
	if err := s.validateAll(s.groups); err != nil {
		return nil, fmt.Errorf("groups: loaded data invalid: %w", err)
	}
	return s, nil
}

// List returns a copy of all groups.
func (s *Store) List() []model.Group {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Group, len(s.groups))
	copy(out, s.groups)
	return out
}

// Get returns one group by id.
func (s *Store) Get(id string) (model.Group, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, g := range s.groups {
		if g.ID == id {
			return g, true
		}
	}
	return model.Group{}, false
}

// GetByName returns one group by name.
func (s *Store) GetByName(name string) (model.Group, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, g := range s.groups {
		if strings.EqualFold(g.Name, name) {
			return g, true
		}
	}
	return model.Group{}, false
}

// Upsert creates or replaces a group. Empty ID means create.
func (s *Store) Upsert(g model.Group) (model.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if err := validateGroup(g, s.groups, g.ID); err != nil {
		return model.Group{}, err
	}
	idx := -1
	for i := range s.groups {
		if s.groups[i].ID == g.ID {
			idx = i
			break
		}
	}
	if g.ID == "" {
		id, err := newID()
		if err != nil {
			return model.Group{}, err
		}
		g.ID = id
		g.CreatedAt = now
		g.UpdatedAt = now
		s.groups = append(s.groups, g)
	} else {
		if idx < 0 {
			return model.Group{}, ErrNotFound
		}
		g.CreatedAt = s.groups[idx].CreatedAt
		g.UpdatedAt = now
		s.groups[idx] = g
	}
	if err := s.persistLocked(); err != nil {
		return model.Group{}, err
	}
	return g, nil
}

// Delete removes a group.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.groups {
		if s.groups[i].ID == id {
			s.groups = append(s.groups[:i], s.groups[i+1:]...)
			return s.persistLocked()
		}
	}
	return ErrNotFound
}

// ReplaceAll validates and stores a complete group list (used by import/restore).
func (s *Store) ReplaceAll(in []model.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateAll(in); err != nil {
		return err
	}
	s.groups = in
	return s.persistLocked()
}

// ForNode returns the ids of all groups this node belongs to.
func (s *Store) ForNode(n *model.Node) []string {
	if n == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for i := range s.groups {
		g := &s.groups[i]
		if g.Excluded(n.ID) {
			continue
		}
		if g.Matches(n) || g.Contains(n.ID) {
			out = append(out, g.ID)
		}
	}
	sort.Strings(out)
	return out
}

// Candidates resolves the union of the requested groups against the full node
// list. An empty group list means "all nodes". Unknown group ids contribute
// nothing, which combined with an empty result yields fail-closed behaviour in
// the proxy layer (503, never fallback to all nodes).
func (s *Store) Candidates(groupIDs []string, nodes []*model.Node) []*model.Node {
	if len(groupIDs) == 0 {
		out := make([]*model.Node, 0, len(nodes))
		out = append(out, nodes...)
		return out
	}
	wanted := make(map[string]bool, len(groupIDs))
	for _, id := range groupIDs {
		wanted[id] = true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]bool, len(nodes))
	out := make([]*model.Node, 0, len(nodes))
	for _, n := range nodes {
		if n == nil || seen[n.ID] {
			continue
		}
		perNode := s.membershipsLocked(n)
		hit := false
		for _, gid := range perNode {
			if wanted[gid] {
				hit = true
				break
			}
		}
		if hit {
			seen[n.ID] = true
			out = append(out, n)
		}
	}
	return out
}

// membershipsLocked returns the node's groups; caller holds lock.
func (s *Store) membershipsLocked(n *model.Node) []string {
	var out []string
	for i := range s.groups {
		g := &s.groups[i]
		if g.Excluded(n.ID) {
			continue
		}
		if g.Matches(n) || g.Contains(n.ID) {
			out = append(out, g.ID)
		}
	}
	return out
}

// Resolver returns a function suitable for registry.SetGroupsResolver.
func (s *Store) Resolver() func(*model.Node) []string {
	return func(n *model.Node) []string { return s.ForNode(n) }
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	file := store.New[[]model.Group](s.path)
	if err := file.Save(s.groups); err != nil {
		return err
	}
	return nil
}

func (s *Store) validateAll(list []model.Group) error {
	for i := range list {
		if err := validateGroup(list[i], list[:i], list[i].ID); err != nil {
			return err
		}
	}
	return nil
}

// validateGroup checks one group. selfID is excluded from the duplicate-name
// check (empty when creating).
func validateGroup(g model.Group, existing []model.Group, selfID string) error {
	if strings.TrimSpace(g.Name) == "" {
		return fieldErr("name", "must not be empty")
	}
	if len(g.Name) > 128 {
		return fieldErr("name", "must be at most 128 bytes")
	}
	for _, other := range existing {
		if other.ID == selfID && selfID != "" {
			continue
		}
		if strings.EqualFold(other.Name, g.Name) {
			return fieldErr("name", "duplicate group name %q", g.Name)
		}
	}
	for name, values := range map[string][]string{
		"match.tags_any": g.Match.TagsAny, "match.regions_any": g.Match.RegionsAny,
		"nodes_add": g.NodesAdd, "nodes_remove": g.NodesRemove,
	} {
		for _, v := range values {
			if strings.TrimSpace(v) == "" {
				return fieldErr(name, "must not contain empty values")
			}
		}
	}
	return nil
}

func newID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("groups: generate id: %w", err)
	}
	return "g_" + hex.EncodeToString(b), nil
}

func fieldErr(field, format string, args ...any) error {
	return fmt.Errorf("groups: %s: %s", field, fmt.Sprintf(format, args...))
}
