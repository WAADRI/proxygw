// Package rules persists ACL rules and sticky blacklist rules in rules.json.
package rules

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"

	"proxygw/internal/model"
	"proxygw/internal/store"
)

// File is the on-disk representation of rules.json.
type File struct {
	ACL    []model.ACLRule    `json:"acl"`
	Sticky []model.StickyRule `json:"sticky"`
}

// Store is a concurrency safe rule store.
type Store struct {
	mu     sync.RWMutex
	path   string
	data   File
	logger interface {
		Warn(msg string, args ...any)
	}
}

// NewStore loads rules.json (missing file = empty rules).
func NewStore(path string, logger interface {
	Warn(msg string, args ...any)
}) (*Store, error) {
	s := &Store{path: path, logger: logger}
	if path != "" {
		f := store.New[File](path)
		data, warnings, err := f.Load(File{})
		if err != nil {
			return nil, err
		}
		for _, w := range warnings {
			if s.logger != nil {
				s.logger.Warn(w)
			}
		}
		s.data = data
	}
	if err := validateACL(s.data.ACL); err != nil {
		return nil, fmt.Errorf("rules: invalid acl: %w", err)
	}
	if err := validateSticky(s.data.Sticky); err != nil {
		return nil, fmt.Errorf("rules: invalid sticky rules: %w", err)
	}
	return s, nil
}

// ACL returns a copy of the ACL rules sorted by order.
func (s *Store) ACL() []model.ACLRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.ACLRule, len(s.data.ACL))
	copy(out, s.data.ACL)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Order < out[j].Order })
	return out
}

// Sticky returns a copy of the sticky blacklist rules.
func (s *Store) Sticky() []model.StickyRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.StickyRule, len(s.data.Sticky))
	copy(out, s.data.Sticky)
	return out
}

// SetACL replaces the full ACL rule set after validation.
func (s *Store) SetACL(list []model.ACLRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateACL(list); err != nil {
		return err
	}
	prev := s.data.ACL
	s.data.ACL = list
	if err := s.persistLocked(); err != nil {
		s.data.ACL = prev
		return err
	}
	return nil
}

// SetSticky replaces the full sticky rule set after validation.
func (s *Store) SetSticky(list []model.StickyRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateSticky(list); err != nil {
		return err
	}
	prev := s.data.Sticky
	s.data.Sticky = list
	if err := s.persistLocked(); err != nil {
		s.data.Sticky = prev
		return err
	}
	return nil
}

// UpsertACL creates or updates one ACL rule.
func (s *Store) UpsertACL(rule model.ACLRule) (model.ACLRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	candidate := append([]model.ACLRule(nil), s.data.ACL...)
	if rule.ID == "" {
		id, err := newID("acl_")
		if err != nil {
			return model.ACLRule{}, err
		}
		rule.ID = id
		rule.CreatedAt = now
		rule.UpdatedAt = now
		candidate = append(candidate, rule)
	} else {
		found := false
		for i := range candidate {
			if candidate[i].ID == rule.ID {
				rule.CreatedAt = candidate[i].CreatedAt
				rule.UpdatedAt = now
				candidate[i] = rule
				found = true
				break
			}
		}
		if !found {
			return model.ACLRule{}, fmt.Errorf("rules: acl rule %q not found", rule.ID)
		}
	}
	if err := validateACL(candidate); err != nil {
		return model.ACLRule{}, err
	}
	prev := s.data.ACL
	s.data.ACL = candidate
	if err := s.persistLocked(); err != nil {
		s.data.ACL = prev
		return model.ACLRule{}, err
	}
	return rule, nil
}

// DeleteACL removes one ACL rule.
func (s *Store) DeleteACL(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.ACL {
		if s.data.ACL[i].ID == id {
			s.data.ACL = append(s.data.ACL[:i], s.data.ACL[i+1:]...)
			return s.persistLocked()
		}
	}
	return fmt.Errorf("rules: acl rule %q not found", id)
}

// UpsertSticky creates or updates one sticky blacklist rule.
func (s *Store) UpsertSticky(rule model.StickyRule) (model.StickyRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	candidate := append([]model.StickyRule(nil), s.data.Sticky...)
	if rule.ID == "" {
		id, err := newID("st_")
		if err != nil {
			return model.StickyRule{}, err
		}
		rule.ID = id
		rule.CreatedAt = now
		rule.UpdatedAt = now
		candidate = append(candidate, rule)
	} else {
		found := false
		for i := range candidate {
			if candidate[i].ID == rule.ID {
				rule.CreatedAt = candidate[i].CreatedAt
				rule.UpdatedAt = now
				candidate[i] = rule
				found = true
				break
			}
		}
		if !found {
			return model.StickyRule{}, fmt.Errorf("rules: sticky rule %q not found", rule.ID)
		}
	}
	if err := validateSticky(candidate); err != nil {
		return model.StickyRule{}, err
	}
	prev := s.data.Sticky
	s.data.Sticky = candidate
	if err := s.persistLocked(); err != nil {
		s.data.Sticky = prev
		return model.StickyRule{}, err
	}
	return rule, nil
}

// DeleteSticky removes one sticky blacklist rule.
func (s *Store) DeleteSticky(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Sticky {
		if s.data.Sticky[i].ID == id {
			s.data.Sticky = append(s.data.Sticky[:i], s.data.Sticky[i+1:]...)
			return s.persistLocked()
		}
	}
	return fmt.Errorf("rules: sticky rule %q not found", id)
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	f := store.New[File](s.path)
	return f.Save(s.data)
}

func validateACL(list []model.ACLRule) error {
	for i := range list {
		r := &list[i]
		if r.Action != model.ActionAllow && r.Action != model.ActionDeny {
			return fmt.Errorf("acl[%d]: action must be allow or deny, got %q", i, r.Action)
		}
		for _, p := range r.Protocols {
			switch p {
			case model.ProtoHTTP, model.ProtoConnect, model.ProtoSOCKS5, model.ProtoTCP:
			default:
				return fmt.Errorf("acl[%d]: unsupported protocol %q", i, p)
			}
		}
		for _, port := range r.Ports {
			if port == "" {
				return fmt.Errorf("acl[%d]: empty port", i)
			}
		}
	}
	return nil
}

func validateSticky(list []model.StickyRule) error {
	for i := range list {
		r := &list[i]
		if len(r.Target.CIDRs) == 0 && len(r.Target.Domains) == 0 && len(r.NodeGroups) == 0 && len(r.NodeIDs) == 0 {
			return fmt.Errorf("sticky[%d]: rule matches nothing (需要至少一个目标或节点维度)", i)
		}
		if r.Note == "" && r.ID == "" {
			return fmt.Errorf("sticky[%d]: note is required for new rules", i)
		}
	}
	return nil
}

func newID(prefix string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rules: generate id: %w", err)
	}
	return prefix + hex.EncodeToString(b), nil
}
