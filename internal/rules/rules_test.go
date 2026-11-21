package rules

import (
	"path/filepath"
	"testing"

	"proxygw/internal/model"
)

func TestACLCRUDAndValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	s, err := NewStore(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.UpsertACL(model.ACLRule{Order: 10, Domains: []string{"*.bank.com"}, Action: model.ActionDeny, Note: "bank"})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID == "" || r.CreatedAt.IsZero() {
		t.Fatalf("rule ids not filled: %+v", r)
	}
	r.Action = model.ActionAllow
	upd, err := s.UpsertACL(r)
	if err != nil {
		t.Fatal(err)
	}
	if upd.CreatedAt != r.CreatedAt {
		t.Fatal("created_at must be preserved")
	}
	if got := s.ACL(); len(got) != 1 || got[0].Action != model.ActionAllow {
		t.Fatalf("acl = %+v", got)
	}
	if err := s.DeleteACL(r.ID); err != nil {
		t.Fatal(err)
	}
	if len(s.ACL()) != 0 {
		t.Fatal("delete failed")
	}
	if _, err := s.UpsertACL(model.ACLRule{Action: "bogus"}); err == nil {
		t.Fatal("invalid action must be rejected")
	}
	if _, err := s.UpsertACL(model.ACLRule{Action: model.ActionAllow, Protocols: []string{"ftp"}}); err == nil {
		t.Fatal("invalid protocol must be rejected")
	}
	// Persistence round trip through the same file.
	if _, err := s.UpsertACL(model.ACLRule{Order: 1, Action: model.ActionDeny}); err != nil {
		t.Fatal(err)
	}
	s2, err := NewStore(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.ACL()) != 1 {
		t.Fatalf("reload acl = %+v", s2.ACL())
	}
}

func TestStickyRules(t *testing.T) {
	s, err := NewStore("", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertSticky(model.StickyRule{}); err == nil {
		t.Fatal("empty sticky rule must be rejected")
	}
	r, err := s.UpsertSticky(model.StickyRule{
		Note:   "banks never stick",
		Target: model.TargetSpec{Domains: []string{"*.bank.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Sticky(); len(got) != 1 || got[0].ID != r.ID {
		t.Fatalf("sticky = %+v", got)
	}
	// Node dimension only is valid too.
	if _, err := s.UpsertSticky(model.StickyRule{Note: "residential pool", NodeGroups: []string{"g1"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSticky(r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSticky("missing"); err == nil {
		t.Fatal("delete missing must fail")
	}
}
