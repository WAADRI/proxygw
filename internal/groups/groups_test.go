package groups

import (
	"os"
	"path/filepath"
	"testing"

	"proxygw/internal/model"
)

func node(id string, tags []string, region, country string) *model.Node {
	return &model.Node{ID: id, Tags: tags, Region: region, Geo: model.Geo{Country: country}}
}

func TestMembershipSelectorsAndExplicitLists(t *testing.T) {
	s, err := NewStore("", nil)
	if err != nil {
		t.Fatal(err)
	}
	g1, err := s.Upsert(model.Group{Name: "us", Match: model.GroupMatch{TagsAny: []string{"us-residential"}}})
	if err != nil {
		t.Fatal(err)
	}
	g2, err := s.Upsert(model.Group{Name: "jp", Match: model.GroupMatch{RegionsAny: []string{"JP"}}})
	if err != nil {
		t.Fatal(err)
	}
	g3, err := s.Upsert(model.Group{
		Name:        "explicit",
		NodesAdd:    []string{"n1", "n2"},
		NodesRemove: []string{"n2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	n1 := node("n1", []string{"Us-Residential"}, "us-west", "US")
	n2 := node("n2", nil, "jp-tokyo", "JP")
	n3 := node("n3", nil, "unknown", "")
	if nodeInSlice(s.ForNode(n1), g1.ID) != true {
		t.Fatalf("n1 should match tag selector; got %v", s.ForNode(n1))
	}
	if nodeInSlice(s.ForNode(n2), g2.ID) != true {
		t.Fatalf("n2 should match region selector; got %v", s.ForNode(n2))
	}
	if nodeInSlice(s.ForNode(n1), g3.ID) != true || nodeInSlice(s.ForNode(n3), g3.ID) {
		t.Fatalf("nodes_add/nodes_remove not applied: n1=%v n3=%v", s.ForNode(n1), s.ForNode(n3))
	}
	// Explicit remove beats selector match for g3 only.
	excluded := node("n2", nil, "", "")
	if nodeInSlice(s.ForNode(excluded), g3.ID) {
		t.Fatal("n2 explicitly removed must not be member of g3")
	}
}

func TestCandidatesFailClosedSemantics(t *testing.T) {
	s, _ := NewStore("", nil)
	g1, _ := s.Upsert(model.Group{Name: "g1", Match: model.GroupMatch{TagsAny: []string{"a"}}})
	g2, _ := s.Upsert(model.Group{Name: "g2", Match: model.GroupMatch{TagsAny: []string{"b"}}})
	nodes := []*model.Node{node("n1", []string{"a"}, "", ""), node("n2", []string{"b"}, "", "")}
	got := s.Candidates([]string{g1.ID}, nodes)
	if len(got) != 1 || got[0].ID != "n1" {
		t.Fatalf("candidates = %v", got)
	}
	both := s.Candidates([]string{g1.ID, g2.ID}, nodes)
	if len(both) != 2 {
		t.Fatalf("union candidates = %v", both)
	}
	if got := s.Candidates([]string{"missing"}, nodes); len(got) != 0 {
		t.Fatalf("unknown group must yield empty candidates, got %v", got)
	}
	// Empty credential group list means all nodes.
	if got := s.Candidates(nil, nodes); len(got) != 2 {
		t.Fatalf("empty groups should mean all nodes, got %v", got)
	}
}

func TestValidationAndPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "groups.json")
	s, err := NewStore(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Upsert(model.Group{Name: ""}); err == nil {
		t.Fatal("empty name must fail")
	}
	g, err := s.Upsert(model.Group{Name: "pool"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Upsert(model.Group{Name: "POOL"}); err == nil {
		t.Fatal("duplicate name (case insensitive) must fail")
	}
	if err := s.Delete(g.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(g.ID); err == nil {
		t.Fatal("delete missing must fail")
	}
	// Persistence round trip.
	if _, err := s.Upsert(model.Group{Name: "persisted", Match: model.GroupMatch{TagsAny: []string{"x"}}}); err != nil {
		t.Fatal(err)
	}
	s2, err := NewStore(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	list := s2.List()
	if len(list) != 1 || list[0].Name != "persisted" {
		t.Fatalf("reloaded groups = %+v", list)
	}
	// Remove the temp file to make sure a broken store fails clearly.
	if err := os.WriteFile(path, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	// backup exists from previous save, so load may recover; corrupt both.
	if err := os.WriteFile(path+".bak", []byte("{bad too"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(path, nil); err == nil {
		t.Fatal("corrupt store must fail")
	}
}

func TestResolver(t *testing.T) {
	s, _ := NewStore("", nil)
	if _, err := s.Upsert(model.Group{Name: "a", Match: model.GroupMatch{TagsAny: []string{"t"}}}); err != nil {
		t.Fatal(err)
	}
	fn := s.Resolver()
	got := fn(node("n", []string{"t"}, "", ""))
	if len(got) != 1 {
		t.Fatalf("resolver = %v", got)
	}
}

func nodeInSlice(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
