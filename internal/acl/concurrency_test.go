package acl

import (
	"sync"
	"testing"

	"proxygw/internal/model"
)

// TestConcurrentCheckSetRulesExplain exercises the engine concurrently under
// the race detector: readers must never see a partially compiled rule set and
// failed SetRules calls must not corrupt the current snapshot.
func TestConcurrentCheckSetRulesExplain(t *testing.T) {
	e := newEngine(t, Options{
		AllowLoopbackTargets: true,
		DefaultAction:        func() string { return model.ActionAllow },
	})
	rulesA := []model.ACLRule{
		{ID: "deny-a", Order: 1, Domains: []string{"a.example.com"}, Action: model.ActionDeny},
	}
	rulesB := []model.ACLRule{
		{ID: "deny-b", Order: 1, Domains: []string{"b.example.com"}, Ports: []string{"8080-8090"}, Action: model.ActionDeny},
	}
	invalid := []model.ACLRule{
		{ID: "broken", Order: 1, SrcCIDRs: []string{"10.0.0.0/33"}, Action: model.ActionAllow},
	}
	mustSetRules(t, e, rulesA...)

	targets := []model.RequestTarget{
		mkTarget(model.ProtoHTTP, "a.example.com", 443, "203.0.113.5"),
		mkTarget(model.ProtoHTTP, "b.example.com", 8085, "203.0.113.5"),
		mkTarget(model.ProtoHTTP, "b.example.com", 443, "203.0.113.5"),
		mkTarget(model.ProtoConnect, "127.0.0.1", 8080, "127.0.0.1"),
		mkTarget(model.ProtoSOCKS5, "", 1, ""),
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				for _, target := range targets {
					_ = e.Check(target)
					_ = e.Explain(target)
				}
				_ = e.Rules()
				_ = e.ForcedDenies()
			}
		}()
	}
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 150; i++ {
				var err error
				if (w+i)%2 == 0 {
					err = e.SetRules(rulesA)
				} else {
					err = e.SetRules(rulesB)
				}
				if err != nil {
					t.Errorf("concurrent SetRules: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			if err := e.SetRules(invalid); err == nil {
				t.Error("concurrent SetRules with invalid rules = nil, want error")
				return
			}
		}
	}()
	wg.Wait()

	// The last valid SetRules in the loop left a coherent snapshot behind.
	rules := e.Rules()
	if len(rules) != 1 || (rules[0].ID != "deny-a" && rules[0].ID != "deny-b") {
		t.Fatalf("Rules() after concurrent updates = %+v, want one valid snapshot", rules)
	}
}
