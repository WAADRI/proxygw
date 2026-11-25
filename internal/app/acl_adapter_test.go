package app

import (
	"testing"

	"proxygw/internal/acl"
	"proxygw/internal/model"
)

func TestACLAdapterForwardsRouteGroups(t *testing.T) {
	engine := acl.New(acl.Options{})
	if err := engine.SetRules([]model.ACLRule{{
		ID:         "route-cn",
		Order:      1,
		Domains:    []string{"www.cisa.gov"},
		Action:     model.ActionRoute,
		NodeGroups: []string{"cn-edge"},
	}}); err != nil {
		t.Fatalf("SetRules: %v", err)
	}
	adapter := &aclAdapter{engine: engine}
	groups, err := adapter.ForcedGroups(model.RequestTarget{
		Protocol: model.ProtoSOCKS5,
		Host:     "www.cisa.gov",
		Port:     80,
	})
	if err != nil {
		t.Fatalf("ForcedGroups: %v", err)
	}
	if len(groups) != 1 || groups[0] != "cn-edge" {
		t.Fatalf("forced groups = %v", groups)
	}
}
