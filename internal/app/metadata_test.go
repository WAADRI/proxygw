package app

import (
	"testing"

	"proxygw/internal/model"
)

func TestNodeGeoIPPrefersV4AndFallsBackToV6(t *testing.T) {
	cases := []struct {
		name string
		node model.Node
		want string
	}{
		{"v4", model.Node{EgressIP: model.EgressIP{V4: "203.0.113.4", V6: "2001:db8::4"}}, "203.0.113.4"},
		{"v6-only", model.Node{EgressIP: model.EgressIP{V6: "240d:c000:f020:1400::1"}}, "240d:c000:f020:1400::1"},
		{"empty", model.Node{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nodeGeoIP(tc.node); got != tc.want {
				t.Fatalf("nodeGeoIP = %q, want %q", got, tc.want)
			}
		})
	}
}
