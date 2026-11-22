package config

import "testing"

func TestNormalizePanelDomain(t *testing.T) {
	cases := []struct {
		raw  string
		want string
		bad  bool
	}{
		{raw: "", want: ""},
		{raw: "  ", want: ""},
		{raw: "panel.example.test", want: "panel.example.test"},
		{raw: "Panel.Example.Test.", want: "panel.example.test"},
		{raw: "panel.example.test:443", want: "panel.example.test"},
		{raw: "127.0.0.1", want: "127.0.0.1"},
		{raw: "[2001:db8::1]:443", want: "2001:db8::1"},
		{raw: "https://panel.example.test", bad: true},
		{raw: "panel.example.test/path", bad: true},
		{raw: "*.example.test", bad: true},
		{raw: "bad_host.example.test", bad: true},
		{raw: "-bad.example.test", bad: true},
		{raw: "panel.example.test:99999", bad: true},
	}
	for _, tc := range cases {
		got, err := NormalizePanelDomain(tc.raw)
		if tc.bad {
			if err == nil {
				t.Fatalf("NormalizePanelDomain(%q) = %q, want error", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("NormalizePanelDomain(%q): %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizePanelDomain(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestServerPanelDomainValidation(t *testing.T) {
	cfg := DefaultServerConfig()
	cfg.Server.PanelDomain = " Node.Panel.Example.:443 "
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.Server.PanelDomain != "node.panel.example" {
		t.Fatalf("PanelDomain = %q, want normalized node.panel.example", cfg.Server.PanelDomain)
	}

	cfg = DefaultServerConfig()
	cfg.Server.PanelDomain = "https://node.panel.example"
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate accepted a panel_domain with a URL scheme")
	}
}
