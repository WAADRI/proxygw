package acl

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"proxygw/internal/model"
)

// representativeIP returns a concrete address inside cidr: the network address
// for a host route, otherwise the network address plus one.
func representativeIP(t *testing.T, cidr string) net.IP {
	t.Helper()
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	// ParseCIDR may return IPv4 addresses in 16-byte form; normalize the family
	// before masking so the result is a well formed address.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	} else {
		ip = ip.To16()
	}
	out := make(net.IP, len(ip))
	copy(out, ip.Mask(n.Mask))
	ones, bits := n.Mask.Size()
	if ones < bits {
		for i := len(out) - 1; i >= 0; i-- {
			out[i]++
			if out[i] != 0 {
				break
			}
		}
	}
	return out
}

func TestForcedDenyListExhaustive(t *testing.T) {
	e := newEngine(t, Options{})
	list := e.ForcedDenies()
	if len(list) == 0 {
		t.Fatal("ForcedDenies() is empty")
	}

	// The panel list must advertise every baseline category.
	wantNames := []string{
		"cloud_metadata", "loopback", "private_network", "unique_local_ipv6",
		"link_local", "unspecified", "cgnat", "loopback_hostname", "high_risk_ports",
	}
	have := map[string]bool{}
	for _, fr := range list {
		have[fr.Name] = true
		if fr.Name == "" || fr.Reason == "" {
			t.Fatalf("forced rule %+v has empty name or reason", fr)
		}
		if len(fr.CIDRs) == 0 && len(fr.Ports) == 0 && fr.Name != "loopback_hostname" {
			t.Fatalf("forced rule %q has no CIDRs and no ports", fr.Name)
		}
	}
	for _, name := range wantNames {
		if !have[name] {
			t.Fatalf("ForcedDenies() misses %q: %+v", name, list)
		}
	}

	// Every advertised CIDR must actually be denied by the named forced rule.
	for _, fr := range list {
		for _, cidr := range fr.CIDRs {
			target := mkTarget(model.ProtoConnect, representativeIP(t, cidr).String(), 443, "")
			requireDenied(t, e, target, true, fr.Name)
		}
		for _, portText := range fr.Ports {
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatalf("forced rule %q has non-numeric port %q", fr.Name, portText)
			}
			target := mkTarget(model.ProtoHTTP, "example.com", port, "")
			requireDenied(t, e, target, true, fr.Name)
		}
		if fr.Name == "loopback_hostname" {
			requireDenied(t, e, mkTarget(model.ProtoHTTP, "localhost", 8080, ""), true, fr.Name)
		}
	}
}

// TestForcedSpotChecks pins the exact entries required by the specification,
// including the cloud metadata endpoint and the high risk port list.
func TestForcedSpotChecks(t *testing.T) {
	e := newEngine(t, Options{})
	cases := []struct {
		name string
		host string
		port int
		rule string
	}{
		{"cloud metadata v4", "169.254.169.254", 80, "cloud_metadata"},
		{"cloud metadata v6", "fe80::a9fe:a9fe", 80, "cloud_metadata"},
		{"cloud metadata mapped v6", "::ffff:169.254.169.254", 80, "cloud_metadata"},
		{"loopback v4 start", "127.0.0.0", 80, "loopback"},
		{"loopback v4 end", "127.255.255.255", 80, "loopback"},
		{"loopback v6", "::1", 80, "loopback"},
		{"loopback mapped v6", "::ffff:127.0.0.1", 80, "loopback"},
		{"private 10", "10.0.0.1", 443, "private_network"},
		{"private 172.16 start", "172.16.0.1", 443, "private_network"},
		{"private 172.31 end", "172.31.255.255", 443, "private_network"},
		{"private 192.168", "192.168.1.1", 443, "private_network"},
		{"unique local fc00", "fc00::1", 443, "unique_local_ipv6"},
		{"unique local fdff", "fdff:ffff::1", 443, "unique_local_ipv6"},
		{"link local v4", "169.254.1.1", 443, "link_local"},
		{"link local v6", "fe80::1", 443, "link_local"},
		{"unspecified v4", "0.0.0.1", 443, "unspecified"},
		{"unspecified v6", "::", 443, "unspecified"},
		{"cgnat start", "100.64.0.1", 443, "cgnat"},
		{"cgnat end", "100.127.255.254", 443, "cgnat"},
		{"localhost name", "localhost", 8080, "loopback_hostname"},
		{"localhost subdomain", "agent.localhost", 8080, "loopback_hostname"},
		{"localhost upper case", "LOCALHOST", 8080, "loopback_hostname"},
		{"localhost trailing dot", "localhost.", 8080, "loopback_hostname"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireDenied(t, e, mkTarget(model.ProtoConnect, tc.host, tc.port, ""), true, tc.rule)
		})
	}

	// Required high risk ports, on any target and protocol.
	for _, port := range []int{25, 135, 139, 445, 6379} {
		for _, proto := range []string{model.ProtoHTTP, model.ProtoConnect, model.ProtoSOCKS5, model.ProtoTCP} {
			for _, host := range []string{"example.com", "8.8.8.8"} {
				target := mkTarget(proto, host, port, "")
				requireDenied(t, e, target, true, "high_risk_ports")
			}
		}
	}
}

// TestForcedDenyCannotBeOverridden proves that user allow rules (including a
// catch-all rule) can never bypass the forced list.
func TestForcedDenyCannotBeOverridden(t *testing.T) {
	e := newEngineWithDefault(t, model.ActionDeny)
	mustSetRules(t, e,
		model.ACLRule{ID: "allow-all", Order: 1, Action: model.ActionAllow},
		model.ACLRule{ID: "allow-metadata", Order: 2, Domains: []string{"169.254.169.254"}, Action: model.ActionAllow},
		model.ACLRule{ID: "allow-loopback", Order: 3, Domains: []string{"127.0.0.1", "localhost"}, Action: model.ActionAllow},
		model.ACLRule{ID: "allow-redis", Order: 4, Domains: []string{"example.com"}, Ports: []string{"6379"}, Action: model.ActionAllow},
	)
	requireDenied(t, e, mkTarget(model.ProtoHTTP, "169.254.169.254", 80, ""), true, "cloud_metadata")
	requireDenied(t, e, mkTarget(model.ProtoHTTP, "127.0.0.1", 80, ""), true, "loopback")
	requireDenied(t, e, mkTarget(model.ProtoHTTP, "localhost", 80, ""), true, "loopback_hostname")
	requireDenied(t, e, mkTarget(model.ProtoHTTP, "example.com", 6379, ""), true, "high_risk_ports")
	requireDenied(t, e, mkTarget(model.ProtoHTTP, "10.1.2.3", 80, ""), true, "private_network")
	// The catch-all allow rule still applies to safe targets.
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "example.com", 443, ""))
	// Explain marks such decisions as forced.
	d := e.Explain(mkTarget(model.ProtoHTTP, "example.com", 6379, ""))
	if d.Allowed || !d.Forced || d.RuleID != "high_risk_ports" {
		t.Fatalf("Explain = %+v, want forced high_risk_ports", d)
	}
}

// TestForcedBoundaryAddressesAllowed checks addresses just outside the forced
// ranges are not denied by the baseline.
func TestForcedBoundaryAddressesAllowed(t *testing.T) {
	e := newEngine(t, Options{})
	for _, host := range []string{
		"11.0.0.1",           // outside 10/8
		"172.32.0.1",         // outside 172.16/12
		"192.169.0.1",        // outside 192.168/16
		"fb00::1",            // outside fc00::/7
		"169.253.0.1",        // outside 169.254/16
		"169.255.0.1",        // outside 169.254/16
		"100.128.0.1",        // outside 100.64/10
		"1.2.3.4",            // outside 0.0.0.0/8
		"8.8.8.8",            // public
		"2001:db8::1",        // documentation range, not forced
		"example.com",        // domain names are not resolved here
		"localhost.evil.com", // not the localhost suffix
	} {
		target := mkTarget(model.ProtoConnect, host, 443, "")
		requireAllowed(t, e, target)
	}
}

// TestHostLiteralNormalizationAgainstForcedList verifies that bracketed,
// trailing-dot and zoned IP forms cannot slip past the forced IP list.
func TestHostLiteralNormalizationAgainstForcedList(t *testing.T) {
	e := newEngine(t, Options{})
	cases := []struct {
		host string
		rule string
	}{
		{"127.0.0.1.", "loopback"},
		{"[::1]", "loopback"},
		{"[::ffff:127.0.0.1]", "loopback"},
		{"fe80::1%eth0", "link_local"},
		{"[fe80::1%eth0]", "link_local"},
		{"10.0.0.1.", "private_network"},
	}
	for _, tc := range cases {
		requireDenied(t, e, mkTarget(model.ProtoConnect, tc.host, 443, ""), true, tc.rule)
	}
}

// TestDomainTargetsAreNotResolvedByDesign documents the G.1/G.2 boundary: the
// engine never performs DNS, so a domain target is only matched literally and
// the node side has to enforce the address checks after resolution.
func TestDomainTargetsAreNotResolvedByDesign(t *testing.T) {
	e := newEngine(t, Options{})
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "metadata.google.internal", 80, ""))
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "example.com", 80, ""))
}

func TestForcedDeniesReturnsCopies(t *testing.T) {
	e := newEngine(t, Options{})
	list := e.ForcedDenies()
	first := list[0]
	if len(first.CIDRs) == 0 {
		t.Fatalf("first forced rule has no CIDRs: %+v", first)
	}
	originalCIDR := first.CIDRs[0]
	first.CIDRs[0] = "0.0.0.0/0"
	first.Name = "tampered"
	first.Reason = "tampered"

	again := e.ForcedDenies()
	if again[0].CIDRs[0] != originalCIDR || again[0].Name == "tampered" || again[0].Reason == "tampered" {
		t.Fatalf("ForcedDenies() mutation leaked: %+v", again[0])
	}
}

func TestTestEscapeHatchOptions(t *testing.T) {
	e := newEngine(t, Options{AllowLoopbackTargets: true})
	// Loopback, private, link-local, unique-local, loopback host names and the
	// high risk port list are exempted for in-process tests.
	requireAllowed(t, e, mkTarget(model.ProtoConnect, "127.0.0.1", 8080, ""))
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "localhost", 8080, ""))
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "10.1.2.3", 80, ""))
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "169.254.1.1", 80, ""))
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "fc00::1", 80, ""))
	requireAllowed(t, e, mkTarget(model.ProtoHTTP, "example.com", 6379, ""))
	// Security critical baseline entries stay denied even with the switch on.
	requireDenied(t, e, mkTarget(model.ProtoHTTP, "169.254.169.254", 80, ""), true, "cloud_metadata")
	requireDenied(t, e, mkTarget(model.ProtoHTTP, "0.0.0.1", 80, ""), true, "unspecified")
	requireDenied(t, e, mkTarget(model.ProtoHTTP, "100.64.0.1", 80, ""), true, "cgnat")

	// User rules and the default action still apply while the switch is active.
	mustSetRules(t, e, model.ACLRule{ID: "deny-example", Order: 1, Domains: []string{"example.com"}, Action: model.ActionDeny})
	requireDenied(t, e, mkTarget(model.ProtoHTTP, "example.com", 443, ""), false, "deny-example")

	e2 := newEngineWithDefault(t, model.ActionDeny)
	// e2 was built with the escape hatch off, so loopback is still forced.
	requireDenied(t, e2, mkTarget(model.ProtoConnect, "127.0.0.1", 8080, ""), true, "loopback")
}

func TestTestEscapeHatchEnvironment(t *testing.T) {
	for _, value := range []string{"1", "true", "TRUE", " 1 "} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(envLoopback, value)
			e := New(Options{})
			requireAllowed(t, e, mkTarget(model.ProtoConnect, "127.0.0.1", 8080, ""))
			requireAllowed(t, e, mkTarget(model.ProtoHTTP, "example.com", 6379, ""))
			requireDenied(t, e, mkTarget(model.ProtoHTTP, "169.254.169.254", 80, ""), true, "cloud_metadata")
		})
	}
	for _, value := range []string{"", "0", "false", "no"} {
		t.Run("off-"+value, func(t *testing.T) {
			t.Setenv(envLoopback, value)
			e := New(Options{})
			requireDenied(t, e, mkTarget(model.ProtoConnect, "127.0.0.1", 8080, ""), true, "loopback")
		})
	}
}

func TestTestEscapeHatchReadAtNew(t *testing.T) {
	t.Setenv(envLoopback, "1")
	e := New(Options{})
	// Changing the environment after New must not change the engine snapshot.
	t.Setenv(envLoopback, "")
	requireAllowed(t, e, mkTarget(model.ProtoConnect, "127.0.0.1", 8080, ""))
}

// TestForcedListNamesUniqueAndReasonsReadable is a panel requirement check.
func TestForcedListNamesUniqueAndReasonsReadable(t *testing.T) {
	e := newEngine(t, Options{})
	seen := map[string]bool{}
	for _, fr := range e.ForcedDenies() {
		if seen[fr.Name] {
			t.Fatalf("duplicate forced rule name %q", fr.Name)
		}
		seen[fr.Name] = true
		if strings.TrimSpace(fr.Reason) == "" {
			t.Fatalf("forced rule %q has empty reason", fr.Name)
		}
		for _, cidr := range fr.CIDRs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				t.Fatalf("forced rule %q has invalid CIDR %q", fr.Name, cidr)
			}
		}
		for _, port := range fr.Ports {
			if _, err := parsePortRange(port); err != nil {
				t.Fatalf("forced rule %q has invalid port %q", fr.Name, port)
			}
		}
	}
}
