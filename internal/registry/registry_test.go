package registry

import (
	"path/filepath"
	"testing"

	"proxygw/internal/metrics"
	"proxygw/internal/model"
	"proxygw/internal/protocol"
)

// slogLogger is an alias placeholder so the helper signature stays obvious in
// tests that pass nil loggers; registry.New accepts nil.
type slogLogger = struct{}

func meta(nodeID string, plane int, egress string) PlaneMeta {
	return PlaneMeta{
		NodeID:     nodeID,
		PlaneIndex: plane,
		Alias:      nodeID + "-alias",
		Tags:       []string{"tag1", "tag2"},
		Region:     "us",
		Weight:     3,
		Version:    "1.2.3",
		Transport:  "quic",
		EgressV4:   egress,
	}
}

func TestAttachDetachOnlineAndEpoch(t *testing.T) {
	r, err := New(nil, nil, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer r.Close()

	n, epoch, err := r.AttachPlane(meta("node-a", 0, "1.2.3.4"))
	if err != nil {
		t.Fatalf("AttachPlane: %v", err)
	}
	if epoch != 1 {
		t.Fatalf("first epoch = %d, want 1", epoch)
	}
	if !n.Online || n.Planes != 1 || n.EgressIP.V4 != "1.2.3.4" {
		t.Fatalf("unexpected node: %+v", n)
	}
	if n.BreakerState != model.BreakerClosed {
		t.Fatalf("breaker state = %q, want closed", n.BreakerState)
	}
	if n.CreatedAt.IsZero() || n.UpdatedAt.IsZero() || n.LastHeartbeat.IsZero() {
		t.Fatalf("timestamps not populated: %+v", n)
	}
	if r.OnlineCount() != 1 || r.Count() != 1 || r.UniqueEgressCount() != 1 {
		t.Fatalf("counters online=%d total=%d egress=%d", r.OnlineCount(), r.Count(), r.UniqueEgressCount())
	}

	_, epoch2, err := r.AttachPlane(meta("node-a", 1, "1.2.3.4"))
	if err != nil {
		t.Fatalf("AttachPlane plane1: %v", err)
	}
	if epoch2 != 2 {
		t.Fatalf("second epoch = %d, want 2", epoch2)
	}
	n, _ = r.Get("node-a")
	if n.Planes != 2 || !n.Online {
		t.Fatalf("planes = %d online=%v", n.Planes, n.Online)
	}

	r.DetachPlane("node-a", 0)
	n, _ = r.Get("node-a")
	if n.Planes != 1 || !n.Online {
		t.Fatalf("after one detach planes = %d online=%v", n.Planes, n.Online)
	}
	r.DetachPlane("node-a", 1)
	n, _ = r.Get("node-a")
	if n.Planes != 0 || n.Online {
		t.Fatalf("after last detach planes = %d online=%v", n.Planes, n.Online)
	}
	if r.OnlineCount() != 0 || r.Count() != 1 || r.UniqueEgressCount() != 0 {
		t.Fatalf("counters after offline online=%d total=%d egress=%d", r.OnlineCount(), r.Count(), r.UniqueEgressCount())
	}
	// Detaching an unknown plane or node is a no-op.
	r.DetachPlane("node-a", 7)
	r.DetachPlane("missing", 0)

	_, epoch3, err := r.AttachPlane(meta("node-a", 1, "1.2.3.4"))
	if err != nil {
		t.Fatalf("re-attach: %v", err)
	}
	if epoch3 != 3 {
		t.Fatalf("epoch after re-attach = %d, want 3", epoch3)
	}
	if r.Epoch("node-a") != 3 || r.Epoch("missing") != 0 {
		t.Fatalf("Epoch mismatch")
	}
}

func TestDuplicateEgress(t *testing.T) {
	r, _ := New(nil, nil, "")
	defer r.Close()
	if _, _, err := r.AttachPlane(meta("node-a", 0, "1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.AttachPlane(meta("node-b", 0, "1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.AttachPlane(meta("node-c", 0, "5.6.7.8")); err != nil {
		t.Fatal(err)
	}
	a, _ := r.Get("node-a")
	b, _ := r.Get("node-b")
	c, _ := r.Get("node-c")
	if a.DuplicateOf != "" {
		t.Fatalf("canonical node must not be a duplicate: %q", a.DuplicateOf)
	}
	if b.DuplicateOf != "node-a" {
		t.Fatalf("duplicate_of = %q, want node-a", b.DuplicateOf)
	}
	if c.DuplicateOf != "" {
		t.Fatalf("different egress must not be duplicate: %q", c.DuplicateOf)
	}
	if r.UniqueEgressCount() != 2 || r.OnlineCount() != 3 {
		t.Fatalf("unique=%d online=%d", r.UniqueEgressCount(), r.OnlineCount())
	}
	// Once the canonical node goes offline the remaining duplicate becomes
	// canonical and the unique count recomputes.
	r.DetachPlane("node-a", 0)
	b, _ = r.Get("node-b")
	if b.DuplicateOf != "" {
		t.Fatalf("duplicate_of after canonical offline = %q, want empty", b.DuplicateOf)
	}
	if r.UniqueEgressCount() != 2 {
		t.Fatalf("unique egress after detach = %d, want 2", r.UniqueEgressCount())
	}
	// IPv6-only nodes are deduplicated as well.
	if _, _, err := r.AttachPlane(PlaneMeta{NodeID: "v6-a", PlaneIndex: 0, EgressV6: "2001:db8::1"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.AttachPlane(PlaneMeta{NodeID: "v6-b", PlaneIndex: 0, EgressV6: "2001:db8::1"}); err != nil {
		t.Fatal(err)
	}
	v6b, _ := r.Get("v6-b")
	if v6b.DuplicateOf != "v6-a" {
		t.Fatalf("ipv6 duplicate_of = %q, want v6-a", v6b.DuplicateOf)
	}
}

func TestUpdateStats(t *testing.T) {
	r, _ := New(nil, nil, "")
	defer r.Close()
	if _, _, err := r.AttachPlane(meta("node-a", 0, "1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	r.UpdateStats("node-a", protocol.Stats{Inflight: 5, BytesIn: 100, BytesOut: 200, LatencyMS: 100, Transport: "ws", Version: "9.9.9"})
	n, _ := r.Get("node-a")
	if n.Inflight != 5 || n.BytesIn != 100 || n.BytesOut != 200 || n.LatencyEWMA != 100 {
		t.Fatalf("stats not applied: %+v", n)
	}
	if n.Transport != "ws" || n.Version != "9.9.9" {
		t.Fatalf("transport/version not applied: %+v", n)
	}
	r.UpdateStats("node-a", protocol.Stats{Inflight: 2, BytesIn: 50, BytesOut: 60, LatencyMS: 200})
	n, _ = r.Get("node-a")
	wantEWMA := 0.8*100 + 0.2*200
	if n.LatencyEWMA < wantEWMA-0.001 || n.LatencyEWMA > wantEWMA+0.001 {
		t.Fatalf("latency ewma = %v, want %v", n.LatencyEWMA, wantEWMA)
	}
	if n.Inflight != 2 || n.BytesIn != 50 || n.BytesOut != 60 {
		t.Fatalf("stats not replaced: %+v", n)
	}
	// A STATS report may reveal a changed egress IP; duplicates recompute.
	if _, _, err := r.AttachPlane(meta("node-b", 0, "9.9.9.9")); err != nil {
		t.Fatal(err)
	}
	r.UpdateStats("node-b", protocol.Stats{EgressV4: "1.2.3.4"})
	n, _ = r.Get("node-b")
	if n.EgressIP.V4 != "1.2.3.4" || n.EgressIP.Source != "stats" {
		t.Fatalf("egress update: %+v", n.EgressIP)
	}
	if n.DuplicateOf != "node-a" {
		t.Fatalf("duplicate_of after egress change = %q, want node-a", n.DuplicateOf)
	}
	if r.UniqueEgressCount() != 1 {
		t.Fatalf("unique egress = %d, want 1", r.UniqueEgressCount())
	}
	// Unknown nodes are ignored.
	r.UpdateStats("ghost", protocol.Stats{Inflight: 1})
}

func TestUpdateNodeUpdateStatus(t *testing.T) {
	r, _ := New(nil, nil, "")
	defer r.Close()
	if _, _, err := r.AttachPlane(meta("node-u", 0, "1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	r.UpdateNodeUpdate("node-u", protocol.UpdateStatus{
		State:          protocol.UpdateDownloading,
		CurrentVersion: "1.0.7",
		TargetVersion:  "1.0.8",
		Progress:       42,
		Message:        "downloading",
		UpdatedAt:      1234567890000,
	})
	n, _ := r.Get("node-u")
	if n.Update == nil || n.Update.State != protocol.UpdateDownloading ||
		n.Update.TargetVersion != "1.0.8" || n.Update.Progress != 42 {
		t.Fatalf("update status = %+v", n.Update)
	}
	if n.Update.UpdatedAt.UnixMilli() != 1234567890000 {
		t.Fatalf("updated_at = %s", n.Update.UpdatedAt)
	}
}

func TestOverridesAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-overrides.json")
	r, err := New(nil, nil, path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := r.AttachPlane(meta("node-a", 0, "1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateNodeOverride(model.NodeOverride{
		ID: "node-a", Alias: "operator-alias", Region: "jp", ISPLabel: "isp-x",
		Tags: []string{"op"}, Weight: 7, Enabled: false,
	}); err != nil {
		t.Fatalf("UpdateNodeOverride: %v", err)
	}
	n, _ := r.Get("node-a")
	if n.Alias != "operator-alias" || n.Region != "jp" || n.ISPLabel != "isp-x" || n.Weight != 7 || n.Enabled {
		t.Fatalf("override not applied: %+v", n)
	}
	// A node re-reporting its own fields must not steal operator values back.
	if _, _, err := r.AttachPlane(meta("node-a", 1, "1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	n, _ = r.Get("node-a")
	if n.Alias != "operator-alias" || n.Region != "jp" || n.Enabled {
		t.Fatalf("operator override lost on re-attach: %+v", n)
	}
	if err := r.SetEnabled("node-a", true); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}
	n, _ = r.Get("node-a")
	if !n.Enabled {
		t.Fatal("SetEnabled(true) not applied")
	}
	// Unknown node: SetEnabled still persists an override for a later attach.
	if err := r.SetEnabled("later-node", false); err != nil {
		t.Fatalf("SetEnabled unknown node: %v", err)
	}
	if err := r.UpdateNodeOverride(model.NodeOverride{ID: "  "}); err == nil {
		t.Fatal("empty override id must be rejected")
	}
	r.Close()

	// Restart: overrides are reloaded and applied when the node reconnects.
	r2, err := New(nil, nil, path)
	if err != nil {
		t.Fatalf("restart New: %v", err)
	}
	defer r2.Close()
	if _, _, err := r2.AttachPlane(PlaneMeta{NodeID: "node-a", PlaneIndex: 0, Alias: "reported", EgressV4: "1.2.3.4", Weight: 2}); err != nil {
		t.Fatal(err)
	}
	n, _ = r2.Get("node-a")
	if n.Alias != "operator-alias" || !n.Enabled || n.Weight != 7 {
		t.Fatalf("persisted override not restored: %+v", n)
	}
	if _, _, err := r2.AttachPlane(PlaneMeta{NodeID: "later-node", PlaneIndex: 0}); err != nil {
		t.Fatal(err)
	}
	ln, _ := r2.Get("later-node")
	if ln.Enabled {
		t.Fatal("persisted disable for not-yet-seen node not restored")
	}
	if ln.Weight <= 0 {
		t.Fatalf("weight = %d, must stay positive for weighted scheduling", ln.Weight)
	}
}

func TestGroupsResolver(t *testing.T) {
	r, _ := New(nil, nil, "")
	defer r.Close()
	r.SetGroupsResolver(func(n *model.Node) []string {
		if n.Enabled {
			return []string{"group-enabled"}
		}
		return []string{"group-disabled"}
	})
	if _, _, err := r.AttachPlane(meta("node-a", 0, "1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	n, _ := r.Get("node-a")
	if len(n.Groups) != 1 || n.Groups[0] != "group-enabled" {
		t.Fatalf("groups = %v", n.Groups)
	}
	list := r.List()
	if len(list) != 1 || list[0].ID != "node-a" {
		t.Fatalf("List = %+v", list)
	}
}

func TestSetNodeOnlineAndMetrics(t *testing.T) {
	m := metrics.New()
	r, err := New(nil, m, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer r.Close()
	// Attaching a node updates the global gauges.
	if _, _, err := r.AttachPlane(meta("node-a", 0, "1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	if got := gaugeValue(t, m, "nodes_online"); got != 1 {
		t.Fatalf("nodes_online = %v, want 1", got)
	}
	if got := gaugeValue(t, m, "nodes_total"); got != 1 {
		t.Fatalf("nodes_total = %v, want 1", got)
	}
	if got := gaugeValue(t, m, "egress_unique_ips"); got != 1 {
		t.Fatalf("egress_unique_ips = %v, want 1", got)
	}
	r.SetNodeOnline("node-a", false)
	n, _ := r.Get("node-a")
	if n.Online {
		t.Fatal("SetNodeOnline(false) not applied")
	}
	if got := gaugeValue(t, m, "nodes_online"); got != 0 {
		t.Fatalf("nodes_online after offline = %v, want 0", got)
	}
	if r.OnlineCount() != 0 || r.UniqueEgressCount() != 0 {
		t.Fatalf("counters not recomputed after SetNodeOnline")
	}
	r.SetNodeOnline("node-a", true)
	if r.OnlineCount() != 1 || r.UniqueEgressCount() != 1 {
		t.Fatalf("counters not recomputed after SetNodeOnline(true)")
	}
}

func TestClose(t *testing.T) {
	r, _ := New(nil, nil, "")
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, _, err := r.AttachPlane(meta("node-a", 0, "1.2.3.4")); err != ErrClosed {
		t.Fatalf("AttachPlane after close = %v, want ErrClosed", err)
	}
	if err := r.UpdateNodeOverride(model.NodeOverride{ID: "node-a", Enabled: true}); err != ErrClosed {
		t.Fatalf("UpdateNodeOverride after close = %v, want ErrClosed", err)
	}
	if err := r.SetEnabled("node-a", true); err != ErrClosed {
		t.Fatalf("SetEnabled after close = %v, want ErrClosed", err)
	}
	if _, _, err := r.AttachPlane(PlaneMeta{NodeID: ""}); err != ErrEmptyNodeID {
		t.Fatalf("empty node id = %v, want ErrEmptyNodeID", err)
	}
}

func gaugeValue(t *testing.T, m *metrics.Metrics, name string) float64 {
	t.Helper()
	families, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, fam := range families {
		if fam.GetName() != name {
			continue
		}
		if len(fam.GetMetric()) == 0 {
			return 0
		}
		return fam.GetMetric()[0].GetGauge().GetValue()
	}
	t.Fatalf("metric %s not found", name)
	return 0
}
