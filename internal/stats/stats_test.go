package stats

import (
	"testing"
	"time"
)

func TestTrendEmitsAndTrims(t *testing.T) {
	tr := NewTrend(5*time.Second, time.Second)
	tr.Record(3, 1, 2)
	// Force emission by moving internal clock: use interval-sized sleep is slow;
	// emulate by repeatedly calling Record after sleeping one interval.
	time.Sleep(1100 * time.Millisecond)
	tr.Record(2, 0, 4)
	pts := tr.Snapshot()
	if len(pts) == 0 {
		t.Fatal("expected at least one trend point")
	}
	if pts[len(pts)-1].Active != 4 {
		t.Fatalf("active = %d", pts[len(pts)-1].Active)
	}
}

func TestTopNWindowAndOrdering(t *testing.T) {
	top := NewTopN(2*time.Minute, time.Minute, 8)
	top.Record("a.example.com", 100, false)
	top.Record("a.example.com", 100, true)
	top.Record("b.example.com", 50, false)
	out := top.Top(5)
	if len(out) != 2 || out[0].Target != "a.example.com" || out[0].Count != 2 || out[0].Errors != 1 {
		t.Fatalf("topn = %+v", out)
	}
	if out[0].Bytes != 200 {
		t.Fatalf("bytes = %d", out[0].Bytes)
	}
}

func TestTopNCardinalityCap(t *testing.T) {
	top := NewTopN(time.Minute, time.Minute, 3)
	for _, k := range []string{"a", "b", "c", "d", "e"} {
		top.Record(k, 1, false)
	}
	out := top.Top(10)
	total := int64(0)
	for _, s := range out {
		total += s.Count
	}
	if total != 5 {
		t.Fatalf("events lost: total=%d out=%+v", total, out)
	}
}

func TestCounters(t *testing.T) {
	var c Counters
	c.AddRequests(true)
	c.AddRequests(false)
	c.AddRetry()
	c.AddRateLimited()
	c.AddBreakerTrip()
	req, errs, retries, limited, trips := c.Snapshot()
	if req != 2 || errs != 1 || retries != 1 || limited != 1 || trips != 1 {
		t.Fatalf("counters = %d %d %d %d %d", req, errs, retries, limited, trips)
	}
}
