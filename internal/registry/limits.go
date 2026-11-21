package registry

// Bounds applied to self reported node metadata. client_id and the HELLO fields
// are self reported by the node, so the server clamps everything that surfaces
// in the panel or feeds the scheduler.

const (
	maxNodeWeight = 10000
	maxStatBytes  = int64(1) << 60
	maxStatMS     = 600000.0
	maxInflight   = int64(1_000_000_000)
)

func clampString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	// Cut on a rune boundary to keep valid UTF-8.
	cut := max
	for cut > 0 && cut < len(s) && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	return s[:cut]
}

func clampWeight(w int) int {
	if w <= 0 {
		return 1
	}
	if w > maxNodeWeight {
		return maxNodeWeight
	}
	return w
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
