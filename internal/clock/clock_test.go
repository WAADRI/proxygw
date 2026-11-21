package clock_test

import (
	"sync"
	"testing"
	"time"

	"proxygw/internal/clock"
)

// baseTime is the fixed local/remote reference instant used by the tests.
var baseTime = time.UnixMilli(1_700_000_000_000)

// sampleOffset records one sample whose local clock is remote + offset.
func sampleOffset(d *clock.Detector, offset time.Duration) {
	d.Sample(baseTime.UnixMilli(), baseTime.Add(offset))
}

// TestZeroOffset: an exact match reports no offset and no skew.
func TestZeroOffset(t *testing.T) {
	d := clock.NewDetector(0, 0)
	sampleOffset(d, 0)
	if got := d.Offset(); got != 0 {
		t.Fatalf("Offset = %v, want 0", got)
	}
	if d.Skewed() {
		t.Fatal("Detector with a zero offset reported skew")
	}
	st := d.Stats()
	if st.Samples != 1 || st.Offset != 0 || st.Min != 0 || st.Max != 0 {
		t.Fatalf("Stats = %+v, want one zero sample", st)
	}
}

// TestPositiveAndNegativeOffsets covers both skew directions.
func TestPositiveAndNegativeOffsets(t *testing.T) {
	ahead := clock.NewDetector(8, 0)
	sampleOffset(ahead, 5*time.Second)
	if got := ahead.Offset(); got != 5*time.Second {
		t.Fatalf("positive Offset = %v, want 5s", got)
	}
	if ahead.Skewed() {
		t.Fatal("5s offset should not be skewed at the 30s threshold")
	}

	behind := clock.NewDetector(8, 0)
	sampleOffset(behind, -45*time.Second)
	if got := behind.Offset(); got != -45*time.Second {
		t.Fatalf("negative Offset = %v, want -45s", got)
	}
	if !behind.Skewed() {
		t.Fatal("-45s offset should be skewed at the 30s threshold")
	}
	st := behind.Stats()
	if st.Min != -45*time.Second || st.Max != -45*time.Second {
		t.Fatalf("Stats min/max = %v/%v, want -45s/-45s", st.Min, st.Max)
	}
}

// TestMedianOdd: the middle sample wins.
func TestMedianOdd(t *testing.T) {
	d := clock.NewDetector(8, 0)
	sampleOffset(d, 10*time.Second)
	sampleOffset(d, -5*time.Second)
	sampleOffset(d, 30*time.Second)
	if got := d.Offset(); got != 10*time.Second {
		t.Fatalf("median(10s, -5s, 30s) = %v, want 10s", got)
	}
	st := d.Stats()
	if st.Min != -5*time.Second || st.Max != 30*time.Second {
		t.Fatalf("Stats min/max = %v/%v", st.Min, st.Max)
	}
}

// TestMedianEven: an even sample count uses the mean of the two middle values.
func TestMedianEven(t *testing.T) {
	two := clock.NewDetector(8, 0)
	sampleOffset(two, 10*time.Second)
	sampleOffset(two, 20*time.Second)
	if got := two.Offset(); got != 15*time.Second {
		t.Fatalf("median(10s, 20s) = %v, want 15s", got)
	}

	four := clock.NewDetector(8, 0)
	for _, off := range []time.Duration{time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond, 5 * time.Millisecond} {
		sampleOffset(four, off)
	}
	if got := four.Offset(); got != 3*time.Millisecond {
		t.Fatalf("median(1ms, 2ms, 4ms, 5ms) = %v, want 3ms", got)
	}

	// Averaging must tolerate mixed signs as well.
	mixed := clock.NewDetector(8, 0)
	sampleOffset(mixed, -1*time.Second)
	sampleOffset(mixed, 1*time.Second)
	if got := mixed.Offset(); got != 0 {
		t.Fatalf("median(-1s, 1s) = %v, want 0", got)
	}
}

// TestThresholdBoundary: strictly greater than the threshold triggers skew;
// 29s is fine, exactly 30s is fine, 31s alerts (mirror for negative offsets).
func TestThresholdBoundary(t *testing.T) {
	cases := []struct {
		name   string
		offset time.Duration
		want   bool
	}{
		{"29s", 29 * time.Second, false},
		{"30s", 30 * time.Second, false},
		{"31s", 31 * time.Second, true},
		{"-29s", -29 * time.Second, false},
		{"-30s", -30 * time.Second, false},
		{"-31s", -31 * time.Second, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := clock.NewDetector(8, 0) // threshold defaults to 30s
			sampleOffset(d, tc.offset)
			if got := d.Skewed(); got != tc.want {
				t.Fatalf("Skewed for %v = %v, want %v", tc.offset, got, tc.want)
			}
		})
	}
}

// TestCustomThreshold verifies the constructor argument is honoured.
func TestCustomThreshold(t *testing.T) {
	d := clock.NewDetector(4, 100*time.Millisecond)
	sampleOffset(d, 50*time.Millisecond)
	if d.Skewed() {
		t.Fatal("50ms offset should not be skewed at a 100ms threshold")
	}
	sampleOffset(d, 150*time.Millisecond)
	// median(50ms, 150ms) = 100ms, which is not > threshold.
	if d.Skewed() {
		t.Fatal("median of exactly 100ms must not be skewed (strict comparison)")
	}
	sampleOffset(d, 250*time.Millisecond)
	// median(50ms, 150ms, 250ms) = 150ms > 100ms.
	if !d.Skewed() {
		t.Fatal("median 150ms should be skewed at a 100ms threshold")
	}
}

// TestWindowRolling: once the ring is full the oldest samples are evicted.
func TestWindowRolling(t *testing.T) {
	d := clock.NewDetector(4, 0)
	for _, off := range []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 300 * time.Millisecond, 400 * time.Millisecond} {
		sampleOffset(d, off)
	}
	st := d.Stats()
	if st.Samples != 4 || st.Offset != 250*time.Millisecond || st.Min != 100*time.Millisecond || st.Max != 400*time.Millisecond {
		t.Fatalf("full window Stats = %+v, want samples=4 offset=250ms min=100ms max=400ms", st)
	}

	// Add two more samples: 100ms and 200ms must be gone.
	sampleOffset(d, time.Second)
	sampleOffset(d, 2*time.Second)
	st = d.Stats()
	if st.Samples != 4 {
		t.Fatalf("Samples = %d, want 4", st.Samples)
	}
	if st.Min != 300*time.Millisecond || st.Max != 2*time.Second {
		t.Fatalf("min/max = %v/%v, want 300ms/2s after rolling", st.Min, st.Max)
	}
	if st.Offset != 700*time.Millisecond {
		t.Fatalf("median after rolling = %v, want 700ms", st.Offset)
	}
}

// TestDefaultWindow: NewDetector(0, 0) keeps DefaultWindow samples.
func TestDefaultWindow(t *testing.T) {
	d := clock.NewDetector(0, 0)
	if clock.DefaultWindow != 32 {
		t.Fatalf("DefaultWindow = %d, want 32", clock.DefaultWindow)
	}
	for i := 1; i <= 40; i++ {
		sampleOffset(d, time.Duration(i)*time.Millisecond)
	}
	st := d.Stats()
	if st.Samples != clock.DefaultWindow {
		t.Fatalf("Samples = %d, want %d", st.Samples, clock.DefaultWindow)
	}
	// The window holds the last 32 samples: 9ms .. 40ms.
	if st.Min != 9*time.Millisecond || st.Max != 40*time.Millisecond {
		t.Fatalf("min/max = %v/%v, want 9ms/40ms", st.Min, st.Max)
	}
	// Even count: mean of the two middle values (24ms, 25ms).
	if st.Offset != 24*time.Millisecond+500*time.Microsecond {
		t.Fatalf("median = %v, want 24.5ms", st.Offset)
	}
}

// TestReset clears samples but keeps the detector usable.
func TestReset(t *testing.T) {
	d := clock.NewDetector(8, 0)
	sampleOffset(d, 45*time.Second)
	if !d.Skewed() {
		t.Fatal("45s offset should be skewed before Reset")
	}
	d.Reset()
	if st := d.Stats(); st.Samples != 0 || st.Offset != 0 || st.Min != 0 || st.Max != 0 {
		t.Fatalf("Stats after Reset = %+v, want zero value", st)
	}
	if d.Offset() != 0 {
		t.Fatalf("Offset after Reset = %v, want 0", d.Offset())
	}
	if d.Skewed() {
		t.Fatal("empty detector must not report skew")
	}
	sampleOffset(d, 2*time.Second)
	if st := d.Stats(); st.Samples != 1 || st.Offset != 2*time.Second {
		t.Fatalf("Stats after Reset+Sample = %+v", st)
	}
}

// TestIgnoresMissingRemoteTimestamps: a zero/negative remote timestamp cannot
// be measured and must not pollute the window.
func TestIgnoresMissingRemoteTimestamps(t *testing.T) {
	d := clock.NewDetector(4, 0)
	d.Sample(0, time.Now())
	d.Sample(-1, time.Now())
	if st := d.Stats(); st.Samples != 0 {
		t.Fatalf("Samples = %d, want 0 after invalid timestamps", st.Samples)
	}
	sampleOffset(d, 3*time.Second)
	if st := d.Stats(); st.Samples != 1 || st.Offset != 3*time.Second {
		t.Fatalf("Stats = %+v, want the valid sample only", st)
	}
}

// TestMillisecondResolution checks the remote millisecond timestamp conversion.
func TestMillisecondResolution(t *testing.T) {
	d := clock.NewDetector(4, 0)
	remoteMS := int64(1_700_000_000_123)
	local := time.UnixMilli(remoteMS).Add(1500 * time.Millisecond)
	d.Sample(remoteMS, local)
	if got := d.Offset(); got != 1500*time.Millisecond {
		t.Fatalf("Offset = %v, want 1.5s", got)
	}
}

// TestConcurrentSampleAndStats is the -race guard for the detector.
func TestConcurrentSampleAndStats(t *testing.T) {
	d := clock.NewDetector(16, 10*time.Second)
	const writers = 8
	const readers = 4
	const iterations = 200
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			local := baseTime.Add(time.Duration(i) * time.Second)
			for j := 0; j < iterations; j++ {
				// Cycle through -45s .. +45s to exercise the skewed branch.
				offset := time.Duration((i*iterations+j)%91-45) * time.Second
				d.Sample(local.UnixMilli(), local.Add(offset))
			}
		}(i)
	}
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = d.Offset()
				_ = d.Skewed()
				_ = d.Stats()
			}
		}()
	}
	wg.Wait()
	st := d.Stats()
	if st.Samples < 0 || st.Samples > 16 {
		t.Fatalf("Samples = %d, want 0..16", st.Samples)
	}
	if st.Min > st.Max {
		t.Fatalf("Min %v > Max %v", st.Min, st.Max)
	}
}

// TestConcurrentResetAndSample mixes resets into the sample/read workload.
func TestConcurrentResetAndSample(t *testing.T) {
	d := clock.NewDetector(8, 5*time.Second)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for j := 0; j < 500; j++ {
			sampleOffset(d, time.Duration(j%20-10)*time.Second)
		}
	}()
	go func() {
		defer wg.Done()
		for j := 0; j < 100; j++ {
			d.Reset()
			_ = d.Stats()
		}
	}()
	wg.Wait()
}
