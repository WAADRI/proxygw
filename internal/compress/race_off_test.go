//go:build !race

package compress_test

// raceEnabled reports whether the test binary was built with the race
// detector. The detector makes sync.Pool randomly drop items on Put, so tests
// that assert exact pool reuse relax their assertions in race builds.
const raceEnabled = false
