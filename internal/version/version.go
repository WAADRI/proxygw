// Package version exposes build metadata injected at link time.
package version

import "runtime"

// These variables are set via -ldflags, e.g.
//
//	-X proxygw/internal/version.Version=1.2.3
var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)

// Info is the payload served by the /version endpoint.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
}

// Current returns the metadata of the running binary.
func Current() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildTime: BuildTime,
		GoVersion: runtime.Version(),
	}
}
