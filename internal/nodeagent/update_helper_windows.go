//go:build windows

package nodeagent

import (
	"os/exec"
	"syscall"
)

// startUpdateHelper launches the copied helper with a detached console so the
// old node process can exit and release the target .exe. CREATE_BREAKAWAY_FROM_JOB
// matters for NSSM/WinSW: otherwise stopping the app/service can also terminate
// every child process in the service job before the helper replaces the binary.
func startUpdateHelper(path string, args []string) error {
	start := func(flags uint32) error {
		cmd := exec.Command(path, args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			CreationFlags: flags,
			HideWindow:    true,
		}
		return cmd.Start()
	}
	const (
		detachedProcess        = 0x00000008
		createNewProcessGroup  = 0x00000200
		createBreakawayFromJob = 0x01000000
	)
	base := uint32(detachedProcess | createNewProcessGroup)
	if err := start(base | createBreakawayFromJob); err == nil {
		return nil
	}
	// Some job objects disallow breakaway; fall back so the update still starts,
	// but service-managed deployments should allow it for reliable replacement.
	return start(base)
}
