//go:build !windows

package nodeagent

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// startUpdateHelper launches the copied helper in a new session so it survives
// the node process exit. Under systemd we prefer a transient scope: a direct
// child would be killed together with the old service cgroup when the service
// stops.
func startUpdateHelper(path string, args []string, _ string) error {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		if systemdRun, err := exec.LookPath("systemd-run"); err == nil {
			scopeArgs := []string{
				"--scope", "--quiet", "--collect",
				"--unit=" + fmt.Sprintf("proxygw-update-%d", os.Getpid()),
				"--", path,
			}
			scopeArgs = append(scopeArgs, args...)
			cmd := exec.Command(systemdRun, scopeArgs...)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if err := cmd.Start(); err == nil {
				return nil
			}
		}
	}
	cmd := exec.Command(path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}
