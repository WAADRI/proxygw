//go:build windows

package nodeagent

import (
	"os/exec"
	"syscall"
)

// startUpdateHelper launches the copied helper with a detached console so the
// old node process can exit and release the target .exe.
func startUpdateHelper(path string, args []string) error {
	cmd := exec.Command(path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x00000008 | 0x00000200, // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
		HideWindow:    true,
	}
	return cmd.Start()
}
