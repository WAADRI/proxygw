//go:build windows

package nodeagent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// startUpdateHelper launches the copied helper. For a Windows service-managed
// node it must run outside the service process tree: NSSM stops the service by
// terminating the app tree, and a helper started as a child (even detached) may
// be killed before it can replace the binary. A one-shot Scheduled Task as
// SYSTEM is outside that tree; the task wrapper deletes the task after the
// helper exits.
func startUpdateHelper(path string, args []string, serviceName string) error {
	if strings.TrimSpace(serviceName) != "" {
		if err := startScheduledUpdateHelper(path, args); err != nil {
			return fmt.Errorf("创建更新计划任务失败（服务 %s）: %w", serviceName, err)
		}
		return nil
	}
	return startDetachedHelper(path, args)
}

func startDetachedHelper(path string, args []string) error {
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
	return start(base)
}

func startScheduledUpdateHelper(path string, args []string) error {
	stateDir := filepath.Dir(path)
	taskName := fmt.Sprintf("ProxygwUpdate-%d", os.Getpid())
	batchPath := filepath.Join(stateDir, "proxygw-update-helper.cmd")
	quotedHelper := `"` + path + `"`
	quotedArgs := make([]string, 0, len(args))
	for _, arg := range args {
		quotedArgs = append(quotedArgs, `"`+strings.ReplaceAll(arg, `"`, `\"`)+`"`)
	}
	batch := "@echo off\r\n" +
		quotedHelper + " " + strings.Join(quotedArgs, " ") + " > \"" + path + ".log\" 2>&1\r\n" +
		"schtasks.exe /Delete /TN \"" + taskName + "\" /F >nul 2>&1\r\n"
	if err := os.WriteFile(batchPath, []byte(batch), 0o600); err != nil {
		return fmt.Errorf("写入 helper 启动脚本: %w", err)
	}
	action := `cmd.exe /c "` + batchPath + `"`
	create := exec.Command("schtasks.exe", "/Create", "/TN", taskName,
		"/TR", action, "/SC", "ONCE", "/ST", "23:59", "/RU", "SYSTEM",
		"/RL", "HIGHEST", "/F")
	if out, err := create.CombinedOutput(); err != nil {
		_ = os.Remove(batchPath)
		return fmt.Errorf("schtasks create: %w: %s", err, strings.TrimSpace(string(out)))
	}
	run := exec.Command("schtasks.exe", "/Run", "/TN", taskName)
	if out, err := run.CombinedOutput(); err != nil {
		_ = exec.Command("schtasks.exe", "/Delete", "/TN", taskName, "/F").Run()
		_ = os.Remove(batchPath)
		return fmt.Errorf("schtasks run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
