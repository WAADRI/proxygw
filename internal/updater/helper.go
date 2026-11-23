package updater

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"proxygw/internal/protocol"
)

// HelperOptions describes one already-downloaded, checksum-verified update.
type HelperOptions struct {
	Target      string
	NewBinary   string
	ParentPID   int
	RestartArgs []string
	StatusPath  string
	Version     string
	WorkDir     string
	// ServiceName is the Windows service manager name (for example an NSSM
	// service). When set, the helper stops the service before waiting for the
	// old process and starts it again after the replacement.
	ServiceName string
}

// RunApplyHelper is the child-process side of a node update. It waits for the
// old node process to exit, replaces the executable atomically and starts the
// new binary (or asks systemd to restart the unit). It returns a process exit
// code and writes progress to StatusPath for the next node process to report.
func RunApplyHelper(opts HelperOptions) int {
	if strings.TrimSpace(opts.Target) == "" || strings.TrimSpace(opts.NewBinary) == "" {
		return 1
	}
	defer os.Remove(opts.NewBinary)
	if err := writeHelperStatus(opts.StatusPath, protocol.UpdateStatus{
		State:         protocol.UpdateReplacing,
		TargetVersion: opts.Version,
		Progress:      100,
		Message:       "等待旧进程退出",
	}); err != nil {
		return 1
	}
	if opts.ServiceName != "" {
		_ = writeHelperStatus(opts.StatusPath, protocol.UpdateStatus{
			State:         protocol.UpdateReplacing,
			TargetVersion: opts.Version,
			Progress:      100,
			Message:       "停止 Windows 服务 " + opts.ServiceName,
		})
		if err := stopManagedService(opts.ServiceName); err != nil {
			_ = writeHelperStatus(opts.StatusPath, protocol.UpdateStatus{
				State:         protocol.UpdateFailed,
				TargetVersion: opts.Version,
				Error:         fmt.Sprintf("停止服务 %s 失败: %v", opts.ServiceName, err),
			})
			return 1
		}
	}
	if err := waitParentExit(opts.ParentPID, opts.Target, 90*time.Second); err != nil {
		_ = writeHelperStatus(opts.StatusPath, protocol.UpdateStatus{
			State:         protocol.UpdateFailed,
			TargetVersion: opts.Version,
			Error:         err.Error(),
		})
		return 1
	}

	backup := opts.Target + ".old"
	_ = os.Remove(backup)
	installed := false
	// The staged binary lives in the system temp dir which may be a different
	// filesystem; copy it next to the target first so the final rename is atomic.
	stagedTarget := opts.Target + ".new"
	defer os.Remove(stagedTarget)
	if err := copyHelperFile(opts.NewBinary, stagedTarget); err != nil {
		_ = writeHelperStatus(opts.StatusPath, protocol.UpdateStatus{
			State:         protocol.UpdateFailed,
			TargetVersion: opts.Version,
			Error:         fmt.Sprintf("复制新二进制到目标目录失败: %v", err),
		})
		return 1
	}
	if err := renameWithRetry(opts.Target, backup, 30*time.Second); err != nil {
		_ = writeHelperStatus(opts.StatusPath, protocol.UpdateStatus{
			State:         protocol.UpdateFailed,
			TargetVersion: opts.Version,
			Error:         fmt.Sprintf("备份旧二进制失败: %v", err),
		})
		return 1
	}
	defer func() {
		if !installed {
			_ = os.Rename(backup, opts.Target)
		}
	}()
	if err := renameWithRetry(stagedTarget, opts.Target, 30*time.Second); err != nil {
		_ = writeHelperStatus(opts.StatusPath, protocol.UpdateStatus{
			State:         protocol.UpdateFailed,
			TargetVersion: opts.Version,
			Error:         fmt.Sprintf("替换新二进制失败: %v", err),
		})
		return 1
	}
	if err := os.Chmod(opts.Target, 0o755); err != nil {
		_ = os.Remove(opts.Target)
		_ = os.Rename(backup, opts.Target)
		_ = writeHelperStatus(opts.StatusPath, protocol.UpdateStatus{
			State:         protocol.UpdateFailed,
			TargetVersion: opts.Version,
			Error:         fmt.Sprintf("设置新二进制权限失败: %v", err),
		})
		return 1
	}
	installed = true

	_ = writeHelperStatus(opts.StatusPath, protocol.UpdateStatus{
		State:         protocol.UpdateRestarting,
		TargetVersion: opts.Version,
		Progress:      100,
		Message:       "正在重启节点",
	})
	if err := restartUpdatedBinary(opts.Target, opts.RestartArgs, opts.WorkDir, opts.ServiceName); err != nil {
		// Roll back on restart failure so the node does not stay offline.
		_ = os.Remove(opts.Target)
		_ = os.Rename(backup, opts.Target)
		installed = false
		_ = writeHelperStatus(opts.StatusPath, protocol.UpdateStatus{
			State:         protocol.UpdateRolledBack,
			TargetVersion: opts.Version,
			Error:         fmt.Sprintf("新版本启动失败，已回滚: %v", err),
		})
		_ = restartUpdatedBinary(opts.Target, opts.RestartArgs, opts.WorkDir, opts.ServiceName)
		return 1
	}
	_ = os.Remove(backup)
	_ = writeHelperStatus(opts.StatusPath, protocol.UpdateStatus{
		State:          protocol.UpdateSuccess,
		TargetVersion:  opts.Version,
		CurrentVersion: opts.Version,
		Progress:       100,
		Message:        "更新完成，节点已重启",
	})
	return 0
}

func writeHelperStatus(path string, st protocol.UpdateStatus) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	st.UpdatedAt = protocol.NowMillis()
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func restartUpdatedBinary(target string, args []string, workDir, serviceName string) error {
	if serviceName != "" {
		return startManagedService(serviceName)
	}
	if unit := systemdUnit(); unit != "" {
		if path, err := exec.LookPath("systemctl"); err == nil {
			if err := exec.Command(path, "restart", unit).Run(); err == nil {
				return nil
			}
		}
	}
	return startDetached(target, args, workDir)
}

// systemdUnit returns the current systemd service unit when the node is running
// under systemd, or "" for bare/direct deployments.
func systemdUnit() string {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return ""
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 3 {
			continue
		}
		path := fields[2]
		base := filepath.Base(strings.TrimRight(path, "/"))
		if strings.HasSuffix(base, ".service") {
			return base
		}
	}
	return ""
}

func startDetached(target string, args []string, workDir string) error {
	cmd := exec.Command(target, args...)
	if workDir != "" {
		cmd.Dir = workDir
	}
	return startDetachedCmd(cmd)
}

func copyHelperFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		return err
	}
	return os.Chmod(dst, 0o755)
}
