package nodeagent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"proxygw/internal/protocol"
	"proxygw/internal/updater"
)

const (
	runtimeDocker = "docker"
	runtimeBinary = "binary"

	updateStatusFile = "update-status.json"
	updateHelperName = "proxygw-update-helper"
)

// detectRuntime classifies how this node process is deployed. Only a binary
// deployment can safely replace its own executable; Docker/Kubernetes nodes must
// be updated through their image instead.
func detectRuntime() (string, bool) {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return runtimeDocker, false
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		text := string(data)
		for _, marker := range []string{"docker", "kubepods", "containerd", "libpod"} {
			if strings.Contains(text, marker) {
				return runtimeDocker, false
			}
		}
	}
	if strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST")) != "" {
		return runtimeDocker, false
	}
	return runtimeBinary, true
}

func (a *Agent) updateStatusPath() string {
	if a.cfg == nil || strings.TrimSpace(a.cfg.StateDir) == "" {
		return ""
	}
	return filepath.Join(a.cfg.StateDir, updateStatusFile)
}

// loadUpdateStatus restores the result written by the helper before restart, so
// the freshly started node can report success/failure to the panel.
func (a *Agent) loadUpdateStatus() {
	a.updateMu.Lock()
	a.updateStatus = protocol.UpdateStatus{
		State:          protocol.UpdateIdle,
		CurrentVersion: a.version,
		UpdatedAt:      protocol.NowMillis(),
	}
	path := a.updateStatusPath()
	a.updateMu.Unlock()
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var st protocol.UpdateStatus
	if err := json.Unmarshal(data, &st); err != nil {
		return
	}
	if st.CurrentVersion == "" {
		st.CurrentVersion = a.version
	}
	if st.UpdatedAt == 0 {
		st.UpdatedAt = protocol.NowMillis()
	}
	a.updateMu.Lock()
	a.updateStatus = st
	a.updateMu.Unlock()
	// A transient helper state read by a freshly started node means the
	// previous update did not finish (for example the helper was killed by a
	// service manager). Convert it to a terminal failure instead of showing
	// "replacing" forever in the panel.
	switch st.State {
	case protocol.UpdateChecking, protocol.UpdateDownloading, protocol.UpdateVerified,
		protocol.UpdateWaitingRestart, protocol.UpdateReplacing, protocol.UpdateRestarting:
		a.updateMu.Lock()
		a.updateStatus = protocol.UpdateStatus{
			State:          protocol.UpdateFailed,
			CurrentVersion: a.version,
			TargetVersion:  st.TargetVersion,
			Error:          "上次更新未完成：节点已重启但未完成替换",
			UpdatedAt:      protocol.NowMillis(),
		}
		a.updateMu.Unlock()
	}
}

func (a *Agent) updateStatusSnapshot() *protocol.UpdateStatus {
	a.refreshUpdateStatusFromDisk()
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	if a.updateStatus.State == "" {
		return nil
	}
	st := a.updateStatus
	return &st
}

// refreshUpdateStatusFromDisk picks up the helper's final status written after
// the new process has already started.
func (a *Agent) refreshUpdateStatusFromDisk() {
	path := a.updateStatusPath()
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var st protocol.UpdateStatus
	if err := json.Unmarshal(data, &st); err != nil || st.State == "" {
		return
	}
	a.updateMu.Lock()
	if st.UpdatedAt > a.updateStatus.UpdatedAt {
		if st.CurrentVersion == "" {
			st.CurrentVersion = a.version
		}
		a.updateStatus = st
	}
	a.updateMu.Unlock()
}

func (a *Agent) isUpdateRunning() bool {
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	return a.updateRunning
}

// startUpdate handles one server UPDATE command. Concurrent commands are
// idempotent: only the first starts work.
func (a *Agent) startUpdate(cmd protocol.UpdateCommand) {
	if !a.updateCapable || a.runtimeEnv != runtimeBinary {
		a.setUpdateStatus(protocol.UpdateStatus{
			State:          protocol.UpdateFailed,
			CurrentVersion: a.version,
			TargetVersion:  cmd.Version,
			Error:          "当前节点运行在容器环境，请通过更新镜像升级",
		})
		return
	}
	a.updateMu.Lock()
	if a.updateRunning {
		a.updateMu.Unlock()
		return
	}
	a.updateRunning = true
	a.updateStatus = protocol.UpdateStatus{
		State:          protocol.UpdateChecking,
		CurrentVersion: a.version,
		TargetVersion:  cmd.Version,
		Message:        "正在检查最新版本",
		UpdatedAt:      protocol.NowMillis(),
	}
	a.updateMu.Unlock()
	go a.broadcastUpdateStatus()
	a.log.Info("收到节点更新指令", "event", "update.start", "target", cmd.Version, "command_id", cmd.CommandID)
	go a.runUpdate(cmd)
}

func (a *Agent) runUpdate(cmd protocol.UpdateCommand) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	u := updater.FromEnv("client", a.log, a.version)
	staged, err := u.StageWithProgress(ctx, func(p updater.StageProgress) {
		a.setUpdateStatus(protocol.UpdateStatus{
			State:          p.State,
			CurrentVersion: a.version,
			TargetVersion:  p.Version,
			Progress:       p.Progress,
			Message:        p.Message,
		})
	})
	if err != nil {
		a.failUpdate(fmt.Errorf("下载或校验更新包失败: %w", err))
		return
	}
	if !staged.Updated {
		a.finishUpdate(fmt.Sprintf("已是最新版本 %s", staged.Version))
		return
	}
	helperStarted := false
	defer func() {
		if !helperStarted {
			_ = os.Remove(staged.BinaryPath)
		}
	}()

	target, err := os.Executable()
	if err != nil {
		a.failUpdate(fmt.Errorf("无法定位当前二进制: %w", err))
		return
	}
	if resolved, rerr := filepath.EvalSymlinks(target); rerr == nil {
		target = resolved
	}
	if err := checkReplaceAllowed(filepath.Dir(target)); err != nil {
		a.failUpdate(err)
		return
	}
	stateDir := strings.TrimSpace(a.cfg.StateDir)
	if stateDir == "" {
		a.failUpdate(errors.New("state_dir 为空，无法写入更新状态"))
		return
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		a.failUpdate(fmt.Errorf("无法创建状态目录: %w", err))
		return
	}
	// The helper runs from a scheduled task whose working directory is
	// C:\Windows\System32, not the service AppDirectory. All paths passed to it
	// must therefore be absolute (state_dir is often configured as "state").
	if abs, aerr := filepath.Abs(stateDir); aerr == nil {
		stateDir = abs
	}
	newBinary := staged.BinaryPath
	if abs, aerr := filepath.Abs(newBinary); aerr == nil {
		newBinary = abs
	}
	statusPath := filepath.Join(stateDir, updateStatusFile)
	helperName := updateHelperName
	if runtime.GOOS == "windows" {
		helperName += ".exe"
	}
	helperPath := filepath.Join(stateDir, helperName)
	if err := copyExecutable(target, helperPath); err != nil {
		a.failUpdate(fmt.Errorf("无法准备更新 helper: %w", err))
		return
	}
	args := os.Args[1:]
	argsJSON, err := json.Marshal(args)
	if err != nil {
		a.failUpdate(err)
		return
	}
	workDir, _ := os.Getwd()
	helperArgs := []string{
		"-apply-update",
		"-update-target", target,
		"-update-new", newBinary,
		"-update-pid", fmt.Sprint(os.Getpid()),
		"-update-args", base64.StdEncoding.EncodeToString(argsJSON),
		"-update-status", statusPath,
		"-update-version", staged.Version,
		"-update-cwd", workDir,
	}
	serviceName := detectUpdateService()
	if serviceName != "" {
		helperArgs = append(helperArgs, "-update-service", serviceName)
		a.log.Info("节点运行在 Windows 服务下，helper 将通过外部计划任务启动",
			"event", "update.service", "service", serviceName)
	}
	if err := startUpdateHelper(helperPath, helperArgs, serviceName); err != nil {
		a.failUpdate(fmt.Errorf("启动更新 helper 失败: %w", err))
		return
	}
	helperStarted = true
	a.setUpdateStatus(protocol.UpdateStatus{
		State:          protocol.UpdateWaitingRestart,
		CurrentVersion: a.version,
		TargetVersion:  staged.Version,
		Progress:       100,
		Message:        "helper 已启动，等待节点退出后替换二进制",
	})
	a.updatePending.Store(true)
	select {
	case <-a.updateExit:
	default:
		close(a.updateExit)
	}
}

func (a *Agent) failUpdate(err error) {
	a.log.Error("节点更新失败", "event", "update.failed", "error", err)
	a.setUpdateStatus(protocol.UpdateStatus{
		State:          protocol.UpdateFailed,
		CurrentVersion: a.version,
		Error:          err.Error(),
	})
	a.updateMu.Lock()
	a.updateRunning = false
	a.updateMu.Unlock()
}

func (a *Agent) finishUpdate(message string) {
	a.setUpdateStatus(protocol.UpdateStatus{
		State:          protocol.UpdateSuccess,
		CurrentVersion: a.version,
		TargetVersion:  a.version,
		Progress:       100,
		Message:        message,
	})
	a.updateMu.Lock()
	a.updateRunning = false
	a.updateMu.Unlock()
}

func (a *Agent) setUpdateStatus(st protocol.UpdateStatus) {
	if st.UpdatedAt == 0 {
		st.UpdatedAt = protocol.NowMillis()
	}
	if st.CurrentVersion == "" {
		st.CurrentVersion = a.version
	}
	a.updateMu.Lock()
	a.updateStatus = st
	a.updateMu.Unlock()
	a.broadcastUpdateStatus()
}

func (a *Agent) broadcastUpdateStatus() {
	st := a.updateStatusSnapshot()
	if st == nil {
		return
	}
	payload, err := protocol.Marshal(st)
	if err != nil {
		return
	}
	a.sessMu.Lock()
	list := make([]*session, 0, len(a.sessions))
	for sess := range a.sessions {
		list = append(list, sess)
	}
	a.sessMu.Unlock()
	for _, sess := range list {
		if err := sess.sendControl(protocol.FrameUpdateSt, payload); err != nil {
			a.log.Debug("上报更新状态失败", "event", "update.status_fail", "error", err)
		}
	}
}

// UpdatePending reports whether this agent is exiting to let the helper replace
// the executable. The process supervisor must not reconnect in that case.
func (a *Agent) UpdatePending() bool { return a.updatePending.Load() }

func checkReplaceAllowed(dir string) error {
	if dir == "" {
		return errors.New("目标二进制目录为空")
	}
	f, err := os.CreateTemp(dir, ".proxygw-write-check-*")
	if err != nil {
		return fmt.Errorf("二进制目录不可写（%s）: %w", dir, err)
	}
	name := f.Name()
	f.Close()
	_ = os.Remove(name)
	return nil
}

func copyExecutable(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		return err
	}
	return os.Chmod(dst, 0o755)
}
