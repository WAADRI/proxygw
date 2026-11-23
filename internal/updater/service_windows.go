//go:build windows

package updater

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func scPath() string {
	if root := strings.TrimSpace(os.Getenv("SystemRoot")); root != "" {
		p := root + `\System32\sc.exe`
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "sc.exe"
}

func scOutput(args ...string) (string, error) {
	cmd := exec.Command(scPath(), args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// serviceState returns the raw sc state token, for example "RUNNING".
func serviceState(name string) string {
	out, err := scOutput("query", name)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "STATE" {
			// STATE : 4 RUNNING
			return fields[len(fields)-1]
		}
	}
	return ""
}

func waitServiceState(name, wanted string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		state := serviceState(name)
		if state == wanted {
			return nil
		}
		if state == "" {
			return fmt.Errorf("无法查询服务 %s 状态", name)
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("等待服务 %s 进入 %s 超时（当前 %s）", name, wanted, serviceState(name))
}

func stopManagedService(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	out, err := scOutput("stop", name)
	if err != nil && !strings.Contains(strings.ToLower(out), "already") {
		// sc returns 1062 for an already stopped service; tolerate it.
		if !strings.Contains(out, "1062") {
			return fmt.Errorf("sc stop %s: %v: %s", name, err, out)
		}
	}
	if state := serviceState(name); state == "STOPPED" {
		return nil
	}
	if err := waitServiceState(name, "STOPPED", 90*time.Second); err != nil {
		return err
	}
	return nil
}

func startManagedService(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	out, err := scOutput("start", name)
	if err != nil {
		if !strings.Contains(out, "1056") { // already running
			return fmt.Errorf("sc start %s: %v: %s", name, err, out)
		}
	}
	return waitServiceState(name, "RUNNING", 90*time.Second)
}

func renameWithRetry(src, dst string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		if err := os.Rename(src, dst); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return lastErr
		}
		time.Sleep(500 * time.Millisecond)
	}
}
