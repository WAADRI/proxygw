// Command proxygw-client is the node agent: it dials the server from behind NAT
// and opens real TCP connections from its own network egress.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"proxygw/internal/app"
	"proxygw/internal/config"
	"proxygw/internal/logx"
	"proxygw/internal/nodeagent"
	"proxygw/internal/updater"
	"proxygw/internal/version"
)

// clientSession is the subset of app.Client the reconnect loop needs; tests
// replace it with a fake.
type clientSession interface {
	Run(context.Context) error
	Close() error
	Status() nodeagent.Status
	ClientID() string
	BootMessages() []string
	UpdatePending() bool
}

func main() { os.Exit(run()) }

func run() int {
	var (
		configPath    = flag.String("config", "config.client.yaml", "节点配置文件路径")
		showVersion   = flag.Bool("version", false, "打印版本信息后退出")
		checkOnly     = flag.Bool("check-config", false, "仅校验配置后退出")
		updateCheck   = flag.Bool("update-check", false, "仅检查 GitHub 是否有新版本")
		updateNow     = flag.Bool("update", false, "下载并安装最新版本后退出（需手动重启）")
		applyUpdate   = flag.Bool("apply-update", false, "内部使用：更新 helper")
		updateTarget  = flag.String("update-target", "", "内部使用：目标二进制")
		updateNew     = flag.String("update-new", "", "内部使用：新二进制")
		updatePID     = flag.Int("update-pid", 0, "内部使用：旧进程 PID")
		updateArgs    = flag.String("update-args", "", "内部使用：重启参数（base64 JSON）")
		updateStatus  = flag.String("update-status", "", "内部使用：状态文件")
		updateVersion = flag.String("update-version", "", "内部使用：目标版本")
		updateCwd     = flag.String("update-cwd", "", "内部使用：重启工作目录")
	)
	flag.Parse()

	if *applyUpdate {
		return runUpdateHelper(updateHelperInvocation{
			target:  *updateTarget,
			newPath: *updateNew,
			parent:  *updatePID,
			args:    *updateArgs,
			status:  *updateStatus,
			version: *updateVersion,
			cwd:     *updateCwd,
		})
	}

	if *showVersion {
		writeJSON(version.Current())
		return 0
	}
	if *updateCheck || *updateNow {
		// Update mode must work before a client configuration exists.
		return updater.HandleCLI("client", slog.Default(), version.Version, *updateCheck, *updateNow)
	}

	cfg, warnings, err := loadClientConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "启动失败：%v\n", err)
		return 1
	}
	logger, err := logx.New(cfg.Log, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "启动失败：%v\n", err)
		return 1
	}
	logger.Info("proxygw-client 启动中",
		"version", version.Version, "commit", version.Commit, "build_time", version.BuildTime,
		"go", version.Current().GoVersion)
	for _, w := range warnings {
		logger.Warn(w)
	}
	if *checkOnly {
		logger.Info("配置校验通过（check-config）")
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	updater.StartBackground(ctx, "client", logger, version.Version)
	return runClientLoop(ctx, logger, cfg, func() (clientSession, error) {
		return app.NewClient(app.ClientOptions{Config: cfg, Logger: logger})
	}, shutdownReconnectDelay)
}

// shutdownReconnectDelay gives a restarting server time to come back before the
// fresh agent starts dialing. The agent still applies its normal backoff when
// the server stays unavailable.
const shutdownReconnectDelay = 5 * time.Second

// runClientLoop keeps the process alive across server-initiated shutdowns. A
// nil Run return without a cancelled local context means the server drained the
// session for a restart, so a fresh agent is built after delay. Fatal errors,
// local signals and a non-nil Run error still terminate the process.
func runClientLoop(ctx context.Context, logger *slog.Logger, cfg *config.ClientConfig, newClient func() (clientSession, error), delay time.Duration) int {
	first := true
	var lastTransport string
	var lastPlanes int
	for {
		client, err := newClient()
		if err != nil {
			logger.Error("节点初始化失败", "error", err)
			return 1
		}
		if first {
			for _, msg := range client.BootMessages() {
				logger.Warn(msg)
			}
			logger.Info("节点配置就绪",
				"server", cfg.ServerURL,
				"client_id", client.ClientID(),
				"alias", cfg.Alias,
				"region", cfg.Region,
				"tags", cfg.NormalizedTags(),
				"transport", cfg.Transport,
				"quic_fallback", cfg.QUICFallback,
				"planes", cfg.Planes,
				"tls_mode", cfg.TLS.Mode)
			first = false
		}

		runErr := client.Run(ctx)
		st := client.Status()
		updatePending := client.UpdatePending()
		_ = client.Close()
		lastTransport, lastPlanes = st.Transport, st.Planes
		if updatePending {
			logger.Info("节点更新 helper 已接管，退出当前进程", "event", "agent.update_restart")
			return 0
		}
		if runErr != nil {
			if nodeagentFatal(runErr) {
				logger.Error("节点因致命错误退出（不会自动重连）", "error", runErr)
			} else {
				logger.Error("节点异常退出", "error", runErr)
			}
			return 1
		}
		if ctx.Err() != nil {
			break
		}
		logger.Warn("服务端已停机，节点保持运行并准备重连",
			"event", "agent.reconnect",
			"retry_after_ms", delay.Milliseconds())
		if !sleepCtx(ctx, delay) {
			break
		}
	}
	logger.Info("proxygw-client 已退出", "transport", lastTransport, "planes", lastPlanes)
	return 0
}

// sleepCtx waits for d unless ctx is cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func loadClientConfig(path string) (*config.ClientConfig, []string, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) && path == "config.client.yaml" {
			cfg, warnings, lerr := config.LoadClient("")
			if lerr != nil {
				return nil, nil, lerr
			}
			warnings = append(warnings, "未找到 config.client.yaml，仅使用内置默认值与环境变量")
			return cfg, warnings, nil
		}
		return nil, nil, fmt.Errorf("config: file %s: %w", path, err)
	}
	return config.LoadClient(path)
}

// nodeagentFatal avoids importing nodeagent in main just for one check; the
// app layer already classifies pin mismatches as fatal, so a simple string
// match keeps the exit log accurate.
func nodeagentFatal(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return contains(s, "pin") || contains(s, "authentication") || contains(s, "version") || contains(s, "fatal")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
