// Command proxygw-server is the public gateway server: proxy entry points,
// tunnel service and web panel in one binary.
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

	"proxygw/internal/app"
	"proxygw/internal/config"
	"proxygw/internal/logx"
	"proxygw/internal/updater"
	"proxygw/internal/version"
)

func main() { os.Exit(run()) }

func run() int {
	var (
		configPath  = flag.String("config", "config.server.yaml", "服务端配置文件路径")
		showVersion = flag.Bool("version", false, "打印版本信息后退出")
		checkOnly   = flag.Bool("check-config", false, "仅校验配置后退出")
		updateCheck = flag.Bool("update-check", false, "仅检查 GitHub 是否有新版本")
		updateNow   = flag.Bool("update", false, "下载并安装最新版本后退出（需手动重启）")
	)
	flag.Parse()

	if *showVersion {
		writeJSON(version.Current())
		return 0
	}
	if *updateCheck || *updateNow {
		// Update mode must work before service configuration/certificates exist.
		return updater.HandleCLI("server", slog.Default(), version.Version, *updateCheck, *updateNow)
	}

	cfg, warnings, err := loadServerConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "启动失败：%v\n", err)
		return 1
	}
	logger, err := logx.New(cfg.Log, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "启动失败：%v\n", err)
		return 1
	}
	logger.Info("proxygw-server 启动中",
		"version", version.Version, "commit", version.Commit, "build_time", version.BuildTime,
		"go", version.Current().GoVersion)
	for _, w := range warnings {
		logger.Warn(w)
	}
	if *checkOnly {
		// Config validation already happened in LoadServer; avoid side effects
		// such as certificate generation in check mode.
		logger.Info("配置校验通过（check-config）")
		return 0
	}

	srv, err := app.NewServer(app.ServerOptions{Config: cfg, Logger: logger})
	if err != nil {
		fmt.Fprintf(os.Stderr, "启动失败：%v\n", err)
		return 1
	}
	printBootMessages(srv.BootMessages())
	if err := srv.Listen(); err != nil {
		logger.Error("监听失败", "error", err)
		return 1
	}
	logger.Info("proxygw-server 已就绪",
		"shared_tcp", srv.ListenAddr(),
		"http_proxy", cfg.Proxy.HTTPListen,
		"socks5", cfg.Proxy.SOCKS5Listen,
		"auth_mode", cfg.Proxy.AuthMode,
		"transport", cfg.Tunnel.Transport,
		"tls_mode", cfg.TLS.Mode)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	updater.StartBackground(ctx, "server", logger, version.Version)
	if err := srv.Run(ctx); err != nil {
		logger.Error("服务异常退出", "error", err)
		return 1
	}
	logger.Info("proxygw-server 已退出")
	return 0
}

// loadServerConfig loads the config, tolerating a missing default config file
// (defaults + environment only) but failing hard for explicitly given paths.
func loadServerConfig(path string) (*config.ServerConfig, []string, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) && path == "config.server.yaml" {
			cfg, warnings, lerr := config.LoadServer("")
			if lerr != nil {
				return nil, nil, lerr
			}
			warnings = append(warnings, "未找到 config.server.yaml，仅使用内置默认值与环境变量")
			return cfg, warnings, nil
		}
		return nil, nil, fmt.Errorf("config: file %s: %w", path, err)
	}
	return config.LoadServer(path)
}

// printBootMessages prints one-time secrets (credentials, node tokens, pin) to
// the operator console only; they are never logged at INFO level and never
// persisted in plain text.
func printBootMessages(msgs []string) {
	if len(msgs) == 0 {
		return
	}
	fmt.Fprintln(os.Stderr, "\n================ proxygw 首次启动信息（只显示一次，请保存） ================")
	for _, m := range msgs {
		fmt.Fprintln(os.Stderr, "  "+m)
	}
	fmt.Fprint(os.Stderr, "============================================================================\n\n")
}

func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
