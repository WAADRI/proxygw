// Command proxygw-client is the node agent: it dials the server from behind NAT
// and opens real TCP connections from its own network egress.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"proxygw/internal/app"
	"proxygw/internal/config"
	"proxygw/internal/logx"
	"proxygw/internal/version"
)

func main() { os.Exit(run()) }

func run() int {
	var (
		configPath  = flag.String("config", "config.client.yaml", "节点配置文件路径")
		showVersion = flag.Bool("version", false, "打印版本信息后退出")
		checkOnly   = flag.Bool("check-config", false, "仅校验配置后退出")
	)
	flag.Parse()

	if *showVersion {
		writeJSON(version.Current())
		return 0
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

	client, err := app.NewClient(app.ClientOptions{Config: cfg, Logger: logger})
	if err != nil {
		logger.Error("节点初始化失败", "error", err)
		return 1
	}
	defer func() { _ = client.Close() }()
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := client.Run(ctx); err != nil {
		if nodeagentFatal(err) {
			logger.Error("节点因致命错误退出（不会自动重连）", "error", err)
		} else {
			logger.Error("节点异常退出", "error", err)
		}
		return 1
	}
	st := client.Status()
	logger.Info("proxygw-client 已退出", "transport", st.Transport, "planes", st.Planes)
	return 0
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
