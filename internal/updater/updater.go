// Package updater checks the project's GitHub releases and can replace the
// running binary with a newer verified build.
//
// The updater is intentionally opt-in. It never runs for container images by
// default, because replacing a file inside a container is not persistent; image
// tags remain the supported update path for Docker deployments.
package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"log/slog"
)

const (
	DefaultRepository = "WAADRI/proxygw"
	DefaultInterval   = 24 * time.Hour
	DefaultCheckDelay = time.Minute
	assetPrefix       = "node-proxy_"
	maxChecksumBytes  = 1 << 20
	maxArchiveBytes   = 512 << 20
)

// Options configures one updater instance.
type Options struct {
	Repository     string
	CurrentVersion string
	Role           string // "server" or "client"
	Proxies        []string
	APIBase        string
	GitHubBase     string
	Logger         *slog.Logger
	GOOS           string
	GOARCH         string
	BinaryPath     string
	Client         *http.Client
}

// Release is the newest published release.
type Release struct {
	Tag     string
	Version string
}

// Result describes one update attempt.
type Result struct {
	Updated    bool
	Version    string
	BinaryPath string
	Archive    string
}

// Updater performs release checks and binary replacement.
type Updater struct {
	repo    string
	current string
	role    string
	proxies []string
	apiBase string
	ghBase  string
	logger  *slog.Logger
	goos    string
	goarch  string
	binPath string
	client  *http.Client
}

// FromEnv builds an updater from the documented UPDATE_* environment variables.
func FromEnv(role string, logger *slog.Logger, currentVersion string) *Updater {
	client := &http.Client{Timeout: 15 * time.Minute}
	opts := Options{
		Repository:     envString("UPDATE_REPOSITORY", DefaultRepository),
		CurrentVersion: currentVersion,
		Role:           role,
		Proxies:        splitList(os.Getenv("UPDATE_PROXIES")),
		APIBase:        "https://api.github.com",
		GitHubBase:     "https://github.com",
		Logger:         logger,
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		Client:         client,
	}
	if len(opts.Proxies) == 0 {
		opts.Proxies = []string{"https://gh-proxy.com", "https://ghproxy.net"}
	}
	return New(opts)
}

// New validates options and returns an updater.
func New(opts Options) *Updater {
	repo := strings.TrimSpace(opts.Repository)
	if repo == "" {
		repo = DefaultRepository
	}
	proxies := make([]string, 0, len(opts.Proxies))
	for _, proxy := range opts.Proxies {
		proxy = strings.TrimSpace(proxy)
		if proxy == "" {
			continue
		}
		if !strings.HasPrefix(proxy, "http://") && !strings.HasPrefix(proxy, "https://") {
			continue
		}
		proxies = append(proxies, strings.TrimRight(proxy, "/"))
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 15 * time.Minute}
	}
	goos := opts.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := opts.GOARCH
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	apiBase := strings.TrimRight(opts.APIBase, "/")
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	ghBase := strings.TrimRight(opts.GitHubBase, "/")
	if ghBase == "" {
		ghBase = "https://github.com"
	}
	return &Updater{
		repo:    repo,
		current: opts.CurrentVersion,
		role:    opts.Role,
		proxies: proxies,
		apiBase: apiBase,
		ghBase:  ghBase,
		logger:  opts.Logger,
		goos:    goos,
		goarch:  goarch,
		binPath: opts.BinaryPath,
		client:  opts.Client,
	}
}

// Enabled reports whether background update checking is enabled.
func Enabled() bool { return envBool("UPDATE_ENABLED") }

// AutoApply reports whether a discovered update should be downloaded and
// installed in the background.
func AutoApply() bool { return envBool("UPDATE_AUTO_APPLY") }

// Interval returns the background check interval.
func Interval() time.Duration {
	raw := strings.TrimSpace(os.Getenv("UPDATE_INTERVAL"))
	if raw == "" {
		return DefaultInterval
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < time.Minute {
		return DefaultInterval
	}
	return d
}

// HandleCLI implements the shared -update / -update-check command line modes.
// It returns the process exit code.
func HandleCLI(role string, logger *slog.Logger, currentVersion string, checkOnly, apply bool) int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	u := FromEnv(role, logger, currentVersion)
	if checkOnly {
		release, newer, err := u.Check(ctx)
		if err != nil {
			logger.Error("检查更新失败", "event", "update.check_failed", "error", err)
			return 1
		}
		if newer {
			logger.Info("发现新版本", "event", "update.available",
				"current", currentVersion, "latest", release.Version, "tag", release.Tag)
		} else {
			logger.Info("当前已是最新版本", "event", "update.current", "version", currentVersion)
		}
		return 0
	}
	if !apply {
		return 0
	}
	result, err := u.Update(ctx)
	if err != nil {
		logger.Error("更新失败", "event", "update.failed", "error", err)
		return 1
	}
	if !result.Updated {
		logger.Info("当前已是最新版本", "event", "update.current", "version", currentVersion)
		return 0
	}
	logger.Warn("二进制更新完成，重启进程后生效", "event", "update.applied",
		"version", result.Version, "binary", result.BinaryPath)
	return 0
}

// StartBackground starts the optional periodic checker. It is a no-op unless
// UPDATE_ENABLED is true. autoApply only replaces the on-disk binary; restarting
// the process remains the operator's/supervisor's decision.
func StartBackground(ctx context.Context, role string, logger *slog.Logger, currentVersion string) {
	if !Enabled() {
		return
	}
	u := FromEnv(role, logger, currentVersion)
	go u.Watch(ctx, Interval(), AutoApply())
}

// Check returns the latest release and whether it is newer than the running
// version. It never downloads binary assets.
func (u *Updater) Check(ctx context.Context) (Release, bool, error) {
	release, err := u.latest(ctx)
	if err != nil {
		return Release{}, false, err
	}
	if !IsNewer(release.Version, u.current) {
		return release, false, nil
	}
	return release, true, nil
}

// Update checks for a newer release, downloads the matching asset plus its
// SHA-256 checksum, verifies the archive and atomically replaces the running
// binary. Existing processes keep running the old binary until restart.
func (u *Updater) Update(ctx context.Context) (Result, error) {
	release, newer, err := u.Check(ctx)
	if err != nil {
		return Result{}, err
	}
	if !newer {
		return Result{Version: release.Version}, nil
	}
	u.logger.Info("发现新版本，开始更新", "event", "update.available",
		"current", u.current, "latest", release.Version)

	assetName := u.assetName(release.Version)
	directAsset := fmt.Sprintf("%s/%s/releases/download/%s/%s", u.ghBase, u.repo, release.Tag, assetName)
	sources := make([]string, 0, len(u.proxies)+1)
	preferProxy := envBool("UPDATE_PREFER_PROXY")
	if preferProxy {
		for _, proxy := range u.proxies {
			sources = append(sources, proxyURL(proxy, directAsset))
		}
	}
	sources = append(sources, directAsset)
	if !preferProxy {
		for _, proxy := range u.proxies {
			sources = append(sources, proxyURL(proxy, directAsset))
		}
	}

	var lastErr error
	for _, assetURL := range sources {
		u.logger.Debug("尝试下载更新包", "event", "update.download", "url", redactURL(assetURL))
		sourceCtx := ctx
		cancel := func() {}
		// Direct GitHub from some networks blackholes rather than resetting;
		// keep a short per-source budget so the proxy fallback is reached quickly.
		if assetURL == directAsset {
			sourceCtx, cancel = context.WithTimeout(ctx, 90*time.Second)
		}
		result, err := u.downloadAndInstall(sourceCtx, release, assetURL)
		cancel()
		if err != nil {
			lastErr = err
			u.logger.Warn("更新包下载或校验失败，尝试下一个源", "event", "update.source_failed",
				"url", redactURL(assetURL), "error", err)
			continue
		}
		return result, nil
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的更新下载源")
	}
	return Result{}, fmt.Errorf("updater: %w", lastErr)
}

// Watch periodically checks for updates until ctx is cancelled. autoApply only
// replaces the on-disk binary; it does not restart the current process.
func (u *Updater) Watch(ctx context.Context, interval time.Duration, autoApply bool) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	delay := DefaultCheckDelay
	if raw := strings.TrimSpace(os.Getenv("UPDATE_CHECK_DELAY")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d >= 0 {
			delay = d
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		release, newer, err := u.Check(ctx)
		if err != nil {
			u.logger.Warn("检查更新失败", "event", "update.check_failed", "error", err)
		} else if !newer {
			u.logger.Debug("当前已是最新版本", "event", "update.current", "version", u.current)
		} else if autoApply {
			if result, err := u.Update(ctx); err != nil {
				u.logger.Warn("自动更新失败", "event", "update.apply_failed", "error", err)
			} else {
				u.logger.Warn("更新包已安装，重启进程后生效", "event", "update.applied",
					"version", result.Version, "binary", result.BinaryPath)
			}
		} else {
			u.logger.Warn("发现新版本（未启用自动安装）", "event", "update.available",
				"current", u.current, "latest", release.Version)
		}
		timer.Reset(interval)
	}
}

func (u *Updater) latestVersionForLog(ctx context.Context) string {
	release, _, err := u.Check(ctx)
	if err != nil {
		return "unknown"
	}
	return release.Version
}

func (u *Updater) latest(ctx context.Context) (Release, error) {
	// Preferred: GitHub REST API (works through corporate egress/proxies that
	// allow api.github.com).
	tag, err := u.latestViaAPI(ctx)
	if err == nil && tag != "" {
		return releaseFromTag(tag)
	}
	apiErr := err

	// Fallback: follow /releases/latest and read the redirect target. This is
	// the path that also works through gh-proxy style mirrors.
	targets := []string{u.ghBase + "/" + u.repo + "/releases/latest"}
	for _, proxy := range u.proxies {
		targets = append(targets, proxyURL(proxy, targets[0]))
	}
	var lastErr error
	for _, target := range targets {
		tag, err := u.tagFromLatestRedirect(ctx, target)
		if err != nil {
			lastErr = err
			continue
		}
		return releaseFromTag(tag)
	}
	if lastErr == nil {
		lastErr = errors.New("no redirect target")
	}
	if apiErr != nil {
		return Release{}, fmt.Errorf("updater: GitHub API: %v; latest redirect: %w", apiErr, lastErr)
	}
	return Release{}, fmt.Errorf("updater: latest redirect: %w", lastErr)
}

func (u *Updater) latestViaAPI(ctx context.Context) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
		u.apiBase+"/repos/"+u.repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "proxygw-updater")
	if token := strings.TrimSpace(os.Getenv("UPDATE_GITHUB_TOKEN")); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("GitHub API status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return "", err
	}
	return strings.TrimSpace(payload.TagName), nil
}

func (u *Updater) tagFromLatestRedirect(ctx context.Context, target string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "proxygw-updater")
	client := *u.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	location := strings.TrimSpace(resp.Header.Get("Location"))
	if location == "" {
		return "", errors.New("redirect without Location")
	}
	parsed, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	path := strings.TrimRight(parsed.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return "", errors.New("redirect path has no release tag")
	}
	tag := parts[len(parts)-1]
	if !strings.HasPrefix(tag, "v") {
		return "", fmt.Errorf("unexpected release tag %q", tag)
	}
	return tag, nil
}

func (u *Updater) downloadAndInstall(ctx context.Context, release Release, assetURL string) (Result, error) {
	checksumURL := assetURL + ".sha256"
	expected, err := u.downloadChecksum(ctx, checksumURL)
	if err != nil {
		return Result{}, fmt.Errorf("checksum: %w", err)
	}
	archive, err := u.downloadArchive(ctx, assetURL)
	if err != nil {
		return Result{}, err
	}
	defer os.Remove(archive)

	actual, err := fileSHA256(archive)
	if err != nil {
		return Result{}, err
	}
	if actual != expected {
		return Result{}, fmt.Errorf("archive checksum mismatch: got %s want %s", actual, expected)
	}
	newPath, err := u.extractBinary(archive, release.Version)
	if err != nil {
		return Result{}, err
	}
	installed, err := u.install(newPath)
	if err != nil {
		os.Remove(newPath)
		return Result{}, err
	}
	u.logger.Warn("二进制更新已完成，重启进程后生效", "event", "update.applied",
		"version", release.Version, "binary", installed)
	return Result{Updated: true, Version: release.Version, BinaryPath: installed, Archive: archive}, nil
}

func (u *Updater) downloadChecksum(ctx context.Context, target string) (string, error) {
	body, err := u.fetch(ctx, target, maxChecksumBytes)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(body))
	if len(fields) == 0 {
		return "", errors.New("empty checksum file")
	}
	sum := strings.ToLower(fields[0])
	if len(sum) != sha256.Size*2 {
		return "", fmt.Errorf("invalid checksum %q", sum)
	}
	if _, err := hex.DecodeString(sum); err != nil {
		return "", err
	}
	return sum, nil
}

func (u *Updater) downloadArchive(ctx context.Context, target string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "proxygw-updater")
	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download status %d", resp.StatusCode)
	}
	suffix := ".tar.gz"
	if u.goos == "windows" {
		suffix = ".zip"
	}
	file, err := os.CreateTemp("", "proxygw-update-*"+suffix)
	if err != nil {
		return "", err
	}
	defer file.Close()
	written, err := io.Copy(file, io.LimitReader(resp.Body, maxArchiveBytes+1))
	if err != nil {
		os.Remove(file.Name())
		return "", err
	}
	if written > maxArchiveBytes {
		os.Remove(file.Name())
		return "", errors.New("archive too large")
	}
	return file.Name(), nil
}

func (u *Updater) fetch(ctx context.Context, target string, limit int64) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "proxygw-updater")
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func (u *Updater) extractBinary(archive, version string) (string, error) {
	targetName := "proxygw-server"
	if u.role == "client" {
		targetName = "proxygw-client"
	}
	if u.goos == "windows" {
		targetName += ".exe"
	}
	out, err := os.CreateTemp("", "proxygw-new-*")
	if err != nil {
		return "", err
	}
	outPath := out.Name()
	out.Close()
	defer func() {
		if err != nil {
			os.Remove(outPath)
		}
	}()

	if u.goos == "windows" {
		err = extractFromZip(archive, targetName, outPath)
	} else {
		err = extractFromTarGz(archive, targetName, outPath)
	}
	if err != nil {
		return "", err
	}
	if err = os.Chmod(outPath, 0o755); err != nil {
		return "", err
	}
	return outPath, nil
}

func extractFromTarGz(archive, targetName, outPath string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != targetName {
			continue
		}
		return copyToFile(tr, outPath, 0o755)
	}
	return fmt.Errorf("archive %s does not contain %s", archive, targetName)
}

func extractFromZip(archive, targetName, outPath string) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, file := range zr.File {
		if file.FileInfo().IsDir() || filepath.Base(file.Name) != targetName {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		return copyToFile(rc, outPath, 0o755)
	}
	return fmt.Errorf("archive %s does not contain %s", archive, targetName)
}

func copyToFile(src io.Reader, path string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, src); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (u *Updater) install(newPath string) (string, error) {
	exe := u.binPath
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			return "", err
		}
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	tmp := filepath.Join(dir, "."+filepath.Base(exe)+".new")
	if err := copyFile(newPath, tmp, 0o755); err != nil {
		return "", fmt.Errorf("copy new binary: %w", err)
	}
	if runtime.GOOS == "windows" {
		os.Remove(tmp)
		return "", errors.New("Windows 无法替换正在运行的 exe；请手动用更新包替换后重启")
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("replace %s: %w（目录需可写）", exe, err)
	}
	return exe, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return copyToFile(in, dst, mode)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (u *Updater) assetName(version string) string {
	ext := ".tar.gz"
	if u.goos == "windows" {
		ext = ".zip"
	}
	return fmt.Sprintf("%s%s_%s_%s%s", assetPrefix, strings.TrimPrefix(version, "v"), u.goos, u.goarch, ext)
}

func releaseFromTag(tag string) (Release, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return Release{}, errors.New("empty release tag")
	}
	version := strings.TrimPrefix(tag, "v")
	if version == "" {
		return Release{}, fmt.Errorf("invalid release tag %q", tag)
	}
	return Release{Tag: tag, Version: version}, nil
}

// IsNewer reports whether remote is a newer release than current. Non-semver
// local versions (dev/main/build snapshots) are treated as older.
func IsNewer(remote, current string) bool {
	r, okR := parseVersion(remote)
	c, okC := parseVersion(current)
	if !okR {
		return false
	}
	if !okC {
		return true
	}
	for i := 0; i < 3; i++ {
		if r[i] != c[i] {
			return r[i] > c[i]
		}
	}
	return false
}

func parseVersion(raw string) ([3]int, bool) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "v"))
	if raw == "" {
		return [3]int{}, false
	}
	if idx := strings.IndexAny(raw, "-+"); idx >= 0 {
		raw = raw[:idx]
	}
	parts := strings.Split(raw, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i := 0; i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

func proxyURL(proxy, target string) string {
	if strings.Contains(proxy, "{url}") {
		return strings.ReplaceAll(proxy, "{url}", target)
	}
	return strings.TrimRight(proxy, "/") + "/" + target
}

func envString(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func splitList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := make([]string, 0, 2)
	for _, item := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.RawQuery = ""
	return u.String()
}
