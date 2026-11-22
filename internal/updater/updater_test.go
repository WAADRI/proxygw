package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestIsNewer(t *testing.T) {
	cases := []struct {
		remote, current string
		want            bool
	}{
		{"1.0.5", "1.0.4", true},
		{"1.0.5", "1.0.5", false},
		{"v1.0.6", "1.0.5", true},
		{"1.2.0", "1.10.0", false},
		{"dev", "1.0.0", false},
		{"2.0.0", "dev", true},
	}
	for _, tc := range cases {
		if got := IsNewer(tc.remote, tc.current); got != tc.want {
			t.Errorf("IsNewer(%q,%q)=%v want %v", tc.remote, tc.current, got, tc.want)
		}
	}
}

func TestAssetName(t *testing.T) {
	u := New(Options{Role: "client", GOOS: "linux", GOARCH: "amd64", Logger: discardLogger()})
	if got := u.assetName("1.2.3"); got != "node-proxy_1.2.3_linux_amd64.tar.gz" {
		t.Fatalf("asset name = %q", got)
	}
	u = New(Options{Role: "server", GOOS: "windows", GOARCH: "arm64", Logger: discardLogger()})
	if got := u.assetName("v1.2.3"); got != "node-proxy_1.2.3_windows_arm64.zip" {
		t.Fatalf("asset name = %q", got)
	}
}

func TestCheckViaGitHubAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/owner/repo/releases/latest" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"tag_name": "v1.2.3"})
	}))
	defer srv.Close()

	u := New(Options{
		Repository:     "owner/repo",
		CurrentVersion: "1.0.0",
		Role:           "client",
		APIBase:        srv.URL,
		GitHubBase:     srv.URL,
		GOOS:           "linux",
		GOARCH:         "amd64",
		Logger:         discardLogger(),
		Client:         srv.Client(),
	})
	release, newer, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !newer || release.Version != "1.2.3" || release.Tag != "v1.2.3" {
		t.Fatalf("release=%+v newer=%v", release, newer)
	}
}

func TestCheckFallsBackToProxyLatestRedirect(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	defer api.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The proxy mirrors /<absolute github url>; only the latest redirect is
		// needed here.
		http.Redirect(w, r, "/https://github.com/owner/repo/releases/tag/v1.2.3", http.StatusFound)
	}))
	defer proxy.Close()

	u := New(Options{
		Repository:     "owner/repo",
		CurrentVersion: "1.0.0",
		Role:           "client",
		Proxies:        []string{proxy.URL},
		APIBase:        api.URL,
		GitHubBase:     "http://127.0.0.1:1",
		GOOS:           "linux",
		GOARCH:         "amd64",
		Logger:         discardLogger(),
		Client:         &http.Client{Timeout: 5 * time.Second},
	})
	release, newer, err := u.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !newer || release.Tag != "v1.2.3" {
		t.Fatalf("release=%+v newer=%v", release, newer)
	}
}

func TestUpdateDownloadsVerifiesAndInstalls(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("running executable replacement is unsupported on Windows")
	}
	const version = "1.2.3"
	newBinary := []byte("#!/bin/sh\necho updated\n")
	archive := makeTarGz(t, "node-proxy_"+version+"_linux_amd64/proxygw-client", newBinary)
	sum := sha256.Sum256(archive)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]string{"tag_name": "v" + version})
		case "/owner/repo/releases/download/v" + version + "/node-proxy_" + version + "_linux_amd64.tar.gz.sha256":
			_, _ = io.WriteString(w, hex.EncodeToString(sum[:])+"  node-proxy_"+version+"_linux_amd64.tar.gz\n")
		case "/owner/repo/releases/download/v" + version + "/node-proxy_" + version + "_linux_amd64.tar.gz":
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	exe := filepath.Join(dir, "proxygw-client")
	if err := os.WriteFile(exe, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := New(Options{
		Repository:     "owner/repo",
		CurrentVersion: "1.0.0",
		Role:           "client",
		APIBase:        srv.URL,
		GitHubBase:     srv.URL,
		GOOS:           "linux",
		GOARCH:         "amd64",
		BinaryPath:     exe,
		Logger:         discardLogger(),
		Client:         srv.Client(),
	})
	result, err := u.Update(context.Background())
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !result.Updated || result.Version != version {
		t.Fatalf("result=%+v", result)
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, newBinary) {
		t.Fatalf("installed binary = %q, want %q", got, newBinary)
	}
}

func makeTarGz(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
