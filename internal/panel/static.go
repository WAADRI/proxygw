package panel

import (
	"errors"
	"io/fs"
	"net/http"
	pathpkg "path"
	"strconv"
	"strings"
)

// staticContentTypes maps asset extensions to response content types. The list
// is intentionally small: the embedded panel only ships html/css/js plus a few
// optional icons.
var staticContentTypes = map[string]string{
	".html":  "text/html; charset=utf-8",
	".htm":   "text/html; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".mjs":   "text/javascript; charset=utf-8",
	".json":  "application/json; charset=utf-8",
	".map":   "application/json; charset=utf-8",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".gif":   "image/gif",
	".webp":  "image/webp",
	".ico":   "image/x-icon",
	".txt":   "text/plain; charset=utf-8",
	".woff":  "font/woff",
	".woff2": "font/woff2",
}

// serveWeb serves /static/* from the embedded asset tree and answers every
// other non-API path with index.html (SPA fallback).
func (s *Server) serveWeb(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if p == "/static" || strings.HasPrefix(p, staticPrefix) {
		s.serveAsset(w, r)
		return
	}
	s.serveIndex(w, r)
}

// serveAsset serves one embedded asset under /static/. Missing or malformed
// asset paths return 404 instead of the SPA fallback.
func (s *Server) serveAsset(w http.ResponseWriter, r *http.Request) {
	if s.opts.WebFS == nil {
		s.writePlain(w, http.StatusServiceUnavailable, "面板前端资源未内嵌（WebFS 为空）")
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, staticPrefix)
	if rel == "" || strings.HasSuffix(rel, "/") || strings.ContainsAny(rel, "\\\x00") || strings.Contains(rel, "..") {
		s.writePlain(w, http.StatusNotFound, "资源不存在")
		return
	}
	clean := strings.TrimPrefix(pathpkg.Clean("/"+rel), "/")
	if clean == "" || clean == "." {
		s.writePlain(w, http.StatusNotFound, "资源不存在")
		return
	}
	data, err := fs.ReadFile(s.opts.WebFS, clean)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			s.writePlain(w, http.StatusNotFound, "资源不存在")
			return
		}
		s.log.Error("读取内嵌面板资源失败", "asset", clean, "error", err)
		s.writePlain(w, http.StatusInternalServerError, "读取面板资源失败")
		return
	}
	h := w.Header()
	h.Set("Content-Type", contentTypeFor(clean))
	h.Set("Cache-Control", "no-cache")
	h.Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

// serveIndex serves the SPA entry point for "/" and for client side routes.
func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	if s.opts.WebFS == nil {
		s.writePlain(w, http.StatusServiceUnavailable, "面板前端资源未内嵌（WebFS 为空）")
		return
	}
	data, err := fs.ReadFile(s.opts.WebFS, indexFileName)
	if err != nil {
		s.log.Error("内嵌面板缺少 index.html", "error", err)
		s.writePlain(w, http.StatusServiceUnavailable, "面板前端资源缺失（index.html）")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

// contentTypeFor returns the response content type for an asset path.
func contentTypeFor(name string) string {
	if idx := strings.LastIndexByte(name, '.'); idx >= 0 {
		if ct, ok := staticContentTypes[strings.ToLower(name[idx:])]; ok {
			return ct
		}
	}
	return "application/octet-stream"
}

// writePlain writes a small plain text response (static asset errors and the
// missing-WebFS placeholder). JSON is used for /api responses; this helper is
// only for the web surface.
func (s *Server) writePlain(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(message + "\n"))
}
