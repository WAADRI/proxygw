//go:build windows

package nodeagent

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// detectUpdateService finds the Windows service that launches this executable.
// It supports NSSM (Application under Parameters) and plain sc.exe services
// (ImagePath pointing at the executable). UPDATE_SERVICE_NAME overrides the
// detection for other wrappers.
func detectUpdateService() string {
	if name := strings.TrimSpace(os.Getenv("UPDATE_SERVICE_NAME")); name != "" {
		return name
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	exe = filepath.Clean(exe)
	root, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, registry.READ)
	if err != nil {
		return ""
	}
	defer root.Close()
	names, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return ""
	}
	for _, name := range names {
		if params, err := registry.OpenKey(root, name+`\Parameters`, registry.READ); err == nil {
			app, _, _ := params.GetStringValue("Application")
			params.Close()
			if sameExecutable(app, exe) {
				return name
			}
		}
		if svc, err := registry.OpenKey(root, name, registry.READ); err == nil {
			image, _, _ := svc.GetStringValue("ImagePath")
			svc.Close()
			if sameExecutable(serviceImageExecutable(image), exe) {
				return name
			}
		}
	}
	return ""
}

func sameExecutable(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	clean := func(p string) string {
		p = strings.Trim(p, `"`)
		p = strings.TrimSpace(p)
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		return filepath.Clean(p)
	}
	return strings.EqualFold(clean(a), clean(b))
}

// serviceImageExecutable extracts the executable from an sc.exe ImagePath,
// which may be quoted and may carry arguments.
func serviceImageExecutable(image string) string {
	image = strings.TrimSpace(image)
	if image == "" {
		return ""
	}
	if image[0] == '"' {
		if end := strings.IndexByte(image[1:], '"'); end >= 0 {
			return image[1 : 1+end]
		}
		return strings.Trim(image, `"`)
	}
	if idx := strings.IndexAny(image, " \t"); idx >= 0 {
		return image[:idx]
	}
	return image
}
