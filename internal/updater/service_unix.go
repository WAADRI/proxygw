//go:build !windows

package updater

import (
	"os"
	"time"
)

func stopManagedService(string) error  { return nil }
func startManagedService(string) error { return nil }

func renameWithRetry(src, dst string, _ time.Duration) error {
	return os.Rename(src, dst)
}
