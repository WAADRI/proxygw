//go:build !windows

package nodeagent

// detectUpdateService is only meaningful on Windows service managers.
func detectUpdateService() string { return "" }
