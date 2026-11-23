package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"proxygw/internal/updater"
)

type updateHelperInvocation struct {
	target  string
	newPath string
	parent  int
	args    string
	status  string
	version string
	cwd     string
}

// runUpdateHelper decodes the restart arguments and delegates to the updater
// helper. It must run before the normal configuration load: the helper has no
// node config and intentionally survives the old process.
func runUpdateHelper(inv updateHelperInvocation) int {
	var args []string
	if inv.args != "" {
		raw, err := base64.StdEncoding.DecodeString(inv.args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "update helper: decode args: %v\n", err)
			return 1
		}
		if err := json.Unmarshal(raw, &args); err != nil {
			fmt.Fprintf(os.Stderr, "update helper: parse args: %v\n", err)
			return 1
		}
	}
	return updater.RunApplyHelper(updater.HelperOptions{
		Target:      inv.target,
		NewBinary:   inv.newPath,
		ParentPID:   inv.parent,
		RestartArgs: args,
		StatusPath:  inv.status,
		Version:     inv.version,
		WorkDir:     inv.cwd,
	})
}
