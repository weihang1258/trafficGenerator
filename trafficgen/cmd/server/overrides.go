// Package main: CLI flag override helpers.
package main

import (
	"github.com/trafficgen/trafficgen/pkg/config"
)

// applyCLIOverrides applies CLI flag overrides onto the loaded config.
// Exposed for testing -- production callers pass the parsed flag values.
// Currently only --fs-root is supported: a non-empty fsRoot takes
// precedence over config.Filesystem.Root (which defaults to
// "data/filesystem").
func applyCLIOverrides(cfg *config.Config, fsRoot string) {
	if fsRoot != "" {
		cfg.Filesystem.Root = fsRoot
	}
}
