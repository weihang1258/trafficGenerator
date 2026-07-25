package main

import (
	"testing"

	"github.com/trafficgen/trafficgen/pkg/config"
)

func TestApplyCLIOverrides_FsRoot(t *testing.T) {
	cfg := &config.Config{Filesystem: config.FilesystemConfig{Root: "data/filesystem"}}
	applyCLIOverrides(cfg, "/custom/fs")
	if cfg.Filesystem.Root != "/custom/fs" {
		t.Fatalf("expected /custom/fs, got %q", cfg.Filesystem.Root)
	}
}

func TestApplyCLIOverrides_FsRootEmpty_NoOp(t *testing.T) {
	cfg := &config.Config{Filesystem: config.FilesystemConfig{Root: "data/filesystem"}}
	applyCLIOverrides(cfg, "")
	if cfg.Filesystem.Root != "data/filesystem" {
		t.Fatalf("expected data/filesystem (unchanged), got %q", cfg.Filesystem.Root)
	}
}
