package config_test

import (
	"testing"

	"github.com/trafficgen/trafficgen/pkg/config"
)

func TestConfig_FilesystemDefault(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load err=%v", err)
	}
	if cfg.Filesystem.Root == "" {
		t.Fatalf("Filesystem.Root should default to non-empty")
	}
}
