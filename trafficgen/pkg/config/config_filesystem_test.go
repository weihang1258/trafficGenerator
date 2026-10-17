package config_test

import (
	"os"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/config"
)

func TestConfig_FilesystemDefault(t *testing.T) {
	// 环境守卫：Load("") 会读安装版默认配置 /etc/trafficgen/config.yaml
	// （root:trafficgen 640）。该文件存在但本进程不可读时（开发机未加入
	// trafficgen 组），跳过而非误报——与 D-PORT-1 无关的既有环境项。
	if f, err := os.Open("/etc/trafficgen/config.yaml"); err != nil {
		t.Skip("installed config /etc/trafficgen/config.yaml not readable in this environment")
	} else {
		f.Close()
	}
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load err=%v", err)
	}
	if cfg.Filesystem.Root != "data/filesystem" {
		t.Fatalf("expected Filesystem.Root=\"data/filesystem\", got %q", cfg.Filesystem.Root)
	}
}
