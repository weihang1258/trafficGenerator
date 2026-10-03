package mcp

import (
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/replay"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/config"
	"github.com/trafficgen/trafficgen/pkg/netif"
)

// TestNewServerAutoCreatesServiceAccount 钉住 v1 发布契约：全新数据库
// （users 表为空）时，NewServer 自动创建 enabled 的 MCP 服务账号——
// 安装脚本无法预建用户（密码是 bcrypt），不自动建号则发布包开箱即 fatal
// （"service account not found in users table"）。
//
// 行为面：
//   - 用户名/角色取 cfg.ServiceUserID/ServiceUserRole，密码 bcrypt 自
//     cfg.ServiceAccountPassword（密码来自配置文件，不进日志——这也是
//     旧实现拒绝 auto-create 的顾虑，在配置驱动下不成立）
//   - 已存在同名用户：不改动、不重复创建（幂等，升级/手建场景安全）
//   - 已存在但 disabled：维持拒绝启动（禁用语义优先于自动补建）
func TestNewServerAutoCreatesServiceAccount(t *testing.T) {
	sdb, err := storage.NewDB(&config.DatabaseConfig{Type: "sqlite",
		SQLite: config.SQLiteConfig{Path: filepath.Join(t.TempDir(), "test.db")}})
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer sdb.Close()

	eng := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	eng.SetLayerPlannerFactory(layers.BuildLayersPlanner)
	eng.SetBuildFunc(replay.NewBuildFunc(core.NewBuilder().Build))
	if err := eng.Start(); err != nil {
		t.Fatalf("engine start: %v", err)
	}
	defer eng.Stop()

	cfg := &config.MCPConfig{
		Enabled:                true,
		ServiceUserID:          "mcp-service",
		ServiceUserRole:        "user",
		ServiceAccountPassword: "rel-test-pw",
		AuditLog:               false,
		Transports:             config.MCPTransports{Stdio: false},
	}
	if _, err := NewServer(cfg, eng, sdb, netif.NewManager()); err != nil {
		t.Fatalf("NewServer on empty users table: %v", err)
	}

	var u storage.UserModel
	if err := sdb.Where("username = ?", "mcp-service").First(&u).Error; err != nil {
		t.Fatalf("service account not created: %v", err)
	}
	if !u.Enabled {
		t.Errorf("created service account disabled")
	}
	if u.Role != "user" {
		t.Errorf("role = %q, want user (from cfg.ServiceUserRole)", u.Role)
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("rel-test-pw")) != nil {
		t.Errorf("password hash does not match cfg.ServiceAccountPassword")
	}

	// 幂等：二次 NewServer 不报错、不重复建号。
	if _, err := NewServer(cfg, eng, sdb, netif.NewManager()); err != nil {
		t.Fatalf("second NewServer (idempotency): %v", err)
	}
	var count int64
	sdb.Model(&storage.UserModel{}).Where("username = ?", "mcp-service").Count(&count)
	if count != 1 {
		t.Errorf("service account count = %d, want 1 (must not duplicate)", count)
	}

	// disabled 账号仍拒绝启动：禁用语义优先。
	sdb.Model(&storage.UserModel{}).Where("username = ?", "mcp-service").Update("enabled", false)
	if _, err := NewServer(cfg, eng, sdb, netif.NewManager()); err == nil {
		t.Errorf("NewServer with disabled service account must fail")
	}
}
