package storage

import (
	"path/filepath"
	"testing"

	"github.com/trafficgen/trafficgen/pkg/config"
)

// TestSQLiteWALPragmas 钉住 SQLite 打开时的 PRAGMA 契约（v1 发布项）：
//   - journal_mode=WAL：MCP 客户端高频轮询（读）与任务状态写并发，默认
//     DELETE 模式写阻塞读、锁放大；WAL 读写不互斥。
//   - busy_timeout=5000：写锁竞争时等 5s 而非立即 SQLITE_BUSY 报错。
//
// 两条都必须经 DSN pragma（glebarez 驱动）在连接建立时生效——不是打开后
// 补执行（连接池每条新连接都要继承）。
func TestSQLiteWALPragmas(t *testing.T) {
	dir := t.TempDir()
	db, err := NewDB(&config.DatabaseConfig{
		Type: "sqlite",
		SQLite: config.SQLiteConfig{
			Path: filepath.Join(dir, "test.db"),
		},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer sqlClose(t, db)

	var mode string
	if err := db.Raw("PRAGMA journal_mode").Scan(&mode).Error; err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal (MCP poll/write concurrency requires WAL)", mode)
	}

	var timeout int
	if err := db.Raw("PRAGMA busy_timeout").Scan(&timeout).Error; err != nil {
		t.Fatalf("read busy_timeout: %v", err)
	}
	if timeout != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", timeout)
	}
}

// sqlClose 收尾关闭连接（连接池可能为 0 连接，关闭错误不致命）。
func sqlClose(t *testing.T, db *DB) {
	t.Helper()
	// db.DB 是内嵌的 *gorm.DB 字段；.DB() 才是取 database/sql 句柄的方法。
	if sqlDB, err := db.DB.DB(); err == nil {
		_ = sqlDB.Close()
	}
}
