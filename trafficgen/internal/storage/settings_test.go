package storage

import (
	"path/filepath"
	"testing"

	sqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// newTestDB opens a fresh SQLite DB on a temp file and runs AutoMigrate.
// Returns the DB handle and the file path (so a test can reopen the file
// to simulate a process restart).
func newTestDB(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	gormDB, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &DB{DB: gormDB}, path
}

// reopenDB reopens an existing SQLite file and runs AutoMigrate (no-op if
// tables already exist).
func reopenDB(t *testing.T, path string) *DB {
	t.Helper()
	gormDB, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	if err := AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &DB{DB: gormDB}
}

// TestSettings_Persist verifies that settings saved through one DB handle are
// read back through a freshly reopened handle (simulating a process restart).
func TestSettings_Persist(t *testing.T) {
	db, path := newTestDB(t)

	// First "instance": GetSettings creates defaults, then we save overrides.
	s, err := db.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings (initial): %v", err)
	}
	s.MaxTasks = 50
	s.BufferSize = 2048
	s.LogLevel = "warn"
	if err := db.SaveSettings(s); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	// Second "instance": reopen the same file and read back.
	db2 := reopenDB(t, path)
	got, err := db2.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings (reread): %v", err)
	}
	if got.MaxTasks != 50 || got.BufferSize != 2048 || got.LogLevel != "warn" {
		t.Errorf("settings not persisted across reopen: %+v", got)
	}
}

// TestSettings_Defaults verifies that GetSettings on a fresh DB returns the
// documented defaults and seeds the row.
func TestSettings_Defaults(t *testing.T) {
	db, _ := newTestDB(t)
	s, err := db.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if s.MaxTasks != 100 || s.BufferSize != 4096 || s.LogLevel != "info" {
		t.Errorf("defaults wrong: %+v", s)
	}
}
