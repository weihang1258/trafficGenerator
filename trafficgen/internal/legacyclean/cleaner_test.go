package legacyclean

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/trafficgen/trafficgen/internal/storage"
)

// newTestDB opens a fresh SQLite DB on a temp file and runs AutoMigrate.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	gormDB, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := storage.AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return gormDB
}

// seedStrategy inserts a strategy row. config/mode control classification.
func seedStrategy(t *testing.T, db *gorm.DB, id, userID, mode, protocol, config string) {
	t.Helper()
	if err := db.Create(&storage.StrategyModel{
		ID: id, UserID: userID, Name: "s-" + id, Mode: mode, Protocol: protocol, Config: config,
	}).Error; err != nil {
		t.Fatalf("seed strategy %s: %v", id, err)
	}
}

// seedTask inserts a task row referencing strategyIDs (JSON array string).
func seedTask(t *testing.T, db *gorm.DB, id string, strategyIDs string) {
	t.Helper()
	if err := db.Create(&storage.TaskModel{
		ID: id, UserID: "u1", Name: "t-" + id, Status: "completed", StrategyIDs: strategyIDs,
	}).Error; err != nil {
		t.Fatalf("seed task %s: %v", id, err)
	}
}

const (
	flatHTTP  = `{"http":{"method":"GET"}}`
	layered   = `{"layers":[{"ip":{}},{"tcp":{}},{"http":{}}]}`
	garbage   = `{not-json`
	replayCfg = `{"pcap_asset_id":"a1","speed":{"mode":"original"}}`
)

// ---- Classifier (spec: §11.2 删除目标 = synth 且 config 无 layers 键) ----

func TestClassifier_LayersKeyPresent(t *testing.T) {
	if got := Classify("synth", layered); got != KindLayerChain {
		t.Fatalf("Classify(layers) = %v, want KindLayerChain", got)
	}
}

func TestClassifier_LayersKeyAbsent(t *testing.T) {
	if got := Classify("synth", flatHTTP); got != KindLegacy {
		t.Fatalf("Classify(flat) = %v, want KindLegacy", got)
	}
}

func TestClassifier_EmptyConfig(t *testing.T) {
	if got := Classify("synth", `{}`); got != KindLegacy {
		t.Fatalf("Classify({}) = %v, want KindLegacy", got)
	}
}

func TestClassifier_MalformedJSON(t *testing.T) {
	if got := Classify("synth", garbage); got != KindUnparseable {
		t.Fatalf("Classify(garbage) = %v, want KindUnparseable", got)
	}
}

func TestClassifier_ReplayNeverLegacy(t *testing.T) {
	if got := Classify("replay", replayCfg); got != KindReplay {
		t.Fatalf("Classify(replay) = %v, want KindReplay", got)
	}
}

// ---- Run: dry-run ----

func TestRun_DryRunWritesNothing(t *testing.T) {
	db := newTestDB(t)
	seedStrategy(t, db, "s1", "u1", "synth", "http", flatHTTP)
	seedStrategy(t, db, "s2", "u1", "synth", "http", layered)
	backupDir := filepath.Join(t.TempDir(), "backups")

	res, err := New(db).Run(context.Background(), Options{BackupPath: filepath.Join(backupDir, "b.json")})
	if err != nil {
		t.Fatalf("dry-run err: %v", err)
	}
	if !res.DryRun || res.Deleted != 0 || res.Legacy != 1 {
		t.Fatalf("dry-run result = %+v, want DryRun=true Legacy=1 Deleted=0", res)
	}
	var count int64
	db.Model(&storage.StrategyModel{}).Count(&count)
	if count != 2 {
		t.Fatalf("rows after dry-run = %d, want 2 (nothing deleted)", count)
	}
	if _, err := os.Stat(filepath.Join(backupDir, "b.json")); !os.IsNotExist(err) {
		t.Fatalf("backup file should not exist after dry-run, stat err = %v", err)
	}
}

// ---- Run: apply ----

func TestRun_ApplyDeletesOnlyLegacy(t *testing.T) {
	db := newTestDB(t)
	seedStrategy(t, db, "s1", "u1", "synth", "http", flatHTTP)   // legacy
	seedStrategy(t, db, "s2", "u1", "synth", "http", layered)    // keep
	seedStrategy(t, db, "s3", "u1", "replay", "tcp", replayCfg) // keep
	backupPath := filepath.Join(t.TempDir(), "backups", "b.json")

	res, err := New(db).Run(context.Background(), Options{Apply: true, BackupPath: backupPath})
	if err != nil {
		t.Fatalf("apply err: %v", err)
	}
	if res.Deleted != 1 || res.Legacy != 1 {
		t.Fatalf("result = %+v, want Deleted=1 Legacy=1", res)
	}
	var ids []string
	db.Model(&storage.StrategyModel{}).Pluck("id", &ids)
	if len(ids) != 2 || ids[0] != "s2" || ids[1] != "s3" {
		t.Fatalf("remaining ids = %v, want [s2 s3]", ids)
	}
	// Backup file exists, parses, and contains exactly the deleted row (all columns).
	raw, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	var bk backupFile
	if err := json.Unmarshal(raw, &bk); err != nil {
		t.Fatalf("unmarshal backup: %v", err)
	}
	if len(bk.Strategies) != 1 || bk.Strategies[0].ID != "s1" || bk.Strategies[0].Mode != "synth" || bk.Strategies[0].Config != flatHTTP {
		t.Fatalf("backup strategies = %+v, want exactly s1 with full columns", bk.Strategies)
	}
}

func TestRun_ReferencedSkippedByDefault(t *testing.T) {
	db := newTestDB(t)
	seedStrategy(t, db, "s1", "u1", "synth", "http", flatHTTP)
	seedTask(t, db, "t1", `["s1"]`)

	res, err := New(db).Run(context.Background(), Options{Apply: true, BackupPath: filepath.Join(t.TempDir(), "b.json")})
	if err != nil {
		t.Fatalf("apply err: %v", err)
	}
	if res.Referenced != 1 || res.Deleted != 0 || res.DanglingTasks != 1 {
		t.Fatalf("result = %+v, want Referenced=1 Deleted=0 DanglingTasks=1", res)
	}
	var count int64
	db.Model(&storage.StrategyModel{}).Where("id = ?", "s1").Count(&count)
	if count != 1 {
		t.Fatalf("referenced strategy should be kept, count = %d", count)
	}
}

func TestRun_ForceDeletesReferenced(t *testing.T) {
	db := newTestDB(t)
	seedStrategy(t, db, "s1", "u1", "synth", "http", flatHTTP)
	seedTask(t, db, "t1", `["s1"]`)
	backupPath := filepath.Join(t.TempDir(), "backups", "b.json")

	res, err := New(db).Run(context.Background(), Options{Apply: true, Force: true, BackupPath: backupPath})
	if err != nil {
		t.Fatalf("apply err: %v", err)
	}
	if res.Deleted != 1 || res.Referenced != 1 {
		t.Fatalf("result = %+v, want Deleted=1 Referenced=1", res)
	}
	var count int64
	db.Model(&storage.StrategyModel{}).Where("id = ?", "s1").Count(&count)
	if count != 0 {
		t.Fatalf("forced strategy should be deleted, count = %d", count)
	}
	// Task row is untouched (no scrub).
	var task storage.TaskModel
	db.First(&task, "id = ?", "t1")
	if task.StrategyIDs != `["s1"]` {
		t.Fatalf("task strategy_ids changed (should be untouched): %q", task.StrategyIDs)
	}
	// Backup records strategy -> task mapping.
	raw, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	var bk backupFile
	if err := json.Unmarshal(raw, &bk); err != nil {
		t.Fatalf("unmarshal backup: %v", err)
	}
	if tasks := bk.ReferencedTaskIDs["s1"]; len(tasks) != 1 || tasks[0] != "t1" {
		t.Fatalf("referenced_task_ids = %v, want {s1:[t1]}", bk.ReferencedTaskIDs)
	}
}

// ---- Filters ----

func TestRun_UserFilter(t *testing.T) {
	db := newTestDB(t)
	seedStrategy(t, db, "s1", "u1", "synth", "http", flatHTTP)
	seedStrategy(t, db, "s2", "u2", "synth", "http", flatHTTP)

	res, err := New(db).Run(context.Background(), Options{Apply: true, UserID: "u2", BackupPath: filepath.Join(t.TempDir(), "b.json")})
	if err != nil {
		t.Fatalf("apply err: %v", err)
	}
	if res.Deleted != 1 {
		t.Fatalf("deleted = %d, want 1", res.Deleted)
	}
	var ids []string
	db.Model(&storage.StrategyModel{}).Pluck("id", &ids)
	if len(ids) != 1 || ids[0] != "s1" {
		t.Fatalf("remaining ids = %v, want [s1]", ids)
	}
}

func TestRun_ProtocolFilter(t *testing.T) {
	db := newTestDB(t)
	seedStrategy(t, db, "s1", "u1", "synth", "http", flatHTTP)
	seedStrategy(t, db, "s2", "u1", "synth", "dns", `{"dns":{"query":"x.com"}}`)

	res, err := New(db).Run(context.Background(), Options{Apply: true, Protocol: "dns", BackupPath: filepath.Join(t.TempDir(), "b.json")})
	if err != nil {
		t.Fatalf("apply err: %v", err)
	}
	if res.Deleted != 1 {
		t.Fatalf("deleted = %d, want 1", res.Deleted)
	}
	var ids []string
	db.Model(&storage.StrategyModel{}).Pluck("id", &ids)
	if len(ids) != 1 || ids[0] != "s1" {
		t.Fatalf("remaining ids = %v, want [s1]", ids)
	}
}

func TestRun_LimitCapsTargets(t *testing.T) {
	db := newTestDB(t)
	for i := 1; i <= 5; i++ {
		seedStrategy(t, db, "s"+strings.Repeat("0", 2)+string(rune('0'+i)), "u1", "synth", "http", flatHTTP)
	}

	res, err := New(db).Run(context.Background(), Options{Apply: true, Limit: 2, BackupPath: filepath.Join(t.TempDir(), "b.json")})
	if err != nil {
		t.Fatalf("apply err: %v", err)
	}
	if res.Deleted != 2 || res.Legacy != 5 {
		t.Fatalf("deleted = %d legacy = %d, want Deleted=2 Legacy=5 (Legacy counts all classified, only Deleted is capped)", res.Deleted, res.Legacy)
	}
	if res.Skipped != 3 {
		t.Fatalf("skipped = %d, want 3 (5 targets, 2 deleted)", res.Skipped)
	}
	var count int64
	db.Model(&storage.StrategyModel{}).Count(&count)
	if count != 3 {
		t.Fatalf("remaining rows = %d, want 3", count)
	}
}

func TestRun_EmptyFilterResult(t *testing.T) {
	db := newTestDB(t)
	seedStrategy(t, db, "s1", "u1", "synth", "http", flatHTTP)

	res, err := New(db).Run(context.Background(), Options{Apply: true, UserID: "nobody", BackupPath: filepath.Join(t.TempDir(), "b.json")})
	if err != nil {
		t.Fatalf("apply err: %v", err)
	}
	if res.Deleted != 0 || res.Scanned != 0 {
		t.Fatalf("result = %+v, want Deleted=0 Scanned=0", res)
	}
}

// ---- Idempotency ----

func TestRun_Idempotent(t *testing.T) {
	db := newTestDB(t)
	seedStrategy(t, db, "s1", "u1", "synth", "http", flatHTTP)

	for i := 0; i < 2; i++ {
		res, err := New(db).Run(context.Background(), Options{Apply: true, BackupPath: filepath.Join(t.TempDir(), "b.json")})
		if err != nil {
			t.Fatalf("apply #%d err: %v", i+1, err)
		}
		if i == 0 && res.Deleted != 1 {
			t.Fatalf("first apply deleted = %d, want 1", res.Deleted)
		}
		if i == 1 && (res.Deleted != 0 || res.Legacy != 0) {
			t.Fatalf("second apply = %+v, want all zeros", res)
		}
	}
}

// ---- Failure paths ----

func TestRun_BackupWriteFailureAborts(t *testing.T) {
	db := newTestDB(t)
	seedStrategy(t, db, "s1", "u1", "synth", "http", flatHTTP)
	// A path whose parent is an existing FILE cannot be created → backup write fails.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	badPath := filepath.Join(blocker, "b.json")

	_, err := New(db).Run(context.Background(), Options{Apply: true, BackupPath: badPath})
	if err == nil {
		t.Fatalf("apply should fail on backup write error")
	}
	var count int64
	db.Model(&storage.StrategyModel{}).Count(&count)
	if count != 1 {
		t.Fatalf("rows after failed backup = %d, want 1 (zero deletions)", count)
	}
}

func TestRun_ClosedDBError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	gormDB, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := storage.AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	seedStrategy(t, gormDB, "s1", "u1", "synth", "http", flatHTTP)

	sqlDB, err := gormDB.DB()
	if err != nil {
		t.Fatalf("sql.DB: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err = New(gormDB).Run(context.Background(), Options{Apply: true, BackupPath: filepath.Join(t.TempDir(), "b.json")})
	if err == nil {
		t.Fatalf("Run on closed DB should error, not panic")
	}
	if !errors.Is(err, gorm.ErrInvalidDB) && !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_NoBackupSkipsBackup(t *testing.T) {
	db := newTestDB(t)
	seedStrategy(t, db, "s1", "u1", "synth", "http", flatHTTP)
	backupPath := filepath.Join(t.TempDir(), "backups", "b.json")

	res, err := New(db).Run(context.Background(), Options{Apply: true, NoBackup: true, BackupPath: backupPath})
	if err != nil {
		t.Fatalf("apply err: %v", err)
	}
	if res.Deleted != 1 || res.BackupPath != "" {
		t.Fatalf("result = %+v, want Deleted=1 BackupPath=\"\"", res)
	}
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("backup file should not exist with -no-backup, stat err = %v", err)
	}
}

func TestRun_UnparseableDeletedAndCounted(t *testing.T) {
	db := newTestDB(t)
	seedStrategy(t, db, "s1", "u1", "synth", "http", garbage)

	res, err := New(db).Run(context.Background(), Options{Apply: true, BackupPath: filepath.Join(t.TempDir(), "b.json")})
	if err != nil {
		t.Fatalf("apply err: %v", err)
	}
	if res.Unparseable != 1 || res.Deleted != 1 {
		t.Fatalf("result = %+v, want Unparseable=1 Deleted=1", res)
	}
	var count int64
	db.Model(&storage.StrategyModel{}).Count(&count)
	if count != 0 {
		t.Fatalf("unparseable strategy should be deleted, count = %d", count)
	}
}

// ---- reference counting: substring false-positive guard ----

func TestCountTasksReferencing_NoSubstringFalsePositive(t *testing.T) {
	db := newTestDB(t)
	seedStrategy(t, db, "abc", "u1", "synth", "http", flatHTTP)
	seedTask(t, db, "t1", `["abcd"]`) // similar-prefix id, must NOT match "abc"
	seedTask(t, db, "t2", `["abc"]`)

	refs, n, err := countTasksReferencing(db, []string{"abc"})
	if err != nil {
		t.Fatalf("countTasksReferencing err: %v", err)
	}
	if len(refs) != 1 || refs[0] != "abc" {
		t.Fatalf("referenced = %v, want [abc] (abcd must not match)", refs)
	}
	if n != 1 {
		t.Fatalf("dangling tasks = %d, want 1 (only t2)", n)
	}
}

// ---- backup default path ----

func TestDefaultBackupPath(t *testing.T) {
	p, err := defaultBackupPath(time.Date(2026, 8, 14, 10, 30, 5, 0, time.UTC))
	if err != nil {
		t.Fatalf("defaultBackupPath err: %v", err)
	}
	if !strings.Contains(p, "strategies-legacy-20260814-103005.json") {
		t.Fatalf("backup path = %q, want timestamped strategies-legacy-20260814-103005.json", p)
	}
}
