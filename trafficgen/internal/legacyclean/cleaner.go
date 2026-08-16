package legacyclean

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gorm.io/gorm"

	"github.com/trafficgen/trafficgen/internal/storage"
)

// Options controls a cleanup run.
type Options struct {
	UserID   string // "" = all users
	Protocol string // "" = all protocols
	Limit    int    // 0 = no limit; caps the number of delete targets (after filters, in stable order)

	Apply      bool // false = dry-run: report only, write nothing
	Force      bool // delete legacy strategies referenced by tasks too (backup records the strategy->task mapping)
	BackupPath string
	NoBackup   bool
}

// Result summarizes a cleanup run.
type Result struct {
	DryRun bool `json:"dry_run"`

	Scanned     int            `json:"scanned"`
	Legacy      int            `json:"legacy"`
	LayerChain  int            `json:"layer_chain"`
	Unparseable int            `json:"unparseable"`
	ByProtocol  map[string]int `json:"by_protocol"`

	// Referenced = legacy targets referenced by >=1 task row (deleted only
	// with Force). Counted across ALL targets, before -limit truncation, so
	// it reflects the full delete set; DanglingTasks below is post-limit.
	Referenced int `json:"referenced"`
	// Deleted = legacy rows actually deleted.
	Deleted int `json:"deleted"`
	// Skipped = classified legacy targets that stay in the DB: referenced
	// without Force, or beyond the Limit cap.
	Skipped int `json:"skipped"`
	// DanglingTasks = distinct tasks referencing >=1 deleted strategy (0 without
	// Force: referenced strategies are kept). After a force apply, those tasks
	// fail with HTTP 400 "strategy not found" on Start.
	DanglingTasks int64 `json:"dangling_tasks"`

	BackupPath string        `json:"backup_path"`
	Elapsed    time.Duration `json:"elapsed_ns"`
}

// backupFile is the on-disk JSON backup written before deletion.
type backupFile struct {
	Tool      string              `json:"tool"`
	CreatedAt string              `json:"created_at"`
	Apply     bool                `json:"apply"`
	Force     bool                `json:"force"`
	Strategies []storage.StrategyModel `json:"strategies"`
	// ReferencedTaskIDs maps each force-deleted referenced strategy to its
	// referencing task IDs so the deletion is reversible.
	ReferencedTaskIDs map[string][]string `json:"referenced_task_ids,omitempty"`
}

// Cleaner performs legacy-strategy cleanup against a gorm DB handle.
type Cleaner struct {
	db *gorm.DB
}

// New returns a Cleaner for the given DB.
func New(db *gorm.DB) *Cleaner {
	return &Cleaner{db: db}
}

// Run scans for legacy strategies and, with Apply, deletes them after writing
// a JSON backup. Dry-run (Apply=false) never writes anything.
func (c *Cleaner) Run(ctx context.Context, opts Options) (*Result, error) {
	start := time.Now()
	res := &Result{
		DryRun:     !opts.Apply,
		ByProtocol: map[string]int{},
	}

	rows, err := c.scanStrategies(ctx, opts.UserID, opts.Protocol)
	if err != nil {
		return nil, err
	}

	// Classify into delete targets vs kept rows. Scan order is stable
	// (created_at ASC, id ASC) so Limit truncates deterministically.
	var targets []storage.StrategyModel
	for _, s := range rows {
		switch Classify(s.Mode, s.Config) {
		case KindLegacy:
			res.Legacy++
			targets = append(targets, s)
		case KindUnparseable:
			res.Unparseable++
			targets = append(targets, s)
		case KindLayerChain:
			res.LayerChain++
		case KindReplay:
			// kept, never a delete target
		}
		res.ByProtocol[s.Protocol]++
	}
	res.Scanned = len(rows)

	// Reference data comes from one full scan of the tasks table, parsed in
	// memory. Per-target LIKE counts would be slow (one query per target), and
	// an OR-chain of LIKE conditions blows SQLite's expression-tree depth
	// limit with ~2k targets (reproduced on the live DB).
	var idx *taskIndex
	var refs []string
	if len(targets) > 0 {
		idx, err = loadTaskIndex(c.db)
		if err != nil {
			return nil, fmt.Errorf("load task index: %w", err)
		}
		refs, _ = idx.referenced(targetIDs(targets))
		res.Referenced = len(refs)
	}
	// Deletion targets = classified legacy targets, minus referenced ones
	// (kept unless Force; those land in Skipped and are still reported).
	// The limit caps ACTUAL deletions: referenced rows are filtered out first,
	// so the cap is never consumed by rows that would be kept anyway.
	if !opts.Force && len(refs) > 0 {
		refSet := make(map[string]bool, len(refs))
		for _, id := range refs {
			refSet[id] = true
		}
		kept := targets[:0]
		for _, s := range targets {
			if !refSet[s.ID] {
				kept = append(kept, s)
			}
		}
		targets = kept
	}
	if opts.Limit > 0 && len(targets) > opts.Limit {
		targets = targets[:opts.Limit]
	}

	// DanglingTasks counts tasks referencing strategies that are actually
	// deleted (or would be, in dry-run). Computed against the FINAL target
	// list: with Force+Limit, tasks referencing beyond-cap strategies survive
	// and must not be counted. Without Force, referenced rows were filtered
	// out above, so nothing can dangle.
	var danglingRefs []string
	if len(targets) > 0 {
		danglingRefs, res.DanglingTasks = idx.referenced(targetIDs(targets))
	}

	if !opts.Apply || len(targets) == 0 {
		res.Skipped = res.Legacy + res.Unparseable - len(targets)
		if res.Skipped < 0 {
			res.Skipped = 0
		}
		res.Elapsed = time.Since(start)
		return res, nil
	}

	// Backup FIRST: any backup failure aborts before a single delete.
	backupPath := opts.BackupPath
	if backupPath == "" {
		backupPath, err = defaultBackupPath(time.Now())
		if err != nil {
			return nil, err
		}
	}
	if !opts.NoBackup {
		refTaskIDs := map[string][]string{}
		if opts.Force {
			// Only strategies actually in the backup (final targets) get a
			// mapping; beyond-cap kept rows are not in the backup.
			for _, id := range danglingRefs {
				refTaskIDs[id] = idx.taskIDs(id)
			}
		}
		if err := writeBackup(backupPath, targets, refTaskIDs, opts); err != nil {
			return nil, fmt.Errorf("write backup: %w", err)
		}
		res.BackupPath = backupPath
	}

	deleted, err := c.deleteTargets(targets)
	if err != nil {
		return nil, fmt.Errorf("delete strategies: %w", err)
	}
	res.Deleted = deleted
	res.Skipped = res.Legacy + res.Unparseable - res.Deleted
	if res.Skipped < 0 {
		res.Skipped = 0
	}
	res.Elapsed = time.Since(start)
	return res, nil
}

// scanStrategies loads all synth strategies (optionally filtered), in stable
// order. Replay rows are excluded at the SQL level; they are never targets.
func (c *Cleaner) scanStrategies(ctx context.Context, userID, protocol string) ([]storage.StrategyModel, error) {
	q := c.db.WithContext(ctx).Model(&storage.StrategyModel{}).Where("mode = ?", "synth")
	if userID != "" {
		q = q.Where("user_id = ?", userID)
	}
	if protocol != "" {
		q = q.Where("protocol = ?", protocol)
	}
	var rows []storage.StrategyModel
	if err := q.Order("created_at ASC, id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("scan strategies: %w", err)
	}
	return rows, nil
}

func targetIDs(rows []storage.StrategyModel) []string {
	ids := make([]string, 0, len(rows))
	for _, s := range rows {
		ids = append(ids, s.ID)
	}
	return ids
}

// taskIndex is an in-memory index of task -> strategy-ids, used for
// reference counting. It scans the tasks table once and matches strategy IDs
// against parsed JSON array elements.
type taskIndex struct {
	tasks []taskRefs
}

type taskRefs struct {
	id     string
	refs   []string
	refSet map[string]struct{}
}

// loadTaskIndex loads every task row's id and strategy_ids and parses the
// JSON array. Unparseable strategy_ids is treated as "references nothing" —
// the column is written by the API as a JSON array, and a malformed value
// cannot contain a valid strategy reference.
func loadTaskIndex(db *gorm.DB) (*taskIndex, error) {
	var tasks []storage.TaskModel
	if err := db.Model(&storage.TaskModel{}).Select("id", "strategy_ids").Find(&tasks).Error; err != nil {
		return nil, err
	}
	idx := &taskIndex{
		tasks: make([]taskRefs, 0, len(tasks)),
	}
	for _, t := range tasks {
		var ids []string
		if t.StrategyIDs != "" {
			if err := json.Unmarshal([]byte(t.StrategyIDs), &ids); err != nil {
				continue // malformed row: cannot reference anything
			}
		}
		refSet := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			refSet[id] = struct{}{}
		}
		idx.tasks = append(idx.tasks, taskRefs{id: t.ID, refs: ids, refSet: refSet})
	}
	return idx, nil
}

// referenced returns the strategy IDs referenced by >=1 task, and the number
// of distinct tasks referencing any of them. Exact match on parsed array
// elements: no substring false positives, no expression-tree depth limit.
func (idx *taskIndex) referenced(ids []string) ([]string, int64) {
	want := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		want[id] = struct{}{}
	}
	referenced := []string{}
	var dangling int64
	seen := make(map[string]struct{})
	for _, t := range idx.tasks {
		hit := false
		for _, rid := range t.refs {
			if _, ok := want[rid]; ok {
				hit = true
				seen[rid] = struct{}{}
			}
		}
		if hit {
			dangling++
		}
	}
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			referenced = append(referenced, id)
		}
	}
	return referenced, dangling
}

// taskIDs returns the IDs of all tasks referencing the strategy (sorted).
func (idx *taskIndex) taskIDs(id string) []string {
	var out []string
	for _, t := range idx.tasks {
		if _, ok := t.refSet[id]; ok {
			out = append(out, t.id)
		}
	}
	sort.Strings(out)
	return out
}

// defaultBackupPath returns the timestamped default backup path under
// data/backups.
func defaultBackupPath(now time.Time) (string, error) {
	dir := filepath.Join("data", "backups")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create backup dir: %w", err)
	}
	return filepath.Join(dir, "strategies-legacy-"+now.Format("20060102-150405")+".json"), nil
}

// writeBackup writes the deleted rows as JSON, fsyncs the file, and creates
// the parent directory on demand. The caller must treat any error as fatal
// BEFORE deleting anything. An existing backup file is never overwritten —
// overwriting would silently destroy a previous run's restore data.
func writeBackup(path string, targets []storage.StrategyModel, refTaskIDs map[string][]string, opts Options) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("backup file already exists: %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}
	bk := backupFile{
		Tool:             "trafficgen-legacy-clean",
		CreatedAt:        time.Now().UTC().Format(time.RFC3339),
		Apply:            true,
		Force:            opts.Force,
		Strategies:       targets,
		ReferencedTaskIDs: refTaskIDs,
	}
	raw, err := json.MarshalIndent(bk, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal backup: %w", err)
	}
	// O_EXCL guards the stat race: two concurrent runs cannot clobber each
	// other's backup even if both pass the existence check.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(raw); err != nil {
		return err
	}
	return f.Sync()
}

// deleteTargets deletes the rows in a single transaction, chunked to stay
// under SQLite's ~999 bind-variable limit. Any chunk error rolls back all.
// The returned count is the number of rows actually deleted.
//
// Classification is re-verified inside the transaction: a row scanned as
// legacy may have been converted to the layer-chain format since the scan,
// and must not be deleted. Rows already gone (concurrently deleted) are
// skipped, not errors.
func (c *Cleaner) deleteTargets(targets []storage.StrategyModel) (int, error) {
	deleted := 0
	err := c.db.Transaction(func(tx *gorm.DB) error {
		ids := targetIDs(targets)
		const chunk = 500
		for start := 0; start < len(ids); start += chunk {
			end := start + chunk
			if end > len(ids) {
				end = len(ids)
			}
			chunkIDs := ids[start:end]

			var rows []storage.StrategyModel
			if err := tx.Where("id IN ?", chunkIDs).Find(&rows).Error; err != nil {
				return err
			}
			if len(rows) == 0 {
				continue
			}
			var stillLegacy []string
			for _, s := range rows {
				switch Classify(s.Mode, s.Config) {
				case KindLegacy, KindUnparseable:
					stillLegacy = append(stillLegacy, s.ID)
				}
			}
			if len(stillLegacy) == 0 {
				continue
			}
			res := tx.Where("id IN ?", stillLegacy).
				Delete(&storage.StrategyModel{})
			if res.Error != nil {
				return res.Error
			}
			deleted += int(res.RowsAffected)
		}
		return nil
	})
	return deleted, err
}
