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

	// Referenced = legacy targets referenced by >=1 task row (deleted only with Force).
	Referenced int `json:"referenced"`
	// Deleted = legacy rows actually deleted.
	Deleted int `json:"deleted"`
	// Skipped = classified legacy targets that stay in the DB: referenced
	// without Force, or beyond the Limit cap.
	Skipped int `json:"skipped"`
	// DanglingTasks = distinct tasks referencing >=1 delete target. After an
	// apply, those tasks fail with HTTP 400 "strategy not found" on Start.
	DanglingTasks int64 `json:"dangling_tasks"`

	BackupPath string        `json:"backup_path"`
	Elapsed    time.Duration `json:"elapsed_ms"`
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

	if opts.Limit > 0 && len(targets) > opts.Limit {
		targets = targets[:opts.Limit]
	}

	// Deletion targets = classified legacy targets, minus referenced ones
	// (kept unless Force; those land in Skipped and are still reported).
	var refs []string
	if len(targets) > 0 {
		var dangling int64
		refs, dangling, err = countTasksReferencing(c.db, targetIDs(targets))
		if err != nil {
			return nil, fmt.Errorf("count task references: %w", err)
		}
		res.Referenced = len(refs)
		res.DanglingTasks = dangling
	}
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
			for _, id := range refs {
				tids, err := taskIDsByStrategy(c.db, id)
				if err != nil {
					return nil, fmt.Errorf("collect task ids for %s: %w", id, err)
				}
				refTaskIDs[id] = tids
			}
		}
		if err := writeBackup(backupPath, targets, refTaskIDs, opts); err != nil {
			return nil, fmt.Errorf("write backup: %w", err)
		}
		res.BackupPath = backupPath
	}

	if err := c.deleteTargets(targets); err != nil {
		return nil, fmt.Errorf("delete strategies: %w", err)
	}
	res.Deleted = len(targets)
	res.Skipped = res.Legacy + res.Unparseable - res.Deleted
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

// countTasksReferencing returns the strategy IDs referenced by >=1 task, and
// the number of distinct tasks referencing any of them.
//
// Task strategy_ids is a JSON array; membership is tested with a quoted LIKE
// ('%"<id>"%'). Quoting both ends prevents uuid-prefix false positives, and
// LIKE avoids json_each because the glebarez/sqlite modernc build has no JSON1
// extension (driver README). A quoted "id" can never appear inside an
// unrelated array element or a bare string, and real strategy IDs never
// contain double quotes.
func countTasksReferencing(db *gorm.DB, ids []string) ([]string, int64, error) {
	if len(ids) == 0 {
		return nil, 0, nil
	}
	referenced := []string{}
	var dangling int64
	for _, id := range ids {
		var n int64
		if err := db.Model(&storage.TaskModel{}).
			Where("strategy_ids LIKE ?", `%"`+id+`"%`).Count(&n).Error; err != nil {
			return nil, 0, err
		}
		if n > 0 {
			referenced = append(referenced, id)
		}
	}
	if len(referenced) > 0 {
		var q *gorm.DB
		for i, id := range referenced {
			cond := "strategy_ids LIKE ?"
			if i == 0 {
				q = db.Model(&storage.TaskModel{}).Where(cond, `%"`+id+`"%`)
			} else {
				q = q.Or(cond, `%"`+id+`"%`)
			}
		}
		if err := q.Count(&dangling).Error; err != nil {
			return nil, 0, err
		}
	}
	return referenced, dangling, nil
}

// taskIDsByStrategy returns the IDs of all tasks referencing the strategy.
func taskIDsByStrategy(db *gorm.DB, id string) ([]string, error) {
	var tasks []storage.TaskModel
	if err := db.Model(&storage.TaskModel{}).
		Where("strategy_ids LIKE ?", `%"`+id+`"%`).Find(&tasks).Error; err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(tasks))
	for _, t := range tasks {
		ids = append(ids, t.ID)
	}
	sort.Strings(ids)
	return ids, nil
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
// BEFORE deleting anything.
func writeBackup(path string, targets []storage.StrategyModel, refTaskIDs map[string][]string, opts Options) error {
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
	f, err := os.Create(path)
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
func (c *Cleaner) deleteTargets(targets []storage.StrategyModel) error {
	return c.db.Transaction(func(tx *gorm.DB) error {
		ids := targetIDs(targets)
		const chunk = 500
		for start := 0; start < len(ids); start += chunk {
			end := start + chunk
			if end > len(ids) {
				end = len(ids)
			}
			if err := tx.Where("id IN ?", ids[start:end]).
				Delete(&storage.StrategyModel{}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
