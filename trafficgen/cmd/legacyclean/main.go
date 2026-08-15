// Package main implements tg-legacy-clean, the P5 legacy-strategy cleanup CLI.
//
// It scans the strategies table and classifies each row as layer-chain (new
// format), legacy flat (delete target), unparseable, or replay. Legacy flat
// strategies (design doc 18-layer-config-design.md §11.2) are deleted only
// with -apply, after writing a JSON backup of the deleted rows. Without
// -apply the tool is a dry-run that reports and writes nothing.
//
// Usage:
//
//	tg-legacy-clean [-db path] [-apply] [-force] [-backup path] [-no-backup]
//	               [-user id] [-protocol name] [-limit n] [-json]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	sqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/trafficgen/trafficgen/internal/legacyclean"
)

// forceHint returns a hint when referenced strategies would be kept by a plain
// apply (they are deleted only with -force).
func forceHint(res *legacyclean.Result) string {
	if res.Skipped > 0 {
		return fmt.Sprintf(" (skipped=%d: referenced by tasks, kept without -force)", res.Skipped)
	}
	return ""
}
// sortedProtocols returns the ByProtocol keys in sorted order for stable output.
func sortedProtocols(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func main() {
	var (
		dbPath   = flag.String("db", "./data/trafficgen.db", "SQLite database path")
		apply    = flag.Bool("apply", false, "delete legacy strategies (default: dry-run, report only)")
		force    = flag.Bool("force", false, "also delete legacy strategies referenced by tasks (task rows are left untouched; the backup records the strategy->task mapping)")
		backup   = flag.String("backup", "", "backup file path (default data/backups/strategies-legacy-<timestamp>.json)")
		noBackup = flag.Bool("no-backup", false, "skip writing the JSON backup")
		user     = flag.String("user", "", "only scan strategies of this user_id")
		protocol = flag.String("protocol", "", "only scan strategies of this protocol")
		limit    = flag.Int("limit", 0, "cap the number of delete targets (0 = no limit)")
		asJSON   = flag.Bool("json", false, "print a machine-readable summary as the only stdout output")
	)
	flag.Parse()

	gormDB, err := gorm.Open(sqlite.Open(*dbPath), &gorm.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open db %s: %v\n", *dbPath, err)
		os.Exit(1)
	}

	res, err := legacyclean.New(gormDB).Run(context.Background(), legacyclean.Options{
		UserID:     *user,
		Protocol:   *protocol,
		Limit:      *limit,
		Apply:      *apply,
		Force:      *force,
		BackupPath: *backup,
		NoBackup:   *noBackup,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "legacy-clean: %v\n", err)
		os.Exit(1)
	}

	if *asJSON {
		out := struct {
			DryRun      bool           `json:"dry_run"`
			Scanned     int            `json:"scanned"`
			Legacy      int            `json:"legacy"`
			LayerChain  int            `json:"layer_chain"`
			Unparseable int            `json:"unparseable"`
			Referenced  int            `json:"referenced"`
			Deleted     int            `json:"deleted"`
			Skipped     int            `json:"skipped"`
			Dangling    int64          `json:"dangling_tasks"`
			ByProtocol  map[string]int `json:"by_protocol"`
			BackupPath  string         `json:"backup_path"`
			ElapsedMS   int64          `json:"elapsed_ms"`
		}{
			DryRun: res.DryRun, Scanned: res.Scanned, Legacy: res.Legacy,
			LayerChain: res.LayerChain, Unparseable: res.Unparseable,
			Referenced: res.Referenced, Deleted: res.Deleted, Skipped: res.Skipped,
			Dangling: res.DanglingTasks, ByProtocol: res.ByProtocol,
			BackupPath: res.BackupPath, ElapsedMS: res.Elapsed.Milliseconds(),
		}
		raw, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal summary: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(raw))
		return
	}

	printHuman(res, *noBackup)
}

func printHuman(res *legacyclean.Result, noBackup bool) {
	mode := "apply"
	if res.DryRun {
		mode = "dry-run"
	}
	fmt.Printf("tg-legacy-clean: %s\n", mode)
	fmt.Printf("scanned        %d\n", res.Scanned)
	fmt.Printf("legacy (flat)  %d\n", res.Legacy)
	fmt.Printf("layer_chain    %d\n", res.LayerChain)
	fmt.Printf("unparseable    %d\n", res.Unparseable)
	fmt.Printf("referenced     %d\n", res.Referenced)
	fmt.Printf("deleted        %d\n", res.Deleted)
	fmt.Printf("skipped        %d\n", res.Skipped)
	fmt.Printf("dangling_tasks %d\n", res.DanglingTasks)
	if len(res.ByProtocol) > 0 {
		fmt.Println("by_protocol:")
		for _, p := range sortedProtocols(res.ByProtocol) {
			fmt.Printf("  %-12s %d\n", p, res.ByProtocol[p])
		}
	}
	if res.BackupPath != "" {
		fmt.Printf("backup         %s\n", res.BackupPath)
	} else if noBackup {
		fmt.Println("backup         skipped (-no-backup)")
	}
	if res.DryRun {
		// Skipped > 0 in dry-run means referenced targets kept without -force;
		// they would not be deleted by a plain apply.
		fmt.Printf("dry-run: %d legacy strategies would be deleted; pass -apply to delete%s\n",
			res.Legacy+res.Unparseable-res.Skipped, forceHint(res))
	}
}
