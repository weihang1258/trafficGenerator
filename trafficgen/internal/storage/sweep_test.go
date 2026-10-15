package storage

// D-ROBUST-1 T-RB1-3：孤儿清扫单测（MCP 面验收在部署后 live 做）。

import "testing"

func TestSweepOrphanTasks(t *testing.T) {
	db, _ := newTestDB(t)
	seed := []TaskModel{
		{ID: "orphan-run", UserID: "u1", Name: "r", Status: "running"},
		{ID: "orphan-pending", UserID: "u1", Name: "p", Status: "pending"},
		{ID: "orphan-starting", UserID: "u1", Name: "s", Status: "starting"},
		{ID: "done", UserID: "u1", Name: "c", Status: "completed"},
	}
	for i := range seed {
		if err := db.Create(&seed[i]).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	n, err := db.SweepOrphanTasks()
	if err != nil {
		t.Fatalf("SweepOrphanTasks: %v", err)
	}
	if n != 3 {
		t.Fatalf("swept = %d, want 3", n)
	}
	var got TaskModel
	if err := db.Where("id = ?", "orphan-run").First(&got).Error; err != nil {
		t.Fatalf("orphan-run: %v", err)
	}
	if got.Status != "error" || got.ErrorMessage != "interrupted by server restart" {
		t.Fatalf("orphan-run = %s / %q", got.Status, got.ErrorMessage)
	}
	var done TaskModel
	if err := db.Where("id = ?", "done").First(&done).Error; err != nil {
		t.Fatalf("done: %v", err)
	}
	if done.Status != "completed" {
		t.Fatalf("completed task must be untouched, got %s", done.Status)
	}
	// 幂等：再扫一次 = 0 行。
	if n2, _ := db.SweepOrphanTasks(); n2 != 0 {
		t.Fatalf("second sweep = %d, want 0", n2)
	}
}
