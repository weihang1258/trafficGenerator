package core

import (
	"testing"
	"time"
)

// P2-⑤（提示词实测 2026-10-06）：最后一批包直接走完成路径，不经中间
// progress 分支——修复前 OnProgress(100) 永不触发，任务完成后实发统计
// 永远为 0。契约：任务完成时必须收到一次 progress=100 的终态通知，且
// 携带非零 stats（mock planner 产出了包）。
func TestEngineFinalProgressNotification(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 64, QueueSize: 64,
	})
	e.RegisterPlanner(&mockBatchPlanner{name: "tcp", perFlow: 2})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 64), nil })

	done := make(chan string, 1)
	progress := make(chan float64, 8)
	var finalStats TaskStats
	e.OnTaskComplete = func(taskID string) { done <- taskID }
	e.OnProgress = func(taskID string, p float64, stats TaskStats) {
		progress <- p
		finalStats = stats
	}

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{
		ID:       "final-progress-1",
		Name:     "final-progress",
		Protocol: "tcp",
		ClassID:  "final-progress-1",
		Spec:     FlowSpec{Count: 1},
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("task did not complete in 10s")
	}

	// 终态通知：progress 序列里必须出现过 100（修复前只有中间值或什么都没有）。
	close(progress)
	saw100 := false
	for p := range progress {
		if p >= 100 {
			saw100 = true
		}
	}
	if !saw100 {
		t.Error("completed task never delivered a progress=100 notification; final stats are lost")
	}
	if finalStats.PacketsSent == 0 {
		t.Errorf("final stats PacketsSent = 0, want >0 (engine counted %d written packets)", task.Spec.Count)
	}
}
