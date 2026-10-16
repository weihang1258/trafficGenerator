package core

// 复测回执 #3 发现①：停止任务不释放并发槽（StopTask 缺 taskStore delete，
// FailTask 的"已停止"守卫恰好跳过 delete）——幻影 max_tasks limit。
// 红例：stop 后 activeTaskCount 必须归零（泄漏时恒 1）。
import (
	"testing"
	"time"
)

func TestStopTaskReleasesActiveSlot(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 64, QueueSize: 16,
	})
	rel := make(chan struct{})
	e.RegisterPlanner(&blockingPlanner{name: "tcp", release: rel})
	defer close(rel)
	e.SetBuildFunc(NewBuilder().Build)
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()
	e.maxTasks.Store(1)

	task := Task{ID: "leak-probe", Name: "leak-probe", Protocol: "tcp", Spec: FlowSpec{Count: 1}}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := e.StopTask("leak-probe"); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if n := e.activeTaskCount(); n != 0 {
		t.Fatalf("after stop activeTaskCount = %d, want 0 (slot leak → phantom max_tasks)", n)
	}
	// 泄漏后新任务必须能提交（幻影拒绝复现面）。
	if err := e.SubmitTask(Task{ID: "after-stop", Name: "after-stop", Protocol: "tcp", Spec: FlowSpec{Count: 1}}); err != nil {
		t.Fatalf("submit after stop: %v (phantom max_tasks leak)", err)
	}
}
