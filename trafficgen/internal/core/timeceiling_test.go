package core

// 复测 #3 P1 红例（修正版）：限速等待路径的任务级截止。
// 任务：100 包 × 100B = 10000B，限速 250B/s → 无修复时排空需 40s；
// time=1s 截止 → 修复后 ~2s 内终态。判据：3s 内终态（任务存活 << 限速排空时长）。
import (
	"context"
	"fmt"
	"testing"
	"time"
)

type burstPlanner struct{ name string }

func (p *burstPlanner) Name() string                 { return p.name }
func (p *burstPlanner) Validate(spec FlowSpec) error { return nil }
func (p *burstPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	ch := make(chan PacketConfig, 128)
	go func() {
		defer close(ch)
		for i := 0; i < 100; i++ {
			ch <- PacketConfig{FlowID: fmt.Sprintf("f-%d", i), PacketIndex: uint64(i)}
		}
	}()
	return ch, nil
}

func TestTimeCeilingTerminatesRateLimitedTask(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	e.RegisterPlanner(&burstPlanner{name: "tcp"})
	e.SetBuildFunc(NewBuilder().Build)
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()
	e.SetClassRateLimit("rate-c1", 250) // 250B/s：10000B 排空需 40s

	task := Task{
		ID: "tc-1", Name: "tc-1", Protocol: "tcp", ClassID: "rate-c1",
		TaskFCType: "time", TaskFCValue: 1,
		Spec: FlowSpec{Count: 100},
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		e.taskMu.RLock()
		_, alive := e.taskStore["tc-1"]
		e.taskMu.RUnlock()
		if !alive {
			return // 终态（complete 或 fail 均算“及时终止”）
		}
		time.Sleep(50 * time.Millisecond)
	}
	e.taskMu.RLock()
	pct := "n/a"
	if entry, ok := e.taskStore["tc-1"]; ok {
		pct = fmt.Sprintf("%v%%", entry.status.Progress)
	}
	e.taskMu.RUnlock()
	t.Fatalf("time=1s ceiling did not terminate within 3s; progress=%s (unfixed: paced drain needs 40s)", pct)
}
