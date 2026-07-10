package core

import (
	"context"
	"testing"
	"time"
)

// mockPlanner yields spec.Count packet configs for testing without a real protocol.
// It registers under a real protocol name (e.g. "tcp") to pass ValidateTask.
type mockPlanner struct {
	name string
}

func (m *mockPlanner) Name() string                 { return m.name }
func (m *mockPlanner) Validate(spec FlowSpec) error { return nil }
func (m *mockPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	ch := make(chan PacketConfig)
	go func() {
		defer close(ch)
		for i := 0; i < spec.Count; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- PacketConfig{FlowID: "f1", PacketIndex: uint64(i)}:
			}
		}
	}()
	return ch, nil
}

// TestRateLimit_EnforcesBPS verifies that a task with BPS set actually throttles
// output. With BPS=100k, 1000-byte packets, 200 packets = 200000 bytes total.
// TokenBucket burst=65536 covers the first ~65 packets instantly; the remaining
// ~135000 bytes must wait at 100000 B/s -> ~1.35s. Without rate limiting the
// whole batch finishes in a few ms, so asserting elapsed >= 800ms cleanly
// distinguishes enforced vs unenforced.
func TestRateLimit_EnforcesBPS(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	e.RegisterPlanner(&mockPlanner{name: "tcp"})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) {
		return make([]byte, 1000), nil
	})

	done := make(chan string, 1)
	e.OnTaskComplete = func(taskID string) { done <- taskID }

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{
		ID:       "rl-1",
		Name:     "rate-limit-test",
		Protocol: "tcp",
		ClassID:  "rl-1",
		Spec:     FlowSpec{BPS: "100k", Count: 200},
	}
	start := time.Now()
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("task did not complete within 8s")
	}
	elapsed := time.Since(start)
	if elapsed < 800*time.Millisecond {
		t.Errorf("rate limit not enforced: elapsed=%v, want >= 800ms", elapsed)
	}
}

// TestEngine_GetCPUUsage verifies that GetCPUUsage reports nonzero process CPU
// usage after burning CPU. Uses Getrusage (user+system time), so the burn
// goroutine's CPU time is reflected process-wide.
func TestEngine_GetCPUUsage(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 64, QueueSize: 32,
	})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	// Burn CPU to produce nonzero process CPU time since engine start.
	done := make(chan struct{})
	go func() {
		x := 0
		for i := 0; i < 5e7; i++ {
			x++
		}
		_ = x
		close(done)
	}()
	<-done
	time.Sleep(100 * time.Millisecond) // let OS account CPU time

	cpu := e.GetCPUUsage()
	if cpu <= 0 {
		t.Errorf("GetCPUUsage() = %v, expected > 0", cpu)
	}
}
