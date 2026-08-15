package core

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// mockPlanner yields one packet config per Plan() call (one per flow).
// processTask calls Plan spec.Count times, so a task with spec.Count=N
// produces N packets total. This matches real protocol planners, which
// generate a fixed packet sequence per flow regardless of Count.
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
		select {
		case <-ctx.Done():
			return
		case ch <- PacketConfig{FlowID: "f1", PacketIndex: 0}:
		}
	}()
	return ch, nil
}

// TestRateLimit_EnforcesBPS verifies that a task with BPS set actually throttles
// output. BPS is bits/second: 1M = 1 Mbps = 125000 B/s. With 1000-byte packets,
// 200 packets = 200000 bytes total. TokenBucket burst=65536 covers the first
// ~65 packets instantly; the remaining ~135000 bytes must wait at 125000 B/s
// -> ~1.08s. Without rate limiting the whole batch finishes in a few ms, so
// asserting elapsed >= 800ms cleanly distinguishes enforced vs unenforced.
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
		Spec:     FlowSpec{BPS: "1M", Count: 200},
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

// TestEngine_MaxTasksLimit verifies that SetMaxTasks caps concurrent tasks.
func TestEngine_MaxTasksLimit(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 64, QueueSize: 32,
	})
	e.RegisterPlanner(&mockPlanner{name: "tcp"})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 10), nil })
	e.SetMaxTasks(1)
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	// First task is accepted.
	first := Task{ID: "mt-1", Name: "max-tasks-1", Protocol: "tcp", ClassID: "mt-1",
		Spec: FlowSpec{BPS: "1k", Count: 10000}} // slow task so it stays active
	if err := e.SubmitTask(first); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	// Give the config worker a moment to register the task in the store.
	time.Sleep(100 * time.Millisecond)

	// Second task while the first is still active should be rejected.
	second := Task{ID: "mt-2", Name: "max-tasks-2", Protocol: "tcp", ClassID: "mt-2",
		Spec: FlowSpec{BPS: "1k", Count: 10000}}
	err := e.SubmitTask(second)
	if err == nil {
		t.Error("second submit should have been rejected due to max_tasks, but succeeded")
	}
}

// mockBatchPlanner generates a fixed number of packets per flow regardless of
// spec.Count, so batch tests can predict packet counts per class.
type mockBatchPlanner struct {
	name    string
	perFlow int
}

func (m *mockBatchPlanner) Name() string                 { return m.name }
func (m *mockBatchPlanner) Validate(spec FlowSpec) error { return nil }
func (m *mockBatchPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	ch := make(chan PacketConfig)
	go func() {
		defer close(ch)
		for i := 0; i < m.perFlow; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- PacketConfig{FlowID: spec.SrcIP, PacketIndex: uint64(i)}:
			}
		}
	}()
	return ch, nil
}

// TestMixedTraffic_Batch verifies that a BatchSpec task runs multiple protocol
// classes concurrently, producing the expected packet count per class and
// mixing them into the shared output.
func TestMixedTraffic_Batch(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 2, PacketWorkers: 2, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	e.RegisterPlanner(&mockBatchPlanner{name: "tcp", perFlow: 4})
	e.RegisterPlanner(&mockBatchPlanner{name: "udp", perFlow: 2})

	var mu sync.Mutex
	seen := map[string]int{}
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) {
		mu.Lock()
		seen[c.ClassID]++
		mu.Unlock()
		return make([]byte, 64), nil
	})

	done := make(chan string, 1)
	e.OnTaskComplete = func(taskID string) { done <- taskID }

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	// 2 classes: TCP (5 flows x 4 packets = 20) and UDP (3 flows x 2 = 6).
	task := Task{
		ID:       "batch-1",
		Name:     "mixed-traffic-test",
		Protocol: "batch",
		Batch: &BatchSpec{
			Classes: []TrafficClass{
				{
					ID: "tcp", Type: "tcp", FlowCount: 5,
					Config: map[string]interface{}{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
					Tuples: TupleConfig{
						SrcIP:   StrategyConfig{Strategy: "fixed", Value: "10.0.0.1"},
						DstIP:   StrategyConfig{Strategy: "fixed", Value: "10.0.0.2"},
						SrcPort: StrategyConfig{Strategy: "fixed", Value: float64(1000)},
						DstPort: StrategyConfig{Strategy: "fixed", Value: float64(80)},
					},
				},
				{
					ID: "udp", Type: "udp", FlowCount: 3,
					Config: map[string]interface{}{"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4"},
					Tuples: TupleConfig{
						SrcIP:   StrategyConfig{Strategy: "fixed", Value: "10.0.0.3"},
						DstIP:   StrategyConfig{Strategy: "fixed", Value: "10.0.0.4"},
						SrcPort: StrategyConfig{Strategy: "fixed", Value: float64(2000)},
						DstPort: StrategyConfig{Strategy: "fixed", Value: float64(53)},
					},
				},
			},
		},
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("batch task did not complete within 10s")
	}

	mu.Lock()
	defer mu.Unlock()
	// ClassIDs are tagged "taskID:classID" by the batch path.
	if seen["batch-1:tcp"] != 20 {
		t.Errorf("tcp packets = %d, want 20", seen["batch-1:tcp"])
	}
	if seen["batch-1:udp"] != 6 {
		t.Errorf("udp packets = %d, want 6", seen["batch-1:udp"])
	}
}

// TestTask_ZeroConfigsFails verifies that a task producing 0 packet configs
// FAILS instead of hanging (regression for the old silent-completion and
// the pre-2026-08 hang where SetTaskTotalConfigs only completed when
// count > 0). A planner that yields 0 packets per flow means the spec's
// intent (packets) was not realized — reporting completed would mask
// broken planners (jt808/jt809/jtt905 Plan() stubs).
func TestTask_ZeroConfigsFails(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 64, QueueSize: 32,
	})
	e.RegisterPlanner(&fixedPacketsPlanner{name: "tcp", perFlow: 0})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 10), nil })
	failed := make(chan string, 1)
	failMsg := make(chan string, 1)
	e.OnTaskFailed = func(taskID string, errMsg string) { failed <- taskID; failMsg <- errMsg }
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{ID: "zero-1", Name: "zero-config", Protocol: "tcp", ClassID: "zero-1",
		Spec: FlowSpec{Count: 1}} // 1 flow, but planner yields 0 packets per flow
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case <-failed:
		if msg := <-failMsg; msg == "" {
			t.Errorf("zero-config task failed with empty error message")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("zero-config task hung instead of failing")
	}
}

// TestRateLimit_CleanupAfterCompletion verifies that a task's rate limiter is
// removed from the engine once the task completes (prevents unbounded map growth).
func TestRateLimit_CleanupAfterCompletion(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 64, QueueSize: 32,
	})
	e.RegisterPlanner(&mockPlanner{name: "tcp"})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 10), nil })
	done := make(chan string, 1)
	e.OnTaskComplete = func(taskID string) { done <- taskID }
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{ID: "cleanup-1", Name: "cleanup-test", Protocol: "tcp", ClassID: "cleanup-1",
		Spec: FlowSpec{BPS: "100k", Count: 5}}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	<-done

	if limiter := e.GetRateLimiter("cleanup-1"); limiter != nil {
		t.Error("rate limiter not cleaned up after task completion")
	}
}

// TestBufferOverflow_TaskCompletes verifies a task still reaches completion when
// the packet buffer overflows. Previously, buffer.Put returning false (overflow)
// caused an early return that skipped OnPacketWritten, so writtenPackets never
// reached totalConfigs and the task hung in "running" forever, leaking the task
// store entry, rate limiter, and output writer. With the fix, OnPacketWritten
// fires even on overflow (the packet was already sent to the output writer).
func TestBufferOverflow_TaskCompletes(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 8, QueueSize: 128, // tiny buffer: 100 packets will overflow
	})
	e.RegisterPlanner(&mockPlanner{name: "tcp"})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) {
		return make([]byte, 100), nil
	})
	done := make(chan string, 1)
	e.OnTaskComplete = func(taskID string) { done <- taskID }

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{
		ID: "overflow-1", Name: "overflow-test", Protocol: "tcp", ClassID: "overflow-1",
		Spec: FlowSpec{Count: 100}, // 100 packets >> BufferSize 8
	}
	start := time.Now()
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case <-done:
		// Task completed despite buffer overflow dropping packets.
	case <-time.After(5 * time.Second):
		t.Fatalf("task did not complete within 5s (buffer overflow stalled completion); elapsed=%v", time.Since(start))
	}
}

// TestBuildError_FailsTask verifies a packet build failure cannot wedge the
// task in "running" forever. The packet worker drops failed packets and never
// calls OnPacketWritten, so completion waiting only on writtenPackets >=
// totalConfigs never fires. The engine must account for build failures and
// fail the task once every planned config is accounted for (written + failed).
func TestBuildError_FailsTask(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	e.RegisterPlanner(&mockPlanner{name: "tcp"})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) {
		return nil, fmt.Errorf("simulated build failure")
	})

	done := make(chan string, 1)
	e.OnTaskFailed = func(taskID, _ string) { done <- taskID }

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{
		ID: "build-err-1", Name: "build-error-test", Protocol: "tcp", ClassID: "build-err-1",
		Spec: FlowSpec{Count: 1},
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case <-done:
		// Task failed because the only packet could not be built.
	case <-time.After(8 * time.Second):
		t.Fatal("task wedged in running after packet build failure; expected failed")
	}

	// The failed task must be fully cleaned up (FailTask deletes the store entry).
	e.taskMu.Lock()
	_, still := e.taskStore["build-err-1"]
	e.taskMu.Unlock()
	if still {
		t.Error("failed task still present in task store")
	}
}

// TestBuildError_MixedWrittenAndFailed verifies the drain accounting when a
// task has both successful and failed packets: completion fires (as failed)
// only after ALL planned configs are accounted for, not after the first
// partial count.
func TestBuildError_MixedWrittenAndFailed(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	e.RegisterPlanner(&mockPlanner{name: "tcp"})
	var calls int
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) {
		calls++
		if calls == 2 {
			return nil, fmt.Errorf("simulated build failure")
		}
		return make([]byte, 10), nil
	})

	done := make(chan string, 1)
	e.OnTaskFailed = func(taskID, _ string) { done <- taskID }

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{
		ID: "build-err-2", Name: "build-error-mixed", Protocol: "tcp", ClassID: "build-err-2",
		Spec: FlowSpec{Count: 2},
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case <-done:
		// Task failed once the second (failing) packet was accounted for.
	case <-time.After(8 * time.Second):
		t.Fatal("mixed written/failed task hung; expected failed")
	}
}
