package core

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ctxBlockingPlanner blocks on ctx.Done() so a time-capped task's deadline
// fires before any config is emitted — modeling the legitimate zero-config
// completion path (time-limited task, no packets yet).
type ctxBlockingPlanner struct{ name string }

func (m *ctxBlockingPlanner) Name() string                 { return m.name }
func (m *ctxBlockingPlanner) Validate(spec FlowSpec) error { return nil }
func (m *ctxBlockingPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	ch := make(chan PacketConfig)
	go func() {
		defer close(ch)
		<-ctx.Done()
	}()
	return ch, nil
}

// emptyChannelPlanner validates OK but yields zero configs — modeling the
// broken Plan() stubs (jt808/jt809/jtt905, worker.go:175 dispatches to
// planners[task.Protocol], whose Plan returns a closed channel). A planner
// whose flow genuinely produces no packets has no valid fallback today:
// planners must fail fast (e.g. postgresql rejects a nil spec.PostgreSQL).
type emptyChannelPlanner struct{ name string }

func (m *emptyChannelPlanner) Name() string                 { return m.name }
func (m *emptyChannelPlanner) Validate(spec FlowSpec) error { return nil }
func (m *emptyChannelPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	ch := make(chan PacketConfig)
	close(ch)
	return ch, nil
}

// blockThenZeroPlanner blocks on ctx.Done() inside Plan, then returns a
// synchronously closed (empty) channel. With flowCount >= 2 the worker's first
// per-flow range exits via channel close (NOT the in-range ctx select), so
// iteration 2's loop-head select deterministically sees the expired context —
// exercising the loop-head DeadlineExceeded branch, which the
// ctxBlockingPlanner-based test can never reach (its planner closes the
// channel only after ctx expires, so the in-range select handles the deadline
// and the loop-head branch is dead code in that test).
type blockThenZeroPlanner struct{ name string }

func (m *blockThenZeroPlanner) Name() string                 { return m.name }
func (m *blockThenZeroPlanner) Validate(spec FlowSpec) error { return nil }
func (m *blockThenZeroPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	<-ctx.Done()
	ch := make(chan PacketConfig)
	close(ch)
	return ch, nil
}

// failValidateThenZeroPlanner models a broken batch class: the first flow's
// Validate fails (+1 flowFailure via the per-flow path), subsequent flows
// validate OK but Plan emits 0 configs. With FlowCount=2 this exercises the
// guard's interaction with already-counted per-flow failures.
type failValidateThenZeroPlanner struct {
	name string
	n    int64 // per-call counter, first call fails Validate
}

func (m *failValidateThenZeroPlanner) Name() string { return m.name }
func (m *failValidateThenZeroPlanner) Validate(spec FlowSpec) error {
	if atomic.AddInt64(&m.n, 1) == 1 {
		return errors.New("first flow invalid")
	}
	return nil
}
func (m *failValidateThenZeroPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	ch := make(chan PacketConfig)
	close(ch)
	return ch, nil
}

// TestEngine_ZeroConfigTaskFails: a single-protocol task whose planner
// produced zero configs must FAIL, not report completed with 0 packets.
// Regression for jt808/jt809/jtt905: their Plan() stub returns an empty
// channel, and the worker's onTaskDone(task.ID, nil, 0) let the engine
// complete the task silently (CLAUDE.md: "task reported completed with
// 0 packets" anti-pattern).
func TestEngine_ZeroConfigTaskFails(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	e.RegisterPlanner(&emptyChannelPlanner{name: "jt808"})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 64), nil })

	failed := make(chan string, 1)
	failMsg := make(chan string, 1)
	e.OnTaskFailed = func(taskID string, errMsg string) {
		failed <- taskID
		failMsg <- errMsg
	}

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{
		ID:       "zero-1",
		Name:     "zero-config",
		Protocol: "jt808",
		ClassID:  "zero-1",
		Spec:     FlowSpec{Count: 1},
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}

	select {
	case <-failed:
		msg := <-failMsg
		if msg == "" {
			t.Errorf("task failed with empty error message")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("zero-config task did not fail; engine completed it silently")
	}
}

// TestEngine_BatchZeroConfigClassFails: a batch whose classes all yield zero
// configs fails with the "all flows failed" error — mirroring the
// single-protocol zero-config failure. Uses emptyChannelPlanner as the
// broken class (registered under a real protocol name to pass
// ValidateBatchSpec's type whitelist).
func TestEngine_BatchZeroConfigClassFails(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 2, PacketWorkers: 2, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	e.RegisterPlanner(&emptyChannelPlanner{name: "jt808"})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 64), nil })

	failed := make(chan string, 1)
	failMsg := make(chan string, 1)
	e.OnTaskFailed = func(taskID string, errMsg string) { failed <- taskID; failMsg <- errMsg }

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{
		ID:       "batch-zero",
		Name:     "batch-zero-config",
		Protocol: "batch",
		Batch: &BatchSpec{
			Classes: []TrafficClass{
				{
					ID: "broken", Type: "jt808", FlowCount: 2,
					Config: map[string]interface{}{},
				},
			},
		},
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}

	select {
	case <-failed:
		if msg := <-failMsg; msg == "" {
			t.Errorf("batch zero-config task failed with empty error message")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("batch zero-config class did not fail the task")
	}
}

// TestEngine_BatchZeroConfigWithHealthyClass: a 0-config class inside a batch
// with a healthy sibling class must NOT fail the task (batch semantics tolerate
// partial class failure) — but its flows count as failed, and the healthy
// class's packets must still flow through.
func TestEngine_BatchZeroConfigWithHealthyClass(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 2, PacketWorkers: 2, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	e.RegisterPlanner(&emptyChannelPlanner{name: "jt808"})
	e.RegisterPlanner(&mockBatchPlanner{name: "tcp", perFlow: 2})
	var mu sync.Mutex
	seen := map[string]int{}
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) {
		mu.Lock()
		seen[c.ClassID]++
		mu.Unlock()
		return make([]byte, 64), nil
	})

	done := make(chan string, 1)
	failed := make(chan string, 1)
	e.OnTaskComplete = func(taskID string) { done <- taskID }
	e.OnTaskFailed = func(taskID, _ string) { failed <- taskID }

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{
		ID:       "batch-mixed",
		Name:     "batch-mixed-zero",
		Protocol: "batch",
		Batch: &BatchSpec{
			Classes: []TrafficClass{
				{
					ID: "broken", Type: "jt808", FlowCount: 2,
					Config: map[string]interface{}{},
				},
				{
					ID: "tcp", Type: "tcp", FlowCount: 1,
					Config: map[string]interface{}{},
				},
			},
		},
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}

	select {
	case <-done:
		// Task completes: the healthy class still produces its packets.
	case <-failed:
		t.Fatal("batch with one healthy class failed; expected completion")
	case <-time.After(5 * time.Second):
		t.Fatal("batch task neither completed nor failed")
	}

	mu.Lock()
	defer mu.Unlock()
	if seen["batch-mixed:tcp"] != 2 {
		t.Errorf("healthy tcp class packets = %d, want 2", seen["batch-mixed:tcp"])
	}
	if n := seen["batch-mixed:broken"]; n != 0 {
		t.Errorf("zero-config class emitted %d packets, want 0", n)
	}
}

// TestEngine_BatchPartialFailZeroConfigNoDoubleCount: a class whose per-flow
// failures were already counted (Validate/Plan errors increment flowFailures
// per flow) must not have its zero-emission guard double-count the full
// FlowCount — that would push the batch past the all-flows-failed threshold
// and misreport a mixed batch that actually produced packets (replay+batch
// guard review finding). class A (FlowCount=2): flow 1 fails Validate (+1),
// flow 2 plans OK but emits 0 configs; class B (FlowCount=1) healthy.
// flowFailures must be 1+1+0=2 < totalFlows=3 → task completes with B's packet.
func TestEngine_BatchPartialFailZeroConfigNoDoubleCount(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 2, PacketWorkers: 2, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	e.RegisterPlanner(&mockBatchPlanner{name: "tcp", perFlow: 1})
	e.RegisterPlanner(&failValidateThenZeroPlanner{name: "jt808"})
	var mu sync.Mutex
	seen := map[string]int{}
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) {
		mu.Lock()
		seen[c.ClassID]++
		mu.Unlock()
		return make([]byte, 64), nil
	})

	done := make(chan string, 1)
	failed := make(chan string, 1)
	e.OnTaskComplete = func(taskID string) { done <- taskID }
	e.OnTaskFailed = func(taskID, _ string) { failed <- taskID }

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{
		ID:       "batch-partial",
		Name:     "batch-partial-fail",
		Protocol: "batch",
		Batch: &BatchSpec{
			Classes: []TrafficClass{
				{ID: "broken", Type: "jt808", FlowCount: 2,
					Config: map[string]interface{}{}},
				{ID: "tcp", Type: "tcp", FlowCount: 1,
					Config: map[string]interface{}{}},
			},
		},
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}

	select {
	case <-done:
		// 2 real failures < 3 total flows: batch completes with healthy output.
	case <-failed:
		t.Fatal("batch with 2/3 failed flows must complete; got all-flows-failed (double-counted?)")
	case <-time.After(5 * time.Second):
		t.Fatal("batch task neither completed nor failed")
	}

	mu.Lock()
	defer mu.Unlock()
	if got := seen["batch-partial:tcp"]; got != 1 {
		t.Errorf("healthy class emitted %d packets, want 1", got)
	}
}

// TestEngine_UnknownProtocolFails: regression guard — unknown protocols are
// rejected at SubmitTask (convert.go ValidateTask); the 0-config guard must
// not change that.
func TestEngine_UnknownProtocolFails(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 64), nil })

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{
		ID:       "zero-3",
		Name:     "unknown",
		Protocol: "nosuchproto",
		ClassID:  "zero-3",
		Spec:     FlowSpec{Count: 1},
	}
	if err := e.SubmitTask(task); err == nil {
		t.Fatal("unknown-protocol task submitted without error")
	}
}

// TestEngine_ZeroConfigTimeTaskCompletes: a time-capped task whose deadline
// expires before any packet is emitted is LEGITIMATE zero-config completion —
// the task ran its configured lifetime (engine.go:694 WithTimeout, worker.go
// DeadlineExceeded branch reports nil). The 0-config guard must not turn this
// into a failure (review found: the guard's taskCtx.Err()==nil condition is
// adjacent to this exemption and untested).
func TestEngine_ZeroConfigTimeTaskCompletes(t *testing.T) {
	// fixedPacketsPlanner yields perFlow configs then closes the channel, so a
	// slow-flow planner (20ms/flow) with perFlow=0 still completes instantly;
	// use a planner that BLOCKS on ctx so the deadline fires with 0 configs.
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	e.RegisterPlanner(&ctxBlockingPlanner{name: "tcp"})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 64), nil })

	done := make(chan string, 1)
	failed := make(chan string, 1)
	e.OnTaskComplete = func(taskID string) { done <- taskID }
	e.OnTaskFailed = func(taskID, _ string) { failed <- taskID }

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{
		ID:       "time-zero",
		Name:     "time-zero-config",
		Protocol: "tcp",
		ClassID:  "time-zero",
		Spec:     FlowSpec{Count: 1, Duration: 1}, // 1s deadline
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}

	select {
	case <-done:
		// Time-capped zero-config task completed normally.
	case <-failed:
		t.Fatal("time-capped zero-config task failed; expected normal completion")
	case <-time.After(5 * time.Second):
		t.Fatal("time-capped zero-config task hung")
	}
}

// TestEngine_TimeoutZeroConfigCompletes deterministically exercises the
// worker's loop-head deadline branch: the planner blocks on ctx expiry inside
// Plan, so flow 0's range exits via channel close and iteration 1's loop-head
// select sees the expired context — normal completion, no guard trip.
// flowCount=2 is required: with flowCount=1 the guard (correctly) fires
// because the context is still alive when the sole flow finishes.
func TestEngine_TimeoutZeroConfigCompletes(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	e.RegisterPlanner(&blockThenZeroPlanner{name: "tcp"})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 64), nil })

	done := make(chan string, 1)
	failed := make(chan string, 1)
	failMsg := make(chan string, 1)
	e.OnTaskComplete = func(taskID string) { done <- taskID }
	e.OnTaskFailed = func(taskID, msg string) { failed <- taskID; failMsg <- msg }

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{
		ID:       "timeout-zero",
		Name:     "timeout-zero-config",
		Protocol: "tcp",
		ClassID:  "timeout-zero",
		Spec:     FlowSpec{Count: 2, Duration: 1}, // 2 flows, 1s deadline
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}

	select {
	case <-done:
		// Loop-head deadline branch reported normal completion.
	case <-failed:
		t.Fatalf("timeout zero-config task failed (%v); want normal completion", <-failMsg)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout zero-config task hung")
	}
}

// TestEngine_ReplayZeroConfigFails: a single-protocol replay task whose
// planner emitted zero configs must FAIL (review found this guard had no
// test — deleting worker.go's processReplayTask guard leaves the suite
// green). Mirrors TestEngine_ZeroConfigTaskFails for the replay path.
func TestEngine_ReplayZeroConfigFails(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	e.SetReplayPlanner(&stubReplayPlanner{packetsPerCall: 0})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 64), nil })

	failed := make(chan string, 1)
	failMsg := make(chan string, 1)
	e.OnTaskFailed = func(taskID string, errMsg string) { failed <- taskID; failMsg <- errMsg }

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{
		ID:       "replay-zero",
		Name:     "replay-zero-config",
		Protocol: "replay",
		ClassID:  "replay-zero",
		Mode:     "replay",
		Replay:   json.RawMessage(`{"pcap_asset_id":"empty","speed":{"mode":"original"}}`),
		Spec:     FlowSpec{Count: 1},
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}

	select {
	case <-failed:
		if msg := <-failMsg; msg == "" {
			t.Errorf("replay zero-config task failed with empty error message")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("replay zero-config task did not fail; engine completed it silently")
	}
}

// TestEngine_BatchReplayZeroConfigFails: a batch whose replay class produced
// zero configs must fail the task (all flows failed). Regression for the
// batch replay class path, which has no per-class config tally: a
// zero-emission replay class would silently produce 0 packets and report
// completion (review finding #1 — same jt808/jt809/jtt905 class of bug, via
// the replay route).
func TestEngine_BatchReplayZeroConfigFails(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 2, PacketWorkers: 2, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	e.SetReplayPlanner(&stubReplayPlanner{packetsPerCall: 0})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 64), nil })

	failed := make(chan string, 1)
	failMsg := make(chan string, 1)
	e.OnTaskFailed = func(taskID string, errMsg string) { failed <- taskID; failMsg <- errMsg }

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	task := Task{
		ID:       "batch-replay-zero",
		Name:     "batch-replay-zero",
		Protocol: "batch",
		Batch: &BatchSpec{
			Classes: []TrafficClass{
				{
					ID: "r1", Type: "replay",
					Replay: json.RawMessage(`{"pcap_asset_id":"empty","speed":{"mode":"original"}}`),
				},
			},
		},
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}

	select {
	case <-failed:
		if msg := <-failMsg; msg == "" {
			t.Errorf("batch replay zero-config task failed with empty error message")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("batch replay zero-config class did not fail the task")
	}
}

// TestEngine_FlowCeilingSkippedTaskCompletes: a strategy task whose flows were
// all skipped by the task-level flows ceiling (shared parent counter exhausted
// by a sibling — worker.go:281 break) produces 0 configs with a live context.
// That is LEGITIMATE 0-config completion, not a broken planner: the ceiling
// did its job. The 0-config guard must exempt the ceiling-skipped case
// (review finding: worker.go:386/511 guard would misreport it as failed).
func TestEngine_FlowCeilingSkippedTaskCompletes(t *testing.T) {
	e, _ := setupEngine(t, 1, 0) // perFlow=1: a planned flow emits exactly 1 config
	completed := make(chan string, 1)
	failed := make(chan string, 1)
	e.OnTaskComplete = func(taskID string) { completed <- taskID }
	e.OnTaskFailed = func(taskID, _ string) { failed <- taskID }

	parentID := "t8-parent"
	// taskA consumes the ceiling (flows=1) and completes with its 1 packet.
	taskA := Task{
		ID: "t8-stratA", Name: "strat-a", Protocol: "tcp", ClassID: "t8-stratA",
		ParentTaskID: parentID,
		Spec:         FlowSpec{Count: 100},
		TaskFCType:   "flows", TaskFCValue: 1,
	}
	if err := e.SubmitTask(taskA); err != nil {
		t.Fatalf("submit A: %v", err)
	}
	select {
	case <-completed:
	case <-time.After(5 * time.Second):
		t.Fatal("taskA (ceiling consumer) did not complete")
	}

	// taskB races for the counter; if the ceiling is already exhausted its
	// loop breaks at the first flow — 0 configs, live context. It must
	// complete normally, not fail as "planner produced 0 packet configs".
	taskB := Task{
		ID: "t8-stratB", Name: "strat-b", Protocol: "tcp", ClassID: "t8-stratB",
		ParentTaskID: parentID,
		Spec:         FlowSpec{Count: 100},
		TaskFCType:   "flows", TaskFCValue: 1,
	}
	if err := e.SubmitTask(taskB); err != nil {
		t.Fatalf("submit B: %v", err)
	}

	select {
	case <-completed:
		// Correct: the ceiling legitimately skipped taskB's flows.
	case <-failed:
		t.Fatal("ceiling-skipped strategy task failed; expected normal completion")
	case <-time.After(5 * time.Second):
		t.Fatal("ceiling-skipped strategy task hung")
	}

	e.CleanupTaskFlowControl(parentID)
}

// gatePlanner signals entry into Plan, then blocks until released — lets a
// test sequence the ceiling race deterministically: a broken task can be
// confirmed "inside its planner" before a sibling exhausts the shared counter.
type gatePlanner struct {
	name        string
	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
}

func (m *gatePlanner) Name() string                 { return m.name }
func (m *gatePlanner) Validate(spec FlowSpec) error { return nil }
func (m *gatePlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	m.enteredOnce.Do(func() { close(m.entered) })
	select {
	case <-m.release:
	case <-ctx.Done():
	}
	ch := make(chan PacketConfig)
	close(ch)
	return ch, nil
}

// TestEngine_ZeroConfigNotExemptedByExhaustedCeiling: a broken planner's
// 0-config task must FAIL even when the shared flows ceiling ends up exhausted
// by a sibling. The ceiling-exemption must be based on whether THIS task's
// loop actually broke at the ceiling (exact local facts), not on a counter
// reconstruction — a broken planner can run before the sibling exhausts the
// counter and produce 0 configs with a live context, and a later counter
// read must not retroactively mask it (adversarial review finding #1).
// Deterministic ordering via gatePlanner: broken passes the ceiling check and
// blocks inside Plan; healthy then exhausts the ceiling; broken is released
// and emits 0 configs — its guard must still fail it.
func TestEngine_ZeroConfigNotExemptedByExhaustedCeiling(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	gate := &gatePlanner{name: "jt808", entered: make(chan struct{}), release: make(chan struct{})}
	e.RegisterPlanner(gate)
	e.RegisterPlanner(&mockPlanner{name: "tcp"})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 64), nil })

	failed := make(chan string, 1)
	e.OnTaskFailed = func(taskID, _ string) { failed <- taskID }

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	parentID := "t8x-parent"
	broken := Task{
		ID: "t8x-broken", Name: "broken", Protocol: "jt808", ClassID: "t8x-broken",
		ParentTaskID: parentID,
		Spec:         FlowSpec{Count: 1},
		TaskFCType:   "flows", TaskFCValue: 1,
	}
	healthy := Task{
		ID: "t8x-healthy", Name: "healthy", Protocol: "tcp", ClassID: "t8x-healthy",
		ParentTaskID: parentID,
		Spec:         FlowSpec{Count: 1},
		TaskFCType:   "flows", TaskFCValue: 1,
	}
	if err := e.SubmitTask(broken); err != nil {
		t.Fatalf("submit broken: %v", err)
	}
	// broken is now past the ceiling check (counter=1 <= 1) and inside Plan.
	<-gate.entered
	// healthy exhausts the ceiling: its loop breaks at the first flow and it
	// completes normally (ceiling legitimately skipped it before it ran).
	if err := e.SubmitTask(healthy); err != nil {
		t.Fatalf("submit healthy: %v", err)
	}
	// Release broken: its planner emits 0 configs with a live context. The
	// shared counter is now past the ceiling — a counter-reconstruction
	// exemption would mask the broken task as ceiling-skipped.
	close(gate.release)

	select {
	case <-failed:
		// Broken task correctly failed despite the exhausted ceiling.
	case <-time.After(5 * time.Second):
		t.Fatal("broken 0-config task did not fail; ceiling exhaustion masked it")
	}

	e.CleanupTaskFlowControl(parentID)
}

// TestEngine_ReplayFlowCeilingSkippedCompletes: a single-protocol replay task
// whose flows were all skipped by the task-level flows ceiling (shared parent
// counter exhausted by a sibling — the replay planner's countFlow skips at
// emit time, planner.go:189) produces 0 configs with a live context. That is
// LEGITIMATE 0-config completion, not a broken replay. The processReplayTask
// 0-config guard must exempt the ceiling-skipped case (mirror of the synth
// path; the fix for TestEngine_FlowCeilingSkippedTaskCompletes must apply
// here too).
func TestEngine_ReplayFlowCeilingSkippedCompletes(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	// respectFC mirrors the real replay planner's ceiling behavior: the second
	// task's PlanReplay sees the counter already past the ceiling and emits 0.
	e.SetReplayPlanner(&stubReplayPlanner{packetsPerCall: 1, respectFC: true})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 64), nil })

	completed := make(chan string, 1)
	failed := make(chan string, 1)
	e.OnTaskComplete = func(taskID string) { completed <- taskID }
	e.OnTaskFailed = func(taskID, _ string) { failed <- taskID }

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	parentID := "t8r-parent"
	replayJSON := json.RawMessage(`{"pcap_asset_id":"a","speed":{"mode":"original"}}`)
	// taskA consumes the ceiling (flows=1) and completes with its 1 packet.
	taskA := Task{
		ID: "t8r-A", Name: "replay-a", Protocol: "replay", ClassID: "t8r-A",
		ParentTaskID: parentID, Mode: "replay", Replay: replayJSON,
		Spec:       FlowSpec{Count: 1},
		TaskFCType: "flows", TaskFCValue: 1,
	}
	if err := e.SubmitTask(taskA); err != nil {
		t.Fatalf("submit A: %v", err)
	}
	select {
	case <-completed:
	case <-time.After(5 * time.Second):
		t.Fatal("taskA (replay ceiling consumer) did not complete")
	}

	// taskB's PlanReplay increments the exhausted counter and emits 0 configs
	// with a live context — must complete normally, not fail.
	taskB := Task{
		ID: "t8r-B", Name: "replay-b", Protocol: "replay", ClassID: "t8r-B",
		ParentTaskID: parentID, Mode: "replay", Replay: replayJSON,
		Spec:       FlowSpec{Count: 1},
		TaskFCType: "flows", TaskFCValue: 1,
	}
	if err := e.SubmitTask(taskB); err != nil {
		t.Fatalf("submit B: %v", err)
	}

	select {
	case <-completed:
		// Correct: the ceiling legitimately skipped taskB's replay flows.
	case <-failed:
		t.Fatal("ceiling-skipped replay task failed; expected normal completion")
	case <-time.After(5 * time.Second):
		t.Fatal("ceiling-skipped replay task hung")
	}

	e.CleanupTaskFlowControl(parentID)
}
