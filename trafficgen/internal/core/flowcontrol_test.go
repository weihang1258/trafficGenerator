package core

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/storage"
)

// fixedPacketsPlanner produces a fixed number of packet configs per flow,
// ignoring spec.Count (unlike mockPlanner which uses Count as packet count).
// This models real protocol planners that generate a fixed packet sequence
// per flow. An optional per-packet delay makes time-based tests observable.
type fixedPacketsPlanner struct {
	name    string
	perFlow int
	delay   time.Duration // delay between packets within a flow (0 = no delay)
	mu      sync.Mutex
	flows   int32 // number of flows actually planned
}

func (p *fixedPacketsPlanner) Name() string                 { return p.name }
func (p *fixedPacketsPlanner) Validate(spec FlowSpec) error { return nil }
func (p *fixedPacketsPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	atomic.AddInt32(&p.flows, 1)
	ch := make(chan PacketConfig)
	go func() {
		defer close(ch)
		for i := 0; i < p.perFlow; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- PacketConfig{FlowID: "f1", PacketIndex: uint64(i)}:
			}
			if p.delay > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(p.delay):
				}
			}
		}
	}()
	return ch, nil
}

func (p *fixedPacketsPlanner) FlowsRun() int32 { return atomic.LoadInt32(&p.flows) }

// setupEngine creates an engine with a fixedPacketsPlanner registered as "tcp".
func setupEngine(t *testing.T, perFlow int, delay time.Duration) (*Engine, *fixedPacketsPlanner) {
	t.Helper()
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 256,
	})
	pl := &fixedPacketsPlanner{name: "tcp", perFlow: perFlow, delay: delay}
	e.RegisterPlanner(pl)
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 100), nil })
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() { e.Stop() })
	return e, pl
}

// waitTaskDone waits for a task to leave the engine's task store.
func waitTaskDone(t *testing.T, e *Engine, taskID string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if _, err := e.GetTaskStatus(taskID); err != nil {
			return // removed from store = terminal
		}
		select {
		case <-deadline:
			t.Fatalf("task %s did not finish within %v", taskID, timeout)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// ---------------------------------------------------------------------------
// T1: Strategy flows=N generates N flows (currently dead: only 1 flow)
// ---------------------------------------------------------------------------

func TestStrategyFlows_GeneratesMultipleFlows(t *testing.T) {
	e, pl := setupEngine(t, 1, 0)

	task := Task{
		ID:           "t1-flows",
		Name:         "flows-test",
		Protocol:     "tcp",
		ClassID:      "t1-flows",
		ParentTaskID: "t1-flows",
		Spec:         FlowSpec{Count: 5}, // 5 flows
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitTaskDone(t, e, "t1-flows", 5*time.Second)

	if got := pl.FlowsRun(); got != 5 {
		t.Errorf("flows run = %d, want 5 (spec.Count must control flow count)", got)
	}
}

// ---------------------------------------------------------------------------
// T2: Strategy time=N stops after N seconds (currently dead: no timeout)
// Uses a slow planner so without a timeout the task outlasts the deadline.
// ---------------------------------------------------------------------------

func TestStrategyTime_StopsAtDuration(t *testing.T) {
	// 200 packets × 20ms = 4s per flow if Duration is ignored.
	e, _ := setupEngine(t, 200, 20*time.Millisecond)

	task := Task{
		ID:           "t2-time",
		Name:         "time-test",
		Protocol:     "tcp",
		ClassID:      "t2-time",
		ParentTaskID: "t2-time",
		Spec:         FlowSpec{Count: 1, Duration: 1}, // 1s timeout
	}
	start := time.Now()
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitTaskDone(t, e, "t2-time", 8*time.Second)
	elapsed := time.Since(start)

	// With Duration honoured: ~1s. Without (current bug): ~4s.
	if elapsed > 2500*time.Millisecond {
		t.Errorf("time-limited task took %v, want <= 2.5s (1s duration + slack)", elapsed)
	}
}

// ---------------------------------------------------------------------------
// T3: StrategyModelToTask sets independent ClassID + ParentTaskID per strategy
// (currently ClassID = parentTaskID, shared across all strategies)
// ---------------------------------------------------------------------------

func TestStrategyModelToTask_IndependentClassID(t *testing.T) {
	parentTask := &storage.TaskModel{
		ID:           "parent-uuid",
		StrategyIDs:  `["stratA","stratB"]`,
		OutputType:   "pcap",
		OutputConfig: `{"pcap_path":"x.pcap"}`,
	}
	stratA := &storage.StrategyModel{
		ID: "stratA", Protocol: "tcp",
		Config:      `{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}`,
		FlowControl: `{"type":"bps","value":100000000}`,
	}
	stratB := &storage.StrategyModel{
		ID: "stratB", Protocol: "udp",
		Config:      `{"src_ip":"10.0.0.3","dst_ip":"10.0.0.4"}`,
		FlowControl: `{"type":"bps","value":200000000}`,
	}

	ctA, err := StrategyModelToTask(parentTask, stratA, "")
	if err != nil {
		t.Fatalf("convert A: %v", err)
	}
	ctB, err := StrategyModelToTask(parentTask, stratB, "")
	if err != nil {
		t.Fatalf("convert B: %v", err)
	}

	// ClassID must differ per strategy (independent rate buckets).
	if ctA.ClassID == ctB.ClassID {
		t.Errorf("strategies share ClassID %q (must be independent)", ctA.ClassID)
	}
	// ClassID should equal the engine task ID (= parentID-strategyID).
	if ctA.ClassID != ctA.ID {
		t.Errorf("ClassID %q != task ID %q", ctA.ClassID, ctA.ID)
	}
	// ParentTaskID must be the parent task's ID.
	if ctA.ParentTaskID != "parent-uuid" || ctB.ParentTaskID != "parent-uuid" {
		t.Errorf("ParentTaskID wrong: A=%q B=%q, want parent-uuid", ctA.ParentTaskID, ctB.ParentTaskID)
	}
}

// ---------------------------------------------------------------------------
// T4: StrategyModelToTask does NOT let task-level FC override strategy spec
// (currently task FC overwrites spec.BPS/Count/Duration)
// ---------------------------------------------------------------------------

func TestStrategyModelToTask_TaskFCDoesNotOverrideSpec(t *testing.T) {
	// Strategy says bps=100M. Task-level FC says bps=200M (ceiling, not override).
	parentTask := &storage.TaskModel{
		ID:           "parent-uuid",
		StrategyIDs:  `["stratA"]`,
		OutputType:   "pcap",
		OutputConfig: `{"pcap_path":"x.pcap"}`,
		FlowControl:  `{"type":"bps","value":200000000}`, // task-level ceiling
	}
	stratA := &storage.StrategyModel{
		ID: "stratA", Protocol: "tcp",
		Config:      `{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}`,
		FlowControl: `{"type":"bps","value":100000000}`, // strategy-level
	}

	ct, err := StrategyModelToTask(parentTask, stratA, "")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}

	// spec.BPS must reflect the STRATEGY's bps (100M), NOT be overwritten by
	// the task-level 200M. The task-level FC goes into TaskFCType/TaskFCValue.
	if ct.Spec.BPS != "100M" {
		t.Errorf("spec.BPS = %q, want 100M (strategy-level must NOT be overridden by task FC)", ct.Spec.BPS)
	}
	if ct.TaskFCType != "bps" {
		t.Errorf("TaskFCType = %q, want bps", ct.TaskFCType)
	}
	if ct.TaskFCValue != 200000000 {
		t.Errorf("TaskFCValue = %v, want 200000000", ct.TaskFCValue)
	}
}

// ---------------------------------------------------------------------------
// T5: Task-level BPS creates a parent bucket (currently not created)
// ---------------------------------------------------------------------------

func TestTaskLevelBPS_CreatesParentBucket(t *testing.T) {
	e, _ := setupEngine(t, 1, 0)

	parentID := "t5-parent"
	taskA := Task{
		ID:           "t5-parent-stratA",
		Name:         "strat-a",
		Protocol:     "tcp",
		ClassID:      "t5-parent-stratA",
		ParentTaskID: parentID,
		Spec:         FlowSpec{BPS: "200M", Count: 1},
		TaskFCType:   "bps",
		TaskFCValue:  200000000,
	}

	if err := e.SubmitTask(taskA); err != nil {
		t.Fatalf("submit: %v", err)
	}

	// SubmitTask must create the parent bucket from TaskFCType=bps.
	if e.GetRateLimiter(parentID) == nil {
		t.Error("no parent rate limiter created for task-level BPS ceiling")
	}

	waitTaskDone(t, e, "t5-parent-stratA", 5*time.Second)
}

// ---------------------------------------------------------------------------
// T6: Task-level time ceils duration (currently task FC time ignored)
// ---------------------------------------------------------------------------

func TestTaskLevelTime_CeilsDuration(t *testing.T) {
	e, _ := setupEngine(t, 200, 20*time.Millisecond) // 4s per flow if unbounded

	// Strategy time=60s, task-level time=1s -> stops at 1s.
	task := Task{
		ID:           "t6-time",
		Name:         "task-time-test",
		Protocol:     "tcp",
		ClassID:      "t6-time",
		ParentTaskID: "t6-parent",
		Spec:         FlowSpec{Count: 1, Duration: 60}, // 60s strategy time
		TaskFCType:   "time",
		TaskFCValue:  1, // 1s task-level ceiling
	}

	start := time.Now()
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitTaskDone(t, e, "t6-time", 8*time.Second)
	elapsed := time.Since(start)

	// With task-level time honoured: min(60,1)=1s. Without: 4s (strategy time
	// also ignored currently) or 60s.
	if elapsed > 2500*time.Millisecond {
		t.Errorf("task-level time=1s took %v, want <= 2.5s", elapsed)
	}
}

// ---------------------------------------------------------------------------
// T7: Task-level flows ceils total flow count across strategies
// (currently no counter; with the loop fix but no counter, total would exceed)
// ---------------------------------------------------------------------------

func TestTaskLevelFlows_CeilsTotal(t *testing.T) {
	e, pl := setupEngine(t, 1, 0)

	parentID := "t7-parent"
	// Two strategies each flows=100, task-level flows=1 -> total must be <= 1.
	// Currently: processTask ignores Count -> 1 flow per strategy = 2 total > 1.
	taskA := Task{
		ID:           "t7-parent-stratA",
		Name:         "strat-a",
		Protocol:     "tcp",
		ClassID:      "t7-parent-stratA",
		ParentTaskID: parentID,
		Spec:         FlowSpec{Count: 100},
		TaskFCType:   "flows",
		TaskFCValue:  1,
	}
	taskB := Task{
		ID:           "t7-parent-stratB",
		Name:         "strat-b",
		Protocol:     "tcp",
		ClassID:      "t7-parent-stratB",
		ParentTaskID: parentID,
		Spec:         FlowSpec{Count: 100},
		TaskFCType:   "flows",
		TaskFCValue:  1,
	}

	if err := e.SubmitTask(taskA); err != nil {
		t.Fatalf("submit A: %v", err)
	}
	if err := e.SubmitTask(taskB); err != nil {
		t.Fatalf("submit B: %v", err)
	}

	waitTaskDone(t, e, "t7-parent-stratA", 5*time.Second)
	waitTaskDone(t, e, "t7-parent-stratB", 5*time.Second)

	if total := pl.FlowsRun(); total > 1 {
		t.Errorf("total flows = %d, want <= 1 (task-level flows ceiling=1)", total)
	}
}

// ---------------------------------------------------------------------------
// T9: CleanupTaskFlowControl clears parent bucket + counters
// ---------------------------------------------------------------------------

func TestCleanupTaskFlowControl_ClearsParent(t *testing.T) {
	e, _ := setupEngine(t, 1, 0)

	parentID := "t9-parent"
	e.SetClassRateLimit(parentID, 100_000_000)
	e.getOrCreateFlowCounter(parentID)

	if e.GetRateLimiter(parentID) == nil {
		t.Fatal("parent limiter not created")
	}

	e.CleanupTaskFlowControl(parentID)

	if e.GetRateLimiter(parentID) != nil {
		t.Error("parent rate limiter not cleaned up")
	}
	e.rateMu.RLock()
	_, counterExists := e.flowCounters[parentID]
	e.rateMu.RUnlock()
	if counterExists {
		t.Error("flow counter not cleaned up")
	}
}

// ---------------------------------------------------------------------------
// T10: BPS-only strategy (Count=0) defaults to 1 flow
// Guards against a loop-implementation that forgets the Count<=0 default.
// ---------------------------------------------------------------------------

func TestStrategyBpsOnly_DefaultsOneFlow(t *testing.T) {
	e, pl := setupEngine(t, 3, 0)

	task := Task{
		ID:           "t10-bps-only",
		Name:         "bps-only",
		Protocol:     "tcp",
		ClassID:      "t10-bps-only",
		ParentTaskID: "t10-bps-only",
		Spec:         FlowSpec{BPS: "100M"}, // Count=0 (zero value)
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitTaskDone(t, e, "t10-bps-only", 5*time.Second)

	if got := pl.FlowsRun(); got != 1 {
		t.Errorf("bps-only flows = %d, want 1 (Count=0 must default to 1 flow)", got)
	}
}

// ---------------------------------------------------------------------------
// T11: Task-level BPS parent bucket uses exact bps (no formatBPS round-trip)
// A non-round value like 1.5Gbps must not be rounded to 2G.
// ---------------------------------------------------------------------------

func TestTaskLevelBPS_ExactRate(t *testing.T) {
	e, _ := setupEngine(t, 1, 0)

	// 1.5 Gbps = 1500000000 bps. formatBPS would round to "2G" -> 2e9 bps.
	task := Task{
		ID:           "t11-exact",
		Name:         "exact-rate",
		Protocol:     "tcp",
		ClassID:      "t11-exact-strat",
		ParentTaskID: "t11-parent",
		Spec:         FlowSpec{Count: 1},
		TaskFCType:   "bps",
		TaskFCValue:  1_500_000_000,
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}

	limiter := e.GetRateLimiter("t11-parent")
	if limiter == nil {
		t.Fatal("no parent rate limiter")
	}
	// Rate() is bytes/sec; bps = rate * 8.
	gotBPS := limiter.Rate() * 8
	if gotBPS != 1_500_000_000 {
		t.Errorf("parent bucket rate = %d bps, want 1500000000 (1.5G exact, no rounding)", gotBPS)
	}

	waitTaskDone(t, e, "t11-exact", 5*time.Second)
}

// ---------------------------------------------------------------------------
// T12: SubmitTask queue-full failure cleans up the child rate limiter
// A task that fails to enqueue must not leak its rate-limiter bucket.
// ---------------------------------------------------------------------------

// blockingPlanner blocks Plan until the release channel is closed, keeping the
// task in the engine so the task queue stays full.
type blockingPlanner struct {
	name    string
	release <-chan struct{}
}

func (p *blockingPlanner) Name() string                 { return p.name }
func (p *blockingPlanner) Validate(spec FlowSpec) error { return nil }
func (p *blockingPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	ch := make(chan PacketConfig)
	go func() {
		defer close(ch)
		select {
		case <-ctx.Done():
		case <-p.release:
		}
	}()
	return ch, nil
}

func TestSubmitTask_QueueFullCleansRateLimiter(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 0, // unbuffered: send blocks when no receiver
	})
	release := make(chan struct{})
	e.RegisterPlanner(&blockingPlanner{name: "tcp", release: release})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 10), nil })
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { close(release); e.Stop() })

	// With an unbuffered taskChan and one ConfigWorker (sem cap 4), 4 blockers
	// fill the worker's semaphore and a 5th is received but stalls the worker
	// on the sem acquire -- so the worker stops receiving. The 6th task's send
	// then has no receiver, times out after 5s -> "task queue full". Each
	// blocker's Plan blocks on `release`, holding its sem slot.
	for i := 0; i < 5; i++ {
		b := Task{
			ID: fmt.Sprintf("blocker-%d", i), Name: "block", Protocol: "tcp",
			ClassID: fmt.Sprintf("blocker-%d", i), Spec: FlowSpec{Count: 1},
		}
		if err := e.SubmitTask(b); err != nil {
			t.Fatalf("submit blocker %d: %v", i, err)
		}
	}
	// Let the config worker drain taskChan and stall on the 5th blocker's sem.
	time.Sleep(200 * time.Millisecond)

	// 6th task with a BPS bucket -> should fail to enqueue (queue full)
	// and its child bucket must be cleaned up.
	overflow := Task{
		ID: "overflow", Name: "over", Protocol: "tcp", ClassID: "overflow",
		Spec: FlowSpec{BPS: "100M", Count: 1},
	}
	err := e.SubmitTask(overflow)
	if err == nil {
		t.Skip("overflow task unexpectedly queued; queue timing dependent")
	}

	if limiter := e.GetRateLimiter("overflow"); limiter != nil {
		t.Error("overflow task's rate limiter leaked after queue-full failure")
	}
}

// failingPlanner's Plan always returns an error (models a planner that fails
// mid-task, e.g. resource exhaustion). Used to test that a failed flow does
// not permanently consume a task-level flows-ceiling slot.
type failingPlanner struct {
	name string
}

func (p *failingPlanner) Name() string                 { return p.name }
func (p *failingPlanner) Validate(spec FlowSpec) error { return nil }
func (p *failingPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	return nil, fmt.Errorf("simulated plan failure")
}

// ---------------------------------------------------------------------------
// T13: A failed Plan() must release its flows-ceiling slot.
// Without the fix, the counter is incremented before Plan() and never
// decremented on failure, so sibling strategies get fewer slots than the
// ceiling promises.
// ---------------------------------------------------------------------------
func TestTaskLevelFlows_FailedPlanReleasesSlot(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 256,
	})
	e.RegisterPlanner(&failingPlanner{name: "udp"})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 10), nil })
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	parentID := "t13-parent"
	// One strategy using protocol "udp" (the failing planner). Ceiling=5, Count=1.
	task := Task{
		ID:           "t13-fail",
		Name:         "fail-strat",
		Protocol:     "udp",
		ClassID:      "t13-fail",
		ParentTaskID: parentID,
		Spec:         FlowSpec{Count: 1},
		TaskFCType:   "flows",
		TaskFCValue:  5,
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitTaskDone(t, e, "t13-fail", 5*time.Second)

	// The failed flow incremented the counter then (with the fix) released it.
	// Counter must be 0 so sibling strategies can use all 5 slots.
	counter := e.getOrCreateFlowCounter(parentID)
	if got := atomic.LoadInt64(counter); got != 0 {
		t.Errorf("flow counter = %d after failed Plan, want 0 (failed flow must release its slot)", got)
	}
}

// ---------------------------------------------------------------------------
// T14: Sub-second task-level time ceiling must not truncate to 0.
// int(0.5)=0 -> WithTimeout(0) cancels immediately (0 flows). The fix uses
// float64 seconds so 0.5s = 500ms.
// ---------------------------------------------------------------------------
func TestTaskLevelTime_SubSecondNotTruncated(t *testing.T) {
	e, pl := setupEngine(t, 1, 0)

	task := Task{
		ID:           "t14-subsec",
		Name:         "subsec-time",
		Protocol:     "tcp",
		ClassID:      "t14-subsec",
		ParentTaskID: "t14-parent",
		Spec:         FlowSpec{Count: 1, Duration: 60}, // strategy 60s
		TaskFCType:   "time",
		TaskFCValue:  0.5, // 500ms task-level ceiling
	}
	start := time.Now()
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitTaskDone(t, e, "t14-subsec", 5*time.Second)
	elapsed := time.Since(start)

	// With the fix: task runs ~500ms and produces 1 flow (not immediately
	// cancelled). Without: WithTimeout(0) cancels before Plan -> 0 flows.
	if got := pl.FlowsRun(); got != 1 {
		t.Errorf("flows = %d, want 1 (sub-second time must not cancel immediately)", got)
	}
	if elapsed > 2*time.Second {
		t.Errorf("elapsed = %v, want < 2s (0.5s ceiling should not run long)", elapsed)
	}
}
