package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/storage"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

	// 第14轮 B1 新语义：time = 持续发送直到 deadline（流循环不设上界，
	// Count 不参与）。0.5s 内持续产流（FlowsRun>=1 且量级远超单流），
	// deadline 正常收尾（elapsed 贴 TaskFCValue）。
	if got := pl.FlowsRun(); got < 1 {
		t.Errorf("flows = %d, want >= 1 (time mode keeps producing until deadline)", got)
	}
	if elapsed > 2*time.Second {
		t.Errorf("elapsed = %v, want < 2s (0.5s ceiling should not run long)", elapsed)
	}
}

// ---------------------------------------------------------------------------
// D-REQ-1 批 1: task-level flow_control type=packets —— 总包数封顶
// 设计：CODE_DESIGN.md D-REQ-1 批 1 定稿（2026-10-19）。
// ---------------------------------------------------------------------------

// pktTestEngine builds an engine wired BEFORE Start (build func / replay
// planner are captured by workers at Start).
func pktTestEngine(t *testing.T, build func(PacketConfig) ([]byte, error)) *Engine {
	t.Helper()
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 256,
	})
	e.SetBuildFunc(build)
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() { e.Stop() })
	return e
}

// TestTaskLevelPackets_CeilsAggregate: 两策略各产 100 包/流，任务级
// packets=37 —— 合计转发的 config 必须恰好 37（预留式封顶，超出的一个
// 回吐不转发）；两引擎任务都须正常完成——额度被姊妹吃满的一方 0 包属
// 封顶履职，0 包守卫不得误报 failed。
func TestTaskLevelPackets_CeilsAggregate(t *testing.T) {
	var built int64
	e := pktTestEngine(t, func(c PacketConfig) ([]byte, error) {
		atomic.AddInt64(&built, 1)
		return make([]byte, 100), nil
	})
	pl := &fixedPacketsPlanner{name: "tcp", perFlow: 100}
	e.RegisterPlanner(pl)

	var failed sync.Map
	e.OnTaskFailed = func(taskID string, errMsg string) { failed.Store(taskID, errMsg) }

	mk := func(id string) Task {
		return Task{
			ID: id, Name: id, Protocol: "tcp", ClassID: id,
			ParentTaskID: "t15-parent",
			Spec:         FlowSpec{Count: 1},
			TaskFCType:   "packets",
			TaskFCValue:  37,
		}
	}
	if err := e.SubmitTask(mk("t15-parent-stratA")); err != nil {
		t.Fatalf("submit A: %v", err)
	}
	if err := e.SubmitTask(mk("t15-parent-stratB")); err != nil {
		t.Fatalf("submit B: %v", err)
	}
	waitTaskDone(t, e, "t15-parent-stratA", 5*time.Second)
	waitTaskDone(t, e, "t15-parent-stratB", 5*time.Second)

	if got := atomic.LoadInt64(&built); got != 37 {
		t.Errorf("total packets = %d, want exactly 37 (reserve-per-config cap)", got)
	}
	failed.Range(func(k, v interface{}) bool {
		t.Errorf("task %v failed: %v (packets ceiling must complete cleanly, 0-config guard must exempt)", k, v)
		return true
	})
}

// TestTaskLevelPackets_FirstToStopWithTime: 策略级 time=60s + 任务级
// packets=5 —— 先到先停：包数封顶先命中，任务须在 2s 内以恰好 5 包正常
// 完成（不等 60s deadline；满速 20ms/包 → 5 包 0.1s，60s 永远追不上）。
func TestTaskLevelPackets_FirstToStopWithTime(t *testing.T) {
	var built int64
	e := pktTestEngine(t, func(c PacketConfig) ([]byte, error) {
		atomic.AddInt64(&built, 1)
		return make([]byte, 100), nil
	})
	pl := &fixedPacketsPlanner{name: "tcp", perFlow: 1000, delay: 20 * time.Millisecond}
	e.RegisterPlanner(pl)

	var failed sync.Map
	e.OnTaskFailed = func(taskID string, errMsg string) { failed.Store(taskID, errMsg) }

	task := Task{
		ID: "t16-combo", Name: "combo", Protocol: "tcp", ClassID: "t16-combo",
		ParentTaskID: "t16-parent",
		Spec:         FlowSpec{Count: 1, Duration: 60}, // 策略级 60s deadline
		TaskFCType:   "packets",
		TaskFCValue:  5,
	}
	start := time.Now()
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitTaskDone(t, e, "t16-combo", 5*time.Second)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("elapsed = %v, want < 2s (packets ceiling must win first-to-stop)", elapsed)
	}
	if got := atomic.LoadInt64(&built); got != 5 {
		t.Errorf("packets = %d, want exactly 5", got)
	}
	failed.Range(func(k, v interface{}) bool {
		t.Errorf("task %v failed: %v", k, v)
		return true
	})
}

// TestTaskLevelPackets_CounterCleaned: CleanupTaskFlowControl 须同时清理
// packets 共享计数器（防引擎生命周期泄漏，镜像 flowCounters）。
func TestTaskLevelPackets_CounterCleaned(t *testing.T) {
	e, _ := setupEngine(t, 1, 0)

	e.getOrCreatePacketCounter("t17-parent")
	e.CleanupTaskFlowControl("t17-parent")

	e.rateMu.RLock()
	_, ok := e.packetCounters["t17-parent"]
	e.rateMu.RUnlock()
	if ok {
		t.Error("packet counter survived CleanupTaskFlowControl (leak)")
	}
}

// emittingReplayPlanner emits n configs then closes (replay packets-cap test).
type emittingReplayPlanner struct{ n int }

func (p *emittingReplayPlanner) PlanReplay(ctx context.Context, specJSON json.RawMessage, taskID, classID, userID string, fc *ReplayFC) (<-chan PacketConfig, error) {
	ch := make(chan PacketConfig)
	go func() {
		defer close(ch)
		for i := 0; i < p.n; i++ {
			select {
			case <-ctx.Done():
				return
			case ch <- PacketConfig{FlowID: "rf", PacketIndex: uint64(i)}:
			}
		}
	}()
	return ch, nil
}

// TestTaskLevelPackets_ReplayTruncates: replay 任务 packets 封顶在 config
// 转发点截断——planner 产 100，cap=10 → 恰好 10 包、正常完成不误报
// （封顶完成分支先于子 ctx cancel 判定）。
func TestTaskLevelPackets_ReplayTruncates(t *testing.T) {
	var built int64
	// replayPlanner 由 Start 的 NewConfigWorker 捕获——须先装配再启动。
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 256,
	})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) {
		atomic.AddInt64(&built, 1)
		return make([]byte, 100), nil
	})
	e.SetReplayPlanner(&emittingReplayPlanner{n: 100})
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	var failed sync.Map
	e.OnTaskFailed = func(taskID string, errMsg string) { failed.Store(taskID, errMsg) }

	task := Task{
		ID: "t18-replay", Name: "replay-cap", Mode: "replay",
		Replay:       []byte(`{"pcap_asset_id":"a1"}`),
		ClassID:      "t18-replay",
		ParentTaskID: "t18-parent",
		TaskFCType:   "packets",
		TaskFCValue:  10,
		UserID:       "u1",
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitTaskDone(t, e, "t18-replay", 5*time.Second)

	if got := atomic.LoadInt64(&built); got != 10 {
		t.Errorf("packets = %d, want exactly 10 (replay truncated at forward point)", got)
	}
	failed.Range(func(k, v interface{}) bool {
		t.Errorf("task %v failed: %v", k, v)
		return true
	})
}

// ---------------------------------------------------------------------------
// D-REQ-1 批 2: time 无任何速率 → 建单告警一次（可发现性，语义保持全速）
// ---------------------------------------------------------------------------

// syncBuffer is a thread-safe bytes.Buffer for log capture (load_balance_test.go 同款).
type fcSyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *fcSyncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}
func (b *fcSyncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestTimeWithoutBPS_WarnsAtSubmit: 任务级 time / 策略级 time 且策略无 bps
// → SubmitTask 告警 "time flow control without a rate limit"；配了 bps 不告警。
func TestTimeWithoutBPS_WarnsAtSubmit(t *testing.T) {
	var buf fcSyncBuffer
	encoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	zap.ReplaceGlobals(zap.New(zapcore.NewCore(encoder, zapcore.AddSync(&buf), zapcore.DebugLevel)))
	t.Cleanup(func() { zap.ReplaceGlobals(zap.NewNop()) })

	// ① 任务级 time、策略无 bps → 告警
	e, _ := setupEngine(t, 1, 0)
	submit := func(id string, spec FlowSpec, fcType string) {
		t.Helper()
		task := Task{
			ID: id, Name: id, Protocol: "tcp", ClassID: id,
			ParentTaskID: id + "-parent", Spec: spec,
			TaskFCType: fcType, TaskFCValue: 60,
		}
		if err := e.SubmitTask(task); err != nil {
			t.Fatalf("submit %s: %v", id, err)
		}
	}
	submit("tw1", FlowSpec{Count: 1}, "time")
	if out := buf.String(); !strings.Contains(out, "time flow control without a rate limit") {
		t.Errorf("① want warn for task time without bps, got: %s", out)
	}

	// ② 策略级 Duration、无 bps → 告警
	submit("tw2", FlowSpec{Count: 1, Duration: 60}, "")
	if out := buf.String(); !strings.Contains(out, "time flow control without a rate limit") {
		t.Errorf("② want warn for strategy time without bps, got: %s", out)
	}

	// ③ 策略配了 bps → 不告警
	before := len(buf.String())
	submit("tw3", FlowSpec{Count: 1, BPS: "100M"}, "time")
	if out := buf.String()[before:]; strings.Contains(out, "time flow control without a rate limit") {
		t.Errorf("③ must not warn when strategy bps present, got: %s", out)
	}

	// ④ replay 任务（original/multiplier 速度=按 pcap 时间戳限速）→ 不告警
	// （复审 MINOR-2b：Spec.BPS 仅 speed.mode=bps 时写入，原条件会误报）。
	task := Task{
		ID: "tw4", Name: "tw4", ClassID: "tw4", ParentTaskID: "tw4-parent",
		Mode: "replay", Replay: []byte(`{"pcap_asset_id":"a"}`),
		TaskFCType: "time", TaskFCValue: 60,
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit tw4: %v", err)
	}
	if out := buf.String(); strings.Count(out, "time flow control without a rate limit") != 2 {
		t.Errorf("④ must not warn for replay task (warn count=%d, want 2 from ①②)",
			strings.Count(out, "time flow control without a rate limit"))
	}
}

// ---------------------------------------------------------------------------
// 复审 MINOR-1 红例：转发 select 走 Done 分支时必须回吐已预留的槽
// ---------------------------------------------------------------------------

// TestTaskLevelPackets_DeadlineDoesNotBurnSlot：确定性构造"claim 已成功、
// send 未就绪"的窗口——首个 build 卡死包管线（shard 通道填满后转发 select
// 只剩 Done 一个就绪分支，deadline 一到必走 Done）。无回吐时该槽永久烧掉：
// 计数器 = 实发 +1 ≠ 构建数；有回吐则计数器 == 实发 == 构建数。
func TestTaskLevelPackets_DeadlineDoesNotBurnSlot(t *testing.T) {
	var built int64
	block := make(chan struct{})
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4, QueueSize: 8, MaxBufferBytes: 1 << 20,
	})
	// QueueSize=8 → shard chan cap 16；planner 产 64 包 → 转发必在通道
	// 填满后阻塞在 select（首个 build 又卡死在 PacketWorker）。
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) {
		if atomic.AddInt64(&built, 1) == 1 {
			<-block
		}
		return make([]byte, 10), nil
	})
	e.RegisterPlanner(&fixedPacketsPlanner{name: "tcp", perFlow: 64})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	task := Task{
		ID: "t19-burn", Name: "burn", Protocol: "tcp", ClassID: "t19-burn",
		ParentTaskID: "t19-parent",
		Spec:         FlowSpec{Count: 1, Duration: 1}, // 策略级 1s deadline
		TaskFCType:   "packets",
		TaskFCValue:  100, // 需求(64)之上：烧槽≠封顶命中
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// 阻塞窗口必须跨过 deadline(1s)：约 50ms 即填满通道并卡死在 select，
	// 1.2s 时 Done 已就绪而 send 未就绪 → select 必走 Done 分支。
	time.Sleep(1200 * time.Millisecond)
	close(block) // 放行管线，让已转发的包排空、任务收敛
	waitTaskDone(t, e, "t19-burn", 10*time.Second)

	e.rateMu.RLock()
	counter := *e.packetCounters["t19-parent"]
	e.rateMu.RUnlock()
	got := atomic.LoadInt64(&built)
	if counter != got {
		t.Errorf("packet counter = %d, built = %d: deadline 分支烧掉了 %d 个已预留槽（回吐缺失）",
			counter, got, counter-got)
	}
}

// TestTaskLevelPackets_ReplayZeroConfigSibling：replay 路径 0 包豁免——
// 姊妹吃满 packets 额度后，本 replay 任务产 0 包须正常完成（封顶履职），
// 不得落 0 包守卫误报（复审 MINOR-3：此路径此前无测试）。
func TestTaskLevelPackets_ReplayZeroConfigSibling(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, // 串行：A 完成后 B 才跑
		BufferSize: 512, QueueSize: 128, MaxBufferBytes: 1 << 20,
	})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 64), nil })
	e.SetReplayPlanner(&stubReplayPlanner{packetsPerCall: 1})

	var failed sync.Map
	e.OnTaskFailed = func(taskID string, errMsg string) { failed.Store(taskID, errMsg) }
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	replayJSON := []byte(`{"pcap_asset_id":"a","speed":{"mode":"original"}}`)
	mk := func(id string) Task {
		return Task{
			ID: id, Name: id, ClassID: id, ParentTaskID: "t20-parent",
			Mode: "replay", Replay: replayJSON,
			TaskFCType:  "packets",
			TaskFCValue: 1, // A 吃满
		}
	}
	if err := e.SubmitTask(mk("t20-A")); err != nil {
		t.Fatalf("submit A: %v", err)
	}
	waitTaskDone(t, e, "t20-A", 5*time.Second)
	if err := e.SubmitTask(mk("t20-B")); err != nil {
		t.Fatalf("submit B: %v", err)
	}
	waitTaskDone(t, e, "t20-B", 5*time.Second)

	failed.Range(func(k, v interface{}) bool {
		t.Errorf("task %v failed: %v (0 包豁免必须生效)", k, v)
		return true
	})
}
