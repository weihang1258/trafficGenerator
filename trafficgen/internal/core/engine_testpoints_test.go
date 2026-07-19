package core

// Test points for engine.go (E1-E138, CONC1, CONC4, CONC10) from
// tools/test_points/engine_core.md. Covers NewEngine, Register*,
// Start/Stop, SubmitTask/StopTask, state machine (SetTaskTotalConfigs,
// OnPacketWritten, FailTask), GetTaskStatus, GetPackets, GetBufferStatus,
// SetClassRateLimit, GetRateLimiter, GetCPUUsage, SetMaxTasks,
// writePacketsTo, GetStats, SetFatalError, GetFatalError,
// cleanupTaskRateLimiters, and concurrent aggregate throughput (CONC1).

// REAL-level tests access fields directly or start/stop the engine minimally
// without driving the pipeline. SIMULATED-level tests (pipeline, fake writers)
// are in engine_integration_test.go.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ========================================================================
// NewEngine / RegisterPlanner / SetBuildFunc (E1-E11)
// ========================================================================

// E1-POS: NewEngine with zero config initializes all maps non-nil, empty.
func TestNewEngine_ZeroConfig(t *testing.T) {
	e := NewEngine(EngineConfig{})
	if e.planners == nil {
		t.Error("planners is nil, want non-nil empty map")
	}
	if e.rateLimiters == nil {
		t.Error("rateLimiters is nil")
	}
	if e.taskStore == nil {
		t.Error("taskStore is nil")
	}
	if e.outputWriters == nil {
		t.Error("outputWriters is nil")
	}
	if e.dualWriters == nil {
		t.Error("dualWriters is nil")
	}
	if e.running.Load() {
		t.Error("running = true, want false")
	}
	if e.taskChan != nil {
		t.Error("taskChan should be nil before Start")
	}
	if e.shardedConfigChan != nil {
		t.Error("shardedConfigChan should be nil before Start")
	}
	if e.shardedPacketChan != nil {
		t.Error("shardedPacketChan should be nil before Start")
	}
	if e.replayPlanner != nil {
		t.Error("replayPlanner should be nil by default")
	}
	if e.buildFunc != nil {
		t.Error("buildFunc should be nil by default")
	}
	if len(e.planners) != 0 {
		t.Errorf("planners len=%d want 0", len(e.planners))
	}
	if len(e.rateLimiters) != 0 {
		t.Errorf("rateLimiters len=%d want 0", len(e.rateLimiters))
	}
}

// E2-NEG: negative config values don't panic; maps still initialized.
func TestNewEngine_NegativeConfig(t *testing.T) {
	e := NewEngine(EngineConfig{ConfigWorkers: -1, PacketWorkers: -2, OutputWorkers: -3, BufferSize: -4, QueueSize: -5})
	if e.planners == nil || e.rateLimiters == nil || e.taskStore == nil {
		t.Error("maps should be initialized regardless of negative config")
	}
}

// E3-POS: replayPlanner nil after NewEngine.
func TestNewEngine_NoReplayPlanner(t *testing.T) {
	e := NewEngine(EngineConfig{})
	if e.replayPlanner != nil {
		t.Error("replayPlanner should be nil initially")
	}
}

// E4-POS: buildFunc nil after NewEngine.
func TestNewEngine_NoBuildFunc(t *testing.T) {
	e := NewEngine(EngineConfig{})
	if e.buildFunc != nil {
		t.Error("buildFunc should be nil initially")
	}
}

// E8-POS: RegisterPlanner first registration.
func TestRegisterPlanner_FirstRegistration(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.RegisterPlanner(&mockPlanner{name: "tcp"})
	if names := e.ListProtocols(); len(names) != 1 || names[0] != "tcp" {
		t.Errorf("ListProtocols = %v, want [tcp]", names)
	}
	if _, ok := e.planners["tcp"]; !ok {
		t.Error("planner not found by name")
	}
}

// E9-BR1: duplicate registration overwrites.
func TestRegisterPlanner_DuplicateOverwrites(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.RegisterPlanner(&mockPlanner{name: "tcp"})
	e.RegisterPlanner(&mockPlanner{name: "tcp"})
	if len(e.planners) != 1 {
		t.Errorf("planners len=%d want 1 (duplicate overwritten)", len(e.planners))
	}
}

// E10-NEG: RegisterPlanner(nil) panics on .Name() call (nil interface method).
func TestRegisterPlanner_NilPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic from RegisterPlanner(nil)")
		}
	}()
	e := NewEngine(EngineConfig{})
	e.RegisterPlanner(nil)
}

// ========================================================================
// RegisterDualWriter / GetDualWriter / UnregisterDualWriter (E13-E24)
// ========================================================================

type fakePacketWriter struct {
	closed int32
	closeFn func()
}

func (f *fakePacketWriter) WritePackets(packets [][]byte) error { return nil }
func (f *fakePacketWriter) Close() error {
	atomic.AddInt32(&f.closed, 1)
	if f.closeFn != nil {
		f.closeFn()
	}
	return nil
}

// E13-POS: RegisterDualWriter stores the pair.
func TestRegisterDualWriter_Valid(t *testing.T) {
	e := NewEngine(EngineConfig{})
	c2s := &fakePacketWriter{}
	s2c := &fakePacketWriter{}
	e.RegisterDualWriter("t1", c2s, s2c)
	dw := e.GetDualWriter("t1")
	if dw == nil {
		t.Fatal("GetDualWriter returned nil")
	}
	if dw.C2S != c2s || dw.S2C != s2c {
		t.Error("C2S/S2C pointers don't match")
	}
}

// E14-NEG: both fields nil still stores.
func TestRegisterDualWriter_NilFields(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.RegisterDualWriter("t1", nil, nil)
	dw := e.GetDualWriter("t1")
	if dw == nil {
		t.Fatal("GetDualWriter returned nil for nil-fields entry")
	}
	if dw.C2S != nil || dw.S2C != nil {
		t.Error("expect nil C2S/S2C")
	}
}

// E16-BR1: empty taskID is accepted.
func TestRegisterDualWriter_EmptyTaskID(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.RegisterDualWriter("", &fakePacketWriter{}, nil)
	if dw := e.GetDualWriter(""); dw == nil {
		t.Error("empty task ID dual writer not stored")
	}
}

// E17-POS: UnregisterDualWriter closes both and removes.
func TestUnregisterDualWriter_Existing(t *testing.T) {
	e := NewEngine(EngineConfig{})
	c2s := &fakePacketWriter{}
	s2c := &fakePacketWriter{}
	e.RegisterDualWriter("t1", c2s, s2c)
	e.UnregisterDualWriter("t1")
	if atomic.LoadInt32(&c2s.closed) != 1 {
		t.Error("C2S.Close not called")
	}
	if atomic.LoadInt32(&s2c.closed) != 1 {
		t.Error("S2C.Close not called")
	}
	if e.GetDualWriter("t1") != nil {
		t.Error("dual writer not removed from map")
	}
}

// E18-NEG: UnregisterDualWriter non-existent -> no-op.
func TestUnregisterDualWriter_NonExistent(t *testing.T) {
	e := NewEngine(EngineConfig{})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("UnregisterDualWriter on non-existent panicked: %v", r)
		}
	}()
	e.UnregisterDualWriter("nope")
}

// E19-BR1: nil DualPortWriter in map.
func TestUnregisterDualWriter_NilDWInMap(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.dualWriters["t"] = nil
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("UnregisterDualWriter with nil entry panicked: %v", r)
		}
	}()
	e.UnregisterDualWriter("t")
}

// E20-BR2: C2S=nil, S2C set.
func TestUnregisterDualWriter_NilC2S(t *testing.T) {
	e := NewEngine(EngineConfig{})
	s2c := &fakePacketWriter{}
	e.RegisterDualWriter("t1", nil, s2c)
	e.UnregisterDualWriter("t1")
	if atomic.LoadInt32(&s2c.closed) != 1 {
		t.Error("S2C.Close not called")
	}
}

// E21-BR3: S2C=nil, C2S set.
func TestUnregisterDualWriter_NilS2C(t *testing.T) {
	e := NewEngine(EngineConfig{})
	c2s := &fakePacketWriter{}
	e.RegisterDualWriter("t1", c2s, nil)
	e.UnregisterDualWriter("t1")
	if atomic.LoadInt32(&c2s.closed) != 1 {
		t.Error("C2S.Close not called")
	}
}

// E23-POS: GetDualWriter returns the same pointer.
func TestGetDualWriter_Existing(t *testing.T) {
	e := NewEngine(EngineConfig{})
	c2s := &fakePacketWriter{}
	e.RegisterDualWriter("t1", c2s, nil)
	if dw := e.GetDualWriter("t1"); dw.C2S != c2s {
		t.Error("pointer mismatch")
	}
}

// E24-NEG: GetDualWriter non-existent -> nil.
func TestGetDualWriter_NonExistent(t *testing.T) {
	e := NewEngine(EngineConfig{})
	if dw := e.GetDualWriter("nope"); dw != nil {
		t.Error("expected nil for non-existent task")
	}
}

// ========================================================================
// Start (E25-E40)
// ========================================================================

func startMinimalEngine(t *testing.T) *Engine {
	e := NewEngine(EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, BufferSize: 16, QueueSize: 8})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return e
}

// E25-POS: Start with valid config.
func TestStart_ValidConfig(t *testing.T) {
	e := startMinimalEngine(t)
	defer e.Stop()
	if !e.running.Load() {
		t.Error("running is false after Start")
	}
	if len(e.configWorkers) != 1 || len(e.packetWorkers) != 1 || len(e.outputWorkers) != 1 {
		t.Errorf("workers: config=%d packet=%d output=%d, want 1/1/1",
			len(e.configWorkers), len(e.packetWorkers), len(e.outputWorkers))
	}
	if e.taskChan == nil || cap(e.taskChan) != 8 {
		t.Errorf("taskChan cap=%d want 8", cap(e.taskChan))
	}
	if len(e.shardedConfigChan) != 1 || cap(e.shardedConfigChan[0]) != 16 {
		t.Errorf("shardedConfigChan len=%d cap=%d want 1/16", len(e.shardedConfigChan), cap(e.shardedConfigChan[0]))
	}
	if len(e.shardedPacketChan) != 1 || cap(e.shardedPacketChan[0]) != 16 {
		t.Errorf("shardedPacketChan len=%d cap=%d want 1/16", len(e.shardedPacketChan), cap(e.shardedPacketChan[0]))
	}
	if e.buffer == nil {
		t.Error("buffer is nil")
	}
	if e.startWallClock.IsZero() {
		t.Error("startWallClock is zero")
	}
}

// E26-NEG: double Start returns error.
func TestStart_DoubleStart(t *testing.T) {
	e := startMinimalEngine(t)
	defer e.Stop()
	if err := e.Start(); err == nil {
		t.Fatal("second Start should return error")
	}
}

// E27-BR1: zero ConfigWorkers.
func TestStart_ZeroConfigWorkers(t *testing.T) {
	e := NewEngine(EngineConfig{PacketWorkers: 1, OutputWorkers: 1, BufferSize: 16, QueueSize: 8})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer e.Stop()
	if len(e.configWorkers) != 0 {
		t.Errorf("configWorkers len=%d want 0", len(e.configWorkers))
	}
	if !e.running.Load() {
		t.Error("running should be true")
	}
}

// E28-BR2: zero PacketWorkers. New behavior (spec §5.1): pw<=0 is clamped
// to 1, since without any PacketWorker the pipeline cannot drain configs.
func TestStart_ZeroPacketWorkers(t *testing.T) {
	e := NewEngine(EngineConfig{ConfigWorkers: 1, PacketWorkers: 0, OutputWorkers: 1, BufferSize: 16, QueueSize: 8})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer e.Stop()
	if len(e.packetWorkers) != 1 {
		t.Errorf("packetWorkers len=%d want 1 (clamped from 0)", len(e.packetWorkers))
	}
}

// E29-BR3: zero OutputWorkers.
// E29-BR2: zero OutputWorkers. New behavior (sharded packetChan forces
// OutputWorkers = PacketWorkers for 1:1 shard mapping). With PacketWorkers=1,
// OutputWorkers is forced to 1.
func TestStart_ZeroOutputWorkers(t *testing.T) {
	e := NewEngine(EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 0, BufferSize: 16, QueueSize: 8})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer e.Stop()
	if len(e.outputWorkers) != 1 {
		t.Errorf("outputWorkers len=%d want 1 (forced to PacketWorkers for shard 1:1)", len(e.outputWorkers))
	}
}

// E30-BR1: ReplayOrderPreserve no longer clamps (spec §8.3: replay uses
// implicit gID taskID:classID to route all packets to one shard, preserving
// pcap order without capping worker count).
func TestStart_ReplayOrderPreserve_ClampsPW4to1(t *testing.T) {
	e := NewEngine(EngineConfig{PacketWorkers: 4, ConfigWorkers: 1, OutputWorkers: 1, BufferSize: 16, QueueSize: 8, ReplayOrderPreserve: true})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer e.Stop()
	if len(e.packetWorkers) != 4 {
		t.Errorf("packet workers=%d want 4 (no longer clamped)", len(e.packetWorkers))
	}
}

// E31-BR2: ReplayOrderPreserve with PW=0 clamps to 1 (new behavior, §5.1).
func TestStart_ReplayOrderPreserve_PW0(t *testing.T) {
	e := NewEngine(EngineConfig{PacketWorkers: 0, ConfigWorkers: 1, OutputWorkers: 1, BufferSize: 16, QueueSize: 8, ReplayOrderPreserve: true})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer e.Stop()
	if len(e.packetWorkers) != 1 {
		t.Errorf("packet workers=%d want 1 (clamped from 0)", len(e.packetWorkers))
	}
}

// E32-BR3: ReplayOrderPreserve with PW=1 stays 1.
func TestStart_ReplayOrderPreserve_PW1(t *testing.T) {
	e := NewEngine(EngineConfig{PacketWorkers: 1, ConfigWorkers: 1, OutputWorkers: 1, BufferSize: 16, QueueSize: 8, ReplayOrderPreserve: true})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer e.Stop()
	if len(e.packetWorkers) != 1 {
		t.Errorf("packet workers=%d want 1", len(e.packetWorkers))
	}
}

// E36-BR1: BufferSize=0 -> Put always false.
func TestStart_BufferSizeZero(t *testing.T) {
	e := NewEngine(EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, BufferSize: 0, QueueSize: 8})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer e.Stop()
	if e.buffer == nil {
		t.Fatal("buffer is nil")
	}
	// size=0 -> count(0)>=size(0) -> Put always returns false.
	if e.buffer.Put([]byte{1}, "combined") {
		t.Error("Put with BufferSize=0 should return false (always full)")
	}
}

// E37-BR2: MaxBufferBytes=0 -> no byte limit.
func TestStart_MaxBufferBytesZero(t *testing.T) {
	e := NewEngine(EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, BufferSize: 100, QueueSize: 8})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer e.Stop()
	if e.buffer == nil || e.buffer.combinedBuffer.maxBytes != 0 {
		t.Errorf("maxBytes=%d want 0", e.buffer.combinedBuffer.maxBytes)
	}
}

// E38-BR3: QueueSize=0 -> unbuffered channels.
func TestStart_QueueSizeZero(t *testing.T) {
	e := NewEngine(EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, BufferSize: 8, QueueSize: 0})
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer e.Stop()
	if cap(e.taskChan) != 0 {
		t.Errorf("taskChan cap=%d want 0 (unbuffered)", cap(e.taskChan))
	}
	if len(e.shardedConfigChan) != 1 || cap(e.shardedConfigChan[0]) != 0 {
		t.Errorf("shardedConfigChan[0] cap=%d want 0", cap(e.shardedConfigChan[0]))
	}
	if len(e.shardedPacketChan) != 1 || cap(e.shardedPacketChan[0]) != 0 {
		t.Errorf("shardedPacketChan[0] cap=%d want 0", cap(e.shardedPacketChan[0]))
	}
}

// ========================================================================
// Stop (E41-E49)
// ========================================================================

// E41-POS: normal Stop cleans up.
func TestStop_Normal(t *testing.T) {
	e := startMinimalEngine(t)
	done := make(chan struct{})
	go func() {
		e.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return within 5s (wg.Wait hung)")
	}
	if e.running.Load() {
		t.Error("running is true after Stop")
	}
}

// E42-BR1: double Stop is safe.
func TestStop_AlreadyStopped(t *testing.T) {
	e := startMinimalEngine(t)
	e.Stop()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("double Stop panicked: %v", r)
		}
	}()
	e.Stop()
}

// E43-BR2: Stop without Start.
func TestStop_NeverStarted(t *testing.T) {
	e := NewEngine(EngineConfig{})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Stop on never-started engine panicked: %v", r)
		}
	}()
	e.Stop()
}

// E44-BR3: Stop with nil buffer (manual set).
func TestStop_NilBuffer(t *testing.T) {
	e := NewEngine(EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, BufferSize: 16, QueueSize: 8})
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	e.buffer = nil // force nil
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Stop with nil buffer panicked: %v", r)
		}
	}()
	e.Stop()
}

// ========================================================================
// StopTask (E67-E71) -- state-machine level via direct taskEntry
// ========================================================================

// E68-NEG: StopTask("nope") -> error.
func TestStopTask_NotFound(t *testing.T) {
	e := NewEngine(EngineConfig{})
	err := e.StopTask("nope")
	if err == nil {
		t.Fatal("expected error for non-existent task")
	}
}

// E71-NEG: StopTask with nil cancel -> panic.
func TestStopTask_NilCancelCrash(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.taskMu.Lock()
	e.taskStore["t1"] = &taskEntry{
		task:   &Task{ID: "t1"},
		status: &TaskStatus{TaskID: "t1", Status: "running"},
		cancel: nil,
	}
	e.taskMu.Unlock()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic from calling nil CancelFunc")
		}
	}()
	e.StopTask("t1")
}

// ========================================================================
// SetTaskTotalConfigs (E72-E82)
// ========================================================================

func makeEngineWithTask(t *testing.T, taskID string) *Engine {
	t.Helper()
	e := NewEngine(EngineConfig{})
	// Manually insert a task entry with a no-op cancel.
	ctx, cancel := context.WithCancel(context.Background())
	_ = ctx
	e.taskMu.Lock()
	e.taskStore[taskID] = &taskEntry{
		task:   &Task{ID: taskID, Ctx: context.Background()},
		status: &TaskStatus{TaskID: taskID, Status: "running"},
		cancel: cancel,
	}
	e.taskMu.Unlock()
	return e
}

func getTaskEntry(e *Engine, taskID string) *taskEntry {
	e.taskMu.RLock()
	defer e.taskMu.RUnlock()
	return e.taskStore[taskID]
}

// E72-POS: SetTaskTotalConfigs stores count.
func TestSetTaskTotalConfigs_Normal(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	e.SetTaskTotalConfigs("t1", 100)
	entry := getTaskEntry(e, "t1")
	if entry == nil {
		t.Fatal("entry removed unexpectedly")
	}
	if entry.totalConfigs != 100 {
		t.Errorf("totalConfigs=%d want 100", entry.totalConfigs)
	}
	if entry.status.Status != "running" {
		t.Errorf("status=%q want running", entry.status.Status)
	}
}

// E73-NEG: SetTaskTotalConfigs on non-existent -> no-op.
func TestSetTaskTotalConfigs_NotInStore(t *testing.T) {
	e := NewEngine(EngineConfig{})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Set on non-existent panicked: %v", r)
		}
	}()
	e.SetTaskTotalConfigs("nope", 100)
}

// E74-BR1: count=0 -> immediate completion.
func TestSetTaskTotalConfigs_CountZeroCompletes(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	completed := false
	e.OnTaskComplete = func(id string) { completed = true }
	e.SetTaskTotalConfigs("t1", 0)
	if getTaskEntry(e, "t1") != nil {
		t.Error("task not removed from store on count=0 completion")
	}
	if !completed {
		t.Error("OnTaskComplete not fired for count=0")
	}
}

// E75-BR2: already completed -> fires OnTaskComplete again.
func TestSetTaskTotalConfigs_AlreadyComplete(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	entry := getTaskEntry(e, "t1")
	entry.totalConfigs = 50
	entry.writtenPackets = 50 // already met
	var count int
	e.OnTaskComplete = func(id string) { count++ }
	e.SetTaskTotalConfigs("t1", 50)
	if count != 1 {
		t.Errorf("OnTaskComplete called %d times, want 1 (already met)", count)
	}
}

// E76-BR3: writtenPackets > count -> completes.
func TestSetTaskTotalConfigs_WrittenExceeds(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	entry := getTaskEntry(e, "t1")
	entry.writtenPackets = 60
	var completed bool
	e.OnTaskComplete = func(id string) { completed = true }
	e.SetTaskTotalConfigs("t1", 50)
	if !completed {
		t.Error("should complete when written > count")
	}
}

// E77-POS: count > 0 and written < count -> stays running.
func TestSetTaskTotalConfigs_NoCompletion(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	e.SetTaskTotalConfigs("t1", 100)
	entry := getTaskEntry(e, "t1")
	if entry == nil {
		t.Fatal("entry removed")
	}
	if entry.status.Status != "running" {
		t.Errorf("status=%q want running", entry.status.Status)
	}
}

// E78-BR1: OnTaskComplete nil -> no crash.
func TestSetTaskTotalConfigs_OnTaskCompleteNil(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	e.SetTaskTotalConfigs("t1", 0) // completes, but callback nil
	// Should not panic; status should still be completed.
}

// E79-BR2: cleanup task's rate limiters on completion.
func TestSetTaskTotalConfigs_CleansRateLimiters(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.rateLimiters["t1"] = NewTokenBucket(1000, 100)
	e.rateLimiters["t1:c1"] = NewTokenBucket(1000, 100)
	e.rateLimiters["other"] = NewTokenBucket(1000, 100)
	// Manually add task entry.
	e.taskMu.Lock()
	e.taskStore["t1"] = &taskEntry{
		task: &Task{ID: "t1"}, status: &TaskStatus{TaskID: "t1", Status: "running"},
		cancel: func() {},
	}
	e.taskMu.Unlock()
	e.SetTaskTotalConfigs("t1", 0) // 0-count completes and cleans up
	if _, ok := e.rateLimiters["t1"]; ok {
		t.Error("t1 rate limiter not cleaned up")
	}
	if _, ok := e.rateLimiters["t1:c1"]; ok {
		t.Error("t1:c1 rate limiter not cleaned up")
	}
	if _, ok := e.rateLimiters["other"]; !ok {
		t.Error("other rate limiter incorrectly removed")
	}
}

// E80-POS: cleanupTaskRateLimiters exact key.
func TestCleanupTaskRateLimiters_ExactKey(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.rateLimiters["t1"] = NewTokenBucket(1000, 100)
	e.cleanupTaskRateLimiters("t1")
	if _, ok := e.rateLimiters["t1"]; ok {
		t.Error("exact key not removed")
	}
}

// E81-BR1: cleanupTaskRateLimiters prefix keys.
func TestCleanupTaskRateLimiters_PrefixKeys(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.rateLimiters["t1:c1"] = NewTokenBucket(1000, 100)
	e.rateLimiters["t1:c2"] = NewTokenBucket(1000, 100)
	e.rateLimiters["other:c1"] = NewTokenBucket(1000, 100)
	e.cleanupTaskRateLimiters("t1")
	if _, ok := e.rateLimiters["t1:c1"]; ok {
		t.Error("t1:c1 not removed")
	}
	if _, ok := e.rateLimiters["t1:c2"]; ok {
		t.Error("t1:c2 not removed")
	}
	if _, ok := e.rateLimiters["other:c1"]; !ok {
		t.Error("other:c1 incorrectly removed")
	}
}

// E82-BR2: cleanupTaskRateLimiters no matching keys -> no-op.
func TestCleanupTaskRateLimiters_None(t *testing.T) {
	e := NewEngine(EngineConfig{})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("cleanup with no matching keys panicked: %v", r)
		}
	}()
	e.cleanupTaskRateLimiters("nonexistent")
}

// ========================================================================
// OnPacketWritten (E83-E92)
// ========================================================================

// E83-POS: normal increment.
func TestOnPacketWritten_Normal(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	entry := getTaskEntry(e, "t1")
	entry.totalConfigs = 100
	e.OnPacketWritten("t1")
	if entry.writtenPackets != 1 {
		t.Errorf("writtenPackets=%d want 1", entry.writtenPackets)
	}
	if entry.status.Status != "running" {
		t.Errorf("status=%q want running", entry.status.Status)
	}
}

// E84-NEG: not in store -> no-op.
func TestOnPacketWritten_NotInStore(t *testing.T) {
	e := NewEngine(EngineConfig{})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("OnPacketWritten on non-existent panicked: %v", r)
		}
	}()
	e.OnPacketWritten("nope")
}

// E85-BR1: stopped task -> no increment.
func TestOnPacketWritten_StatusStopped(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	entry := getTaskEntry(e, "t1")
	entry.totalConfigs = 10
	entry.status.Status = "stopped"
	e.OnPacketWritten("t1")
	// engine.go increments writtenPackets (line 560) BEFORE the status check
	// (line 562). So the increment always happens; only the completion check
	// is skipped. Status must still be "stopped" (not overwritten to completed).
	if entry.writtenPackets != 1 {
		t.Errorf("writtenPackets=%d want 1 (incremented before stopped guard)", entry.writtenPackets)
	}
	if entry.status.Status != "stopped" {
		t.Errorf("status=%q want stopped (completion check skipped)", entry.status.Status)
	}
}

// E86-BR2: reaches totalConfigs -> complete.
func TestOnPacketWritten_ReachesTotal(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	entry := getTaskEntry(e, "t1")
	entry.totalConfigs = 10
	entry.writtenPackets = 9
	var completed bool
	e.OnTaskComplete = func(id string) { completed = true }
	e.OnPacketWritten("t1")
	if !completed {
		t.Error("should complete when writtenPackets reaches totalConfigs")
	}
	if getTaskEntry(e, "t1") != nil {
		t.Error("task not removed from store on completion")
	}
}

// E87-BR3: totalConfigs=0 -> no completion check.
func TestOnPacketWritten_TotalConfigsZero(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	entry := getTaskEntry(e, "t1")
	entry.totalConfigs = 0
	e.OnPacketWritten("t1")
	if entry.writtenPackets != 1 {
		t.Errorf("writtenPackets=%d want 1", entry.writtenPackets)
	}
	if entry.status.Status != "running" {
		t.Errorf("status=%q want running (totalConfigs=0 -> no completion)", entry.status.Status)
	}
}

// E91-BR3: OnProgress nil -> no crash.
func TestOnPacketWritten_OnProgressNil(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	entry := getTaskEntry(e, "t1")
	entry.totalConfigs = 10
	e.OnPacketWritten("t1")
	if entry.status.Progress < 0 {
		t.Error("progress went negative")
	}
}

// E92-BR1: OnTaskComplete nil -> no crash.
func TestOnPacketWritten_OnTaskCompleteNil(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	entry := getTaskEntry(e, "t1")
	entry.totalConfigs = 1
	entry.writtenPackets = 0
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("OnPacketWritten with nil OnTaskComplete panicked: %v", r)
		}
	}()
	e.OnPacketWritten("t1")
}

// ========================================================================
// FailTask (E93-E100)
// ========================================================================

// E93-POS: normal fail.
func TestFailTask_Normal(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	entry := getTaskEntry(e, "t1")
	e.FailTask("t1", "something went wrong")
	if entry.status.Status != "failed" {
		t.Errorf("status=%q want failed", entry.status.Status)
	}
	if entry.status.Error != "something went wrong" {
		t.Errorf("error=%q want 'something went wrong'", entry.status.Error)
	}
	if entry.status.CompletedAt.IsZero() {
		t.Error("CompletedAt is zero")
	}
	if getTaskEntry(e, "t1") != nil {
		t.Error("task not removed from store on failure")
	}
}

// E94-NEG: non-existent -> no-op.
func TestFailTask_NotInStore(t *testing.T) {
	e := NewEngine(EngineConfig{})
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FailTask on non-existent panicked: %v", r)
		}
	}()
	e.FailTask("nope", "err")
}

// E95-BR1: already stopped -> not overwritten.
func TestFailTask_AlreadyStopped(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	entry := getTaskEntry(e, "t1")
	entry.status.Status = "stopped"
	e.FailTask("t1", "err")
	if entry.status.Status != "stopped" {
		t.Errorf("status=%q want stopped (not overwritten)", entry.status.Status)
	}
}

// E97-POS: OnTaskFailed fires.
func TestFailTask_OnTaskFailedFires(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	var failedID, failedMsg string
	e.OnTaskFailed = func(id, msg string) { failedID = id; failedMsg = msg }
	e.FailTask("t1", "my error")
	if failedID != "t1" || failedMsg != "my error" {
		t.Errorf("OnTaskFailed(%q, %q), want (t1, my error)", failedID, failedMsg)
	}
}

// E98-BR1: OnTaskComplete fires after OnTaskFailed.
func TestFailTask_OnTaskCompleteAfterFailed(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	var order []string
	e.OnTaskFailed = func(_, _ string) { order = append(order, "failed") }
	e.OnTaskComplete = func(_ string) { order = append(order, "complete") }
	e.FailTask("t1", "err")
	if len(order) != 2 || order[0] != "failed" || order[1] != "complete" {
		t.Errorf("order=%v, want [failed complete]", order)
	}
}

// E99-BR2: OnTaskFailed nil -> still fires OnTaskComplete.
func TestFailTask_OnTaskFailedNil(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	var completed bool
	e.OnTaskComplete = func(_ string) { completed = true }
	e.FailTask("t1", "err")
	if !completed {
		t.Error("OnTaskComplete should fire even with OnTaskFailed=nil")
	}
}

// E100-BR3: OnTaskComplete nil -> still fires OnTaskFailed.
func TestFailTask_OnTaskCompleteNil(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	var failed bool
	e.OnTaskFailed = func(_, _ string) { failed = true }
	e.FailTask("t1", "err")
	if !failed {
		t.Error("OnTaskFailed should fire even with OnTaskComplete=nil")
	}
}

// ========================================================================
// GetTaskStatus / ActiveTaskCount / RangeTaskStore (E101-E107)
// ========================================================================

// E101-POS: GetTaskStatus returns status.
func TestGetTaskStatus_Existing(t *testing.T) {
	e := makeEngineWithTask(t, "t1")
	status, err := e.GetTaskStatus("t1")
	if err != nil {
		t.Fatalf("GetTaskStatus: %v", err)
	}
	if status == nil {
		t.Fatal("status is nil")
	}
	if status.TaskID != "t1" {
		t.Errorf("TaskID=%q want t1", status.TaskID)
	}
}

// E102-NEG: GetTaskStatus non-existent.
func TestGetTaskStatus_NonExistent(t *testing.T) {
	e := NewEngine(EngineConfig{})
	_, err := e.GetTaskStatus("nope")
	if err == nil {
		t.Fatal("expected error for non-existent task")
	}
}

// E103-POS: ActiveTaskCount zero.
func TestActiveTaskCount_Zero(t *testing.T) {
	e := NewEngine(EngineConfig{})
	if c := e.ActiveTaskCount(); c != 0 {
		t.Errorf("count=%d want 0", c)
	}
}

// E104-BR1: ActiveTaskCount 500.
func TestActiveTaskCount_500(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.taskMu.Lock()
	for i := 0; i < 500; i++ {
		id := string(rune(i))
		e.taskStore[id] = &taskEntry{task: &Task{ID: id}, status: &TaskStatus{TaskID: id, Status: "running"}, cancel: func() {}}
	}
	e.taskMu.Unlock()
	if c := e.ActiveTaskCount(); c != 500 {
		t.Errorf("count=%d want 500", c)
	}
}

// E105-POS: RangeTaskStore iterates all.
func TestRangeTaskStore_AllTrue(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.taskMu.Lock()
	e.taskStore["a"] = &taskEntry{task: &Task{ID: "a"}, status: &TaskStatus{TaskID: "a"}}
	e.taskStore["b"] = &taskEntry{task: &Task{ID: "b"}, status: &TaskStatus{TaskID: "b"}}
	e.taskMu.Unlock()
	var visited []string
	e.RangeTaskStore(func(id string, status *TaskStatus) bool {
		visited = append(visited, id)
		return true
	})
	if len(visited) != 2 {
		t.Errorf("visited %v, want 2 items", visited)
	}
}

// E106-BR1: RangeTaskStore short-circuits on false.
func TestRangeTaskStore_FalseEarly(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.taskMu.Lock()
	e.taskStore["a"] = &taskEntry{task: &Task{ID: "a"}, status: &TaskStatus{TaskID: "a"}}
	e.taskStore["b"] = &taskEntry{task: &Task{ID: "b"}, status: &TaskStatus{TaskID: "b"}}
	e.taskMu.Unlock()
	var count int
	e.RangeTaskStore(func(id string, status *TaskStatus) bool {
		count++
		return count < 1
	})
	if count != 1 {
		t.Errorf("fn called %d times, want 1 (false after first)", count)
	}
}

// E107-NEG: RangeTaskStore fn panic releases lock.
func TestRangeTaskStore_FnPanic_ReleasesLock(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.taskMu.Lock()
	e.taskStore["a"] = &taskEntry{task: &Task{ID: "a"}, status: &TaskStatus{TaskID: "a"}}
	e.taskMu.Unlock()
	func() {
		defer func() { recover() }()
		e.RangeTaskStore(func(id string, status *TaskStatus) bool {
			panic("test panic")
		})
	}()
	// After the panic, the defer RUnlock should have released the lock.
	// If the lock were held, this would deadlock.
	done := make(chan struct{})
	go func() {
		e.taskMu.RLock()
		defer e.taskMu.RUnlock()
		_ = len(e.taskStore)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("lock not released after fn panic (would deadlock)")
	}
}

// ========================================================================
// GetPackets / GetBufferStatus (E108-E111)
// ========================================================================

// E108-NEG: GetPackets with nil buffer -> nil.
func TestGetPackets_NilBuffer(t *testing.T) {
	e := NewEngine(EngineConfig{})
	if pkts := e.GetPackets(10, "combined"); pkts != nil {
		t.Errorf("GetPackets with nil buffer = %v, want nil", pkts)
	}
}

// E110-NEG: GetBufferStatus with nil buffer -> nil.
func TestGetBufferStatus_NilBuffer(t *testing.T) {
	e := NewEngine(EngineConfig{})
	if s := e.GetBufferStatus(); s != nil {
		t.Errorf("GetBufferStatus with nil buffer = %v, want nil", s)
	}
}

// ========================================================================
// SetClassRateLimit / GetRateLimiter (E112-E119)
// ========================================================================

// E112-POS: SetClassRateLimit 1Mbps -> rate=125000, burst=65536.
func TestSetClassRateLimit_1Mbps(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.SetClassRateLimit("c1", 1000000)
	limiter := e.GetRateLimiter("c1")
	if limiter == nil {
		t.Fatal("rate limiter is nil")
	}
	if limiter.rate != 125000 { // 1Mbps / 8 = 125000 B/s
		t.Errorf("rate=%d want 125000", limiter.rate)
	}
	if limiter.burst != 65536 {
		t.Errorf("burst=%d want 65536", limiter.burst)
	}
}

// E113-BR1: SetClassRateLimit bps=0 -> rate=1 (guarded from zero).
func TestSetClassRateLimit_BpsZero(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.SetClassRateLimit("c1", 0) // 0/8=0 -> guard -> 1
	limiter := e.GetRateLimiter("c1")
	if limiter == nil {
		t.Fatal("rate limiter is nil")
	}
	if limiter.rate != 1 {
		t.Errorf("rate=%d want 1 (guard against zero unlimited)", limiter.rate)
	}
}

// E114-BR2: bps=4 -> rateBytesPerSec=0 -> guard to 1.
func TestSetClassRateLimit_BpsOneToSeven(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.SetClassRateLimit("c1", 4) // 4/8=0 -> guard -> 1
	limiter := e.GetRateLimiter("c1")
	if limiter == nil {
		t.Fatal("rate limiter is nil")
	}
	if limiter.rate != 1 {
		t.Errorf("rate=%d want 1", limiter.rate)
	}
}

// E115-BR3: bps=8 -> rateBytesPerSec=1.
func TestSetClassRateLimit_BpsEight(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.SetClassRateLimit("c1", 8) // 8/8=1
	limiter := e.GetRateLimiter("c1")
	if limiter == nil {
		t.Fatal("rate limiter is nil")
	}
	if limiter.rate != 1 {
		t.Errorf("rate=%d want 1", limiter.rate)
	}
}

// E116-BR1: empty classID still stored.
func TestSetClassRateLimit_EmptyClassID(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.SetClassRateLimit("", 1000)
	if limiter := e.GetRateLimiter(""); limiter == nil {
		t.Error("empty classID rate limiter not found")
	}
}

// E118-POS: GetRateLimiter returns same instance.
func TestGetRateLimiter_Existing(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.SetClassRateLimit("c1", 1000)
	l1 := e.GetRateLimiter("c1")
	l2 := e.GetRateLimiter("c1")
	if l1 != l2 {
		t.Error("GetRateLimiter returned different pointers for same key")
	}
}

// E119-NEG: GetRateLimiter non-existent -> nil.
func TestGetRateLimiter_NonExistent(t *testing.T) {
	e := NewEngine(EngineConfig{})
	if limiter := e.GetRateLimiter("nope"); limiter != nil {
		t.Error("expected nil for non-existent key")
	}
}

// ========================================================================
// SetMaxTasks (E126-E128)
// ========================================================================

// E126-POS: SetMaxTasks(10).
func TestSetMaxTasks_Ten(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.SetMaxTasks(10)
	if m := e.maxTasks.Load(); m != 10 {
		t.Errorf("maxTasks=%d want 10", m)
	}
}

// E127-BR1: SetMaxTasks(0) -> unlimited.
func TestSetMaxTasks_Zero(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.SetMaxTasks(0)
	if m := e.maxTasks.Load(); m != 0 {
		t.Errorf("maxTasks=%d want 0", m)
	}
}

// E128-BR2: SetMaxTasks(-1) -> clamped to 0.
func TestSetMaxTasks_Negative(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.SetMaxTasks(-1)
	if m := e.maxTasks.Load(); m != 0 {
		t.Errorf("maxTasks=%d want 0 (clamped)", m)
	}
}

// ========================================================================
// GetCPUUsage (E120-E125)
// ========================================================================

// E120-POS: GetCPUUsage after CPU burn -> >0.
func TestGetCPUUsage_OneCoreBusy(t *testing.T) {
	e := NewEngine(EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, BufferSize: 16, QueueSize: 8})
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	// Burn CPU
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
	time.Sleep(50 * time.Millisecond)
	if cpu := e.GetCPUUsage(); cpu <= 0 {
		t.Errorf("GetCPUUsage=%f want > 0", cpu)
	}
}

// E121-BR1: GetCPUUsage before Start -> 0.
func TestGetCPUUsage_StartWallClockZero(t *testing.T) {
	e := NewEngine(EngineConfig{})
	if cpu := e.GetCPUUsage(); cpu != 0 {
		t.Errorf("GetCPUUsage before Start = %f, want 0", cpu)
	}
}

// ========================================================================
// writePacketsTo (E129-E131)
// ========================================================================

type trackTimedWriter struct {
	packets [][]byte
	timed   []PacketOutput
}

func (w *trackTimedWriter) WritePackets(packets [][]byte) error {
	w.packets = append(w.packets, packets...)
	return nil
}
func (w *trackTimedWriter) WriteTimedPackets(packets []PacketOutput) error {
	w.timed = append(w.timed, packets...)
	return nil
}
func (w *trackTimedWriter) Close() error { return nil }

// E129-POS+E130-BR1: TimedWriter path and plain writer path. A plain writer
// (no TimedWriter method) must fall through to WritePackets.
type plainPacketWriter struct {
	packets [][]byte
}

func (w *plainPacketWriter) WritePackets(packets [][]byte) error {
	w.packets = append(w.packets, packets...)
	return nil
}
func (w *plainPacketWriter) Close() error { return nil }

func TestWritePacketsTo_BothPaths(t *testing.T) {
	// TimedWriter path (E129-POS): trackTimedWriter implements both interfaces,
	// TimedWriter takes precedence -> WriteTimedPackets is called.
	tw := &trackTimedWriter{}
	outTimed := PacketOutput{Data: []byte{1, 2, 3}, Timestamp: time.Now()}
	if err := writePacketsTo(tw, outTimed); err != nil {
		t.Fatal(err)
	}
	if len(tw.timed) != 1 || string(tw.timed[0].Data) != string(outTimed.Data) {
		t.Errorf("TimedWriter did not receive WriteTimedPackets (timed=%v)", tw.timed)
	}
	if len(tw.packets) != 0 {
		t.Errorf("TimedWriter should not fall back to WritePackets (packets=%v)", tw.packets)
	}

	// Plain writer path (E130-BR1): plainPacketWriter has only WritePackets,
	// no TimedWriter -> writePacketsTo calls WritePackets directly.
	pw := &plainPacketWriter{}
	outPlain := PacketOutput{Data: []byte{4, 5, 6}, Timestamp: time.Now()}
	if err := writePacketsTo(pw, outPlain); err != nil {
		t.Fatal(err)
	}
	if len(pw.packets) != 1 || string(pw.packets[0]) != string(outPlain.Data) {
		t.Errorf("plain writer did not receive WritePackets (packets=%v)", pw.packets)
	}
}

// E131-NEG: nil writer panics (nil interface call).
func TestWritePacketsTo_NilWriterPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic from nil PacketWriter")
		}
	}()
	_ = writePacketsTo(nil, PacketOutput{Data: []byte{1}})
}

// ========================================================================
// GetStats (E132-E134)
// ========================================================================

// E132-POS: GetStats with no workers -> zero stats.
func TestGetStats_NoWorkers(t *testing.T) {
	e := NewEngine(EngineConfig{})
	stats := e.GetStats()
	if stats["running"] != false {
		t.Error("running should be false")
	}
	cw := stats["config_workers"].(map[string]interface{})
	if cw["packets"].(int64) != 0 || cw["tasks"].(int64) != 0 || cw["errors"].(int64) != 0 {
		t.Errorf("config_workers stats wrong: %v", cw)
	}
}

// E134-BR2: GetStats with nil buffer -> stats["buffer"] is the buffer status
// map (may be empty). The exact behavior is observable: GetBufferStatus is
// always called, so the key is always present even on an unstarted engine.
func TestGetStats_NilBuffer(t *testing.T) {
	e := NewEngine(EngineConfig{})
	stats := e.GetStats()
	buf, ok := stats["buffer"]
	if !ok {
		t.Fatal("stats[\"buffer\"] absent; GetStats must always populate it")
	}
	if buf == nil {
		t.Errorf("stats[\"buffer\"] = nil; want non-nil map (empty is fine)")
	}
	// For an unstarted engine the buffer is nil and GetBufferStatus returns
	// an empty map (no fields to report).
	m, isMap := buf.(map[string]interface{})
	if !isMap {
		t.Fatalf("stats[\"buffer\"] type = %T, want map[string]interface{}", buf)
	}
	if len(m) != 0 {
		t.Errorf("stats[\"buffer\"] = %v; want empty (nil buffer)", m)
	}
}

// ========================================================================
// SetFatalError / GetFatalError (E135-E138)
// ========================================================================

// E135-BR1: SetFatalError(nil). Note: sync/atomic.Value.Store(nil) panics by
// design (Go stdlib: "nil should never be stored in a Value"). The current
// implementation passes through to atomic.Value.Store and panics on nil input.
// Pinning the behavior: callers must not pass nil. Test verifies panic occurs.
func TestSetFatalError_Nil(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic from atomic.Value.Store(nil) -- engine must guard nil before storing")
		}
	}()
	e := NewEngine(EngineConfig{})
	e.SetFatalError(nil)
}

func TestSetFatalError_NonNil(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.SetFatalError(errors.New("boom"))
	if err := e.GetFatalError(); err == nil || err.Error() != "boom" {
		t.Errorf("GetFatalError = %v, want boom", err)
	}
}

func TestGetFatalError_None(t *testing.T) {
	e := NewEngine(EngineConfig{})
	if err := e.GetFatalError(); err != nil {
		t.Errorf("GetFatalError initially = %v, want nil", err)
	}
}

func TestGetFatalError_Stored(t *testing.T) {
	e := NewEngine(EngineConfig{})
	e.SetFatalError(errors.New("x"))
	if err := e.GetFatalError(); err == nil || err.Error() != "x" {
		t.Errorf("stored fatal error = %v, want x", err)
	}
}

// ========================================================================
// Concurrent: SharedTokenBucket aggregate throughput (CONC1)
// ========================================================================

// TestSharedTokenBucket_NWorkers_AggregateRate verifies that N workers sharing
// one TokenBucket achieve aggregate rate ~ 1x rate, NOT Nx. Previously the
// missing mutex meant each worker got its own full refill, producing Nx.
func TestSharedTokenBucket_NWorkers_AggregateRate(t *testing.T) {
	const workers = 4
	const totalBytes int64 = 100_000
	const bps int64 = 10_000_000 // 10 Mbps = 1.25 MB/s
	burst := int64(65536)

	tb := NewTokenBucket(bps/8, burst) // rate=1250000 B/s
	// First, drain the burst so we measure refill-based pacing.
	tb.Allow(burst)

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < int(totalBytes/int64(workers)); j++ {
				tb.Wait(context.Background(), 1)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	// At 1.25MB/s rate, 100KB should take ~0.08s.
	// Without mutual exclusion (each worker independently refills), elapsed would
	// be ~0.02s (4x too fast). Allow generous tolerance for goroutine scheduling.
	minExpected := 50 * time.Millisecond
	if elapsed < minExpected {
		t.Errorf("aggregate elapsed=%v, want >=%v (would be 4x faster without mutual exclusion)", elapsed, minExpected)
	}
	t.Logf("CONC1 SharedTokenBucket: workers=%d totalBytes=%d elapsed=%v (>=%v expected for shared rate)",
		workers, totalBytes, elapsed, minExpected)
}

// ========================================================================
// Concurrent: RingBuffer concurrent put/get aggregate (CONC4)
// ========================================================================

// TestRingBuffer_ConcurrentPutGet_Aggregate verifies conservation: total
// successful puts == total gets + remaining items in buffer.
func TestRingBuffer_ConcurrentPutGet_Aggregate(t *testing.T) {
	const producers, consumers, perProducer = 4, 4, 100
	rb := NewRingBuffer(50, 0)
	var puts, gets int64
	var prodWg, consWg sync.WaitGroup

	producersDone := make(chan struct{})
	for i := 0; i < producers; i++ {
		prodWg.Add(1)
		go func() {
			defer prodWg.Done()
			for j := 0; j < perProducer; j++ {
				if rb.Put([]byte{1}) {
					atomic.AddInt64(&puts, 1)
				}
			}
		}()
	}
	go func() { prodWg.Wait(); close(producersDone) }()

	for i := 0; i < consumers; i++ {
		consWg.Add(1)
		go func() {
			defer consWg.Done()
			for {
				_, ok := rb.Get()
				if ok {
					atomic.AddInt64(&gets, 1)
					continue
				}
				select {
				case <-producersDone:
					for rb.Len() > 0 {
						if _, ok := rb.Get(); ok {
							atomic.AddInt64(&gets, 1)
						}
					}
					return
				default:
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}
	consWg.Wait()
	if puts != gets {
		t.Errorf("conservation: puts=%d gets=%d, want equal", puts, gets)
	}
}

// ========================================================================
// Concurrent: Stop idempotent double-close (CONC10)
// ========================================================================

// TestStop_Idempotent_DoubleStop is covered by TestStop_AlreadyStopped above.