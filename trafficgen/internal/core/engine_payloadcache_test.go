package core_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// TestEngine_SetPayloadCache verifies the engine wiring for PayloadCache.
// The cache is injected at the engine level by the server (Task 13), and
// the worker reads it via Engine.PayloadCache() to inject into each
// task's ctx so planners can resolve FileSource payloads.
func TestEngine_SetPayloadCache(t *testing.T) {
	e := core.NewEngine(core.EngineConfig{})
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)
	e.SetPayloadCache(pc)
	got := e.PayloadCache()
	if got != pc {
		t.Fatalf("PayloadCache got %p, want %p", got, pc)
	}
}

// TestWithPayloadCache_RoundTrip verifies the ctx-injection helper used
// by the worker (core.WithPayloadCache) and the planner-side reader
// (core.PayloadCacheFrom) agree on the key type. The 5 protocol planners
// (ftp, sip, sctp, http, icmp) call core.PayloadCacheFrom(ctx) — the
// engine worker must call core.WithPayloadCache(ctx, pc) for them to
// find the cache.
func TestWithPayloadCache_RoundTrip(t *testing.T) {
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)
	got := core.PayloadCacheFrom(ctx)
	if got != pc {
		t.Fatalf("PayloadCacheFrom got %p, want %p", got, pc)
	}
}

// TestPayloadCacheFrom_NoCache verifies the reader returns nil (not a
// panic) when no cache was injected. Planners rely on this nil-check to
// skip FileSource resolution gracefully when running outside the engine
// (e.g. unit tests that forgot to inject).
func TestPayloadCacheFrom_NoCache(t *testing.T) {
	if got := core.PayloadCacheFrom(context.Background()); got != nil {
		t.Fatalf("PayloadCacheFrom on bare ctx got %p, want nil", got)
	}
}

// cacheCapturingPlanner is a ProtocolPlanner double that captures the
// *core.PayloadCache read from ctx via core.PayloadCacheFrom at Plan()
// call time. Mirrors the fcCapturingPlanner pattern (replay_strategy_test.go)
// but captures a ctx-value instead of an fc pointer. The captured value is
// read back by the test after the task completes via done.
type cacheCapturingPlanner struct {
	mu       sync.Mutex
	captured *core.PayloadCache
	called   chan struct{}
}

func (p *cacheCapturingPlanner) Name() string                 { return "tcp" }
func (p *cacheCapturingPlanner) Validate(spec core.FlowSpec) error { return nil }

func (p *cacheCapturingPlanner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	p.mu.Lock()
	p.captured = core.PayloadCacheFrom(ctx)
	p.mu.Unlock()
	close(p.called)
	ch := make(chan core.PacketConfig)
	close(ch)
	return ch, nil
}

// capturedCache returns the cache observed by Plan, or nil if Plan has
// not yet been called. Safe to call after the test has waited on p.called.
func (p *cacheCapturingPlanner) capturedCache() *core.PayloadCache {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.captured
}

// TestWorker_InjectsPayloadCacheIntoPlannerCtx is the integration test
// requested by the Task 13 review (Important finding). It drives the full
// engine pipeline (SubmitTask → ConfigWorker → ProtocolPlanner.Plan) and
// verifies the cache the planner observes via core.PayloadCacheFrom(ctx)
// is the exact pointer installed on the engine via SetPayloadCache.
//
// Without the worker calling core.WithPayloadCache(taskCtx, pc) before
// p.Plan(ctx, spec) (worker.go:206-209), the planner would see nil and
// this test would fail — that's the regression this test guards against.
// The unit tests above (TestWithPayloadCache_RoundTrip,
// TestEngine_SetPayloadCache) only verify the helpers in isolation; they
// would pass even if the worker forgot to inject.
//
// We use a single-flow, zero-packet planner (Plan closes the channel
// immediately) so the task completes deterministically without needing
// a packet builder or output drain.
func TestWorker_InjectsPayloadCacheIntoPlannerCtx(t *testing.T) {
	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1,
		PacketWorkers: 1,
		OutputWorkers: 1,
		BufferSize:    32,
		QueueSize:     16,
	})
	stub := &cacheCapturingPlanner{called: make(chan struct{})}
	e.RegisterPlanner(stub)
	e.SetBuildFunc(func(c core.PacketConfig) ([]byte, error) {
		return make([]byte, 0), nil
	})

	// Engine-wide cache installed before Start (mirrors server wiring).
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)
	e.SetPayloadCache(pc)

	if err := e.Start(); err != nil {
		t.Fatalf("engine start: %v", err)
	}
	defer e.Stop()

	done := make(chan string, 1)
	e.OnTaskComplete = func(taskID string) { done <- taskID }

	task := core.Task{
		ID:       "pc-inject-1",
		Name:     "pc-inject-test",
		Protocol: "tcp",
		ClassID:  "pc-inject-1",
		Spec:     core.FlowSpec{Count: 1},
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Wait for Plan to be called (cache captured) OR task completion OR
	// timeout. We can't wait only on `done` because the planner channel
	// closes immediately but the packet builder + output worker still
	// need to drain. The planner's `called` channel is the authoritative
	// signal that the injection happened.
	select {
	case <-stub.called:
		// Plan was called — proceed to assert.
	case <-done:
		// Task already finished (fast path); also fine, Plan was called.
	case <-time.After(5 * time.Second):
		t.Fatal("planner.Plan was never called within 5s — worker did not dispatch the task")
	}

	got := stub.capturedCache()
	if got == nil {
		t.Fatal("planner saw nil PayloadCache — worker did not inject WithPayloadCache(taskCtx, pc) before calling Plan")
	}
	if got != pc {
		t.Fatalf("planner saw cache %p, want engine-installed cache %p", got, pc)
	}

	// Drain task completion so deferred Stop doesn't race on a still-running task.
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("task did not complete within 5s")
	}
}

// TestWorker_NoEngine_NoCacheInjection verifies the degradation path:
// when the engine has no PayloadCache wired (test-only path, mirrors the
// fcCapturingPlanner pattern), the worker's `if w.engine != nil` guard
// runs but the inner `if pc := w.engine.PayloadCache(); pc != nil`
// check is false, so WithPayloadCache is NOT called. The planner then
// observes core.PayloadCacheFrom(ctx) == nil (NOT a panic). This is
// the intended degradation: planners must nil-check the cache before
// using it.
//
// Mirrors the TestProcessReplayTask_CallsPlanReplayWithFC pattern
// (replay_strategy_test.go) — drives the engine path but leaves
// SetPayloadCache unset so PayloadCache() returns nil.
func TestWorker_NoEngine_NoCacheInjection(t *testing.T) {
	stub := &cacheCapturingPlanner{called: make(chan struct{})}

	// Construct a ConfigWorker without an engine. We can't call
	// NewConfigWorker here from core_test (it's in package core), so we
	// drive the engine path with an engine that has no PayloadCache set.
	// This exercises the same code branch: w.engine != nil but
	// w.engine.PayloadCache() == nil → worker skips injection.
	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1,
		PacketWorkers: 1,
		OutputWorkers: 1,
		BufferSize:    32,
		QueueSize:     16,
	})
	e.RegisterPlanner(stub)
	e.SetBuildFunc(func(c core.PacketConfig) ([]byte, error) {
		return make([]byte, 0), nil
	})
	// Deliberately do NOT call SetPayloadCache — engine.PayloadCache()
	// returns nil, so the worker's inner guard skips injection.

	if err := e.Start(); err != nil {
		t.Fatalf("engine start: %v", err)
	}
	defer e.Stop()

	done := make(chan string, 1)
	e.OnTaskComplete = func(taskID string) { done <- taskID }

	task := core.Task{
		ID:       "pc-noengine-1",
		Name:     "pc-noengine-test",
		Protocol: "tcp",
		ClassID:  "pc-noengine-1",
		Spec:     core.FlowSpec{Count: 1},
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}

	select {
	case <-stub.called:
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("planner.Plan was never called within 5s")
	}

	got := stub.capturedCache()
	if got != nil {
		t.Fatalf("planner saw cache %p, want nil (engine has no PayloadCache — worker must skip injection)", got)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("task did not complete within 5s")
	}
}
