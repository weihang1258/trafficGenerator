package core

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

// layerPlannerStub is a ProtocolPlanner stub recording the protocol name and
// layers JSON it was built from, then delegating planning to an inner planner.
// Used to verify the engine's per-task layer-planner dispatch without
// importing the layers package (layers imports core — tests here can't).
type layerPlannerStub struct {
	inner ProtocolPlanner
	proto string
	raw   json.RawMessage
	plans atomic.Int64
}

func (s *layerPlannerStub) Name() string { return s.proto }
func (s *layerPlannerStub) Validate(spec FlowSpec) error {
	return s.inner.Validate(spec)
}
func (s *layerPlannerStub) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	s.plans.Add(1)
	return s.inner.Plan(ctx, spec)
}

// fakeLayerFactory builds a layerPlannerStub wrapping the given protocol's
// registered planner, recording (protocol, layersJSON). Mirrors the server's
// wiring of layers.BuildLayersPlanner into SetLayerPlannerFactory. A nil entry
// (or absent key) makes the factory reject — the submission must fail.
func fakeLayerFactory(inner map[string]ProtocolPlanner) func(protocol string, layersJSON json.RawMessage) (ProtocolPlanner, error) {
	return func(protocol string, layersJSON json.RawMessage) (ProtocolPlanner, error) {
		p, ok := inner[protocol]
		if !ok || p == nil {
			return nil, fmt.Errorf("layers: no planner for protocol %q", protocol)
		}
		return &layerPlannerStub{inner: p, proto: protocol, raw: append(json.RawMessage(nil), layersJSON...)}, nil
	}
}

// TestSubmitTask_LayersDispatchesToPerTaskPlanner: a task carrying a "layers"
// config must dispatch to the per-task layer planner (built by the injected
// factory at SubmitTask), not the protocol-name planner (P2c 层链驱动生成).
func TestSubmitTask_LayersDispatchesToPerTaskPlanner(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 256,
	})
	base := &fixedPacketsPlanner{name: "tcp", perFlow: 2}
	e.RegisterPlanner(base)
	var built *layerPlannerStub
	e.SetLayerPlannerFactory(func(protocol string, layersJSON json.RawMessage) (ProtocolPlanner, error) {
		// Capture the built planner directly: the map entry is deleted at task
		// completion, so reading e.layerPlanners after waitTaskDone would race
		// the cleanup and prove nothing about dispatch.
		s := &layerPlannerStub{inner: base, proto: protocol, raw: append(json.RawMessage(nil), layersJSON...)}
		built = s
		return s, nil
	})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 100), nil })
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	layersJSON := json.RawMessage(`[{"tcp":{}}]`)
	if err := e.SubmitTask(Task{
		ID: "t1", Name: "layers-tcp", Protocol: "tcp",
		Spec: FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80},
		Layers: layersJSON,
	}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitTaskDone(t, e, "t1", 5*time.Second)

	// The per-task planner must have been built by the factory (layers JSON
	// preserved) and dispatched to (Plan called).
	if built == nil {
		t.Fatal("layer planner factory not invoked")
	}
	if string(built.raw) != string(layersJSON) {
		t.Errorf("factory got layers %s, want %s", built.raw, layersJSON)
	}
	if built.plans.Load() == 0 {
		t.Errorf("per-task layer planner never dispatched (Plan not called)")
	}
	if base.FlowsRun() == 0 {
		t.Errorf("inner planner never planned")
	}
}

// TestSubmitTask_LayersFactoryErrorFailsSubmission: a layers config the
// factory rejects must fail the submission (task never enqueued) — not
// silently generate an empty flow.
func TestSubmitTask_LayersFactoryErrorFailsSubmission(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 256,
	})
	e.RegisterPlanner(&fixedPacketsPlanner{name: "tcp", perFlow: 2})
	e.SetLayerPlannerFactory(fakeLayerFactory(map[string]ProtocolPlanner{"tcp": nil})) // stub always errors
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 100), nil })
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	err := e.SubmitTask(Task{
		ID: "t1", Name: "bad-layers", Protocol: "tcp",
		Spec: FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80},
		Layers: json.RawMessage(`[{"bogus":{}}]`),
	})
	if err == nil {
		t.Fatal("expected submit error for layers factory failure")
	}
	if _, err2 := e.GetTaskStatus("t1"); err2 == nil {
		t.Error("failed layers task leaked into task store")
	}
}

// TestSubmitTask_LayersFactoryNilErrors: submitting a layers task while no
// factory is wired (e.g. a unit-test engine) must error, not panic.
func TestSubmitTask_LayersFactoryNilErrors(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 256,
	})
	e.RegisterPlanner(&fixedPacketsPlanner{name: "tcp", perFlow: 2})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 100), nil })
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	err := e.SubmitTask(Task{
		ID: "t1", Name: "no-factory", Protocol: "tcp",
		Spec: FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80},
		Layers: json.RawMessage(`[{"tcp":{}}]`),
	})
	if err == nil {
		t.Fatal("expected error when layer planner factory is not wired")
	}
	if _, err2 := e.GetTaskStatus("t1"); err2 == nil {
		t.Error("failed layers task leaked into task store")
	}
}

// TestSubmitTask_LayersNoFactoryEntry: without a layers config, the worker
// must dispatch to the protocol-name planner (legacy path regression).
func TestSubmitTask_LayersNoFactoryEntry(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 256,
	})
	base := &fixedPacketsPlanner{name: "tcp", perFlow: 2}
	e.RegisterPlanner(base)
	e.SetLayerPlannerFactory(fakeLayerFactory(map[string]ProtocolPlanner{"tcp": base}))
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 100), nil })
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	if err := e.SubmitTask(Task{
		ID: "t1", Name: "plain", Protocol: "tcp",
		Spec: FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80},
	}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitTaskDone(t, e, "t1", 5*time.Second)
	if base.FlowsRun() == 0 {
		t.Errorf("protocol-name planner never dispatched for a layers-less task")
	}
}

// TestSubmitTask_LayersCleanupOnCompletion: the per-task planner entry must be
// removed when the task completes (no map leak across tasks).
func TestSubmitTask_LayersCleanupOnCompletion(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 256,
	})
	base := &fixedPacketsPlanner{name: "tcp", perFlow: 1}
	e.RegisterPlanner(base)
	e.SetLayerPlannerFactory(fakeLayerFactory(map[string]ProtocolPlanner{"tcp": base}))
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 100), nil })
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	if err := e.SubmitTask(Task{
		ID: "t1", Name: "layers-cleanup", Protocol: "tcp",
		Spec: FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80},
		Layers: json.RawMessage(`[{"tcp":{}}]`),
	}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	waitTaskDone(t, e, "t1", 5*time.Second)

	e.taskMu.RLock()
	_, leaked := e.layerPlanners["t1"]
	e.taskMu.RUnlock()
	if leaked {
		t.Error("layer planner entry leaked after task completion")
	}
}

// TestSubmitTask_LayersCleanupOnFailedSubmit: a layers task whose submission
// fails after the planner was registered (engine stopped between the running
// check and the channel send) must not leak the layerPlanners entry.
func TestSubmitTask_LayersCleanupOnFailedSubmit(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 256,
	})
	base := &fixedPacketsPlanner{name: "tcp", perFlow: 1}
	e.RegisterPlanner(base)
	e.SetLayerPlannerFactory(fakeLayerFactory(map[string]ProtocolPlanner{"tcp": base}))
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 100), nil })
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	// Stop the engine after SubmitTask begins but before the channel send:
	// the channel guard must fail the submission and clean up the planner
	// entry. The workers already hold their own taskChan copy, so nilling the
	// engine's field makes the guard trip deterministically (a closed stopChan
	// would race the live worker for the task instead).
	e.taskChan = nil
	e.stopChan = make(chan struct{})
	close(e.stopChan)
	e.running.Store(true)

	err := e.SubmitTask(Task{
		ID: "t1", Name: "layers-failed-submit", Protocol: "tcp",
		Spec: FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 80},
		Layers: json.RawMessage(`[{"tcp":{}}]`),
	})
	if err == nil {
		t.Fatal("expected submit error on closed task channel")
	}
	e.taskMu.RLock()
	_, leaked := e.layerPlanners["t1"]
	_, storeLeak := e.taskStore["t1"]
	e.taskMu.RUnlock()
	if leaked {
		t.Error("layer planner entry leaked after failed submit")
	}
	if storeLeak {
		t.Error("taskStore entry leaked after failed submit")
	}
}
