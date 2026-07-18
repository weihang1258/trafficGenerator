package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestProcessTaskRoutesSameFlowToSameShard verifies that all packets of one
// flow (same group_id) land on exactly one shard when using multiple
// PacketWorkers. This is the core ordering guarantee (spec §3.4 invariant 1).
func TestProcessTaskRoutesSameFlowToSameShard(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 4, OutputWorkers: 1,
		BufferSize: 1000, QueueSize: 100,
	})
	e.RegisterPlanner(&stubShardPlanner{name: "stub", packetsPerFlow: 20})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	spec := FlowSpec{
		Count:   1,
		GroupID: &StrategyConfig{Strategy: "fixed", Value: "call-A"},
	}
	task := Task{
		ID: "task1", Protocol: "stub", Spec: spec,
		Ctx: context.Background(),
	}
	e.taskChan <- task

	// Wait for ConfigWorker to process the task and push all packets
	time.Sleep(200 * time.Millisecond)

	// All 20 packets should land on exactly one shard
	nonZero := 0
	var totalPackets int64
	for i := range e.shardCounts {
		c := e.shardCounts[i].Load()
		totalPackets += c
		if c > 0 {
			nonZero++
		}
	}
	if totalPackets != 20 {
		t.Fatalf("total packets = %d, want 20", totalPackets)
	}
	if nonZero != 1 {
		t.Fatalf("expected all packets in 1 shard, got %d shards non-zero", nonZero)
	}
}

// TestProcessTaskDifferentGroupsSpreadAcrossShards verifies that flows with
// different group_ids spread across multiple shards (no false coalescing).
func TestProcessTaskDifferentGroupsSpreadAcrossShards(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 4, OutputWorkers: 1,
		BufferSize: 1000, QueueSize: 100,
	})
	e.RegisterPlanner(&stubShardPlanner{name: "stub", packetsPerFlow: 5})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	// Submit 20 tasks with different fixed group_ids -- should spread across 4 shards
	for i := 0; i < 20; i++ {
		spec := FlowSpec{
			Count:   1,
			GroupID: &StrategyConfig{Strategy: "fixed", Value: "g-" + string(rune('A'+i))},
		}
		task := Task{
			ID: "task-" + string(rune('A'+i)), Protocol: "stub", Spec: spec,
			Ctx: context.Background(),
		}
		e.taskChan <- task
	}

	time.Sleep(500 * time.Millisecond)

	nonZero := 0
	for i := range e.shardCounts {
		if e.shardCounts[i].Load() > 0 {
			nonZero++
		}
	}
	// With 20 distinct group_ids and 4 shards, we expect >1 shard to be used.
	// (Hash distribution might not hit all 4, but should hit >= 2.)
	if nonZero < 2 {
		t.Fatalf("expected >=2 shards used for 20 distinct group_ids, got %d", nonZero)
	}
}

// TestProcessTaskFallbackTo4Tuple verifies that without group_id, packets
// route by unordered 4-tuple hash (single-flow ordering).
func TestProcessTaskFallbackTo4Tuple(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 4, OutputWorkers: 1,
		BufferSize: 1000, QueueSize: 100,
	})
	e.RegisterPlanner(&stubShardPlanner{name: "stub", packetsPerFlow: 10})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	// No group_id -- should fall back to 4-tuple
	spec := FlowSpec{
		Count:    1,
		SrcIP:    "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 1000, DstPort: 80,
	}
	task := Task{ID: "task1", Protocol: "stub", Spec: spec, Ctx: context.Background()}
	e.taskChan <- task

	time.Sleep(200 * time.Millisecond)

	nonZero := 0
	for i := range e.shardCounts {
		if e.shardCounts[i].Load() > 0 {
			nonZero++
		}
	}
	if nonZero != 1 {
		t.Fatalf("fallback 4-tuple: expected 1 shard, got %d", nonZero)
	}
}

// stubShardPlanner emits N packets for a single flow. Used to verify routing
// without depending on real protocol planners.
type stubShardPlanner struct {
	name           string
	packetsPerFlow int
}

func (s *stubShardPlanner) Name() string { return s.name }
func (s *stubShardPlanner) Validate(spec FlowSpec) error { return nil }
func (s *stubShardPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	ch := make(chan PacketConfig, s.packetsPerFlow)
	go func() {
		defer close(ch)
		for i := 0; i < s.packetsPerFlow; i++ {
			ch <- PacketConfig{
				FlowID:      "test-flow",
				PacketIndex: uint64(i),
			}
		}
	}()
	return ch, nil
}

// keep atomic import used
var _ = atomic.AddInt64
