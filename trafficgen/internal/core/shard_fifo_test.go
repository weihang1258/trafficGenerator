package core

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// TestSameFlowPacketsArriveInFIFOOrder verifies that packets of one flow
// (same group_id) arrive at PacketWorker in strict PacketIndex order — the
// core ordering guarantee (spec §3.4 invariant 3). Captures packets at the
// PacketWorker input via a custom buildFunc that records indices.
func TestSameFlowPacketsArriveInFIFOOrder(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 4, OutputWorkers: 1,
		BufferSize: 1000, QueueSize: 100,
	})
	e.RegisterPlanner(&fifoStubPlanner{packetsPerFlow: 50})

	var mu sync.Mutex
	var seen []uint64
	e.buildFunc = func(c PacketConfig) ([]byte, error) {
		mu.Lock()
		seen = append(seen, c.PacketIndex)
		mu.Unlock()
		return []byte{0}, nil
	}

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	spec := FlowSpec{
		Count:   1,
		GroupID: &StrategyConfig{Strategy: "fixed", Value: "call-A"},
	}
	task := Task{ID: "task1", Protocol: "stub", Spec: spec, Ctx: context.Background()}
	e.taskChan <- task

	time.Sleep(300 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 50 {
		t.Fatalf("captured %d packets, want 50", len(seen))
	}
	for i, idx := range seen {
		if idx != uint64(i) {
			t.Fatalf("FIFO violation at position %d: got PacketIndex=%d, want %d", i, idx, i)
		}
	}
}

// TestClassLevelGroupIDPropagated verifies that TrafficClass.GroupID (the
// struct field) is propagated to spec.GroupID in processBatchTask, taking
// precedence over config-map group_id (review finding L2).
func TestClassLevelGroupIDPropagated(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 4, OutputWorkers: 1,
		BufferSize: 1000, QueueSize: 100,
	})
	e.RegisterPlanner(&fifoStubPlanner{packetsPerFlow: 5})

	// Capture the gID that reaches the worker via buildFunc
	var mu sync.Mutex
	var seenGID string
	e.buildFunc = func(c PacketConfig) ([]byte, error) {
		mu.Lock()
		if g, ok := c.Metadata["group_id"].(string); ok {
			seenGID = g
		}
		mu.Unlock()
		return []byte{0}, nil
	}

	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	// Batch with class-level GroupID (NOT in config map)
	task := Task{
		ID: "task1",
		Batch: &BatchSpec{
			Classes: []TrafficClass{
				{
					ID:        "c1",
					Type:      "stub",
					FlowCount: 1,
					GroupID:   &StrategyConfig{Strategy: "fixed", Value: "from-class-field"},
				},
			},
		},
		Ctx: context.Background(),
	}
	e.taskChan <- task

	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if seenGID != "from-class-field" {
		t.Fatalf("seenGID = %q, want 'from-class-field' (class-level GroupID must propagate)", seenGID)
	}
}

// TestHotGIDTriggersImbalanceWarn verifies that submitting group_id=fixed "all"
// (all flows bind to one gID) actually triggers the WARN via the real pipeline
// (review finding G6 — not just synthetic shardCounts manipulation).
func TestHotGIDTriggersImbalanceWarn(t *testing.T) {
	var buf hotGIDBuffer
	encoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	core := zapcore.NewCore(encoder, zapcore.AddSync(&buf), zapcore.DebugLevel)
	logger := zap.New(core)
	zap.ReplaceGlobals(logger)

	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 4, OutputWorkers: 1,
		BufferSize: 1000, QueueSize: 100,
	})
	e.RegisterPlanner(&fifoStubPlanner{packetsPerFlow: 10})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	// Submit 20 flows all with the same group_id "all" — should all land on
	// one shard, triggering imbalance WARN on the next monitor tick.
	for i := 0; i < 20; i++ {
		spec := FlowSpec{
			Count:   1,
			GroupID: &StrategyConfig{Strategy: "fixed", Value: "all"},
		}
		task := Task{
			ID: "hot-task-" + strconv.Itoa(i), Protocol: "stub", Spec: spec,
			Ctx: context.Background(),
		}
		e.taskChan <- task
	}

	// Wait for packets to land + monitor tick (10s is too long for a test;
	// trigger checkShardBalance manually after packets land)
	time.Sleep(500 * time.Millisecond)
	e.checkShardBalance()

	time.Sleep(50 * time.Millisecond)
	out := buf.String()
	if strings.Contains(out, "shard load imbalance") {
		return // PASS
	}
	t.Fatalf("expected WARN for hot gID 'all' (all flows on 1 shard), got: %s", out)
}

// fifoStubPlanner emits N packets with PacketIndex 0..N-1 for one flow.
type fifoStubPlanner struct {
	packetsPerFlow int
}

func (s *fifoStubPlanner) Name() string { return "stub" }
func (s *fifoStubPlanner) Validate(spec FlowSpec) error { return nil }
func (s *fifoStubPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	ch := make(chan PacketConfig, s.packetsPerFlow)
	go func() {
		defer close(ch)
		for i := 0; i < s.packetsPerFlow; i++ {
			ch <- PacketConfig{
				FlowID:      "fifo-flow",
				PacketIndex: uint64(i),
			}
		}
	}()
	return ch, nil
}

type hotGIDBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *hotGIDBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *hotGIDBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}
