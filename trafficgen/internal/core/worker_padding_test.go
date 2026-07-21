package core

import (
	"context"
	"hash/maphash"
	"sync"
	"sync/atomic"
	"testing"
)

// TestProcessBatchTask_PadMinFrame_Propagation verifies that processBatchTask
// (worker.go:434) propagates spec.PadMinFrame to config.L2.Pad for each emitted
// packet. This is the batch-path counterpart to the single-task propagation
// covered by TestMCP_GenerateTraffic_PadMinFrame_* (which exercises
// processTask via the MCP generate_traffic surface).
//
// Why a separate test: the batch path (processBatchTask) and single-task path
// (processTask) each have their OWN copy of the propagation logic (worker.go
// lines 273-278 and 602-606). A regression in one copy would not be caught by
// tests that only exercise the other. Per CLAUDE.md Testing Policy §3 ("If a
// method/branch exists, it needs a test that exercises it"), both paths need
// direct coverage.
//
// Three states are tested, mirroring the MCP E2E tests:
//   - absent:  spec.PadMinFrame=nil    -> config.L2.Pad stays nil (builder defaults ON)
//   - false:   spec.PadMinFrame=*false -> config.L2.Pad=*false (builder skips padding)
//   - true:    spec.PadMinFrame=*true  -> config.L2.Pad=*true  (builder pads)
//
// We use stubProtocolPlanner (already defined in audit_fixes_test.go) which
// emits bare PacketConfig{} with L2.Pad=nil - the same state real planners
// leave L2.Pad in. The worker's propagation is the only path that can set
// L2.Pad, so this test directly verifies it.
func TestProcessBatchTask_PadMinFrame_Propagation(t *testing.T) {
	cases := []struct {
		name    string
		padSet  bool // whether to include pad_min_frame in class config
		padVal  bool // value when padSet=true
		wantNil bool // expected: config.L2.Pad == nil
		wantPad bool // expected: *config.L2.Pad when not nil
	}{
		{"absent", false, false, true, false},
		{"explicit_false", true, false, false, false},
		{"explicit_true", true, true, false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// stubProtocolPlanner emits bare PacketConfig{} (L2.Pad=nil).
			// This matches what real planners do: they leave L2.Pad nil
			// and rely on the worker to propagate spec.PadMinFrame.
			stub := &stubProtocolPlanner{packetsPerFlow: 2}
			planners := map[string]ProtocolPlanner{"stub": stub}

			taskChan := make(chan Task, 1)
			configChan := make(chan PacketConfig, 64)
			var wg sync.WaitGroup
			e := NewEngine(EngineConfig{PacketWorkers: 1, QueueSize: 64})
			e.shardedConfigChan = []chan PacketConfig{configChan}
			e.shardCounts = make([]atomic.Int64, 1)
			e.shardSeed = maphash.MakeSeed()
			worker := NewConfigWorker(0, planners, nil, taskChan, &wg, e)

			worker.SetOnTaskDone(func(taskID string, err error, count int64) {
				if err != nil {
					t.Errorf("onTaskDone err: %v", err)
				}
			})

			// Drain configChan so processBatchTask never blocks on send.
			var captured []PacketConfig
			var captureMu sync.Mutex
			drainDone := make(chan struct{})
			go func() {
				for cfg := range configChan {
					captureMu.Lock()
					captured = append(captured, cfg)
					captureMu.Unlock()
				}
				close(drainDone)
			}()

			classConfig := map[string]interface{}{
				"src_ip": "192.0.2.1",
				"dst_ip": "192.0.2.2",
			}
			if tc.padSet {
				classConfig["pad_min_frame"] = tc.padVal
			}

			task := Task{
				ID:  "batch-pad-" + tc.name,
				Ctx: context.Background(),
				Batch: &BatchSpec{
					Classes: []TrafficClass{{
						ID:        "c1",
						Type:      "stub",
						FlowCount: 1,
						Config:    classConfig,
					}},
				},
			}
			worker.processBatchTask(task)

			close(configChan)
			<-drainDone

			captureMu.Lock()
			defer captureMu.Unlock()
			if len(captured) == 0 {
				t.Fatal("no packets emitted from processBatchTask")
			}
			for i, cfg := range captured {
				if tc.wantNil {
					if cfg.L2.Pad != nil {
						t.Errorf("frame[%d] L2.Pad=%v, want nil (absent -> default ON via builder)", i, *cfg.L2.Pad)
					}
				} else {
					if cfg.L2.Pad == nil {
						t.Fatalf("frame[%d] L2.Pad=nil, want *%v (worker failed to propagate spec.PadMinFrame)", i, tc.wantPad)
					}
					if *cfg.L2.Pad != tc.wantPad {
						t.Errorf("frame[%d] *L2.Pad=%v, want %v", i, *cfg.L2.Pad, tc.wantPad)
					}
				}
			}
		})
	}
}

// TestProcessBatchTask_PadMinFrame_NoClobberPlannerPreset verifies that the
// worker's `if config.L2.Pad == nil` guard works in the batch path: if a
// planner emits a packet with L2.Pad already set, the worker must NOT
// overwrite it with spec.PadMinFrame. This is the batch-path counterpart to
// the single-task path's guard (worker.go:276).
//
// Uses presetPadPlanner (defined below) which emits L2.Pad=*true, then runs
// processBatchTask with pad_min_frame=false in the class config. Emitted
// configs must have L2.Pad=*true (planner wins), not *false (worker's spec).
func TestProcessBatchTask_PadMinFrame_NoClobberPlannerPreset(t *testing.T) {
	planners := map[string]ProtocolPlanner{"preset": &presetPadPlanner{pad: true}}
	taskChan := make(chan Task, 1)
	configChan := make(chan PacketConfig, 64)
	var wg sync.WaitGroup
	e := NewEngine(EngineConfig{PacketWorkers: 1, QueueSize: 64})
	e.shardedConfigChan = []chan PacketConfig{configChan}
	e.shardCounts = make([]atomic.Int64, 1)
	e.shardSeed = maphash.MakeSeed()
	worker := NewConfigWorker(0, planners, nil, taskChan, &wg, e)

	var captured []PacketConfig
	var captureMu sync.Mutex
	drainDone := make(chan struct{})
	go func() {
		for cfg := range configChan {
			captureMu.Lock()
			captured = append(captured, cfg)
			captureMu.Unlock()
		}
		close(drainDone)
	}()

	task := Task{
		ID:  "batch-noclobber",
		Ctx: context.Background(),
		Batch: &BatchSpec{
			Classes: []TrafficClass{{
				ID:        "c1",
				Type:      "preset",
				FlowCount: 1,
				Config: map[string]interface{}{
					"pad_min_frame": false, // conflicts with planner's preset *true
				},
			}},
		},
	}
	worker.processBatchTask(task)
	close(configChan)
	<-drainDone

	captureMu.Lock()
	defer captureMu.Unlock()
	if len(captured) == 0 {
		t.Fatal("no packets emitted")
	}
	for i, cfg := range captured {
		if cfg.L2.Pad == nil {
			t.Fatalf("frame[%d] L2.Pad=nil, want *true (planner preset)", i)
		}
		if *cfg.L2.Pad != true {
			t.Errorf("frame[%d] *L2.Pad=%v, want true (planner preset must NOT be clobbered by worker)", i, *cfg.L2.Pad)
		}
	}
}

// presetPadPlanner is a ProtocolPlanner that emits one packet with L2.Pad
// pre-set to a fixed value. Used to verify the worker's no-clobber guard.
type presetPadPlanner struct {
	pad bool
}

func (p *presetPadPlanner) Name() string                      { return "preset" }
func (p *presetPadPlanner) Validate(spec FlowSpec) error       { return nil }
func (p *presetPadPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	pad := p.pad
	ch := make(chan PacketConfig, 1)
	ch <- PacketConfig{L2: L2Config{Pad: &pad}}
	close(ch)
	return ch, nil
}
