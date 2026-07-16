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

// stubReplayPlanner is a ReplayPlanner double used by C1 tests. It optionally
// fails PlanReplay for a designated asset ID (simulating a missing asset).
type stubReplayPlanner struct {
	failAssetID string // if non-empty, PlanReplay returns an error when the spec's pcap_asset_id equals this
	failErr     error
	// packets emitted on success: emitted per PlanReplay call before closing the channel.
	packetsPerCall int
}

func (s *stubReplayPlanner) PlanReplay(ctx context.Context, specJSON json.RawMessage, taskID, classID, userID string, fc *ReplayFC) (<-chan PacketConfig, error) {
	var spec struct {
		PcapAssetID string `json:"pcap_asset_id"`
	}
	_ = json.Unmarshal(specJSON, &spec)
	if s.failAssetID != "" && spec.PcapAssetID == s.failAssetID {
		return nil, s.failErr
	}
	ch := make(chan PacketConfig, s.packetsPerCall)
	for i := 0; i < s.packetsPerCall; i++ {
		ch <- PacketConfig{ClassID: classID}
	}
	close(ch)
	return ch, nil
}

// TestAuditFix_ReplayFailureSurfaces (C1): when a replay class fails to plan
// (missing asset), processBatchTask must call onTaskDone with an error, not nil.
// Before the fix, totalFlows was 0 for replay classes so the "all flows failed"
// guard never fired and the task silently completed.
//
// This test drives processBatchTask directly via a ConfigWorker with a stub
// ReplayPlanner and observes the onTaskDone callback -- it does NOT compute
// totalFlows in the test body.
func TestAuditFix_ReplayFailureSurfaces(t *testing.T) {
	stubErr := errors.New("asset not found")
	planner := &stubReplayPlanner{failAssetID: "nonexistent", failErr: stubErr}

	taskChan := make(chan Task, 1)
	configChan := make(chan PacketConfig, 16)
	var wg sync.WaitGroup
	worker := NewConfigWorker(0, map[string]ProtocolPlanner{}, planner, taskChan, configChan, &wg, nil)

	var mu sync.Mutex
	var gotErr error
	var gotDone bool
	worker.SetOnTaskDone(func(taskID string, err error, count int64) {
		mu.Lock()
		defer mu.Unlock()
		gotErr = err
		gotDone = true
	})

	// Drain configChan so processBatchTask never blocks on send.
	drainDone := make(chan struct{})
	go func() {
		for range configChan {
		}
		close(drainDone)
	}()

	task := Task{
		ID:  "t1",
		Ctx: context.Background(),
		Batch: &BatchSpec{
			Classes: []TrafficClass{{
				ID:     "r1",
				Type:   "replay",
				Replay: json.RawMessage(`{"pcap_asset_id":"nonexistent","speed":{"mode":"max"}}`),
			}},
		},
	}
	worker.processBatchTask(task)

	close(configChan)
	<-drainDone

	mu.Lock()
	defer mu.Unlock()
	if !gotDone {
		t.Fatal("onTaskDone never fired")
	}
	if gotErr == nil {
		t.Fatal("C1 regression: pure-replay batch with failed planning reported nil error (would be 'completed' status). Want non-nil 'all flows failed' error.")
	}
	// The message should mention that all flows failed.
	if got := gotErr.Error(); !contains(got, "all") || !contains(got, "failed") {
		t.Errorf("error = %q, want message mentioning 'all ... failed'", got)
	}
}

// TestAuditFix_ReplayFailureInMixedBatch (C1 mixed): a mixed batch with 1 failed
// replay class + 1 succeeding synth class must still report success overall (
// totalFlows=1+N, flowFailures=1, 1 < 1+N so no "all failed" guard). The key
// invariant here is that the replay failure is counted (so a pure-replay batch
// reports failure), but does not mask a successful mixed batch.
func TestAuditFix_ReplayFailureInMixedBatch(t *testing.T) {
	stubErr := errors.New("asset not found")
	planner := &stubReplayPlanner{failAssetID: "missing", failErr: stubErr}
	stubProto := &stubProtocolPlanner{packetsPerFlow: 1}

	taskChan := make(chan Task, 1)
	configChan := make(chan PacketConfig, 64)
	var wg sync.WaitGroup
	worker := NewConfigWorker(0, map[string]ProtocolPlanner{"tcp": stubProto}, planner, taskChan, configChan, &wg, nil)

	var mu sync.Mutex
	var gotErr error
	worker.SetOnTaskDone(func(taskID string, err error, count int64) {
		mu.Lock()
		defer mu.Unlock()
		gotErr = err
	})

	drainDone := make(chan struct{})
	go func() {
		for range configChan {
		}
		close(drainDone)
	}()

	task := Task{
		ID:  "t2",
		Ctx: context.Background(),
		Batch: &BatchSpec{
			Classes: []TrafficClass{
				{ID: "r1", Type: "replay", Replay: json.RawMessage(`{"pcap_asset_id":"missing","speed":{"mode":"max"}}`)},
				{ID: "t1", Type: "tcp", FlowCount: 10},
			},
		},
	}
	worker.processBatchTask(task)
	close(configChan)
	<-drainDone

	mu.Lock()
	defer mu.Unlock()
	// mixed batch: 1 replay-fail + 10 synth-ok = 1 failure of 11 total. Not "all failed".
	if gotErr != nil {
		t.Errorf("mixed batch with 1 replay failure + 10 synth-ok reported error %v, want nil", gotErr)
	}
}

// TestAuditFix_ValidateReplaySpec (H7): invalid replay specs are rejected at
// submission time. Before the fix, only `len(c.Replay) == 0` was checked, so a
// bogus speed mode silently fell back to MaxPacer and dual-without-interface2
// was accepted.
func TestAuditFix_ValidateReplaySpec(t *testing.T) {
	cases := []struct {
		name    string
		replay  string
		wantErr bool
	}{
		{"valid original", `{"pcap_asset_id":"a1","speed":{"mode":"original"},"direction":"single"}`, false},
		{"valid multiplier", `{"pcap_asset_id":"a1","speed":{"mode":"multiplier","multiplier":2},"direction":"dual"}`, false},
		{"missing asset", `{"speed":{"mode":"original"}}`, true},
		{"bad speed mode", `{"pcap_asset_id":"a1","speed":{"mode":"warp9"}}`, true},
		{"bps no value", `{"pcap_asset_id":"a1","speed":{"mode":"bps"}}`, true},
		{"pps zero", `{"pcap_asset_id":"a1","speed":{"mode":"pps","pps":0}}`, true},
		{"bad direction", `{"pcap_asset_id":"a1","speed":{"mode":"original"},"direction":"triple"}`, true},
		{"bad checksum", `{"pcap_asset_id":"a1","speed":{"mode":"original"},"checksum_mode":"magic"}`, true},
		{"malformed json", `{not json`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			batch := &BatchSpec{
				Classes: []TrafficClass{{ID: "r1", Type: "replay", Replay: json.RawMessage(tc.replay)}},
			}
			err := ValidateBatchSpec(*batch)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %q, got nil", tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error for %q: %v", tc.name, err)
			}
		})
	}
}

// TestAuditFix_PacketWorkersCap (H6): when ReplayOrderPreserve is set, the
// engine caps PacketWorkers to 1 to preserve pcap file order. Before the fix,
// the default PacketWorkers=8 caused multi-worker parallelism to reorder
// packets on the output side.
func TestAuditFix_PacketWorkersCap(t *testing.T) {
	cfg := EngineConfig{
		ConfigWorkers:       1,
		PacketWorkers:       8,
		OutputWorkers:       1,
		BufferSize:          16,
		ReplayOrderPreserve: true,
	}
	e := NewEngine(cfg)
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer e.Stop()

	if got := len(e.packetWorkers); got != 1 {
		t.Errorf("with ReplayOrderPreserve=true, PacketWorkers=8 → engine created %d workers, want 1", got)
	}
}

// TestAuditFix_PacketWorkersUnrestricted (H6): without ReplayOrderPreserve,
// the engine honors PacketWorkers as configured. This guards against a fix that
// caps too aggressively.
func TestAuditFix_PacketWorkersUnrestricted(t *testing.T) {
	cfg := EngineConfig{
		ConfigWorkers:       1,
		PacketWorkers:       4,
		OutputWorkers:       1,
		BufferSize:          16,
		ReplayOrderPreserve: false,
	}
	e := NewEngine(cfg)
	if err := e.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer e.Stop()

	if got := len(e.packetWorkers); got != 4 {
		t.Errorf("without ReplayOrderPreserve, PacketWorkers=4 → engine created %d workers, want 4", got)
	}
}

// stubProtocolPlanner is a ProtocolPlanner double: Validate always succeeds and
// Plan emits packetsPerFlow configs on the returned channel.
type stubProtocolPlanner struct {
	packetsPerFlow int
	planErr        error
	callCount      int64
}

func (s *stubProtocolPlanner) Name() string { return "stub" }

func (s *stubProtocolPlanner) Validate(spec FlowSpec) error { return nil }

func (s *stubProtocolPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	atomic.AddInt64(&s.callCount, 1)
	if s.planErr != nil {
		return nil, s.planErr
	}
	ch := make(chan PacketConfig, s.packetsPerFlow)
	for i := 0; i < s.packetsPerFlow; i++ {
		ch <- PacketConfig{}
	}
	close(ch)
	return ch, nil
}

// contains reports whether substr is in s (case-insensitive comparison would
// require strings; we use a byte-level compare for simplicity).
func contains(s, substr string) bool {
	return len(substr) == 0 || (len(s) >= len(substr) && indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// _ = time.Now avoids "imported and not used" if the file is edited later to
// remove the last time reference.
var _ = time.Now
