package replay

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// capturingWriter collects all packets written, for verification.
type capturingWriter struct {
	mu      sync.Mutex
	packets [][]byte
}

func (w *capturingWriter) WritePackets(p [][]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.packets = append(w.packets, p...)
	return nil
}
func (w *capturingWriter) Close() error { return nil }

// TestReplay_E2E_IPMap verifies an end-to-end replay: a batch task with a
// replay class runs through the engine, the buildFunc dispatches to the
// rewriter, and the output packets have the rewritten IP.
func TestReplay_E2E_IPMap(t *testing.T) {
	_, db, assetID, _ := setupReplayAsset(t)

	// Engine with replay buildFunc + planner.
	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 256, QueueSize: 64,
	})
	e.SetBuildFunc(NewBuildFunc(core.NewBuilder().Build))
	e.SetReplayPlanner(NewReplayPlanner(db))

	done := make(chan string, 1)
	e.OnTaskComplete = func(taskID string) { done <- taskID }
	e.OnTaskFailed = func(taskID, msg string) { t.Errorf("task failed: %s", msg); done <- taskID }

	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	defer e.Stop()

	// Capturing output writer for the task.
	cw := &capturingWriter{}
	e.RegisterOutputWriter("t1", cw)

	// Batch task with one replay class (ipmap 10.0.0.1 -> 11.0.0.1).
	replaySpec, _ := json.Marshal(ReplaySpec{
		PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "max"}, Direction: "single", ChecksumMode: "recompute",
		Rewrites: []RewriteRule{{Kind: "ipmap", Mapping: map[string]string{"10.0.0.1": "11.0.0.1"}}},
	})
	task := core.Task{
		ID: "t1", Name: "replay-e2e",
			UserID: "u1", Protocol: "batch",
		Batch: &core.BatchSpec{
			Classes: []core.TrafficClass{{ID: "r1", Type: "replay", Replay: replaySpec}},
		},
		OutputMode: "pcap",
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Wait for completion via the callback (avoids polling GetTaskStatus which
	// returns a shared pointer raced by OnPacketWritten).
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("task did not complete in 5s")
	}

	cw.mu.Lock()
	defer cw.mu.Unlock()
	if len(cw.packets) != 3 {
		t.Fatalf("captured packets = %d, want 3", len(cw.packets))
	}
	// Each output packet should have src_ip = 11.0.0.1 (rewritten from 10.0.0.1).
	// The src_ip offset is 26 for a standard Eth+IPv4 frame.
	for i, p := range cw.packets {
		if len(p) < 30 {
			t.Errorf("packet %d too short: %d bytes", i, len(p))
			continue
		}
		gotIP := string(p[26:30])
		wantIP := string([]byte{11, 0, 0, 1})
		if gotIP != wantIP {
			t.Errorf("packet %d src_ip = %x, want %x (11.0.0.1)", i, p[26:30], []byte{11, 0, 0, 1})
		}
	}
	_ = context.Background
}
