package replay

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/output"
)

// TestRealNIC_ReplayMode_SinglePort verifies the mode=replay single-protocol
// path (processReplayTask with fc!=nil) injects packets on a real NIC. Unlike
// TestRealNIC_SinglePort which uses the batch path, this test submits a Task
// with Mode="replay" (no Batch), exercising:
//   - processTask -> processReplayTask dispatch (not processBatchTask)
//   - fc construction (non-nil, FlowCounter nil since no flows ceiling)
//   - planner pacer routing (empty mode -> pacer nil, routes through engine)
//   - real NIC injection via the registered writer
// Gated on enp135s0f0np0 being openable (root/CAP_NET_RAW + NIC present).
func TestRealNIC_ReplayMode_SinglePort(t *testing.T) {
	const iface = "enp135s0f0np0"
	iw, err := output.NewInterfaceWriter(iface)
	if err != nil {
		t.Skipf("cannot open %s for injection (skipping NIC test): %v", iface, err)
	}
	defer iw.Close()

	_, db, assetID, _ := setupReplayAsset(t)
	e := core.NewEngine(core.EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, BufferSize: 256, QueueSize: 64})
	e.SetBuildFunc(NewBuildFunc(core.NewBuilder().Build))
	e.SetReplayPlanner(NewReplayPlanner(db))
	done := make(chan string, 1)
	e.OnTaskComplete = func(id string) { done <- id }
	e.OnTaskFailed = func(id, msg string) { t.Errorf("task failed: %s", msg); done <- id }
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	defer e.Stop()

	e.RegisterOutputWriter("tnic-replay", &nicWriter{w: iw})

	spec, _ := json.Marshal(ReplaySpec{
		PcapAssetID: assetID, Speed: ReplaySpeed{Mode: ""}, Direction: "single", ChecksumMode: "recompute",
		Rewrites: []RewriteRule{{Kind: "ipmap", Mapping: map[string]string{"10.0.0.1": "11.0.0.1"}}},
	})
	// mode=replay single-protocol task (no Batch, no Protocol planner).
	task := core.Task{
		ID:           "tnic-replay",
		Name:         "nic-replay-mode",
		UserID:       "u1",
		Mode:         "replay",
		Replay:       spec,
		ClassID:      "tnic-replay",
		ParentTaskID: "tnic-replay-parent",
		Interface:    iface,
		OutputMode:   "interface",
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("mode=replay did not complete in 5s")
	}

	stats := iw.Stats()
	if stats["packets_sent"].(int64) < 3 {
		t.Errorf("packets_sent = %v, want >= 3 (mode=replay path)", stats["packets_sent"])
	}
	if stats["errors"].(int64) > 0 {
		t.Errorf("injection errors = %v", stats["errors"])
	}
	t.Logf("NIC %s mode=replay injection: %d packets sent, %d errors",
		iface, stats["packets_sent"], stats["errors"])
}

// TestRealNIC_ReplayMode_OriginalSpeed verifies the mode=replay path with
// speed=original keeps the TimestampPacer attached (R4) and paces packets on a
// real NIC. The capture timestamps are 1ms apart, so 3 packets take ~2ms.
func TestRealNIC_ReplayMode_OriginalSpeed(t *testing.T) {
	const iface = "enp135s0f0np0"
	iw, err := output.NewInterfaceWriter(iface)
	if err != nil {
		t.Skipf("cannot open %s for injection (skipping NIC test): %v", iface, err)
	}
	defer iw.Close()

	_, db, assetID, _ := setupReplayAsset(t)
	e := core.NewEngine(core.EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, BufferSize: 256, QueueSize: 64})
	e.SetBuildFunc(NewBuildFunc(core.NewBuilder().Build))
	e.SetReplayPlanner(NewReplayPlanner(db))
	done := make(chan string, 1)
	e.OnTaskComplete = func(id string) { done <- id }
	e.OnTaskFailed = func(id, msg string) { t.Errorf("task failed: %s", msg); done <- id }
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	defer e.Stop()

	e.RegisterOutputWriter("tnic-orig", &nicWriter{w: iw})

	spec, _ := json.Marshal(ReplaySpec{
		PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "original"}, Direction: "single", ChecksumMode: "recompute",
	})
	task := core.Task{
		ID:           "tnic-orig",
		Name:         "nic-replay-orig",
		UserID:       "u1",
		Mode:         "replay",
		Replay:       spec,
		ClassID:      "tnic-orig",
		ParentTaskID: "tnic-orig-parent",
		Interface:    iface,
		OutputMode:   "interface",
	}
	start := time.Now()
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("mode=replay original did not complete in 5s")
	}
	elapsed := time.Since(start)

	stats := iw.Stats()
	if stats["packets_sent"].(int64) < 3 {
		t.Errorf("packets_sent = %v, want >= 3 (original speed mode)", stats["packets_sent"])
	}
	// Capture timestamps are 1000us, 2000us, 3000us. With multiplier=1, the
	// pacer sleeps ~2ms total (delta between first and last). Allow generous
	// slack for scheduler jitter. Just verify it didn't complete instantly
	// (which would mean pacer was dropped).
	if elapsed < 1*time.Millisecond {
		t.Errorf("elapsed = %v, want >= 1ms (TimestampPacer should pace)", elapsed)
	}
	t.Logf("NIC %s mode=replay original: %d packets in %v, %d errors",
		iface, stats["packets_sent"], elapsed, stats["errors"])
}
