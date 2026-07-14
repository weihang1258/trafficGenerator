package replay

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/output"
)

// nicWriter adapts output.InterfaceWriter to core.PacketWriter for the NIC test.
type nicWriter struct{ w *output.InterfaceWriter }

func (nw *nicWriter) WritePackets(p [][]byte) error { return nw.w.Write(p) }
func (nw *nicWriter) Close() error                  { return nw.w.Close() }

// TestRealNIC_SinglePort injects replayed packets on enp135s0f0np0 and verifies
// the injection path succeeds (packets sent, no errors). Gated on the NIC being
// openable (root/CAP_NET_RAW + NIC present).
func TestRealNIC_SinglePort(t *testing.T) {
	const iface = "enp135s0f0np0"
	iw, err := output.NewInterfaceWriter(iface)
	if err != nil {
		t.Skipf("cannot open %s for injection (skipping NIC test): %v", iface, err)
	}
	defer iw.Close()

	// Build a small replay asset (3 TCP packets) + engine.
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

	// Register the NIC writer for the task (single-port).
	e.RegisterOutputWriter("tnic", &nicWriter{w: iw})

	spec, _ := json.Marshal(ReplaySpec{
		PcapAssetID: assetID, Speed: ReplaySpeed{Mode: "max"}, Direction: "single", ChecksumMode: "recompute",
		Rewrites: []RewriteRule{{Kind: "ipmap", Mapping: map[string]string{"10.0.0.1": "11.0.0.1"}}},
	})
	task := core.Task{ID: "tnic", Name: "nic-replay", UserID: "u1", Protocol: "batch",
		Batch: &core.BatchSpec{Classes: []core.TrafficClass{{ID: "r", Type: "replay", Replay: spec}}}}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("replay did not complete in 5s")
	}

	stats := iw.Stats()
	if stats["packets_sent"].(int64) < 3 {
		t.Errorf("packets_sent = %v, want >= 3", stats["packets_sent"])
	}
	if stats["errors"].(int64) > 0 {
		t.Errorf("injection errors = %v", stats["errors"])
	}
	t.Logf("NIC %s injection: %d packets sent, %d errors", iface, stats["packets_sent"], stats["errors"])
	_ = context.Background
}
