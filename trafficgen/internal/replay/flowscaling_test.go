package replay

import (
	"context"
	"net"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestGenerateClones_Inc verifies inc-strategy clones get incrementing IPs.
func TestGenerateClones_Inc(t *testing.T) {
	fs := &FlowScaling{
		Count:  3,
		SrcIP:  core.StrategyConfig{Strategy: "inc", Range: []interface{}{"11.0.0.1", "11.0.0.100"}, Step: 1},
		DstIP:  core.StrategyConfig{Strategy: "fixed", Value: "22.0.0.1"},
		SeqOffset: core.StrategyConfig{Strategy: "random", Range: []interface{}{"0", "4294967295"}, Seed: 42},
	}
	clones, err := generateClones(fs)
	if err != nil {
		t.Fatalf("generateClones: %v", err)
	}
	if len(clones) != 3 {
		t.Fatalf("clones = %d, want 3", len(clones))
	}
	want := []string{"11.0.0.1", "11.0.0.2", "11.0.0.3"}
	for i, c := range clones {
		if c.SrcIP != want[i] {
			t.Errorf("clone %d SrcIP = %s, want %s", i, c.SrcIP, want[i])
		}
		if c.DstIP != "22.0.0.1" {
			t.Errorf("clone %d DstIP = %s, want 22.0.0.1", i, c.DstIP)
		}
	}
	// Seq offsets should be non-zero (random) and differ across clones.
	if clones[0].SeqOffset == clones[1].SeqOffset {
		t.Errorf("seq offsets should differ: %d vs %d", clones[0].SeqOffset, clones[1].SeqOffset)
	}
}

// TestClonePatches verifies clonePatches produces IP/port patches at the right offsets.
func TestClonePatches(t *testing.T) {
	layout := testLayout(t)
	c := Clone{SrcIP: "11.0.0.1", DstPort: 443}
	patches := clonePatches(c, layout)
	foundSrc, foundPort := false, false
	for _, p := range patches {
		if p.Field == "src_ip" && p.Offset == layout.SrcIP {
			if net.IP(p.Bytes).Equal(net.ParseIP("11.0.0.1").To4()) {
				foundSrc = true
			}
		}
		if p.Field == "dst_port" && p.Offset == layout.DstPort {
			foundPort = true
		}
	}
	if !foundSrc {
		t.Error("no src_ip patch")
	}
	if !foundPort {
		t.Error("no dst_port patch")
	}
}

// TestCheckFlowScalingConflict verifies a field rule + FlowScaling on the same
// field errors, but mapping + FlowScaling is allowed.
func TestCheckFlowScalingConflict(t *testing.T) {
	fs := &FlowScaling{SrcIP: core.StrategyConfig{Strategy: "inc", Range: []interface{}{"11.0.0.1", "11.0.0.10"}}}
	// Field rule on src_ip + FlowScaling src_ip -> conflict.
	err := checkFlowScalingConflict(fs, []RewriteRule{{Kind: "field", Target: "src_ip"}})
	if err == nil {
		t.Error("expected conflict (field + flowscaling same field)")
	}
	// Mapping rule + FlowScaling -> allowed (no conflict).
	err = checkFlowScalingConflict(fs, []RewriteRule{{Kind: "ipmap", Mapping: map[string]string{"1.0.0.1": "11.0.0.1"}}})
	if err != nil {
		t.Errorf("mapping + flowscaling should be allowed: %v", err)
	}
}

// TestPlanner_FlowScaling verifies the planner emits N configs per packet with
// distinct clone IPs.
func TestPlanner_FlowScaling(t *testing.T) {
	planner, _, assetID, _ := setupReplayAsset(t)
	spec := ReplaySpec{
		PcapAssetID: assetID,
		Speed:       ReplaySpeed{Mode: "max"},
		Direction:   "single",
		FlowScaling: &FlowScaling{
			Count: 2,
			SrcIP: core.StrategyConfig{Strategy: "inc", Range: []interface{}{"11.0.0.1", "11.0.0.10"}, Step: 1},
			DstIP: core.StrategyConfig{Strategy: "fixed", Value: "22.0.0.1"},
		},
	}
	ch, err := planner.Plan(context.Background(), spec, "t", "c", "u1")
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var configs []core.PacketConfig
	for cfg := range ch {
		configs = append(configs, cfg)
	}
	// 3 original packets * 2 clones = 6 configs.
	if len(configs) != 6 {
		t.Fatalf("configs = %d, want 6 (3 packets x 2 clones)", len(configs))
	}
	// Clone 0 (configs 0,2,4) should have src_ip=11.0.0.1; clone 1 (1,3,5) =11.0.0.2.
	for i, cfg := range configs {
		patches := cfg.Metadata["_patches"].([]Patch)
		var srcIP string
		for _, p := range patches {
			if p.Field == "src_ip" {
				srcIP = net.IP(p.Bytes).String()
			}
		}
		wantIP := "11.0.0.1"
		if i%2 == 1 {
			wantIP = "11.0.0.2"
		}
		if srcIP != wantIP {
			t.Errorf("config %d (clone %d) src_ip = %s, want %s", i, i%2, srcIP, wantIP)
		}
	}
}
