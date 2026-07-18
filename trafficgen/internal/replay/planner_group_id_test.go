package replay

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestComputeReplayGroupID_ExplicitFixed(t *testing.T) {
	spec := ReplaySpec{
		GroupID: &core.StrategyConfig{Strategy: "fixed", Value: "call-A"},
	}
	g := computeReplayGroupID(spec, "task1", "class1", 0)
	if g != "call-A" {
		t.Fatalf("gID = %q, want call-A", g)
	}
}

func TestComputeReplayGroupID_ImplicitNoFlowScaling(t *testing.T) {
	spec := ReplaySpec{}
	g := computeReplayGroupID(spec, "task1", "class1", 0)
	if g != "task1:class1" {
		t.Fatalf("gID = %q, want task1:class1", g)
	}
}

func TestComputeReplayGroupID_ImplicitWithFlowScaling(t *testing.T) {
	spec := ReplaySpec{
		FlowScaling: &FlowScaling{Count: 3},
	}
	g0 := computeReplayGroupID(spec, "task1", "class1", 0)
	g1 := computeReplayGroupID(spec, "task1", "class1", 1)
	if g0 != "task1:class1:0" || g1 != "task1:class1:1" {
		t.Fatalf("g0=%q g1=%q, want task1:class1:0/1", g0, g1)
	}
}

func TestComputeReplayGroupID_PatternStrategy(t *testing.T) {
	spec := ReplaySpec{
		GroupID: &core.StrategyConfig{
			Strategy: "pattern",
			Pattern:  "call-{n}",
			Range:    []interface{}{1, 100},
		},
	}
	g0 := computeReplayGroupID(spec, "task1", "class1", 0)
	g7 := computeReplayGroupID(spec, "task1", "class1", 7)
	if g0 != "call-1" || g7 != "call-8" {
		t.Fatalf("g0=%q g7=%q, want call-1/call-8", g0, g7)
	}
}

func TestComputeReplayGroupID_IncStrategy(t *testing.T) {
	spec := ReplaySpec{
		GroupID: &core.StrategyConfig{
			Strategy: "inc",
			Range:    []interface{}{1, 100},
			Step:     1,
		},
	}
	g0 := computeReplayGroupID(spec, "task1", "class1", 0)
	g1 := computeReplayGroupID(spec, "task1", "class1", 1)
	if g0 != "1" || g1 != "2" {
		t.Fatalf("g0=%q g1=%q, want 1/2", g0, g1)
	}
}

func TestComputeReplayGroupID_ExplicitStrategyOverridesFlowScaling(t *testing.T) {
	// Explicit GroupID strategy takes priority over FlowScaling implicit
	spec := ReplaySpec{
		FlowScaling: &FlowScaling{Count: 3},
		GroupID:     &core.StrategyConfig{Strategy: "fixed", Value: "call-A"},
	}
	g := computeReplayGroupID(spec, "task1", "class1", 0)
	if g != "call-A" {
		t.Fatalf("gID = %q, want call-A (explicit strategy overrides FlowScaling)", g)
	}
}

func TestComputeReplayGroupID_ListStrategy(t *testing.T) {
	spec := ReplaySpec{
		GroupID: &core.StrategyConfig{
			Strategy: "list",
			List:     []string{"call-A", "call-B", "call-C"},
		},
	}
	g0 := computeReplayGroupID(spec, "task1", "class1", 0)
	g1 := computeReplayGroupID(spec, "task1", "class1", 1)
	g3 := computeReplayGroupID(spec, "task1", "class1", 3) // wraps
	if g0 != "call-A" || g1 != "call-B" || g3 != "call-A" {
		t.Fatalf("g0=%q g1=%q g3=%q, want call-A/call-B/call-A", g0, g1, g3)
	}
}

// Use context to silence unused import warning if test doesn't directly use it.
var _ = context.Background
var _ = json.Marshal
var _ = strconv.Itoa
var _ = strings.ReplaceAll
