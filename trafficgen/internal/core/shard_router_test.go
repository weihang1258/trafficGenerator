package core

import (
	"strconv"
	"testing"
)

func TestComputeHashKeyGroupIDTakesPriority(t *testing.T) {
	spec := FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 1000, DstPort: 80,
		GroupID: &StrategyConfig{Strategy: "fixed", Value: "call-A"},
	}
	task := Task{ID: "taskA", ClassID: "classB"}
	hashKey, gID := computeHashKey(spec, task, 0)
	if hashKey != "call-A" || gID != "call-A" {
		t.Fatalf("hashKey=%q gID=%q, want call-A/call-A", hashKey, gID)
	}
}

func TestComputeHashKeyFallbackTo4Tuple(t *testing.T) {
	spec := FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 1000, DstPort: 80,
	}
	task := Task{ID: "taskA", ClassID: "classB"}
	hashKey, gID := computeHashKey(spec, task, 0)
	want := "10.0.0.1-10.0.0.2-80-1000"
	if hashKey != want {
		t.Fatalf("hashKey=%q want %q", hashKey, want)
	}
	if gID != "" {
		t.Fatalf("gID=%q want empty (fallback)", gID)
	}
}

func TestComputeHashKeyBidirectionalSameKey(t *testing.T) {
	spec1 := FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1000, DstPort: 80}
	spec2 := FlowSpec{SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 80, DstPort: 1000}
	task := Task{ID: "taskA", ClassID: "classB"}
	k1, _ := computeHashKey(spec1, task, 0)
	k2, _ := computeHashKey(spec2, task, 0)
	if k1 != k2 {
		t.Fatalf("bidirectional keys differ: %q vs %q", k1, k2)
	}
}

func TestComputeHashKeyReplayImplicitGID(t *testing.T) {
	spec := FlowSpec{}
	task := Task{ID: "taskA", ClassID: "classB", Mode: "replay"}
	hashKey, gID := computeHashKey(spec, task, 0)
	want := "taskA:classB"
	if hashKey != want || gID != want {
		t.Fatalf("hashKey=%q gID=%q want %q", hashKey, gID, want)
	}
}

func TestComputeHashKeyPatternStrategy(t *testing.T) {
	spec := FlowSpec{
		GroupID: &StrategyConfig{
			Strategy: "pattern",
			Pattern:  "call-{n}",
			Range:    []interface{}{1, 100},
		},
	}
	task := Task{ID: "taskA", ClassID: "classB"}
	hashKey0, gID0 := computeHashKey(spec, task, 0)
	hashKey7, gID7 := computeHashKey(spec, task, 7)
	if gID0 != "call-1" {
		t.Fatalf("gID0=%q want call-1", gID0)
	}
	if gID7 != "call-8" {
		t.Fatalf("gID7=%q want call-8", gID7)
	}
	if gID0 == gID7 {
		t.Fatalf("different flowIdx should produce different gID: %q == %q", gID0, gID7)
	}
	if hashKey0 != gID0 || hashKey7 != gID7 {
		t.Fatalf("hashKey should equal gID for pattern strategy")
	}
}

func TestComputeHashKeyIncStrategy(t *testing.T) {
	spec := FlowSpec{
		GroupID: &StrategyConfig{
			Strategy: "inc",
			Range:    []interface{}{1, 100},
			Step:     1,
		},
	}
	task := Task{ID: "taskA", ClassID: "classB"}
	_, gID0 := computeHashKey(spec, task, 0)
	_, gID1 := computeHashKey(spec, task, 1)
	if gID0 != "1" || gID1 != "2" {
		t.Fatalf("gID0=%q gID1=%q want 1/2", gID0, gID1)
	}
}

func TestComputeHashKeyListStrategy(t *testing.T) {
	spec := FlowSpec{
		GroupID: &StrategyConfig{
			Strategy: "list",
			List:     []string{"call-A", "call-B", "call-C"},
		},
	}
	task := Task{ID: "taskA", ClassID: "classB"}
	_, gID0 := computeHashKey(spec, task, 0)
	_, gID1 := computeHashKey(spec, task, 1)
	_, gID3 := computeHashKey(spec, task, 3) // wraps
	if gID0 != "call-A" || gID1 != "call-B" {
		t.Fatalf("gID0=%q gID1=%q want call-A/call-B", gID0, gID1)
	}
	if gID3 != "call-A" {
		t.Fatalf("gID3=%q want call-A (wrap)", gID3)
	}
}

func TestComputeHashKeyRandStrategyDeterministic(t *testing.T) {
	spec := FlowSpec{
		GroupID: &StrategyConfig{
			Strategy: "rand",
			Range:    []interface{}{1, 1000},
			Seed:     42,
		},
	}
	task := Task{ID: "taskA", ClassID: "classB"}
	_, gID0a := computeHashKey(spec, task, 0)
	_, gID0b := computeHashKey(spec, task, 0)
	if gID0a != gID0b {
		t.Fatalf("rand not deterministic: %q vs %q", gID0a, gID0b)
	}
	if gID0a == "" {
		t.Fatal("gID0 empty, want a number 1..1000")
	}
	// Verify the value is within [1, 1000]
	n, err := strconv.Atoi(gID0a)
	if err != nil || n < 1 || n > 1000 {
		t.Fatalf("gID0a=%q want number in [1,1000]", gID0a)
	}
}

func TestComputeHashKeyGroupIDNilStrategyEmpty(t *testing.T) {
	// GroupID present but strategy empty -> treat as no group_id, fall through
	spec := FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 1000, DstPort: 80,
		GroupID: &StrategyConfig{}, // strategy=""
	}
	task := Task{ID: "taskA", ClassID: "classB"}
	hashKey, gID := computeHashKey(spec, task, 0)
	if gID != "" {
		t.Fatalf("gID=%q want empty for empty-strategy GroupID", gID)
	}
	want := "10.0.0.1-10.0.0.2-80-1000"
	if hashKey != want {
		t.Fatalf("hashKey=%q want %q (fallback)", hashKey, want)
	}
}
