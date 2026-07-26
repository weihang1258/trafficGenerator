package core_test

import (
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestMapToFlowSpec_ValidationErrors_NegativeFillBytes verifies the
// strategy_convert validator catches Fill.Bytes=-1 and surfaces it via
// spec.ValidationErrors. Before the fix, this would silently pass through
// mapToFlowSpec and panic make([]byte, -1) deep in the planner.
func TestMapToFlowSpec_ValidationErrors_NegativeFillBytes(t *testing.T) {
	cfg := map[string]interface{}{
		"file_source": map[string]interface{}{
			"fill": map[string]interface{}{
				"byte":  0x41,
				"bytes": -1,
			},
		},
	}
	spec := core.MapToFlowSpec(cfg, "tcp")
	if len(spec.ValidationErrors) == 0 {
		t.Fatalf("expected ValidationErrors non-empty for Fill.Bytes=-1, got empty")
	}
}

// TestMapToFlowSpec_ValidationErrors_RandomMinGtMax verifies inverted
// random range is caught.
func TestMapToFlowSpec_ValidationErrors_RandomMinGtMax(t *testing.T) {
	cfg := map[string]interface{}{
		"file_source": map[string]interface{}{
			"random": map[string]interface{}{
				"min_bytes": 200,
				"max_bytes": 100,
				"seed":      42,
			},
		},
	}
	spec := core.MapToFlowSpec(cfg, "tcp")
	if len(spec.ValidationErrors) == 0 {
		t.Fatalf("expected ValidationErrors for MinBytes>MaxBytes, got empty")
	}
}

// TestMapToFlowSpec_ValidationErrors_CleanForValidSpec verifies valid
// input does NOT set ValidationErrors — important regression guard so
// the validator doesn't false-positive on every config.
func TestMapToFlowSpec_ValidationErrors_CleanForValidSpec(t *testing.T) {
	cfg := map[string]interface{}{
		"file_source": map[string]interface{}{
			"literal": "hello",
		},
	}
	spec := core.MapToFlowSpec(cfg, "tcp")
	if len(spec.ValidationErrors) != 0 {
		t.Fatalf("valid spec got ValidationErrors %v, want empty", spec.ValidationErrors)
	}
}

// TestMapToFlowSpec_ValidationErrors_CleanWhenNoFileSource verifies
// configs that don't use file_source (the vast majority) don't trip
// the validator.
func TestMapToFlowSpec_ValidationErrors_CleanWhenNoFileSource(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "20.0.0.1",
	}
	spec := core.MapToFlowSpec(cfg, "tcp")
	if len(spec.ValidationErrors) != 0 {
		t.Fatalf("no-file_source spec got ValidationErrors %v, want empty", spec.ValidationErrors)
	}
}
