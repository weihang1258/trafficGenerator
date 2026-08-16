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

// TestMapToFlowSpec_UniversalHTTPSubConfig verifies the universal HTTP read:
// a non-HTTP protocol (tftp, UDP-only) with a coexisting "http" sub-map must
// surface spec.HTTP so the tftp planner's V20 mutual-exclusion check
// ("http field must not be set") is reachable at plan time. Before the
// universal read, cfg["http"] was only parsed inside case "http" and the
// V20 check was dead code for tftp — the coexist-reject case passed with
// status=completed instead of failing.
func TestMapToFlowSpec_UniversalHTTPSubConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"src_ip": "10.0.0.100",
		"dst_ip": "10.0.0.1",
		"tftp": map[string]interface{}{
			"mode":         "read",
			"filename":     "x.bin",
			"blocks_count": 1,
		},
		"http": map[string]interface{}{
			"method": "GET",
			"uri":    "/",
		},
	}
	spec := core.MapToFlowSpec(cfg, "tftp")
	if spec.TFTP == nil {
		t.Fatalf("expected spec.TFTP populated for protocol=tftp")
	}
	if spec.HTTP == nil {
		t.Fatalf("expected spec.HTTP populated from universal read for protocol=tftp, got nil (V20 check would be unreachable)")
	}
	if spec.HTTP.Method != "GET" || spec.HTTP.URI != "/" {
		t.Fatalf("unexpected HTTP config: %+v", spec.HTTP)
	}
}

// TestMapToFlowSpec_UniversalDNSSubConfig verifies the universal DNS read
// mirrors the HTTP one: a tftp config with a coexisting "dns" sub-map must
// surface spec.DNS so the tftp planner's V20 "dns field must not be set"
// check fires.
func TestMapToFlowSpec_UniversalDNSSubConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"tftp": map[string]interface{}{
			"mode":         "read",
			"filename":     "x.bin",
			"blocks_count": 1,
		},
		"dns": map[string]interface{}{
			"domain": "example.com",
		},
	}
	spec := core.MapToFlowSpec(cfg, "tftp")
	if spec.DNS == nil {
		t.Fatalf("expected spec.DNS populated from universal read for protocol=tftp, got nil")
	}
	if spec.DNS.Domain != "example.com" {
		t.Fatalf("unexpected DNS config: %+v", spec.DNS)
	}
}

// TestMapToFlowSpec_UniversalSCTPSubConfig verifies the universal SCTP read
// (parser with nested chunks/heartbeats) still works from the hoisted
// location for protocol=sctp.
func TestMapToFlowSpec_UniversalSCTPSubConfig(t *testing.T) {
	cfg := map[string]interface{}{
		"sctp": map[string]interface{}{
			"verification_tag": float64(123),
			"initiate_tag":     float64(456),
			"abort":            true,
			"fragment_size":    float64(1400),
		},
	}
	spec := core.MapToFlowSpec(cfg, "sctp")
	if spec.SCTP == nil {
		t.Fatalf("expected spec.SCTP populated for protocol=sctp")
	}
	if spec.SCTP.VerificationTag != 123 || spec.SCTP.InitiateTag != 456 {
		t.Fatalf("unexpected SCTP config: %+v", spec.SCTP)
	}
	if !spec.SCTP.Abort || spec.SCTP.FragmentSize != 1400 {
		t.Fatalf("unexpected SCTP abort/fragment: %+v", spec.SCTP)
	}
}
