package core_test

// Integration: the JSON→FlowSpec path (MapToFlowSpec) must carry a
// session-level disconnect_reason so that the mqtt planner's Validate can
// reject an out-of-whitelist code. This lives in package core_test (not
// core) because mqtt imports core — an internal test would be an import
// cycle.
//
// Spec-driven: MQTTSession.DisconnectReason is a per-session override that
// mergeSession copies into the effective config, and validateMergedSession
// applies the same whitelist rules as the top-level field (mqtt.go). The
// JSON key must survive conversion for that check to fire.

import (
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/mqtt"
)

func TestParseMQTTConfig_InvalidSessionReasonRejectedByPlanner(t *testing.T) {
	spec := core.MapToFlowSpec(map[string]interface{}{
		"src_ip": "10.0.0.1",
		"dst_ip": "10.0.0.2",
		"mqtt": map[string]interface{}{
			"version":   float64(5),
			"client_id": "c1",
			"sessions": []interface{}{
				map[string]interface{}{
					"client_id":         "s1",
					"disconnect_reason": float64(0x7F),
				},
			},
		},
	}, "mqtt")
	if spec.MQTT == nil {
		t.Fatal("spec.MQTT is nil")
	}
	if len(spec.MQTT.Sessions) != 1 || spec.MQTT.Sessions[0].DisconnectReason == nil {
		t.Fatalf("sessions = %+v, want 1 session with disconnect_reason", spec.MQTT.Sessions)
	}
	// The planner's Validate is the gate the API relies on; exercising the
	// converted spec against it proves the JSON key reaches the whitelist
	// check.
	p := mqtt.NewPlanner()
	err := p.Validate(spec)
	if err == nil {
		t.Error("expected planner validation error for session disconnect_reason 0x7F, got nil")
	}
	// Assert the rejection is the whitelist check itself, not some earlier
	// validation failure that would also produce an error.
	if err != nil && !strings.Contains(err.Error(), "disconnect_reason") {
		t.Errorf("planner error = %v, want a disconnect_reason whitelist rejection", err)
	}
}
