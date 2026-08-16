package core

// Tests for parseMQTTConfig / parseMQTTSessions — the JSON→config layer
// between the API and the MQTT planner.
//
// Spec-driven: MQTTSession carries a per-session disconnect_reason override
// (internal/core/types.go MQTTSession.DisconnectReason) that must be
// reachable from JSON the same way as the top-level field. These tests fail
// BEFORE the fix: parseMQTTSessions never read the "disconnect_reason" key,
// so a session-level override was silently dropped and the planner used the
// top-level value (or 0) instead.
//
// The planner-rejection integration test lives in
// strategy_convert_mqtt_integration_test.go (package core_test) because the
// mqtt package imports core.

import (
	"testing"
)

// T-187c: session-level disconnect_reason parses into MQTTSession.
func TestParseMQTTSessions_DisconnectReason(t *testing.T) {
	cfg := parseMQTTConfig(map[string]interface{}{
		"version": 5,
		"sessions": []interface{}{
			map[string]interface{}{
				"client_id":         "s1",
				"disconnect_reason": float64(141),
			},
		},
	})
	if cfg == nil {
		t.Fatal("parseMQTTConfig returned nil")
	}
	if len(cfg.Sessions) != 1 {
		t.Fatalf("sessions len = %d, want 1", len(cfg.Sessions))
	}
	s := cfg.Sessions[0]
	if s.DisconnectReason == nil {
		t.Fatalf("session disconnect_reason not parsed (nil), want 141")
	}
	if *s.DisconnectReason != 141 {
		t.Errorf("session disconnect_reason = %d, want 141", *s.DisconnectReason)
	}
}

// T-187c control: a session without the key keeps the pointer nil (inherit
// semantics), and parsing an invalid code 0x7F must still carry the value so
// the planner's whitelist check can reject it.
func TestParseMQTTSessions_DisconnectReasonControl(t *testing.T) {
	cfg := parseMQTTConfig(map[string]interface{}{
		"version": 5,
		"sessions": []interface{}{
			map[string]interface{}{"client_id": "s1"},
			map[string]interface{}{
				"client_id":         "s2",
				"disconnect_reason": float64(0x7F),
			},
		},
	})
	if cfg == nil || len(cfg.Sessions) != 2 {
		t.Fatalf("cfg = %+v, want 2 sessions", cfg)
	}
	if cfg.Sessions[0].DisconnectReason != nil {
		t.Errorf("session without key got reason %d, want nil (inherit)", *cfg.Sessions[0].DisconnectReason)
	}
	if cfg.Sessions[1].DisconnectReason == nil || *cfg.Sessions[1].DisconnectReason != 0x7F {
		t.Errorf("session reason = %v, want 0x7F (carried for planner validation)", cfg.Sessions[1].DisconnectReason)
	}
}
