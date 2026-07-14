package core

// Test points for convert.go (SC1-SC15) from tools/test_points/engine_core.md.
// Only adds test points not already covered by convert_test.go (TestParseBPS,
// TestAPIRequestToTask). Each test asserts observable values, not "no error".

import (
	"strings"
	"testing"
)

// SC1-POS: generateTaskID returns "task-" + 16 hex chars and is unique.
func TestGenerateTaskID_Format(t *testing.T) {
	id1 := generateTaskID()
	if !strings.HasPrefix(id1, "task-") {
		t.Fatalf("id1=%q missing task- prefix", id1)
	}
	hex := strings.TrimPrefix(id1, "task-")
	if len(hex) != 16 {
		t.Errorf("hex suffix len=%d, want 16 (8 random bytes)", len(hex))
	}
	for _, c := range hex {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isHex {
			t.Errorf("suffix %q contains non-hex char %q", hex, c)
		}
	}
	// Two calls should differ (8 random bytes -> collision probability ~2^-64).
	id2 := generateTaskID()
	if id1 == id2 {
		t.Errorf("two generateTaskID calls returned identical id %q (randomness broken)", id1)
	}
}

// SC2-POS: APIRequestToTask passes through all fields and generates a non-empty ID.
func TestAPIRequestToTask_AllFields(t *testing.T) {
	spec := FlowSpec{SrcIP: "192.168.1.1", DstIP: "192.168.1.2", SrcPort: 12345, DstPort: 80}
	task := APIRequestToTask("mytask", "desc-here", "tcp", spec, "eth0")
	if task.ID == "" {
		t.Error("ID empty; want generated non-empty")
	}
	if task.Name != "mytask" {
		t.Errorf("Name=%q want mytask", task.Name)
	}
	if task.Description != "desc-here" {
		t.Errorf("Description=%q want desc-here", task.Description)
	}
	if task.Protocol != "tcp" {
		t.Errorf("Protocol=%q want tcp", task.Protocol)
	}
	if task.Interface != "eth0" {
		t.Errorf("Interface=%q want eth0", task.Interface)
	}
	if task.Spec.SrcIP != "192.168.1.1" || task.Spec.DstPort != 80 {
		t.Errorf("Spec not passed through: %+v", task.Spec)
	}
}

// SC3-BR1: empty strings still yield a generated ID; other fields stay empty.
func TestAPIRequestToTask_EmptyStrings(t *testing.T) {
	task := APIRequestToTask("", "", "", FlowSpec{}, "")
	if task.ID == "" {
		t.Error("ID should still be generated even with empty inputs")
	}
	if task.Name != "" || task.Description != "" || task.Protocol != "" || task.Interface != "" {
		t.Errorf("fields not empty: %+v", task)
	}
}

// SC13-NEG: "1kk" -> strip one 'k' -> ParseInt("1k") fails -> 0, error.
func TestParseBPS_1kk(t *testing.T) {
	got, err := ParseBPS("1kk")
	if err == nil {
		t.Fatalf("expected error for 1kk, got nil (value=%d)", got)
	}
	if got != 0 {
		t.Errorf("on error, got=%d want 0", got)
	}
}

// SC14-BR2: "0" -> 0, nil (explicit zero, not an error).
func TestParseBPS_Zero(t *testing.T) {
	got, err := ParseBPS("0")
	if err != nil {
		t.Fatalf("unexpected error for 0: %v", err)
	}
	if got != 0 {
		t.Errorf("got=%d want 0", got)
	}
}

// SC15-NEG: "1.5M" -> strip 'M' -> ParseInt("1.5") fails -> 0, error.
func TestParseBPS_Decimal(t *testing.T) {
	got, err := ParseBPS("1.5M")
	if err == nil {
		t.Fatalf("expected error for 1.5M, got nil (value=%d)", got)
	}
	if got != 0 {
		t.Errorf("on error, got=%d want 0", got)
	}
}
