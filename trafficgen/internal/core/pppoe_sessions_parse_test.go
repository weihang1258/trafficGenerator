package core

import (
	"encoding/json"
	"testing"
)

// D-PPPOE-1 P4 红例（9.49 sessions[] 全生命周期，SIPSession parse 漏接线
// 先例）：sessions 内 per-entry 字段必须从层 config 解析。parse 层红例
// （planner 层直构 spec 绕过 parse，测不到此处）。
func TestParsePPPoESessions(t *testing.T) {
	raw := `[{"session_id": 100, "data_frames": 2, "data_payload": "hello", "inner_proto": 6, "data_direction": "down"},
	          {"session_id": {"type": "inc", "range": [10, 20], "step": 1}, "skip_discovery": true},
	          {}]`
	var arr []interface{}
	if err := json.Unmarshal([]byte(raw), &arr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	sess := ParsePPPoESessions(arr)
	if len(sess) != 3 {
		t.Fatalf("sessions=%d want 3", len(sess))
	}
	s0 := sess[0]
	if s0.SessionID != 100 {
		t.Fatalf("s0 session_id=%d want 100", s0.SessionID)
	}
	if s0.DataFrames != 2 {
		t.Fatalf("s0 data_frames=%d want 2 (per-entry override)", s0.DataFrames)
	}
	if string(s0.DataPayload) != "hello" {
		t.Fatalf("s0 data_payload=%q want hello", s0.DataPayload)
	}
	if s0.InnerProto != 6 {
		t.Fatalf("s0 inner_proto=%d want 6", s0.InnerProto)
	}
	if s0.DataDirection != "down" {
		t.Fatalf("s0 data_direction=%q want down", s0.DataDirection)
	}
	s1 := sess[1]
	if s1.SessionIDDyn == nil {
		t.Fatalf("s1 dynamic session_id dropped by parse")
	}
	if !s1.SkipDiscovery {
		t.Fatalf("s1 skip_discovery dropped by parse")
	}
	if sess[2].SessionID != 0 || sess[2].DataFrames != 0 {
		t.Fatalf("s2 zero-entry must parse as zero values: %+v", sess[2])
	}
}

// parsePPPoEConfig 必须把 sessions 接进 PPPoEConfig（translate 复用
// parsePPPoEConfig，漏接=事件面静默空会话）。
func TestParsePPPoEConfigWiresSessions(t *testing.T) {
	raw := `{"ac_name": "BRAS-1", "sessions": [{"session_id": 7, "data_frames": 1}]}`
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cfg := parsePPPoEConfig(m)
	if cfg == nil {
		t.Fatalf("parsePPPoEConfig nil")
	}
	if cfg.ACName != "BRAS-1" {
		t.Fatalf("ac_name=%q want BRAS-1", cfg.ACName)
	}
	if len(cfg.Sessions) != 1 || cfg.Sessions[0].SessionID != 7 {
		t.Fatalf("sessions not wired through parsePPPoEConfig: %+v", cfg.Sessions)
	}
}
