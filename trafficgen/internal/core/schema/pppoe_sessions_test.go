package schema

import (
	"strings"
	"testing"
)

// D-PPPOE-1 P4 红例（failing 先行）：pppoe 层 sessions[] 三面。
// 锚词 = Planner.Validate 背 door 同文案（C 类两路独立闭合，sip WP-A 口径）。

// 红例① sessions 与顶层行为键（6 键：session_id/skip_discovery/data_frames/
// data_payload/inner_proto/data_direction）同给 → 互斥判死。
func TestPPPoESessionsBehaviorMutexRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "pppoe", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"pppoe": map[string]any{
				"data_frames": 3,
				"sessions": []any{
					map[string]any{"session_id": 100},
				},
			}},
		},
	}, &FlowControl{Type: "flows", Value: 1})
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "pppoe: sessions and top-level session config are mutually exclusive") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want sessions/behavior mutex rejection, got %v", errs)
	}
}

// 红例② 空 sessions 数组 → 同锚词面。
func TestPPPoESessionsEmptyRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "pppoe", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"pppoe": map[string]any{
				"sessions": []any{},
			}},
		},
	}, nil)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "pppoe: sessions and top-level session config are mutually exclusive") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want empty-sessions rejection, got %v", errs)
	}
}

// 红例③ 重复显式 session_id → 判死。
func TestPPPoESessionsDuplicateIDRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "pppoe", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"pppoe": map[string]any{
				"sessions": []any{
					map[string]any{"session_id": 100},
					map[string]any{"session_id": 100},
				},
			}},
		},
	}, &FlowControl{Type: "flows", Value: 1})
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "pppoe: duplicate session_id") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want duplicate session_id rejection, got %v", errs)
	}
}

// 正例：sessions[] 单独给，模板键（ac_name 等 9 键）共存合法（继承语义）。
func TestPPPoESessionsWithTemplateKeysAccepted(t *testing.T) {
	_, errs := ValidateStrategy("synth", "pppoe", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"pppoe": map[string]any{
				"ac_name": "BRAS-1",
				"auth":    "pap",
				"sessions": []any{
					map[string]any{"session_id": 100, "data_frames": 2},
					map[string]any{"data_frames": 1},
				},
			}},
		},
	}, &FlowControl{Type: "flows", Value: 1})
	for _, e := range errs {
		if strings.Contains(e.Message, "pppoe:") {
			t.Fatalf("template keys must coexist with sessions, got %q", e.Message)
		}
	}
}
