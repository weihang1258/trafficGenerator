package schema

import (
	"strings"
	"testing"
)

// D-SIP-2 WP-A 红例（failing 先行）：sip 层 sessions[] 多会话三面。
// 形状与 radius_static_port_test 同构（最小证明形）。

// 红例① sessions 与 dialog 同给 → 互斥判死（create-time 400）。
func TestSIPSessionsDialogMutexRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "sip", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"sip": map[string]any{
				"dialog": []any{
					map[string]any{"method": "OPTIONS", "uri": "sip:callee@20.0.0.1"},
				},
				"sessions": []any{
					map[string]any{"src_port": 22001},
				},
			}},
		},
	}, &FlowControl{Type: "flows", Value: 1})
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "sip: sessions and dialog are mutually exclusive") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want sessions/dialog mutex rejection, got %v", errs)
	}
}

// 红例② 空 sessions 数组 → 同锚词面（D-SIP-2 定稿口径）。
func TestSIPSessionsEmptyRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "sip", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"sip": map[string]any{
				"sessions": []any{},
			}},
		},
	}, nil)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "sip: sessions and dialog are mutually exclusive") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want empty-sessions rejection, got %v", errs)
	}
}

// 红例③ sessions 内标量端口 + flows=2 → static-copy 拒（2.9/12.9 扩扫）。
func TestSIPSessionsStaticCopyRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "sip", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"sip": map[string]any{
				"sessions": []any{
					map[string]any{"src_port": 22001},
					map[string]any{"src_port": 22002},
				},
			}},
		},
	}, &FlowControl{Type: "flows", Value: 2})
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "static four-tuple") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want sessions static-copy rejection, got %v", errs)
	}
}

// 放行面：sessions 独立使用（无 dialog）合法——红例实现前整层拒，防误伤。
func TestSIPSessionsAloneAccepted(t *testing.T) {
	_, errs := ValidateStrategy("synth", "sip", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"sip": map[string]any{
				"sessions": []any{
					map[string]any{"src_port": 22001},
				},
			}},
		},
	}, nil)
	for _, e := range errs {
		if strings.Contains(e.Message, "sessions") {
			t.Fatalf("sessions alone must be accepted, got %v", errs)
		}
	}
}
