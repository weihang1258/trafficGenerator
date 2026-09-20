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

// D-SIP-2 WP-B 红例：medias 与 media 互斥（create 400）。
func TestSIPMediasMutexRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "sip", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"sip": map[string]any{
				"media":  map[string]any{"frames": 2},
				"medias": []any{map[string]any{"direction": "up", "frames": 2}},
			}},
		},
	}, nil)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "sip: media and medias are mutually exclusive") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want media/medias mutex rejection, got %v", errs)
	}
}

// D-SIP-2 WP-B：空 medias 数组同锚词面。
func TestSIPMediasEmptyRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "sip", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"sip": map[string]any{"medias": []any{}}},
		},
	}, nil)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "sip: media and medias are mutually exclusive") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want empty-medias rejection, got %v", errs)
	}
}

// D-SIP-2 WP-B：medias 内标量端口 + flows=2 → static-copy 拒。
func TestSIPMediasStaticCopyRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "sip", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"sip": map[string]any{
				"medias": []any{map[string]any{"direction": "up", "src_port": 30001, "frames": 2}},
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
		t.Fatalf("want medias static-copy rejection, got %v", errs)
	}
}

// D-SIP-2 WP-D 红例：tls 链上 sessions 判死（一链一连接无多会话等价物）。
func TestSIPTLSChainSessionsRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "sip", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"tcp": map[string]any{}},
			map[string]any{"tls": map[string]any{}},
			map[string]any{"sip": map[string]any{
				"sessions": []any{map[string]any{"src_port": 22001}},
			}},
		},
	}, nil)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "sessions are not supported on a tcp/tls sip chain") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want tls×sessions rejection, got %v", errs)
	}
}

// D-SIP-2 WP-D 红例：tls 链上 media 判死（RTP 是 UDP 裸流不进 TLS）。
func TestSIPTLSChainMediaRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "sip", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"tcp": map[string]any{}},
			map[string]any{"tls": map[string]any{}},
			map[string]any{"sip": map[string]any{
				"dialog": []any{map[string]any{"method": "OPTIONS", "uri": "sip:x"}},
				"media":  map[string]any{"frames": 2},
			}},
		},
	}, nil)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "media is not supported on a tcp/tls sip chain") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want tls×media rejection, got %v", errs)
	}
}

// D-SIP-2 WP-D 红例：纯 tcp 链上 sips: URI 判死（SIPS 必须走 TLS）。
func TestSIPSIPSUriWithoutTLSRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "sip", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"tcp": map[string]any{}},
			map[string]any{"sip": map[string]any{
				"dialog": []any{map[string]any{"method": "INVITE", "uri": "sips:callee@20.0.0.1"}},
			}},
		},
	}, nil)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "sip: sips uri requires a tls layer in the chain") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want sips-needs-tls rejection, got %v", errs)
	}
}

// 放行面：无 tls/sips 的 [ip,sip] 自驱链不受事件面检查误伤。
func TestSIPSelfDriveChainAccepted(t *testing.T) {
	_, errs := ValidateStrategy("synth", "sip", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"sip": map[string]any{
				"dialog": []any{map[string]any{"method": "OPTIONS", "uri": "sip:x"}},
				"media":  map[string]any{"frames": 2},
			}},
		},
	}, nil)
	for _, e := range errs {
		if strings.Contains(e.Message, "tcp/tls sip chain") || strings.Contains(e.Message, "sips uri") {
			t.Fatalf("self-drive chain must not hit event-plane checks: %v", e)
		}
	}
}
