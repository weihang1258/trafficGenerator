package schema

import (
	"strings"
	"testing"
)

// D-COAP-2 红例（failing 先行）：coap 层 session_src_ips/session_src_ports
// 数组 = 逐会话地址声明（协议内多会话，语义同 D-SIP-2 WP-A 的 sessions[]
// 内嵌端口同权）。flows>1 + 外层静态四元组 + 会话地址数组**不构成静态拷贝**
// ——数组即"逐流有别"证明，checkLayerChainStaticCopy 必须豁免（此前业务层
// 逃生口只认 strategy 对象，数组形状漏判 → coap_multi_session 套件 error）。
func TestCoapSessionArraysExemptStaticCopy(t *testing.T) {
	_, errs := ValidateStrategy("synth", "coap", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{"src": "10.0.0.1", "dst": "20.0.0.1"}},
			map[string]any{"udp": map[string]any{"src_port": 56565, "dst_port": 5683}},
			map[string]any{"coap": map[string]any{
				"session_src_ips":   []any{"10.0.0.1", "10.0.0.2"},
				"session_src_ports": []any{56565, 56566},
			}},
		},
	}, &FlowControl{Type: "flows", Value: 2})
	for _, e := range errs {
		if strings.Contains(e.Message, "static four-tuple") {
			t.Fatalf("session address arrays are per-flow-distinct proof, must exempt static-copy: %v", errs)
		}
	}
}

// 反例护栏：会话地址数组缺位（无 session_src_*）时静态拷贝照旧拒——
// 豁免只认数组证据，不放开形状。
func TestCoapStaticTupleWithoutSessionArraysStillRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "coap", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{"src": "10.0.0.1", "dst": "20.0.0.1"}},
			map[string]any{"udp": map[string]any{"src_port": 56565, "dst_port": 5683}},
			map[string]any{"coap": map[string]any{"method": "GET"}},
		},
	}, &FlowControl{Type: "flows", Value: 2})
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "static four-tuple") {
			found = true
		}
	}
	if !found {
		t.Fatalf("static tuple + flows>1 without session arrays must still be rejected, got %v", errs)
	}
}
