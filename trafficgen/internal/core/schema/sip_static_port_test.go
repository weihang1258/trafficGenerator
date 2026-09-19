package schema

import (
	"strings"
	"testing"
)

// D-SIP-1 红例⑥（failing 先行，P-PIPE #19 P4）：sip 层静态标量端口 +
// flows=2 → static-copy 拒（依赖链③执法洞修补，前四协议同款）。
// 形状=[ip{},sip{ports}] 最小证明形（ip 层空配置不触发自身）。
func TestSIPStaticPortFlowsRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "sip", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"sip": map[string]any{
				"src_port": 12001, "dst_port": 5060,
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
		t.Fatalf("want static-copy rejection for sip-layer static ports + flows=2, got %v", errs)
	}
}
