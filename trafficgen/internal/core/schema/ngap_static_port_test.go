package schema

import (
	"strings"
	"testing"
)

// D-NGAP-1 红例⑥（failing 先行，P-PIPE #17 P4）：ngap 层静态标量端口 +
// flows=2 → static-copy 拒（依赖链③执法洞修补，h323/mpls 同款）。
// 形状=[ip{},ngap{ports}] 最小证明形（ip 层空配置不触发自身）。
func TestNGAPStaticPortFlowsRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "ngap", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"ngap": map[string]any{
				"src_port": 12345, "dst_port": 38412,
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
		t.Fatalf("want static-copy rejection for ngap-layer static ports + flows=2, got %v", errs)
	}
}
