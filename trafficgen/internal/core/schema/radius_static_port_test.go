package schema

import (
	"strings"
	"testing"
)

// D-RADIUS-1 红例⑦（failing 先行，P-PIPE #20 P4）：radius 层静态标量端口
// + flows=2 → static-copy 拒（依赖链③执法洞修补，前七协议同款）。
// 形状=[ip{},radius{ports}] 最小证明形（ip 层空配置不触发自身）。
func TestRadiusStaticPortFlowsRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "radius", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"radius": map[string]any{
				"src_port": 12345, "dst_port": 1812,
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
		t.Fatalf("want static-copy rejection for radius-layer static ports + flows=2, got %v", errs)
	}
}
