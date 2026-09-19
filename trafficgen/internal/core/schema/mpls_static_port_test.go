package schema

import (
	"strings"
	"testing"
)

// D-MPLS-1 红例⑥（failing 先行，P-PIPE #16 P4）：mpls 层静态端口 + flows=2
// 必须拒（12.9 静态复制）。实现前扫描列表无 mpls（semantic.go:187）——
// 执法洞（依赖链③）。ip 层空（对门无贡献）的最小证明形状。
func TestMPLSStaticPortFlowsRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "mpls", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"mpls": map[string]any{
				"src_port": 12345, "dst_port": 80,
				"labels": []any{map[string]any{"label": 100}},
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
		t.Fatalf("want static-copy rejection for mpls-layer static ports + flows=2, got %v", errs)
	}
}
