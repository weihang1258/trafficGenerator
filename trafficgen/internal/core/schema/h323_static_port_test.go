package schema

import (
	"strings"
	"testing"
)

// D-H323-1 红例⑥（failing 先行，P-PIPE #15 P4）：h323 层静态端口 + flows=2
// 必须拒（12.9 静态复制）。实现前 checkLayerChainStaticCopy 扫描列表只有
// ip/tcp/udp/eth（semantic.go:186）——h323 层端口标量漏网=执法洞（依赖链③）。
func TestH323StaticPortFlowsRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "h323", map[string]any{
		"layers": []any{
			// 洞的最小证明形状：ip 层无显式地址（无标量无对象=对门无贡献，
			// worker 保底端口在 translate 层值赢后被 h323 静态标量覆盖），
			// 唯一四元组真相=h323 层静态标量端口 → flows=2 时 N 条完全
			// 相同四元组（12.9 违规面）。
			map[string]any{"ip": map[string]any{}},
			map[string]any{"h323": map[string]any{"src_port": 12345, "dst_port": 1720}},
		},
	}, &FlowControl{Type: "flows", Value: 2})
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "static four-tuple") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want static-copy rejection for h323-layer static ports + flows=2, got %v", errs)
	}
}
