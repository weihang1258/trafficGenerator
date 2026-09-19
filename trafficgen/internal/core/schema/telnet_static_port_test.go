package schema

import (
	"strings"
	"testing"
)

// D-TELNET-1 红例⑥（failing 先行，P-PIPE #18 P4）：telnet 层静态标量端口
// + flows=2 → static-copy 拒（依赖链③执法洞修补，h323/mpls/ngap 同款）。
// 形状=[ip{},telnet{ports}] 最小证明形（ip 层空配置不触发自身）。
func TestTelnetStaticPortFlowsRejected(t *testing.T) {
	_, errs := ValidateStrategy("synth", "telnet", map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{}},
			map[string]any{"telnet": map[string]any{
				"src_port": 12345, "dst_port": 23,
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
		t.Fatalf("want static-copy rejection for telnet-layer static ports + flows=2, got %v", errs)
	}
}
