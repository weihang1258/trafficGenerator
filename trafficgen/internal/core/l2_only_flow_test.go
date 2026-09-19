package core_test

import (
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// D-SV-1 ⑥（P5 实测红转绿，failing 先行）：L2-only（goose/sv）无端口概念，
// worker 多流保底递增（worker.go :307 DefaultSrcPort+i）会往 spec 注入假
// 端口，被终结层 "Layer 2 only" 校验拒收（sv_mac_dyn_inc flows=3 实测
// planning failed）。修法：mapToFlowSpec 对 l2Only 恒置 HasExplicitSrcPort
// ——worker 跳过递增，spec 端口保持 0 值真相（校验器查零值口径不变）。
// goose 同享此修（12.9 MAC 动态逃生口的 flows 面一并打通）。
func TestL2OnlyHasExplicitSrcPort(t *testing.T) {
	spec := core.MapToFlowSpec(map[string]interface{}{
		"src_mac": "aa:bb:cc:dd:ee:03",
		"layers": []interface{}{
			map[string]interface{}{"eth": map[string]interface{}{}},
			map[string]interface{}{"sv": map[string]interface{}{
				"sv_id": "xxxxMUnn01", "appid": 16384, "conf_rev": 1,
				"samples_per_cycle": 80,
				"data":              []interface{}{map[string]interface{}{"name": "I_A", "type": "int32", "inst_mag": 100}},
			}},
		},
	}, "sv")
	if !spec.HasExplicitSrcPort {
		t.Fatal("L2-only spec must set HasExplicitSrcPort (worker port auto-increment would inject fake 12345+i and trip the L2-only validator)")
	}
	if spec.SrcPort != 0 || spec.DstPort != 0 {
		t.Fatalf("L2-only spec ports must stay 0, got src=%d dst=%d", spec.SrcPort, spec.DstPort)
	}
}
