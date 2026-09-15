package core

import (
	"encoding/json"
	"strings"
	"testing"
)

// D-GRE-2 步骤 0 红例（parseLayerDyn 侧——worker 逐流解析入口）：
// 隧道链内层 ip 层写动态对象必须报错（现状：外层对象被内层静默顶掉，
// 2026-09-15 探针 C 实锤）。
func TestParseLayerDyn_InnerIPDynamicRejected(t *testing.T) {
	layersJSON := `[
	 {"ip": {"src": {"strategy":"list","list":["10.0.0.1","10.0.0.2"]}}},
	 {"gre": {}},
	 {"ip": {"src": {"strategy":"list","list":["30.0.0.1","30.0.0.2"]}}},
	 {"udp": {}},
	 {"dns": {}}
	]`
	var raw interface{}
	json.Unmarshal([]byte(layersJSON), &raw)
	_, errs := parseLayerDyn(raw)
	found := false
	for _, e := range errs {
		if strings.Contains(e, "inner ip layer does not support dynamic") {
			found = true
		}
	}
	if !found {
		t.Fatalf("parseLayerDyn errs = %v, want inner-ip-dynamic rejection", errs)
	}
}
