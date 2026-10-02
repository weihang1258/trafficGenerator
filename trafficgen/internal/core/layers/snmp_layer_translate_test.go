package layers_test

import (
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// snmp 层 config 翻译语义：显式 version=0 必须保留为 v1（SNMP.3.x
// presence 教训——不能塌成缺省 v2c）；缺键默认 v2c/public/1 与 flat
// 遗留语义一致。
func TestSNMPLayerConfigTranslate(t *testing.T) {
	mk := func(cfg map[string]interface{}) *core.SNMPConfig {
		p := layers.NewChainPlannerFromChain("snmp", []layers.Layer{
			{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
			{Name: "udp", Config: map[string]interface{}{}},
			{Name: "snmp", Config: cfg},
		})
		spec, err := p.ValidateSpec(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"})
		if err != nil {
			t.Fatalf("ValidateSpec: %v", err)
		}
		return spec.SNMP
	}

	vb := func() []interface{} {
		return []interface{}{map[string]interface{}{"name": "1.3.6.1.2.1.1.1.0"}}
	}
	s := mk(map[string]interface{}{"version": float64(0), "community": "private", "var_binds": vb()})
	if s == nil || s.Version != 0 || s.Community != "private" {
		t.Fatalf("explicit v1 config lost: %+v", s)
	}

	s = mk(map[string]interface{}{"var_binds": vb()})
	if s == nil || s.Version != 1 || s.Community != "public" || s.MaxRepetitions != 1 {
		t.Fatalf("absent-key defaults wrong: %+v", s)
	}

	// 空层 {} → spec.SNMP 保持 nil（validator 对 nil 放行，生成器走 P0b-2
	// 默认流）；非 nil 零配置会被 Get 空 varbinds 检查判死。
	if s := mk(map[string]interface{}{}); s != nil {
		t.Fatalf("empty layer must keep spec.SNMP nil, got %+v", s)
	}
}
