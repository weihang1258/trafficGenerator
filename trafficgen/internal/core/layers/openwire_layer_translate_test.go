package layers_test

import (
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/openwire"
)

// openwire 层链闭环：层 config 进 spec.OpenWire；层内 tcp.dst_port 是
// 端口真相，必须先于协议级 validator 回填（enip/dameng 先例的根因修：
// validator 在 :413、通用回填原在 :417，端口域校验被缺省 80 旁路）。
func TestOpenWireLayerConfigTranslate(t *testing.T) {
	mk := func(dstPort uint16, cfg map[string]interface{}) (*core.FlowSpec, error) {
		p := layers.NewChainPlannerFromChain("openwire", []layers.Layer{
			{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
			{Name: "tcp", Config: map[string]interface{}{"src_port": float64(40001), "dst_port": float64(dstPort)}},
			{Name: "openwire", Config: cfg},
		})
		// DstPort=80 = mapToFlowSpec flat 判死后的通用缺省（生产形状）：
		// validator 必须看到的是层回填值，不是 spec 直传值。
		spec, err := p.ValidateSpec(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40001, DstPort: 80})
		return &spec, err
	}

	cfg := map[string]interface{}{
		"connections": []interface{}{map[string]interface{}{
			"connection_id": float64(1), "client_id": "c1", "src_port": float64(40001),
			"events": []interface{}{map[string]interface{}{"kind": "wire_format_info", "direction": "c2s"}},
		}},
	}

	s, err := mk(61616, cfg)
	if err != nil {
		t.Fatalf("contract port rejected: %v", err)
	}
	if s.OpenWire == nil || len(s.OpenWire.Connections) != 1 {
		t.Fatalf("layer config not translated: %+v", s.OpenWire)
	}

	// 错端口必须被 validator 拒且报错点名层值 5000（证明回填先于校验）。
	if _, err := mk(5000, cfg); err == nil || !strings.Contains(err.Error(), "5000") {
		t.Fatalf("wrong layer port bypassed the validator (want error naming 5000): %v", err)
	}
}
