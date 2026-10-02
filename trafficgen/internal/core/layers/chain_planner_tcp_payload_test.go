package layers_test

import (
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// tcp 载体 payload 住 tcp 层 config（层链唯一配置真相，CORE_MEMORY 1.11）：
// 层内声明 → spec.Payload（生成器 tcp.go 读 spec.Payload）；缺省保留原值
// （flat 路径兼容）。
func TestTCPLayerPayloadTranslate(t *testing.T) {
	p := layers.NewChainPlannerFromChain("tcp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
		{Name: "tcp", Config: map[string]interface{}{"src_port": float64(12345), "dst_port": float64(8080), "payload": "hello-layer"}},
	})
	spec, err := p.ValidateSpec(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 8080})
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if string(spec.Payload) != "hello-layer" {
		t.Fatalf("spec.Payload = %q, want %q", spec.Payload, "hello-layer")
	}
}

// 层内无 payload → spec.Payload 保持原值（引擎直调路径不误清）。
func TestTCPLayerPayloadAbsentKeepsSpec(t *testing.T) {
	p := layers.NewChainPlannerFromChain("tcp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
		{Name: "tcp", Config: map[string]interface{}{"src_port": float64(12345), "dst_port": float64(8080)}},
	})
	spec, err := p.ValidateSpec(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 8080, Payload: []byte("legacy")})
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if string(spec.Payload) != "legacy" {
		t.Fatalf("spec.Payload = %q, want %q", spec.Payload, "legacy")
	}
}

// 评审 LOW：payload 只在独立传输流协议 tcp（tcp 为终结层）下有意义；
// 中链 tcp 层的 payload 是死配置（被静默忽略），必须判死（CORE_MEMORY
// 死配置=违规）。
func TestTCPLayerPayloadMidChainRejected(t *testing.T) {
	p := layers.NewChainPlannerFromChain("ethmining", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
		{Name: "tcp", Config: map[string]interface{}{"payload": "dead-config"}},
		{Name: "ethmining", Config: map[string]interface{}{}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 3333}
	if _, err := p.ValidateSpec(spec); err == nil || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("err = %v, want mid-chain payload rejection", err)
	}
}
