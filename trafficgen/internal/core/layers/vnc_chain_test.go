package layers_test

// D-VNC-1 P4 链级红例：[ip→vnc] raw 自驱链（五连协议对称：legacy 自建
// TCP 握手/挥手 wrap，防双换 Direction=up）。控制通道 5900 由 legacy
// Plan :561 缺省。13 锚背 door 由 validator 承接。

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 vnc 包 init 注册 raw 链生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/vnc"
)

func TestChainPlanner_VNCRawChain(t *testing.T) {
	p := layers.NewChainPlannerFromChain("vnc", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		// 数值面经 JSON 往返（getIntPresence float64 面，mustJSONMap 同口径）。
		{Name: "vnc", Config: mustJSONMap(t, `{
			"initial_fbu": [
				{"x": 0, "y": 1, "width": 12, "height": 19, "encoding": "xcursor"},
				{"x": 0, "y": 0, "width": 12, "height": 19, "encoding": "hextile"}
			],
			"update_rects": [
				{"x": 0, "y": 0, "width": 12, "height": 19, "encoding": "hextile"}
			],
			"rounds": 1
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
	validated, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if validated.VNC == nil {
		t.Fatalf("translate must populate spec.VNC from the vnc layer config")
	}
	// parse 缺省面（getIntPresence：显式 0 保留，缺省在 parse 落）。
	if validated.VNC.SecurityType != 16 || validated.VNC.Rounds != 1 || validated.VNC.Width != 1024 {
		t.Fatalf("parse defaults lost: sec=%d rounds=%d width=%d", validated.VNC.SecurityType, validated.VNC.Rounds, validated.VNC.Width)
	}
	ch, err := p.Plan(context.Background(), validated)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	for pkt := range ch {
		n++
		if pkt.L4.Protocol != "tcp" {
			t.Fatalf("packet %d proto=%q want tcp", n, pkt.L4.Protocol)
		}
		if pkt.L4.DstPort != 5900 && pkt.L4.SrcPort != 5900 {
			t.Fatalf("packet %d ports %d->%d: 5900 must appear", n, pkt.L4.SrcPort, pkt.L4.DstPort)
		}
	}
	// 冒烟形包数以 legacy 实测钉（33 帧=3 握手+13 握手消息+客户端消息
	// 面+FBU 循环+4 拆链；与 suite T-1 同 config 同源互证）。
	if n != 33 {
		t.Fatalf("packets=%d want 33 (smoke shape)", n)
	}
}

// 背 door 锚：链上 ValidateSpec 经 protocolValidator 调用 legacy Validate。
func TestChainPlanner_VNCValidatorAnchors(t *testing.T) {
	p := layers.NewChainPlannerFromChain("vnc", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "vnc", Config: mustJSONMap(t, `{"security_type": 7}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	_, err := p.ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "invalid vnc security type") {
		t.Fatalf("want security-type anchor, got %v", err)
	}
}
