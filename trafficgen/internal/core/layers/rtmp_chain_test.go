package layers_test

// D-RTMP-1 P4 链级红例（failing 先行）：[ip→rtmp] raw 自驱链（裁定1，
// ldap 对称：legacy 自建 TCP 握手/分段原样 wrap，防双换 Direction=up）。
// 握手分段数=关键形状面：C0C1 1537B→2 段、S0S1S2 3073B→3 段、C2 1536B→2 段。

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 rtmp 包 init 注册 raw 链生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/rtmp"
)

func TestChainPlanner_RTMPRawChain(t *testing.T) {
	p := layers.NewChainPlannerFromChain("rtmp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		// 数值面经 JSON 往返（getInt float64 面，pppoe mustJSONMap 同口径）。
		{Name: "rtmp", Config: mustJSONMap(t, `{
			"command": "publish", "app": "live", "stream_name": "cam1",
			"data": [
				{"direction": "up", "msg_type": 8, "chunk_stream_id": 4, "payload": "audio-frame"},
				{"direction": "down", "msg_type": 9, "chunk_stream_id": 6, "payload": "video-frame"}
			]
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 1935}
	validated, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if validated.RTMP == nil {
		t.Fatalf("translate must populate spec.RTMP from the rtmp layer config")
	}
	if validated.RTMP.Command != "publish" || len(validated.RTMP.Data) != 2 {
		t.Fatalf("spec.RTMP not populated from layer: cmd=%q data=%d", validated.RTMP.Command, len(validated.RTMP.Data))
	}
	ch, err := p.Plan(context.Background(), validated)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	var flags []uint8
	for pkt := range ch {
		n++
		flags = append(flags, pkt.L4.Flags)
		if pkt.L4.Protocol != "tcp" {
			t.Fatalf("packet %d proto=%q want tcp", n, pkt.L4.Protocol)
		}
		if pkt.L4.DstPort != 1935 && pkt.L4.SrcPort != 1935 {
			t.Fatalf("packet %d ports %d->%d: 1935 must appear", n, pkt.L4.SrcPort, pkt.L4.DstPort)
		}
	}
	// publish 全会话形状：3 握手 + 握手段(2+3+2) + 命令面 + 2 数据段 +
	// 4 挥手——命令面段数以 legacy 实测钉（首跑探形后定值）。
	if flags[0] != 0x02 || flags[1] != 0x12 || flags[2] != 0x10 {
		t.Fatalf("handshake flags=%v want SYN/SYNACK/ACK", flags[:3])
	}
}

// 背 door 锚：链上 ValidateSpec 经 protocolValidator 调用 legacy Validate。
func TestChainPlanner_RTMPValidatorAnchors(t *testing.T) {
	p := layers.NewChainPlannerFromChain("rtmp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "rtmp", Config: mustJSONMap(t, `{"command": "pause"}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	_, err := p.ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "invalid Command") {
		t.Fatalf("want invalid Command anchor, got %v", err)
	}
}
