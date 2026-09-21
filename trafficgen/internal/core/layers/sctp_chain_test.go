package layers_test

// D-SCTP-1 P4 链级红例：[ip→sctp] raw 自驱链（七连协议对称：legacy 全消息
// 面 wrap，防双换 Direction=up）。SCTP 自成 L4（IP proto 132），端口住
// sctp 层（1.12 立项补位：src_port/dst_port 字段+translate 回填 spec），
// 无协议级缺省（flat 同口径）。4 锚背 door 由 validator 承接。

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 sctp 包 init 注册 raw 链生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/sctp"
)

func TestChainPlanner_SCTPRawChain(t *testing.T) {
	p := layers.NewChainPlannerFromChain("sctp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		// 数值面经 JSON 往返（mustJSONMap 同口径）；data 字符串形由扁平
		// parse 承接（chunks[].data 双形 string/字节数组）。
		{Name: "sctp", Config: mustJSONMap(t, `{
			"src_port": 12345, "dst_port": 38412,
			"chunks": [{"direction": "down", "ppid": 60, "data": "hello"}]
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	validated, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if validated.SCTP == nil {
		t.Fatalf("translate must populate spec.SCTP from the sctp layer config")
	}
	if len(validated.SCTP.Chunks) != 1 || validated.SCTP.Chunks[0].PPID != 60 {
		t.Fatalf("chunks not populated: %+v", validated.SCTP.Chunks)
	}
	// 端口回填（1.12 补位）：sctp 层显式 dst_port 覆盖框架缺省 80。
	if validated.DstPort != 38412 || validated.SrcPort != 12345 {
		t.Fatalf("ports not backfilled from sctp layer: src=%d dst=%d", validated.SrcPort, validated.DstPort)
	}
	ch, err := p.Plan(context.Background(), validated)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	for pkt := range ch {
		n++
		if pkt.L4.Protocol != "sctp" {
			t.Fatalf("packet %d proto=%q want sctp", n, pkt.L4.Protocol)
		}
		if pkt.L4.DstPort != 38412 && pkt.L4.SrcPort != 38412 {
			t.Fatalf("packet %d ports %d->%d: 38412 must appear", n, pkt.L4.SrcPort, pkt.L4.DstPort)
		}
	}
	// 基线关联：4 握手+1 DATA+3 SHUTDOWN=8（与 suite T-3 同源互证）。
	if n != 8 {
		t.Fatalf("packets=%d want 8 (4 hs + 1 DATA + 3 shutdown)", n)
	}
}

// 背 door 锚：链上 ValidateSpec 经 protocolValidator 调用 legacy Validate。
func TestChainPlanner_SCTPValidatorAnchors(t *testing.T) {
	p := layers.NewChainPlannerFromChain("sctp", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "sctp", Config: mustJSONMap(t, `{
			"heartbeats": {"alt_path": {"alt_src_ip": "2e01::46"}}
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	_, err := p.ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "only IPv4 multi-homing") {
		t.Fatalf("want AltPath IPv6 anchor, got %v", err)
	}
}
