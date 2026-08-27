package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/gtp"
)

// 冒烟：gtp 终结层接入 [ip→udp→gtp] 链。GTP-U 默认端口 2152（Mode=u）。
// GTP header + 内层 IP 包逐数据报事件（tftp 重放模式，生成器复用 legacy
// Plan）。UDP 无握手。
func TestChainPlannerGTPSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 0,
		GTP: &core.GTPConfig{Mode: "u", Version: 1, TEID: 0x1234},
	}
	// 端口留空：gtp 的 dst 由 Plan 按 Mode 默认 2152（无 FieldContract）。
	ch, err := layers.NewChainPlanner("gtp").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, up, down := 0, 0, 0
	var dstPort uint16
	for p := range ch {
		n++
		if p.L4.Protocol != "udp" {
			t.Fatalf("L4.Protocol=%s, want udp", p.L4.Protocol)
		}
		dstPort = p.L4.DstPort
		if p.Direction == "up" {
			up++
		} else {
			down++
		}
	}
	if n == 0 {
		t.Fatalf("gtp chain produced 0 packets")
	}
	if dstPort != 2152 {
		t.Fatalf("GTP-U DstPort=%d, want 2152 (Plan 内按 Mode=u 默认)", dstPort)
	}
	t.Logf("gtp chain produced %d packets (up=%d down=%d @2152)", n, up, down)
}

// 冒烟：GTP-C 模式（Mode=c）端口 2123（TS 29.060 §6）。
func TestChainPlannerGTPCSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 0,
		GTP: &core.GTPConfig{Mode: "c", Version: 1},
	}
	ch, err := layers.NewChainPlanner("gtp").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, dstPort := 0, uint16(0)
	for p := range ch {
		n++
		dstPort = p.L4.DstPort
	}
	if n == 0 {
		t.Fatalf("gtp-c chain produced 0 packets")
	}
	if dstPort != 2123 {
		t.Fatalf("GTP-C DstPort=%d, want 2123", dstPort)
	}
}

// 冒烟：nil GTP config → 校验拒绝（legacy 硬要求 spec.gtp）。
func TestChainPlannerGTPNilRejected(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 2123}
	_, err := layers.NewChainPlanner("gtp").Plan(context.Background(), spec)
	if err == nil {
		t.Fatalf("nil gtp config: expected validation error (legacy requires spec.gtp)")
	}
}
