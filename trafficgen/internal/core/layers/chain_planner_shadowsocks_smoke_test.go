package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/shadowsocks"
)

// 冒烟：shadowsocks 终结层接入 [ip→tcp→shadowsocks] 链。默认 DstPort 8388
// （FieldContract tcp.dst_port=8388）上包；salt + AEAD chunk 帧序列事件经 tcp
// 层包装为 PSH-ACK 数据段，含 TCP 握手（validator 校准
// spec.TCP.Handshake/Termination=true）。
func TestChainPlannerShadowsocksSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		Shadowsocks: &core.ShadowsocksConfig{},
	}
	v, err := layers.NewChainPlanner("shadowsocks").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	if v.DstPort != 8388 {
		t.Fatalf("DstPort=%d, want 8388", v.DstPort)
	}
	ch, err := layers.NewChainPlanner("shadowsocks").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, syn, psh := 0, 0, 0
	for p := range ch {
		n++
		if p.Direction == "up" && p.L4.Flags == layers.FlagSYN {
			syn++
		}
		if len(p.Payload) > 0 {
			psh++
		}
	}
	if n == 0 {
		t.Fatalf("shadowsocks chain produced 0 packets")
	}
	if syn == 0 {
		t.Fatalf("shadowsocks chain: no TCP SYN (handshake missing; validator must force Handshake=true)")
	}
	if psh == 0 {
		t.Fatalf("shadowsocks chain: no data segments (salt/chunk frames expected)")
	}
	t.Logf("shadowsocks chain produced %d packets (%d SYN, %d data segments)", n, syn, psh)
}

// 冒烟：nil Shadowsocks config → 校验拒绝（legacy 硬要求 spec.shadowsocks）。
func TestChainPlannerShadowsocksNilRejected(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
	_, err := layers.NewChainPlanner("shadowsocks").Plan(context.Background(), spec)
	if err == nil {
		t.Fatalf("nil shadowsocks config: expected validation error (legacy requires spec.shadowsocks)")
	}
}

// 冒烟：shadowsocks Mode=udp 在链上被拒绝（tcp 层无法发 Shadowsocks UDP 数据报）。
func TestChainPlannerShadowsocksUDPModeRejected(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		Shadowsocks: &core.ShadowsocksConfig{Mode: "udp"},
	}
	_, err := layers.NewChainPlanner("shadowsocks").ValidateSpec(spec)
	if err == nil {
		t.Fatalf("shadowsocks Mode=udp: expected validation error")
	}
}
