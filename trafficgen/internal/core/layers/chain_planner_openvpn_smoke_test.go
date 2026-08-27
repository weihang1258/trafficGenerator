package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/openvpn"
)

// 冒烟：openvpn 终结层接入 [ip→udp→openvpn] 链。默认 DstPort 1194（FieldContract
// udp.dst_port=1194）上包；P_CONTROL_RESET/P_DATA 数据报序列逐事件（tftp
// 重放模式，生成器复用 legacy Plan）。UDP 无握手，不校验 TCP
// Handshake/Termination。
func TestChainPlannerOpenVPNSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		OpenVPN: &core.OpenVPNConfig{},
	}
	v, err := layers.NewChainPlanner("openvpn").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	if v.DstPort != 1194 {
		t.Fatalf("DstPort=%d, want 1194", v.DstPort)
	}
	ch, err := layers.NewChainPlanner("openvpn").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, up := 0, 0
	var upPort uint16
	for p := range ch {
		n++
		if p.L4.Protocol != "udp" {
			t.Fatalf("L4.Protocol=%s, want udp", p.L4.Protocol)
		}
		if p.Direction == "up" {
			up++
			upPort = p.L4.DstPort
		}
	}
	if n == 0 {
		t.Fatalf("openvpn chain produced 0 packets")
	}
	if up == 0 {
		t.Fatalf("openvpn chain: no up packets")
	}
	if upPort != 1194 {
		t.Fatalf("up packet DstPort=%d, want 1194 (FieldContract default)", upPort)
	}
	t.Logf("openvpn chain produced %d packets (%d up)", n, up)
}

// 冒烟：nil OpenVPN config → 校验拒绝（legacy 硬要求 spec.openvpn）。
func TestChainPlannerOpenVPNNilRejected(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
	_, err := layers.NewChainPlanner("openvpn").Plan(context.Background(), spec)
	if err == nil {
		t.Fatalf("nil openvpn config: expected validation error (legacy requires spec.openvpn)")
	}
}

// 冒烟：openvpn proto=tcp 在链上被拒绝（udp 层无法做 OpenVPN-over-TCP 帧前缀+TLS）。
func TestChainPlannerOpenVPNTCPModeRejected(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		OpenVPN: &core.OpenVPNConfig{Proto: "tcp"},
	}
	_, err := layers.NewChainPlanner("openvpn").ValidateSpec(spec)
	if err == nil {
		t.Fatalf("openvpn proto=tcp: expected validation error (udp layer cannot do OpenVPN-over-TCP framing + TLS)")
	}
}
