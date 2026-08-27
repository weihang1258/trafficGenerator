package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/vmess"
)

const testUUID = "12345678-1234-1234-1234-123456789012"

// 冒烟：vmess 终结层接入 [ip→tcp→vmess] 链。默认 DstPort 443（FieldContract
// tcp.dst_port=443）上包；request/response AEAD 帧序列事件经 tcp 层包装为
// PSH-ACK 数据段，含 TCP 握手（validator 校准
// spec.TCP.Handshake/Termination=true）。
func TestChainPlannerVmessSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		Vmess: &core.VmessConfig{UUID: testUUID, Port: 443},
	}
	v, err := layers.NewChainPlanner("vmess").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	if v.DstPort != 443 {
		t.Fatalf("DstPort=%d, want 443", v.DstPort)
	}
	ch, err := layers.NewChainPlanner("vmess").Plan(context.Background(), spec)
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
		t.Fatalf("vmess chain produced 0 packets")
	}
	if syn == 0 {
		t.Fatalf("vmess chain: no TCP SYN (handshake missing; validator must force Handshake=true)")
	}
	if psh == 0 {
		t.Fatalf("vmess chain: no data segments (request/response frames expected)")
	}
	t.Logf("vmess chain produced %d packets (%d SYN, %d data segments)", n, syn, psh)
}

// 冒烟：nil Vmess config → 校验拒绝（legacy 硬要求 spec.vmess）。
func TestChainPlannerVmessNilRejected(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
	_, err := layers.NewChainPlanner("vmess").Plan(context.Background(), spec)
	if err == nil {
		t.Fatalf("nil vmess config: expected validation error (legacy requires spec.vmess)")
	}
}

// 冒烟：vmess Command=0x02 (UDP) 在链上被拒绝（tcp 层无法发 VMess UDP 数据报）。
func TestChainPlannerVmessUDPModeRejected(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		Vmess: &core.VmessConfig{UUID: testUUID, Command: 2},
	}
	_, err := layers.NewChainPlanner("vmess").ValidateSpec(spec)
	if err == nil {
		t.Fatalf("vmess Command=0x02 (UDP): expected validation error")
	}
}
