package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/rdp"
)

// 冒烟：rdp 终结层接入 [ip→tcp→rdp] 链。默认 DstPort 3389（FieldContract
// tcp.dst_port=3389）上包；X.224 CR/CC + MCS + security PDU 序列逐帧事件经 tcp
// 层包装为 PSH-ACK 数据段，含 TCP 握手（validator 校准
// spec.TCP.Handshake/Termination=true）。
func TestChainPlannerRDPSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		RDP: &core.RDPConfig{
			Scenario: "full_session",
		},
	}
	v, err := layers.NewChainPlanner("rdp").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	if v.DstPort != 3389 {
		t.Fatalf("DstPort=%d, want 3389", v.DstPort)
	}
	ch, err := layers.NewChainPlanner("rdp").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, syn, psh := 0, 0, 0
	var firstPayload []byte
	for p := range ch {
		n++
		if p.Direction == "up" && p.L4.Flags == layers.FlagSYN {
			syn++
		}
		if len(p.Payload) > 0 {
			psh++
			if firstPayload == nil {
				firstPayload = p.Payload
			}
		}
	}
	if n == 0 {
		t.Fatalf("rdp chain produced 0 packets")
	}
	if syn == 0 {
		t.Fatalf("rdp chain: no TCP SYN (handshake missing; validator must force Handshake=true)")
	}
	if psh == 0 {
		t.Fatalf("rdp chain: no data segments (X.224/MCS PDUs expected)")
	}
	// 首个数据段是 X.224 CR：TPKT 版本字节 0x03 + CR (0xE0) 或首字节 0x03。
	// X.224 Connection Request: TPKT header 0x03 0x00 <len> 0x02 0xF0 0x80 ...
	if len(firstPayload) < 5 || firstPayload[0] != 0x03 {
		t.Fatalf("rdp chain: first data segment does not begin with X.224 TPKT (0x03), got %x", firstPayload[:min(5, len(firstPayload))])
	}
	t.Logf("rdp chain produced %d packets (%d SYN, %d data segments)", n, syn, psh)
}

// 冒烟：rdp TLS 模式在链上被拒绝（tcp 层无法包裹 RDP PDU 于 TLS）。
func TestChainPlannerRDPTLSModeRejected(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		RDP: &core.RDPConfig{SecurityLayer: "tls"},
	}
	_, err := layers.NewChainPlanner("rdp").ValidateSpec(spec)
	if err == nil {
		t.Fatalf("rdp TLS mode: expected validation error (tcp layer cannot wrap RDP PDUs in TLS)")
	}
}

// 冒烟：nil RDP config → 校验拒绝（legacy 硬要求 spec.rdp）。
func TestChainPlannerRDPNilRejected(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
	_, err := layers.NewChainPlanner("rdp").Plan(context.Background(), spec)
	if err == nil {
		t.Fatalf("nil rdp config: expected validation error (legacy requires spec.rdp)")
	}
}
