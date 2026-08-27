package layers_test

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/grpc"
)

// 冒烟：grpc 终结层接入 [ip→tcp→grpc] 链。默认 DstPort 8604（FieldContract
// tcp.dst_port=8604）上包；HTTP/2 preface + SETTINGS + 逐 call HEADERS/DATA/
// trailers 逐帧事件经 tcp 层包装为 PSH-ACK 数据段，含 TCP 握手（validator
// 校准 spec.TCP.Handshake/Termination=true）。
func TestChainPlannerGRPCSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		GRPC: &core.GRPCConfig{
			Service:         "telemetry.Telemetry",
			Method:          "Subscribe",
			RequestMessages: [][]byte{{0x0a, 0x01, 0x01}},
		},
	}
	v, err := layers.NewChainPlanner("grpc").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	if v.DstPort != 8604 {
		t.Fatalf("DstPort=%d, want 8604", v.DstPort)
	}
	ch, err := layers.NewChainPlanner("grpc").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, syn, psh := 0, 0, 0
	var allPayload []byte
	for p := range ch {
		n++
		if p.Direction == "up" && p.L4.Flags == layers.FlagSYN {
			syn++
		}
		if len(p.Payload) > 0 {
			psh++
			allPayload = append(allPayload, p.Payload...)
		}
	}
	if n == 0 {
		t.Fatalf("grpc chain produced 0 packets")
	}
	if syn == 0 {
		t.Fatalf("grpc chain: no TCP SYN (handshake missing; validator must force Handshake=true)")
	}
	if psh == 0 {
		t.Fatalf("grpc chain: no data segments (preface/frames expected)")
	}
	// HTTP/2 connection preface magic必须出现在 up 数据段中。
	if !strings.HasPrefix(string(allPayload), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
		t.Fatalf("grpc chain: data stream does not begin with HTTP/2 preface magic")
	}
	t.Logf("grpc chain produced %d packets (%d SYN, %d data segments)", n, syn, psh)
}

// 冒烟：完全空 spec（GRPC=nil）→ 默认单 unary 零消息 call 流程。验证生成器
// nil 默认化（与 legacy Plan 同款：&core.GRPCConfig{}），避免"校验通过但 0 包"
// 空流。
func TestChainPlannerGRPCNilConfigDefaultFlow(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
	}
	ch, err := layers.NewChainPlanner("grpc").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, psh := 0, 0
	var allPayload []byte
	for p := range ch {
		n++
		if len(p.Payload) > 0 {
			psh++
			allPayload = append(allPayload, p.Payload...)
		}
	}
	if n == 0 {
		t.Fatalf("nil grpc config produced 0 packets; want default call flow")
	}
	if psh == 0 {
		t.Fatalf("nil config: got 0 data segments, want preface + settings + frames")
	}
	if !strings.HasPrefix(string(allPayload), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
		t.Fatalf("nil config: data stream does not begin with HTTP/2 preface magic")
	}
}
