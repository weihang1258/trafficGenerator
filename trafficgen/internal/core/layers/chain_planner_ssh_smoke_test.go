package layers_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ssh"
)

// 冒烟：ssh 终结层接入 [ip→tcp→ssh] 链。默认 DstPort 22（FieldContract
// tcp.dst_port=22）上包；version exchange + KEXINIT/KEXDH + NEWKEYS + userauth
// + channel 逐 BPP 帧事件经 tcp 层包装为 PSH-ACK 数据段，含 TCP 握手（validator
// 校准 spec.TCP.Handshake/Termination=true）。
func TestChainPlannerSSHSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		SSH: &core.SSHConfig{
			Scenario:      "exec",
			ClientVersion: "SSH-2.0-trafficgen_test",
		},
	}
	v, err := layers.NewChainPlanner("ssh").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	if v.DstPort != 22 {
		t.Fatalf("DstPort=%d, want 22", v.DstPort)
	}
	ch, err := layers.NewChainPlanner("ssh").Plan(context.Background(), spec)
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
		t.Fatalf("ssh chain produced 0 packets")
	}
	if syn == 0 {
		t.Fatalf("ssh chain: no TCP SYN (handshake missing; validator must force Handshake=true)")
	}
	if psh == 0 {
		t.Fatalf("ssh chain: no data segments (version/KEXINIT/BPP frames expected)")
	}
	// SSH version exchange "SSH-2.0-" 前缀必须出现在数据流中。
	if !bytes.Contains(allPayload, []byte("SSH-2.0-")) {
		t.Fatalf("ssh chain: data stream does not contain SSH version prefix \"SSH-2.0-\"")
	}
	t.Logf("ssh chain produced %d packets (%d SYN, %d data segments)", n, syn, psh)
}

// 冒烟：完全空 spec（SSH=nil）→ 默认手动 auth/channel 流程。验证生成器 nil
// 默认化（与 legacy Plan 同款：&core.SSHConfig{}），避免"校验通过但 0 包"空流。
func TestChainPlannerSSHNilConfigDefaultFlow(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
	}
	ch, err := layers.NewChainPlanner("ssh").Plan(context.Background(), spec)
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
		t.Fatalf("nil ssh config produced 0 packets; want default auth flow")
	}
	if psh == 0 {
		t.Fatalf("nil config: got 0 data segments, want version + KEXINIT + auth frames")
	}
	// nil 配置（双向版本均空）→ legacy 跳版本交换，只产 BPP 帧（KEXINIT msg 20/21）。
	// 断言数据流含 BPP 帧：KEXINIT 首个字节是 SSH_MSG_KEXINIT (20) 但 BPP 有
	// packet_length 前缀，故直接断言数据流非空且有可解析 BPP 字节即可。
	if len(allPayload) < 32 {
		t.Fatalf("nil config: data stream too short (%d bytes), expected BPP frames", len(allPayload))
	}
}
