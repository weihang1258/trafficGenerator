package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/redis"
)

// 冒烟：redis 终结层接入 [ip→tcp→redis] 链。默认 DstPort 6379（FieldContract
// tcp.dst_port=6379）上包；命令/回复逐帧事件经 tcp 层包装为 PSH-ACK 数据段，
// 含 TCP 握手（validator 校准 spec.TCP.Handshake/Termination=true）。
func TestChainPlannerRedisSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		Redis: &core.RedisConfig{
			Commands: []core.RedisCommand{
				{Args: []string{"PING"}, AutoReply: core.RedisAutoReplyPong},
			},
		},
	}
	v, err := layers.NewChainPlanner("redis").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	if v.DstPort != 6379 {
		t.Fatalf("DstPort=%d, want 6379", v.DstPort)
	}
	ch, err := layers.NewChainPlanner("redis").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, syn, psh := 0, 0, 0
	var payloads []string
	for p := range ch {
		n++
		if p.Direction == "up" && p.L4.Flags == layers.FlagSYN {
			syn++
		}
		if len(p.Payload) > 0 {
			psh++
			payloads = append(payloads, string(p.Payload))
		}
	}
	if n == 0 {
		t.Fatalf("redis chain produced 0 packets")
	}
	if syn == 0 {
		t.Fatalf("redis chain: no TCP SYN (handshake missing; validator must force Handshake=true)")
	}
	// PING 命令（up, *1\r\n$4\r\nPING\r\n）+ PONG 回复（down, +PONG\r\n）
	if psh < 2 {
		t.Fatalf("redis chain: got %d data segments, want >=2 (PING + PONG)", psh)
	}
	t.Logf("redis chain produced %d packets (%d SYN, %d data segments)", n, syn, psh)
}

// 冒烟：完全空 spec（Redis=nil）→ 默认 SelectDB=-1 + 默认命令（单 PING）。
// 验证生成器 nil 默认化（与 legacy Plan 同款），避免"校验通过但 0 包"空流。
func TestChainPlannerRedisNilConfigDefaultFlow(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
	}
	ch, err := layers.NewChainPlanner("redis").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, psh := 0, 0
	for p := range ch {
		n++
		if len(p.Payload) > 0 {
			psh++
		}
	}
	if n == 0 {
		t.Fatalf("nil redis config produced 0 packets; want default PING flow")
	}
	if psh < 2 {
		t.Fatalf("nil config: got %d data segments, want >=2 (default PING + PONG)", psh)
	}
}
