package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/pop3"
)

// 冒烟：pop3 终结层接入 [ip→tcp→pop3] 链。默认 DstPort 110（FieldContract
// tcp.dst_port=110）上包；banner + 命令/响应对逐帧事件经 tcp 层包装为
// PSH-ACK 数据段，含 TCP 握手（validator 校准 Handshake/Termination=true）。
func TestChainPlannerPOP3Smoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		POP3: &core.POP3Config{
			Banner: "+OK POP3 server ready",
			Commands: []core.POP3Command{
				{Cmd: "USER alice", Response: "+OK"},
				{Cmd: "PASS secret", Response: "+OK"},
				{Cmd: "QUIT", Response: "+OK"},
			},
		},
	}
	v, err := layers.NewChainPlanner("pop3").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	if v.DstPort != 110 {
		t.Fatalf("DstPort=%d, want 110", v.DstPort)
	}
	ch, err := layers.NewChainPlanner("pop3").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, syn, upData, downData := 0, 0, 0, 0
	for p := range ch {
		n++
		if p.Direction == "up" && p.L4.Flags == layers.FlagSYN {
			syn++
		}
		if len(p.Payload) > 0 {
			if p.Direction == "up" {
				upData++
			} else {
				downData++
			}
		}
	}
	if n == 0 {
		t.Fatalf("pop3 chain produced 0 packets")
	}
	if syn == 0 {
		t.Fatalf("pop3 chain: no TCP SYN (validator must force Handshake=true)")
	}
	if upData != 3 || downData != 4 { // banner + 3 responses down；3 commands up
		t.Fatalf("pop3 chain: got %d up data / %d down data, want 3/4", upData, downData)
	}
}

// 冒烟：EmitMailDrop 合成路径——RETR 响应由 buildMailDropResponse 从
// Mailbox 合成（多行点填充体），而非用户 Response。
func TestChainPlannerPOP3MailDrop(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12346,
		POP3: &core.POP3Config{
			Mailbox: &core.POP3Mailbox{Messages: []core.POP3Message{
				{UID: "u1", Headers: []string{"From: a@b.c"}, Body: "hello"},
			}},
			Commands: []core.POP3Command{
				{Cmd: "RETR 1", EmitMailDrop: true, MsgNum: 1},
			},
		},
	}
	ch, err := layers.NewChainPlanner("pop3").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	var maildrop []byte
	for p := range ch {
		if p.Direction == "down" && len(p.Payload) > 0 {
			maildrop = append(maildrop[:0], p.Payload...)
		}
	}
	if len(maildrop) == 0 {
		t.Fatalf("maildrop chain produced no data")
	}
	if !bytesContains(maildrop, []byte("+OK ")) {
		t.Fatalf("maildrop response missing +OK status line: %q", string(maildrop))
	}
}

func bytesContains(b, sub []byte) bool {
	for i := 0; i+len(sub) <= len(b); i++ {
		match := true
		for j := range sub {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
