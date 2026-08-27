package layers_test

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/imap"
)

// 冒烟：imap 终结层接入 [ip→tcp→imap] 链。默认 DstPort 143（FieldContract
// tcp.dst_port=143）上包；greeting + 命令/响应逐帧事件经 tcp 层包装，
// 含 TCP 握手（validator 校准 Handshake/Termination=true）。
func TestChainPlannerIMAPSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		IMAP: &core.IMAPConfig{
			Banner: "* OK IMAP4rev1 ready",
			Commands: []core.IMAPCommand{
				{Tag: "A001", Cmd: "LOGIN alice secret", Responses: []string{"A001 OK LOGIN completed"}},
				{Cmd: "NOOP", Responses: []string{"A002 OK NOOP completed"}}, // 空 Tag 自动 A002
			},
		},
	}
	v, err := layers.NewChainPlanner("imap").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	if v.DstPort != 143 {
		t.Fatalf("DstPort=%d, want 143", v.DstPort)
	}
	ch, err := layers.NewChainPlanner("imap").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, syn, upData, downData := 0, 0, 0, 0
	var upPayloads []string
	for p := range ch {
		n++
		if p.Direction == "up" && p.L4.Flags == layers.FlagSYN {
			syn++
		}
		if len(p.Payload) > 0 {
			if p.Direction == "up" {
				upData++
				upPayloads = append(upPayloads, string(p.Payload))
			} else {
				downData++
			}
		}
	}
	if n == 0 {
		t.Fatalf("imap chain produced 0 packets")
	}
	if syn == 0 {
		t.Fatalf("imap chain: no TCP SYN (validator must force Handshake=true)")
	}
	// greeting(down) + 2 commands(up) + 2 responses(down)
	if upData != 2 || downData != 3 {
		t.Fatalf("imap chain: got %d up / %d down data, want 2/3", upData, downData)
	}
	// 自动 tag（空 Tag 的第二条命令：autoTagCounter 从 1 起 → A001，与
	// legacy 同款——与用户显式 tag 撞名是用户责任，planner 不校验）。
	joined := strings.Join(upPayloads, "|")
	if !strings.Contains(joined, "A001 LOGIN alice secret") || !strings.Contains(joined, "A001 NOOP") {
		t.Fatalf("tag format wrong: %q", joined)
	}
}

// 冒烟：literal {N} 占位路径——FETCH 响应的 {100} 被替换为实际长度 +
// literal 体逐帧发出（RFC 9051 §2.2.4 literal wire 格式）。
func TestChainPlannerIMAPLiteral(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12346,
		IMAP: &core.IMAPConfig{
			Commands: []core.IMAPCommand{
				{
					Cmd:       "FETCH 1 BODY[]",
					Responses: []string{"* 1 FETCH (BODY[] {5})"},
					LiteralBody: "hello",
				},
			},
		},
	}
	ch, err := layers.NewChainPlanner("imap").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	var literalSeen bool
	for p := range ch {
		if p.Direction == "down" && string(p.Payload) == "hello" {
			literalSeen = true
		}
	}
	if !literalSeen {
		t.Fatalf("literal body 'hello' not emitted as a frame")
	}
}

// 冒烟：IDLE 模式（RFC 2177）——IDLE → + idling → push → DONE → done。
func TestChainPlannerIMAPIDLE(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12347,
		IMAP: &core.IMAPConfig{
			IDLE: &core.IMAPIDLE{
				PushResponses: []string{"* 37 EXISTS"},
				DoneResponse:  "A001 OK IDLE terminated",
			},
			Commands: []core.IMAPCommand{{Tag: "A001", EmitIDLE: true}},
		},
	}
	ch, err := layers.NewChainPlanner("imap").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	var idleCmd, cont, push, done bool
	for p := range ch {
		s := string(p.Payload)
		switch {
		case p.Direction == "up" && s == "A001 IDLE\r\n":
			idleCmd = true
		case p.Direction == "down" && s == "+ idling\r\n":
			cont = true
		case p.Direction == "down" && s == "* 37 EXISTS\r\n":
			push = true
		case p.Direction == "up" && s == "DONE\r\n":
			done = true
		}
	}
	if !idleCmd || !cont || !push || !done {
		t.Fatalf("IDLE sequence incomplete: cmd=%v cont=%v push=%v done=%v", idleCmd, cont, push, done)
	}
}
