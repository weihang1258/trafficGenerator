package layers_test

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mysql"
)

// 冒烟：mysql 终结层接入 [ip→tcp→mysql] 链。默认 DstPort 3306（FieldContract
// tcp.dst_port=3306）上包；Greeting → auth → 命令逐帧事件经 tcp 层包装，
// 含 TCP 握手（validator 校准 Handshake/Termination=true）。
func TestChainPlannerMySQLSmoke(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345,
		MySQL: &core.MySQLConfig{
			Username: "root",
			Commands: []core.MySQLCommand{
				{Opcode: 0x01, Body: ""}, // COM_QUIT
			},
		},
	}
	v, err := layers.NewChainPlanner("mysql").ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec err: %v", err)
	}
	if v.DstPort != 3306 {
		t.Fatalf("DstPort=%d, want 3306", v.DstPort)
	}
	ch, err := layers.NewChainPlanner("mysql").Plan(context.Background(), spec)
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
		t.Fatalf("mysql chain produced 0 packets")
	}
	if syn == 0 {
		t.Fatalf("mysql chain: no TCP SYN (validator must force Handshake=true)")
	}
	// up: handshake response + 1 command；down: greeting + auth OK + 1 reply
	if upData != 2 || downData != 3 {
		t.Fatalf("mysql chain: got %d up / %d down data, want 2/3", upData, downData)
	}
}

// 冒烟：空 MySQLConfig 默认流——Greeting + auth 但无命令（ServerBypassAuth
// 默认 false → auth 往返）。验证 nil config 默认化不与空流。
func TestChainPlannerMySQLDefaultFlow(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12346}
	ch, err := layers.NewChainPlanner("mysql").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	n, upData := 0, 0
	for p := range ch {
		n++
		if len(p.Payload) > 0 && p.Direction == "up" {
			upData++
		}
	}
	if n == 0 {
		t.Fatalf("nil mysql config produced 0 packets")
	}
	if upData < 1 { // handshake response (auth) 至少 1 up
		t.Fatalf("default flow: got %d up data, want >=1 (auth handshake response)", upData)
	}
}

// 冒烟：ServerBypassAuth 跳过 auth 往返——只 greeting + commands。
func TestChainPlannerMySQLBypassAuth(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12347,
		MySQL: &core.MySQLConfig{
			ServerBypassAuth: true,
			Commands: []core.MySQLCommand{{Opcode: 0x0e, Body: "SHOW DATABASES"}},
		},
	}
	ch, err := layers.NewChainPlanner("mysql").Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err: %v", err)
	}
	upData, downData := 0, 0
	var upBytes []string
	for p := range ch {
		if len(p.Payload) > 0 {
			if p.Direction == "up" {
				upData++
				upBytes = append(upBytes, string(p.Payload))
			} else {
				downData++
			}
		}
	}
	// up: 仅 1 命令（无 handshake response）；down: greeting + 1 reply
	if upData != 1 || downData != 2 {
		t.Fatalf("bypass-auth: got %d up / %d down data, want 1/2", upData, downData)
	}
	joined := strings.Join(upBytes, "|")
	if !strings.Contains(joined, "\x0e") {
		t.Fatalf("command opcode 0x0e missing from up frames: %q", joined)
	}
}
