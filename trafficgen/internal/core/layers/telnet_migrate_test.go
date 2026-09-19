package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/telnet" // init 注册 telnet 层生成器 + 校验器
)

// D-TELNET-1 §4 红例①②③④（failing 先行，P-PIPE #18 P4）。
// 实现前预期：①红（CheckProtoFlat 无 telnet presence 分支）；②红
// （registry 无 telnet 行，V9 拒 unknown layer）；③红（translate 无 case
// + 生成器未注册）；④红（translate 不落 spec.TELNET → 恒 nil）。

func telnetChain(t *testing.T, telnetCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	layers_ := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"telnet": telnetCfg},
	}
	out, _ := json.Marshal(layers_)
	return out
}

// 红例①【D-TELNET-1 §2】：顶层 telnet 子映射 presence 判死——空 map 也死。
func TestTelnetChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
			map[string]interface{}{"telnet": map[string]interface{}{}},
		},
		"telnet": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("telnet", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(telnet, {layers, telnet:{}}) = \"\", want top-level telnet presence rejection")
	} else if !strings.Contains(msg, "top-level telnet sub-config") {
		t.Fatalf("anchor mismatch: %q", msg)
	}
}

// 红例②【D-TELNET-1 §1】：telnet 层 14 键 V9 放行（registry 无行 → 实现
// 前整层 unknown）。业务 10 键（banner/dialog/terminal_type/window_cols/
// window_rows/file_source/scenario/username/password/commands）+ 端口 2 键。
func TestTelnetChain_LayerFieldsAccepted(t *testing.T) {
	raw := telnetChain(t, map[string]interface{}{
		"src_port":      12345,
		"dst_port":      23,
		"banner":        "Welcome\r\n",
		"terminal_type": "xterm-256color",
		"window_cols":   120,
		"window_rows":   40,
		"scenario":      "login_full",
		"username":      "alice",
		"password":      "secret123",
		"commands":      []interface{}{"uname", "pwd"},
		"dialog": []interface{}{
			map[string]interface{}{"type": "data", "direction": "down", "data": "login: "},
		},
		"file_source": map[string]interface{}{
			"file_source": "/tmp/telnet-payload.txt",
		},
	})
	if _, err := layers.ValidateLayers(raw, "telnet"); err != nil {
		t.Fatalf("ValidateLayers: %v", err)
	}
}

// 红例③【D-TELNET-1 §3】：translate + 生成器上线——[ip,telnet] 链最小
// 13 包（3 握手 + defaultDialog 6 事件 + 4 挥手）。legacy 输出
// L4.Protocol="tcp"、事件字节在 Payload（telnet.go:227-271 emit 合同）。
func TestTelnetChain_LayerTranslateMinimalDialog(t *testing.T) {
	p := layers.NewChainPlannerFromChain("telnet", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "telnet", Config: map[string]interface{}{
			"src_port": 12345, "dst_port": 23,
		}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// flags 序：SYN/SYN-ACK/ACK + will/do/login/alice/$/exit + FIN/ACK/FIN/ACK
	wantFlags := []uint8{0x02, 0x12, 0x10, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x11, 0x10, 0x11, 0x10}
	// 方向面：up 包 dst=23（服务端口），down 包 dst=12345（客户端口，
	// legacy 逐 emit 自换——defaultDialog 事件序 will↓/do↑/login↓/alice↑/
	// $↓/exit↑，emit 调用序 telnet.go:283-339 实钉）。
	wantDst := []uint16{23, 12345, 23, 12345, 23, 12345, 23, 12345, 23, 23, 12345, 12345, 23}
	// 事件字节面（defaultDialog 前两事件：IAC WILL SGA / IAC DO SGA）
	wantPayload := [][]byte{{0xff, 0xfb, 0x03}, {0xff, 0xfd, 0x03}}
	n := 0
	for pkt := range ch {
		if n >= len(wantFlags) {
			t.Fatalf("packet overflow: got >%d packets", len(wantFlags))
		}
		if pkt.L4.Protocol != "tcp" {
			t.Fatalf("packet %d: L4.Protocol=%q want tcp", n+1, pkt.L4.Protocol)
		}
		if pkt.L4.Flags != wantFlags[n] {
			t.Fatalf("packet %d: flags=0x%x want 0x%x (TCP lifecycle order)", n+1, pkt.L4.Flags, wantFlags[n])
		}
		if pkt.L4.DstPort != wantDst[n] {
			t.Fatalf("packet %d: dstPort=%d want %d (legacy self-managed direction)", n+1, pkt.L4.DstPort, wantDst[n])
		}
		if n == 3 || n == 4 {
			if string(pkt.Payload) != string(wantPayload[n-3]) {
				t.Fatalf("packet %d: IAC bytes=%x want %x", n+1, pkt.Payload, wantPayload[n-3])
			}
		}
		n++
	}
	if n != len(wantFlags) {
		t.Fatalf("packets=%d want %d (3 handshake + 6 dialog + 4 teardown)", n, len(wantFlags))
	}
}

// 红例④【D-TELNET-1 决策 C】：translate 把层 config 填进 spec.TELNET——
// 经 ValidateSpec 后 spec.TELNET 非 nil 且业务键逐槽映射（实现前恒 nil =
// defaultDialog 静默）。dialog 列表与 file_source object 直迁证通路。
func TestTelnetChain_PresenceFilled(t *testing.T) {
	p := layers.NewChainPlannerFromChain("telnet", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "telnet", Config: map[string]interface{}{
			"banner":        "Welcome\r\n",
			"terminal_type": "vt100",
			"window_cols":   120,
			"window_rows":   40,
			"scenario":      "login_full",
			"username":      "bob",
			"password":      "pw123",
			"commands":      []interface{}{"uname", "pwd"},
			"dialog": []interface{}{
				map[string]interface{}{"type": "data", "direction": "up", "data": "hello"},
			},
		}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	out, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if out.Telnet == nil {
		t.Fatal("spec.TELNET must be translated from the layer config")
	}
	g := out.Telnet
	if g.Banner != "Welcome\r\n" || g.TerminalType != "vt100" || g.WindowCols != 120 || g.WindowRows != 40 {
		t.Fatalf("business keys not mapped: %+v", g)
	}
	if g.Scenario != "login_full" || g.Username != "bob" || g.Password != "pw123" {
		t.Fatalf("scenario keys not mapped: %+v", g)
	}
	if len(g.Commands) != 2 || g.Commands[0] != "uname" || g.Commands[1] != "pwd" {
		t.Fatalf("commands not mapped: %+v", g.Commands)
	}
	if len(g.Dialog) != 1 || g.Dialog[0].Type != "data" || g.Dialog[0].Direction != "up" || g.Dialog[0].Data != "hello" {
		t.Fatalf("dialog not drilled: %+v", g.Dialog)
	}
}
