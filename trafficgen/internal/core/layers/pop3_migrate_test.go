package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/pop3" // init 注册 pop3 终结层生成器
)

// D-POP3-1 步骤 0 红例族（failing 先行，2026-09-17，smtp_migrate_test.go 同款）。
// 实现前预期：①红（presence 未判死，放行）；②红（setDefaultDstPort(110)
// 未调，DstPort 保持 0）；③绿（翻译分支已齐，本例锁回归——若红说明有人动了分支）。

func pop3MigrateChain(t *testing.T, pop3Cfg map[string]interface{}) json.RawMessage {
	t.Helper()
	chain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 13000, "dst_port": 110}},
		map[string]interface{}{"pop3": pop3Cfg},
	}
	out, _ := json.Marshal(chain)
	return out
}

func firstPOP3BannerPayload(t *testing.T, p core.ProtocolPlanner, spec core.FlowSpec) []byte {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for pkt := range ch {
		if pkt.L4.Protocol == "tcp" && pkt.Direction == "down" && len(pkt.Payload) > 0 {
			if pkt.L4.Flags != 0x18 {
				continue
			}
			return pkt.Payload
		}
	}
	return nil
}

// 红例1【D-POP3-1 §1/§5】：顶层 pop3 子映射 presence 判死——空 map 也死
// （mqtt/dns/smtp 先例）。现状：放行。
func TestPOP3Chain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"tcp": map[string]interface{}{}},
			map[string]interface{}{"pop3": map[string]interface{}{}},
		},
		"pop3": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("pop3", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(pop3, {layers, pop3:{}}) = \"\", want top-level pop3 presence rejection")
	}
	if msg := core.CheckProtoFlat("pop3", cfg); !strings.Contains(msg, "no longer accepts a top-level pop3 sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q, want sub-anchor `no longer accepts a top-level pop3 sub-config`", msg)
	}
}

// 红例2【D-POP3-1 §1】：扁平无端口时 DstPort 缺省 110（现状：注释写默认
// 110，实际未调 setDefaultDstPort，spec.DstPort 保持 0）。
func TestPOP3Flat_DefaultDstPort110(t *testing.T) {
	spec := core.MapToFlowSpec(map[string]interface{}{"pop3": map[string]interface{}{}}, "pop3")
	if len(spec.ValidationErrors) > 0 {
		t.Fatalf("MapToFlowSpec validation errors: %v", spec.ValidationErrors)
	}
	if spec.DstPort != 110 {
		t.Fatalf("DstPort = %d, want 110 (flat pop3 without dst_port must default per RFC 1939 §6)", spec.DstPort)
	}
}

// 绿例（回归锁）【D-POP3-1 §1】：层 mailbox 翻译进 spec.POP3（翻译分支已齐；
// 若本例红，说明有人动了 translateTerminalConfig pop3 分支）。
func TestPOP3Chain_LayerMailboxTranslates(t *testing.T) {
	raw := pop3MigrateChain(t, map[string]interface{}{
		"banner": "+OK POP3 server ready",
		"mailbox": map[string]interface{}{
			"messages": []interface{}{
				map[string]interface{}{
					"uid":     "uid-1",
					"headers": []interface{}{"From: a@b.c"},
					"body":    "hello",
				},
			},
		},
		"commands": []interface{}{
			map[string]interface{}{"cmd": "RETR 1", "emit_mail_drop": true, "msg_num": 1},
		},
	})
	p, err := layers.BuildLayersPlanner("pop3", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 13000, DstPort: 110}
	payload := firstPOP3BannerPayload(t, p, spec)
	if payload == nil {
		t.Fatal("Plan produced no POP3 banner frame, want +OK greeting")
	}
	if !strings.HasPrefix(string(payload), "+OK POP3 server ready") {
		t.Fatalf("banner = %q, want layer value `+OK POP3 server ready` (layer config must translate into spec.POP3)", payload)
	}
}
