package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/imap" // 显式导入：用 DefaultPort 断言缺省口径（init 注册终结层生成器同款生效）
)

// D-IMAP-1 步骤 0 红例族（failing 先行，2026-09-17，pop3_migrate_test.go 同款）。
// 实现前预期：①红（presence 未判死，放行）；②红（setDefaultDstPort(143)
// 未调，DstPort 落通用缺省 80）；③红（registry imap 零 Fields）；④红
// （无 translateTerminalConfig imap 分支——③先拦 unknown field；即便绕过，
// 层 banner 也进不了 spec.IMAP，生成器走默认空会话）。

func imapMigrateChain(t *testing.T, imapCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	chain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 14000, "dst_port": 143}},
		map[string]interface{}{"imap": imapCfg},
	}
	out, _ := json.Marshal(chain)
	return out
}

func firstIMAPBannerPayload(t *testing.T, p core.ProtocolPlanner, spec core.FlowSpec) []byte {
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

// 红例1【D-IMAP-1 §1/§5】：顶层 imap 子映射 presence 判死——空 map 也死
// （mqtt/dns/smtp/pop3 先例）。现状：放行。
func TestIMAPChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"tcp": map[string]interface{}{}},
			map[string]interface{}{"imap": map[string]interface{}{}},
		},
		"imap": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("imap", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(imap, {layers, imap:{}}) = \"\", want top-level imap presence rejection")
	}
	if msg := core.CheckProtoFlat("imap", cfg); !strings.Contains(msg, "rejects a top-level imap sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q, want sub-anchor `rejects a top-level imap sub-config`", msg)
	}
}

// 红例2【D-IMAP-1 §1】：扁平无端口时 DstPort 缺省 143（现状：无
// setDefaultDstPort 调用，spec.DstPort 落通用缺省 80）。
func TestIMAPFlat_DefaultDstPort143(t *testing.T) {
	spec := core.MapToFlowSpec(map[string]interface{}{"imap": map[string]interface{}{}}, "imap")
	if len(spec.ValidationErrors) > 0 {
		t.Fatalf("MapToFlowSpec validation errors: %v", spec.ValidationErrors)
	}
	if spec.DstPort != uint16(imap.DefaultPort) {
		t.Fatalf("DstPort = %d, want %d (flat imap without dst_port must default per RFC 9051 §2.1)", spec.DstPort, imap.DefaultPort)
	}
}

// 红例3【D-IMAP-1 §1/§13】：registry imap 登记 5 业务键（现状：零 Fields，
// 层内 banner/commands/idle/pipelined_commands/allow_utf8_mailbox 全被 V9
// 判 unknown field）。
func TestIMAPRegistry_FieldsRegistered(t *testing.T) {
	r := layers.DefaultRegistry()
	s, ok := r.Get("imap")
	if !ok {
		t.Fatal("registry has no imap layer")
	}
	for _, k := range []string{"banner", "commands", "idle", "pipelined_commands", "allow_utf8_mailbox"} {
		if _, ok := s.Fields[k]; !ok {
			t.Fatalf("registry imap missing field %q (want banner/commands/idle/pipelined_commands/allow_utf8_mailbox)", k)
		}
	}
}

// 红例4【D-IMAP-1 §1】：层 banner+commands 翻译进 spec.IMAP（现状：无翻译
// 分支——③未修时 BuildLayersPlanner 即报 unknown field；翻译缺失时生成器
// 走默认空会话，包内无 banner）。
func TestIMAPChain_LayerBannerTranslates(t *testing.T) {
	raw := imapMigrateChain(t, map[string]interface{}{
		"banner": "* OK IMAP4rev1 ready",
		"commands": []interface{}{
			map[string]interface{}{"tag": "A001", "cmd": "LOGIN alice secret", "responses": []interface{}{"A001 OK LOGIN completed"}},
		},
	})
	p, err := layers.BuildLayersPlanner("imap", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 14000, DstPort: 143}
	payload := firstIMAPBannerPayload(t, p, spec)
	if payload == nil {
		t.Fatal("Plan produced no IMAP banner frame, want * OK greeting")
	}
	if !strings.HasPrefix(string(payload), "* OK IMAP4rev1 ready") {
		t.Fatalf("banner = %q, want layer value `* OK IMAP4rev1 ready` (layer config must translate into spec.IMAP)", payload)
	}
}
