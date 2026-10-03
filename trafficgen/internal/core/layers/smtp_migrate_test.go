package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/smtp" // init 注册 smtp 终结层生成器
)

// D-SMTP-1 步骤 0 红例族（failing 先行，2026-09-16）。
// 实现前全红：①顶层 smtp presence 未判死（放行）；②translateTerminalConfig
// 无 case "smtp"（层 banner 被忽略，spec.SMTP 保持 nil）；③扁平侧无默认 25
//（注释写默认，实际未调 setDefaultDstPort，复审 R5）。红例走 BuildLayersPlanner
// 全链口径 + CheckProtoFlat 直接口径（mqtt/dns 先例同款）。

func smtpMigrateChain(t *testing.T, smtpCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	chain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 12345, "dst_port": 25}},
		map[string]interface{}{"smtp": smtpCfg},
	}
	out, _ := json.Marshal(chain)
	return out
}

func smtpMigrateSpec() core.FlowSpec {
	return core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 25}
}

// firstSMTPBannerPayload returns the first down-direction data-frame payload
// (server banner, 220 greeting). nil = no banner frame found.
func firstSMTPBannerPayload(t *testing.T, p core.ProtocolPlanner, spec core.FlowSpec) []byte {
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

// 红例1【D-SMTP-1 §1/§5】：顶层 smtp 子映射 presence 判死——空 map 也死
// （mqtt/dns 先例）。现状：放行。
func TestSMTPChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"tcp": map[string]interface{}{}},
			map[string]interface{}{"smtp": map[string]interface{}{}},
		},
		"smtp": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("smtp", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(smtp, {layers, smtp:{}}) = \"\", want top-level smtp presence rejection")
	}
	if msg := core.CheckProtoFlat("smtp", cfg); !strings.Contains(msg, "rejects a top-level smtp sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q, want sub-anchor `rejects a top-level smtp sub-config`", msg)
	}
}

// 红例2【D-SMTP-1 §1】：层 banner 翻译进 spec.SMTP（现状：translateTerminalConfig
// 无 case "smtp"，层值被忽略，banner 回退自动生成）。
func TestSMTPChain_LayerBannerTranslates(t *testing.T) {
	raw := smtpMigrateChain(t, map[string]interface{}{"banner": "220 mx.example.org ESMTP Postfix"})
	p, err := layers.BuildLayersPlanner("smtp", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	payload := firstSMTPBannerPayload(t, p, smtpMigrateSpec())
	if payload == nil {
		t.Fatal("Plan produced no SMTP banner frame, want 220 greeting")
	}
	if !strings.HasPrefix(string(payload), "220 mx.example.org ESMTP Postfix") {
		t.Fatalf("banner = %q, want layer value `220 mx.example.org ESMTP Postfix` (layer config must translate into spec.SMTP)", payload)
	}
}

// 红例3【D-SMTP-1 §1/复审 R5】：扁平无端口时 DstPort 缺省 25（现状：注释写
// 默认 25，实际未调 setDefaultDstPort，spec.DstPort 保持 0）。
func TestSMTPFlat_DefaultDstPort25(t *testing.T) {
	spec := core.MapToFlowSpec(map[string]interface{}{"smtp": map[string]interface{}{}}, "smtp")
	if len(spec.ValidationErrors) > 0 {
		t.Fatalf("MapToFlowSpec validation errors: %v", spec.ValidationErrors)
	}
	if spec.DstPort != 25 {
		t.Fatalf("DstPort = %d, want 25 (flat smtp without dst_port must default per RFC 5321 §3.1)", spec.DstPort)
	}
}
