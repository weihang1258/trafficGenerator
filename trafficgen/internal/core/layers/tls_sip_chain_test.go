package layers_test

// D-SIP-2 WP-D 回归：[ip→tcp→tls→sip] 事件面链。sip 生成器翻
// dialog→MessageEvents，tls 变换器包 record（7 握手 + 每消息一
// ApplicationData record），tcp 层持握手/挥手——16 包形状落盘钉。

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 tls/sip 包 init 注册隧道层生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/sip"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tls"
)

func TestChainPlanner_SIP_TLSChain(t *testing.T) {
	p := layers.NewChainPlannerFromChain("sip", []layers.Layer{
		{Name: "ip"},
		{Name: "tcp"},
		{Name: "tls", Config: map[string]interface{}{}},
		{Name: "sip", Config: map[string]interface{}{
			"dialog": []interface{}{
				map[string]interface{}{"method": "OPTIONS", "uri": "sips:callee@20.0.0.1"},
				map[string]interface{}{"status_code": 200.0, "status_text": "OK"},
			},
		}},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12001, DstPort: 5061,
		SIP: &core.SIPConfig{Dialog: []core.SIPMessage{
			{Method: "OPTIONS", URI: "sips:callee@20.0.0.1"},
			{StatusCode: 200, StatusText: "OK"},
		}}}
	validated, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	ch, err := p.Plan(context.Background(), validated)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var handshakeRecs, appDataRecs int
	n := 0
	for pkt := range ch {
		n++
		pl := pkt.Payload
		if len(pl) == 0 {
			continue
		}
		switch pl[0] {
		case 0x16:
			handshakeRecs++
		case 0x17:
			appDataRecs++
			if !strings.Contains(string(pl), "SIP/2.0") {
				t.Fatalf("app-data record %d must carry the SIP message bytes", n)
			}
		}
	}
	// 3 TCP 握手 + 7 TLS 握手 record（CH/SH/EE/Cert/CV/Fin×2）+ 2 app-data
	// （OPTIONS/200 各一 record）+ 4 TCP 挥手 = 16。
	if n != 16 {
		t.Fatalf("packets=%d want 16 (3 tcp-hs + 7 tls-hs + 2 appdata + 4 tcp-fin)", n)
	}
	if handshakeRecs != 7 {
		t.Fatalf("tls handshake records=%d want 7 (RFC 8446 §2 synthetic client flight+server flight)", handshakeRecs)
	}
	if appDataRecs != 2 {
		t.Fatalf("app-data records=%d want 2 (one per dialog message)", appDataRecs)
	}
}
