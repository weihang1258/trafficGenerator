package layers_test

// D-LDAP-1 P4 链级红例（failing 先行）：[ip→ldap] raw 自驱链（裁定1，
// radius 对称：legacy 自建 TCP 握手/分段/挥手原样 wrap，pppoe/srv6 防双换
// 模式 Direction 统一 "up"）。目的端口 389 由 legacy Plan 缺省（链路径
// 无端口位）。

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 ldap 包 init 注册 raw 链生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/ldap"
)

func TestChainPlanner_LDAPRawChain(t *testing.T) {
	p := layers.NewChainPlannerFromChain("ldap", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		// 数值面经 JSON 往返（getUint16/getInt 只认 float64/json.Number，
		// pppoe_chain_test mustJSONMap 同口径）。
		{Name: "ldap", Config: mustJSONMap(t, `{
			"rounds": 2, "result_code": 49,
			"filter_type": "equality", "search_filter": "uid", "filter_value": "alice"
		}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 389}
	validated, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if validated.LDAP == nil {
		t.Fatalf("translate must populate spec.LDAP from the ldap layer config")
	}
	if validated.LDAP.ResultCode != 49 || validated.LDAP.FilterType != "equality" {
		t.Fatalf("spec.LDAP not populated from layer: %+v", validated.LDAP)
	}
	ch, err := p.Plan(context.Background(), validated)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	var flags []uint8
	for pkt := range ch {
		n++
		flags = append(flags, pkt.L4.Flags)
		if pkt.L4.Protocol != "tcp" {
			t.Fatalf("packet %d proto=%q want tcp (legacy self-built TCP)", n, pkt.L4.Protocol)
		}
		if pkt.L4.DstPort != 389 && pkt.L4.SrcPort != 389 {
			t.Fatalf("packet %d ports %d->%d: 389 must appear on every segment", n, pkt.L4.SrcPort, pkt.L4.DstPort)
		}
	}
	// 3 握手 + 2 轮×(bind up/down + search up + entry/done down) + unbind + 4 挥手。
	// rounds=2: 3 + 2*5 + 1 + 4 = 18（bind/search 消息 < MSS 单段）。
	if n != 18 {
		t.Fatalf("packets=%d want 18 (3 hs + 2 rounds x 5 msgs + unbind + 4 fin)", n)
	}
	// 握手形状：SYN/SYN-ACK/ACK。
	if flags[0] != 0x02 || flags[1] != 0x12 || flags[2] != 0x10 {
		t.Fatalf("handshake flags=%v want SYN/SYNACK/ACK", flags[:3])
	}
	// 挥手形状：FIN-ACK/ACK/FIN-ACK/ACK。
	if flags[14] != 0x11 || flags[15] != 0x10 || flags[16] != 0x11 || flags[17] != 0x10 {
		t.Fatalf("teardown flags=%v want FINACK/ACK/FINACK/ACK", flags[14:])
	}
}

// 7 锚背 door：链上 ValidateSpec 经 protocolValidator 调用 legacy Validate。
func TestChainPlanner_LDAPValidatorAnchors(t *testing.T) {
	p := layers.NewChainPlannerFromChain("ldap", []layers.Layer{
		{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{Name: "ldap", Config: mustJSONMap(t, `{"version": 4}`)},
	})
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1"}
	_, err := p.ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "invalid version") {
		t.Fatalf("want invalid version anchor, got %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
