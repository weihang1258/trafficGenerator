package core

import "testing"

// D-SIP-1 红例⑤（failing 先行，P-PIPE #19 P4）：sip 层端口动态对象
// allowlist 放行（决策 E1，h323/mpls/ngap/telnet 已批延续）。实现前 sip
// 不在 layerDynAllowlist → LayerDynAllowlisted 返 false。
func TestSIPLayerPortDynAllowlisted(t *testing.T) {
	for _, f := range []string{"src_port", "dst_port"} {
		if !LayerDynAllowlisted("sip", f) {
			t.Fatalf("LayerDynAllowlisted(sip, %s) = false, want true (D-SIP-1 decision E1)", f)
		}
	}
	// 业务 2 键全关（D-SIP-1 §12：dialog=会话结构（头补全状态机跨消息
	// 依赖）、media=SDP 关联语义（3.9），逐流变破坏联结语义）。
	for _, f := range []string{"dialog", "media"} {
		if LayerDynAllowlisted("sip", f) {
			t.Fatalf("LayerDynAllowlisted(sip, %s) = true, want false (business keys stay static)", f)
		}
	}
}
