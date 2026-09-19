package core

import "testing"

// D-H323-1 红例⑤（failing 先行，P-PIPE #15 P4）：h323 层端口动态对象
// allowlist 放行（决策 E1，用户已批）。实现前 h323 不在 layerDynAllowlist
// → LayerDynAllowlisted 返 false（对象即 does not support dynamic）。
func TestH323LayerPortDynAllowlisted(t *testing.T) {
	for _, f := range []string{"src_port", "dst_port"} {
		if !LayerDynAllowlisted("h323", f) {
			t.Fatalf("LayerDynAllowlisted(h323, %s) = false, want true (D-H323-1 decision E1)", f)
		}
	}
	// 业务 8 键全关（D-H323-1 §12：结构选择器/会话语义，icmpv6 同判）。
	for _, f := range []string{"role", "scenario", "crv", "display_name", "calls", "rewrite_addr", "media", "ras"} {
		if LayerDynAllowlisted("h323", f) {
			t.Fatalf("LayerDynAllowlisted(h323, %s) = true, want false (business keys stay static)", f)
		}
	}
}
