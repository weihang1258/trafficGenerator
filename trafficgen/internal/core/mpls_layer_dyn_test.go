package core

import "testing"

// D-MPLS-1 红例⑤（failing 先行，P-PIPE #16 P4）：mpls 层端口动态对象
// allowlist 放行（决策 E1，h323 已批延续）。实现前 mpls 不在
// layerDynAllowlist → LayerDynAllowlisted 返 false。
func TestMPLSLayerPortDynAllowlisted(t *testing.T) {
	for _, f := range []string{"src_port", "dst_port"} {
		if !LayerDynAllowlisted("mpls", f) {
			t.Fatalf("LayerDynAllowlisted(mpls, %s) = false, want true (D-MPLS-1 decision E1)", f)
		}
	}
	// 业务 5 键全关（D-MPLS-1 §12：标签栈=路径身份等，逐流变破坏 LSP 语义）。
	for _, f := range []string{"labels", "multicast", "inner_proto", "inner_payload", "frames", "direction"} {
		if LayerDynAllowlisted("mpls", f) {
			t.Fatalf("LayerDynAllowlisted(mpls, %s) = true, want false (business keys stay static)", f)
		}
	}
}
