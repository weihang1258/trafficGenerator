package core

import "testing"

// D-RADIUS-1 红例⑥（failing 先行，P-PIPE #20 P4）：radius 层端口动态对象
// allowlist 放行（决策 E1，前六协议已批延续）。实现前 radius 不在
// layerDynAllowlist → LayerDynAllowlisted 返 false。
func TestRadiusLayerPortDynAllowlisted(t *testing.T) {
	for _, f := range []string{"src_port", "dst_port"} {
		if !LayerDynAllowlisted("radius", f) {
			t.Fatalf("LayerDynAllowlisted(radius, %s) = false, want true (D-RADIUS-1 decision E1)", f)
		}
	}
	// 业务 7 键全关（D-RADIUS-1 §12：码面=协议语义选择器、rounds=轮数
	// 结构、identifier=轮序基址、authenticator=鉴权面、attributes/
	// response_attributes=AVP 静态模板，逐流变破坏联结语义）。
	for _, f := range []string{
		"code", "response_code", "identifier", "rounds", "authenticator",
		"attributes", "response_attributes",
	} {
		if LayerDynAllowlisted("radius", f) {
			t.Fatalf("LayerDynAllowlisted(radius, %s) = true, want false (business keys stay static)", f)
		}
	}
}
