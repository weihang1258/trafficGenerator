package core

import "testing"

// D-TELNET-1 红例⑤（failing 先行，P-PIPE #18 P4）：telnet 层端口动态对象
// allowlist 放行（决策 E1，h323/mpls/ngap 已批延续）。实现前 telnet 不在
// layerDynAllowlist → LayerDynAllowlisted 返 false。
func TestTelnetLayerPortDynAllowlisted(t *testing.T) {
	for _, f := range []string{"src_port", "dst_port"} {
		if !LayerDynAllowlisted("telnet", f) {
			t.Fatalf("LayerDynAllowlisted(telnet, %s) = false, want true (D-TELNET-1 decision E1)", f)
		}
	}
	// 业务 10 键全关（D-TELNET-1 §12：banner/dialog/terminal_type/
	// window_cols/window_rows/file_source/scenario/username/password/
	// commands——会话身份/结构选择器/凭据面，逐流变破坏交互语义）。
	for _, f := range []string{
		"banner", "dialog", "terminal_type", "window_cols", "window_rows",
		"file_source", "scenario", "username", "password", "commands",
	} {
		if LayerDynAllowlisted("telnet", f) {
			t.Fatalf("LayerDynAllowlisted(telnet, %s) = true, want false (business keys stay static)", f)
		}
	}
}
