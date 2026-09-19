package core

import "testing"

// D-NGAP-1 红例⑤（failing 先行，P-PIPE #17 P4）：ngap 层端口动态对象
// allowlist 放行（决策 E1，h323/mpls 已批延续）。实现前 ngap 不在
// layerDynAllowlist → LayerDynAllowlisted 返 false。
func TestNGAPLayerPortDynAllowlisted(t *testing.T) {
	for _, f := range []string{"src_port", "dst_port"} {
		if !LayerDynAllowlisted("ngap", f) {
			t.Fatalf("LayerDynAllowlisted(ngap, %s) = false, want true (D-NGAP-1 decision E1)", f)
		}
	}
	// 业务 12 键全关（D-NGAP-1 §12：结构选择器/联结身份/载荷，逐流变破坏
	// gNB↔AMF 联结语义）。
	for _, f := range []string{
		"global_ran_node_id", "supported_ta_list", "default_paging_drx",
		"amf_name", "ran_ue_ngap_id", "amf_ue_ngap_id",
		"initial_ue_message", "initial_nas", "downlink_nas", "uplink_nas",
		"pdu_session_setup", "ue_context_release",
	} {
		if LayerDynAllowlisted("ngap", f) {
			t.Fatalf("LayerDynAllowlisted(ngap, %s) = true, want false (business keys stay static)", f)
		}
	}
}
