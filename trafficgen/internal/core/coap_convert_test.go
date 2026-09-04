package core

import "testing"

func TestMapToFlowSpecCoAPParsesConfigAndDefaultPort(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{
		"coap": map[string]interface{}{"method": "GET", "token": "AQID"},
	}, "coap")
	if spec.CoAP == nil || spec.CoAP.Method != "GET" || string(spec.CoAP.Token) != "\x01\x02\x03" {
		t.Fatalf("coap config = %#v", spec.CoAP)
	}
	// CoAP 目的端口 5683 由 ChainPlanner.ValidateSpec 的 DstPort switch 在
	// Plan 时补齐（T2.4 起 mapToFlowSpec 不再设置）—— 端口默认行为由
	// layers/flat_dstport_default_test.go 锁定。
}
