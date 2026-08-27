package core

import "testing"

func TestMapToFlowSpecCoAPParsesConfigAndDefaultPort(t *testing.T) {
	spec := mapToFlowSpec(map[string]interface{}{
		"coap": map[string]interface{}{"method": "GET", "token": "AQID"},
	}, "coap")
	if spec.CoAP == nil || spec.CoAP.Method != "GET" || string(spec.CoAP.Token) != "\x01\x02\x03" {
		t.Fatalf("coap config = %#v", spec.CoAP)
	}
	if spec.DstPort != 5683 {
		t.Fatalf("dst port = %d, want 5683", spec.DstPort)
	}
}
