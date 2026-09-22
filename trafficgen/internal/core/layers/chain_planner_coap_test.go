package layers_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/coap"
	_ "github.com/trafficgen/trafficgen/internal/protocol/udp"
)

func TestChainPlanner_CoAP_ResponseEmitted_Probe(t *testing.T) {
	chain, err := layers.BuildLayersPlanner("coap", json.RawMessage(`[{"udp":{}},{"coap":{}}]`))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 56565, DstPort: 5683,
		CoAP: &core.CoAPConfig{Method: "GET", Confirmable: true, Token: []byte{1, 2, 3, 4}, MessageID: 4097,
			ResponseCode: "2.05", ResponsePayload: []byte("{}"), ResponseContentFormat: 50}}
	ch, err := chain.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var ups, downs int
	for p := range ch {
		if p.Direction == "up" {
			ups++
		} else if p.Direction == "down" {
			downs++
		}
	}
	if ups < 1 {
		t.Fatalf("expected >=1 up request, got %d", ups)
	}
	if downs < 1 {
		t.Fatalf("expected >=1 down response (Meta.CoAP not wired), got %d", downs)
	}
}
