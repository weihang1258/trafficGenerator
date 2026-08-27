package layers_test

import (
	"context"
	"testing"

	_ "github.com/trafficgen/trafficgen/internal/protocol/amqp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/bgp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dameng"
	_ "github.com/trafficgen/trafficgen/internal/protocol/drda"
	_ "github.com/trafficgen/trafficgen/internal/protocol/iec104"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mongodb"
	_ "github.com/trafficgen/trafficgen/internal/protocol/thrift"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tns"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestChainPlannerP0b2EmptyConfigDefaultFlow(t *testing.T) {
	cases := []struct {
		proto string
		port  uint16
	}{
		{"tns", 1521}, {"mongodb", 27017}, {"dameng", 5236},
		{"bgp", 179}, {"iec104", 2404}, {"thrift", 9090}, {"drda", 446},
		{"amqp", 5672},
	}
	for _, c := range cases {
		spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234}
		v, err := layers.NewChainPlanner(c.proto).ValidateSpec(spec)
		if err != nil {
			t.Errorf("%s: ValidateSpec err: %v", c.proto, err)
			continue
		}
		if v.DstPort != c.port {
			t.Errorf("%s: ValidateSpec DstPort=%d, want %d", c.proto, v.DstPort, c.port)
		}
		ch, err := layers.NewChainPlanner(c.proto).Plan(context.Background(), spec)
		if err != nil {
			t.Errorf("%s: Plan err: %v", c.proto, err)
			continue
		}
		n, upOk := 0, 0
		for p := range ch {
			if p.Direction == "up" && p.L4.DstPort == c.port {
				upOk++
			}
			n++
		}
		if n == 0 {
			t.Errorf("%s: empty config produced 0 packets", c.proto)
			continue
		}
		if upOk == 0 {
			t.Errorf("%s: no up packet with DstPort=%d", c.proto, c.port)
		}
	}
}
