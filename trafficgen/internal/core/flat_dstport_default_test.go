package core_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dns"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ntp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/snmp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/syslog"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ssdp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mdns"
	_ "github.com/trafficgen/trafficgen/internal/protocol/modbus"
)

// TestFlatConfigWithoutDstPort_UsesProtocolPort is the failing test for the
// T2.1 DstPort-default defect: mapToFlowSpec applies the universal default
// (port 80) to spec.DstPort when the user did not provide dst_port. The chain
// planner's DstPort switch in validateSpecBase (gated on spec.DstPort==0)
// therefore never fires for batch-1 protocols, and packets emerge carrying
// port 80 instead of the protocol's well-known port. Production path: REST
// or MCP create → StrategyModelToTask → mapToFlowSpec → ChainPlanner.Plan.
// This test exercises the exact path the API uses.
func TestFlatConfigWithoutDstPort_UsesProtocolPort(t *testing.T) {
	cases := []struct {
		proto string
		cfg   map[string]interface{}
		want  uint16
	}{
		{
			proto: "dns",
			cfg: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				"dns":      map[string]interface{}{"domain": "example.com"},
			},
			want: 53,
		},
		{
			proto: "ntp",
			cfg: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				"ntp":      map[string]interface{}{},
			},
			want: 123,
		},
		{
			proto: "snmp",
			cfg: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				"snmp":     map[string]interface{}{"var_binds": []interface{}{map[string]interface{}{"name": "1.3.6.1.2.1.1.1.0"}}},
			},
			want: 161,
		},
		{
			proto: "ssdp",
			cfg: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				"ssdp":     map[string]interface{}{"message_type": "msearch", "search_target": "ssdp:all"},
			},
			want: 1900,
		},
		{
			proto: "modbus",
			cfg: map[string]interface{}{
				"src_ip":   "10.0.0.1",
				"dst_ip":   "20.0.0.1",
				"src_port": float64(12345),
				"modbus":   map[string]interface{}{"unit_id": float64(1)},
			},
			want: 502,
		},
	}
	for _, c := range cases {
		t.Run(c.proto, func(t *testing.T) {
			spec := core.ConvertFlatSpec(c.cfg, c.proto)
			ch, err := layers.NewChainPlanner(c.proto).Plan(context.Background(), spec)
			if err != nil {
				t.Fatalf("%s Plan: %v", c.proto, err)
			}
			for pc := range ch {
				// Down-direction packets carry the swapped client port
				// (src_port) as their DstPort — only up packets carry the
				// protocol's well-known server port, which is the field
				// the bug concerns (server-side reachability).
				if pc.Direction == "up" && pc.L4.DstPort != c.want {
					t.Errorf("%s: flat cfg without dst_port produced up DstPort=%d, want %d (universal default leaks; protocol port default from validateSpecBase skipped because spec.DstPort=80≠0)",
						c.proto, pc.L4.DstPort, c.want)
				}
			}
		})
	}
}
