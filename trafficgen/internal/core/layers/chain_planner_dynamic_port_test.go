package layers_test

import (
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// Regression (T5.2 offline chain suite finding): mapToFlowSpec writes the
// universal default 80 into spec.DstPort; validateSpecBase's DstPort switch
// enters via isUniversalDefault for dynamic-port layers (dhcp/dhcpv6/rip)
// whose cases are documented "0 stays 0" but have empty bodies — the 80
// survives, applySpecToChain writes it into the udp layer cfg, and the wire
// carries udp.dstport=80 instead of the per-role/per-version port resolved
// by the generator. Failing-first: this test pins the reset-to-0 semantics.
func TestValidateSpec_DynamicPortLayersResetUniversalDefault(t *testing.T) {
	for _, proto := range []string{"dhcp", "dhcpv6", "rip"} {
		spec := core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
			SrcPort: 12345, DstPort: 80, // universal defaults from mapToFlowSpec
		}
		if proto == "dhcpv6" {
			spec.SrcIP, spec.DstIP = "2001:db8::1", "2001:db8::2"
		}
		got, err := layers.NewChainPlanner(proto).ValidateSpec(spec)
		if err != nil {
			t.Errorf("%s: ValidateSpec err: %v", proto, err)
			continue
		}
		if got.DstPort != 0 {
			t.Errorf("%s: DstPort = %d, want 0 (universal default 80 must reset for dynamic per-role resolution)", proto, got.DstPort)
		}
	}
}

// Explicit user ports must be preserved on the same layers (user > dynamic
// default, design §8 priority).
func TestValidateSpec_DynamicPortLayersKeepExplicitPort(t *testing.T) {
	for _, proto := range []string{"dhcp", "dhcpv6", "rip"} {
		spec := core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
			SrcPort: 50000, DstPort: 1067, // explicit non-default
		}
		if proto == "dhcpv6" {
			spec.SrcIP, spec.DstIP = "2001:db8::1", "2001:db8::2"
		}
		got, err := layers.NewChainPlanner(proto).ValidateSpec(spec)
		if err != nil {
			t.Errorf("%s: ValidateSpec err: %v", proto, err)
			continue
		}
		if got.DstPort != 1067 {
			t.Errorf("%s: DstPort = %d, want 1067 (explicit user port preserved)", proto, got.DstPort)
		}
	}
}
