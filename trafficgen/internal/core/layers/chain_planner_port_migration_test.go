package layers_test

import (
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// Blank-import the protocol packages to trigger their init() functions
	// that RegisterLayerGenerator for the migrated protocols. Without
	// these, NewChainPlanner("modbus"/"tftp"/"radius") would fail with
	// "generator not implemented" (the test package parallels cmd/server
	// main.go's empty-import wiring). Radius is omitted because it has no
	// layer generator yet (still legacy path), so its DstPort default
	// remains in strategy_convert.go.
	_ "github.com/trafficgen/trafficgen/internal/protocol/dhcp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dhcpv6"
	_ "github.com/trafficgen/trafficgen/internal/protocol/modbus"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tftp"
)

// TestChainPlanner_TFTP_DefaultPort verifies the chain defaults dst port to
// 69 (RFC 1350) for tftp when the user did not write dst_port — the default
// migrated here from mapToFlowSpec (strategy_convert.go) so the chain
// planner is the single source of truth for tftp's well-known port.
func TestChainPlanner_TFTP_DefaultPort(t *testing.T) {
	p := layers.NewChainPlanner("tftp")
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 40000,
		TFTP:    &core.TFTPConfig{Filename: "boot.img", DataPayloadPattern: []byte("A")},
	}
	out, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if out.DstPort != 69 {
		t.Errorf("tftp DstPort = %d, want 69 (RFC 1350 default)", out.DstPort)
	}
	// Explicit dst_port must win over the default.
	spec.DstPort = 1069
	out, err = p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec(explicit): %v", err)
	}
	if out.DstPort != 1069 {
		t.Errorf("tftp explicit DstPort = %d, want 1069 (user value must win)", out.DstPort)
	}
}

// TestChainPlanner_DHCP_DHCPv6_PortStaysZero verifies dhcp/dhcpv6 keep
// DstPort 0 in the spec — the terminal generators resolve per-role/per-
// direction ports at emit time (resolvePorts / resolveAddrs), matching the
// legacy planners. mapToFlowSpec no longer pre-fills 67/547.
func TestChainPlanner_DHCP_DHCPv6_PortStaysZero(t *testing.T) {
	for _, name := range []string{"dhcp", "dhcpv6"} {
		p := layers.NewChainPlanner(name)
		spec := core.FlowSpec{
			SrcIP:   "10.0.0.1",
			DstIP:   "20.0.0.1",
			SrcPort: 40000,
		}
		if name == "dhcp" {
			spec.DHCP = &core.DHCPConfig{Messages: []core.DHCPMessage{{Type: 1}}}
		} else {
			spec.DHCPv6 = &core.DHCPv6Config{Messages: []core.DHCPv6Message{{MsgType: 1}}}
			spec.SrcIP = "fe80::1"
			spec.DstIP = "fe80::2"
			spec.SrcMAC = "02:00:00:00:00:01"
		}
		out, err := p.ValidateSpec(spec)
		if err != nil {
			t.Fatalf("%s ValidateSpec: %v", name, err)
		}
		if out.DstPort != 0 {
			t.Errorf("%s DstPort = %d, want 0 (generator resolves per-role port at emit time)", name, out.DstPort)
		}
	}
}

// TestChainPlanner_Modbus_DefaultPort verifies modbus defaults to 502 via
// the chain (the mapToFlowSpec duplicate was removed).
func TestChainPlanner_Modbus_DefaultPort(t *testing.T) {
	p := layers.NewChainPlanner("modbus")
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 40000,
		MODBUS:  &core.MODBUSConfig{},
	}
	out, err := p.ValidateSpec(spec)
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	if out.DstPort != 502 {
		t.Errorf("modbus DstPort = %d, want 502 (default)", out.DstPort)
	}
}
