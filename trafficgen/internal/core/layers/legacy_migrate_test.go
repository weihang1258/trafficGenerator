package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// TestLegacyPlannerRegression_ChainSufficient verifies that for every
// protocol registered via legacy NewPlanner() in cmd/server/main.go AND
// migrated to NewChainPlanner, the chain path alone produces a non-empty
// packet stream from a minimal FlowSpec. This is the regression gate for
// Task 4.1 batch 1 — if a future chain migration breaks output, this
// test fails BEFORE the protocol gets flipped in main.go.
//
// The list must match the protocols whose main.go registration is
// flipped from <proto>.NewPlanner() to layers.NewChainPlanner(<proto>).
// Each entry is a minimal spec exercising the chain's terminal + transport
// (handlers for the protocol's mandatory config live in
// internal/protocol/<proto>/).
func TestLegacyPlannerRegression_ChainSufficient(t *testing.T) {
	cases := []struct {
		proto string
		spec  core.FlowSpec
	}{
		// tftp (P4a / 字节级 MatchLegacyPlan)
		{"tftp", core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234, DstPort: 69,
			TFTP: &core.TFTPConfig{Mode: "read", Filename: "a.txt", BlocksCount: 1, DataPayloadPattern: []byte("x")},
		}},
		// modbus (P4a / MatchLegacyPlan)
		{"modbus", core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234, DstPort: 502,
			MODBUS: &core.MODBUSConfig{
				Transactions: []core.MODBUSOperation{{FunctionCode: 3, StartingAddress: 0, Quantity: 4}},
			},
		}},
	}
	for _, c := range cases {
		t.Run(c.proto, func(t *testing.T) {
			ch, err := layers.NewChainPlanner(c.proto).Plan(context.Background(), c.spec)
			if err != nil {
				t.Fatalf("Plan err: %v", err)
			}
			n := 0
			for range ch {
				n++
			}
			if n == 0 {
				t.Errorf("chain produced 0 packets for %s — chain path insufficient", c.proto)
			}
		})
	}
}
