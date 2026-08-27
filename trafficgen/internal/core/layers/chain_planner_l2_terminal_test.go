package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/goose"
	_ "github.com/trafficgen/trafficgen/internal/protocol/sv"
)

func TestGOOSEAndSVChainKeepDistinctEtherTypes(t *testing.T) {
	cases := []struct {
		name      string
		planner   string
		spec      core.FlowSpec
		etherType uint16
	}{
		{
			name:    "goose",
			planner: "goose",
			spec: core.FlowSpec{SrcMAC: "aa:bb:cc:dd:ee:01", GOOSE: &core.GOOSEConfig{
				APPID: 0x1000, GOCBRef: "gcb", DatSet: "set", TALMs: 500, ConfRev: 1,
				Data: []core.GOOSEData{{Type: "boolean", Value: true}}, Count: 1,
			}},
			etherType: core.EtherTypeGOOSE,
		},
		{
			name:    "sv",
			planner: "sv",
			spec: core.FlowSpec{SrcMAC: "aa:bb:cc:dd:ee:01", SV: &core.SVConfig{
				SVID: "sv01", APPID: 0x4000, ConfRev: 1, SamplesPerCycle: 4, SMPSynch: 2,
				Data: []core.SVData{{Name: "I_A", Type: "int32", InstMag: 30}}, Count: 1,
			}},
			etherType: core.EtherTypeSV,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch, err := layers.NewChainPlanner(tc.planner).Plan(context.Background(), tc.spec)
			if err != nil {
				t.Fatal(err)
			}
			var packets []core.PacketConfig
			for packet := range ch {
				packets = append(packets, packet)
			}
			if len(packets) != 1 {
				t.Fatalf("packets=%d, want 1", len(packets))
			}
			packet := packets[0]
			if packet.L2.EtherType != tc.etherType {
				t.Fatalf("EtherType=0x%04x, want 0x%04x", packet.L2.EtherType, tc.etherType)
			}
			if packet.L3.Protocol != 0 || packet.L4.Protocol != tc.planner {
				t.Fatalf("unexpected network layers: L3=%+v L4=%+v", packet.L3, packet.L4)
			}
		})
	}
}
