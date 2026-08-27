package goose

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func validConfig() *core.GOOSEConfig {
	return &core.GOOSEConfig{APPID: 0x1000, GOCBRef: "gcb", DatSet: "set", TALMs: 500, ConfRev: 1, Data: []core.GOOSEData{{Type: "boolean", Value: true}}}
}

func TestBuildPayloadHasGOOSEHeaderAndBERAPDU(t *testing.T) {
	payload, err := BuildPayload(validConfig(), 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) < 10 || binary.BigEndian.Uint16(payload[:2]) != 0x1000 {
		t.Fatalf("payload header=%x", payload[:min(10, len(payload))])
	}
	if got := binary.BigEndian.Uint16(payload[2:4]); int(got) != len(payload) {
		t.Fatalf("length=%d want %d", got, len(payload))
	}
	if payload[8] != 0x61 {
		t.Fatalf("APDU tag=0x%02x", payload[8])
	}
}

func TestPlannerRejectsInvalidGOOSEConfiguration(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*core.GOOSEConfig)
		want   string
	}{
		{"appid", func(c *core.GOOSEConfig) { c.APPID = 0x4000 }, "appid"},
		{"control block", func(c *core.GOOSEConfig) { c.GOCBRef = "" }, "gocb_ref"},
		{"data type", func(c *core.GOOSEConfig) { c.Data[0].Type = "int32" }, "boolean"},
		{"data value", func(c *core.GOOSEConfig) { c.Data[0].Value = "true" }, "boolean"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(cfg)
			err := (&Planner{}).Validate(core.FlowSpec{GOOSE: cfg})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

func TestPlannerEmitsCountersAndEthernetOnlyPackets(t *testing.T) {
	cfg := validConfig()
	cfg.Count = 2
	ch, err := (&Planner{}).Plan(context.Background(), core.FlowSpec{SrcMAC: "aa:bb:cc:dd:ee:01", GOOSE: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	if len(packets) != 2 {
		t.Fatalf("packets=%d", len(packets))
	}
	for _, p := range packets {
		if p.L2.EtherType != core.EtherTypeGOOSE || p.L4.Protocol != "goose" || p.L3.Protocol != 0 {
			t.Fatalf("packet layers=%+v", p)
		}
	}
	if packets[0].Payload[8] != 0x61 || packets[1].Payload[8] != 0x61 {
		t.Fatalf("missing BER APDU")
	}
}

func TestGeneratorRejectsNilRequestAndEmitsMessages(t *testing.T) {
	g := &Generator{}
	if err := g.Generate(context.Background(), nil); err == nil {
		t.Fatal("nil request accepted")
	}
	var events []core.PacketConfig
	cfg := validConfig()
	cfg.Count = 2
	err := g.Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{GOOSE: cfg, SrcMAC: "aa:bb:cc:dd:ee:01"}, Emit: func(p core.PacketConfig) error {
		events = append(events, p)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].L2.EtherType != core.EtherTypeGOOSE {
		t.Fatalf("events=%d first=%+v", len(events), events)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
