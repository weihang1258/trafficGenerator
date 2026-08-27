package opcua

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestBuildHELAndACKLengths(t *testing.T) {
	hel, err := BuildHEL(0)
	if err != nil {
		t.Fatal(err)
	}
	if string(hel[:4]) != "HELF" {
		t.Fatalf("prefix %q", hel[:4])
	}
	if got := binary.LittleEndian.Uint32(hel[4:8]); got != 32 || got != uint32(len(hel)) {
		t.Fatalf("HEL size=%d len=%d", got, len(hel))
	}
	ack, err := BuildACK()
	if err != nil {
		t.Fatal(err)
	}
	if string(ack[:4]) != "ACKF" {
		t.Fatalf("prefix %q", ack[:4])
	}
	if got := binary.LittleEndian.Uint32(ack[4:8]); got != 28 || got != uint32(len(ack)) {
		t.Fatalf("ACK size=%d len=%d", got, len(ack))
	}
}

func TestPlannerEmitsMinimalSequence(t *testing.T) {
	cfg := &core.OPCUAConfig{SecurityMode: "none", Read: true, Close: true}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 4840, OPCUA: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var got []core.PacketConfig
	for p := range ch {
		got = append(got, p)
	}
	if len(got) != 15 {
		t.Fatalf("packets=%d want 15 (3 TCP handshake + 8 UA messages + 4 TCP termination)", len(got))
	}
	var app []core.PacketConfig
	for _, p := range got {
		if len(p.Payload) > 0 {
			app = append(app, p)
		}
	}
	if len(app) != 8 {
		t.Fatalf("application packets=%d want 8", len(app))
	}
	if string(app[0].Payload[:4]) != "HELF" || string(app[1].Payload[:4]) != "ACKF" {
		t.Fatalf("HEL/ACK missing")
	}
	if string(app[2].Payload[:4]) != "OPNF" || string(app[3].Payload[:4]) != "OPNF" {
		t.Fatalf("OPN missing")
	}
	if string(app[4].Payload[:4]) != "MSGF" || string(app[5].Payload[:4]) != "MSGF" {
		t.Fatalf("MSG missing")
	}
	if string(app[6].Payload[:4]) != "CLOF" || string(app[7].Payload[:4]) != "CLOF" {
		t.Fatalf("CLO missing")
	}
}

func TestValidateRejectsMalformedConfig(t *testing.T) {
	p := Planner{}
	cases := []struct {
		name string
		cfg  *core.OPCUAConfig
		want string
	}{
		{"mode", &core.OPCUAConfig{SecurityMode: "bad"}, "security_mode"},
		{"size", &core.OPCUAConfig{BadMessageSize: true}, "MessageSize"},
		{"length", &core.OPCUAConfig{BadLength: true}, "length"},
		{"channel", &core.OPCUAConfig{SkipChannel: true, Read: true}, "secureChannel"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := p.Validate(core.FlowSpec{OPCUA: tc.cfg})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

func TestLayerGeneratorRegistered(t *testing.T) {
	g, err := layers.NewLayerGenerator("opcua")
	if err != nil {
		t.Fatal(err)
	}
	if g.Name() != "opcua" {
		t.Fatalf("name=%q", g.Name())
	}
}

func TestEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空 config（nil OPCUA）默认化（security none + read + close），
	// Validate/Plan/Generate 均产默认流。
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 4840}
	p := Planner{}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("empty config Validate err: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("empty config Plan err: %v", err)
	}
	n := 0
	for range ch {
		n++
	}
	if n == 0 {
		t.Fatal("empty config produced 0 packets")
	}

	var events []layers.MessageEvent
	err = (&OPCUAGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, DstPort: 4840},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatalf("empty config Generate err: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("empty config generated 0 events")
	}
}
