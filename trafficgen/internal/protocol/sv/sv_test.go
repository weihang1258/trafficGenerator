package sv

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func validSV() *core.SVConfig {
	return &core.SVConfig{SVID: "sv01", APPID: 0x4000, ConfRev: 1, SamplesPerCycle: 4, SMPSynch: 2, Data: []core.SVData{{Name: "I_A", Type: "int32", InstMag: 30}}}
}

func TestBuildPayloadSVHeaderAndASDU(t *testing.T) {
	p, err := BuildPayload(validSV(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) < 20 || binary.BigEndian.Uint16(p[:2]) != 0x4000 {
		t.Fatalf("header=%x", p)
	}
	if got := binary.BigEndian.Uint16(p[2:4]); int(got) != len(p) {
		t.Fatalf("length=%d want %d", got, len(p))
	}
	if !strings.Contains(string(p), "sv01") {
		t.Fatalf("missing svID in %x", p)
	}
	if p[8] != 0x60 {
		t.Fatalf("APDU tag=0x%02x", p[8])
	}
}

func TestPlannerSVRejectsIPAndInvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		spec core.FlowSpec
		want string
	}{
		{"appid", core.FlowSpec{SV: func() *core.SVConfig { c := validSV(); c.APPID = 0x3fff; return c }()}, "appid"},
		{"confrev", core.FlowSpec{SV: func() *core.SVConfig { c := validSV(); c.ConfRev = 0; return c }()}, "confRev"},
		{"synch", core.FlowSpec{SV: func() *core.SVConfig { c := validSV(); c.SMPSynch = 5; return c }()}, "smpSynch"},
		{"cycle", core.FlowSpec{SV: func() *core.SVConfig { c := validSV(); c.SamplesPerCycle = 0; return c }()}, "samples_per_cycle"},
		{"ip", core.FlowSpec{SrcIP: "192.0.2.1", SV: validSV()}, "Layer 2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (&Planner{}).Validate(tc.spec)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

func TestPlannerSVEmitsEthernetOnlyAndWraps(t *testing.T) {
	c := validSV()
	c.Count = 6
	ch, err := (&Planner{}).Plan(context.Background(), core.FlowSpec{SrcMAC: "aa:bb:cc:dd:ee:01", SV: c})
	if err != nil {
		t.Fatal(err)
	}
	var ps []core.PacketConfig
	for p := range ch {
		ps = append(ps, p)
	}
	if len(ps) != 6 {
		t.Fatalf("packets=%d", len(ps))
	}
	for _, p := range ps {
		if p.L2.EtherType != core.EtherTypeSV || p.L4.Protocol != "sv" || p.L3.Protocol != 0 {
			t.Fatalf("not L2-only: %+v", p)
		}
	}
	if got := binary.BigEndian.Uint16(ps[0].Payload[findTLV(ps[0].Payload, 0x82)+2:]); got != 0 {
		t.Fatalf("smpCnt0=%d", got)
	}
	if got := binary.BigEndian.Uint16(ps[4].Payload[findTLV(ps[4].Payload, 0x82)+2:]); got != 0 {
		t.Fatalf("wrapped smpCnt=%d", got)
	}
}

func findTLV(p []byte, tag byte) int {
	for i := 8; i+3 < len(p); i++ {
		if p[i] == tag && p[i+1] == 2 {
			return i
		}
	}
	return -2
}

func TestBuildPayloadPreservesNegativeInt32Bytes(t *testing.T) {
	c := validSV()
	c.Data[0].InstMag = -2
	p, err := BuildPayload(c, 0)
	if err != nil {
		t.Fatal(err)
	}
	idx := strings.Index(string(p), string([]byte{0x87, 0x04}))
	if idx < 0 || idx+6 > len(p) || !bytes.Equal(p[idx+2:idx+6], []byte{0xff, 0xff, 0xff, 0xfe}) {
		t.Fatalf("data encoding=%x", p)
	}
}

func TestPlanSVSmpCntDoesNotTruncateBeforeModulo(t *testing.T) {
	c := validSV()
	c.Count = 65537
	c.SamplesPerCycle = 4000
	packets, err := (&Planner{}).Plan(context.Background(), core.FlowSpec{SrcMAC: "aa:bb:cc:dd:ee:01", SV: c})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= 65536; i++ {
		p, ok := <-packets
		if !ok {
			t.Fatalf("planner closed after %d packets", i)
		}
		if i == 65536 {
			idx := findTLV(p.Payload, 0x82)
			if idx < 0 || idx+4 > len(p.Payload) {
				t.Fatalf("missing smpCnt TLV in packet %d: %x", i, p.Payload)
			}
			if got := binary.BigEndian.Uint16(p.Payload[idx+2 : idx+4]); got != 1536 {
				t.Fatalf("smpCnt=%d at packet %d, want 1536", got, i)
			}
		}
	}
}

func TestGeneratorSVEmitsEventAndDoubleSend(t *testing.T) {
	c := validSV()
	c.Count = 2
	c.DoubleSend = true
	var got []core.PacketConfig
	err := (&Generator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{SV: c, SrcMAC: "aa:bb:cc:dd:ee:01"}, Emit: func(p core.PacketConfig) error { got = append(got, p); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("events=%d", len(got))
	}
	if got[0].L2.EtherType != core.EtherTypeSV || got[1].Payload[8] != got[0].Payload[8] {
		t.Fatalf("double-send mismatch")
	}
}
