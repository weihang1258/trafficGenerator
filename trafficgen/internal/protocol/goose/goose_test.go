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
		{"bad type", func(c *core.GOOSEConfig) { c.Data = append(c.Data, core.GOOSEData{Type: "bogus"}) }, "unsupported data type"},
		{"no members", func(c *core.GOOSEConfig) { c.Data = nil }, "at least one"},
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

// TestPlannerRetransmitSequence verifies the event_seq state machine: one
// initial heartbeat (st=1 sq=1), then a change burst (st=2 sq=0 +
// retransmits frames sq 1..N), then heartbeat resumes. Guards the P3 T4.2
// goose_retransmit case sequence.
func TestPlannerRetransmitSequence(t *testing.T) {
	cfg := validConfig()
	cfg.Count = 8
	cfg.EventSeq = []core.GOOSEEventSeq{{DataIdx: 0, DelayMs: 5, Retransmits: 5}}
	ch, err := (&Planner{}).Plan(context.Background(), core.FlowSpec{SrcMAC: "aa:bb:cc:dd:ee:01", GOOSE: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var stNums, sqNums []int
	for p := range ch {
		st, _ := extractGooseCounter(p.Payload, 0x85)
		sq, _ := extractGooseCounter(p.Payload, 0x86)
		stNums = append(stNums, st)
		sqNums = append(sqNums, sq)
	}
	wantSt := []int{1, 2, 2, 2, 2, 2, 2, 2}
	wantSq := []int{1, 0, 1, 2, 3, 4, 5, 6}
	if len(stNums) != len(wantSt) {
		t.Fatalf("frames=%d want %d", len(stNums), len(wantSt))
	}
	for i := range wantSt {
		if stNums[i] != wantSt[i] || sqNums[i] != wantSq[i] {
			t.Errorf("frame %d: st=%d sq=%d, want st=%d sq=%d", i+1, stNums[i], sqNums[i], wantSt[i], wantSq[i])
		}
	}
}

// extractGooseCounter returns the integer value of the BER member with the
// given tag from a GOOSE payload (stNum=0x85, sqNum=0x86). Returns 0 if the
// tag is absent (unexpected); the test fails via the value assertion.
func extractGooseCounter(payload []byte, tag byte) (int, error) {
	for i := 0; i+2 < len(payload); i++ {
		if payload[i] != tag {
			continue
		}
		ln := int(payload[i+1])
		if i+2+ln <= len(payload) {
			v := 0
			for _, b := range payload[i+2 : i+2+ln] {
				v = v<<8 | int(b)
			}
			return v, nil
		}
	}
	return 0, nil
}

// TestPlannerRejectsNonContiguousSqNum verifies that an event_seq with
// sqnum_step > 1 (non-contiguous jump) is rejected — the neg_sqnum negative
// case (P3 T4.2 validation gap).
func TestPlannerRejectsNonContiguousSqNum(t *testing.T) {
	cfg := validConfig()
	cfg.EventSeq = []core.GOOSEEventSeq{{DataIdx: 0, DelayMs: 5, Retransmits: 2, SqNumStep: 2}}
	err := (&Planner{}).Validate(core.FlowSpec{GOOSE: cfg})
	if err == nil || !strings.Contains(err.Error(), "sqNum") {
		t.Fatalf("err=%v want sqNum rejection", err)
	}
}
