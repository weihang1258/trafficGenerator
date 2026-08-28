package coap

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func bptr(b bool) *bool { return &b }

func TestBlock2ValueEncoding(t *testing.T) {
	cases := []struct {
		num  uint32
		more bool
		szx  uint8
		want string
	}{
		{0, false, 3, "03"}, // NUM=0 M=0 SZX=3
		{0, true, 3, "0b"},  // NUM=0 M=1 SZX=3
		{1, false, 3, "13"}, // NUM=1 M=0 SZX=3
		{0, false, 1, "01"}, // SZX=1 (16B)
	}
	for _, c := range cases {
		got := block2Value(c.num, c.more, c.szx)
		if hex.EncodeToString(got) != c.want {
			t.Errorf("block2Value(%d,%v,%d) = %s, want %s", c.num, c.more, c.szx, hex.EncodeToString(got), c.want)
		}
	}
}

func TestBuildMessageEncodesBlock2RequestAndResponse(t *testing.T) {
	req, err := BuildMessage(&CoAPConfig{Method: "GET", Path: []string{"large"}, Confirmable: true, MessageID: 4104,
		Token: []byte{1, 2, 3, 4}, Block2: &core.BlockConfig{Number: 0, More: false, SizeExp: 3}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if req[0] != 0x44 {
		t.Fatalf("req type = 0x%02x, want 0x44 (V1/CON/tkl4)", req[0])
	}
	// Block2 option (23) after Uri-Path (11): delta 12 -> c1, value 03
	if hex.EncodeToString(req) != "4401100801020304b56c61726765c103" {
		t.Fatalf("req hex = %s", hex.EncodeToString(req))
	}
	resp, err := BuildMessage(&CoAPConfig{MessageID: 4104, Token: []byte{1, 2, 3, 4}, ResponseCode: "2.05",
		ResponseBlock2: &core.BlockConfig{Number: 0, More: true, SizeExp: 3}, ResponsePayload: []byte("block-000")}, true)
	if err != nil {
		t.Fatal(err)
	}
	if resp[0] != 0x64 {
		t.Fatalf("resp type = 0x%02x, want 0x64 (V1/ACK/tkl4)", resp[0])
	}
	// Block2 option (23) first option: delta 23 -> d1 0a, value 0b
	if !strings.HasPrefix(hex.EncodeToString(resp), "6445100801020304d10a0b") {
		t.Fatalf("resp hex prefix = %s", hex.EncodeToString(resp)[:24])
	}
}

func TestConfirmableOverridesNonResponse(t *testing.T) {
	cfg := &CoAPConfig{Method: "GET", Confirmable: true, Response: bptr(false), MessageID: 4101}
	got, err := BuildMessage(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if got[0]&0x30 != 0x00 {
		t.Fatalf("type bits = 0x%02x, want CON (0x00)", got[0]&0x30)
	}
}

func TestEmptyACKHasCodeZero(t *testing.T) {
	typ := uint8(2)
	got, err := buildMessageTyped(&CoAPConfig{MessageID: 0x102}, false, &typ)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 0x60 || got[1] != 0x00 {
		t.Fatalf("empty ACK header = %02x %02x, want 60 00", got[0], got[1])
	}
	if len(got) != 4 {
		t.Fatalf("empty ACK len = %d, want 4", len(got))
	}
}

func TestGeneratorScenarioRetransmit(t *testing.T) {
	cfg := &CoAPConfig{Method: "GET", Path: []string{"health"}, Confirmable: true, Token: []byte{1, 2, 3, 4}, MessageID: 4101,
		Retransmit: &core.CoAPRetransmitConfig{MaxRetransmit: 4, ForceTimeout: true, AckTimeout: 2000000000}, Response: bptr(false)}
	var events []layers.MessageEvent
	if err := (&CoAPGenerator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{CoAP: cfg, SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 56570, DstPort: 5683}, EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil }}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 5 {
		t.Fatalf("retransmit = %d events, want 5", len(events))
	}
	for i, ev := range events {
		if !ev.Up {
			t.Errorf("event %d must be up", i)
		}
	}
}

func TestGeneratorScenarioErrorResponses(t *testing.T) {
	cfg := &CoAPConfig{Method: "GET", Path: []string{"missing"}, Confirmable: true, Token: []byte{1, 2, 3, 4}, MessageID: 4106,
		ErrorResponses: []core.ErrorResponseConfig{{Code: "4.04", Path: []string{"missing"}}, {Code: "4.13", Path: []string{"too-large"}}, {Code: "5.00", Path: []string{"failure"}}}}
	var events []layers.MessageEvent
	if err := (&CoAPGenerator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{CoAP: cfg, SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 56574, DstPort: 5683}, EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil }}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 6 {
		t.Fatalf("error_responses = %d events, want 6", len(events))
	}
	for i := 0; i < 6; i++ {
		if i%2 == 0 && !events[i].Up {
			t.Errorf("event %d (request) must be up", i)
		}
		if i%2 == 1 && events[i].Up {
			t.Errorf("event %d (response) must be down", i)
		}
	}
}

func TestGeneratorScenarioObserve(t *testing.T) {
	cfg := &CoAPConfig{Method: "GET", Path: []string{"temperature"}, Confirmable: true, Token: []byte{1, 2, 3, 4}, MessageID: 4105,
		ResponseCode: "2.05", ResponsePayload: []byte("23.5"), Observe: &core.ObserveConfig{Register: true, StartSequence: 100, NotifyCount: 2, Confirmable: true, NotificationTypes: []string{"NON", "CON"}}}
	var events []layers.MessageEvent
	if err := (&CoAPGenerator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{CoAP: cfg, SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 56576, DstPort: 5683}, EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil }}); err != nil {
		t.Fatal(err)
	}
	// GET(up) + ack 2.05(down) + NON notif(down) + CON notif(down) + empty ACK(up) = 5
	if len(events) != 5 {
		t.Fatalf("observe = %d events, want 5", len(events))
	}
	if events[1].Bytes[0] != 0x64 || events[1].Bytes[1] != 69 {
		t.Fatalf("ack header = %x", events[1].Bytes[0:2])
	}
}
