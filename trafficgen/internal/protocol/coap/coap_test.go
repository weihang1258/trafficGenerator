package coap

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestBuildMessageEncodesGETPathTokenAndPayload(t *testing.T) {
	cfg := &CoAPConfig{
		Method:      "GET",
		Path:        []string{"sensors", "temp"},
		Token:       []byte{1, 2, 3, 4},
		MessageID:   0x1001,
		Confirmable: true,
	}
	got, err := BuildMessage(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := "44011001"
	if hex.EncodeToString(got[:4]) != wantPrefix {
		t.Fatalf("fixed header = %x, want %s", got[:4], wantPrefix)
	}
	if string(got[4:8]) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("token = %x, want 01020304", got[4:8])
	}
	if string(got[8:]) != string([]byte{0xB7, 's', 'e', 'n', 's', 'o', 'r', 's', 0x04, 't', 'e', 'm', 'p'}) {
		t.Fatalf("options = %x", got[8:])
	}
}

func TestBuildMessageEncodesContentFormatAndPayload(t *testing.T) {
	cfg := &CoAPConfig{
		Method:        "POST",
		Token:         []byte{0x10},
		MessageID:     2,
		ContentFormat: 50,
		Payload:       []byte(`{"v":23}`),
	}
	got, err := BuildMessage(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 0x41 || got[1] != 0x02 || got[2] != 0 || got[3] != 2 {
		t.Fatalf("header = %x", got[:4])
	}
	if string(got[len(got)-8:]) != `{"v":23}` {
		t.Fatalf("payload suffix = %q", got[len(got)-8:])
	}
	for i := 4; i < len(got)-8; i++ {
		if got[i] == 0xff {
			if i+1 > len(got)-8 {
				t.Fatal("payload marker has no payload")
			}
			if got[i+1] != '{' {
				t.Fatalf("payload marker followed by %x", got[i+1])
			}
			return
		}
	}
	t.Fatal("missing payload marker")
}

func TestBuildResponseEchoesMIDAndToken(t *testing.T) {
	cfg := &CoAPConfig{
		Token:                 []byte{1, 2, 3, 4},
		MessageID:             0x1001,
		ResponseCode:          "2.05",
		ResponsePayload:       []byte(`{"value":23.5}`),
		ResponseContentFormat: 50,
	}
	got, err := BuildMessage(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 0x64 || got[1] != 69 || got[2] != 0x10 || got[3] != 1 {
		t.Fatalf("response header = %x", got[:4])
	}
	if string(got[4:8]) != string(cfg.Token) {
		t.Fatalf("response token = %x", got[4:8])
	}
}

func TestPlannerRejectsInvalidVersionTokenAndCode(t *testing.T) {
	cases := []struct {
		name string
		cfg  *CoAPConfig
		want string
	}{
		{"version", &CoAPConfig{Version: 2, Method: "GET"}, "version"},
		{"token", &CoAPConfig{Method: "GET", Token: make([]byte, 9)}, "token"},
		{"code", &CoAPConfig{Code: 0x7f}, "code"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (Planner{}).Validate(core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40000, CoAP: tc.cfg})
			if err == nil || !contains(err.Error(), tc.want) {
				t.Fatalf("Validate error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPlannerUDPPlanEmitsRequestAndResponse(t *testing.T) {
	cfg := &CoAPConfig{Method: "GET", Path: []string{"sensors", "temp"}, Token: []byte{1, 2, 3, 4}, MessageID: 0x1001, Confirmable: true, ResponseCode: "2.05", ResponsePayload: []byte("ok")}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 56565, DstPort: 5683, CoAP: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for packet := range ch {
		packets = append(packets, packet)
	}
	if len(packets) != 2 || packets[0].Direction != "up" || packets[1].Direction != "down" {
		t.Fatalf("packets = %#v", packets)
	}
	if packets[0].Payload[0] != 0x44 || packets[1].Payload[0] != 0x64 {
		t.Fatalf("types = %x, %x", packets[0].Payload[0], packets[1].Payload[0])
	}
}

func TestCoAPGeneratorEmitsEvents(t *testing.T) {
	cfg := &CoAPConfig{Method: "GET", Token: []byte{1}, MessageID: 7, ResponseCode: "2.05"}
	var events []layers.MessageEvent
	err := (&CoAPGenerator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{CoAP: cfg}, EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || !events[0].Up || events[1].Up {
		t.Fatalf("events = %#v", events)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空 config（nil CoAP）默认化（GET 请求），Validate/Plan/Generate
	// 均产默认流。
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 5683, DstPort: 5683}
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
	err = (&CoAPGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 5683, DstPort: 5683},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatalf("empty config Generate err: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("empty config generated 0 events")
	}
}
