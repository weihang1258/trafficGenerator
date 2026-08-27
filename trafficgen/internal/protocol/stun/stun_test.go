package stun

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func TestBuildBindingRequestHeader(t *testing.T) {
	id := []byte("0123456789ab")
	msg, err := BuildMessageFromEvent(&core.STUNEvent{
		Kind:      "request",
		Direction: "c2s",
	}, id)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(msg[:8]); got != "000100002112a442" {
		t.Fatalf("header=%s, want 000100002112a442", got)
	}
	if hex.EncodeToString(msg[8:20]) != hex.EncodeToString(id) {
		t.Fatalf("id mismatch: got %x, want %x", msg[8:20], id)
	}
	// No body attributes → total length = 20 (header only).
	if len(msg) != 20 {
		t.Fatalf("len=%d, want 20 (header only)", len(msg))
	}
}

func TestBuildSuccessXORMappedIPv4(t *testing.T) {
	msg, err := BuildMessageFromEvent(&core.STUNEvent{
		Kind:      "success",
		Direction: "s2c",
		Attributes: []core.STUNAttribute{
			{Type: "xor-mapped-address", Address: "192.0.2.1", Port: 40000},
		},
	}, []byte("0123456789ab"))
	if err != nil {
		t.Fatal(err)
	}
	// Header: 0x0101 (Binding Success) + length (12) + cookie + id
	if len(msg) != 32 || msg[0] != 1 || msg[1] != 1 {
		t.Fatalf("message type=%x, want 0x0101", msg[:2])
	}
	// Attribute: XOR-MAPPED-ADDRESS (type=0x0020, length=8, IPv4=1, port=xor, addr=xor)
	if msg[20] != 0x00 || msg[21] != 0x20 || msg[22] != 0x00 || msg[23] != 0x08 {
		t.Fatalf("attribute type/len=%x, want 0x0020/8", msg[20:24])
	}
}

func TestPlannerRejectsEmptyConfig(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "192.0.2.1", DstIP: "198.51.100.1",
		SrcPort: 50000, DstPort: 3478, STUN: &core.STUNConfig{},
	}
	if err := (Planner{}).Validate(spec); err == nil || !strings.Contains(err.Error(), "event") {
		t.Fatalf("err=%v, want event rejection", err)
	}
}

func TestValidateRejectsInvalidEventKind(t *testing.T) {
	if err := ValidateConfig(&core.STUNConfig{Events: []core.STUNEvent{
		{Kind: "invalid", Direction: "c2s"},
	}}); err == nil || !strings.Contains(err.Error(), "kind") {
		t.Fatalf("err=%v, want unknown event kind rejection", err)
	}
}

func TestValidateRejectsWireFaultAndInvalidTransactionID(t *testing.T) {
	if err := ValidateConfig(&core.STUNConfig{WireFault: &core.STUNFault{Kind: ""}}); err == nil || !strings.Contains(err.Error(), "kind") {
		t.Fatalf("err=%v", err)
	}
	if _, err := BuildMessageFromEvent(&core.STUNEvent{Kind: "request", Direction: "c2s"}, []byte{1}); err == nil || !strings.Contains(err.Error(), "transaction") {
		t.Fatalf("err=%v", err)
	}
}
func TestEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空 config（nil STUN）默认化（BindingRequest c2s），
	// Validate/Plan/Generate 均产默认流。
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 50000, DstPort: 3478}
	if err := (Planner{}).Validate(spec); err != nil {
		t.Fatalf("empty config Validate err: %v", err)
	}
	ch, err := (Planner{}).Plan(context.Background(), spec)
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
	err = (&Generator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 50000, DstPort: 3478},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatalf("empty config Generate err: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("empty config generated 0 events")
	}
}
