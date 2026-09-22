package layers_test

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/stun"
)

func TestSTUNChainGeneratesIPv6UDPBinding(t *testing.T) {
	p := layers.NewChainPlanner("stun")
	ch, err := p.Plan(context.Background(), core.FlowSpec{
		SrcIP: "2001:db8::1", DstIP: "2001:db8::2",
		SrcPort: 50000, STUN: &core.STUNConfig{
			Events: []core.STUNEvent{
				{Kind: "request", Direction: "c2s"},
			},
		},
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for pkt := range ch {
		packets = append(packets, pkt)
	}
	if len(packets) != 1 {
		t.Fatalf("packets=%d, want one binding packet", len(packets))
	}
	pkt := packets[0]
	if pkt.L3.Protocol != 17 || pkt.L4.Protocol != "udp" {
		t.Fatalf("transport=%d/%q, want UDP", pkt.L3.Protocol, pkt.L4.Protocol)
	}
	if pkt.L4.DstPort != 3478 {
		t.Fatalf("destination port=%d, want 3478", pkt.L4.DstPort)
	}
	if len(pkt.Payload) < 20 || binary.BigEndian.Uint16(pkt.Payload[:2]) != stunBindingRequest {
		t.Fatalf("payload=%x, want STUN Binding request", pkt.Payload)
	}
	if binary.BigEndian.Uint32(pkt.Payload[4:8]) != stunMagicCookie {
		t.Fatalf("cookie=%x, want %x", binary.BigEndian.Uint32(pkt.Payload[4:8]), stunMagicCookie)
	}
}

const (
	stunBindingRequest = 0x0001
	stunMagicCookie    = 0x2112a442
)
