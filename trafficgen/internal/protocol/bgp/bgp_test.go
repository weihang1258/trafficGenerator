package bgp

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func testConfig() *BGPConfig {
	return &BGPConfig{Version: 4, ASN: 64512, HoldTime: 90, Identifier: "192.0.2.1", WireProfile: "bgp_rfc4271_ipv4_unicast"}
}

func TestBuildOpenExactRFC4271Bytes(t *testing.T) {
	got, err := BuildOpen(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	want := "ffffffffffffffffffffffffffffffff001d0104fc00005ac000020100"
	if hex.EncodeToString(got) != want {
		t.Fatalf("OPEN=%x want %s", got, want)
	}
	if len(got) != int(got[16])<<8|int(got[17]) {
		t.Fatalf("length field mismatch: %d", len(got))
	}
}

func TestBuildKeepaliveMinimumLegalMessage(t *testing.T) {
	got, err := BuildKeepalive()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "ffffffffffffffffffffffffffffffff001304" {
		t.Fatalf("KEEPALIVE=%x", got)
	}
	if len(got) != 19 {
		t.Fatalf("length=%d", len(got))
	}
}

func TestBuildOpenRejectsMalformedConfiguration(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*BGPConfig)
		want   string
	}{
		{"marker", func(c *BGPConfig) { c.Marker = []byte("bad") }, "marker"},
		{"length", func(c *BGPConfig) { c.Length = 18 }, "length"},
		{"version", func(c *BGPConfig) { c.Version = 3 }, "version"},
		{"asn", func(c *BGPConfig) { c.ASN = 65536 }, "asn"},
		{"identifier", func(c *BGPConfig) { c.Identifier = "2001:db8::1" }, "identifier"},
		{"capability", func(c *BGPConfig) { c.Capabilities = []byte{1} }, "capabilit"},
		{"update", func(c *BGPConfig) { c.Update = []byte{1} }, "update"},
		{"notification", func(c *BGPConfig) { c.Notification = []byte{1} }, "notification"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig()
			tc.mutate(c)
			if _, err := BuildOpen(c); err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

func TestPlannerAcceptsIPv6TransportWithIPv4Identifier(t *testing.T) {
	cfg := testConfig()
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "2001:db8::1", DstIP: "2001:db8::2", SrcPort: 40000, DstPort: 179, BGP: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	if len(packets) < 10 {
		t.Fatalf("packets=%d", len(packets))
	}
	if packets[3].Direction != "up" || packets[4].Direction != "down" {
		t.Fatalf("directions=%q,%q", packets[3].Direction, packets[4].Direction)
	}
	if hex.EncodeToString(packets[3].Payload) != "ffffffffffffffffffffffffffffffff001d0104fc00005ac000020100" {
		t.Fatalf("open=%x", packets[3].Payload)
	}
	if hex.EncodeToString(packets[5].Payload) != "ffffffffffffffffffffffffffffffff001304" {
		t.Fatalf("keepalive=%x", packets[5].Payload)
	}
}

func TestPlannerRejectsUnsupportedCarrierAndIPv6Profile(t *testing.T) {
	cases := []struct {
		name string
		spec core.FlowSpec
		want string
	}{
		{"udp", core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 179, BGP: testConfig(), Metadata: map[string]interface{}{"transport": "udp"}}, "tcp"},
		{"profile", core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 179, BGP: &BGPConfig{Version: 4, ASN: 64512, Identifier: "192.0.2.1", WireProfile: "bgp_ipv6_mp_reach"}}, "profile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := (Planner{}).Plan(context.Background(), tc.spec); err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

func TestGeneratorEmitsBidirectionalApplicationEvents(t *testing.T) {
	var events []layers.MessageEvent
	err := (&BGPGenerator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{BGP: testConfig()}, EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 6 {
		t.Fatalf("events=%d want 6", len(events))
	}
	for i, ev := range events {
		wantUp := i%2 == 0
		if ev.Up != wantUp {
			t.Fatalf("event %d direction=%v", i, ev.Up)
		}
	}
	for _, ev := range events {
		if len(ev.Bytes) < 19 || ev.Bytes[0] != 0xff {
			t.Fatalf("invalid message=%x", ev.Bytes)
		}
	}
}

func TestGeneratorRejectsNilAndUnsupportedConfig(t *testing.T) {
	if err := (&BGPGenerator{}).Generate(context.Background(), nil); err == nil {
		t.Fatal("nil request accepted")
	}
	bad := testConfig()
	bad.Update = []byte{1}
	if err := (&BGPGenerator{}).Generate(context.Background(), &layers.GenRequest{Meta: layers.FlowMeta{BGP: bad}, EmitMsg: func(layers.MessageEvent) error { return nil }}); err == nil || !strings.Contains(strings.ToLower(err.Error()), "update") {
		t.Fatalf("err=%v", err)
	}
}

func TestPlannerEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空配置（BGP nil）→ Plan 默认化并产默认流。
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 1234})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range ch {
		count++
	}
	if count < 6 {
		t.Fatalf("packets=%d want >=6", count)
	}
}

func TestGeneratorEmptyConfigProducesDefaultFlow(t *testing.T) {
	// P0b-2：空配置（BGP nil）→ Generate 默认化并产默认流。
	var events []layers.MessageEvent
	err := (&BGPGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 6 {
		t.Fatalf("events=%d want 6", len(events))
	}
	// 默认 OPEN：version 4, ASN 64512, holdtime 0(零值保持显式), identifier 192.0.2.1。
	if hex.EncodeToString(events[0].Bytes) != "ffffffffffffffffffffffffffffffff001d0104fc000000c000020100" {
		t.Fatalf("open=%x", events[0].Bytes)
	}
	if hex.EncodeToString(events[2].Bytes) != "ffffffffffffffffffffffffffffffff001304" {
		t.Fatalf("keepalive=%x", events[2].Bytes)
	}
}
