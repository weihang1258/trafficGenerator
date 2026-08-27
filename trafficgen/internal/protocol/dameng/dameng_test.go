package dameng

import (
	"context"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func hex(b []byte) string {
	const hextable = "0123456789abcdef"
	r := make([]byte, len(b)*2)
	for i, v := range b {
		r[i*2] = hextable[v>>4]
		r[i*2+1] = hextable[v&0x0f]
	}
	return string(r)
}

// --- Builder tests ---

func TestBuildPacket(t *testing.T) {
	ev := core.DamengEvent{Kind: "connect", Profile: "connect_default"}
	pkt, err := buildPacket(ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) == 0 {
		t.Fatal("packet should not be empty")
	}
	if string(pkt) != "connect_default" {
		t.Fatalf("payload=%q want connect_default", string(pkt))
	}
}

func TestBuildPacketDefaultProfile(t *testing.T) {
	ev := core.DamengEvent{Kind: "connect"}
	pkt, err := buildPacket(ev)
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt) != "dm8" {
		t.Fatalf("payload=%q want dm8", string(pkt))
	}
}

func TestProfilePayload(t *testing.T) {
	tests := []struct {
		profile string
		want    string
	}{
		{"connect_default", "connect_default"},
		{"auth_default", "auth_default"},
		{"sql_select_default", "sql_select_default"},
		{"", "dm8"},
	}
	for _, tc := range tests {
		got := profilePayload(tc.profile)
		if string(got) != tc.want {
			t.Fatalf("profilePayload(%q)=%q want %q", tc.profile, string(got), tc.want)
		}
	}
}

func TestCheckWireFaultNil(t *testing.T) {
	if err := checkWireFault(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckWireFaultEmpty(t *testing.T) {
	var raw []byte
	if err := checkWireFault(raw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckWireFaultTruncate(t *testing.T) {
	raw := []byte(`{"kind":"truncate_message","value":1}`)
	err := checkWireFault(raw)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCheckWireFaultMessageLimit(t *testing.T) {
	raw := []byte(`{"kind":"message_limit","value":"over_limit"}`)
	err := checkWireFault(raw)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCheckWireFaultUnknown(t *testing.T) {
	raw := []byte(`{"kind":"bogus","value":1}`)
	err := checkWireFault(raw)
	if err == nil || err.Error() != `dameng: wire fault: unknown kind "bogus"` {
		t.Fatalf("err=%v want unknown kind", err)
	}
}

// --- Planner Validate tests ---

func TestValidateDamengConfigRequired(t *testing.T) {
	// P0b-2: 空配置（nil）允许——Plan/Generate 会默认化并产默认流。
	if err := (Planner{}).Validate(core.FlowSpec{}); err != nil {
		t.Fatalf("Validate(nil config) err=%v want nil", err)
	}
}

func TestValidateDamengWireProfileRequired(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{Dameng: &core.DamengConfig{}})
	if err == nil || err.Error() != "dameng: wire_profile is required" {
		t.Fatalf("err=%v want wire_profile is required", err)
	}
}

func TestValidateDamengUnknownProfile(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		Dameng: &core.DamengConfig{
			WireProfile: "unknown_profile",
			Events: []core.DamengEvent{
				{Kind: "connect"},
			},
		},
	})
	if err == nil || err.Error() != `dameng: unknown wire profile "unknown_profile"` {
		t.Fatalf("err=%v want unknown profile", err)
	}
}

func TestValidateDamengEventsRequired(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		Dameng: &core.DamengConfig{WireProfile: "dm8_profile_pending"},
	})
	if err == nil || err.Error() != "dameng: at least one event or session required" {
		t.Fatalf("err=%v want at least one event or session", err)
	}
}

func TestValidateDamengMutuallyExclusive(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Events: []core.DamengEvent{
				{Kind: "connect"},
			},
			Sessions: []core.DamengSession{
				{Events: []core.DamengEvent{{Kind: "connect"}}},
			},
		},
	})
	if err == nil || err.Error() != "dameng: events and sessions are mutually exclusive" {
		t.Fatalf("err=%v want mutually exclusive", err)
	}
}

func TestValidateDamengPayloadSize(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			PayloadSize: "bogus",
			Events: []core.DamengEvent{
				{Kind: "connect"},
			},
		},
	})
	if err == nil || err.Error() != `dameng: unsupported payload_size "bogus"` {
		t.Fatalf("err=%v want unsupported payload_size", err)
	}
}

func TestValidateDamengWireFault(t *testing.T) {
	raw := []byte(`{"kind":"truncate_message","value":1}`)
	err := (Planner{}).Validate(core.FlowSpec{
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Events: []core.DamengEvent{
				{Kind: "connect"},
			},
			WireFault: raw,
		},
	})
	if err == nil {
		t.Fatal("expected error for wire_fault")
	}
}

func TestValidateDamengEventSequence(t *testing.T) {
	tests := []struct {
		name string
		evs  []core.DamengEvent
	}{
		{
			name: "first event not connect",
			evs: []core.DamengEvent{
				{Kind: "auth_request"},
			},
		},
		{
			name: "auth_response without auth_request",
			evs: []core.DamengEvent{
				{Kind: "connect"},
				{Kind: "auth_response"},
			},
		},
		{
			name: "SQL before auth",
			evs: []core.DamengEvent{
				{Kind: "sql_request", SQL: "SELECT 1"},
			},
		},
		{
			name: "close not last",
			evs: []core.DamengEvent{
				{Kind: "connect"},
				{Kind: "close"},
				{Kind: "auth_request"},
			},
		},
		{
			name: "unknown kind",
			evs: []core.DamengEvent{
				{Kind: "bogus"},
			},
		},
		{
			name: "empty SQL",
			evs: []core.DamengEvent{
				{Kind: "connect"},
				{Kind: "auth_request"},
				{Kind: "auth_response", Result: "success"},
				{Kind: "sql_request", SQL: ""},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := (Planner{}).Validate(core.FlowSpec{
				Dameng: &core.DamengConfig{
					WireProfile: "dm8_profile_pending",
					Events:      tc.evs,
				},
			})
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestValidateDamengBadIP(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Events: []core.DamengEvent{
				{Kind: "connect"},
			},
		},
		SrcIP: "not-an-ip",
	})
	if err == nil || err.Error() != "dameng: invalid source IP" {
		t.Fatalf("err=%v want invalid source IP", err)
	}
}

func TestValidateDamengBadDstIP(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Events: []core.DamengEvent{
				{Kind: "connect"},
			},
		},
		DstIP: "not-an-ip",
	})
	if err == nil || err.Error() != "dameng: invalid destination IP" {
		t.Fatalf("err=%v want invalid destination IP", err)
	}
}

func TestValidateDamengSessionEmpty(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Sessions: []core.DamengSession{
				{Events: []core.DamengEvent{}},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for empty session")
	}
}

func TestValidateDamengValid(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Events: []core.DamengEvent{
				{Kind: "connect", Direction: "c2s", Profile: "connect_default"},
				{Kind: "auth_request", Direction: "c2s", Profile: "auth_default", Username: "SYSDBA"},
				{Kind: "auth_response", Direction: "s2c", Profile: "auth_default", Result: "success"},
				{Kind: "sql_request", Direction: "c2s", Profile: "sql_select_default", SQL: "SELECT 1"},
				{Kind: "sql_response", Direction: "s2c", Profile: "sql_select_default", Result: "success"},
			},
		},
		SrcIP: "10.0.0.1",
		DstIP: "20.0.0.1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Plan tests ---

func collectPackets(ch <-chan core.PacketConfig, max int) []core.PacketConfig {
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
		if len(pkts) >= max {
			break
		}
	}
	return pkts
}

func TestPlanDamengConnect(t *testing.T) {
	// S1: connect event → 8 packets
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 5236,
		Count:   1,
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Events: []core.DamengEvent{
				{Kind: "connect", Direction: "c2s", Profile: "connect_default"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 8 {
		t.Fatalf("packet_count=%d want 8", len(packets))
	}
	// 0: SYN, 1: SYN-ACK, 2: ACK, 3: DATA, 4-7: teardown
	if packets[0].L4.Flags != 0x02 {
		t.Fatalf("pkt[0] flags=%02x want SYN", packets[0].L4.Flags)
	}
	if packets[3].L4.DstPort != 5236 {
		t.Fatalf("pkt[3] dst_port=%d want 5236", packets[3].L4.DstPort)
	}
	if len(packets[3].Payload) == 0 {
		t.Fatal("pkt[3] payload is empty")
	}
	if packets[3].Direction != "up" {
		t.Fatalf("pkt[3] direction=%q want up", packets[3].Direction)
	}
}

func TestPlanDamengAuthSuccess(t *testing.T) {
	// S2: connect + auth_request + auth_response → 10 packets
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 5236,
		Count:   1,
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Events: []core.DamengEvent{
				{Kind: "connect", Direction: "c2s", Profile: "connect_default"},
				{Kind: "auth_request", Direction: "c2s", Profile: "auth_default", Username: "SYSDBA"},
				{Kind: "auth_response", Direction: "s2c", Profile: "auth_default", Result: "success"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 10 {
		t.Fatalf("packet_count=%d want 10", len(packets))
	}
	// pkt[3]: connect data up
	if packets[3].Direction != "up" {
		t.Fatalf("pkt[3] direction=%q want up", packets[3].Direction)
	}
	if packets[3].L4.DstPort != 5236 {
		t.Fatalf("pkt[3] dst_port=%d want 5236", packets[3].L4.DstPort)
	}
	// pkt[4]: auth_request up
	if packets[4].Direction != "up" {
		t.Fatalf("pkt[4] direction=%q want up", packets[4].Direction)
	}
	// pkt[5]: auth_response down (src port 5236 = server)
	if packets[5].Direction != "down" {
		t.Fatalf("pkt[5] direction=%q want down", packets[5].Direction)
	}
	if packets[5].L4.SrcPort != 5236 {
		t.Fatalf("pkt[5] src_port=%d want 5236", packets[5].L4.SrcPort)
	}
}

func TestPlanDamengSQLSuccess(t *testing.T) {
	// S3: full authenticated SQL sequence → 12 packets
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 5236,
		Count:   1,
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Events: []core.DamengEvent{
				{Kind: "connect", Direction: "c2s", Profile: "connect_default"},
				{Kind: "auth_request", Direction: "c2s", Profile: "auth_default", Username: "SYSDBA"},
				{Kind: "auth_response", Direction: "s2c", Profile: "auth_default", Result: "success"},
				{Kind: "sql_request", Direction: "c2s", Profile: "sql_select_default", SQL: "SELECT 1"},
				{Kind: "sql_response", Direction: "s2c", Profile: "sql_select_default", Result: "success"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 12 {
		t.Fatalf("packet_count=%d want 12", len(packets))
	}
	// pkt[6]: sql_request up
	if packets[6].Direction != "up" {
		t.Fatalf("pkt[6] direction=%q want up", packets[6].Direction)
	}
	if packets[6].L4.DstPort != 5236 {
		t.Fatalf("pkt[6] dst_port=%d want 5236", packets[6].L4.DstPort)
	}
	// pkt[7]: sql_response down
	if packets[7].Direction != "down" {
		t.Fatalf("pkt[7] direction=%q want down", packets[7].Direction)
	}
	if packets[7].L4.SrcPort != 5236 {
		t.Fatalf("pkt[7] src_port=%d want 5236", packets[7].L4.SrcPort)
	}
	// Verify payloads are non-empty
	if len(packets[3].Payload) == 0 {
		t.Fatal("pkt[3] payload is empty")
	}
	if len(packets[6].Payload) == 0 {
		t.Fatal("pkt[6] payload is empty")
	}
}

func TestPlanDamengSQLError(t *testing.T) {
	// S4: SQL error response
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 5236,
		Count:   1,
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Events: []core.DamengEvent{
				{Kind: "connect", Direction: "c2s", Profile: "connect_default"},
				{Kind: "auth_request", Direction: "c2s", Profile: "auth_default", Username: "SYSDBA"},
				{Kind: "auth_response", Direction: "s2c", Profile: "auth_default", Result: "success"},
				{Kind: "sql_request", Direction: "c2s", Profile: "sql_error_default", SQL: "SELECT missing_column FROM missing_table"},
				{Kind: "sql_response", Direction: "s2c", Profile: "sql_error_default", Result: "error"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 12 {
		t.Fatalf("packet_count=%d want 12", len(packets))
	}
	// pkt[6]: sql_request up
	if packets[6].Direction != "up" {
		t.Fatalf("pkt[6] direction=%q want up", packets[6].Direction)
	}
	// pkt[7]: sql_response down
	if packets[7].Direction != "down" {
		t.Fatalf("pkt[7] direction=%q want down", packets[7].Direction)
	}
	if packets[7].L4.SrcPort != 5236 {
		t.Fatalf("pkt[7] src_port=%d want 5236", packets[7].L4.SrcPort)
	}
}

func TestPlanDamengLengthBoundary(t *testing.T) {
	// S5: length boundary profile
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 5236,
		Count:   1,
		Dameng: &core.DamengConfig{
			WireProfile: "length_boundary",
			PayloadSize: "profile_minimum_nonempty",
			Events: []core.DamengEvent{
				{Kind: "connect", Direction: "c2s", Profile: "connect_default"},
				{Kind: "auth_request", Direction: "c2s", Profile: "auth_default", Username: "SYSDBA"},
				{Kind: "auth_response", Direction: "s2c", Profile: "auth_default", Result: "success"},
				{Kind: "sql_request", Direction: "c2s", Profile: "sql_select_default", SQL: "SELECT 1"},
				{Kind: "sql_response", Direction: "s2c", Profile: "sql_select_default", Result: "success"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 12 {
		t.Fatalf("packet_count=%d want 12", len(packets))
	}
	if len(packets[3].Payload) == 0 {
		t.Fatal("pkt[3] payload is empty")
	}
}

func TestPlanDamengIPv4(t *testing.T) {
	// S6: IPv4
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 5236,
		Count:   1,
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Events: []core.DamengEvent{
				{Kind: "connect", Direction: "c2s", Profile: "connect_default"},
				{Kind: "auth_request", Direction: "c2s", Profile: "auth_default", Username: "SYSDBA"},
				{Kind: "auth_response", Direction: "s2c", Profile: "auth_default", Result: "success"},
				{Kind: "sql_request", Direction: "c2s", Profile: "sql_select_default", SQL: "SELECT 1"},
				{Kind: "sql_response", Direction: "s2c", Profile: "sql_select_default", Result: "success"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 12 {
		t.Fatalf("packet_count=%d want 12", len(packets))
	}
	// pkt[3] should have IPv4 L3
	if packets[3].L3.SrcIP != "10.0.0.1" {
		t.Fatalf("pkt[3] src_ip=%q want 10.0.0.1", packets[3].L3.SrcIP)
	}
	if packets[3].L4.DstPort != 5236 {
		t.Fatalf("pkt[3] dst_port=%d want 5236", packets[3].L4.DstPort)
	}
}

func TestPlanDamengIPv6(t *testing.T) {
	// S7: IPv6
	spec := core.FlowSpec{
		SrcIP:   "2001:db8::1",
		DstIP:   "2001:db8::2",
		SrcPort: 12345,
		DstPort: 5236,
		Count:   1,
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Events: []core.DamengEvent{
				{Kind: "connect", Direction: "c2s", Profile: "connect_default"},
				{Kind: "auth_request", Direction: "c2s", Profile: "auth_default", Username: "SYSDBA"},
				{Kind: "auth_response", Direction: "s2c", Profile: "auth_default", Result: "success"},
				{Kind: "sql_request", Direction: "c2s", Profile: "sql_select_default", SQL: "SELECT 1"},
				{Kind: "sql_response", Direction: "s2c", Profile: "sql_select_default", Result: "success"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 12 {
		t.Fatalf("packet_count=%d want 12", len(packets))
	}
	if packets[3].L3.SrcIP != "2001:db8::1" {
		t.Fatalf("pkt[3] src_ip=%q want 2001:db8::1", packets[3].L3.SrcIP)
	}
	if packets[3].L4.DstPort != 5236 {
		t.Fatalf("pkt[3] dst_port=%d want 5236", packets[3].L4.DstPort)
	}
}

func TestPlanDamengMultiSession(t *testing.T) {
	// S8: two independent sessions → 20 packets
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 5236,
		Count:   1,
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Sessions: []core.DamengSession{
				{
					SrcPort: 12345,
					Events: []core.DamengEvent{
						{Kind: "connect", Direction: "c2s", Profile: "connect_default"},
						{Kind: "auth_request", Direction: "c2s", Profile: "auth_default", Username: "SYSDBA"},
						{Kind: "auth_response", Direction: "s2c", Profile: "auth_default", Result: "success"},
					},
				},
				{
					SrcPort: 12346,
					Events: []core.DamengEvent{
						{Kind: "connect", Direction: "c2s", Profile: "connect_default"},
						{Kind: "auth_request", Direction: "c2s", Profile: "auth_default", Username: "SYSDBA"},
						{Kind: "auth_response", Direction: "s2c", Profile: "auth_default", Result: "success"},
					},
				},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 30)
	if len(packets) != 20 {
		t.Fatalf("packet_count=%d want 20", len(packets))
	}
	// First session starts at pkt[0], second session at pkt[10]
	// pkt[0]: first session SYN
	if packets[0].L4.SrcPort != 12345 {
		t.Fatalf("pkt[0] src_port=%d want 12345", packets[0].L4.SrcPort)
	}
	// pkt[10]: second session SYN
	if packets[10].L4.SrcPort != 12346 {
		t.Fatalf("pkt[10] src_port=%d want 12346", packets[10].L4.SrcPort)
	}
	// Verify distinct src ports
	has12345, has12346 := false, false
	for _, p := range packets {
		if p.L4.SrcPort == 12345 {
			has12345 = true
		}
		if p.L4.SrcPort == 12346 {
			has12346 = true
		}
	}
	if !has12345 {
		t.Fatal("src port 12345 not found")
	}
	if !has12346 {
		t.Fatal("src port 12346 not found")
	}
}

func TestPlanDamengDefaultPort(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "20.0.0.1",
		Count: 1,
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Events: []core.DamengEvent{
				{Kind: "connect", Direction: "c2s", Profile: "connect_default"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 8 {
		t.Fatalf("packet_count=%d want 8", len(packets))
	}
	if packets[3].L4.DstPort != 5236 {
		t.Fatalf("dst_port=%d want 5236 (default)", packets[3].L4.DstPort)
	}
}

func TestPlanDamengContextCancel(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "20.0.0.1",
		Dameng: &core.DamengConfig{
			WireProfile: "dm8_profile_pending",
			Events: []core.DamengEvent{
				{Kind: "connect", Direction: "c2s", Profile: "connect_default"},
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	// Drain the channel — with cancelled context should not hang
	count := 0
	for range ch {
		count++
	}
}

// --- Layer Generator tests ---

func TestDamengGeneratorName(t *testing.T) {
	g := &DamengGenerator{}
	if g.Name() != "dameng" {
		t.Fatalf("Name=%q want dameng", g.Name())
	}
}

func TestDamengGeneratorGenerate(t *testing.T) {
	cfg := &core.DamengConfig{
		WireProfile: "dm8_profile_pending",
		Events: []core.DamengEvent{
			{Kind: "connect", Direction: "c2s", Profile: "connect_default"},
			{Kind: "auth_request", Direction: "c2s", Profile: "auth_default", Username: "SYSDBA"},
			{Kind: "auth_response", Direction: "s2c", Profile: "auth_default", Result: "success"},
		},
	}
	var events []layers.MessageEvent
	emit := func(ev layers.MessageEvent) error {
		events = append(events, ev)
		return nil
	}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{Dameng: cfg},
		EmitMsg: emit,
	}
	ctx := context.Background()
	g := &DamengGenerator{}
	err := g.Generate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("events=%d want 3", len(events))
	}
	// First: connect up
	if !events[0].Up {
		t.Fatalf("event[0] Up=false want true")
	}
	if len(events[0].Bytes) == 0 {
		t.Fatal("event[0] bytes empty")
	}
	// Second: auth_request up
	if !events[1].Up {
		t.Fatalf("event[1] Up=false want true")
	}
	// Third: auth_response down
	if events[2].Up {
		t.Fatalf("event[2] Up=true want false")
	}
}

func TestDamengGeneratorGenerateNilConfig(t *testing.T) {
	// P0b-2: 空配置（nil）默认化并产默认流——至少产一条 connect 报文事件。
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	}
	ctx := context.Background()
	g := &DamengGenerator{}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("Generate(nil config) err=%v want nil", err)
	}
	if len(events) != 1 {
		t.Fatalf("events=%d want 1 (default connect)", len(events))
	}
	if !events[0].Up {
		t.Fatal("event[0] Up=false want true (connect is c2s)")
	}
	if len(events[0].Bytes) == 0 {
		t.Fatal("event[0] bytes empty")
	}
}

func TestPlanDamengNilConfigProducesFlow(t *testing.T) {
	// P0b-2: 空配置（nil）→ 链层 Plan 默认化并产默认流（>0 包）。
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
	ch, err := (Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan(nil config) err=%v want nil", err)
	}
	pkts := collectPackets(ch, 20)
	if len(pkts) == 0 {
		t.Fatal("Plan(nil config) produced 0 packets, want default flow")
	}
}

func TestDamengGeneratorGenerateNilReq(t *testing.T) {
	g := &DamengGenerator{}
	err := g.Generate(context.Background(), nil)
	if err == nil || err.Error() != "dameng generator: EmitMsg is nil" {
		t.Fatalf("err=%v want EmitMsg is nil", err)
	}
}

func TestDamengGeneratorGenerateNilEmitMsg(t *testing.T) {
	req := &layers.GenRequest{Meta: layers.FlowMeta{}}
	g := &DamengGenerator{}
	err := g.Generate(context.Background(), req)
	if err == nil || err.Error() != "dameng generator: EmitMsg is nil" {
		t.Fatalf("err=%v want EmitMsg is nil", err)
	}
}

func TestDamengGeneratorGenerateContextCancel(t *testing.T) {
	cfg := &core.DamengConfig{
		WireProfile: "dm8_profile_pending",
		Events: []core.DamengEvent{
			{Kind: "connect", Direction: "c2s", Profile: "connect_default"},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{Dameng: cfg},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	g := &DamengGenerator{}
	err := g.Generate(ctx, req)
	if err == nil {
		t.Fatalf("expected context error")
	}
}

func TestDamengRegister(t *testing.T) {
	gen, err := layers.NewLayerGenerator("dameng")
	if err != nil {
		t.Fatalf("NewLayerGenerator(dameng): %v", err)
	}
	if gen == nil {
		t.Fatalf("generator is nil")
	}
	if gen.Name() != "dameng" {
		t.Fatalf("name=%q want dameng", gen.Name())
	}
}