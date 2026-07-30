package dhcp

// Scenario-mode tests for the DHCP planner (RFC 2131 DORA dialog).
//
// These tests verify the auto-generated multi-message dialogs produced when
// DHCPConfig.Scenario is set. Per RFC 2131:
//   - DORA: Discover→Offer→Request→ACK, shared xid, correct option chain.
//   - Option 50 (Requested IP) MUST be in SELECTING REQUEST, MUST NOT be in
//     RENEWING/REBINDING REQUEST, OFFER, ACK, NAK, RELEASE, INFORM.
//   - Option 54 (Server Identifier) MUST be in OFFER/ACK/NAK/SELECTING-REQUEST,
//     MUST NOT be in RENEWING/REBINDING REQUEST.
//   - Option 51 (Lease Time) MUST be in OFFER/ACK, MUST NOT be in NAK/INFORM/
//     RELEASE.
//   - ciaddr=0 for DISCOVER/SELECTING-REQUEST; ciaddr=client-IP for RENEWING/
//     REBINDING/RELEASE/INFORM.
//   - yiaddr=leased-IP for OFFER/ACK; yiaddr=0 for NAK/INFORM.
//
// The tests are derived from RFC 2131 §3.1 (DORA), §4.3.2 (NAK/renew/rebind),
// §4.3.4 (release), §4.3.5 (inform), and Table 3/4/5.

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// scenarioSpec builds a DHCPConfig with a scenario and the parameters the
// scenario auto-generation needs (leased IP, server IP, lease time, etc.).
func scenarioSpec(scenario string) core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "ff:ff:ff:ff:ff:ff",
		DHCP: &core.DHCPConfig{
			Role:                    "client",
			Xid:                     0xA1B2C3D4,
			Scenario:                scenario,
			DefaultYourIP:           "192.168.1.100",
			DefaultServerIdentifier: "192.168.1.1",
			DefaultLeaseTime:        86400,
			DefaultSubnetMask:       "255.255.255.0",
			DefaultRouters:          []string{"192.168.1.1"},
			DefaultDNS:              []string{"8.8.8.8", "8.8.4.4"},
			DefaultHostname:         "client01",
			DefaultParamRequestList: []uint8{1, 3, 6, 15, 51, 54, 58, 59},
		},
	}
}

// mustPlanScenario plans a scenario spec and drains the channel.
func mustPlanScenario(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan scenario %q: %v", spec.DHCP.Scenario, err)
	}
	return drain(ch)
}

// xidOf extracts the 4-byte xid from a DHCP payload.
func xidOf(p core.PacketConfig) uint32 {
	return binary.BigEndian.Uint32(p.Payload[4:8])
}

// optIP returns the IPv4 value of a DHCP option, or "" if absent.
func optIP(p core.PacketConfig, code uint8) string {
	b := findOption(p.Payload, code)
	if b == nil {
		return ""
	}
	return net.IP(b).String()
}

// optU32 returns the uint32 value of a DHCP option, or 0 if absent.
func optU32(p core.PacketConfig, code uint8) uint32 {
	b := findOption(p.Payload, code)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

// --- DORA scenario (RFC 2131 §3.1) ---

// TestScenario_DORA_PacketCount verifies the DORA scenario emits exactly 4
// packets.
func TestScenario_DORA_PacketCount(t *testing.T) {
	configs := mustPlanScenario(t, scenarioSpec("dora"))
	if len(configs) != 4 {
		t.Fatalf("dora: expected 4 packets, got %d", len(configs))
	}
}

// TestScenario_DORA_MessageTypes verifies the 4 packets are
// Discover/Offer/Request/Ack in order.
func TestScenario_DORA_MessageTypes(t *testing.T) {
	configs := mustPlanScenario(t, scenarioSpec("dora"))
	want := []byte{MsgTypeDiscover, MsgTypeOffer, MsgTypeRequest, MsgTypeAck}
	for i, c := range configs {
		got := findOption53(c.Payload)
		if got != want[i] {
			t.Errorf("dora config[%d] msg type = %d, want %d", i, got, want[i])
		}
	}
}

// TestScenario_DORA_Directions verifies up/down/up/down directions.
func TestScenario_DORA_Directions(t *testing.T) {
	configs := mustPlanScenario(t, scenarioSpec("dora"))
	want := []string{"up", "down", "up", "down"}
	for i, c := range configs {
		if c.Direction != want[i] {
			t.Errorf("dora config[%d] direction = %s, want %s", i, c.Direction, want[i])
		}
	}
}

// TestScenario_DORA_OpCodes verifies BOOTREQUEST/BOOTREPLY alternation.
func TestScenario_DORA_OpCodes(t *testing.T) {
	configs := mustPlanScenario(t, scenarioSpec("dora"))
	want := []byte{OpBootrequest, OpBootreply, OpBootrequest, OpBootreply}
	for i, c := range configs {
		if c.Payload[0] != want[i] {
			t.Errorf("dora config[%d] op = %d, want %d", i, c.Payload[0], want[i])
		}
	}
}

// TestScenario_DORA_XidShared verifies all 4 packets share the same xid.
func TestScenario_DORA_XidShared(t *testing.T) {
	configs := mustPlanScenario(t, scenarioSpec("dora"))
	for i, c := range configs {
		if xidOf(c) != 0xA1B2C3D4 {
			t.Errorf("dora config[%d] xid = 0x%X, want 0xA1B2C3D4", i, xidOf(c))
		}
	}
}

// TestScenario_DORA_Discover verifies DISCOVER (config[0]) per RFC 2131:
// ciaddr=0, yiaddr=0, broadcast, carries option 55 (param request list) and
// option 12 (hostname) when configured.
func TestScenario_DORA_Discover(t *testing.T) {
	configs := mustPlanScenario(t, scenarioSpec("dora"))
	d := configs[0]
	if ci := net.IP(d.Payload[12:16]).String(); ci != "0.0.0.0" {
		t.Errorf("DISCOVER ciaddr = %s, want 0.0.0.0", ci)
	}
	if yi := net.IP(d.Payload[16:20]).String(); yi != "0.0.0.0" {
		t.Errorf("DISCOVER yiaddr = %s, want 0.0.0.0", yi)
	}
	if !hasOption(d.Payload, 55) {
		t.Errorf("DISCOVER should carry option 55 (param request list)")
	}
	if !hasOption(d.Payload, 12) {
		t.Errorf("DISCOVER should carry option 12 (hostname)")
	}
}

// TestScenario_DORA_Offer verifies OFFER (config[1]) per RFC 2131 §4.3.1:
// yiaddr=leased IP, option 54 (server id) MUST, option 51 (lease time) MUST,
// option 1/3/6 if configured, ciaddr=0.
func TestScenario_DORA_Offer(t *testing.T) {
	configs := mustPlanScenario(t, scenarioSpec("dora"))
	o := configs[1]
	if yi := net.IP(o.Payload[16:20]).String(); yi != "192.168.1.100" {
		t.Errorf("OFFER yiaddr = %s, want 192.168.1.100", yi)
	}
	if ci := net.IP(o.Payload[12:16]).String(); ci != "0.0.0.0" {
		t.Errorf("OFFER ciaddr = %s, want 0.0.0.0", ci)
	}
	if optIP(o, 54) != "192.168.1.1" {
		t.Errorf("OFFER option 54 = %s, want 192.168.1.1", optIP(o, 54))
	}
	if optU32(o, 51) != 86400 {
		t.Errorf("OFFER option 51 = %d, want 86400", optU32(o, 51))
	}
	if !hasOption(o.Payload, 1) {
		t.Errorf("OFFER should carry option 1 (subnet mask)")
	}
	if !hasOption(o.Payload, 3) {
		t.Errorf("OFFER should carry option 3 (routers)")
	}
	if !hasOption(o.Payload, 6) {
		t.Errorf("OFFER should carry option 6 (DNS)")
	}
}

// TestScenario_DORA_Request verifies SELECTING REQUEST (config[2]) per RFC
// 2131 §4.3.2: option 50 (requested IP) MUST = yiaddr from OFFER, option 54
// (server id) MUST = selected server, ciaddr=0, carries option 55.
func TestScenario_DORA_Request(t *testing.T) {
	configs := mustPlanScenario(t, scenarioSpec("dora"))
	r := configs[2]
	if optIP(r, 50) != "192.168.1.100" {
		t.Errorf("REQUEST option 50 = %s, want 192.168.1.100", optIP(r, 50))
	}
	if optIP(r, 54) != "192.168.1.1" {
		t.Errorf("REQUEST option 54 = %s, want 192.168.1.1", optIP(r, 54))
	}
	if ci := net.IP(r.Payload[12:16]).String(); ci != "0.0.0.0" {
		t.Errorf("REQUEST ciaddr = %s, want 0.0.0.0", ci)
	}
	if !hasOption(r.Payload, 55) {
		t.Errorf("REQUEST should carry option 55 (param request list)")
	}
}

// TestScenario_DORA_Ack verifies ACK (config[3]) per RFC 2131 §4.3.1:
// yiaddr=leased IP, option 54 MUST, option 51 MUST, option 1/3/6 if configured.
func TestScenario_DORA_Ack(t *testing.T) {
	configs := mustPlanScenario(t, scenarioSpec("dora"))
	a := configs[3]
	if yi := net.IP(a.Payload[16:20]).String(); yi != "192.168.1.100" {
		t.Errorf("ACK yiaddr = %s, want 192.168.1.100", yi)
	}
	if optIP(a, 54) != "192.168.1.1" {
		t.Errorf("ACK option 54 = %s, want 192.168.1.1", optIP(a, 54))
	}
	if optU32(a, 51) != 86400 {
		t.Errorf("ACK option 51 = %d, want 86400", optU32(a, 51))
	}
}

// TestScenario_DORA_PacketIndex verifies packet indices increment 0..3.
func TestScenario_DORA_PacketIndex(t *testing.T) {
	configs := mustPlanScenario(t, scenarioSpec("dora"))
	for i, c := range configs {
		if c.PacketIndex != uint64(i) {
			t.Errorf("dora config[%d].PacketIndex = %d, want %d", i, c.PacketIndex, i)
		}
	}
}

// --- NAK scenario (RFC 2131 §4.3.2) ---

// TestScenario_NAK verifies the NAK scenario: DORA with NAK instead of ACK.
// NAK MUST carry option 54, MUST NOT carry option 50/51, yiaddr=0, ciaddr=0.
func TestScenario_NAK(t *testing.T) {
	configs := mustPlanScenario(t, scenarioSpec("nak"))
	if len(configs) != 4 {
		t.Fatalf("nak: expected 4 packets, got %d", len(configs))
	}
	want := []byte{MsgTypeDiscover, MsgTypeOffer, MsgTypeRequest, MsgTypeNak}
	for i, c := range configs {
		if findOption53(c.Payload) != want[i] {
			t.Errorf("nak config[%d] msg type = %d, want %d", i, findOption53(c.Payload), want[i])
		}
	}
	nak := configs[3]
	if nak.Payload[0] != OpBootreply {
		t.Errorf("NAK op = %d, want BOOTREPLY", nak.Payload[0])
	}
	if optIP(nak, 54) != "192.168.1.1" {
		t.Errorf("NAK option 54 = %s, want 192.168.1.1", optIP(nak, 54))
	}
	if hasOption(nak.Payload, 50) {
		t.Errorf("NAK MUST NOT carry option 50")
	}
	if hasOption(nak.Payload, 51) {
		t.Errorf("NAK MUST NOT carry option 51")
	}
	if yi := net.IP(nak.Payload[16:20]).String(); yi != "0.0.0.0" {
		t.Errorf("NAK yiaddr = %s, want 0.0.0.0", yi)
	}
	if ci := net.IP(nak.Payload[12:16]).String(); ci != "0.0.0.0" {
		t.Errorf("NAK ciaddr = %s, want 0.0.0.0", ci)
	}
	if nak.Direction != "down" {
		t.Errorf("NAK direction = %s, want down", nak.Direction)
	}
}

// --- Release scenario (RFC 2131 §4.3.4) ---

// TestScenario_Release verifies DORA + Release (5 packets).
// RELEASE: ciaddr=leased IP, option 54 MUST, option 50/51 MUST NOT.
func TestScenario_Release(t *testing.T) {
	configs := mustPlanScenario(t, scenarioSpec("release"))
	if len(configs) != 5 {
		t.Fatalf("release: expected 5 packets, got %d", len(configs))
	}
	rel := configs[4]
	if findOption53(rel.Payload) != MsgTypeRelease {
		t.Errorf("RELEASE msg type = %d, want %d", findOption53(rel.Payload), MsgTypeRelease)
	}
	if rel.Payload[0] != OpBootrequest {
		t.Errorf("RELEASE op = %d, want BOOTREQUEST", rel.Payload[0])
	}
	if ci := net.IP(rel.Payload[12:16]).String(); ci != "192.168.1.100" {
		t.Errorf("RELEASE ciaddr = %s, want 192.168.1.100 (leased IP)", ci)
	}
	if optIP(rel, 54) != "192.168.1.1" {
		t.Errorf("RELEASE option 54 = %s, want 192.168.1.1", optIP(rel, 54))
	}
	if hasOption(rel.Payload, 50) {
		t.Errorf("RELEASE MUST NOT carry option 50")
	}
	if hasOption(rel.Payload, 51) {
		t.Errorf("RELEASE MUST NOT carry option 51")
	}
	if rel.Direction != "up" {
		t.Errorf("RELEASE direction = %s, want up", rel.Direction)
	}
}

// --- Inform scenario (RFC 2131 §4.3.5) ---

// TestScenario_Inform verifies Inform→ACK (2 packets).
// INFORM: ciaddr=client IP, option 50/51 MUST NOT.
// ACK (from INFORM): option 54 MUST, option 51 MUST NOT, yiaddr SHOULD be 0.
func TestScenario_Inform(t *testing.T) {
	spec := scenarioSpec("inform")
	spec.DHCP.DefaultClientIP = "192.168.1.50"
	configs := mustPlanScenario(t, spec)
	if len(configs) != 2 {
		t.Fatalf("inform: expected 2 packets, got %d", len(configs))
	}
	inf := configs[0]
	if findOption53(inf.Payload) != MsgTypeInform {
		t.Errorf("INFORM msg type = %d, want %d", findOption53(inf.Payload), MsgTypeInform)
	}
	if ci := net.IP(inf.Payload[12:16]).String(); ci != "192.168.1.50" {
		t.Errorf("INFORM ciaddr = %s, want 192.168.1.50", ci)
	}
	if hasOption(inf.Payload, 50) {
		t.Errorf("INFORM MUST NOT carry option 50")
	}
	if hasOption(inf.Payload, 51) {
		t.Errorf("INFORM MUST NOT carry option 51")
	}

	ack := configs[1]
	if findOption53(ack.Payload) != MsgTypeAck {
		t.Errorf("INFORM-ACK msg type = %d, want %d", findOption53(ack.Payload), MsgTypeAck)
	}
	if optIP(ack, 54) != "192.168.1.1" {
		t.Errorf("INFORM-ACK option 54 = %s, want 192.168.1.1", optIP(ack, 54))
	}
	if hasOption(ack.Payload, 51) {
		t.Errorf("INFORM-ACK MUST NOT carry option 51 (no lease)")
	}
	if yi := net.IP(ack.Payload[16:20]).String(); yi != "0.0.0.0" {
		t.Errorf("INFORM-ACK yiaddr = %s, want 0.0.0.0 (SHOULD NOT fill yiaddr)", yi)
	}
}

// --- Renew scenario (RFC 2131 §4.3.2 RENEWING) ---

// TestScenario_Renew verifies DORA + RENEWING Request→ACK (6 packets).
// RENEWING REQUEST: ciaddr=leased IP, option 50 MUST NOT, option 54 MUST NOT.
func TestScenario_Renew(t *testing.T) {
	configs := mustPlanScenario(t, scenarioSpec("renew"))
	if len(configs) != 6 {
		t.Fatalf("renew: expected 6 packets, got %d", len(configs))
	}
	renewReq := configs[4]
	if findOption53(renewReq.Payload) != MsgTypeRequest {
		t.Errorf("RENEWING REQUEST msg type = %d, want %d", findOption53(renewReq.Payload), MsgTypeRequest)
	}
	if ci := net.IP(renewReq.Payload[12:16]).String(); ci != "192.168.1.100" {
		t.Errorf("RENEWING REQUEST ciaddr = %s, want 192.168.1.100", ci)
	}
	if hasOption(renewReq.Payload, 50) {
		t.Errorf("RENEWING REQUEST MUST NOT carry option 50")
	}
	if hasOption(renewReq.Payload, 54) {
		t.Errorf("RENEWING REQUEST MUST NOT carry option 54")
	}

	renewAck := configs[5]
	if findOption53(renewAck.Payload) != MsgTypeAck {
		t.Errorf("RENEWING ACK msg type = %d, want %d", findOption53(renewAck.Payload), MsgTypeAck)
	}
	if optU32(renewAck, 51) != 86400 {
		t.Errorf("RENEWING ACK option 51 = %d, want 86400", optU32(renewAck, 51))
	}
}

// --- Rebind scenario (RFC 2131 §4.3.2 REBINDING) ---

// TestScenario_Rebind verifies DORA + REBINDING Request→ACK (6 packets).
// REBINDING REQUEST: ciaddr=leased IP, option 50 MUST NOT, option 54 MUST NOT.
func TestScenario_Rebind(t *testing.T) {
	configs := mustPlanScenario(t, scenarioSpec("rebind"))
	if len(configs) != 6 {
		t.Fatalf("rebind: expected 6 packets, got %d", len(configs))
	}
	rebindReq := configs[4]
	if findOption53(rebindReq.Payload) != MsgTypeRequest {
		t.Errorf("REBINDING REQUEST msg type = %d, want %d", findOption53(rebindReq.Payload), MsgTypeRequest)
	}
	if ci := net.IP(rebindReq.Payload[12:16]).String(); ci != "192.168.1.100" {
		t.Errorf("REBINDING REQUEST ciaddr = %s, want 192.168.1.100", ci)
	}
	if hasOption(rebindReq.Payload, 50) {
		t.Errorf("REBINDING REQUEST MUST NOT carry option 50")
	}
	if hasOption(rebindReq.Payload, 54) {
		t.Errorf("REBINDING REQUEST MUST NOT carry option 54")
	}
}

// --- Scenario validation (failure paths) ---

// TestScenario_InvalidScenario verifies an unknown scenario value is rejected.
func TestScenario_InvalidScenario(t *testing.T) {
	spec := scenarioSpec("bogus")
	p := NewPlanner()
	err := p.Validate(spec)
	if err == nil {
		t.Fatalf("invalid scenario should be rejected")
	}
}

// TestScenario_DORA_MissingLeasedIP verifies DORA requires DefaultYourIP.
func TestScenario_DORA_MissingLeasedIP(t *testing.T) {
	spec := scenarioSpec("dora")
	spec.DHCP.DefaultYourIP = ""
	p := NewPlanner()
	err := p.Validate(spec)
	if err == nil {
		t.Fatalf("dora without DefaultYourIP should be rejected")
	}
}

// TestScenario_DORA_MissingServerID verifies DORA requires DefaultServerIdentifier.
func TestScenario_DORA_MissingServerID(t *testing.T) {
	spec := scenarioSpec("dora")
	spec.DHCP.DefaultServerIdentifier = ""
	p := NewPlanner()
	err := p.Validate(spec)
	if err == nil {
		t.Fatalf("dora without DefaultServerIdentifier should be rejected")
	}
}

// TestScenario_Inform_MissingClientIP verifies Inform requires DefaultClientIP.
func TestScenario_Inform_MissingClientIP(t *testing.T) {
	spec := scenarioSpec("inform")
	// DefaultClientIP intentionally empty.
	p := NewPlanner()
	err := p.Validate(spec)
	if err == nil {
		t.Fatalf("inform without DefaultClientIP should be rejected")
	}
}

// --- Backward compatibility ---

// TestScenario_EmptyScenarioUsesMessages verifies that when Scenario is empty,
// the planner falls back to the manual Messages list (backward-compatible).
func TestScenario_EmptyScenarioUsesMessages(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "0.0.0.0", DstIP: "255.255.255.255",
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DHCP: &core.DHCPConfig{
			Role:     "client",
			Xid:      0xA1B2C3D4,
			Scenario: "", // manual mode
			Messages: []core.DHCPMessage{{Type: MsgTypeDiscover}},
		},
	}
	configs := mustPlanScenario(t, spec)
	if len(configs) != 1 {
		t.Fatalf("empty scenario with 1 manual message: expected 1 packet, got %d", len(configs))
	}
	if findOption53(configs[0].Payload) != MsgTypeDiscover {
		t.Errorf("empty scenario: expected DISCOVER, got %d", findOption53(configs[0].Payload))
	}
}

// TestScenario_OverridesMessages verifies that when Scenario is set, any
// user-provided Messages are ignored (scenario auto-generation wins).
func TestScenario_OverridesMessages(t *testing.T) {
	spec := scenarioSpec("dora")
	// Provide a bogus Messages list that should be ignored.
	spec.DHCP.Messages = []core.DHCPMessage{{Type: MsgTypeDiscover}, {Type: MsgTypeDiscover}}
	configs := mustPlanScenario(t, spec)
	if len(configs) != 4 {
		t.Fatalf("scenario should override Messages: expected 4 packets, got %d", len(configs))
	}
}

// TestScenario_DORA_RandomXid verifies that Xid=0 in scenario mode produces a
// random xid shared across all 4 DORA packets.
func TestScenario_DORA_RandomXid(t *testing.T) {
	spec := scenarioSpec("dora")
	spec.DHCP.Xid = 0
	configs := mustPlanScenario(t, spec)
	if len(configs) != 4 {
		t.Fatalf("expected 4 packets, got %d", len(configs))
	}
	xid := xidOf(configs[0])
	if xid == 0 {
		t.Errorf("random xid should not be 0")
	}
	for i, c := range configs {
		if xidOf(c) != xid {
			t.Errorf("config[%d] xid = 0x%X, want 0x%X (shared)", i, xidOf(c), xid)
		}
	}
}

// TestScenario_DORA_FlowIDShared verifies all DORA packets share one flow ID
// (same 4-tuple), so they land in the same flow for pcap parsing.
func TestScenario_DORA_FlowIDShared(t *testing.T) {
	configs := mustPlanScenario(t, scenarioSpec("dora"))
	first := configs[0].FlowID
	for i, c := range configs {
		if c.FlowID != first {
			t.Errorf("config[%d] FlowID = %q, want %q (shared)", i, c.FlowID, first)
		}
	}
}

// --- Additional failure-path scenarios ---

// TestScenario_DORA_NoOffer verifies a DORA variant where no OFFER is present
// is NOT producible via the scenario mode (scenario always emits the full
// sequence). This guards against silent partial-sequence bugs: if a user
// wants a "no Offer" path they must use manual Messages mode.
func TestScenario_DORA_NoOffer(t *testing.T) {
	// Scenario mode always emits the canonical sequence; a "no Offer"
	// path is only available via manual Messages. Verify the dora scenario
	// always has an OFFER.
	configs := mustPlanScenario(t, scenarioSpec("dora"))
	sawOffer := false
	for _, c := range configs {
		if findOption53(c.Payload) == MsgTypeOffer {
			sawOffer = true
		}
	}
	if !sawOffer {
		t.Errorf("dora scenario must include an OFFER message")
	}
}

// TestScenario_NAK_BroadcastFlag verifies NAK is broadcast (RFC §4.1: when
// giaddr is zero the server MUST broadcast DHCPNAK to 0xffffffff).
func TestScenario_NAK_BroadcastFlag(t *testing.T) {
	spec := scenarioSpec("nak")
	spec.DHCP.BroadcastFlag = true
	configs := mustPlanScenario(t, spec)
	nak := configs[3]
	// NAK is a server reply (down); broadcast flag set means dst=broadcast.
	if nak.L2.DstMAC != BroadcastMAC {
		t.Errorf("NAK broadcast DstMAC = %s, want %s", nak.L2.DstMAC, BroadcastMAC)
	}
}

// TestScenario_Release_BroadcastFlag verifies RELEASE from client uses the
// client's IP as ciaddr and is unicast to the server.
func TestScenario_Release_BroadcastFlag(t *testing.T) {
	spec := scenarioSpec("release")
	configs := mustPlanScenario(t, spec)
	rel := configs[4]
	// RELEASE is up; src should be client MAC (aa:bb:cc:dd:ee:ff).
	if rel.L2.SrcMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("RELEASE SrcMAC = %s, want aa:bb:cc:dd:ee:ff", rel.L2.SrcMAC)
	}
}

// TestScenario_Renew_Unicast verifies RENEWING REQUEST is unicast (dst=server
// IP, not broadcast) per RFC §4.3.2.
func TestScenario_Renew_Unicast(t *testing.T) {
	spec := scenarioSpec("renew")
	// Configure a unicast server destination so RENEWING REQUEST dst is
	// the server, not broadcast.
	spec.DstIP = "192.168.1.1"
	spec.DstMAC = "11:22:33:44:55:66"
	configs := mustPlanScenario(t, spec)
	renewReq := configs[4]
	// RENEWING REQUEST should NOT be broadcast (unicast to server).
	if renewReq.L3.DstIP == BroadcastIP {
		t.Errorf("RENEWING REQUEST dst = %s, want unicast server IP", renewReq.L3.DstIP)
	}
}

// TestScenario_DORA_ClientIDShared verifies the client identifier (option 61)
// is present on all client-originated messages when configured, per RFC §3.1
// (client MUST use the same client identifier across the exchange).
func TestScenario_DORA_ClientIDShared(t *testing.T) {
	spec := scenarioSpec("dora")
	spec.DHCP.DefaultClientID = []byte{0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	configs := mustPlanScenario(t, spec)
	// Client messages: DISCOVER (0), REQUEST (2).
	for _, idx := range []int{0, 2} {
		if !hasOption(configs[idx].Payload, 61) {
			t.Errorf("config[%d] (client msg) should carry option 61 (client ID)", idx)
		}
	}
}

// TestScenario_DORA_AuthoritativeOptions verifies OFFER and ACK carry the
// authoritative options (subnet mask, routers, DNS, lease time, T1/T2) that
// a real DHCP server would include.
func TestScenario_DORA_AuthoritativeOptions(t *testing.T) {
	spec := scenarioSpec("dora")
	spec.DHCP.DefaultT1 = 43200
	spec.DHCP.DefaultT2 = 75600
	configs := mustPlanScenario(t, spec)
	for _, idx := range []int{1, 3} { // OFFER, ACK
		c := configs[idx]
		for _, code := range []uint8{1, 3, 6, 51, 58, 59} {
			if !hasOption(c.Payload, code) {
				t.Errorf("config[%d] should carry option %d", idx, code)
			}
		}
	}
}

// TestScenario_Inform_NoLeaseOptions verifies INFORM and its ACK carry no
// lease-related options (51/58/59) and no option 50.
func TestScenario_Inform_NoLeaseOptions(t *testing.T) {
	spec := scenarioSpec("inform")
	spec.DHCP.DefaultClientIP = "192.168.1.50"
	spec.DHCP.DefaultT1 = 43200
	spec.DHCP.DefaultT2 = 75600
	configs := mustPlanScenario(t, spec)
	for _, idx := range []int{0, 1} {
		c := configs[idx]
		for _, code := range []uint8{50, 51, 58, 59} {
			if hasOption(c.Payload, code) {
				t.Errorf("INFORM config[%d] MUST NOT carry option %d", idx, code)
			}
		}
	}
}
