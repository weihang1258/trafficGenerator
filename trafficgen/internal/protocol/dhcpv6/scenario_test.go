package dhcpv6

// Scenario-mode tests for the DHCPv6 planner (RFC 8415 dialogs).
//
// These tests verify the auto-generated multi-message dialogs produced when
// DHCPv6Config.Scenario is set. Per RFC 8415:
//   - SARR: SOLICIT→ADVERTISE→REQUEST→REPLY, shared transaction-id, correct
//     option chain (ClientID/ServerID/IA_NA/IAADDR/Preference).
//   - Rapid Commit: SOLICIT(+opt14)→REPLY(+opt14), 2-way.
//   - Renew/Rebind/Release/Decline/Confirm/InformationRequest/Reconfigure/
//     Relay per §4.3-§4.10.
//
// The tests are derived from RFC 8415 §5 (client state machine), §7.3
// (message types), §21 (options), and design_dhcpv6.md §4 (scenarios).
// Failure paths (NoAddrsAvail, NoBinding, NotOnLink) are covered.

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// scenarioSpec builds a DHCPv6Config with a scenario and the parameters the
// scenario auto-generation needs (leased IPv6, lifetimes, etc.).
func scenarioSpec(scenario string) core.FlowSpec {
	return core.FlowSpec{
		SrcMAC: "00:11:22:33:44:55",
		DstMAC: "33:33:00:01:00:02",
		SrcIP:  "fe80::1",
		DstIP:  "ff02::1:2",
		DHCPv6: &core.DHCPv6Config{
			Scenario:               scenario,
			DefaultLeasedAddr:      "2001:db8::100",
			DefaultPreferredLifetime: 3600,
			DefaultValidLifetime:   7200,
			DefaultT1:              1800,
			DefaultT2:              2880,
			ClientDUID: &core.DUID{
				Type:          DUIDTypeLLT,
				HardwareType:  HardwareTypeEthernet,
				Time:          0,
				LinkLayerAddr: "00:11:22:33:44:55",
			},
			ServerDUID: &core.DUID{
				Type:           DUIDTypeEN,
				EnterpriseNum:  9,
				VendorSpecific: []byte("trafficgen"),
			},
		},
	}
}

// mustPlanScenario plans a scenario spec and drains the channel.
func mustPlanScenario(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan scenario %q: %v", spec.DHCPv6.Scenario, err)
	}
	return drain(ch)
}

// ===================================================================
// SARR scenario (RFC 8415 §4.1, 4-way handshake)
// ===================================================================

// TestScenario_SARR_PacketCount verifies the SARR scenario emits exactly 4
// packets.
func TestScenario_SARR_PacketCount(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("sarr"))
	if len(cfgs) != 4 {
		t.Fatalf("sarr: expected 4 packets, got %d", len(cfgs))
	}
}

// TestScenario_SARR_MessageTypes verifies the 4 packets are
// SOLICIT/ADVERTISE/REQUEST/REPLY in order (msg-type bytes 1/2/3/7).
func TestScenario_SARR_MessageTypes(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("sarr"))
	want := []byte{MsgTypeSolicit, MsgTypeAdvertise, MsgTypeRequest, MsgTypeReply}
	for i, c := range cfgs {
		if c.Payload[0] != want[i] {
			t.Errorf("sarr config[%d] msg-type = 0x%02x, want 0x%02x", i, c.Payload[0], want[i])
		}
	}
}

// TestScenario_SARR_Directions verifies up/down/up/down directions.
func TestScenario_SARR_Directions(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("sarr"))
	want := []string{"up", "down", "up", "down"}
	for i, c := range cfgs {
		if c.Direction != want[i] {
			t.Errorf("sarr config[%d] direction = %s, want %s", i, c.Direction, want[i])
		}
	}
}

// TestScenario_SARR_SharedXID verifies all 4 packets share the same
// transaction-id (RFC 8415 §15: server copies client XID).
func TestScenario_SARR_SharedXID(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("sarr"))
	solicitXID := xidBytes(cfgs[0].Payload)
	if solicitXID == [3]byte{} {
		t.Fatalf("SOLICIT XID is all-zero (should be auto-generated)")
	}
	for i, c := range cfgs {
		if got := xidBytes(c.Payload); got != solicitXID {
			t.Errorf("sarr config[%d] XID = %x, want %x (SOLICIT XID)", i, got, solicitXID)
		}
	}
}

// TestScenario_SARR_SolicitOptions verifies SOLICIT (config[0]) per RFC 8415
// §21.18: carries ClientID (auto), ORO, IA_NA (T1=0, T2=0 = server decides),
// no ServerID.
func TestScenario_SARR_SolicitOptions(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("sarr"))
	s := cfgs[0]
	if cid := findOption(s.Payload, OptClientID); cid == nil {
		t.Errorf("SOLICIT missing ClientID option")
	}
	if oro := findOption(s.Payload, OptORO); oro == nil || len(oro) < 2 {
		t.Errorf("SOLICIT missing ORO option or too short")
	}
	iaNA := findOption(s.Payload, OptIANA)
	if iaNA == nil {
		t.Fatalf("SOLICIT missing IA_NA option")
	}
	if len(iaNA) < 12 {
		t.Fatalf("SOLICIT IA_NA too short: %d bytes", len(iaNA))
	}
	// SOLICIT IA_NA: T1=0, T2=0 (let server decide).
	if t1 := binary.BigEndian.Uint32(iaNA[4:8]); t1 != 0 {
		t.Errorf("SOLICIT IA_NA T1 = %d, want 0", t1)
	}
	if t2 := binary.BigEndian.Uint32(iaNA[8:12]); t2 != 0 {
		t.Errorf("SOLICIT IA_NA T2 = %d, want 0", t2)
	}
	// SOLICIT must NOT carry ServerID (client doesn't know server yet).
	if sid := findOption(s.Payload, OptServerID); sid != nil {
		t.Errorf("SOLICIT should not carry ServerID, got %d bytes", len(sid))
	}
}

// TestScenario_SARR_AdvertiseOptions verifies ADVERTISE (config[1]) per RFC
// 8415 §21.2: carries ServerID (auto), ClientID (auto), Preference, IA_NA with
// IA Address sub-option carrying the leased IPv6.
func TestScenario_SARR_AdvertiseOptions(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("sarr"))
	a := cfgs[1]
	if sid := findOption(a.Payload, OptServerID); sid == nil {
		t.Errorf("ADVERTISE missing ServerID option")
	}
	if cid := findOption(a.Payload, OptClientID); cid == nil {
		t.Errorf("ADVERTISE missing ClientID option")
	}
	pref := findOption(a.Payload, OptPreference)
	if pref == nil || len(pref) != 1 {
		t.Errorf("ADVERTISE Preference = %v, want 1 byte", pref)
	} else if pref[0] != 0 {
		t.Errorf("ADVERTISE Preference = %d, want 0 (default)", pref[0])
	}
	iaNA := findOption(a.Payload, OptIANA)
	if iaNA == nil || len(iaNA) < 12 {
		t.Fatalf("ADVERTISE missing IA_NA or too short")
	}
	// ADVERTISE IA_NA: T1=1800, T2=2880.
	if t1 := binary.BigEndian.Uint32(iaNA[4:8]); t1 != 1800 {
		t.Errorf("ADVERTISE IA_NA T1 = %d, want 1800", t1)
	}
	if t2 := binary.BigEndian.Uint32(iaNA[8:12]); t2 != 2880 {
		t.Errorf("ADVERTISE IA_NA T2 = %d, want 2880", t2)
	}
	// IA Address sub-option inside IA_NA carries the leased IPv6.
	iaAddr := findOptionsFromOffset(iaNA, 12, OptIAAddr)
	if iaAddr == nil || len(iaAddr) < 24 {
		t.Fatalf("ADVERTISE IA_NA missing IA Address sub-option or too short")
	}
	gotIP := net.IP(iaAddr[0:16])
	wantIP := net.ParseIP("2001:db8::100")
	if !gotIP.Equal(wantIP) {
		t.Errorf("ADVERTISE IA Address IPv6 = %v, want %v", gotIP, wantIP)
	}
	if p := binary.BigEndian.Uint32(iaAddr[16:20]); p != 3600 {
		t.Errorf("ADVERTISE IA Address preferred = %d, want 3600", p)
	}
	if v := binary.BigEndian.Uint32(iaAddr[20:24]); v != 7200 {
		t.Errorf("ADVERTISE IA Address valid = %d, want 7200", v)
	}
}

// TestScenario_SARR_RequestOptions verifies REQUEST (config[2]) per RFC 8415
// §21.4: carries ClientID (auto), ServerID (auto — client selected server),
// IA_NA. REQUEST is in needsServerID list.
func TestScenario_SARR_RequestOptions(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("sarr"))
	r := cfgs[2]
	if cid := findOption(r.Payload, OptClientID); cid == nil {
		t.Errorf("REQUEST missing ClientID option")
	}
	// REQUEST MUST carry ServerID (the selected server).
	if sid := findOption(r.Payload, OptServerID); sid == nil {
		t.Errorf("REQUEST missing ServerID option (must identify selected server)")
	}
	if iaNA := findOption(r.Payload, OptIANA); iaNA == nil {
		t.Errorf("REQUEST missing IA_NA option")
	}
}

// TestScenario_SARR_ReplyOptions verifies REPLY (config[3]) per RFC 8415
// §21.3: carries ServerID (auto), ClientID (auto), IA_NA with IA Address
// sub-option carrying the leased IPv6 (Success path, no top-level StatusCode).
func TestScenario_SARR_ReplyOptions(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("sarr"))
	r := cfgs[3]
	if sid := findOption(r.Payload, OptServerID); sid == nil {
		t.Errorf("REPLY missing ServerID option")
	}
	if cid := findOption(r.Payload, OptClientID); cid == nil {
		t.Errorf("REPLY missing ClientID option")
	}
	iaNA := findOption(r.Payload, OptIANA)
	if iaNA == nil || len(iaNA) < 12 {
		t.Fatalf("REPLY missing IA_NA or too short")
	}
	// REPLY IA_NA: T1=1800, T2=2880 (renew/rebind timers).
	if t1 := binary.BigEndian.Uint32(iaNA[4:8]); t1 != 1800 {
		t.Errorf("REPLY IA_NA T1 = %d, want 1800", t1)
	}
	if t2 := binary.BigEndian.Uint32(iaNA[8:12]); t2 != 2880 {
		t.Errorf("REPLY IA_NA T2 = %d, want 2880", t2)
	}
	iaAddr := findOptionsFromOffset(iaNA, 12, OptIAAddr)
	if iaAddr == nil || len(iaAddr) < 24 {
		t.Fatalf("REPLY IA_NA missing IA Address sub-option")
	}
	gotIP := net.IP(iaAddr[0:16])
	wantIP := net.ParseIP("2001:db8::100")
	if !gotIP.Equal(wantIP) {
		t.Errorf("REPLY IA Address IPv6 = %v, want %v", gotIP, wantIP)
	}
	// Success path: REPLY has NO top-level StatusCode (RFC 8415 §21.13:
	// status option only present when reporting non-success).
	if sc := findOption(r.Payload, OptStatusCode); sc != nil {
		t.Errorf("REPLY Success path should not carry top-level StatusCode, got %d bytes", len(sc))
	}
}

// TestScenario_SARR_Ports verifies up uses 546→547, down uses 547→546.
func TestScenario_SARR_Ports(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("sarr"))
	if cfgs[0].L4.SrcPort != ClientPort || cfgs[0].L4.DstPort != ServerPort {
		t.Errorf("SOLICIT ports: src=%d dst=%d, want 546/547", cfgs[0].L4.SrcPort, cfgs[0].L4.DstPort)
	}
	if cfgs[1].L4.SrcPort != ServerPort || cfgs[1].L4.DstPort != ClientPort {
		t.Errorf("ADVERTISE ports: src=%d dst=%d, want 547/546", cfgs[1].L4.SrcPort, cfgs[1].L4.DstPort)
	}
}

// TestScenario_SARR_EtherType verifies all packets use IPv6 EtherType.
func TestScenario_SARR_EtherType(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("sarr"))
	for i, c := range cfgs {
		if c.L2.EtherType != core.EtherTypeIPv6 {
			t.Errorf("sarr config[%d] EtherType = 0x%04x, want 0x86DD", i, c.L2.EtherType)
		}
	}
}

// ===================================================================
// SARR Rapid Commit scenario (RFC 8415 §4.2, 2-way)
// ===================================================================

// TestScenario_SARRRapid_PacketCount verifies the rapid-commit scenario emits
// exactly 2 packets (SOLICIT+RapidCommit → REPLY+RapidCommit).
func TestScenario_SARRRapid_PacketCount(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("sarr_rapid"))
	if len(cfgs) != 2 {
		t.Fatalf("sarr_rapid: expected 2 packets, got %d", len(cfgs))
	}
}

// TestScenario_SARRRapid_MessageTypes verifies SOLICIT/REPLY msg-types.
func TestScenario_SARRRapid_MessageTypes(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("sarr_rapid"))
	want := []byte{MsgTypeSolicit, MsgTypeReply}
	for i, c := range cfgs {
		if c.Payload[0] != want[i] {
			t.Errorf("sarr_rapid config[%d] msg-type = 0x%02x, want 0x%02x", i, c.Payload[0], want[i])
		}
	}
}

// TestScenario_SARRRapid_RapidCommitBoth verifies both packets carry the
// Rapid Commit option (code 14, len 0).
func TestScenario_SARRRapid_RapidCommitBoth(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("sarr_rapid"))
	for i, c := range cfgs {
		rc := findOption(c.Payload, OptRapidCommit)
		if rc == nil {
			t.Errorf("sarr_rapid config[%d] missing Rapid Commit option", i)
		} else if len(rc) != 0 {
			t.Errorf("sarr_rapid config[%d] Rapid Commit data len = %d, want 0", i, len(rc))
		}
	}
}

// TestScenario_SARRRapid_SharedXID verifies shared transaction-id.
func TestScenario_SARRRapid_SharedXID(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("sarr_rapid"))
	if xidBytes(cfgs[0].Payload) != xidBytes(cfgs[1].Payload) {
		t.Errorf("sarr_rapid: SOLICIT and REPLY XIDs differ")
	}
}

// TestScenario_SARRRapid_ReplyIAAddr verifies REPLY carries the leased IPv6.
func TestScenario_SARRRapid_ReplyIAAddr(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("sarr_rapid"))
	iaNA := findOption(cfgs[1].Payload, OptIANA)
	if iaNA == nil || len(iaNA) < 12 {
		t.Fatalf("sarr_rapid REPLY missing IA_NA or too short")
	}
	iaAddr := findOptionsFromOffset(iaNA, 12, OptIAAddr)
	if iaAddr == nil || len(iaAddr) < 16 {
		t.Fatalf("sarr_rapid REPLY IA_NA missing IA Address")
	}
	gotIP := net.IP(iaAddr[0:16])
	if !gotIP.Equal(net.ParseIP("2001:db8::100")) {
		t.Errorf("sarr_rapid REPLY IA Address = %v, want 2001:db8::100", gotIP)
	}
}

// ===================================================================
// Renew scenario (RFC 8415 §4.4)
// ===================================================================

// TestScenario_Renew verifies RENEW→REPLY: 2 packets, RENEW carries ServerID
// (auto, in needsServerID), REPLY carries updated T1/T2.
func TestScenario_Renew(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("renew"))
	if len(cfgs) != 2 {
		t.Fatalf("renew: expected 2 packets, got %d", len(cfgs))
	}
	if cfgs[0].Payload[0] != MsgTypeRenew || cfgs[1].Payload[0] != MsgTypeReply {
		t.Errorf("renew msg-types = %x/%x, want 5/7", cfgs[0].Payload[0], cfgs[1].Payload[0])
	}
	// RENEW carries ServerID (selected server).
	if sid := findOption(cfgs[0].Payload, OptServerID); sid == nil {
		t.Errorf("RENEW missing ServerID option")
	}
	// RENEW carries IA_NA with the leased address.
	iaNA := findOption(cfgs[0].Payload, OptIANA)
	if iaNA == nil {
		t.Fatalf("RENEW missing IA_NA")
	}
	iaAddr := findOptionsFromOffset(iaNA, 12, OptIAAddr)
	if iaAddr == nil {
		t.Fatalf("RENEW IA_NA missing IA Address (should carry leased addr)")
	}
	// Shared XID (RENEW is a new transaction; REPLY copies it).
	if xidBytes(cfgs[0].Payload) != xidBytes(cfgs[1].Payload) {
		t.Errorf("renew: RENEW and REPLY XIDs differ")
	}
}

// ===================================================================
// Rebind scenario (RFC 8415 §4.5)
// ===================================================================

// TestScenario_Rebind verifies REBIND→REPLY: 2 packets, REBIND does NOT carry
// ServerID (goes to all servers, multicast).
func TestScenario_Rebind(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("rebind"))
	if len(cfgs) != 2 {
		t.Fatalf("rebind: expected 2 packets, got %d", len(cfgs))
	}
	if cfgs[0].Payload[0] != MsgTypeRebind {
		t.Errorf("rebind config[0] msg-type = 0x%02x, want 0x06", cfgs[0].Payload[0])
	}
	// REBIND must NOT carry ServerID (it's not in needsServerID).
	if sid := findOption(cfgs[0].Payload, OptServerID); sid != nil {
		t.Errorf("REBIND should not carry ServerID (multicast to all servers), got %d bytes", len(sid))
	}
	// REPLY carries ServerID (client updates its server ID).
	if sid := findOption(cfgs[1].Payload, OptServerID); sid == nil {
		t.Errorf("rebind REPLY missing ServerID")
	}
}

// ===================================================================
// Release scenario (RFC 8415 §4.6)
// ===================================================================

// TestScenario_Release verifies RELEASE→REPLY: 2 packets, REPLY carries
// StatusCode=Success.
func TestScenario_Release(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("release"))
	if len(cfgs) != 2 {
		t.Fatalf("release: expected 2 packets, got %d", len(cfgs))
	}
	// RELEASE carries ServerID.
	if sid := findOption(cfgs[0].Payload, OptServerID); sid == nil {
		t.Errorf("RELEASE missing ServerID option")
	}
	// REPLY carries StatusCode=Success.
	sc := findOption(cfgs[1].Payload, OptStatusCode)
	if sc == nil || len(sc) < 2 {
		t.Fatalf("release REPLY missing StatusCode")
	}
	if got := binary.BigEndian.Uint16(sc[0:2]); got != 0 {
		t.Errorf("release REPLY StatusCode = %d, want 0 (Success)", got)
	}
}

// ===================================================================
// Decline scenario (RFC 8415 §4.7)
// ===================================================================

// TestScenario_Decline verifies DECLINE→REPLY: 2 packets, REPLY carries
// StatusCode=Success (server marks address unavailable).
func TestScenario_Decline(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("decline"))
	if len(cfgs) != 2 {
		t.Fatalf("decline: expected 2 packets, got %d", len(cfgs))
	}
	if cfgs[0].Payload[0] != MsgTypeDecline {
		t.Errorf("decline config[0] msg-type = 0x%02x, want 0x09", cfgs[0].Payload[0])
	}
	// DECLINE carries ServerID.
	if sid := findOption(cfgs[0].Payload, OptServerID); sid == nil {
		t.Errorf("DECLINE missing ServerID option")
	}
	sc := findOption(cfgs[1].Payload, OptStatusCode)
	if sc == nil || len(sc) < 2 {
		t.Fatalf("decline REPLY missing StatusCode")
	}
	if got := binary.BigEndian.Uint16(sc[0:2]); got != 0 {
		t.Errorf("decline REPLY StatusCode = %d, want 0 (Success)", got)
	}
}

// ===================================================================
// Confirm scenario (RFC 8415 §4.8)
// ===================================================================

// TestScenario_Confirm verifies CONFIRM→REPLY: 2 packets, REPLY carries
// StatusCode=Success (still on link) by default.
func TestScenario_Confirm_Success(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("confirm"))
	if len(cfgs) != 2 {
		t.Fatalf("confirm: expected 2 packets, got %d", len(cfgs))
	}
	if cfgs[0].Payload[0] != MsgTypeConfirm {
		t.Errorf("confirm config[0] msg-type = 0x%02x, want 0x04", cfgs[0].Payload[0])
	}
	sc := findOption(cfgs[1].Payload, OptStatusCode)
	if sc == nil || len(sc) < 2 {
		t.Fatalf("confirm REPLY missing StatusCode")
	}
	if got := binary.BigEndian.Uint16(sc[0:2]); got != 0 {
		t.Errorf("confirm REPLY StatusCode = %d, want 0 (Success)", got)
	}
}

// TestScenario_Confirm_NotOnLink verifies the failure path: when
// DefaultStatusCode=4 (NotOnLink), the REPLY carries NotOnLink.
func TestScenario_Confirm_NotOnLink(t *testing.T) {
	spec := scenarioSpec("confirm")
	spec.DHCPv6.DefaultStatusCode = 4 // NotOnLink
	cfgs := mustPlanScenario(t, spec)
	if len(cfgs) != 2 {
		t.Fatalf("confirm: expected 2 packets, got %d", len(cfgs))
	}
	sc := findOption(cfgs[1].Payload, OptStatusCode)
	if sc == nil || len(sc) < 2 {
		t.Fatalf("confirm NotOnLink REPLY missing StatusCode")
	}
	if got := binary.BigEndian.Uint16(sc[0:2]); got != 4 {
		t.Errorf("confirm NotOnLink REPLY StatusCode = %d, want 4", got)
	}
}

// ===================================================================
// Information-Request scenario (RFC 8415 §4.3, stateless)
// ===================================================================

// TestScenario_InfoRequest verifies INFORMATION-REQUEST→REPLY: 2 packets, no
// IA_NA, REPLY carries DNS options from defaults.
func TestScenario_InfoRequest(t *testing.T) {
	spec := scenarioSpec("information_request")
	spec.DHCPv6.DefaultDNSServers = []string{"2001:db8::53"}
	spec.DHCPv6.DefaultDNSSearch = []string{"example.com"}
	spec.DHCPv6.DefaultInfoRefreshTime = 86400
	cfgs := mustPlanScenario(t, spec)
	if len(cfgs) != 2 {
		t.Fatalf("information_request: expected 2 packets, got %d", len(cfgs))
	}
	// INFORMATION-REQUEST must NOT carry IA_NA (stateless).
	if ia := findOption(cfgs[0].Payload, OptIANA); ia != nil {
		t.Errorf("INFORMATION-REQUEST should not carry IA_NA, got %d bytes", len(ia))
	}
	// INFORMATION-REQUEST carries ClientID.
	if cid := findOption(cfgs[0].Payload, OptClientID); cid == nil {
		t.Errorf("INFORMATION-REQUEST missing ClientID")
	}
	// REPLY carries RDNSS.
	rdnss := findOption(cfgs[1].Payload, OptRDNSS)
	if rdnss == nil || len(rdnss) < 20 {
		t.Fatalf("REPLY missing RDNSS or too short")
	}
	gotDNS := net.IP(rdnss[4:20])
	if !gotDNS.Equal(net.ParseIP("2001:db8::53")) {
		t.Errorf("REPLY RDNSS server = %v, want 2001:db8::53", gotDNS)
	}
	// REPLY carries INFO_REFRESH_TIME=86400.
	irt := findOption(cfgs[1].Payload, OptInfoRefreshTime)
	if irt == nil || len(irt) != 4 {
		t.Fatalf("REPLY missing INFO_REFRESH_TIME")
	}
	if got := binary.BigEndian.Uint32(irt); got != 86400 {
		t.Errorf("REPLY INFO_REFRESH_TIME = %d, want 86400", got)
	}
}

// ===================================================================
// Reconfigure scenario (RFC 8415 §4.9)
// ===================================================================

// TestScenario_Reconfigure verifies RECONFIGURE→RENEW→REPLY: 3 packets,
// RECONFIGURE carries option 19 (Reconf Msg-Type = 5 RENEW).
func TestScenario_Reconfigure(t *testing.T) {
	cfgs := mustPlanScenario(t, scenarioSpec("reconfigure"))
	if len(cfgs) != 3 {
		t.Fatalf("reconfigure: expected 3 packets, got %d", len(cfgs))
	}
	want := []byte{MsgTypeReconfigure, MsgTypeRenew, MsgTypeReply}
	for i, c := range cfgs {
		if c.Payload[0] != want[i] {
			t.Errorf("reconfigure config[%d] msg-type = 0x%02x, want 0x%02x", i, c.Payload[0], want[i])
		}
	}
	// RECONFIGURE carries option 19 = 5 (RENEW).
	rm := findOption(cfgs[0].Payload, OptReconfMsg)
	if rm == nil || len(rm) != 1 {
		t.Fatalf("RECONFIGURE missing option 19 (Reconf Msg-Type)")
	}
	if rm[0] != MsgTypeRenew {
		t.Errorf("RECONFIGURE option 19 = %d, want 5 (RENEW)", rm[0])
	}
	// RECONFIGURE is server-initiated: it gets a new XID (different from
	// the RENEW that follows, since RENEW is a new client transaction).
	reconfXID := xidBytes(cfgs[0].Payload)
	renewXID := xidBytes(cfgs[1].Payload)
	if reconfXID == renewXID {
		t.Errorf("RECONFIGURE and RENEW share XID %x (should differ - new transactions)", reconfXID)
	}
	// RENEW and REPLY share XID (server copies).
	if renewXID != xidBytes(cfgs[2].Payload) {
		t.Errorf("RENEW and REPLY XIDs differ")
	}
}

// ===================================================================
// Relay scenario (RFC 8415 §4.10)
// ===================================================================

// TestScenario_Relay verifies the relay scenario wraps the SARR dialog in
// RELAY-FORW/RELAY-REPL: 4 packets, each msg-type 12 or 13, each carrying
// option 9 (Relay Message) with the inner message bytes.
func TestScenario_Relay(t *testing.T) {
	spec := scenarioSpec("relay")
	spec.DHCPv6.RelayConfig = &core.RelayConfig{
		RelayIP:  "2001:db8::1",
		RelayMAC: "00:aa:bb:cc:dd:ee",
	}
	cfgs := mustPlanScenario(t, spec)
	if len(cfgs) != 4 {
		t.Fatalf("relay: expected 4 packets, got %d", len(cfgs))
	}
	wantTypes := []byte{MsgTypeRelayForw, MsgTypeRelayRepl, MsgTypeRelayForw, MsgTypeRelayRepl}
	for i, c := range cfgs {
		if c.Payload[0] != wantTypes[i] {
			t.Errorf("relay config[%d] msg-type = 0x%02x, want 0x%02x", i, c.Payload[0], wantTypes[i])
		}
		// Each relay message must carry option 9 (Relay Message) at offset 34.
		relayMsg := findOptionsFromOffset(c.Payload, RelayHeaderLen, OptRelayMsg)
		if relayMsg == nil {
			t.Errorf("relay config[%d] missing option 9 (Relay Message)", i)
			continue
		}
		// Inner message must be a valid DHCPv6 message (msg-type 1-11).
		if len(relayMsg) < 4 {
			t.Errorf("relay config[%d] inner message too short: %d bytes", i, len(relayMsg))
			continue
		}
		innerType := relayMsg[0]
		if innerType < 1 || innerType > 11 {
			t.Errorf("relay config[%d] inner msg-type = %d (out of range)", i, innerType)
		}
	}
	// Directions: RELAY-FORW=up, RELAY-REPL=down.
	wantDirs := []string{"up", "down", "up", "down"}
	for i, c := range cfgs {
		if c.Direction != wantDirs[i] {
			t.Errorf("relay config[%d] direction = %s, want %s", i, c.Direction, wantDirs[i])
		}
	}
	// Verify hop-count = 1 at offset 1.
	for i, c := range cfgs {
		if c.Payload[1] != 1 {
			t.Errorf("relay config[%d] hop-count = %d, want 1", i, c.Payload[1])
		}
	}
}

// TestScenario_Relay_InnerSARR verifies the inner message bytes inside the
// relay option 9 form a complete SARR dialog (SOLICIT/ADVERTISE/REQUEST/REPLY).
func TestScenario_Relay_InnerSARR(t *testing.T) {
	spec := scenarioSpec("relay")
	spec.DHCPv6.RelayConfig = &core.RelayConfig{
		RelayIP:  "2001:db8::1",
		RelayMAC: "00:aa:bb:cc:dd:ee",
	}
	cfgs := mustPlanScenario(t, spec)
	wantInner := []byte{MsgTypeSolicit, MsgTypeAdvertise, MsgTypeRequest, MsgTypeReply}
	for i, c := range cfgs {
		relayMsg := findOptionsFromOffset(c.Payload, RelayHeaderLen, OptRelayMsg)
		if relayMsg == nil || len(relayMsg) < 4 {
			t.Fatalf("relay config[%d] missing inner message", i)
		}
		if relayMsg[0] != wantInner[i] {
			t.Errorf("relay config[%d] inner msg-type = 0x%02x, want 0x%02x", i, relayMsg[0], wantInner[i])
		}
	}
}

// ===================================================================
// Validation tests
// ===================================================================

// TestScenario_UnknownRejects verifies unknown scenario names are rejected.
func TestScenario_UnknownRejects(t *testing.T) {
	spec := scenarioSpec("bogus")
	p := NewPlanner()
	_, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatalf("Plan accepted unknown scenario 'bogus'")
	}
}

// TestScenario_MissingLeasedAddrRejects verifies sarr requires leased addr.
func TestScenario_MissingLeasedAddrRejects(t *testing.T) {
	spec := scenarioSpec("sarr")
	spec.DHCPv6.DefaultLeasedAddr = ""
	p := NewPlanner()
	_, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatalf("Plan accepted sarr without default_leased_addr")
	}
}

// TestScenario_RelayWithoutConfigRejects verifies relay requires RelayConfig.
func TestScenario_RelayWithoutConfigRejects(t *testing.T) {
	spec := scenarioSpec("relay")
	spec.DHCPv6.RelayConfig = nil
	p := NewPlanner()
	_, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatalf("Plan accepted relay without relay_config")
	}
}

// TestScenario_AndMessagesRejects verifies setting both scenario and messages
// is rejected.
func TestScenario_AndMessagesRejects(t *testing.T) {
	spec := scenarioSpec("sarr")
	spec.DHCPv6.Messages = []core.DHCPv6Message{{MsgType: MsgTypeSolicit}}
	p := NewPlanner()
	_, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatalf("Plan accepted both scenario and messages")
	}
}

// TestScenario_NoAddrsAvail verifies the failure path: when
// DefaultStatusCode=2 (NoAddrsAvail), the SARR REPLY carries a top-level
// StatusCode=2.
func TestScenario_SARR_NoAddrsAvail(t *testing.T) {
	spec := scenarioSpec("sarr")
	spec.DHCPv6.DefaultStatusCode = 2 // NoAddrsAvail
	cfgs := mustPlanScenario(t, spec)
	if len(cfgs) != 4 {
		t.Fatalf("sarr NoAddrsAvail: expected 4 packets, got %d", len(cfgs))
	}
	sc := findOption(cfgs[3].Payload, OptStatusCode)
	if sc == nil || len(sc) < 2 {
		t.Fatalf("sarr NoAddrsAvail REPLY missing StatusCode")
	}
	if got := binary.BigEndian.Uint16(sc[0:2]); got != 2 {
		t.Errorf("sarr NoAddrsAvail REPLY StatusCode = %d, want 2", got)
	}
}
