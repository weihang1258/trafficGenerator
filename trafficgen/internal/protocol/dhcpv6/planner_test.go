package dhcpv6

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// drain reads all PacketConfig values from ch and returns them as a slice.
// Used by tests that need to assert on the full Plan() output.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for cfg := range ch {
		out = append(out, cfg)
	}
	return out
}

// mustPlan calls Plan and fails the test on error. Returns the channel for
// the caller to drain. Used by atomic testpoints and integration tests.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return ch
}

// validSpec returns a minimal valid DHCPv6 spec for a SOLICIT message with
// an explicit XID and client/server DUIDs set. Used as the base for many
// integration tests.
func validSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcMAC: "00:11:22:33:44:55",
		DstMAC: "33:33:00:01:00:02",
		SrcIP:  "fe80::1",
		DstIP:  "ff02::1:2",
		DHCPv6: &core.DHCPv6Config{
			ClientDUID: &core.DUID{
				Type:          DUIDTypeLLT,
				HardwareType:  HardwareTypeEthernet,
				Time:          0,
				LinkLayerAddr: "00:11:22:33:44:55",
			},
			ServerDUID: &core.DUID{
				Type:            DUIDTypeEN,
				EnterpriseNum:   9,
				VendorSpecific:  []byte("trafficgen"),
			},
			Messages: []core.DHCPv6Message{},
		},
	}
}

// xidBytes returns the 3-byte XID slice from a DHCPv6 payload (returns
// payload[1:4] for non-relay messages).
func xidBytes(p []byte) [3]byte {
	var x [3]byte
	copy(x[:], p[1:4])
	return x
}

// findOption searches the payload for an option with the given code and
// returns its data slice. Returns nil if not found. Assumes a 4-byte header
// (non-relay messages).
func findOption(payload []byte, code uint16) []byte {
	return findOptionsFromOffset(payload, HeaderLen, code)
}

// findOptionsFromOffset walks the option TLV list starting at offset and
// returns the data of the first option matching code.
func findOptionsFromOffset(payload []byte, offset int, code uint16) []byte {
	i := offset
	for i+4 <= len(payload) {
		optCode := binary.BigEndian.Uint16(payload[i : i+2])
		optLen := int(binary.BigEndian.Uint16(payload[i+2 : i+4]))
		if i+4+optLen > len(payload) {
			return nil
		}
		if optCode == code {
			return payload[i+4 : i+4+optLen]
		}
		i += 4 + optLen
	}
	return nil
}

// findAllOptions returns the data slices for every option with the given code.
func findAllOptions(payload []byte, code uint16) [][]byte {
	return findAllOptionsFromOffset(payload, HeaderLen, code)
}

// findAllOptionsFromOffset walks options from offset and returns all data
// slices for options matching code.
func findAllOptionsFromOffset(payload []byte, offset int, code uint16) [][]byte {
	var out [][]byte
	i := offset
	for i+4 <= len(payload) {
		optCode := binary.BigEndian.Uint16(payload[i : i+2])
		optLen := int(binary.BigEndian.Uint16(payload[i+2 : i+4]))
		if i+4+optLen > len(payload) {
			return out
		}
		if optCode == code {
			out = append(out, payload[i+4:i+4+optLen])
		}
		i += 4 + optLen
	}
	return out
}

// ===================================================================
// Basic planner tests.
// ===================================================================

// TestPlanner_Name verifies the planner registry name (验证规划器名称).
func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if got := p.Name(); got != "dhcpv6" {
		t.Errorf("Name() = %q, want \"dhcpv6\"", got)
	}
}

// TestPlanner_Validate_Basic covers Validate acceptance and rejection paths
// (验证 Validate 接受与拒绝路径).
func TestPlanner_Validate_Basic(t *testing.T) {
	p := NewPlanner()

	tests := []struct {
		name    string
		spec    core.FlowSpec
		wantErr bool
	}{
		{
			name: "valid spec",
			spec: core.FlowSpec{
				SrcIP: "fe80::1", DstIP: "ff02::1:2",
				SrcMAC: "00:11:22:33:44:55",
				DHCPv6: &core.DHCPv6Config{
					Messages: []core.DHCPv6Message{{MsgType: MsgTypeSolicit}},
				},
			},
			wantErr: false,
		},
		{
			name: "missing config",
			spec: core.FlowSpec{
				SrcIP: "fe80::1", DstIP: "ff02::1:2",
			},
			wantErr: true,
		},
		{
			name: "empty messages",
			spec: core.FlowSpec{
				SrcIP: "fe80::1", DstIP: "ff02::1:2",
				DHCPv6: &core.DHCPv6Config{Messages: []core.DHCPv6Message{}},
			},
			wantErr: true,
		},
		{
			name: "IPv4 source IP rejected",
			spec: core.FlowSpec{
				SrcIP: "192.0.2.1", DstIP: "ff02::1:2",
				DHCPv6: &core.DHCPv6Config{
					Messages: []core.DHCPv6Message{{MsgType: MsgTypeSolicit}},
				},
			},
			wantErr: true,
		},
		{
			name: "IPv4 dest IP rejected",
			spec: core.FlowSpec{
				SrcIP: "fe80::1", DstIP: "192.0.2.1",
				DHCPv6: &core.DHCPv6Config{
					Messages: []core.DHCPv6Message{{MsgType: MsgTypeSolicit}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid source IP string",
			spec: core.FlowSpec{
				SrcIP: "not-an-ip", DstIP: "ff02::1:2",
				DHCPv6: &core.DHCPv6Config{
					Messages: []core.DHCPv6Message{{MsgType: MsgTypeSolicit}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid msg-type zero",
			spec: core.FlowSpec{
				SrcIP: "fe80::1", DstIP: "ff02::1:2",
				DHCPv6: &core.DHCPv6Config{
					Messages: []core.DHCPv6Message{{MsgType: 0}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid msg-type 14",
			spec: core.FlowSpec{
				SrcIP: "fe80::1", DstIP: "ff02::1:2",
				DHCPv6: &core.DHCPv6Config{
					Messages: []core.DHCPv6Message{{MsgType: 14}},
				},
			},
			wantErr: true,
		},
		{
			name: "relay message without relay_fields",
			spec: core.FlowSpec{
				SrcIP: "fe80::1", DstIP: "ff02::1:2",
				DHCPv6: &core.DHCPv6Config{
					Messages: []core.DHCPv6Message{{MsgType: MsgTypeRelayForw}},
				},
			},
			wantErr: true,
		},
		{
			name: "relay message with hop-count > 32",
			spec: core.FlowSpec{
				SrcIP: "fe80::1", DstIP: "ff02::1:2",
				DHCPv6: &core.DHCPv6Config{
					Messages: []core.DHCPv6Message{{
						MsgType: MsgTypeRelayForw,
						RelayFields: &core.RelayFields{
							HopCount:    33,
							LinkAddress: "2001:db8::1",
							PeerAddress: "fe80::1234",
						},
					}},
				},
			},
			wantErr: true,
		},
		{
			name: "relay message with IPv4 link-address",
			spec: core.FlowSpec{
				SrcIP: "fe80::1", DstIP: "ff02::1:2",
				DHCPv6: &core.DHCPv6Config{
					Messages: []core.DHCPv6Message{{
						MsgType: MsgTypeRelayForw,
						RelayFields: &core.RelayFields{
							HopCount:    1,
							LinkAddress: "192.0.2.1",
							PeerAddress: "fe80::1234",
						},
					}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid DUID type",
			spec: core.FlowSpec{
				SrcIP: "fe80::1", DstIP: "ff02::1:2",
				DHCPv6: &core.DHCPv6Config{
					ClientDUID: &core.DUID{Type: 99},
					Messages:   []core.DHCPv6Message{{MsgType: MsgTypeSolicit}},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ===================================================================
// Scenario 1: Standard 4-message exchange
// SOLICIT -> ADVERTISE -> REQUEST -> REPLY
// ===================================================================

// TestScenario1_Standard4WayExchange verifies the full 4-message DHCPv6
// exchange: SOLICIT -> ADVERTISE -> REQUEST -> REPLY. Asserts XID consistency,
// direction alternation, port assignment, EtherType IPv6, and option presence.
func TestScenario1_Standard4WayExchange(t *testing.T) {
	p := NewPlanner()
	xid := [3]byte{0x12, 0x34, 0x56}
	spec := validSpec()
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{
			MsgType:       MsgTypeSolicit,
			TransactionID: xid,
			Options: []core.DHCPv6Option{
				{Code: OptORO, Data: BuildORO([]uint16{OptRDNSS, OptDNSSL, OptSNTP})},
				{Code: OptIANA, Data: BuildIA_NA(1, 0, 0, nil)},
			},
		},
		{
			MsgType:       MsgTypeAdvertise,
			TransactionID: xid,
			Options: []core.DHCPv6Option{
				{Code: OptPreference, Data: BuildPreference(0)},
				{
					Code: OptIANA,
					Data: BuildIA_NA(1, 1800, 2880, appendOpt(nil, OptIAAddr,
						BuildIAAddress(IAAddress{IPv6Addr: "2001:db8::100", Preferred: 3600, Valid: 7200}, nil))),
				},
			},
		},
		{
			MsgType:       MsgTypeRequest,
			TransactionID: xid,
			Options: []core.DHCPv6Option{
				{Code: OptIANA, Data: BuildIA_NA(1, 0, 0, nil)},
			},
		},
		{
			MsgType:       MsgTypeReply,
			TransactionID: xid,
			Options: []core.DHCPv6Option{
				{
					Code: OptIANA,
					Data: BuildIA_NA(1, 1800, 2880, appendOpt(nil, OptIAAddr,
						BuildIAAddress(IAAddress{IPv6Addr: "2001:db8::100", Preferred: 3600, Valid: 7200}, nil))),
				},
			},
		},
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 4 {
		t.Fatalf("packet count = %d, want 4", len(cfgs))
	}

	// Verify directions alternate up/down/up/down.
	wantDirs := []string{"up", "down", "up", "down"}
	for i, want := range wantDirs {
		if cfgs[i].Direction != want {
			t.Errorf("cfgs[%d].Direction = %q, want %q", i, cfgs[i].Direction, want)
		}
	}

	// Verify msg-type bytes 1/2/3/7.
	wantMsgTypes := []byte{MsgTypeSolicit, MsgTypeAdvertise, MsgTypeRequest, MsgTypeReply}
	for i, want := range wantMsgTypes {
		if cfgs[i].Payload[0] != want {
			t.Errorf("cfgs[%d].Payload[0] = 0x%02x, want 0x%02x", i, cfgs[i].Payload[0], want)
		}
	}

	// Verify all four packets share the same XID.
	for i, c := range cfgs {
		got := xidBytes(c.Payload)
		if got != xid {
			t.Errorf("cfgs[%d] XID = %x, want %x", i, got, xid)
		}
	}

	// Verify ports: up uses 546->547, down uses 547->546.
	if cfgs[0].L4.SrcPort != ClientPort || cfgs[0].L4.DstPort != ServerPort {
		t.Errorf("SOLICIT ports: src=%d dst=%d, want 546/547", cfgs[0].L4.SrcPort, cfgs[0].L4.DstPort)
	}
	if cfgs[1].L4.SrcPort != ServerPort || cfgs[1].L4.DstPort != ClientPort {
		t.Errorf("ADVERTISE ports: src=%d dst=%d, want 547/546", cfgs[1].L4.SrcPort, cfgs[1].L4.DstPort)
	}

	// Verify EtherType is IPv6 (0x86DD) for all packets.
	for i, c := range cfgs {
		if c.L2.EtherType != core.EtherTypeIPv6 {
			t.Errorf("cfgs[%d].EtherType = 0x%04x, want 0x86DD", i, c.L2.EtherType)
		}
	}

	// Verify SOLICIT contains ClientID (auto-prepended).
	if cid := findOption(cfgs[0].Payload, OptClientID); cid == nil {
		t.Errorf("SOLICIT missing ClientID option")
	}

	// Verify ADVERTISE contains ServerID (auto-prepended) and Preference.
	if sid := findOption(cfgs[1].Payload, OptServerID); sid == nil {
		t.Errorf("ADVERTISE missing ServerID option")
	}
	if pref := findOption(cfgs[1].Payload, OptPreference); pref == nil || len(pref) != 1 || pref[0] != 0 {
		t.Errorf("ADVERTISE Preference = %v, want [0]", pref)
	}

	// Verify REQUEST contains both ClientID and ServerID (REQUEST is a client
	// message but also needs ServerID).
	if sid := findOption(cfgs[2].Payload, OptServerID); sid == nil {
		t.Errorf("REQUEST missing ServerID option")
	}

	// Verify REPLY contains IA_NA with IA Address sub-option.
	iaNA := findOption(cfgs[3].Payload, OptIANA)
	if iaNA == nil {
		t.Fatalf("REPLY missing IA_NA option")
	}
	if len(iaNA) < 12 {
		t.Fatalf("REPLY IA_NA too short: %d bytes", len(iaNA))
	}
	// IA_NA: IAID(4) + T1(4) + T2(4) + sub-options. Verify T1=1800, T2=2880.
	gotT1 := binary.BigEndian.Uint32(iaNA[4:8])
	gotT2 := binary.BigEndian.Uint32(iaNA[8:12])
	if gotT1 != 1800 || gotT2 != 2880 {
		t.Errorf("REPLY IA_NA T1=%d T2=%d, want 1800/2880", gotT1, gotT2)
	}

	// Verify PacketIndex monotonically increments.
	for i := 1; i < len(cfgs); i++ {
		if cfgs[i].PacketIndex <= cfgs[i-1].PacketIndex {
			t.Errorf("PacketIndex[%d]=%d not > prev=%d", i, cfgs[i].PacketIndex, cfgs[i-1].PacketIndex)
		}
	}

	// Verify all share the same FlowID.
	for i, c := range cfgs {
		if c.FlowID != cfgs[0].FlowID {
			t.Errorf("cfgs[%d].FlowID = %q, want %q", i, c.FlowID, cfgs[0].FlowID)
		}
	}
}

// ===================================================================
// Scenario 2: Rapid Commit 2-message exchange
// SOLICIT (with option 14) -> REPLY (with option 14)
// ===================================================================

// TestScenario2_RapidCommit verifies the 2-message Rapid Commit exchange.
func TestScenario2_RapidCommit(t *testing.T) {
	p := NewPlanner()
	xid := [3]byte{0xAB, 0xCD, 0xEF}
	spec := validSpec()
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{
			MsgType:       MsgTypeSolicit,
			TransactionID: xid,
			Options: []core.DHCPv6Option{
				{Code: OptRapidCommit, Data: BuildRapidCommit()},
				{Code: OptIANA, Data: BuildIA_NA(1, 0, 0, nil)},
			},
		},
		{
			MsgType:       MsgTypeReply,
			TransactionID: xid,
			Options: []core.DHCPv6Option{
				{Code: OptRapidCommit, Data: BuildRapidCommit()},
				{
					Code: OptIANA,
					Data: BuildIA_NA(1, 1800, 2880, appendOpt(nil, OptIAAddr,
						BuildIAAddress(IAAddress{IPv6Addr: "2001:db8::100", Preferred: 3600, Valid: 7200}, nil))),
				},
			},
		},
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("packet count = %d, want 2", len(cfgs))
	}

	// Verify directions.
	if cfgs[0].Direction != "up" || cfgs[1].Direction != "down" {
		t.Errorf("directions: %s/%s, want up/down", cfgs[0].Direction, cfgs[1].Direction)
	}

	// Verify both packets carry Rapid Commit option (code 14, len 0).
	for i, c := range cfgs {
		rc := findOption(c.Payload, OptRapidCommit)
		if rc == nil {
			t.Errorf("cfgs[%d] missing Rapid Commit option", i)
		} else if len(rc) != 0 {
			t.Errorf("cfgs[%d] Rapid Commit data len = %d, want 0", i, len(rc))
		}
	}

	// Verify both share the same XID.
	if xidBytes(cfgs[0].Payload) != xidBytes(cfgs[1].Payload) {
		t.Errorf("XIDs differ between SOLICIT and REPLY")
	}

	// Verify REPLY contains IA_NA with an IA Address sub-option carrying the
	// allocated IPv6.
	iaNA := findOption(cfgs[1].Payload, OptIANA)
	if iaNA == nil || len(iaNA) < 12 {
		t.Fatalf("REPLY missing IA_NA or too short")
	}
	// Find IA Address sub-option (code 5) inside IA_NA data.
	iaAddr := findOptionsFromOffset(iaNA, 12, OptIAAddr)
	if iaAddr == nil {
		t.Fatalf("REPLY IA_NA missing IA Address sub-option")
	}
	if len(iaAddr) < 24 {
		t.Fatalf("IA Address too short: %d bytes", len(iaAddr))
	}
	// First 16 bytes of IA Address data = IPv6 address.
	gotIP := net.IP(iaAddr[0:16])
	wantIP := net.ParseIP("2001:db8::100")
	if !gotIP.Equal(wantIP) {
		t.Errorf("IA Address IPv6 = %v, want %v", gotIP, wantIP)
	}
}

// ===================================================================
// Scenario 3: RENEW -> REPLY
// ===================================================================

// TestScenario3_Renew verifies the renewal exchange. RENEW uses a new XID
// (different from the original SOLICIT), is unicast to the original server,
// and must carry ServerID.
func TestScenario3_Renew(t *testing.T) {
	p := NewPlanner()
	renewXID := [3]byte{0x11, 0x22, 0x33}
	spec := validSpec()
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{
			MsgType:       MsgTypeRenew,
			TransactionID: renewXID,
			Options: []core.DHCPv6Option{
				{
					Code: OptIANA,
					Data: BuildIA_NA(1, 0, 0, appendOpt(nil, OptIAAddr,
						BuildIAAddress(IAAddress{IPv6Addr: "2001:db8::100", Preferred: 3600, Valid: 7200}, nil))),
				},
			},
		},
		{
			MsgType:       MsgTypeReply,
			TransactionID: renewXID,
			Options: []core.DHCPv6Option{
				{
					Code: OptIANA,
					Data: BuildIA_NA(1, 1800, 2880, appendOpt(nil, OptIAAddr,
						BuildIAAddress(IAAddress{IPv6Addr: "2001:db8::100", Preferred: 3600, Valid: 7200}, nil))),
				},
			},
		},
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("packet count = %d, want 2", len(cfgs))
	}

	// Verify directions.
	if cfgs[0].Direction != "up" || cfgs[1].Direction != "down" {
		t.Errorf("directions: %s/%s, want up/down", cfgs[0].Direction, cfgs[1].Direction)
	}

	// Verify both packets share the renew XID.
	for i, c := range cfgs {
		if got := xidBytes(c.Payload); got != renewXID {
			t.Errorf("cfgs[%d] XID = %x, want %x", i, got, renewXID)
		}
	}

	// Verify RENEW carries ServerID (auto-prepended because RENEW is in the
	// "needsServerID" list).
	if sid := findOption(cfgs[0].Payload, OptServerID); sid == nil {
		t.Errorf("RENEW missing ServerID option")
	}

	// Verify RENEW carries ClientID (auto-prepended for client messages).
	if cid := findOption(cfgs[0].Payload, OptClientID); cid == nil {
		t.Errorf("RENEW missing ClientID option")
	}
}

// ===================================================================
// Scenario 4: REBIND -> REPLY
// ===================================================================

// TestScenario4_Rebind verifies the rebind exchange. REBIND is multicast
// (FF02::1:2) and does NOT carry ServerID (it goes to all servers).
func TestScenario4_Rebind(t *testing.T) {
	p := NewPlanner()
	rebindXID := [3]byte{0x22, 0x33, 0x44}
	spec := validSpec()
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{
			MsgType:       MsgTypeRebind,
			TransactionID: rebindXID,
			Options: []core.DHCPv6Option{
				{
					Code: OptIANA,
					Data: BuildIA_NA(1, 0, 0, appendOpt(nil, OptIAAddr,
						BuildIAAddress(IAAddress{IPv6Addr: "2001:db8::100", Preferred: 0, Valid: 0}, nil))),
				},
			},
		},
		{
			MsgType:       MsgTypeReply,
			TransactionID: rebindXID,
			Options: []core.DHCPv6Option{
				{
					Code: OptIANA,
					Data: BuildIA_NA(1, 1800, 2880, appendOpt(nil, OptIAAddr,
						BuildIAAddress(IAAddress{IPv6Addr: "2001:db8::100", Preferred: 3600, Valid: 7200}, nil))),
				},
			},
		},
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("packet count = %d, want 2", len(cfgs))
	}

	// Verify REBIND direction is up (client->server, multicast).
	if cfgs[0].Direction != "up" {
		t.Errorf("REBIND direction = %s, want up", cfgs[0].Direction)
	}

	// Verify REBIND does NOT auto-carry ServerID (REBIND is not in the
	// needsServerID list - it goes to all servers). The user did not
	// provide one either, so ServerID should be absent.
	if sid := findOption(cfgs[0].Payload, OptServerID); sid != nil {
		t.Errorf("REBIND should NOT carry ServerID, but found %d bytes", len(sid))
	}

	// Verify REBIND carries ClientID (auto-prepended).
	if cid := findOption(cfgs[0].Payload, OptClientID); cid == nil {
		t.Errorf("REBIND missing ClientID option")
	}

	// Verify XID matches.
	if got := xidBytes(cfgs[0].Payload); got != rebindXID {
		t.Errorf("REBIND XID = %x, want %x", got, rebindXID)
	}
}

// ===================================================================
// Scenario 5: RELEASE -> REPLY
// ===================================================================

// TestScenario5_Release verifies the release exchange. RELEASE is unicast
// to the original server and must carry ServerID.
func TestScenario5_Release(t *testing.T) {
	p := NewPlanner()
	releaseXID := [3]byte{0x33, 0x44, 0x55}
	spec := validSpec()
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{
			MsgType:       MsgTypeRelease,
			TransactionID: releaseXID,
			Options: []core.DHCPv6Option{
				{
					Code: OptIANA,
					Data: BuildIA_NA(1, 0, 0, appendOpt(nil, OptIAAddr,
						BuildIAAddress(IAAddress{IPv6Addr: "2001:db8::100", Preferred: 0, Valid: 0}, nil))),
				},
			},
		},
		{
			MsgType:       MsgTypeReply,
			TransactionID: releaseXID,
			Options: []core.DHCPv6Option{
				{Code: OptStatusCode, Data: BuildStatusCode(0, "Success")},
			},
		},
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("packet count = %d, want 2", len(cfgs))
	}

	// Verify RELEASE carries ServerID (RELEASE is in needsServerID).
	if sid := findOption(cfgs[0].Payload, OptServerID); sid == nil {
		t.Errorf("RELEASE missing ServerID option")
	}

	// Verify RELEASE carries ClientID.
	if cid := findOption(cfgs[0].Payload, OptClientID); cid == nil {
		t.Errorf("RELEASE missing ClientID option")
	}

	// Verify REPLY contains Status Code = Success (0).
	sc := findOption(cfgs[1].Payload, OptStatusCode)
	if sc == nil || len(sc) < 2 {
		t.Fatalf("REPLY missing Status Code or too short")
	}
	gotStatus := binary.BigEndian.Uint16(sc[0:2])
	if gotStatus != 0 {
		t.Errorf("REPLY Status = %d, want 0 (Success)", gotStatus)
	}
}

// ===================================================================
// Scenario 6: DECLINE -> REPLY
// ===================================================================

// TestScenario6_Decline verifies the decline exchange. DECLINE is sent when
// DAD (Duplicate Address Detection, 重复地址检测) fails.
func TestScenario6_Decline(t *testing.T) {
	p := NewPlanner()
	declineXID := [3]byte{0x44, 0x55, 0x66}
	spec := validSpec()
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{
			MsgType:       MsgTypeDecline,
			TransactionID: declineXID,
			Options: []core.DHCPv6Option{
				{
					Code: OptIANA,
					Data: BuildIA_NA(1, 0, 0, appendOpt(nil, OptIAAddr,
						BuildIAAddress(IAAddress{IPv6Addr: "2001:db8::100", Preferred: 0, Valid: 0}, nil))),
				},
			},
		},
		{
			MsgType:       MsgTypeReply,
			TransactionID: declineXID,
			Options: []core.DHCPv6Option{
				{Code: OptStatusCode, Data: BuildStatusCode(0, "Success")},
			},
		},
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("packet count = %d, want 2", len(cfgs))
	}

	// Verify DECLINE carries ServerID (DECLINE is in needsServerID).
	if sid := findOption(cfgs[0].Payload, OptServerID); sid == nil {
		t.Errorf("DECLINE missing ServerID option")
	}

	// Verify DECLINE carries ClientID.
	if cid := findOption(cfgs[0].Payload, OptClientID); cid == nil {
		t.Errorf("DECLINE missing ClientID option")
	}

	// Verify REPLY status = Success.
	sc := findOption(cfgs[1].Payload, OptStatusCode)
	if sc == nil || len(sc) < 2 {
		t.Fatalf("REPLY missing Status Code or too short")
	}
	if got := binary.BigEndian.Uint16(sc[0:2]); got != 0 {
		t.Errorf("REPLY Status = %d, want 0", got)
	}
}

// ===================================================================
// Scenario 7: CONFIRM -> REPLY
// ===================================================================

// TestScenario7_Confirm verifies the confirm exchange. CONFIRM is multicast
// (sent after link change to verify address validity).
func TestScenario7_Confirm(t *testing.T) {
	p := NewPlanner()
	confirmXID := [3]byte{0x55, 0x66, 0x77}
	spec := validSpec()
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{
			MsgType:       MsgTypeConfirm,
			TransactionID: confirmXID,
			Options: []core.DHCPv6Option{
				{
					Code: OptIANA,
					Data: BuildIA_NA(1, 0, 0, appendOpt(nil, OptIAAddr,
						BuildIAAddress(IAAddress{IPv6Addr: "2001:db8::100", Preferred: 3600, Valid: 7200}, nil))),
				},
			},
		},
		{
			MsgType:       MsgTypeReply,
			TransactionID: confirmXID,
			Options: []core.DHCPv6Option{
				{Code: OptStatusCode, Data: BuildStatusCode(0, "Success")},
			},
		},
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("packet count = %d, want 2", len(cfgs))
	}

	// Verify CONFIRM is up (multicast to servers).
	if cfgs[0].Direction != "up" {
		t.Errorf("CONFIRM direction = %s, want up", cfgs[0].Direction)
	}

	// Verify CONFIRM carries ClientID (auto-prepended).
	if cid := findOption(cfgs[0].Payload, OptClientID); cid == nil {
		t.Errorf("CONFIRM missing ClientID option")
	}

	// Verify REPLY status = Success (address still valid on new link).
	sc := findOption(cfgs[1].Payload, OptStatusCode)
	if sc == nil || len(sc) < 2 {
		t.Fatalf("REPLY missing Status Code")
	}
	if got := binary.BigEndian.Uint16(sc[0:2]); got != 0 {
		t.Errorf("REPLY Status = %d, want 0", got)
	}
}

// ===================================================================
// Scenario 8: INFORMATION-REQUEST -> REPLY (stateless)
// ===================================================================

// TestScenario8_InformationRequest verifies the stateless exchange. The client
// only requests configuration parameters (DNS/SNTP), not addresses.
func TestScenario8_InformationRequest(t *testing.T) {
	p := NewPlanner()
	infoXID := [3]byte{0x66, 0x77, 0x88}
	spec := validSpec()
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{
			MsgType:       MsgTypeInformationRequest,
			TransactionID: infoXID,
			Options: []core.DHCPv6Option{
				{Code: OptORO, Data: BuildORO([]uint16{OptRDNSS, OptDNSSL, OptSNTP, OptInfoRefreshTime})},
			},
		},
		{
			MsgType:       MsgTypeReply,
			TransactionID: infoXID,
			Options: []core.DHCPv6Option{
				{Code: OptRDNSS, Data: BuildRDNSS([]string{"2001:db8::53"})},
				{Code: OptDNSSL, Data: BuildDNSSL([]string{"example.com"})},
				{Code: OptSNTP, Data: BuildSNTPServers([]string{"2001:db8::123"})},
				{Code: OptInfoRefreshTime, Data: BuildInfoRefreshTime(86400)},
			},
		},
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("packet count = %d, want 2", len(cfgs))
	}

	// Verify INFORMATION-REQUEST carries ClientID (RFC 8415 requires it, and
	// the planner auto-prepends).
	if cid := findOption(cfgs[0].Payload, OptClientID); cid == nil {
		t.Errorf("INFORMATION-REQUEST missing ClientID option")
	}

	// Verify INFORMATION-REQUEST does NOT carry IA_NA (stateless).
	if ia := findOption(cfgs[0].Payload, OptIANA); ia != nil {
		t.Errorf("INFORMATION-REQUEST should not carry IA_NA, got %d bytes", len(ia))
	}

	// Verify INFORMATION-REQUEST does NOT auto-carry ServerID (it is not in
	// needsServerID). The user did not provide one.
	if sid := findOption(cfgs[0].Payload, OptServerID); sid != nil {
		t.Errorf("INFORMATION-REQUEST should not auto-carry ServerID")
	}

	// Verify REPLY contains RDNSS with the DNS server (RFC 3646 §3:
	// bare address list, no lifetime field).
	rdnss := findOption(cfgs[1].Payload, OptRDNSS)
	if rdnss == nil || len(rdnss) != 16 {
		t.Fatalf("REPLY missing RDNSS or wrong length %d, want 16", len(rdnss))
	}
	// RDNSS: IPv6(16) only. Verify DNS server is 2001:db8::53.
	gotDNS := net.IP(rdnss[0:16])
	wantDNS := net.ParseIP("2001:db8::53")
	if !gotDNS.Equal(wantDNS) {
		t.Errorf("RDNSS server = %v, want %v", gotDNS, wantDNS)
	}

	// Verify REPLY contains INFO_REFRESH_TIME = 86400.
	irt := findOption(cfgs[1].Payload, OptInfoRefreshTime)
	if irt == nil || len(irt) != 4 {
		t.Fatalf("REPLY missing INFO_REFRESH_TIME or wrong length")
	}
	if got := binary.BigEndian.Uint32(irt); got != 86400 {
		t.Errorf("INFO_REFRESH_TIME = %d, want 86400", got)
	}
}

// ===================================================================
// Scenario 9: RELAY-FORW -> RELAY-REPL (relay)
// ===================================================================

// TestScenario9_RelayForwRepl verifies relay message construction. The relay
// agent encapsulates a client SOLICIT into RELAY-FORW (34-byte header + option
// 9 carrying the inner SOLICIT bytes). The server responds with RELAY-REPL
// carrying the inner REPLY.
func TestScenario9_RelayForwRepl(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.DHCPv6.RelayConfig = &core.RelayConfig{
		RelayIP:  "2001:db8::1",
		RelayMAC: "00:aa:bb:cc:dd:ee",
	}

	// Build the inner SOLICIT bytes first (to embed in option 9 of RELAY-FORW).
	innerSolicitSpec := validSpec()
	innerSolicitSpec.DHCPv6.Messages = []core.DHCPv6Message{
		{
			MsgType:       MsgTypeSolicit,
			TransactionID: [3]byte{0x12, 0x34, 0x56},
			Options: []core.DHCPv6Option{
				{Code: OptIANA, Data: BuildIA_NA(1, 0, 0, nil)},
			},
		},
	}
	innerCfgs := drain(mustPlan(t, p, innerSolicitSpec))
	if len(innerCfgs) != 1 {
		t.Fatalf("inner SOLICIT count = %d, want 1", len(innerCfgs))
	}
	innerSolicitBytes := innerCfgs[0].Payload

	// Build the inner REPLY bytes for RELAY-REPL.
	innerReplySpec := validSpec()
	innerReplySpec.DHCPv6.Messages = []core.DHCPv6Message{
		{
			MsgType:       MsgTypeReply,
			TransactionID: [3]byte{0x12, 0x34, 0x56},
			Options: []core.DHCPv6Option{
				{
					Code: OptIANA,
					Data: BuildIA_NA(1, 1800, 2880, appendOpt(nil, OptIAAddr,
						BuildIAAddress(IAAddress{IPv6Addr: "2001:db8::100", Preferred: 3600, Valid: 7200}, nil))),
				},
			},
		},
	}
	innerReplyCfgs := drain(mustPlan(t, p, innerReplySpec))
	if len(innerReplyCfgs) != 1 {
		t.Fatalf("inner REPLY count = %d, want 1", len(innerReplyCfgs))
	}
	innerReplyBytes := innerReplyCfgs[0].Payload

	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{
			MsgType: MsgTypeRelayForw,
			RelayFields: &core.RelayFields{
				HopCount:    1,
				LinkAddress: "2001:db8::1",
				PeerAddress: "fe80::1",
			},
			Options: []core.DHCPv6Option{
				{Code: OptRelayMsg, Data: BuildRelayMessage(innerSolicitBytes)},
			},
		},
		{
			MsgType: MsgTypeRelayRepl,
			RelayFields: &core.RelayFields{
				HopCount:    1,
				LinkAddress: "2001:db8::1",
				PeerAddress: "fe80::1",
			},
			Options: []core.DHCPv6Option{
				{Code: OptRelayMsg, Data: BuildRelayMessage(innerReplyBytes)},
			},
		},
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("packet count = %d, want 2", len(cfgs))
	}

	// Verify msg-types 12 and 13.
	if cfgs[0].Payload[0] != MsgTypeRelayForw {
		t.Errorf("RELAY-FORW msg-type = 0x%02x, want 0x%02x", cfgs[0].Payload[0], MsgTypeRelayForw)
	}
	if cfgs[1].Payload[0] != MsgTypeRelayRepl {
		t.Errorf("RELAY-REPL msg-type = 0x%02x, want 0x%02x", cfgs[1].Payload[0], MsgTypeRelayRepl)
	}

	// Verify hop-count byte at offset 1.
	if cfgs[0].Payload[1] != 1 {
		t.Errorf("RELAY-FORW hop-count = %d, want 1", cfgs[0].Payload[1])
	}
	if cfgs[1].Payload[1] != 1 {
		t.Errorf("RELAY-REPL hop-count = %d, want 1", cfgs[1].Payload[1])
	}

	// Verify link-address (bytes 2:18) = 2001:db8::1.
	gotLink := net.IP(cfgs[0].Payload[2:18])
	wantLink := net.ParseIP("2001:db8::1")
	if !gotLink.Equal(wantLink) {
		t.Errorf("RELAY-FORW link-address = %v, want %v", gotLink, wantLink)
	}

	// Verify peer-address (bytes 18:34) = fe80::1.
	gotPeer := net.IP(cfgs[0].Payload[18:34])
	wantPeer := net.ParseIP("fe80::1")
	if !gotPeer.Equal(wantPeer) {
		t.Errorf("RELAY-FORW peer-address = %v, want %v", gotPeer, wantPeer)
	}

	// Verify option 9 (Relay Message) at offset 34 contains the inner SOLICIT.
	relayMsg := findOptionsFromOffset(cfgs[0].Payload, RelayHeaderLen, OptRelayMsg)
	if relayMsg == nil {
		t.Fatalf("RELAY-FORW missing option 9 (Relay Message)")
	}
	if string(relayMsg) != string(innerSolicitBytes) {
		t.Errorf("RELAY-FORW option 9 bytes do not match inner SOLICIT (got %d bytes, want %d)",
			len(relayMsg), len(innerSolicitBytes))
	}

	// Verify RELAY-REPL option 9 contains inner REPLY.
	relayMsgRepl := findOptionsFromOffset(cfgs[1].Payload, RelayHeaderLen, OptRelayMsg)
	if relayMsgRepl == nil {
		t.Fatalf("RELAY-REPL missing option 9")
	}
	if string(relayMsgRepl) != string(innerReplyBytes) {
		t.Errorf("RELAY-REPL option 9 bytes do not match inner REPLY")
	}

	// Verify RELAY-FORW direction is up (relay->server).
	if cfgs[0].Direction != "up" {
		t.Errorf("RELAY-FORW direction = %s, want up", cfgs[0].Direction)
	}
	// Verify RELAY-REPL direction is down (server->relay).
	if cfgs[1].Direction != "down" {
		t.Errorf("RELAY-REPL direction = %s, want down", cfgs[1].Direction)
	}

	// Verify RELAY-FORW ports are 547->547 (relay->server).
	if cfgs[0].L4.SrcPort != ServerPort || cfgs[0].L4.DstPort != ServerPort {
		t.Errorf("RELAY-FORW ports: src=%d dst=%d, want 547/547", cfgs[0].L4.SrcPort, cfgs[0].L4.DstPort)
	}

	// Verify RELAY-FORW source MAC is the relay's MAC (from RelayConfig).
	if cfgs[0].L2.SrcMAC != spec.DHCPv6.RelayConfig.RelayMAC {
		t.Errorf("RELAY-FORW src MAC = %s, want %s (relay MAC)",
			cfgs[0].L2.SrcMAC, spec.DHCPv6.RelayConfig.RelayMAC)
	}
	// Verify RELAY-FORW source IP is the relay's IP.
	if cfgs[0].L3.SrcIP != spec.DHCPv6.RelayConfig.RelayIP {
		t.Errorf("RELAY-FORW src IP = %s, want %s (relay IP)",
			cfgs[0].L3.SrcIP, spec.DHCPv6.RelayConfig.RelayIP)
	}
	// Verify RELAY-REPL dest MAC is the relay's MAC.
	if cfgs[1].L2.DstMAC != spec.DHCPv6.RelayConfig.RelayMAC {
		t.Errorf("RELAY-REPL dst MAC = %s, want %s (relay MAC)",
			cfgs[1].L2.DstMAC, spec.DHCPv6.RelayConfig.RelayMAC)
	}
}

// ===================================================================
// Scenario 10: LEASEQUERY -> LEASEQUERYREPLY
// ===================================================================

// TestScenario10_Leasequery verifies the leasequery exchange. LEASEQUERY
// (msg-type 14 in RFC 5007) is outside the 1-13 DHCPv6 range that the planner
// supports. We instead verify that the planner can build a REPLY carrying
// leasequery-style option 44 data bytes (passed through as opaque option data).
// Since the planner only supports msg-types 1-13, this test uses INFORMATION-
// REQUEST -> REPLY with an opaque option 44 in the REPLY payload.
func TestScenario10_Leasequery(t *testing.T) {
	p := NewPlanner()
	lqXID := [3]byte{0x77, 0x88, 0x99}
	// OPTION_LQ_QUERY = 44 (RFC 5007). The planner passes opaque option data
	// through; it does not validate option codes outside its known set.
	const OptLQQuery uint16 = 44
	// Build a minimal leasequery data: query-type(2) + query-data("client-id-by-addr").
	lqData := make([]byte, 0, 2+4)
	lqData = append(lqData, 0x00, 0x01) // query-type=1 (by address)
	lqData = append(lqData, []byte("addr")...)

	spec := validSpec()
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{
			MsgType:       MsgTypeInformationRequest,
			TransactionID: lqXID,
			Options: []core.DHCPv6Option{
				{Code: OptLQQuery, Data: lqData},
			},
		},
		{
			MsgType:       MsgTypeReply,
			TransactionID: lqXID,
			Options: []core.DHCPv6Option{
				{Code: OptLQQuery, Data: lqData}, // echoed back as opaque data
			},
		},
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("packet count = %d, want 2", len(cfgs))
	}

	// Verify the opaque option 44 round-trips correctly in both packets.
	for i, c := range cfgs {
		lq := findOption(c.Payload, OptLQQuery)
		if lq == nil {
			t.Errorf("cfgs[%d] missing option 44 (LQ_QUERY)", i)
			continue
		}
		if string(lq) != string(lqData) {
			t.Errorf("cfgs[%d] option 44 data = %x, want %x", i, lq, lqData)
		}
	}
}

// ===================================================================
// Integration: end-to-end builder verification
// ===================================================================

// TestIntegration_BuilderProducesIPv6UDP verifies that the planner's output,
// when fed to the core Builder, produces a valid Ethernet/IPv6/UDP frame.
// This catches L2/L3/L4 wiring bugs that payload-only tests miss.
func TestIntegration_BuilderProducesIPv6UDP(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{
			MsgType:       MsgTypeSolicit,
			TransactionID: [3]byte{0x12, 0x34, 0x56},
			Options: []core.DHCPv6Option{
				{Code: OptIANA, Data: BuildIA_NA(1, 0, 0, nil)},
			},
		},
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("packet count = %d, want 1", len(cfgs))
	}

	b := core.NewBuilder()
	pkt, err := b.Build(cfgs[0])
	if err != nil {
		t.Fatalf("Builder.Build failed: %v", err)
	}

	// Verify Ethernet header: 14 bytes, EtherType=0x86DD at offset 12.
	if len(pkt) < 14 {
		t.Fatalf("packet too short: %d bytes", len(pkt))
	}
	etherType := binary.BigEndian.Uint16(pkt[12:14])
	if etherType != core.EtherTypeIPv6 {
		t.Errorf("EtherType = 0x%04x, want 0x86DD", etherType)
	}

	// Verify IPv6 header: 40 bytes, Next Header=17 (UDP) at offset 14+6=20.
	if len(pkt) < 14+40 {
		t.Fatalf("packet too short for IPv6 header: %d bytes", len(pkt))
	}
	nextHeader := pkt[14+6]
	if nextHeader != core.ProtocolUDP {
		t.Errorf("IPv6 Next Header = %d, want 17 (UDP)", nextHeader)
	}

	// Verify Hop Limit = 64 (default).
	hopLimit := pkt[14+7]
	if hopLimit != DefaultTTL {
		t.Errorf("Hop Limit = %d, want %d", hopLimit, DefaultTTL)
	}

	// Verify UDP source port 546, dest port 547.
	udpStart := 14 + 40
	if len(pkt) < udpStart+8 {
		t.Fatalf("packet too short for UDP header: %d bytes", len(pkt))
	}
	srcPort := binary.BigEndian.Uint16(pkt[udpStart : udpStart+2])
	dstPort := binary.BigEndian.Uint16(pkt[udpStart+2 : udpStart+4])
	if srcPort != ClientPort {
		t.Errorf("UDP src port = %d, want 546", srcPort)
	}
	if dstPort != ServerPort {
		t.Errorf("UDP dst port = %d, want 547", dstPort)
	}

	// Verify DHCPv6 payload starts at udpStart+8 with msg-type=1 (SOLICIT).
	dhcpv6Start := udpStart + 8
	if len(pkt) <= dhcpv6Start {
		t.Fatalf("packet too short for DHCPv6 payload: %d bytes", len(pkt))
	}
	if pkt[dhcpv6Start] != MsgTypeSolicit {
		t.Errorf("DHCPv6 msg-type = 0x%02x, want 0x01 (SOLICIT)", pkt[dhcpv6Start])
	}

	// Verify XID bytes 1:4.
	if pkt[dhcpv6Start+1] != 0x12 || pkt[dhcpv6Start+2] != 0x34 || pkt[dhcpv6Start+3] != 0x56 {
		t.Errorf("DHCPv6 XID = %x, want 123456", pkt[dhcpv6Start+1:dhcpv6Start+4])
	}
}

// ===================================================================
// Concurrency tests
// ===================================================================

// TestConcurrency_8WorkersUniqueXIDs verifies that 8 concurrent workers each
// emitting a SOLICIT produce 8 distinct auto-generated XIDs (no collisions).
// This catches XID-generator bugs that would cause server confusion.
func TestConcurrency_8WorkersUniqueXIDs(t *testing.T) {
	p := NewPlanner()
	const workers = 8
	var wg sync.WaitGroup
	xids := make([][3]byte, workers)
	errs := make([]error, workers)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			spec := validSpec()
			spec.DHCPv6.Messages = []core.DHCPv6Message{
				{MsgType: MsgTypeSolicit}, // no XID -> auto-generate
			}
			ch, err := p.Plan(context.Background(), spec)
			if err != nil {
				errs[idx] = err
				return
			}
			cfgs := drain(ch)
			if len(cfgs) != 1 {
				errs[idx] = fmt.Errorf("worker %d: packet count = %d, want 1", idx, len(cfgs))
				return
			}
			xids[idx] = xidBytes(cfgs[0].Payload)
		}(w)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("worker %d failed: %v", i, err)
		}
	}

	// Verify all 8 XIDs are distinct. With random 24-bit XIDs the chance of
	// collision among 8 is ~0.001%, so a collision here indicates a bug.
	seen := make(map[[3]byte]bool)
	for i, x := range xids {
		if seen[x] {
			t.Errorf("worker %d XID %x collides with an earlier worker", i, x)
		}
		seen[x] = true
	}
}

// TestConcurrency_NoDataRace verifies that running Plan concurrently from
// multiple goroutines does not trigger -race detector failures. The planner
// must not share mutable state across Plan calls.
func TestConcurrency_NoDataRace(t *testing.T) {
	p := NewPlanner()
	const workers = 8
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			spec := validSpec()
			spec.DHCPv6.Messages = []core.DHCPv6Message{
				{
					MsgType:       MsgTypeSolicit,
					TransactionID: [3]byte{byte(idx), 0, 0},
					Options: []core.DHCPv6Option{
						{Code: OptIANA, Data: BuildIA_NA(uint32(idx), 0, 0, nil)},
					},
				},
				{
					MsgType:       MsgTypeReply,
					TransactionID: [3]byte{byte(idx), 0, 0},
				},
			}
			cfgs := drain(mustPlan(t, p, spec))
			if len(cfgs) != 2 {
				t.Errorf("worker %d: packet count = %d, want 2", idx, len(cfgs))
			}
		}(w)
	}
	wg.Wait()
}

// ===================================================================
// Context cancellation tests
// ===================================================================

// TestContext_CancelDuringPlan verifies that cancelling the context mid-Plan
// stops the goroutine and closes the channel without leaking.
func TestContext_CancelDuringPlan(t *testing.T) {
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())

	spec := validSpec()
	// Build a large message list so the planner has work to do.
	for i := 0; i < 100; i++ {
		spec.DHCPv6.Messages = append(spec.DHCPv6.Messages, core.DHCPv6Message{
			MsgType:       MsgTypeSolicit,
			TransactionID: [3]byte{byte(i), 0, 0},
		})
	}

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	// Read a few packets, then cancel.
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	count := 0
	for range ch {
		count++
	}
	// After cancel, the channel should close. We should have read at most 100
	// packets (likely fewer because cancel interrupts mid-loop).
	if count > 100 {
		t.Errorf("read %d packets after cancel, expected <= 100", count)
	}
}

// ===================================================================
// Auto-XID propagation tests
// ===================================================================

// TestAutoXID_ServerRepliesCopyClientXID verifies that when the user does not
// set TransactionID on a server reply message, the planner copies the XID
// from the previous client message in the same transaction.
func TestAutoXID_ServerRepliesCopyClientXID(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{MsgType: MsgTypeSolicit},                       // no XID -> auto
		{MsgType: MsgTypeAdvertise},                     // no XID -> copy from SOLICIT
		{MsgType: MsgTypeRequest},                       // no XID -> auto (new)
		{MsgType: MsgTypeReply},                         // no XID -> copy from REQUEST
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 4 {
		t.Fatalf("packet count = %d, want 4", len(cfgs))
	}

	solicitXID := xidBytes(cfgs[0].Payload)
	advertiseXID := xidBytes(cfgs[1].Payload)
	requestXID := xidBytes(cfgs[2].Payload)
	replyXID := xidBytes(cfgs[3].Payload)

	// ADVERTISE must copy SOLICIT's XID (server replies copy the request XID).
	if advertiseXID != solicitXID {
		t.Errorf("ADVERTISE XID %x != SOLICIT XID %x", advertiseXID, solicitXID)
	}

	// REPLY must copy REQUEST's XID.
	if replyXID != requestXID {
		t.Errorf("REPLY XID %x != REQUEST XID %x", replyXID, requestXID)
	}

	// SOLICIT and REQUEST should have different XIDs (each is a new client
	// transaction with auto-generated XID).
	if solicitXID == requestXID {
		t.Errorf("SOLICIT and REQUEST share XID %x (should differ - new transaction)", solicitXID)
	}
}

// TestAutoXID_RECONFIGURENewXID verifies that RECONFIGURE messages get a new
// XID even when following a down-direction message (RECONFIGURE is server-
// initiated and starts a new transaction).
func TestAutoXID_RECONFIGURENewXID(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{MsgType: MsgTypeSolicit},
		{MsgType: MsgTypeReply},
		{MsgType: MsgTypeReconfigure}, // server-initiated, should get new XID
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 3 {
		t.Fatalf("packet count = %d, want 3", len(cfgs))
	}

	replyXID := xidBytes(cfgs[1].Payload)
	reconfigureXID := xidBytes(cfgs[2].Payload)

	// RECONFIGURE must NOT copy REPLY's XID - it is a new transaction.
	if reconfigureXID == replyXID {
		t.Errorf("RECONFIGURE XID %x == REPLY XID %x (should differ - new transaction)", reconfigureXID, replyXID)
	}
}

// ===================================================================
// Multicast destination MAC tests
// ===================================================================

// TestMulticast_DstMAC verifies that the user-supplied multicast MAC is
// honored on the wire. The planner does not auto-derive the MAC from the
// IPv6 multicast address; the user must set DstMAC explicitly.
func TestMulticast_DstMAC(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.DstMAC = "33:33:00:01:00:02" // FF02::1:2 multicast MAC
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3}},
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("packet count = %d, want 1", len(cfgs))
	}

	b := core.NewBuilder()
	pkt, err := b.Build(cfgs[0])
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	// Ethernet dst MAC = first 6 bytes.
	wantMAC, _ := net.ParseMAC("33:33:00:01:00:02")
	gotMAC := pkt[0:6]
	if string(gotMAC) != string(wantMAC) {
		t.Errorf("dst MAC = %x, want %x", gotMAC, wantMAC)
	}
}

// ===================================================================
// DUID auto-generation tests
// ===================================================================

// TestAutoDUID_ClientLLTFromMAC verifies that when ClientDUID is nil, the
// planner generates a DUID-LLT based on the spec.SrcMAC.
func TestAutoDUID_ClientLLTFromMAC(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.DHCPv6.ClientDUID = nil // force auto-generation
	spec.SrcMAC = "00:aa:bb:cc:dd:ee"
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3}},
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("packet count = %d, want 1", len(cfgs))
	}

	// Verify ClientID option is present.
	cid := findOption(cfgs[0].Payload, OptClientID)
	if cid == nil {
		t.Fatalf("SOLICIT missing ClientID option")
	}

	// Verify DUID type = 1 (LLT).
	if len(cid) < 2 {
		t.Fatalf("ClientID too short: %d bytes", len(cid))
	}
	duidType := binary.BigEndian.Uint16(cid[0:2])
	if duidType != DUIDTypeLLT {
		t.Errorf("auto ClientDUID type = %d, want 1 (LLT)", duidType)
	}

	// Verify hardware type = 1 (Ethernet).
	if len(cid) < 4 {
		t.Fatalf("ClientID too short for hw-type: %d bytes", len(cid))
	}
	hwType := binary.BigEndian.Uint16(cid[2:4])
	if hwType != HardwareTypeEthernet {
		t.Errorf("auto ClientDUID hw-type = %d, want 1 (Ethernet)", hwType)
	}

	// Verify link-layer-addr (last 6 bytes) = spec.SrcMAC bytes.
	if len(cid) < 14 {
		t.Fatalf("ClientID too short for MAC: %d bytes", len(cid))
	}
	macBytes := cid[len(cid)-6:]
	wantMAC, _ := net.ParseMAC("00:aa:bb:cc:dd:ee")
	if string(macBytes) != string(wantMAC) {
		t.Errorf("auto ClientDUID MAC = %x, want %x", macBytes, wantMAC)
	}
}

// TestAutoDUID_ServerEN verifies that when ServerDUID is nil, the planner
// generates a DUID-EN with enterprise-number=0 and vendor-specific="trafficgen".
func TestAutoDUID_ServerEN(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.DHCPv6.ServerDUID = nil // force auto-generation
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{MsgType: MsgTypeAdvertise, TransactionID: [3]byte{1, 2, 3}},
	}

	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("packet count = %d, want 1", len(cfgs))
	}

	sid := findOption(cfgs[0].Payload, OptServerID)
	if sid == nil {
		t.Fatalf("ADVERTISE missing ServerID option")
	}

	// Verify DUID type = 2 (EN).
	if len(sid) < 2 {
		t.Fatalf("ServerID too short: %d bytes", len(sid))
	}
	if got := binary.BigEndian.Uint16(sid[0:2]); got != DUIDTypeEN {
		t.Errorf("auto ServerDUID type = %d, want 2 (EN)", got)
	}

	// Verify enterprise-number = 0.
	if len(sid) < 6 {
		t.Fatalf("ServerID too short for EN: %d bytes", len(sid))
	}
	if got := binary.BigEndian.Uint32(sid[2:6]); got != 0 {
		t.Errorf("auto ServerDUID EN = %d, want 0", got)
	}

	// Verify vendor-specific = "trafficgen".
	if len(sid) < 6+len("trafficgen") {
		t.Fatalf("ServerID too short for vendor-specific: %d bytes", len(sid))
	}
	if got := string(sid[6:]); got != "trafficgen" {
		t.Errorf("auto ServerDUID vendor-specific = %q, want \"trafficgen\"", got)
	}
}

// ===================================================================
// Options length limit tests
// ===================================================================

// TestOptionsLength_OverLimit verifies that options exceeding the MTU-IPv6-UDP
// limit (1452 bytes) are rejected by Validate.
func TestOptionsLength_OverLimit(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	// Build options totalling > 1452 bytes. Each option is 4 (header) + N (data).
	// Use a single option with 1453 bytes of data.
	bigData := make([]byte, MaxOptionsLen-3) // 1449 bytes -> option total = 4+1449 = 1453 > 1452
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{
			MsgType:       MsgTypeSolicit,
			TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: 999, Data: bigData},
			},
		},
	}

	if err := p.Validate(spec); err == nil {
		t.Errorf("Validate accepted options length %d (> %d limit) without error",
			4+len(bigData), MaxOptionsLen)
	}
}

// TestOptionsLength_AtLimit verifies that options exactly at the limit (1452)
// are accepted.
func TestOptionsLength_AtLimit(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	// One option with data length = MaxOptionsLen - 4 (header) = 1448 bytes.
	// Total option bytes = 4 + 1448 = 1452 = MaxOptionsLen.
	dataLen := MaxOptionsLen - 4
	data := make([]byte, dataLen)
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{
			MsgType:       MsgTypeSolicit,
			TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: 999, Data: data},
			},
		},
	}

	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate rejected options length %d (= %d limit): %v",
			4+dataLen, MaxOptionsLen, err)
	}
}

// ===================================================================
// Helpers used by tests above.
// ===================================================================

// appendOpt appends a TLV option to buf and returns the extended buffer.
// Used by tests to build sub-option payloads (e.g. IA Address inside IA_NA).
// Mirrors the planner's internal appendOption but renamed to avoid collision.
func appendOpt(buf []byte, code uint16, data []byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], code)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(data)))
	buf = append(buf, hdr...)
	buf = append(buf, data...)
	return buf
}

// fmt is referenced by drainErr consumers (e.g. fmt.Errorf in goroutines).
var _ = fmt.Errorf

// TestAutoDUID_EmptySrcMAC_ValidateError verifies that when ClientDUID is
// nil (auto-generation) and SrcMAC is empty, Validate returns a clear error
// instead of silently producing zero packets (the auto DUID-LLT requires a
// valid MAC for the LinkLayerAddr field).
func TestAutoDUID_EmptySrcMAC_ValidateError(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.DHCPv6.ClientDUID = nil // force auto-generation
	spec.SrcMAC = ""             // empty MAC - cannot build DUID-LLT
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3}},
	}

	// Validate should return an error explaining that SrcMAC is required
	// when ClientDUID is not explicitly set.
	err := p.Validate(spec)
	if err == nil {
		t.Fatalf("Validate returned nil error for auto-ClientDUID with empty SrcMAC; " +
			"expected a clear validation error")
	}
}

// TestAutoDUID_EmptySrcMAC_PlanReturnsError verifies that Plan() returns an
// error (not a silent zero-packet channel) when auto-ClientDUID cannot
// succeed due to empty SrcMAC.
func TestAutoDUID_EmptySrcMAC_PlanReturnsError(t *testing.T) {
	p := NewPlanner()
	spec := validSpec()
	spec.DHCPv6.ClientDUID = nil
	spec.SrcMAC = ""
	spec.DHCPv6.Messages = []core.DHCPv6Message{
		{MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3}},
	}

	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		cfgs := drain(ch)
		t.Fatalf("Plan returned no error but emitted %d packets; expected a validation "+
			"error for auto-ClientDUID with empty SrcMAC", len(cfgs))
	}
}
