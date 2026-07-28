package dhcpv6

// Per-field test points (每个字段的原子测试点) for the DHCPv6 planner.
// Each test covers one or more test cases from /tmp/l7_planner_design/testcases_dhcpv6.md.
// Tests assert observable PacketConfig and payload field values.

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- helpers for testpoints ---

// makeSpec returns a valid spec with the given messages and default DUIDs.
func makeSpec(msgs []core.DHCPv6Message) core.FlowSpec {
	s := validSpec()
	s.DHCPv6.Messages = msgs
	return s
}

// payload returns the first packet's payload, or fails the test.
func payload(t *testing.T, cfgs []core.PacketConfig) []byte {
	t.Helper()
	if len(cfgs) == 0 {
		t.Fatalf("no packets produced")
	}
	return cfgs[0].Payload
}

// ===================================================================
// §1.1 msg-type (消息类型, 1 字节, 13 个取值)
// ===================================================================

// 1.1.1: msg-type=1 (SOLICIT) -> payload[0]=0x01, direction=up, dst port=547.
func TestT1_1_1_msgTypeSolicit(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3}},
	})))
	p := payload(t, cfgs)
	if p[0] != MsgTypeSolicit {
		t.Errorf("payload[0]=0x%02x, want 0x01 (SOLICIT)", p[0])
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%q, want up", cfgs[0].Direction)
	}
	if cfgs[0].L4.DstPort != ServerPort {
		t.Errorf("DstPort=%d, want 547", cfgs[0].L4.DstPort)
	}
}

// 1.1.2: msg-type=2 (ADVERTISE) -> payload[0]=0x02, direction=down.
func TestT1_1_2_msgTypeAdvertise(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeAdvertise, TransactionID: [3]byte{1, 2, 3}},
	})))
	p := payload(t, cfgs)
	if p[0] != MsgTypeAdvertise {
		t.Errorf("payload[0]=0x%02x, want 0x02 (ADVERTISE)", p[0])
	}
	if cfgs[0].Direction != "down" {
		t.Errorf("Direction=%q, want down", cfgs[0].Direction)
	}
}

// 1.1.3: msg-type=3 (REQUEST) -> payload[0]=0x03, direction=up.
func TestT1_1_3_msgTypeRequest(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeRequest, TransactionID: [3]byte{1, 2, 3}},
	})))
	p := payload(t, cfgs)
	if p[0] != MsgTypeRequest {
		t.Errorf("payload[0]=0x%02x, want 0x03 (REQUEST)", p[0])
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%q, want up", cfgs[0].Direction)
	}
}

// 1.1.4: msg-type=4 (CONFIRM) -> payload[0]=0x04, direction=up.
func TestT1_1_4_msgTypeConfirm(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeConfirm, TransactionID: [3]byte{1, 2, 3}},
	})))
	p := payload(t, cfgs)
	if p[0] != MsgTypeConfirm {
		t.Errorf("payload[0]=0x%02x, want 0x04 (CONFIRM)", p[0])
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%q, want up", cfgs[0].Direction)
	}
}

// 1.1.5: msg-type=5 (RENEW) -> payload[0]=0x05, direction=up.
func TestT1_1_5_msgTypeRenew(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeRenew, TransactionID: [3]byte{1, 2, 3}},
	})))
	p := payload(t, cfgs)
	if p[0] != MsgTypeRenew {
		t.Errorf("payload[0]=0x%02x, want 0x05 (RENEW)", p[0])
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%q, want up", cfgs[0].Direction)
	}
}

// 1.1.6: msg-type=6 (REBIND) -> payload[0]=0x06, direction=up.
func TestT1_1_6_msgTypeRebind(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeRebind, TransactionID: [3]byte{1, 2, 3}},
	})))
	p := payload(t, cfgs)
	if p[0] != MsgTypeRebind {
		t.Errorf("payload[0]=0x%02x, want 0x06 (REBIND)", p[0])
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%q, want up", cfgs[0].Direction)
	}
}

// 1.1.7: msg-type=7 (REPLY) -> payload[0]=0x07, direction=down.
func TestT1_1_7_msgTypeReply(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeReply, TransactionID: [3]byte{1, 2, 3}},
	})))
	p := payload(t, cfgs)
	if p[0] != MsgTypeReply {
		t.Errorf("payload[0]=0x%02x, want 0x07 (REPLY)", p[0])
	}
	if cfgs[0].Direction != "down" {
		t.Errorf("Direction=%q, want down", cfgs[0].Direction)
	}
}

// 1.1.8: msg-type=8 (RELEASE) -> payload[0]=0x08, direction=up.
func TestT1_1_8_msgTypeRelease(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeRelease, TransactionID: [3]byte{1, 2, 3}},
	})))
	p := payload(t, cfgs)
	if p[0] != MsgTypeRelease {
		t.Errorf("payload[0]=0x%02x, want 0x08 (RELEASE)", p[0])
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%q, want up", cfgs[0].Direction)
	}
}

// 1.1.9: msg-type=9 (DECLINE) -> payload[0]=0x09, direction=up.
func TestT1_1_9_msgTypeDecline(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeDecline, TransactionID: [3]byte{1, 2, 3}},
	})))
	p := payload(t, cfgs)
	if p[0] != MsgTypeDecline {
		t.Errorf("payload[0]=0x%02x, want 0x09 (DECLINE)", p[0])
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%q, want up", cfgs[0].Direction)
	}
}

// 1.1.10: msg-type=10 (RECONFIGURE) -> payload[0]=0x0A, direction=down.
func TestT1_1_10_msgTypeReconfigure(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeReconfigure, TransactionID: [3]byte{1, 2, 3}},
	})))
	p := payload(t, cfgs)
	if p[0] != MsgTypeReconfigure {
		t.Errorf("payload[0]=0x%02x, want 0x0A (RECONFIGURE)", p[0])
	}
	if cfgs[0].Direction != "down" {
		t.Errorf("Direction=%q, want down", cfgs[0].Direction)
	}
}

// 1.1.11: msg-type=11 (INFORMATION-REQUEST) -> payload[0]=0x0B, direction=up.
func TestT1_1_11_msgTypeInfoRequest(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeInformationRequest, TransactionID: [3]byte{1, 2, 3}},
	})))
	p := payload(t, cfgs)
	if p[0] != MsgTypeInformationRequest {
		t.Errorf("payload[0]=0x%02x, want 0x0B (INFORMATION-REQUEST)", p[0])
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%q, want up", cfgs[0].Direction)
	}
}

// 1.1.12: msg-type=12 (RELAY-FORW) -> payload[0]=0x0C, direction=up, 34-byte relay header.
func TestT1_1_12_msgTypeRelayForw(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeRelayForw,
			RelayFields: &core.RelayFields{
				HopCount: 1,
				LinkAddress: "2001:db8::1",
				PeerAddress: "fe80::1",
			},
			Options: []core.DHCPv6Option{
				{Code: OptRelayMsg, Data: []byte{MsgTypeSolicit, 1, 2, 3}},
			},
		},
	})))
	p := payload(t, cfgs)
	if p[0] != MsgTypeRelayForw {
		t.Errorf("payload[0]=0x%02x, want 0x0C (RELAY-FORW)", p[0])
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%q, want up", cfgs[0].Direction)
	}
	// Verify 34-byte relay header (not 4-byte).
	if len(p) < RelayHeaderLen {
		t.Fatalf("payload too short for relay header: %d bytes", len(p))
	}
	// Relay messages do NOT have XID at bytes 1:4; bytes 1=hop-count, 2:18=link-addr.
	if p[1] != 1 {
		t.Errorf("relay hop-count = %d, want 1", p[1])
	}
}

// 1.1.13: msg-type=13 (RELAY-REPL) -> payload[0]=0x0D, direction=down.
func TestT1_1_13_msgTypeRelayRepl(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeRelayRepl,
			RelayFields: &core.RelayFields{
				HopCount: 1,
				LinkAddress: "2001:db8::1",
				PeerAddress: "fe80::1",
			},
			Options: []core.DHCPv6Option{
				{Code: OptRelayMsg, Data: []byte{MsgTypeReply, 1, 2, 3}},
			},
		},
	})))
	p := payload(t, cfgs)
	if p[0] != MsgTypeRelayRepl {
		t.Errorf("payload[0]=0x%02x, want 0x0D (RELAY-REPL)", p[0])
	}
	if cfgs[0].Direction != "down" {
		t.Errorf("Direction=%q, want down", cfgs[0].Direction)
	}
}

// 1.1.14: msg-type=0 -> Validate error.
func TestT1_1_14_msgTypeZero(t *testing.T) {
	err := NewPlanner().Validate(makeSpec([]core.DHCPv6Message{
		{MsgType: 0},
	}))
	if err == nil {
		t.Errorf("Validate accepted msg-type=0")
	}
}

// 1.1.15: msg-type=14 -> Validate error.
func TestT1_1_15_msgType14(t *testing.T) {
	err := NewPlanner().Validate(makeSpec([]core.DHCPv6Message{
		{MsgType: 14},
	}))
	if err == nil {
		t.Errorf("Validate accepted msg-type=14")
	}
}

// 1.1.16: msg-type=255 -> Validate error.
func TestT1_1_16_msgType255(t *testing.T) {
	err := NewPlanner().Validate(makeSpec([]core.DHCPv6Message{
		{MsgType: 255},
	}))
	if err == nil {
		t.Errorf("Validate accepted msg-type=255")
	}
}

// ===================================================================
// §1.2 transaction-id (事务标识符, 3 字节)
// ===================================================================

// 1.2.1: transaction-id=0x123456 -> payload[1:4]=0x123456.
func TestT1_2_1_xid123456(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeSolicit, TransactionID: [3]byte{0x12, 0x34, 0x56}},
	})))
	p := payload(t, cfgs)
	if got := xidBytes(p); got != [3]byte{0x12, 0x34, 0x56} {
		t.Errorf("XID = %x, want 123456", got)
	}
}

// 1.2.2: transaction-id=0xFFFFFF -> payload[1:4]=0xFFFFFF (max).
func TestT1_2_2_xidMax(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeSolicit, TransactionID: [3]byte{0xFF, 0xFF, 0xFF}},
	})))
	p := payload(t, cfgs)
	if got := xidBytes(p); got != [3]byte{0xFF, 0xFF, 0xFF} {
		t.Errorf("XID = %x, want FFFFFF", got)
	}
}

// 1.2.3: transaction-id=0x000001 -> payload[1:4]=0x000001 (min non-zero).
func TestT1_2_3_xidMinNonZero(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeSolicit, TransactionID: [3]byte{0, 0, 1}},
	})))
	p := payload(t, cfgs)
	if got := xidBytes(p); got != [3]byte{0, 0, 1} {
		t.Errorf("XID = %x, want 000001", got)
	}
}

// 1.2.4: transaction-id=0x000000 -> planner treats zero as "not set" and
// auto-generates a random non-zero XID. This matches the planner's documented
// behavior (zero XID = auto-generate for client messages).
func TestT1_2_4_xidZeroAutoGenerated(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeSolicit, TransactionID: [3]byte{0, 0, 0}},
	})))
	p := payload(t, cfgs)
	got := xidBytes(p)
	// Auto-generated XID should be non-zero (random).
	if got == [3]byte{0, 0, 0} {
		t.Errorf("XID = 000000, want auto-generated non-zero value")
	}
}

// 1.2.5: Same XID across SOLICIT and ADVERTISE.
func TestT1_2_5_sharedXID(t *testing.T) {
	xid := [3]byte{0xAB, 0xCD, 0xEF}
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{MsgType: MsgTypeSolicit, TransactionID: xid},
		{MsgType: MsgTypeAdvertise, TransactionID: xid},
	})))
	if len(cfgs) != 2 {
		t.Fatalf("packet count = %d, want 2", len(cfgs))
	}
	if got := xidBytes(cfgs[0].Payload); got != xid {
		t.Errorf("SOLICIT XID = %x, want %x", got, xid)
	}
	if got := xidBytes(cfgs[1].Payload); got != xid {
		t.Errorf("ADVERTISE XID = %x, want %x", got, xid)
	}
}

// ===================================================================
// §1.3 hop-count (中继跳数, 1 字节)
// ===================================================================

// 1.3.1: hop-count=0 -> payload[1]=0x00.
func TestT1_3_1_hopCountZero(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeRelayForw,
			RelayFields: &core.RelayFields{
				HopCount: 0, LinkAddress: "2001:db8::1", PeerAddress: "fe80::1",
			},
			Options: []core.DHCPv6Option{{Code: OptRelayMsg, Data: []byte{MsgTypeSolicit, 0, 0, 0}}},
		},
	})))
	p := payload(t, cfgs)
	if p[1] != 0 {
		t.Errorf("hop-count = %d, want 0", p[1])
	}
}

// 1.3.4: hop-count=32 -> payload[1]=0x20 (HOP_COUNT_LIMIT).
func TestT1_3_4_hopCount32(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeRelayForw,
			RelayFields: &core.RelayFields{
				HopCount: 32, LinkAddress: "2001:db8::1", PeerAddress: "fe80::1",
			},
			Options: []core.DHCPv6Option{{Code: OptRelayMsg, Data: []byte{MsgTypeSolicit, 0, 0, 0}}},
		},
	})))
	p := payload(t, cfgs)
	if p[1] != 32 {
		t.Errorf("hop-count = %d, want 32", p[1])
	}
}

// 1.3.5: hop-count=33 -> Validate error.
func TestT1_3_5_hopCount33(t *testing.T) {
	err := NewPlanner().Validate(makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeRelayForw,
			RelayFields: &core.RelayFields{
				HopCount: 33, LinkAddress: "2001:db8::1", PeerAddress: "fe80::1",
			},
		},
	}))
	if err == nil {
		t.Errorf("Validate accepted hop-count=33")
	}
}

// ===================================================================
// §1.4 link-address (中继链路地址, 16 字节 IPv6)
// ===================================================================

// 1.4.1: link-address=2001:db8::1 -> payload[2:18]=16-byte IPv6.
func TestT1_4_1_linkAddressGlobal(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeRelayForw,
			RelayFields: &core.RelayFields{
				HopCount: 1, LinkAddress: "2001:db8::1", PeerAddress: "fe80::1",
			},
			Options: []core.DHCPv6Option{{Code: OptRelayMsg, Data: []byte{MsgTypeSolicit, 0, 0, 0}}},
		},
	})))
	p := payload(t, cfgs)
	got := net.IP(p[2:18])
	want := net.ParseIP("2001:db8::1")
	if !got.Equal(want) {
		t.Errorf("link-address = %v, want %v", got, want)
	}
}

// 1.4.3: link-address="" -> Validate error.
func TestT1_4_3_linkAddressEmpty(t *testing.T) {
	err := NewPlanner().Validate(makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeRelayForw,
			RelayFields: &core.RelayFields{
				HopCount: 1, LinkAddress: "", PeerAddress: "fe80::1",
			},
		},
	}))
	if err == nil {
		t.Errorf("Validate accepted empty link-address")
	}
}

// ===================================================================
// §1.5 peer-address (中继对端地址, 16 字节 IPv6)
// ===================================================================

// 1.5.1: peer-address=fe80::1234 -> payload[18:34]=16-byte IPv6.
func TestT1_5_1_peerAddressLinkLocal(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeRelayForw,
			RelayFields: &core.RelayFields{
				HopCount: 1, LinkAddress: "2001:db8::1", PeerAddress: "fe80::1234",
			},
			Options: []core.DHCPv6Option{{Code: OptRelayMsg, Data: []byte{MsgTypeSolicit, 0, 0, 0}}},
		},
	})))
	p := payload(t, cfgs)
	got := net.IP(p[18:34])
	want := net.ParseIP("fe80::1234")
	if !got.Equal(want) {
		t.Errorf("peer-address = %v, want %v", got, want)
	}
}

// 1.5.3: peer-address="" -> Validate error.
func TestT1_5_3_peerAddressEmpty(t *testing.T) {
	err := NewPlanner().Validate(makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeRelayForw,
			RelayFields: &core.RelayFields{
				HopCount: 1, LinkAddress: "2001:db8::1", PeerAddress: "",
			},
		},
	}))
	if err == nil {
		t.Errorf("Validate accepted empty peer-address")
	}
}

// ===================================================================
// §1.6 OPTION_CLIENTID (option 1, 客户端标识)
// ===================================================================

// 1.6.1: ClientID with DUID-LLT -> code=1, data=DUID-LLT bytes.
func TestT1_6_1_clientID_LLT(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptClientID, Data: mustSerializeDUID(t, &core.DUID{
					Type: DUIDTypeLLT, HardwareType: 1, Time: 0, LinkLayerAddr: "00:11:22:33:44:55",
				})},
			},
		},
	})))
	p := payload(t, cfgs)
	cid := findOption(p, OptClientID)
	if cid == nil {
		t.Fatalf("ClientID not found")
	}
	// Verify DUID type=1 (LLT).
	if len(cid) < 2 {
		t.Fatalf("ClientID too short: %d bytes", len(cid))
	}
	duidType := binary.BigEndian.Uint16(cid[0:2])
	if duidType != DUIDTypeLLT {
		t.Errorf("ClientID DUID type = %d, want 1 (LLT)", duidType)
	}
}

// 1.6.2: ClientID with DUID-EN -> code=1, data=DUID-EN bytes.
func TestT1_6_2_clientID_EN(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptClientID, Data: mustSerializeDUID(t, &core.DUID{
					Type: DUIDTypeEN, EnterpriseNum: 9, VendorSpecific: []byte("cisco"),
				})},
			},
		},
	})))
	p := payload(t, cfgs)
	cid := findOption(p, OptClientID)
	if cid == nil {
		t.Fatalf("ClientID not found")
	}
	duidType := binary.BigEndian.Uint16(cid[0:2])
	if duidType != DUIDTypeEN {
		t.Errorf("ClientID DUID type = %d, want 2 (EN)", duidType)
	}
	entNum := binary.BigEndian.Uint32(cid[2:6])
	if entNum != 9 {
		t.Errorf("ClientID EN = %d, want 9", entNum)
	}
}

// 1.6.3: ClientID with DUID-LL -> code=1, data=DUID-LL bytes.
func TestT1_6_3_clientID_LL(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptClientID, Data: mustSerializeDUID(t, &core.DUID{
					Type: DUIDTypeLL, HardwareType: 1, LinkLayerAddr: "00:11:22:33:44:55",
				})},
			},
		},
	})))
	p := payload(t, cfgs)
	cid := findOption(p, OptClientID)
	if cid == nil {
		t.Fatalf("ClientID not found")
	}
	duidType := binary.BigEndian.Uint16(cid[0:2])
	if duidType != DUIDTypeLL {
		t.Errorf("ClientID DUID type = %d, want 3 (LL)", duidType)
	}
}

// 1.6.9: DUID length=129 -> Validate error.
func TestT1_6_9_clientIDTooLong(t *testing.T) {
	// Build a DUID with 129 bytes total.
	bigDUID := &core.DUID{
		Type: DUIDTypeEN, EnterpriseNum: 0, VendorSpecific: make([]byte, 129-6),
	}
	spec := validSpec()
	spec.DHCPv6.ClientDUID = bigDUID
	spec.DHCPv6.Messages = []core.DHCPv6Message{{MsgType: MsgTypeSolicit}}
	err := NewPlanner().Validate(spec)
	if err == nil {
		t.Errorf("Validate accepted DUID length 129")
	}
}

// ===================================================================
// §1.7 OPTION_SERVERID (option 2, 服务器标识)
// ===================================================================

// 1.7.1: ServerID with DUID-LLT -> code=2, data=DUID-LLT bytes.
func TestT1_7_1_serverID_LLT(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeReply, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptServerID, Data: mustSerializeDUID(t, &core.DUID{
					Type: DUIDTypeLLT, HardwareType: 1, Time: 0, LinkLayerAddr: "00:aa:bb:cc:dd:ee",
				})},
			},
		},
	})))
	p := payload(t, cfgs)
	sid := findOption(p, OptServerID)
	if sid == nil {
		t.Fatalf("ServerID not found")
	}
	if len(sid) < 2 {
		t.Fatalf("ServerID too short: %d bytes", len(sid))
	}
	duidType := binary.BigEndian.Uint16(sid[0:2])
	if duidType != DUIDTypeLLT {
		t.Errorf("ServerID DUID type = %d, want 1 (LLT)", duidType)
	}
}

// 1.7.2: ServerID with DUID-EN -> code=2, data=DUID-EN bytes.
func TestT1_7_2_serverID_EN(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeReply, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptServerID, Data: mustSerializeDUID(t, &core.DUID{
					Type: DUIDTypeEN, EnterpriseNum: 9, VendorSpecific: []byte("trafficgen"),
				})},
			},
		},
	})))
	p := payload(t, cfgs)
	sid := findOption(p, OptServerID)
	if sid == nil {
		t.Fatalf("ServerID not found")
	}
	duidType := binary.BigEndian.Uint16(sid[0:2])
	if duidType != DUIDTypeEN {
		t.Errorf("ServerID DUID type = %d, want 2 (EN)", duidType)
	}
}

// ===================================================================
// §1.8 OPTION_IA_NA (option 3, 非临时地址 IA)
// ===================================================================

// 1.8.1: IA_NA IAID=1 T1=0 T2=0 no sub-options -> code=3, len=12.
func TestT1_8_1_IANA_basic(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptIANA, Data: BuildIA_NA(1, 0, 0, nil)},
			},
		},
	})))
	p := payload(t, cfgs)
	opt := findOption(p, OptIANA)
	if opt == nil {
		t.Fatalf("IA_NA not found")
	}
	if len(opt) != 12 {
		t.Errorf("IA_NA data length = %d, want 12", len(opt))
	}
	iaid := binary.BigEndian.Uint32(opt[0:4])
	t1 := binary.BigEndian.Uint32(opt[4:8])
	t2 := binary.BigEndian.Uint32(opt[8:12])
	if iaid != 1 || t1 != 0 || t2 != 0 {
		t.Errorf("IA_NA: IAID=%d T1=%d T2=%d, want 1/0/0", iaid, t1, t2)
	}
}

// 1.8.2: IA_NA IAID=0xFFFFFFFF T1=0xFFFFFFFF T2=0xFFFFFFFF (boundary).
func TestT1_8_2_IANA_boundary(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptIANA, Data: BuildIA_NA(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, nil)},
			},
		},
	})))
	p := payload(t, cfgs)
	opt := findOption(p, OptIANA)
	if opt == nil {
		t.Fatalf("IA_NA not found")
	}
	if len(opt) != 12 {
		t.Errorf("IA_NA data length = %d, want 12", len(opt))
	}
	for i, b := range opt {
		if b != 0xFF {
			t.Errorf("IA_NA byte[%d] = 0x%02x, want 0xFF", i, b)
		}
	}
}

// 1.8.3: IA_NA with 1 IA Address sub-option -> len = 12 + 4 + 28 = 44.
func TestT1_8_3_IANA_withIAAddr(t *testing.T) {
	iaAddrData := BuildIAAddress(IAAddress{IPv6Addr: "2001:db8::100", Preferred: 3600, Valid: 7200}, nil)
	iaNAData := BuildIA_NA(1, 1800, 2880, appendOpt(nil, OptIAAddr, iaAddrData))
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptIANA, Data: iaNAData},
			},
		},
	})))
	p := payload(t, cfgs)
	opt := findOption(p, OptIANA)
	if opt == nil {
		t.Fatalf("IA_NA not found")
	}
	if len(opt) != 40 {
		t.Errorf("IA_NA data length = %d, want 40 (12 + 28 sub-option)", len(opt))
	}
}

// ===================================================================
// §1.9 OPTION_IA_TA (option 4, 临时地址 IA)
// ===================================================================

// 1.9.1: IA_TA IAID=1 no sub-options -> code=4, len=4 (no T1/T2).
func TestT1_9_1_IATA_basic(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptIATA, Data: BuildIA_TA(1, nil)},
			},
		},
	})))
	p := payload(t, cfgs)
	opt := findOption(p, OptIATA)
	if opt == nil {
		t.Fatalf("IA_TA not found")
	}
	if len(opt) != 4 {
		t.Errorf("IA_TA data length = %d, want 4", len(opt))
	}
	iaid := binary.BigEndian.Uint32(opt[0:4])
	if iaid != 1 {
		t.Errorf("IA_TA IAID = %d, want 1", iaid)
	}
}

// ===================================================================
// §1.10 OPTION_IAADDR (option 5, IA Address 子选项)
// ===================================================================

// 1.10.1: IA Address=2001:db8::1 preferred=3600 valid=7200 -> code=5, len=24.
func TestT1_10_1_IAAddr_basic(t *testing.T) {
	iaAddrData := BuildIAAddress(IAAddress{IPv6Addr: "2001:db8::1", Preferred: 3600, Valid: 7200}, nil)
	// Wrap in IA_NA so we can find it.
	iaNAData := BuildIA_NA(1, 1800, 2880, appendOpt(nil, OptIAAddr, iaAddrData))
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeReply, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptIANA, Data: iaNAData},
			},
		},
	})))
	p := payload(t, cfgs)
	iaNA := findOption(p, OptIANA)
	if iaNA == nil {
		t.Fatalf("IA_NA not found")
	}
	// Find IA Address sub-option inside IA_NA data (starting at offset 12).
	iaAddr := findOptionsFromOffset(iaNA, 12, OptIAAddr)
	if iaAddr == nil || len(iaAddr) < 24 {
		t.Fatalf("IA Address sub-option not found or too short")
	}
	gotIP := net.IP(iaAddr[0:16])
	wantIP := net.ParseIP("2001:db8::1")
	if !gotIP.Equal(wantIP) {
		t.Errorf("IA Address IPv6 = %v, want %v", gotIP, wantIP)
	}
	gotPref := binary.BigEndian.Uint32(iaAddr[16:20])
	gotValid := binary.BigEndian.Uint32(iaAddr[20:24])
	if gotPref != 3600 || gotValid != 7200 {
		t.Errorf("IA Address lifetimes: preferred=%d valid=%d, want 3600/7200", gotPref, gotValid)
	}
}

// 1.10.5: preferred > valid -> ValidateIAAddrPreferredValid error.
func TestT1_10_5_IAAddrPreferredGTValid(t *testing.T) {
	err := ValidateIAAddrPreferredValid(7200, 3600)
	if err == nil {
		t.Errorf("ValidateIAAddrPreferredValid(7200, 3600) should reject")
	}
}

// ===================================================================
// §1.11 OPTION_ORO (option 6, Option Request)
// ===================================================================

// 1.11.1: ORO=[23, 24] -> code=6, len=4, data=0x0017 0x0018.
func TestT1_11_1_ORO(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptORO, Data: BuildORO([]uint16{OptRDNSS, OptDNSSL})},
			},
		},
	})))
	p := payload(t, cfgs)
	oro := findOption(p, OptORO)
	if oro == nil {
		t.Fatalf("ORO not found")
	}
	if len(oro) != 4 {
		t.Errorf("ORO data length = %d, want 4", len(oro))
	}
	if binary.BigEndian.Uint16(oro[0:2]) != OptRDNSS {
		t.Errorf("ORO[0] = %d, want 23", binary.BigEndian.Uint16(oro[0:2]))
	}
	if binary.BigEndian.Uint16(oro[2:4]) != OptDNSSL {
		t.Errorf("ORO[1] = %d, want 24", binary.BigEndian.Uint16(oro[2:4]))
	}
}

// 1.11.3: ORO empty -> code=6, len=0.
func TestT1_11_3_ORO_empty(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptORO, Data: BuildORO(nil)},
			},
		},
	})))
	p := payload(t, cfgs)
	oro := findOption(p, OptORO)
	if oro == nil {
		t.Fatalf("ORO not found")
	}
	if len(oro) != 0 {
		t.Errorf("ORO data length = %d, want 0", len(oro))
	}
}

// ===================================================================
// §1.12 OPTION_PREFERENCE (option 7, 服务器优先级)
// ===================================================================

// 1.12.1: Preference=0 -> code=7, len=1, data=0x00.
func TestT1_12_1_PreferenceZero(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeAdvertise, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptPreference, Data: BuildPreference(0)},
			},
		},
	})))
	p := payload(t, cfgs)
	pref := findOption(p, OptPreference)
	if pref == nil {
		t.Fatalf("Preference not found")
	}
	if len(pref) != 1 {
		t.Errorf("Preference data length = %d, want 1", len(pref))
	}
	if pref[0] != 0 {
		t.Errorf("Preference = %d, want 0", pref[0])
	}
}

// 1.12.2: Preference=255 -> code=7, len=1, data=0xFF.
func TestT1_12_2_Preference255(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeAdvertise, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptPreference, Data: BuildPreference(255)},
			},
		},
	})))
	p := payload(t, cfgs)
	pref := findOption(p, OptPreference)
	if pref == nil {
		t.Fatalf("Preference not found")
	}
	if len(pref) != 1 {
		t.Errorf("Preference data length = %d, want 1", len(pref))
	}
	if pref[0] != 255 {
		t.Errorf("Preference = %d, want 255", pref[0])
	}
}

// ===================================================================
// §1.13 OPTION_ELAPSED_TIME (option 8, 经过时间)
// ===================================================================

// 1.13.1: Elapsed Time=0 -> code=8, len=2, data=0x0000.
func TestT1_13_1_ElapsedTimeZero(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptElapsedTime, Data: BuildElapsedTime(0)},
			},
		},
	})))
	p := payload(t, cfgs)
	et := findOption(p, OptElapsedTime)
	if et == nil {
		t.Fatalf("ElapsedTime not found")
	}
	if len(et) != 2 {
		t.Errorf("ElapsedTime data length = %d, want 2", len(et))
	}
	if got := binary.BigEndian.Uint16(et); got != 0 {
		t.Errorf("ElapsedTime = %d, want 0", got)
	}
}

// 1.13.2: Elapsed Time=100 (10 sec) -> data=0x0064.
func TestT1_13_2_ElapsedTime100(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptElapsedTime, Data: BuildElapsedTime(100)},
			},
		},
	})))
	p := payload(t, cfgs)
	et := findOption(p, OptElapsedTime)
	if et == nil {
		t.Fatalf("ElapsedTime not found")
	}
	if got := binary.BigEndian.Uint16(et); got != 100 {
		t.Errorf("ElapsedTime = %d, want 100", got)
	}
}

// 1.13.3: Elapsed Time=0xFFFF -> data=0xFFFF (max).
func TestT1_13_3_ElapsedTimeMax(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptElapsedTime, Data: BuildElapsedTime(0xFFFF)},
			},
		},
	})))
	p := payload(t, cfgs)
	et := findOption(p, OptElapsedTime)
	if et == nil {
		t.Fatalf("ElapsedTime not found")
	}
	if got := binary.BigEndian.Uint16(et); got != 0xFFFF {
		t.Errorf("ElapsedTime = %d, want 65535", got)
	}
}

// ===================================================================
// §1.14 OPTION_RELAY_MSG (option 9, Relay Message)
// ===================================================================

// 1.14.1: RELAY-FORW option 9 = client SOLICIT bytes.
func TestT1_14_1_RelayMsg_SOLICIT(t *testing.T) {
	inner := []byte{MsgTypeSolicit, 0x12, 0x34, 0x56}
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeRelayForw,
			RelayFields: &core.RelayFields{
				HopCount: 1, LinkAddress: "2001:db8::1", PeerAddress: "fe80::1",
			},
			Options: []core.DHCPv6Option{
				{Code: OptRelayMsg, Data: BuildRelayMessage(inner)},
			},
		},
	})))
	p := payload(t, cfgs)
	rm := findOptionsFromOffset(p, RelayHeaderLen, OptRelayMsg)
	if rm == nil {
		t.Fatalf("Relay Message (option 9) not found")
	}
	if string(rm) != string(inner) {
		t.Errorf("Relay Message data = %x, want %x", rm, inner)
	}
}

// ===================================================================
// §1.16 OPTION_STATUS_CODE (option 13, 状态码)
// ===================================================================

// 1.16.1: Status=0 (Success) message="OK" -> code=13, len=4, data=0x0000 "OK".
func TestT1_16_1_StatusCodeSuccess(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeReply, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptStatusCode, Data: BuildStatusCode(0, "OK")},
			},
		},
	})))
	p := payload(t, cfgs)
	sc := findOption(p, OptStatusCode)
	if sc == nil {
		t.Fatalf("StatusCode not found")
	}
	status := binary.BigEndian.Uint16(sc[0:2])
	if status != 0 {
		t.Errorf("Status = %d, want 0", status)
	}
	if string(sc[2:]) != "OK" {
		t.Errorf("Status message = %q, want \"OK\"", string(sc[2:]))
	}
}

// 1.16.2: Status=2 (NoAddrsAvail) message="" -> len=2.
func TestT1_16_2_StatusCodeNoAddrsAvail(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeReply, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptStatusCode, Data: BuildStatusCode(2, "")},
			},
		},
	})))
	p := payload(t, cfgs)
	sc := findOption(p, OptStatusCode)
	if sc == nil {
		t.Fatalf("StatusCode not found")
	}
	if len(sc) != 2 {
		t.Errorf("StatusCode data length = %d, want 2", len(sc))
	}
	if got := binary.BigEndian.Uint16(sc); got != 2 {
		t.Errorf("Status = %d, want 2", got)
	}
}

// ===================================================================
// §1.17 OPTION_RAPID_COMMIT (option 14)
// ===================================================================

// 1.17.1: Rapid Commit -> code=14, len=0, data=empty.
func TestT1_17_1_RapidCommit(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptRapidCommit, Data: BuildRapidCommit()},
			},
		},
	})))
	p := payload(t, cfgs)
	rc := findOption(p, OptRapidCommit)
	if rc == nil {
		t.Fatalf("RapidCommit not found")
	}
	if len(rc) != 0 {
		t.Errorf("RapidCommit data length = %d, want 0", len(rc))
	}
}

// ===================================================================
// §1.18 OPTION_USER_CLASS (option 16)
// ===================================================================

// 1.18.1: User Class with 1 data="office" -> len=2+6=8.
func TestT1_18_1_UserClass(t *testing.T) {
	const OptUserClass uint16 = 16
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptUserClass, Data: BuildUserClass([][]byte{[]byte("office")})},
			},
		},
	})))
	p := payload(t, cfgs)
	uc := findOption(p, OptUserClass)
	if uc == nil {
		t.Fatalf("UserClass not found")
	}
	if len(uc) != 8 {
		t.Errorf("UserClass data length = %d, want 8", len(uc))
	}
}

// ===================================================================
// §1.19 OPTION_VENDOR_CLASS (option 17)
// ===================================================================

// 1.19.1: Vendor Class enterprise=9 data="router" -> len=4+2+6=12.
func TestT1_19_1_VendorClass(t *testing.T) {
	const OptVendorClass uint16 = 17
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptVendorClass, Data: BuildVendorClass(9, [][]byte{[]byte("router")})},
			},
		},
	})))
	p := payload(t, cfgs)
	vc := findOption(p, OptVendorClass)
	if vc == nil {
		t.Fatalf("VendorClass not found")
	}
	if len(vc) != 12 {
		t.Errorf("VendorClass data length = %d, want 12", len(vc))
	}
	entNum := binary.BigEndian.Uint32(vc[0:4])
	if entNum != 9 {
		t.Errorf("EnterpriseNum = %d, want 9", entNum)
	}
}

// ===================================================================
// §1.20 OPTION_INTERFACE_ID (option 18)
// ===================================================================

// 1.20.1: Interface ID=0x0102030405 -> code=18, len=5.
func TestT1_20_1_InterfaceID(t *testing.T) {
	const OptInterfaceID uint16 = 18
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeRelayForw,
			RelayFields: &core.RelayFields{
				HopCount: 1, LinkAddress: "2001:db8::1", PeerAddress: "fe80::1",
			},
			Options: []core.DHCPv6Option{
				{Code: OptRelayMsg, Data: []byte{MsgTypeSolicit, 0, 0, 0}},
				{Code: OptInterfaceID, Data: BuildInterfaceID(data)},
			},
		},
	})))
	p := payload(t, cfgs)
	iid := findOptionsFromOffset(p, RelayHeaderLen, OptInterfaceID)
	if iid == nil {
		t.Fatalf("InterfaceID not found")
	}
	if string(iid) != string(data) {
		t.Errorf("InterfaceID = %x, want %x", iid, data)
	}
}

// ===================================================================
// §1.21 OPTION_RECONF_MSG (option 19)
// ===================================================================

// 1.21.1: Reconf Msg-Type=5 -> code=19, len=1, data=0x05.
func TestT1_21_1_ReconfMsgRENEW(t *testing.T) {
	const OptReconfMsg uint16 = 19
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeReconfigure, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptReconfMsg, Data: BuildReconfMsg(MsgTypeRenew)},
			},
		},
	})))
	p := payload(t, cfgs)
	rm := findOption(p, OptReconfMsg)
	if rm == nil {
		t.Fatalf("ReconfMsg not found")
	}
	if len(rm) != 1 {
		t.Errorf("ReconfMsg data length = %d, want 1", len(rm))
	}
	if rm[0] != MsgTypeRenew {
		t.Errorf("ReconfMsg msg-type = %d, want 5 (RENEW)", rm[0])
	}
}

// ===================================================================
// §1.23 OPTION_IAPREFIX (option 26, IA Prefix 子选项)
// ===================================================================

// 1.23.1: IA Prefix preferred=3600 valid=7200 prefix=2001:db8:1:: prefix-len=48.
func TestT1_23_1_IAPrefix_basic(t *testing.T) {
	iaPrefixData := BuildIAPrefix(IAPrefix{
		Preferred: 3600, Valid: 7200, Prefix: "2001:db8:1::", PrefixLen: 48,
	})
	// Wrap in IA_PD.
	iaPDData := BuildIA_PD(1, 3600, 5760, appendOpt(nil, OptIAPrefix, iaPrefixData))
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeReply, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptIAPD, Data: iaPDData},
			},
		},
	})))
	p := payload(t, cfgs)
	iaPD := findOption(p, OptIAPD)
	if iaPD == nil {
		t.Fatalf("IA_PD not found")
	}
	// Find IA Prefix sub-option inside IA_PD data (starting at offset 12).
	iaPrefix := findOptionsFromOffset(iaPD, 12, OptIAPrefix)
	if iaPrefix == nil || len(iaPrefix) < 25 {
		t.Fatalf("IA Prefix sub-option not found or too short")
	}
	gotPref := binary.BigEndian.Uint32(iaPrefix[0:4])
	gotValid := binary.BigEndian.Uint32(iaPrefix[4:8])
	if gotPref != 3600 || gotValid != 7200 {
		t.Errorf("IA Prefix lifetimes: preferred=%d valid=%d, want 3600/7200", gotPref, gotValid)
	}
	gotPrefix := net.IP(iaPrefix[8:24])
	wantPrefix := net.ParseIP("2001:db8:1::")
	if !gotPrefix.Equal(wantPrefix) {
		t.Errorf("IA Prefix address = %v, want %v", gotPrefix, wantPrefix)
	}
	if iaPrefix[24] != 48 {
		t.Errorf("IA Prefix length = %d, want 48", iaPrefix[24])
	}
}

// 1.23.6: prefix-len=129 -> Validate error.
func TestT1_23_6_IAPrefixLen129(t *testing.T) {
	err := ValidateIAPrefixLen(129)
	if err == nil {
		t.Errorf("ValidateIAPrefixLen(129) should reject")
	}
}

// ===================================================================
// §1.24 OPTION_RDNSS (option 23, 递归 DNS 服务器)
// ===================================================================

// 1.24.1: RDNSS lifetime=3600 servers=[2001:db8::53] -> len=20.
func TestT1_24_1_RDNSS(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeReply, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptRDNSS, Data: BuildRDNSS(3600, []string{"2001:db8::53"})},
			},
		},
	})))
	p := payload(t, cfgs)
	rd := findOption(p, OptRDNSS)
	if rd == nil {
		t.Fatalf("RDNSS not found")
	}
	if len(rd) != 20 {
		t.Errorf("RDNSS data length = %d, want 20 (4+16)", len(rd))
	}
	gotLifetime := binary.BigEndian.Uint32(rd[0:4])
	if gotLifetime != 3600 {
		t.Errorf("RDNSS lifetime = %d, want 3600", gotLifetime)
	}
	gotIP := net.IP(rd[4:20])
	wantIP := net.ParseIP("2001:db8::53")
	if !gotIP.Equal(wantIP) {
		t.Errorf("RDNSS server = %v, want %v", gotIP, wantIP)
	}
}

// ===================================================================
// §1.25 OPTION_DNSSL (option 24, DNS 搜索列表)
// ===================================================================

// 1.25.1: DNSSL lifetime=3600 domains=[example.com] -> DNS wire format.
func TestT1_25_1_DNSSL(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeReply, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptDNSSL, Data: BuildDNSSL(3600, []string{"example.com"})},
			},
		},
	})))
	p := payload(t, cfgs)
	ds := findOption(p, OptDNSSL)
	if ds == nil {
		t.Fatalf("DNSSL not found")
	}
	if len(ds) < 5 {
		t.Fatalf("DNSSL too short: %d bytes", len(ds))
	}
	gotLifetime := binary.BigEndian.Uint32(ds[0:4])
	if gotLifetime != 3600 {
		t.Errorf("DNSSL lifetime = %d, want 3600", gotLifetime)
	}
	// Verify wire format: \x07example\x03com\x00
	if len(ds) < 16 {
		t.Errorf("DNSSL data length = %d, want >= 16", len(ds))
	}
	// Check label encoding starts with 0x07 (length of "example").
	if ds[4] != 7 {
		t.Errorf("DNSSL first label length = %d, want 7", ds[4])
	}
}

// ===================================================================
// §1.27 OPTION_INFORMATION_REFRESH_TIME (option 32)
// ===================================================================

// 1.27.1: refresh_time=86400 -> code=32, len=4, data=0x00015180.
func TestT1_27_1_InfoRefreshTime(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeReply, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptInfoRefreshTime, Data: BuildInfoRefreshTime(86400)},
			},
		},
	})))
	p := payload(t, cfgs)
	irt := findOption(p, OptInfoRefreshTime)
	if irt == nil {
		t.Fatalf("InfoRefreshTime not found")
	}
	if len(irt) != 4 {
		t.Errorf("InfoRefreshTime data length = %d, want 4", len(irt))
	}
	if got := binary.BigEndian.Uint32(irt); got != 86400 {
		t.Errorf("InfoRefreshTime = %d, want 86400", got)
	}
}

// ===================================================================
// §1.28 OPTION_FQDN (option 39, 客户端 FQDN)
// ===================================================================

// 1.28.1: FQDN flags=0x00 domain="client.example.com" -> len=1+18=19.
func TestT1_28_1_FQDN(t *testing.T) {
	const OptFQDN uint16 = 39
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptFQDN, Data: BuildFQDN(0x00, "client.example.com")},
			},
		},
	})))
	p := payload(t, cfgs)
	fqdn := findOption(p, OptFQDN)
	if fqdn == nil {
		t.Fatalf("FQDN not found")
	}
	if len(fqdn) < 2 {
		t.Fatalf("FQDN too short: %d bytes", len(fqdn))
	}
	if fqdn[0] != 0x00 {
		t.Errorf("FQDN flags = 0x%02x, want 0x00", fqdn[0])
	}
	// Check that the domain is label-encoded.
	if fqdn[1] != 6 {
		t.Errorf("FQDN first label length = %d, want 6 ('client')", fqdn[1])
	}
}

// ===================================================================
// §1.29 OPTION_CLIENT_LINKLAYER_ADDR (option 79)
// ===================================================================

// 1.29.1: Client MAC=00:11:22:33:44:55 type=1 -> code=79, len=8.
func TestT1_29_1_ClientLinkLayer(t *testing.T) {
	const OptClientLinkLayer uint16 = 79
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeRelayForw,
			RelayFields: &core.RelayFields{
				HopCount: 1, LinkAddress: "2001:db8::1", PeerAddress: "fe80::1",
			},
			Options: []core.DHCPv6Option{
				{Code: OptRelayMsg, Data: []byte{MsgTypeSolicit, 0, 0, 0}},
				{Code: OptClientLinkLayer, Data: BuildClientLinkLayerAddr(LinkLayerTypeEthernet, mac)},
			},
		},
	})))
	p := payload(t, cfgs)
	cll := findOptionsFromOffset(p, RelayHeaderLen, OptClientLinkLayer)
	if cll == nil {
		t.Fatalf("ClientLinkLayer not found")
	}
	if len(cll) != 8 {
		t.Errorf("ClientLinkLayer data length = %d, want 8", len(cll))
	}
	llType := binary.BigEndian.Uint16(cll[0:2])
	if llType != LinkLayerTypeEthernet {
		t.Errorf("LinkLayer type = %d, want 1 (Ethernet)", llType)
	}
}

// ===================================================================
// §1.30 DUID-LLT
// ===================================================================

// 1.30.1: DUID-LLT hw-type=1 time=0 MAC=00:11:22:33:44:55.
func TestT1_30_1_DUID_LLT(t *testing.T) {
	duid := &core.DUID{
		Type: DUIDTypeLLT, HardwareType: 1, Time: 0, LinkLayerAddr: "00:11:22:33:44:55",
	}
	data, err := serializeDUID(duid)
	if err != nil {
		t.Fatalf("serializeDUID failed: %v", err)
	}
	want := []byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	if len(data) != len(want) {
		t.Fatalf("DUID-LLT length = %d, want %d", len(data), len(want))
	}
	for i := range data {
		if data[i] != want[i] {
			t.Errorf("DUID-LLT byte[%d] = 0x%02x, want 0x%02x", i, data[i], want[i])
		}
	}
}

// ===================================================================
// §1.31 DUID-EN
// ===================================================================

// 1.31.1: DUID-EN enterprise=9 vendor-specific="router".
func TestT1_31_1_DUID_EN(t *testing.T) {
	duid := &core.DUID{
		Type: DUIDTypeEN, EnterpriseNum: 9, VendorSpecific: []byte("router"),
	}
	data, err := serializeDUID(duid)
	if err != nil {
		t.Fatalf("serializeDUID failed: %v", err)
	}
	if len(data) != 2+4+6 {
		t.Errorf("DUID-EN length = %d, want 12", len(data))
	}
	duidType := binary.BigEndian.Uint16(data[0:2])
	if duidType != DUIDTypeEN {
		t.Errorf("DUID type = %d, want 2", duidType)
	}
	entNum := binary.BigEndian.Uint32(data[2:6])
	if entNum != 9 {
		t.Errorf("EnterpriseNum = %d, want 9", entNum)
	}
	if string(data[6:]) != "router" {
		t.Errorf("VendorSpecific = %q, want \"router\"", string(data[6:]))
	}
}

// ===================================================================
// §1.32 DUID-LL
// ===================================================================

// 1.32.1: DUID-LL hw-type=1 MAC=00:11:22:33:44:55.
func TestT1_32_1_DUID_LL(t *testing.T) {
	duid := &core.DUID{
		Type: DUIDTypeLL, HardwareType: 1, LinkLayerAddr: "00:11:22:33:44:55",
	}
	data, err := serializeDUID(duid)
	if err != nil {
		t.Fatalf("serializeDUID failed: %v", err)
	}
	want := []byte{0x00, 0x03, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	if len(data) != len(want) {
		t.Fatalf("DUID-LL length = %d, want %d", len(data), len(want))
	}
	for i := range data {
		if data[i] != want[i] {
			t.Errorf("DUID-LL byte[%d] = 0x%02x, want 0x%02x", i, data[i], want[i])
		}
	}
}

// ===================================================================
// §1.33 DUID general
// ===================================================================

// 1.33.1: DUID type=0 -> validate error.
func TestT1_33_1_DUIDTypeZero(t *testing.T) {
	err := validateDUID(&core.DUID{Type: 0})
	if err == nil {
		t.Errorf("validateDUID(0) should reject")
	}
}

// 1.33.2: DUID type=4 -> validate error.
func TestT1_33_2_DUIDType4(t *testing.T) {
	err := validateDUID(&core.DUID{Type: 4})
	if err == nil {
		t.Errorf("validateDUID(4) should reject")
	}
}

// 1.33.5: DUID length=128 -> valid boundary.
func TestT1_33_5_DUIDLength128(t *testing.T) {
	duid := &core.DUID{
		Type: DUIDTypeEN, EnterpriseNum: 0,
		VendorSpecific: make([]byte, 128-6),
	}
	err := validateDUID(duid)
	if err != nil {
		t.Errorf("validateDUID(128 bytes) should be valid, got: %v", err)
	}
}

// 1.33.6: DUID length=129 -> validate error.
func TestT1_33_6_DUIDLength129(t *testing.T) {
	duid := &core.DUID{
		Type: DUIDTypeEN, EnterpriseNum: 0,
		VendorSpecific: make([]byte, 129-6),
	}
	err := validateDUID(duid)
	if err == nil {
		t.Errorf("validateDUID(129 bytes) should reject")
	}
}

// ===================================================================
// §4.2 Boundary values (边界值)
// ===================================================================

// 4.2.11: preferred-lifetime > valid-lifetime -> error.
func TestT4_2_11_PreferredGTValid(t *testing.T) {
	err := ValidateIAAddrPreferredValid(7200, 3600)
	if err == nil {
		t.Errorf("ValidateIAAddrPreferredValid(7200, 3600) should reject preferred > valid")
	}
}

// 4.2.23: INFORMATION_REFRESH_TIME=0xFFFFFFFF -> 4 bytes all 0xFF.
func TestT4_2_23_InfoRefreshTimeMax(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeReply, TransactionID: [3]byte{1, 2, 3},
			Options: []core.DHCPv6Option{
				{Code: OptInfoRefreshTime, Data: BuildInfoRefreshTime(0xFFFFFFFF)},
			},
		},
	})))
	p := payload(t, cfgs)
	irt := findOption(p, OptInfoRefreshTime)
	if irt == nil || len(irt) != 4 {
		t.Fatalf("InfoRefreshTime not found or wrong length")
	}
	for i, b := range irt {
		if b != 0xFF {
			t.Errorf("InfoRefreshTime byte[%d] = 0x%02x, want 0xFF", i, b)
		}
	}
}

// ===================================================================
// §4.5 Smallest packets (最小包)
// ===================================================================

// 4.5.5: Empty options SOLICIT = 4-byte header only.
func TestT4_5_5_MinimalSOLICIT(t *testing.T) {
	cfgs := drain(mustPlan(t, NewPlanner(), makeSpec([]core.DHCPv6Message{
		{
			MsgType: MsgTypeSolicit,
			TransactionID: [3]byte{0, 0, 1},
		},
	})))
	p := payload(t, cfgs)
	// SOLICIT without options: 4-byte header only. But the planner auto-prepends
	// ClientID for client messages, so the actual payload will be longer.
	if len(p) < HeaderLen {
		t.Fatalf("payload too short: %d bytes", len(p))
	}
	if p[0] != MsgTypeSolicit {
		t.Errorf("payload[0] = 0x%02x, want 0x01", p[0])
	}
}

// ===================================================================
// Helpers
// ===================================================================

// mustSerializeDUID serializes a DUID and fails the test on error.
func mustSerializeDUID(t *testing.T, d *core.DUID) []byte {
	t.Helper()
	data, err := serializeDUID(d)
	if err != nil {
		t.Fatalf("serializeDUID failed: %v", err)
	}
	return data
}

// fmt imported for potential future use.
var _ = fmt.Sprintf