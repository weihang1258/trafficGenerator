package ldp

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func testConfig() *core.LDPConfig {
	return &core.LDPConfig{
		LSRID:              "192.0.2.1",
		LabelSpace:         0,
		Carrier:            "tcp_session",
		KeepaliveTime:      30,
		LabelAdvertisement: "downstream_unsolicited",
	}
}

func testEvent(kind, dir string, mid uint32) core.LDPEvent {
	return core.LDPEvent{Kind: kind, Direction: dir, MessageID: mid}
}

func TestBuildHelloUDPBasic(t *testing.T) {
	// S10 basic Hello, hold=15, no targeted, no transport addr:
	// pdu: ver(2)=0001 len(2)=0016 lsr(4)=c0000201 label(2)=0000
	//      msg: type(2)=0100 len(2)=000c id(4)=00000001
	//      tlv: type(2)=0400 len(2)=0004 hold(2)=000f flags(2)=0000
	pdu := BuildHelloPDU("192.0.2.1", 0, 1, 15, false, "")
	want := "00010016c000020100000100000c0000000104000004000f0000"
	if hex.EncodeToString(pdu) != want {
		t.Fatalf("Hello UDP basic:\ngot:  %x\nwant: %s", pdu, want)
	}
}

func TestBuildHelloTargeted(t *testing.T) {
	// S9: targeted Hello with transport address
	pdu := BuildHelloPDU("192.0.2.1", 0, 1, 15, true, "192.0.2.1")
	want := "0001001ec00002010000010000140000000104000004000f800004010004c0000201"
	if hex.EncodeToString(pdu) != want {
		t.Fatalf("Hello targeted:\ngot:  %x\nwant: %s", pdu, want)
	}
}

func TestBuildHelloZeroHoldDefaults(t *testing.T) {
	// HoldTime=0 should still produce a valid Hello
	pdu := BuildHelloPDU("192.0.2.1", 0, 1, 0, false, "")
	if len(pdu) < 10 {
		t.Fatalf("Hello too short: %d", len(pdu))
	}
}

func TestBuildInitializationExactBytes(t *testing.T) {
	// S1: initialization c2s, lsr=192.0.2.1, receiver=192.0.2.2, ka=30
	pdu := BuildInitPDU("192.0.2.1", 0, 10, 30, "downstream_unsolicited", "192.0.2.2")
	want := "00010020c00002010000020000160000000a0500000e0001001e00001000c00002020000"
	if hex.EncodeToString(pdu) != want {
		t.Fatalf("Init PDU:\ngot:  %x\nwant: %s", pdu, want)
	}
	// Verify PDU Length field
	pduLen := int(pdu[2])<<8 | int(pdu[3])
	if pduLen != 32 {
		t.Fatalf("PDU Length=%d want 32", pduLen)
	}
}

func TestBuildInitializationDownstreamOnDemand(t *testing.T) {
	pdu := BuildInitPDU("192.0.2.1", 0, 10, 30, "downstream_on_demand", "192.0.2.2")
	// Flags byte is at offset 26 (PDU hdr 10 + msg hdr 8 + TLV hdr 4 + Ver 2 + KeepAlive 2)
	ad := pdu[26] >> 6
	if ad != 1 {
		t.Fatalf("AD=%d want 1 (downstream_on_demand)", ad)
	}
}

func TestBuildKeepAlivePDU(t *testing.T) {
	// S2: KeepAlive, msgID=11
	pdu := BuildKeepAlivePDU("192.0.2.1", 0, 11)
	// msg type=0x0201, msg len=4 (just Message ID), pdu len=14 (6+4+4)
	want := "0001000ec00002010000020100040000000b"
	if hex.EncodeToString(pdu) != want {
		t.Fatalf("KeepAlive PDU:\ngot:  %x\nwant: %s", pdu, want)
	}
}

func TestBuildAddressPDU(t *testing.T) {
	// S3: Address message with one address
	pdu := BuildAddressPDU("192.0.2.1", 0, 12, []string{"192.0.2.1"})
	want := "00010018c000020100000300000e0000000c010100060001c0000201"
	if hex.EncodeToString(pdu) != want {
		t.Fatalf("Address PDU:\ngot:  %x\nwant: %s", pdu, want)
	}
}

func TestBuildLabelMappingIPV4(t *testing.T) {
	// S4: label_mapping, fec=203.0.113.0/24, label=74565 (0x12345)
	pdu := BuildLabelMappingPDU("192.0.2.1", 0, 13, "203.0.113.0", 24, 74565)
	// AF is 2 bytes, so FEC value = 1+2+1+3 = 7 bytes, FEC TLV = 4+7 = 11 bytes
	// Label TLV = 4+4 = 8 bytes, body = 19, msgLen = 4+19 = 23, PDU len = 6+8+19 = 33
	want := "00010021c00002010000040000170000000d0100000702000118cb00710200000400012345"
	if hex.EncodeToString(pdu) != want {
		t.Fatalf("LabelMapping PDU:\ngot:  %x\nwant: %s", pdu, want)
	}
}

func TestBuildLabelMappingHost32(t *testing.T) {
	// S8: /32 host route, label=703710 (0xabcde); prefix bytes = 4, FEC value = 8
	pdu := BuildLabelMappingPDU("192.0.2.1", 0, 13, "192.0.2.1", 32, 703710)
	want := "00010022c00002010000040000180000000d0100000802000120c000020102000004000abcde"
	if hex.EncodeToString(pdu) != want {
		t.Fatalf("LabelMapping /32:\ngot:  %x\nwant: %s", pdu, want)
	}
}

func TestBuildLabelRequestIPV4(t *testing.T) {
	// S5: label_request, fec=203.0.113.0/24 (FEC TLV value = 1+2+1+3 = 7)
	pdu := BuildLabelRequestPDU("192.0.2.1", 0, 13, "203.0.113.0", 24)
	want := "00010019c000020100000401000f0000000d0100000702000118cb0071"
	if hex.EncodeToString(pdu) != want {
		t.Fatalf("LabelRequest PDU:\ngot:  %x\nwant: %s", pdu, want)
	}
}

func TestBuildLabelWithdrawIPV4(t *testing.T) {
	// S6: label_withdraw, fec=203.0.113.0/24, label=74565 (0x12345)
	pdu := BuildLabelWithdrawPDU("192.0.2.1", 0, 14, "203.0.113.0", 24, 74565)
	want := "00010021c00002010000040200170000000e0100000702000118cb00710200000400012345"
	if hex.EncodeToString(pdu) != want {
		t.Fatalf("LabelWithdraw PDU:\ngot:  %x\nwant: %s", pdu, want)
	}
}

func TestBuildLabelReleaseIPV4(t *testing.T) {
	// S7: label_release, fec=203.0.113.0/24, label=74565 (0x12345)
	pdu := BuildLabelReleasePDU("192.0.2.1", 0, 14, "203.0.113.0", 24, 74565)
	want := "00010021c00002010000040300170000000e0100000702000118cb00710200000400012345"
	if hex.EncodeToString(pdu) != want {
		t.Fatalf("LabelRelease PDU:\ngot:  %x\nwant: %s", pdu, want)
	}
}

func TestBuildNotificationPDU(t *testing.T) {
	// S11: notification status=1 (Shutdown), from s2c (lsr=192.0.2.2)
	pdu := BuildNotificationPDU("192.0.2.2", 0, 22, 1)
	msgType := uint16(pdu[10])<<8 | uint16(pdu[11])
	if msgType != 0x0001 {
		t.Fatalf("msg type=0x%04x want 0x0001", msgType)
	}
}

func TestBuildNotificationStatusCode(t *testing.T) {
	// Build with explicit status code 10. Per RFC 5036 §3.5.3.1 the Status TLV
	// value is 10 bytes (Status Code 4 + Message ID 4 + Message Type 2); tshark
	// rejects any other length. SameSubtree offset: hdr(10)+msgHdr(8)+tlvHdr(4)=22.
	pdu := BuildNotificationPDU("192.0.2.2", 0, 22, 10)
	if got := len(pdu); got != 32 {
		t.Fatalf("pdu len=%d want 32 (10+8+4+10)", got)
	}
	sc := uint32(pdu[22])<<24 | uint32(pdu[23])<<16 | uint32(pdu[24])<<8 | uint32(pdu[25])
	if sc != 10 {
		t.Fatalf("status code=%d want 10", sc)
	}
	// Status TLV length field must be 10.
	stlvLen := uint16(pdu[20])<<8 | uint16(pdu[21])
	if stlvLen != 10 {
		t.Fatalf("status tlv len=%d want 10", stlvLen)
	}
}

func TestPlannerTCPInitSequence(t *testing.T) {
	// S1: initialization in both directions
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{
		{Kind: "initialization", Direction: "c2s", MessageID: 10, LSRID: "192.0.2.1", ReceiverLSRID: "192.0.2.2"},
		{Kind: "initialization", Direction: "s2c", MessageID: 20, LSRID: "192.0.2.2", ReceiverLSRID: "192.0.2.1"},
	}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 50000, DstPort: 646, LDP: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	// 3 handshake + 2 init + 4 teardown = 9
	if len(packets) != 9 {
		t.Fatalf("packets=%d want 9", len(packets))
	}
	// Packet 4 (index 3) = c2s init
	if packets[3].Direction != "up" {
		t.Fatalf("packet 3 direction=%q want up", packets[3].Direction)
	}
	if len(packets[3].Payload) == 0 {
		t.Fatal("packet 3 has no payload")
	}
	// Packet 5 (index 4) = s2c init
	if packets[4].Direction != "down" {
		t.Fatalf("packet 4 direction=%q want down", packets[4].Direction)
	}
}

func TestPlannerUDPHello(t *testing.T) {
	// S9: single targeted UDP hello
	cfg := &core.LDPConfig{
		LSRID:    "192.0.2.1",
		Carrier:  "udp_discovery",
		Targeted: true,
		Events: []core.LDPEvent{
			{Kind: "hello", Direction: "c2s", MessageID: 1, HoldTime: 15, LSRID: "192.0.2.1"},
		},
	}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 646, DstPort: 646, LDP: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	if len(packets) != 1 {
		t.Fatalf("packets=%d want 1", len(packets))
	}
	if packets[0].L4.Protocol != "udp" {
		t.Fatalf("protocol=%q want udp", packets[0].L4.Protocol)
	}
}

func TestPlannerRejectsNoEvents(t *testing.T) {
	cfg := testConfig()
	cfg.Events = nil
	_, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 646, LDP: cfg})
	if err == nil || !strings.Contains(err.Error(), "event") {
		t.Fatalf("err=%v want event error", err)
	}
}

func TestPlannerRejectsUnknownCarrier(t *testing.T) {
	cfg := testConfig()
	cfg.Carrier = "raw"
	cfg.Events = []core.LDPEvent{{Kind: "hello", Direction: "c2s", MessageID: 1}}
	_, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 646, DstPort: 646, LDP: cfg})
	if err == nil || !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("err=%v want carrier error", err)
	}
}

func TestPlannerRejectsUnknownEventKind(t *testing.T) {
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{{Kind: "bogus", Direction: "c2s", MessageID: 1}}
	_, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 646, LDP: cfg})
	if err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("err=%v want bogus error", err)
	}
}

func TestPlannerRejectsMissingFEC(t *testing.T) {
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{
		{Kind: "initialization", Direction: "c2s", MessageID: 10, LSRID: "192.0.2.1", ReceiverLSRID: "192.0.2.2"},
		{Kind: "initialization", Direction: "s2c", MessageID: 20, LSRID: "192.0.2.2", ReceiverLSRID: "192.0.2.1"},
		{Kind: "label_mapping", Direction: "c2s", MessageID: 13, FEC: "", Label: 100},
	}
	_, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 646, LDP: cfg})
	if err == nil || !strings.Contains(err.Error(), "FEC") {
		t.Fatalf("err=%v want FEC error", err)
	}
}

func TestPlannerRejectsInvalidFEC(t *testing.T) {
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{
		{Kind: "initialization", Direction: "c2s", MessageID: 10, LSRID: "192.0.2.1", ReceiverLSRID: "192.0.2.2"},
		{Kind: "initialization", Direction: "s2c", MessageID: 20, LSRID: "192.0.2.2", ReceiverLSRID: "192.0.2.1"},
		{Kind: "label_mapping", Direction: "c2s", MessageID: 13, FEC: "not-a-cidr", Label: 100},
	}
	_, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 646, LDP: cfg})
	if err == nil || !strings.Contains(err.Error(), "FEC") {
		t.Fatalf("err=%v want FEC error", err)
	}
}

func TestPlannerRejectsLabelOver20Bit(t *testing.T) {
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{
		{Kind: "initialization", Direction: "c2s", MessageID: 10, LSRID: "192.0.2.1", ReceiverLSRID: "192.0.2.2"},
		{Kind: "initialization", Direction: "s2c", MessageID: 20, LSRID: "192.0.2.2", ReceiverLSRID: "192.0.2.1"},
		{Kind: "label_mapping", Direction: "c2s", MessageID: 13, FEC: "203.0.113.0/24", Label: 1 << 20},
	}
	_, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 646, LDP: cfg})
	if err == nil || !strings.Contains(err.Error(), "label") {
		t.Fatalf("err=%v want label error", err)
	}
}

func TestPlannerRejectsPrefixOver32(t *testing.T) {
	// IPv4 has no /33 prefix; net.ParseCIDR rejects it and the planner surfaces
	// the FEC error instead of emitting a malformed PDU.
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{
		{Kind: "initialization", Direction: "c2s", MessageID: 10, LSRID: "192.0.2.1", ReceiverLSRID: "192.0.2.2"},
		{Kind: "initialization", Direction: "s2c", MessageID: 20, LSRID: "192.0.2.2", ReceiverLSRID: "192.0.2.1"},
		{Kind: "label_request", Direction: "c2s", MessageID: 13, FEC: "203.0.113.0/33"},
	}
	_, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 50000, DstPort: 646, LDP: cfg})
	if err == nil {
		t.Fatal("invalid /33 FEC accepted")
	}
}

func TestPlannerRejectsUnknownCarrierValue(t *testing.T) {
	cfg := testConfig()
	cfg.Carrier = "bogus_carrier"
	cfg.Events = []core.LDPEvent{{Kind: "hello", Direction: "c2s", MessageID: 1}}
	_, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 646, DstPort: 646, LDP: cfg})
	if err == nil || !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("err=%v want carrier error", err)
	}
}

func TestPlannerRejectsUnknownEventDirection(t *testing.T) {
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{{Kind: "hello", Direction: "invalid", MessageID: 1}}
	_, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 646, DstPort: 646, LDP: cfg})
	if err == nil || !strings.Contains(err.Error(), "direction") {
		t.Fatalf("err=%v want direction error", err)
	}
}

func TestPlannerRejectsUnknownLabelAdvertisement(t *testing.T) {
	cfg := testConfig()
	cfg.LabelAdvertisement = "bogus"
	cfg.Events = []core.LDPEvent{{Kind: "hello", Direction: "c2s", MessageID: 1}}
	_, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 646, DstPort: 646, LDP: cfg})
	if err == nil || !strings.Contains(err.Error(), "label advertisement") {
		t.Fatalf("err=%v want label advertisement error", err)
	}
}

func TestPlannerInitWithKeepalive(t *testing.T) {
	// S2: init + keepalive
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{
		{Kind: "initialization", Direction: "c2s", MessageID: 10, LSRID: "192.0.2.1", ReceiverLSRID: "192.0.2.2"},
		{Kind: "initialization", Direction: "s2c", MessageID: 20, LSRID: "192.0.2.2", ReceiverLSRID: "192.0.2.1"},
		{Kind: "keepalive", Direction: "c2s", MessageID: 11},
		{Kind: "keepalive", Direction: "s2c", MessageID: 21},
	}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 50000, DstPort: 646, LDP: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	// 3 handshake + 4 events + 4 teardown = 11
	if len(packets) != 11 {
		t.Fatalf("packets=%d want 11", len(packets))
	}
}

func TestPlannerAddress(t *testing.T) {
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{
		{Kind: "initialization", Direction: "c2s", MessageID: 10, LSRID: "192.0.2.1", ReceiverLSRID: "192.0.2.2"},
		{Kind: "initialization", Direction: "s2c", MessageID: 20, LSRID: "192.0.2.2", ReceiverLSRID: "192.0.2.1"},
		{Kind: "address", Direction: "c2s", MessageID: 12, Addresses: []string{"192.0.2.1"}},
	}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 50000, DstPort: 646, LDP: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	// 3 + 3 + 4 = 10
	if len(packets) != 10 {
		t.Fatalf("packets=%d want 10", len(packets))
	}
}

func TestPlannerLabelMappingWithdraw(t *testing.T) {
	// S6: init + label_mapping + label_withdraw
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{
		{Kind: "initialization", Direction: "c2s", MessageID: 10, LSRID: "192.0.2.1", ReceiverLSRID: "192.0.2.2"},
		{Kind: "initialization", Direction: "s2c", MessageID: 20, LSRID: "192.0.2.2", ReceiverLSRID: "192.0.2.1"},
		{Kind: "label_mapping", Direction: "c2s", MessageID: 13, FEC: "203.0.113.0/24", Label: 74565},
		{Kind: "label_withdraw", Direction: "c2s", MessageID: 14, FEC: "203.0.113.0/24", Label: 74565},
	}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 50000, DstPort: 646, LDP: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	// 3 + 4 + 4 = 11
	if len(packets) != 11 {
		t.Fatalf("packets=%d want 11", len(packets))
	}
}

func TestPlannerNotification(t *testing.T) {
	// S11: init + notification
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{
		{Kind: "initialization", Direction: "c2s", MessageID: 10, LSRID: "192.0.2.1", ReceiverLSRID: "192.0.2.2"},
		{Kind: "initialization", Direction: "s2c", MessageID: 20, LSRID: "192.0.2.2", ReceiverLSRID: "192.0.2.1"},
		{Kind: "notification", Direction: "s2c", MessageID: 22, StatusCode: 1},
	}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 50000, DstPort: 646, LDP: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	// 3 + 3 + 4 = 10
	if len(packets) != 10 {
		t.Fatalf("packets=%d want 10", len(packets))
	}
}

func TestPlannerDownstreamOnDemand(t *testing.T) {
	// S12: downstream-on-demand, label_request + label_mapping
	cfg := testConfig()
	cfg.LabelAdvertisement = "downstream_on_demand"
	cfg.Events = []core.LDPEvent{
		{Kind: "initialization", Direction: "c2s", MessageID: 10, LSRID: "192.0.2.1", ReceiverLSRID: "192.0.2.2"},
		{Kind: "initialization", Direction: "s2c", MessageID: 20, LSRID: "192.0.2.2", ReceiverLSRID: "192.0.2.1"},
		{Kind: "label_request", Direction: "c2s", MessageID: 13, FEC: "203.0.113.0/24"},
		{Kind: "label_mapping", Direction: "s2c", MessageID: 23, FEC: "203.0.113.0/24", Label: 74565},
	}
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 50000, DstPort: 646, LDP: cfg})
	if err != nil {
		t.Fatal(err)
	}
	var packets []core.PacketConfig
	for p := range ch {
		packets = append(packets, p)
	}
	// 3 + 4 + 4 = 11
	if len(packets) != 11 {
		t.Fatalf("packets=%d want 11", len(packets))
	}
}

func TestGeneratorEmitsEvents(t *testing.T) {
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{
		{Kind: "initialization", Direction: "c2s", MessageID: 10, LSRID: "192.0.2.1", ReceiverLSRID: "192.0.2.2"},
		{Kind: "initialization", Direction: "s2c", MessageID: 20, LSRID: "192.0.2.2", ReceiverLSRID: "192.0.2.1"},
		{Kind: "keepalive", Direction: "c2s", MessageID: 11},
		{Kind: "keepalive", Direction: "s2c", MessageID: 21},
	}
	var events []layers.MessageEvent
	err := (&LDPGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{LDP: cfg},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("events=%d want 4", len(events))
	}
	// Check alternating directions
	for i, ev := range events {
		wantUp := i%2 == 0
		if ev.Up != wantUp {
			t.Fatalf("event %d direction=%v want up=%v", i, ev.Up, wantUp)
		}
	}
	// Check all have payloads
	for i, ev := range events {
		if len(ev.Bytes) == 0 {
			t.Fatalf("event %d has empty payload", i)
		}
	}
}

func TestGeneratorRejectsNilConfig(t *testing.T) {
	err := (&LDPGenerator{}).Generate(context.Background(), nil)
	if err == nil {
		t.Fatal("nil request accepted")
	}
}

func TestGeneratorRejectsNilEmitMsg(t *testing.T) {
	err := (&LDPGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta:    layers.FlowMeta{LDP: testConfig()},
		EmitMsg: nil,
	})
	if err == nil || !strings.Contains(err.Error(), "EmitMsg") {
		t.Fatalf("err=%v want EmitMsg error", err)
	}
}

func TestResolveFEC(t *testing.T) {
	prefix, pl, err := resolveFEC("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if prefix != "203.0.113.0" {
		t.Fatalf("prefix=%q want 203.0.113.0", prefix)
	}
	if pl != 24 {
		t.Fatalf("pl=%d want 24", pl)
	}
}

func TestResolveFECInvalid(t *testing.T) {
	_, _, err := resolveFEC("not-a-cidr")
	if err == nil {
		t.Fatal("expected error for invalid FEC")
	}
}

func TestResolveFECPrefixOver32(t *testing.T) {
	_, _, err := resolveFEC("203.0.113.0/33")
	if err == nil {
		t.Fatal("expected error for prefix > 32")
	}
}

func TestGenericLabelBounds(t *testing.T) {
	// Generic Label TLV value: 4-byte big-endian label word per RFC 5036
	// (case S4/S8: label 0x12345/0xabcde serialized as-is, not shifted).
	tlv := BuildGenericLabelTLV(0xABCDE)
	val := uint32(tlv[4])<<24 | uint32(tlv[5])<<16 | uint32(tlv[6])<<8 | uint32(tlv[7])
	if val != 0xABCDE {
		t.Fatalf("label value=0x%08x want 0xABC DE", val)
	}
}

func TestBuildFECTLV(t *testing.T) {
	tlv := BuildFECTLV("203.0.113.0", 24)
	// TLV type=0x0100, len=7, fec_type=2, af(2 bytes)=0001, prefix_len=24, prefix=cb0071
	if len(tlv) != 11 {
		t.Fatalf("len=%d want 11", len(tlv))
	}
	if tlv[2] != 0 || tlv[3] != 7 {
		t.Fatalf("tlv len=%d,%d want 0,7", tlv[2], tlv[3])
	}
	if tlv[4] != 2 {
		t.Fatalf("fec type=%d want 2", tlv[4])
	}
	if tlv[5] != 0 || tlv[6] != 1 {
		t.Fatalf("af bytes=%02x%02x want 0001", tlv[5], tlv[6])
	}
	if tlv[7] != 24 {
		t.Fatalf("prefix_len=%d want 24", tlv[7])
	}
}

func TestValidateConfig(t *testing.T) {
	// Valid config
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{{Kind: "hello", Direction: "c2s", MessageID: 1, HoldTime: 15}}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestValidateConfigNil(t *testing.T) {
	if err := ValidateConfig(nil); err == nil {
		t.Fatal("nil config accepted")
	}
}

func TestValidateConfigNoEvents(t *testing.T) {
	cfg := testConfig()
	cfg.Events = nil
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("no events accepted")
	}
}

func TestValidateConfigUnknownKind(t *testing.T) {
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{{Kind: "bogus", Direction: "c2s", MessageID: 1}}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("unknown kind accepted")
	}
}

func TestNormalizeLDPConfig(t *testing.T) {
	cfg := &core.LDPConfig{}
	normalizeLDPConfig(cfg)
	if cfg.LSRID != "192.0.2.1" {
		t.Fatalf("LSRID=%q", cfg.LSRID)
	}
	if cfg.HoldTime != 15 {
		t.Fatalf("HoldTime=%d", cfg.HoldTime)
	}
	if cfg.KeepaliveTime != 30 {
		t.Fatalf("KeepaliveTime=%d", cfg.KeepaliveTime)
	}
	if cfg.LabelAdvertisement != "downstream_unsolicited" {
		t.Fatalf("LabelAdvertisement=%q", cfg.LabelAdvertisement)
	}
}

// --- T4.5 ldp 校验补全回归测试 ---

func TestValidateRejectsKeepaliveBeforeInit(t *testing.T) {
	// neg_state: a KeepAlive first event (no prior Initialization) is an invalid
	// RFC 5036 §2.5.4 session state and must be rejected.
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{testEvent("keepalive", "c2s", 1)}
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("err=%v want keepalive-before-init rejection", err)
	}
}

func TestValidateAcceptsKeepaliveAfterInit(t *testing.T) {
	// KeepAlive AFTER an Initialization is a valid state sequence.
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{
		testEvent("initialization", "c2s", 10),
		testEvent("initialization", "s2c", 20),
		testEvent("keepalive", "c2s", 11),
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("err=%v want nil", err)
	}
}

func TestValidateRejectsUDPDiscoveryNon646Port(t *testing.T) {
	// neg_port: UDP discovery hellos must use source port 646 (RFC 5036 §2.5.2).
	cfg := testConfig()
	cfg.Carrier = "udp_discovery"
	cfg.Events = []core.LDPEvent{testEvent("hello", "c2s", 1)}
	if err := (Planner{}).Validate(core.FlowSpec{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 645, LDP: cfg}); err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("err=%v want udp_discovery 646 port rejection", err)
	}
	if err := (Planner{}).Validate(core.FlowSpec{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 646, LDP: cfg}); err != nil {
		t.Fatalf("646 port err=%v want nil", err)
	}
}

func TestValidateRejectsPrefixOver32(t *testing.T) {
	// neg_prefix_bounds: a /33 FEC must be rejected with a "prefix" error at
	// validation time (not deferred to "planner produced 0 packet configs").
	cfg := testConfig()
	cfg.Events = []core.LDPEvent{
		testEvent("initialization", "c2s", 10),
		testEvent("initialization", "s2c", 20),
		{Kind: "label_request", Direction: "c2s", MessageID: 13, FEC: "203.0.113.0/33"},
	}
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "prefix") {
		t.Fatalf("err=%v want prefix-out-of-range rejection", err)
	}
}

func TestValidateRejectsChecksumFaultKind(t *testing.T) {
	// neg_checksum: fault_kind=checksum is a recognized injection kind and must
	// be rejected (fault injection forces validation failure).
	cfg := testConfig()
	cfg.Carrier = "udp_discovery"
	cfg.FaultKind = "checksum"
	cfg.Events = []core.LDPEvent{testEvent("hello", "c2s", 1)}
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("err=%v want checksum fault rejection", err)
	}
}

func TestValidateRejectsIPv6WithIPv4Profile(t *testing.T) {
	// neg_ipv6_profile: IPv6 transport + IPv4 basic profile must be rejected,
	// not silently mixed.
	cfg := testConfig()
	cfg.WireProfile = "ldp_rfc5036_ipv4_basic"
	cfg.Events = []core.LDPEvent{
		{Kind: "initialization", Direction: "c2s", MessageID: 10, LSRID: "2001:db8::1", ReceiverLSRID: "2001:db8::2"},
	}
	if err := (Planner{}).Validate(core.FlowSpec{SrcIP: "2001:db8::1", DstIP: "2001:db8::2", LDP: cfg}); err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("err=%v want IPv6+IPv4-profile rejection", err)
	}
}

func TestBuildNotificationStatusTLVTenBytes(t *testing.T) {
	// notification: Status TLV value must be exactly 10 bytes (Status Code 4 +
	// Message ID 4 + Message Type 2) per RFC 5036 §3.5.3.1; tshark rejects any
	// other length.
	body := BuildNotification(10, 0, 0)
	if len(body) != 14 { // tlv hdr (4) + 10
		t.Fatalf("status tlv len=%d want 14", len(body))
	}
	if got := uint16(body[2])<<8 | uint16(body[3]); got != 10 {
		t.Fatalf("status tlv length field=%d want 10", got)
	}
}
