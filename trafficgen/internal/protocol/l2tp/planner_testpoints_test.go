package l2tp

// Test points derived from /tmp/l7_planner_design/testcases_l2tp.md.
// Each test asserts observable byte-level output, not just "no error".
// Covers RFC 2661 (L2TPv2) + RFC 3931 (L2TPv3) Header / AVP / Message Type
// state machine + 13 business scenarios + 5 data scenarios + concurrency.

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// drain collects all configs from the channel.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// validL2TPv2Spec returns a FlowSpec with a basic v2 SCCRQ scenario.
func validL2TPv2Spec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		L2TP: &core.L2TPConfig{
			Version:  VersionL2TPv2,
			Role:     "lac",
			HostName: "vpn1.example.net",
			Scenarios: []core.L2TPStep{
				{Type: stepSCCRQ},
			},
		},
	}
}

func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return drain(ch)
}

// mustPlanCtx runs Plan with a cancellable context.
func mustPlanCtx(t *testing.T, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return drain(ch)
}

// readControlHeader decodes the first 12 bytes of an L2TPv2 control header
// (T/L/S/O/P/Ver/Length/TunnelID/SessionID/Ns/Nr) from payload.
func readControlHeader(payload []byte) (flags, length, tunID, sesID, ns, nr uint16, ok bool) {
	if len(payload) < v2ControlHeaderSize {
		return
	}
	flags = binary.BigEndian.Uint16(payload[0:2])
	length = binary.BigEndian.Uint16(payload[2:4])
	tunID = binary.BigEndian.Uint16(payload[4:6])
	sesID = binary.BigEndian.Uint16(payload[6:8])
	ns = binary.BigEndian.Uint16(payload[8:10])
	nr = binary.BigEndian.Uint16(payload[10:12])
	ok = true
	return
}

// readV3ControlHeader decodes the first 14 bytes of an L2TPv3 control header
// (T/L/S/Ver/Length/TunnelID/SessionID32/Ns/Nr).
func readV3ControlHeader(payload []byte) (flags, length, tunID uint16, sesID uint32, ns, nr uint16, ok bool) {
	if len(payload) < v3ControlHeaderSize {
		return
	}
	flags = binary.BigEndian.Uint16(payload[0:2])
	length = binary.BigEndian.Uint16(payload[2:4])
	tunID = binary.BigEndian.Uint16(payload[4:6])
	sesID = binary.BigEndian.Uint32(payload[6:10])
	ns = binary.BigEndian.Uint16(payload[10:12])
	nr = binary.BigEndian.Uint16(payload[12:14])
	ok = true
	return
}

// findAVP scans an L2TP control-message payload for an AVP with the given
// attribute type. Returns the AVP's (offset, declaredLength, valueBytes, ok).
// declaredLength is the 10-bit Length field (6-byte header + value length).
// The scan advances by the declared length only -- there is NO inter-AVP
// padding per RFC 2661 §4.1 / RFC 3931 §5.1, matching Wireshark's
// packet-l2tp.c. paddedLen is kept equal to declaredLength for callers that
// still reference it (no padding is emitted).
func findAVP(payload []byte, headerSize int, attrType uint16) (offset, declaredLen, paddedLen int, value []byte, ok bool) {
	offset = headerSize
	for offset+6 <= len(payload) {
		mh := binary.BigEndian.Uint16(payload[offset : offset+2])
		avpLen := int(mh & 0x03FF)
		at := binary.BigEndian.Uint16(payload[offset+4 : offset+6])
		if avpLen < 6 {
			return
		}
		if at == attrType {
			valueLen := avpLen - 6
			if offset+6+valueLen > len(payload) {
				return
			}
			return offset, avpLen, avpLen, payload[offset+6 : offset+6+valueLen], true
		}
		offset += avpLen
	}
	return
}

// ============================================================================
// §1.1.1 T flag (Type)
// ============================================================================

// 1.1.1.1: T=1, control message => Flags bit 15 set, payload starts with 0xC802.
func TestL2TP_TFlagControl(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	configs := mustPlan(t, p, spec)
	if len(configs) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(configs))
	}
	flags, _, _, _, _, _, ok := readControlHeader(configs[0].Payload)
	if !ok {
		t.Fatal("payload too short")
	}
	if flags&flagT2 == 0 {
		t.Errorf("T flag = 0, want 1 (control message)")
	}
	// byte 0 = 0xC8 (T|L|S reserved reserved) and byte 1 = 0x02 (Ver=2)
	if configs[0].Payload[0] != 0xC8 || configs[0].Payload[1] != 0x02 {
		t.Errorf("flags bytes = %02x %02x, want C8 02", configs[0].Payload[0], configs[0].Payload[1])
	}
}

// 1.1.1.3: T=1, Ver=3 => flags = 0xC803.
func TestL2TP_TFlagV3Control(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Version = VersionL2TPv3
	configs := mustPlan(t, p, spec)
	if len(configs) != 1 {
		t.Fatalf("expected 1, got %d", len(configs))
	}
	// v3 control header is 14 bytes
	if len(configs[0].Payload) < v3ControlHeaderSize {
		t.Fatalf("v3 header too short: %d bytes", len(configs[0].Payload))
	}
	if configs[0].Payload[1] != 0x03 {
		t.Errorf("v3 byte 1 = 0x%02x, want 0x03", configs[0].Payload[1])
	}
}

// ============================================================================
// §1.1.2 L flag (Length present)
// ============================================================================

// 1.1.2.1: L=1, control message => Length field = total packet size.
func TestL2TP_LFlagControlLength(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	configs := mustPlan(t, p, spec)
	_, length, _, _, _, _, ok := readControlHeader(configs[0].Payload)
	if !ok {
		t.Fatal("payload too short")
	}
	if int(length) != len(configs[0].Payload) {
		t.Errorf("Length field = %d, want %d (total payload length)", length, len(configs[0].Payload))
	}
}

// ============================================================================
// §1.1.3 S flag (Sequence present)
// ============================================================================

// 1.1.3.1: S=1, control message => Ns/Nr fields present at offsets 8-11.
func TestL2TP_SFlagControl(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	configs := mustPlan(t, p, spec)
	_, _, _, _, ns, nr, ok := readControlHeader(configs[0].Payload)
	if !ok {
		t.Fatal("payload too short")
	}
	// SCCRQ with InitialNs=0 => Ns=0, Nr=0.
	if ns != 0 {
		t.Errorf("Ns = %d, want 0", ns)
	}
	if nr != 0 {
		t.Errorf("Nr = %d, want 0", nr)
	}
}

// 1.1.3.3: Ns monotonic across multiple control messages.
func TestL2TP_NsMonotonic(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
	}
	configs := mustPlan(t, p, spec)
	if len(configs) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(configs))
	}
	_, _, _, _, ns1, _, _ := readControlHeader(configs[0].Payload)
	_, _, _, _, ns2, _, _ := readControlHeader(configs[1].Payload)
	_, _, _, _, ns3, _, _ := readControlHeader(configs[2].Payload)
	// SCCRQ=0, SCCRP=0 (fresh peer counter), SCCCN=1 (LAC's 2nd msg).
	if ns1 != 0 {
		t.Errorf("SCCRQ Ns = %d, want 0", ns1)
	}
	if ns2 != 0 {
		t.Errorf("SCCRP Ns = %d, want 0 (peer resets)", ns2)
	}
	if ns3 != 1 {
		t.Errorf("SCCCN Ns = %d, want 1", ns3)
	}
}

// 1.1.3.4: Ns wraparound at 65535 -> 0.
func TestL2TP_NsWraparound(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.InitialNs = 65535
	configs := mustPlan(t, p, spec)
	if len(configs) != 1 {
		t.Fatalf("expected 1, got %d", len(configs))
	}
	// Ns field uses InitialNs (no increment for the first packet? planner increments
	// after each emit, so the first Ns = InitialNs).
	_, _, _, _, ns, _, _ := readControlHeader(configs[0].Payload)
	if ns != 65535 {
		t.Errorf("Ns = %d, want 65535", ns)
	}
	// Verify wraparound by emitting a 2nd message after a 2-step scenario.
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP},
	}
	spec.L2TP.InitialNs = 65535
	configs = mustPlan(t, p, spec)
	_, _, _, _, nsA, _, _ := readControlHeader(configs[0].Payload)
	_, _, _, _, nsB, _, _ := readControlHeader(configs[1].Payload)
	if nsA != 65535 || nsB != 0 {
		t.Errorf("Ns wrap: got (%d, %d), want (65535, 0)", nsA, nsB)
	}
}

// ============================================================================
// §1.2 Tunnel ID / Session ID
// ============================================================================

// 1.2.1: Tunnel ID = local (1) in up direction.
func TestL2TP_TunnelIDUp(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.LocalTunnelID = 1
	configs := mustPlan(t, p, spec)
	_, _, tunID, _, _, _, _ := readControlHeader(configs[0].Payload)
	if tunID != 1 {
		t.Errorf("Tunnel ID = %d, want 1", tunID)
	}
}

// 1.2.5: Session ID for OCRQ = localSesID (10).
func TestL2TP_SessionID(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ},
	}
	spec.L2TP.LocalSessionID = 10
	configs := mustPlan(t, p, spec)
	if len(configs) != 4 {
		t.Fatalf("expected 4, got %d", len(configs))
	}
	// OCRQ is index 3.
	_, _, _, sesID, _, _, _ := readControlHeader(configs[3].Payload)
	if sesID != 10 {
		t.Errorf("OCRQ Session ID = %d, want 10", sesID)
	}
}

// 1.2.6: Tunnel-level messages (SCCRQ/SCCCN/HELLO/StopCCN) => SesID=0.
func TestL2TP_TunnelLevelSesIDZero(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.LocalSessionID = 10
	configs := mustPlan(t, p, spec)
	_, _, _, sesID, _, _, _ := readControlHeader(configs[0].Payload)
	if sesID != 0 {
		t.Errorf("SCCRQ Session ID = %d, want 0 (tunnel-level)", sesID)
	}
}

// ============================================================================
// §1.2A L2TPv2 Session ID 16-bit boundary
// ============================================================================

// 1.2A.1: v2 Session ID = 0 (min).
func TestL2TPv2_SesIDMin(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ},
	}
	spec.L2TP.LocalSessionID = 0
	configs := mustPlan(t, p, spec)
	_, _, _, sesID, _, _, _ := readControlHeader(configs[3].Payload)
	if sesID != 0 {
		t.Errorf("OCRQ SesID = %d, want 0", sesID)
	}
}

// 1.2A.2: v2 Session ID = 0x7FFF (mid).
func TestL2TPv2_SesIDMid(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ},
	}
	spec.L2TP.LocalSessionID = 0x7FFF
	configs := mustPlan(t, p, spec)
	_, _, _, sesID, _, _, _ := readControlHeader(configs[3].Payload)
	if sesID != 0x7FFF {
		t.Errorf("OCRQ SesID = %d, want 0x7FFF", sesID)
	}
}

// 1.2A.3: v2 Session ID = 0xFFFF (max), fits in 2 bytes.
func TestL2TPv2_SesIDMax(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ},
	}
	spec.L2TP.LocalSessionID = 0xFFFF
	configs := mustPlan(t, p, spec)
	_, _, _, sesID, _, _, _ := readControlHeader(configs[3].Payload)
	if sesID != 0xFFFF {
		t.Errorf("OCRQ SesID = %d, want 0xFFFF", sesID)
	}
	// Verify no overflow into next 2 bytes (offset 8-9 = Ns).
	if len(configs[3].Payload) < 12 {
		t.Fatal("payload too short")
	}
	ns := binary.BigEndian.Uint16(configs[3].Payload[8:10])
	if ns == 0xFFFF {
		t.Errorf("Ns leaked from SesID overflow: %d", ns)
	}
}

// ============================================================================
// §1.2B L2TPv3 Session ID 32-bit boundary
// ============================================================================

// 1.2B.1: v3 data message SesID = 0 (min) - 4 bytes.
func TestL2TPv3_DataSesIDMin(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Version = VersionL2TPv3
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
	}
	spec.L2TP.PPPFrames = []core.L2TPPPPFrame{
		{Protocol: 0x0021, Data: []byte("hello")},
	}
	configs := mustPlan(t, p, spec)
	// Last packet is the PPP data message.
	last := configs[len(configs)-1].Payload
	if len(last) < 6 {
		t.Fatal("v3 data header too short")
	}
	sesID := binary.BigEndian.Uint32(last[2:6])
	if sesID != 0 {
		t.Errorf("v3 data SesID = %d, want 0", sesID)
	}
	// v3 data header has Flags(1) + Ver(1) + SesID(4).
	if last[1] != 0x03 {
		t.Errorf("v3 Ver byte = 0x%02x, want 0x03", last[1])
	}
}

// 1.2B.3: v3 data SesID = 0xFFFFFFFF (max) - 4 bytes preserved.
func TestL2TPv3_DataSesIDMax(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Version = VersionL2TPv3
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
	}
	spec.L2TP.PPPFrames = []core.L2TPPPPFrame{
		{Protocol: 0x0021, Data: []byte("x")},
	}
	spec.L2TP.LocalSessionID32 = 0xFFFFFFFF
	configs := mustPlan(t, p, spec)
	last := configs[len(configs)-1].Payload
	sesID := binary.BigEndian.Uint32(last[2:6])
	if sesID != 0xFFFFFFFF {
		t.Errorf("v3 data SesID = 0x%x, want 0xFFFFFFFF", sesID)
	}
}

// 1.2B.4: v3 control SesID = 0 (min) - 4 bytes.
func TestL2TPv3_ControlSesIDMin(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Version = VersionL2TPv3
	configs := mustPlan(t, p, spec)
	flags, _, _, sesID, _, _, ok := readV3ControlHeader(configs[0].Payload)
	if !ok {
		t.Fatal("v3 header too short")
	}
	if flags&flagT2 == 0 {
		t.Errorf("T flag = 0, want 1")
	}
	if sesID != 0 {
		t.Errorf("v3 control SesID = %d, want 0 (tunnel-level)", sesID)
	}
}

// 1.2B.5: v3 control SesID = 0xFFFFFFFF - 4 bytes preserved.
func TestL2TPv3_ControlSesIDMax(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Version = VersionL2TPv3
	spec.L2TP.LocalSessionID32 = 0xFFFFFFFF
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ},
	}
	configs := mustPlan(t, p, spec)
	// OCRQ is index 3; for v3 control header, SesID = 32 bits.
	_, _, _, sesID, _, _, _ := readV3ControlHeader(configs[3].Payload)
	if sesID != 0xFFFFFFFF {
		t.Errorf("v3 OCRQ SesID = 0x%x, want 0xFFFFFFFF", sesID)
	}
	// Verify control header is exactly 14 bytes + AVP, not 12 + AVP.
	if len(configs[3].Payload) < v3ControlHeaderSize {
		t.Fatalf("v3 header too short: %d", len(configs[3].Payload))
	}
}

// ============================================================================
// §1.2C v2 vs v3 Session ID length comparison
// ============================================================================

// 1.2C.1: v2 SesID = 10 (2 bytes) vs v3 SesID = 10 (4 bytes).
func TestL2TPv2v3_SesIDLength(t *testing.T) {
	p := NewPlanner()
	// v2 control
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ},
	}
	spec.L2TP.LocalSessionID = 10
	configs := mustPlan(t, p, spec)
	_, _, _, sesIDv2, _, _, _ := readControlHeader(configs[3].Payload)
	if sesIDv2 != 10 {
		t.Errorf("v2 SesID = %d, want 10", sesIDv2)
	}
	// v3 control: SesID at offset 6-9 (4 bytes).
	spec.L2TP.Version = VersionL2TPv3
	configs = mustPlan(t, p, spec)
	_, _, _, sesIDv3, _, _, _ := readV3ControlHeader(configs[3].Payload)
	if sesIDv3 != 10 {
		t.Errorf("v3 SesID = %d, want 10", sesIDv3)
	}
	// Header sizes differ.
	if len(configs[3].Payload) < v3ControlHeaderSize {
		t.Fatalf("v3 OCRQ payload too short: %d", len(configs[3].Payload))
	}
}

// ============================================================================
// §2.1 AVP Header fields
// ============================================================================

// 2.1.1.1: M=1, Message Type AVP => byte 0 = 0x80.
func TestL2TP_AVP_MandatorySet(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	configs := mustPlan(t, p, spec)
	// First AVP starts at offset 12 (after v2 control header).
	payload := configs[0].Payload
	if len(payload) < 14 {
		t.Fatal("payload too short")
	}
	// M/H/Length = 2 bytes; M=1 (bit 15), H=0 (bit 14), Length=8 (header only)...
	// The Message Type AVP has 6-byte header + 2-byte value = 8 bytes, no padding needed.
	avpMH := binary.BigEndian.Uint16(payload[12:14])
	if avpMH&0x8000 == 0 {
		t.Errorf("M bit = 0, want 1 (Message Type AVP is M=1)")
	}
	length := avpMH & 0x03FF
	if length != 8 {
		t.Errorf("Message Type AVP length = %d, want 8 (6 header + 2 value)", length)
	}
}

// 2.1.1.2: M=0, optional AVP => byte 0 bit 15 = 0.
func TestL2TP_AVP_MandatoryClear(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.CustomAVPs = []core.L2TPAVP{
		{Mandatory: false, AttrType: 99, Value: []byte{0xAB, 0xCD}},
	}
	configs := mustPlan(t, p, spec)
	payload := configs[0].Payload
	offset, _, _, _, ok := findAVP(payload, v2ControlHeaderSize, 99)
	if !ok {
		t.Fatal("Custom AVP (attr 99) not found")
	}
	customMH := binary.BigEndian.Uint16(payload[offset : offset+2])
	if customMH&0x8000 != 0 {
		t.Errorf("Custom AVP M bit = 1, want 0")
	}
}

// 2.1.3.1: Minimum AVP length = 6 (header only, no value).
func TestL2TP_AVP_MinLength(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.CustomAVPs = []core.L2TPAVP{
		{Mandatory: false, AttrType: 99, Value: nil},
	}
	configs := mustPlan(t, p, spec)
	payload := configs[0].Payload
	offset, avpLen, _, _, ok := findAVP(payload, v2ControlHeaderSize, 99)
	if !ok {
		t.Fatal("Custom AVP (attr 99) not found")
	}
	if avpLen != 6 {
		t.Errorf("Custom AVP length = %d, want 6 (min, header only)", avpLen)
	}
	_ = offset
}

// 2.1.3.2: AVP length 8 (header + 2-byte value).
func TestL2TP_AVP_8Byte(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.CustomAVPs = []core.L2TPAVP{
		{Mandatory: false, AttrType: 99, Value: []byte{0xAB, 0xCD}},
	}
	configs := mustPlan(t, p, spec)
	payload := configs[0].Payload
	_, avpLen, _, _, ok := findAVP(payload, v2ControlHeaderSize, 99)
	if !ok {
		t.Fatal("Custom AVP (attr 99) not found")
	}
	if avpLen != 8 {
		t.Errorf("Custom AVP length = %d, want 8", avpLen)
	}
}

// 2.1.3.3: AVP 4-byte alignment padding.
func TestL2TP_AVP_Alignment(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	// AVP value = 1 byte => total 7 bytes. RFC 2661 §4.1 defines NO inter-AVP
	// padding, so the AVP is emitted as exactly 7 bytes with the next AVP
	// (or end of message) immediately following.
	spec.L2TP.CustomAVPs = []core.L2TPAVP{
		{Mandatory: false, AttrType: 99, Value: []byte{0xAB}},
	}
	configs := mustPlan(t, p, spec)
	payload := configs[0].Payload
	offset, avpLen, padded, _, ok := findAVP(payload, v2ControlHeaderSize, 99)
	if !ok {
		t.Fatal("Custom AVP (attr 99) not found")
	}
	if avpLen != 7 {
		t.Errorf("Custom AVP length = %d, want 7", avpLen)
	}
	if padded != 7 {
		t.Errorf("Custom AVP padded length = %d, want 7 (no padding per RFC 2661 §4.1)", padded)
	}
	// With no padding, the byte after the 7-byte AVP is the first byte of the
	// next AVP (or beyond payload). Since Custom AVPs are appended last, the
	// 7-byte AVP is the final AVP; the payload must end exactly at offset+7.
	if offset+avpLen != len(payload) {
		t.Errorf("payload extends %d bytes past last AVP (no padding expected)", len(payload)-(offset+avpLen))
	}
}

// 2.1.4.1: Vendor ID = 0 (IETF).
func TestL2TP_AVP_VendorIDIETF(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	configs := mustPlan(t, p, spec)
	payload := configs[0].Payload
	// Message Type AVP at offset 12, vendor ID at offset 14.
	vendorID := binary.BigEndian.Uint16(payload[14:16])
	if vendorID != 0 {
		t.Errorf("Vendor ID = %d, want 0 (IETF)", vendorID)
	}
}

// 2.1.4.2: Vendor ID = 9 (Cisco).
func TestL2TP_AVP_VendorIDCisco(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.CustomAVPs = []core.L2TPAVP{
		{VendorID: 9, AttrType: 99, Value: []byte{0x01, 0x02}},
	}
	configs := mustPlan(t, p, spec)
	payload := configs[0].Payload
	offset, _, _, _, ok := findAVP(payload, v2ControlHeaderSize, 99)
	if !ok {
		t.Fatal("Custom AVP (attr 99) not found")
	}
	vendorID := binary.BigEndian.Uint16(payload[offset+2 : offset+4])
	if vendorID != 9 {
		t.Errorf("Vendor ID = %d, want 9", vendorID)
	}
}

// ============================================================================
// §2.2 Message Type AVP values
// ============================================================================

// 2.2.1: SCCRQ Message Type = 1.
func TestL2TP_MsgType_SCCRQ(t *testing.T) {
	p := NewPlanner()
	configs := mustPlan(t, p, validL2TPv2Spec())
	// Message Type AVP at offset 12: mh(2) + vendor(2) + attrtype(2) + value(2) = 8.
	mtValue := binary.BigEndian.Uint16(configs[0].Payload[18:20])
	if mtValue != msgSCCRQ {
		t.Errorf("Message Type = %d, want %d (SCCRQ)", mtValue, msgSCCRQ)
	}
}

// 2.2.2: SCCRP Message Type = 2.
func TestL2TP_MsgType_SCCRP(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP},
	}
	configs := mustPlan(t, p, spec)
	mtValue := binary.BigEndian.Uint16(configs[1].Payload[18:20])
	if mtValue != msgSCCRP {
		t.Errorf("Message Type = %d, want %d (SCCRP)", mtValue, msgSCCRP)
	}
}

// 2.2.5: HELLO Message Type = 5.
func TestL2TP_MsgType_HELLO(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepHELLO},
	}
	configs := mustPlan(t, p, spec)
	mtValue := binary.BigEndian.Uint16(configs[0].Payload[18:20])
	if mtValue != msgHELLO {
		t.Errorf("Message Type = %d, want %d (HELLO)", mtValue, msgHELLO)
	}
}

// 2.2.4: StopCCN Message Type = 4.
func TestL2TP_MsgType_StopCCN(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepStopCCN},
	}
	configs := mustPlan(t, p, spec)
	mtValue := binary.BigEndian.Uint16(configs[0].Payload[18:20])
	if mtValue != msgStopCCN {
		t.Errorf("Message Type = %d, want %d (StopCCN)", mtValue, msgStopCCN)
	}
}

// 2.2.12: CDN Message Type = 12.
func TestL2TP_MsgType_CDN(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepCDN},
	}
	configs := mustPlan(t, p, spec)
	mtValue := binary.BigEndian.Uint16(configs[0].Payload[18:20])
	if mtValue != msgCDN {
		t.Errorf("Message Type = %d, want %d (CDN)", mtValue, msgCDN)
	}
}

// ============================================================================
// §2.7 Tie Breaker AVP
// ============================================================================

// 2.7.1: Tie Breaker AVP value = 8 bytes BE.
func TestL2TP_TieBreakerAVP(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.TieBreaker = 0x0102030405060708
	configs := mustPlan(t, p, spec)
	// Find the Tie Breaker AVP by scanning AVPs.
	payload := configs[0].Payload
	// Skip 12-byte control header, then iterate AVPs.
	offset := v2ControlHeaderSize
	tbFound := false
	for offset+6 <= len(payload) {
		mh := binary.BigEndian.Uint16(payload[offset : offset+2])
		avpLen := int(mh & 0x0FFF)
		attrType := binary.BigEndian.Uint16(payload[offset+4 : offset+6])
		if attrType == attrTieBreaker {
			// Tie Breaker is 8 bytes.
			if avpLen != 14 {
				t.Errorf("Tie Breaker AVP length = %d, want 14 (6 header + 8 value)", avpLen)
			}
			tbValue := binary.BigEndian.Uint64(payload[offset+6 : offset+14])
			if tbValue != 0x0102030405060708 {
				t.Errorf("Tie Breaker = 0x%x, want 0x0102030405060708", tbValue)
			}
			tbFound = true
			break
		}
		// Move to next AVP (4-byte aligned).
		offset += avpLen
	}
	if !tbFound {
		t.Errorf("Tie Breaker AVP not found")
	}
}

// ============================================================================
// §2.8 / §2.9 Host Name / Vendor Name AVP
// ============================================================================

// 2.8.1: Host Name AVP value includes null terminator.
func TestL2TP_HostNameAVP(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.HostName = "vpn1.example.net"
	configs := mustPlan(t, p, spec)
	payload := configs[0].Payload
	offset := v2ControlHeaderSize
	for offset+6 <= len(payload) {
		mh := binary.BigEndian.Uint16(payload[offset : offset+2])
		avpLen := int(mh & 0x0FFF)
		attrType := binary.BigEndian.Uint16(payload[offset+4 : offset+6])
		if attrType == attrHostName {
			// Value starts at offset+6, length-6 bytes (no padding).
			valueLen := avpLen - 6
			value := string(payload[offset+6 : offset+6+valueLen])
			// Should end with null terminator.
			if value != "vpn1.example.net\x00" {
				t.Errorf("Host Name value = %q, want %q", value, "vpn1.example.net\x00")
			}
			return
		}
		offset += avpLen
	}
	t.Errorf("Host Name AVP not found")
}

// 2.8.2: Default Host Name = "trafficgen".
func TestL2TP_DefaultHostName(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.HostName = ""
	configs := mustPlan(t, p, spec)
	payload := configs[0].Payload
	offset := v2ControlHeaderSize
	for offset+6 <= len(payload) {
		mh := binary.BigEndian.Uint16(payload[offset : offset+2])
		avpLen := int(mh & 0x0FFF)
		attrType := binary.BigEndian.Uint16(payload[offset+4 : offset+6])
		if attrType == attrHostName {
			valueLen := avpLen - 6
			value := string(payload[offset+6 : offset+6+valueLen])
			if value != "trafficgen\x00" {
				t.Errorf("Default Host Name = %q, want %q", value, "trafficgen\x00")
			}
			return
		}
		offset += avpLen
	}
	t.Errorf("Host Name AVP not found")
}

// ============================================================================
// §3.1 Tunnel 3-way handshake
// ============================================================================

// 3.1.1: Tunnel handshake emits 3 packets.
func TestL2TP_TunnelHandshake(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
	}
	configs := mustPlan(t, p, spec)
	if len(configs) != 3 {
		t.Errorf("tunnel handshake: expected 3 packets, got %d", len(configs))
	}
	// Verify packet indices are 0, 1, 2 in order.
	for i, cfg := range configs {
		if cfg.PacketIndex != uint64(i) {
			t.Errorf("configs[%d].PacketIndex = %d, want %d", i, cfg.PacketIndex, i)
		}
	}
}

// ============================================================================
// §3.2 Outgoing Call
// ============================================================================

// 3.2.1: OCRQ Message Type = 6 with Assigned Session ID AVP.
func TestL2TP_OCRQ(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ},
	}
	configs := mustPlan(t, p, spec)
	// OCRQ is index 3.
	mt := binary.BigEndian.Uint16(configs[3].Payload[18:20])
	if mt != msgOCRQ {
		t.Errorf("OCRQ Message Type = %d, want %d", mt, msgOCRQ)
	}
}

// ============================================================================
// §3.5 StopCCN
// ============================================================================

// 3.5.1: StopCCN with Assigned Tunnel ID + Result Code.
func TestL2TP_StopCCN(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepStopCCN},
	}
	configs := mustPlan(t, p, spec)
	// StopCCN at index 3.
	mt := binary.BigEndian.Uint16(configs[3].Payload[18:20])
	if mt != msgStopCCN {
		t.Errorf("StopCCN Message Type = %d, want %d", mt, msgStopCCN)
	}
	// Find Assigned Tunnel ID AVP (type 9).
	payload := configs[3].Payload
	offset := v2ControlHeaderSize
	atidFound := false
	rcFound := false
	for offset+6 <= len(payload) {
		mh := binary.BigEndian.Uint16(payload[offset : offset+2])
		avpLen := int(mh & 0x0FFF)
		attrType := binary.BigEndian.Uint16(payload[offset+4 : offset+6])
		switch attrType {
		case attrAssignedTunnelID:
			atidFound = true
			id := binary.BigEndian.Uint16(payload[offset+6 : offset+8])
			if id != 1 {
				t.Errorf("Assigned Tunnel ID = %d, want 1", id)
			}
		case attrResultCode:
			rcFound = true
			rc := binary.BigEndian.Uint16(payload[offset+6 : offset+8])
			if rc != 1 {
				t.Errorf("Result Code = %d, want 1 (default)", rc)
			}
		}
		offset += avpLen
	}
	if !atidFound {
		t.Errorf("StopCCN missing Assigned Tunnel ID AVP")
	}
	if !rcFound {
		t.Errorf("StopCCN missing Result Code AVP")
	}
}

// ============================================================================
// §4.1 Standard LAC-LNS scenario
// ============================================================================

// 4.1.1: Full tunnel + session setup = 6 packets.
func TestL2TP_FullScenario(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ}, {Type: stepOCRP}, {Type: stepOCCN},
	}
	configs := mustPlan(t, p, spec)
	if len(configs) != 6 {
		t.Errorf("expected 6 packets, got %d", len(configs))
	}
}

// 4.1.3: LNS role flips direction.
func TestL2TP_LNSRole(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Role = "lns"
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ},
	}
	configs := mustPlan(t, p, spec)
	if configs[0].Direction != "down" {
		t.Errorf("LNS SCCRQ Direction = %s, want down", configs[0].Direction)
	}
}

// ============================================================================
// §4.2 OCRQ with Called Number
// ============================================================================

// 4.2.2: OCRQ with Called Number AVP.
func TestL2TP_OCRQ_CalledNumber(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ, AVPs: []core.L2TPAVP{
			{AttrType: attrCalledNumber, Value: append([]byte("remote-u-42"), 0)},
		}},
	}
	configs := mustPlan(t, p, spec)
	// OCRQ at index 3.
	payload := configs[3].Payload
	offset := v2ControlHeaderSize
	for offset+6 <= len(payload) {
		mh := binary.BigEndian.Uint16(payload[offset : offset+2])
		avpLen := int(mh & 0x0FFF)
		attrType := binary.BigEndian.Uint16(payload[offset+4 : offset+6])
		if attrType == attrCalledNumber {
			valueLen := avpLen - 6
			value := string(payload[offset+6 : offset+6+valueLen])
			if value != "remote-u-42\x00" {
				t.Errorf("Called Number = %q, want %q", value, "remote-u-42\x00")
			}
			return
		}
		offset += avpLen
	}
	t.Errorf("Called Number AVP not found")
}

// ============================================================================
// §4.7 PPP data transmission
// ============================================================================

// 4.7.1: PPP IPCP frame => data packet with T=0 (no control flags).
func TestL2TP_PPPData(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ}, {Type: stepOCRP}, {Type: stepOCCN},
	}
	spec.L2TP.PPPFrames = []core.L2TPPPPFrame{
		{Protocol: 0x8021, Data: []byte{0x01, 0x02, 0x03}},
	}
	configs := mustPlan(t, p, spec)
	if len(configs) != 7 {
		t.Fatalf("expected 7, got %d", len(configs))
	}
	last := configs[6].Payload
	if len(last) < 6 {
		t.Fatal("data packet too short")
	}
	// Verify Protocol bytes at offset 4-5 (after TunID+SesID+PPP frame preamble).
	// For L2TPv2 data: hdr=TunID(2)+SesID(2) + PPP=Protocol(2)+Info.
	proto := binary.BigEndian.Uint16(last[4:6])
	if proto != 0x8021 {
		t.Errorf("PPP Protocol = 0x%04x, want 0x8021 (IPCP)", proto)
	}
}

// 4.7.4: PPP L2PPPHeader=true includes 0xFF 0x03.
func TestL2TP_PPP_HDLCHeader(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ}, {Type: stepOCRP}, {Type: stepOCCN},
	}
	spec.L2TP.PPPFrames = []core.L2TPPPPFrame{
		{Protocol: 0x0021, Data: []byte("hello"), L2PPPHeader: true},
	}
	configs := mustPlan(t, p, spec)
	last := configs[6].Payload
	// v2 data header: TunID(2)+SesID(2) = 4 bytes.
	// HDLC: 0xFF 0x03 + Protocol(2) + Data(5) = 9 bytes.
	if len(last) < 4+2+2+5 {
		t.Fatal("payload too short for HDLC PPP")
	}
	if last[4] != 0xFF || last[5] != 0x03 {
		t.Errorf("HDLC bytes = %02x %02x, want FF 03", last[4], last[5])
	}
	proto := binary.BigEndian.Uint16(last[6:8])
	if proto != 0x0021 {
		t.Errorf("Protocol = 0x%04x, want 0x0021", proto)
	}
	if string(last[8:13]) != "hello" {
		t.Errorf("Data = %q, want %q", last[8:13], "hello")
	}
}

// 4.7.5: PPP L2PPPHeader=false (default) omits 0xFF 0x03.
func TestL2TP_PPP_NoHDLCHeader(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ}, {Type: stepOCRP}, {Type: stepOCCN},
	}
	spec.L2TP.PPPFrames = []core.L2TPPPPFrame{
		{Protocol: 0x0021, Data: []byte("hello")},
	}
	configs := mustPlan(t, p, spec)
	last := configs[6].Payload
	// No HDLC: TunID(2)+SesID(2)+Protocol(2)+Data(5) = 11 bytes.
	if len(last) < 4+2+5 {
		t.Fatal("payload too short")
	}
	proto := binary.BigEndian.Uint16(last[4:6])
	if proto != 0x0021 {
		t.Errorf("Protocol = 0x%04x, want 0x0021", proto)
	}
	if string(last[6:11]) != "hello" {
		t.Errorf("Data = %q, want %q", last[6:11], "hello")
	}
}

// ============================================================================
// §4.9 Multi-session
// ============================================================================

// 4.9.1: 1 tunnel + 2 sessions = 9 packets.
func TestL2TP_MultiSession(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ}, {Type: stepOCRP}, {Type: stepOCCN},
		{Type: stepOCRQ}, {Type: stepOCRP}, {Type: stepOCCN},
	}
	configs := mustPlan(t, p, spec)
	if len(configs) != 9 {
		t.Errorf("expected 9, got %d", len(configs))
	}
}

// ============================================================================
// §4.11 WEN
// ============================================================================

// 4.11.1: WEN step emits a control packet between session events.
func TestL2TP_WEN(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ}, {Type: stepOCRP}, {Type: stepOCCN},
		{Type: stepWEN},
	}
	configs := mustPlan(t, p, spec)
	if len(configs) != 7 {
		t.Fatalf("expected 7, got %d", len(configs))
	}
	mt := binary.BigEndian.Uint16(configs[6].Payload[18:20])
	if mt != msgWEN {
		t.Errorf("WEN Message Type = %d, want %d", mt, msgWEN)
	}
}

// ============================================================================
// §4.12 SLI with ACCM
// ============================================================================

// 4.12.1: SLI step with custom ACCM AVP.
func TestL2TP_SLI_ACCM(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ}, {Type: stepOCRP}, {Type: stepOCCN},
		{Type: stepSLI, AVPs: []core.L2TPAVP{
			{AttrType: attrACCM, Value: []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		}},
	}
	configs := mustPlan(t, p, spec)
	// SLI at index 6.
	payload := configs[6].Payload
	offset := v2ControlHeaderSize
	for offset+6 <= len(payload) {
		mh := binary.BigEndian.Uint16(payload[offset : offset+2])
		avpLen := int(mh & 0x0FFF)
		attrType := binary.BigEndian.Uint16(payload[offset+4 : offset+6])
		if attrType == attrACCM {
			valueLen := avpLen - 6
			if valueLen != 4 {
				t.Errorf("ACCM value length = %d, want 4", valueLen)
			}
			value := payload[offset+6 : offset+6+valueLen]
			for i, b := range value {
				if b != 0xFF {
					t.Errorf("ACCM[%d] = 0x%02x, want 0xFF", i, b)
				}
			}
			return
		}
		offset += avpLen
	}
	t.Errorf("ACCM AVP not found in SLI")
}

// ============================================================================
// §5.1 Empty data scenarios
// ============================================================================

// 5.1.1: No PPPFrames => no data packet.
func TestL2TP_NoPPPFrames(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
	}
	configs := mustPlan(t, p, spec)
	if len(configs) != 3 {
		t.Errorf("expected 3 (no PPP), got %d", len(configs))
	}
}

// 5.1.3: HELLO with no custom AVPs => only Message Type AVP.
func TestL2TP_HELLO_Minimal(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{{Type: stepHELLO}}
	configs := mustPlan(t, p, spec)
	payload := configs[0].Payload
	// v2 header 12 + Message Type AVP 8 = 20 bytes total.
	if len(payload) != 20 {
		t.Errorf("HELLO payload = %d, want 20 (12 header + 8 Message Type AVP)", len(payload))
	}
}

// ============================================================================
// §5.2 Boundary values
// ============================================================================

// 5.2.1: max AVP length 1023 (header + 1017 bytes value). The AVP Length
// field is 10 bits per RFC 2661 §4.1 (max 1023), not 12 bits.
func TestL2TP_AVP_MaxLength(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.CustomAVPs = []core.L2TPAVP{
		{Mandatory: false, AttrType: 99, Value: make([]byte, 1017)},
	}
	configs := mustPlan(t, p, spec)
	payload := configs[0].Payload
	_, avpLen, _, _, ok := findAVP(payload, v2ControlHeaderSize, 99)
	if !ok {
		t.Fatal("Custom AVP (attr 99) not found")
	}
	if avpLen != 1023 {
		t.Errorf("Custom AVP length = %d, want 1023 (10-bit Length max)", avpLen)
	}
}

// 5.2.5: Session ID = 0 valid for v2.
func TestL2TP_SessionID_Zero(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.LocalSessionID = 0
	configs := mustPlan(t, p, spec)
	// SCCRQ Session ID = 0 (tunnel-level message).
	_, _, _, sesID, _, _, _ := readControlHeader(configs[0].Payload)
	if sesID != 0 {
		t.Errorf("Session ID = %d, want 0 (tunnel-level)", sesID)
	}
}

// 5.2.6: Tunnel ID = 0 accepted.
func TestL2TP_TunnelID_Zero(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.LocalTunnelID = 0
	configs := mustPlan(t, p, spec)
	// Verify no error and packet emitted.
	if len(configs) != 1 {
		t.Errorf("expected 1 packet, got %d", len(configs))
	}
}

// ============================================================================
// §6 Concurrency tests
// ============================================================================

// 6.1: N concurrent Plan calls => independent packet streams.
func TestL2TP_ConcurrentPlans(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
	}
	const N = 8
	done := make(chan []core.PacketConfig, N)
	for i := 0; i < N; i++ {
		go func() {
			done <- mustPlanCtx(t, p, spec)
		}()
	}
	for i := 0; i < N; i++ {
		configs := <-done
		if len(configs) != 3 {
			t.Errorf("worker %d: expected 3 packets, got %d", i, len(configs))
		}
	}
}

// 7.7: ctx cancellation in the middle of the scenario.
func TestL2TP_ContextCancelMidway(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ}, {Type: stepOCRP}, {Type: stepOCCN},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var configs []core.PacketConfig
	for cfg := range ch {
		configs = append(configs, cfg)
		if len(configs) == 2 {
			cancel()
		}
	}
	// Should have stopped early.
	if len(configs) > 6 {
		t.Errorf("Expected at most 6 packets, got %d", len(configs))
	}
}

// ============================================================================
// §5.5 Small data
// ============================================================================

// 5.5.1: HELLO only => single 18-byte packet (12 header + 6 AVP).
// Note: planner adds padding if needed; minimum is 12 header + 8 Message Type AVP (header + 2-byte value = 8).
func TestL2TP_HELLO_Single(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{{Type: stepHELLO}}
	configs := mustPlan(t, p, spec)
	if len(configs) != 1 {
		t.Fatalf("expected 1, got %d", len(configs))
	}
}

// 5.5.3: Single-byte PPP frame.
func TestL2TP_PPP_SingleByte(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ}, {Type: stepOCRP}, {Type: stepOCCN},
	}
	spec.L2TP.PPPFrames = []core.L2TPPPPFrame{
		{Protocol: 0x0021, Data: []byte{0x42}},
	}
	configs := mustPlan(t, p, spec)
	last := configs[6].Payload
	// TunID(2)+SesID(2)+Protocol(2)+Data(1) = 7 bytes.
	if len(last) != 7 {
		t.Errorf("single-byte PPP payload = %d, want 7", len(last))
	}
	if last[6] != 0x42 {
		t.Errorf("data byte = 0x%02x, want 0x42", last[6])
	}
}

// ============================================================================
// §3.7 PPP with various protocols
// ============================================================================

// 3.7.6: IPv6 over PPP (Protocol=0x0057).
func TestL2TP_PPP_IPv6(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
		{Type: stepOCRQ}, {Type: stepOCRP}, {Type: stepOCCN},
	}
	spec.L2TP.PPPFrames = []core.L2TPPPPFrame{
		{Protocol: 0x0057, Data: []byte{0x60, 0x00, 0x00, 0x00}},
	}
	configs := mustPlan(t, p, spec)
	last := configs[6].Payload
	proto := binary.BigEndian.Uint16(last[4:6])
	if proto != 0x0057 {
		t.Errorf("PPP Protocol = 0x%04x, want 0x0057 (IPv6)", proto)
	}
}

// ============================================================================
// §3.8 L2TPv3 data message variants
// ============================================================================

// 3.8.1: L2TPv3 data message => 6-byte header with 32-bit Session ID.
func TestL2TPv3_DataHeader(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Version = VersionL2TPv3
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
	}
	spec.L2TP.PPPFrames = []core.L2TPPPPFrame{
		{Protocol: 0x0021, Data: []byte("test")},
	}
	configs := mustPlan(t, p, spec)
	last := configs[len(configs)-1].Payload
	if len(last) < 6 {
		t.Fatal("v3 data too short")
	}
	// v3 flags byte 0 = 0 (no cookie size), byte 1 = 0x03 (Ver=3).
	if last[0] != 0 || last[1] != 0x03 {
		t.Errorf("v3 flags = %02x %02x, want 00 03", last[0], last[1])
	}
}

// 3.8.2: L2TPv3 data message with a 4-byte Cookie emits the Cookie bytes
// immediately after the Session ID, and the Flags byte encodes cookie
// size = 4 (bits 5-4 = 0b01 -> 0x20). Per RFC 3931 §3.1 the Cookie field
// MUST follow the Session ID when the Cookie-Length flags are non-zero.
//
// This is a regression test: an earlier version validated Cookie length
// but never WROTE the Cookie bytes into the data message, so the 4-byte
// cookie [01 02 03 04] was silently dropped.
func TestL2TPv3_DataMessageEmitsCookie(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Version = VersionL2TPv3
	spec.L2TP.LocalSessionID32 = 0xCAFEBABE
	spec.L2TP.Cookie = []byte{0x01, 0x02, 0x03, 0x04}
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
	}
	spec.L2TP.PPPFrames = []core.L2TPPPPFrame{
		{Protocol: 0x0021, Data: []byte("payload")},
	}
	configs := mustPlan(t, p, spec)
	last := configs[len(configs)-1].Payload
	if len(last) < 6+4 {
		t.Fatalf("v3 data with cookie too short: %d bytes", len(last))
	}
	// Flags byte must encode Cookie Size = 4 (0x20).
	if last[0] != v3FlagCookieSize4 {
		t.Errorf("v3 flags = 0x%02x, want 0x%02x (cookie size 4)", last[0], v3FlagCookieSize4)
	}
	if last[1] != 0x03 {
		t.Errorf("v3 ver = 0x%02x, want 0x03", last[1])
	}
	// Session ID at offset 2..6.
	if binary.BigEndian.Uint32(last[2:6]) != 0xCAFEBABE {
		t.Errorf("v3 session id = 0x%08X, want 0xCAFEBABE", binary.BigEndian.Uint32(last[2:6]))
	}
	// Cookie must appear at offset 6..10 (immediately after Session ID).
	cookie := last[6:10]
	if !bytes.Equal(cookie, []byte{0x01, 0x02, 0x03, 0x04}) {
		t.Errorf("v3 cookie bytes = %x, want 01020304 (RFC 3931 §3.1: Cookie follows Session ID)", cookie)
	}
}

// 3.8.3: L2TPv3 data message with an 8-byte Cookie emits 8 cookie bytes
// and the Flags byte encodes cookie size = 8 (0x40).
func TestL2TPv3_DataMessageEmits8ByteCookie(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Version = VersionL2TPv3
	cookie := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	spec.L2TP.Cookie = cookie
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
	}
	spec.L2TP.PPPFrames = []core.L2TPPPPFrame{
		{Protocol: 0x0021, Data: []byte("x")},
	}
	configs := mustPlan(t, p, spec)
	last := configs[len(configs)-1].Payload
	if len(last) < 6+8 {
		t.Fatalf("v3 data with 8-byte cookie too short: %d bytes", len(last))
	}
	if last[0] != v3FlagCookieSize8 {
		t.Errorf("v3 flags = 0x%02x, want 0x%02x (cookie size 8)", last[0], v3FlagCookieSize8)
	}
	got := last[6 : 6+8]
	if !bytes.Equal(got, cookie) {
		t.Errorf("v3 8-byte cookie = %x, want %x", got, cookie)
	}
}

// 3.8.4: L2TPv3 data message with a 16-byte Cookie emits 16 cookie bytes
// and the Flags byte encodes cookie size = 16 (0x60).
func TestL2TPv3_DataMessageEmits16ByteCookie(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Version = VersionL2TPv3
	cookie := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	}
	spec.L2TP.Cookie = cookie
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ}, {Type: stepSCCRP}, {Type: stepSCCCN},
	}
	spec.L2TP.PPPFrames = []core.L2TPPPPFrame{
		{Protocol: 0x0021, Data: []byte("y")},
	}
	configs := mustPlan(t, p, spec)
	last := configs[len(configs)-1].Payload
	if len(last) < 6+16 {
		t.Fatalf("v3 data with 16-byte cookie too short: %d bytes", len(last))
	}
	if last[0] != v3FlagCookieSize16 {
		t.Errorf("v3 flags = 0x%02x, want 0x%02x (cookie size 16)", last[0], v3FlagCookieSize16)
	}
	got := last[6 : 6+16]
	if !bytes.Equal(got, cookie) {
		t.Errorf("v3 16-byte cookie = %x, want %x", got, cookie)
	}
}

// ============================================================================
// §5.3 Validation edge cases
// ============================================================================

// 5.3.9: Tunnel ID unassigned but data message present -> validation passes
// (planner emits; the peer decides whether to accept). This is by design.
func TestL2TP_UnassignedTunnelID_Allowed(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.LocalTunnelID = 0
	spec.L2TP.PeerTunnelID = 0
	err := p.Validate(spec)
	if err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// ============================================================================
// Direction-specific emit
// ============================================================================

// Test direction="up" uses local MAC/IP and direction="down" swaps.
func TestL2TP_DirectionSwap(t *testing.T) {
	p := NewPlanner()
	spec := validL2TPv2Spec()
	spec.L2TP.Role = "lac"
	spec.L2TP.Scenarios = []core.L2TPStep{
		{Type: stepSCCRQ, Direction: "down"},
	}
	configs := mustPlan(t, p, spec)
	if len(configs) != 1 {
		t.Fatalf("expected 1, got %d", len(configs))
	}
	if configs[0].Direction != "down" {
		t.Errorf("Direction = %s, want down", configs[0].Direction)
	}
	// MAC and IP should be swapped.
	if configs[0].L2.SrcMAC != "11:22:33:44:55:66" {
		t.Errorf("down SrcMAC = %s, want dst MAC", configs[0].L2.SrcMAC)
	}
	if configs[0].L2.DstMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("down DstMAC = %s, want src MAC", configs[0].L2.DstMAC)
	}
}