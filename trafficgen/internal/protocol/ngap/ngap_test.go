package ngap

// Test points for the NGAP planner. Each test asserts observable
// PacketConfig field values, not just "no error". Derived from the
// session-level structure documented in ngap.go (3GPP TS 38.413 over
// SCTP, port 38412, PPID=60).

import (
	"context"
	"encoding/binary"
	"strings"
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

// validNGAPSpec returns a spec with a minimal NGAP flow (NG Setup only).
// Models a single gNB (基站) → AMF (接入管理功能) association on port 38412.
func validNGAPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 38413, DstPort: 38412,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		NGAP: &core.NGAPConfig{},
		SCTP: &core.SCTPConfig{},
	}
}

// --- Validate ---

func TestNGAPValidate_ValidIPs(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestNGAPValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.SrcIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid SrcIP") {
		t.Errorf("err=%v, want contains 'invalid SrcIP'", err)
	}
}

func TestNGAPValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.DstIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid DstIP") {
		t.Errorf("err=%v, want contains 'invalid DstIP'", err)
	}
}

func TestNGAPValidate_NilNGAPConfig(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("nil NGAP config should be accepted: %v", err)
	}
}

func TestNGAPValidate_NilSCTPConfig(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.SCTP = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("nil SCTP config should be accepted: %v", err)
	}
}

func TestNGAPValidate_IPv6SrcIPRejected(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.SrcIP = "2001:db8::1"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Errorf("err=%v, want contains 'IPv6' (IPv6 rejected)", err)
	}
}

func TestNGAPValidate_IPv6DstIPRejected(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.DstIP = "2001:db8::2"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Errorf("err=%v, want contains 'IPv6' (IPv6 rejected)", err)
	}
}

func TestNGAPValidate_OutOfRangeSrcPort(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.SrcPort = 65535
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "SrcPort") {
		t.Errorf("err=%v, want contains 'SrcPort'", err)
	}
}

func TestNGAPValidate_OutOfRangeDstPort(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.DstPort = 65535
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "DstPort") {
		t.Errorf("err=%v, want contains 'DstPort'", err)
	}
}

func TestNGAPValidate_InvalidPagingDRX(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.DefaultPagingDRX = 5
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "DefaultPagingDRX") {
		t.Errorf("err=%v, want contains 'DefaultPagingDRX'", err)
	}
}

func TestNGAPValidate_InvalidPDUSessionID(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.PDUSessionSetup = &core.NGAPPDUSessionSetup{PDUSessionID: 256}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "PDUSessionID") {
		t.Errorf("err=%v, want contains 'PDUSessionID'", err)
	}
}

func TestNGAPValidate_InvalidSST(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.PDUSessionSetup = &core.NGAPPDUSessionSetup{SST: 256}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "SST") {
		t.Errorf("err=%v, want contains 'SST'", err)
	}
}

func TestNGAPValidate_InvalidPLMNMCC(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.GlobalRANNodeID = &core.NGAPGlobalRANNodeID{PLMNMCC: 1000, PLMNMNC: 1}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "PLMNMCC") {
		t.Errorf("err=%v, want contains 'PLMNMCC'", err)
	}
}

func TestNGAPValidate_InvalidPLMNMNC(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.GlobalRANNodeID = &core.NGAPGlobalRANNodeID{PLMNMCC: 460, PLMNMNC: 1000}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "PLMNMNC") {
		t.Errorf("err=%v, want contains 'PLMNMNC'", err)
	}
}

func TestNGAPValidate_TooLongNAS(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.InitialNAS = make([]byte, 4097)
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("err=%v, want contains 'too long'", err)
	}
}

// --- Plan: packet count and order ---

// TestNGAPPlan_MinimalFlow verifies the minimal flow (SCTP handshake + NG
// Setup + teardown) produces exactly 9 packets.
func TestNGAPPlan_MinimalFlow(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 9 {
		t.Errorf("got %d packets, want 9 (INIT, INIT-ACK, COOKIE-ECHO, COOKIE-ACK, NGSetupReq, NGSetupResp, SHUTDOWN, SHUTDOWN-ACK, SHUTDOWN-COMPLETE)", len(packets))
	}
}

// TestNGAPPlan_InitialUEMessage adds InitialUEMessage → 11 packets.
func TestNGAPPlan_InitialUEMessage(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.InitialUEMessage = true
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 10 {
		t.Errorf("got %d packets, want 10 (4 handshake + 2 NGSetup + 1 InitialUE + 3 teardown)", len(packets))
	}
}

// TestNGAPPlan_FullProcedure verifies a full flow with all optional
// procedures: InitialUE + DownlinkNAS + UplinkNAS + PDUSessionSetup +
// UEContextRelease → 16 packets.
func TestNGAPPlan_FullProcedure(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.InitialUEMessage = true
	spec.NGAP.DownlinkNAS = []byte{0x7e, 0x00, 0x42, 0x01} // minimal NAS
	spec.NGAP.UplinkNAS = []byte{0x7e, 0x00, 0x43, 0x01}
	spec.NGAP.PDUSessionSetup = &core.NGAPPDUSessionSetup{PDUSessionID: 1, SST: 1, SD: 1}
	spec.NGAP.UEContextRelease = true
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	// 4 handshake + 2 NGSetup + 1 InitialUE + 1 DL + 1 UL + 2 PDUSession + 2 UEContextRelease + 3 teardown = 16
	if len(packets) != 16 {
		t.Errorf("got %d packets, want 16", len(packets))
	}
}

// TestNGAPPlan_PacketIndexSequential verifies packet indices are sequential.
func TestNGAPPlan_PacketIndexSequential(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	for i, pkt := range packets {
		if pkt.PacketIndex != uint64(i) {
			t.Errorf("packet %d: PacketIndex=%d, want %d", i, pkt.PacketIndex, i)
		}
	}
}

// TestNGAPPlan_FlowIDCorrect verifies FlowID contains the 4-tuple.
func TestNGAPPlan_FlowIDCorrect(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) == 0 {
		t.Fatal("no packets")
	}
	want := "10.0.0.1-10.0.0.2-38413-38412"
	if packets[0].FlowID != want {
		t.Errorf("FlowID=%q, want %q", packets[0].FlowID, want)
	}
}

// TestNGAPPlan_L4ProtocolIsSCTP verifies L4 protocol is "sctp".
func TestNGAPPlan_L4ProtocolIsSCTP(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	for i, pkt := range packets {
		if pkt.L4.Protocol != "sctp" {
			t.Errorf("packet %d: L4.Protocol=%q, want sctp", i, pkt.L4.Protocol)
		}
	}
}

// TestNGAPPlan_L3ProtocolIsSCTP verifies L3 protocol is 132 (SCTP).
func TestNGAPPlan_L3ProtocolIsSCTP(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	for i, pkt := range packets {
		if pkt.L3.Protocol != core.ProtocolSCTP {
			t.Errorf("packet %d: L3.Protocol=%d, want %d (SCTP)", i, pkt.L3.Protocol, core.ProtocolSCTP)
		}
	}
}

// TestNGAPPlan_PortsCorrect verifies ports match the spec.
func TestNGAPPlan_PortsCorrect(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	// INIT (up): src=38413, dst=38412
	if packets[0].L4.SrcPort != 38413 || packets[0].L4.DstPort != 38412 {
		t.Errorf("INIT packet: src=%d dst=%d, want 38413 38412", packets[0].L4.SrcPort, packets[0].L4.DstPort)
	}
	// INIT-ACK (down): src=38412, dst=38413
	if packets[1].L4.SrcPort != 38412 || packets[1].L4.DstPort != 38413 {
		t.Errorf("INIT-ACK packet: src=%d dst=%d, want 38412 38413", packets[1].L4.SrcPort, packets[1].L4.DstPort)
	}
}

// TestNGAPPlan_Directions verifies the direction alternation pattern.
func TestNGAPPlan_Directions(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	// Minimal: up, down, up, down, up, down, up, down, up
	want := []string{"up", "down", "up", "down", "up", "down", "up", "down", "up"}
	for i, pkt := range packets {
		if i >= len(want) {
			break
		}
		if pkt.Direction != want[i] {
			t.Errorf("packet %d: Direction=%q, want %q", i, pkt.Direction, want[i])
		}
	}
}

// TestNGAPPlan_VerificationTagINITZero verifies INIT carries VerificationTag=0.
func TestNGAPPlan_VerificationTagINITZero(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if packets[0].L4.Ack != 0 {
		t.Errorf("INIT VerificationTag=%d, want 0", packets[0].L4.Ack)
	}
}

// TestNGAPPlan_VerificationTagNonZeroAfterINIT verifies non-INIT packets
// carry non-zero VerificationTags.
func TestNGAPPlan_VerificationTagNonZeroAfterINIT(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	for i, pkt := range packets[1:] {
		if pkt.L4.Ack == 0 {
			t.Errorf("packet %d (after INIT): VerificationTag=0, want non-zero", i+1)
		}
	}
}

// TestNGAPPlan_INITChunkType verifies the first packet's payload starts
// with INIT chunk type (1).
func TestNGAPPlan_INITChunkType(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets[0].Payload) == 0 {
		t.Fatal("INIT packet has no payload")
	}
	if packets[0].Payload[0] != ChunkINIT {
		t.Errorf("INIT chunk type=0x%02x, want 0x%02x", packets[0].Payload[0], ChunkINIT)
	}
}

// TestNGAPPlan_INITAckChunkType verifies the second packet's payload
// starts with INIT-ACK chunk type (2).
func TestNGAPPlan_INITAckChunkType(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets[1].Payload) == 0 {
		t.Fatal("INIT-ACK packet has no payload")
	}
	if packets[1].Payload[0] != ChunkINITAck {
		t.Errorf("INIT-ACK chunk type=0x%02x, want 0x%02x", packets[1].Payload[0], ChunkINITAck)
	}
}

// TestNGAPPlan_SHUTDOWNChunkType verifies the SHUTDOWN packet.
func TestNGAPPlan_SHUTDOWNChunkType(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	// SHUTDOWN is the 7th packet (index 6) in minimal flow.
	if len(packets) < 7 {
		t.Fatalf("expected at least 7 packets, got %d", len(packets))
	}
	if packets[6].Payload[0] != ChunkSHUTDOWN {
		t.Errorf("SHUTDOWN chunk type=0x%02x, want 0x%02x", packets[6].Payload[0], ChunkSHUTDOWN)
	}
}

// TestNGAPPlan_NGSetupRequestHasDATAChunk verifies NGSetupRequest is a
// DATA chunk with PPID=60 (NGAP).
func TestNGAPPlan_NGSetupRequestHasDATAChunk(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	// NGSetupRequest is packet 4 (index 4) in minimal flow.
	if len(packets) < 5 {
		t.Fatalf("expected at least 5 packets, got %d", len(packets))
	}
	pkt := packets[4]
	if len(pkt.Payload) == 0 {
		t.Fatal("NGSetupRequest packet has no payload")
	}
	if pkt.Payload[0] != ChunkDATA {
		t.Errorf("NGSetupRequest chunk type=0x%02x, want 0x%02x (DATA)", pkt.Payload[0], ChunkDATA)
	}
	// Verify PPID=60 (NGAP). DATA chunk header: Type(1)+Flags(1)+Length(2) + TSN(4)+SID(2)+SSN(2)+PPID(4).
	ppid := binary.BigEndian.Uint32(pkt.Payload[12:16])
	if ppid != PPID_NGAP {
		t.Errorf("NGSetupRequest PPID=%d, want %d (NGAP)", ppid, PPID_NGAP)
	}
	// Verify SID=1 (NAS signaling stream).
	sid := binary.BigEndian.Uint16(pkt.Payload[8:10])
	if sid != SID_NAS {
		t.Errorf("NGSetupRequest SID=%d, want %d", sid, SID_NAS)
	}
}

// TestNGAPPlan_NGSetupRequestDirection verifies NGSetupRequest is "up" (gNB→AMF).
func TestNGAPPlan_NGSetupRequestDirection(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if packets[4].Direction != "up" {
		t.Errorf("NGSetupRequest direction=%q, want up", packets[4].Direction)
	}
}

// TestNGAPPlan_NGSetupResponseDirection verifies NGSetupResponse is "down" (AMF→gNB).
func TestNGAPPlan_NGSetupResponseDirection(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if packets[5].Direction != "down" {
		t.Errorf("NGSetupResponse direction=%q, want down", packets[5].Direction)
	}
}

// TestNGAPPlan_NGSetupResponseIsSuccessfulOutcome verifies the response
// NGAP-PDU starts with choice=1 (successfulOutcome).
func TestNGAPPlan_NGSetupResponseIsSuccessfulOutcome(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	pkt := packets[5]
	// DATA chunk payload starts after 16-byte DATA header (Type+Flags+Length+TSN+SID+SSN+PPID).
	dataHeaderLen := 16 // 4-byte chunk header + 12-byte DATA value header
	if len(pkt.Payload) <= dataHeaderLen {
		t.Fatalf("NGSetupResponse payload too short: %d bytes", len(pkt.Payload))
	}
	ngapPDU := pkt.Payload[dataHeaderLen:]
	if len(ngapPDU) == 0 {
		t.Fatal("NGSetupResponse NGAP-PDU is empty")
	}
	if ngapPDU[0] != PDUSuccessfulOutcome {
		t.Errorf("NGSetupResponse PDU choice=%d, want %d (successfulOutcome)", ngapPDU[0], PDUSuccessfulOutcome)
	}
	if ngapPDU[1] != ProcNGSetup {
		t.Errorf("NGSetupResponse procedureCode=%d, want %d", ngapPDU[1], ProcNGSetup)
	}
}

// TestNGAPPlan_NGSetupRequestIsInitiatingMessage verifies the request
// NGAP-PDU starts with choice=0 (initiatingMessage).
func TestNGAPPlan_NGSetupRequestIsInitiatingMessage(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	pkt := packets[4]
	dataHeaderLen := 16
	if len(pkt.Payload) <= dataHeaderLen {
		t.Fatalf("NGSetupRequest payload too short: %d bytes", len(pkt.Payload))
	}
	ngapPDU := pkt.Payload[dataHeaderLen:]
	if len(ngapPDU) == 0 {
		t.Fatal("NGSetupRequest NGAP-PDU is empty")
	}
	if ngapPDU[0] != PDUInitiatingMessage {
		t.Errorf("NGSetupRequest PDU choice=%d, want %d (initiatingMessage)", ngapPDU[0], PDUInitiatingMessage)
	}
	if ngapPDU[1] != ProcNGSetup {
		t.Errorf("NGSetupRequest procedureCode=%d, want %d", ngapPDU[1], ProcNGSetup)
	}
}

// TestNGAPPlan_DefaultTTL verifies TTL defaults to 64.
func TestNGAPPlan_DefaultTTL(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	for i, pkt := range packets {
		if pkt.L3.TTL != DefaultTTL {
			t.Errorf("packet %d: TTL=%d, want %d", i, pkt.L3.TTL, DefaultTTL)
		}
	}
}

// TestNGAPPlan_CustomTTL verifies explicit TTL is honored.
func TestNGAPPlan_CustomTTL(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.TTL = 128
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	for i, pkt := range packets {
		if pkt.L3.TTL != 128 {
			t.Errorf("packet %d: TTL=%d, want 128", i, pkt.L3.TTL)
		}
	}
}

// TestNGAPPlan_ContextCancellation verifies Plan stops when context is cancelled.
func TestNGAPPlan_ContextCancellation(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// Cancel immediately (立即取消).
	cancel()
	packets := drain(ch)
	// Should get fewer than 9 packets (or exactly 0 depending on timing).
	if len(packets) >= 9 {
		t.Errorf("got %d packets after cancel, expected < 9", len(packets))
	}
}

// TestNGAPPlan_CustomAMFName verifies AMFName from config is used in
// NGSetupResponse.
func TestNGAPPlan_CustomAMFName(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.AMFName = "AMF-CUSTOM-99"
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	pkt := packets[5] // NGSetupResponse
	dataHeaderLen := 16
	ngapPDU := pkt.Payload[dataHeaderLen:]
	// AMFName is the first IE in the response: id(2)=1 + criticality(1) + len(1) + value.
	// After the 3-byte NGAP header (choice+proc+crit) and 2-byte IE count,
	// the first IE starts at offset 5.
	ieOffset := 5
	if len(ngapPDU) < ieOffset+4+len(spec.NGAP.AMFName) {
		t.Fatalf("NGSetupResponse NGAP-PDU too short: %d bytes", len(ngapPDU))
	}
	ieID := binary.BigEndian.Uint16(ngapPDU[ieOffset : ieOffset+2])
	if ieID != IEID_AMFName {
		t.Errorf("first IE id=%d, want %d (AMFName)", ieID, IEID_AMFName)
	}
	ieLen := int(ngapPDU[ieOffset+3])
	if ieLen != len(spec.NGAP.AMFName) {
		t.Errorf("AMFName IE len=%d, want %d", ieLen, len(spec.NGAP.AMFName))
	}
	name := string(ngapPDU[ieOffset+4 : ieOffset+4+ieLen])
	if name != spec.NGAP.AMFName {
		t.Errorf("AMFName=%q, want %q", name, spec.NGAP.AMFName)
	}
}

// TestNGAPPlan_DefaultAMFName verifies default AMFName is "AMF-TEST-01".
func TestNGAPPlan_DefaultAMFName(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	pkt := packets[5] // NGSetupResponse
	dataHeaderLen := 16
	ngapPDU := pkt.Payload[dataHeaderLen:]
	ieOffset := 5
	if len(ngapPDU) < ieOffset+4 {
		t.Fatalf("NGSetupResponse NGAP-PDU too short: %d bytes", len(ngapPDU))
	}
	ieID := binary.BigEndian.Uint16(ngapPDU[ieOffset : ieOffset+2])
	if ieID != IEID_AMFName {
		t.Errorf("first IE id=%d, want %d (AMFName)", ieID, IEID_AMFName)
	}
	ieLen := int(ngapPDU[ieOffset+3])
	name := string(ngapPDU[ieOffset+4 : ieOffset+4+ieLen])
	if name != "AMF-TEST-01" {
		t.Errorf("AMFName=%q, want 'AMF-TEST-01'", name)
	}
}

// TestNGAPPlan_UEContextReleaseAddsPackets verifies UEContextRelease adds
// 2 packets (Command + Complete).
func TestNGAPPlan_UEContextReleaseAddsPackets(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.UEContextRelease = true
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 11 {
		t.Errorf("got %d packets, want 11 (9 base + 2 UEContextRelease)", len(packets))
	}
}

// TestNGAPPlan_PDUSessionSetupAddsPackets verifies PDUSessionSetup adds
// 2 packets (Request + Response).
func TestNGAPPlan_PDUSessionSetupAddsPackets(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.PDUSessionSetup = &core.NGAPPDUSessionSetup{PDUSessionID: 5, SST: 2, SD: 100}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	if len(packets) != 11 {
		t.Errorf("got %d packets, want 11 (9 base + 2 PDUSessionSetup)", len(packets))
	}
}

// TestNGAPPlan_DownlinkNASIsDown verifies DownlinkNASTransport is "down".
func TestNGAPPlan_DownlinkNASIsDown(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.InitialUEMessage = true
	spec.NGAP.DownlinkNAS = []byte{0x7e, 0x00, 0x42, 0x01}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	// After InitialUE (index 6), DownlinkNAS should be index 7.
	if len(packets) < 8 {
		t.Fatalf("expected at least 8 packets, got %d", len(packets))
	}
	if packets[7].Direction != "down" {
		t.Errorf("DownlinkNAS direction=%q, want down", packets[7].Direction)
	}
}

// TestNGAPPlan_UplinkNASIsUp verifies UplinkNASTransport is "up".
func TestNGAPPlan_UplinkNASIsUp(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.InitialUEMessage = true
	spec.NGAP.UplinkNAS = []byte{0x7e, 0x00, 0x43, 0x01}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	// After InitialUE (index 6), UplinkNAS should be index 7.
	if len(packets) < 8 {
		t.Fatalf("expected at least 8 packets, got %d", len(packets))
	}
	if packets[7].Direction != "up" {
		t.Errorf("UplinkNAS direction=%q, want up", packets[7].Direction)
	}
}

// TestNGAPPlan_InitialUEWithCustomNAS verifies custom InitialNAS is used.
func TestNGAPPlan_InitialUEWithCustomNAS(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.InitialUEMessage = true
	spec.NGAP.InitialNAS = []byte{0x01, 0x02, 0x03, 0x04}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	pkt := packets[6] // InitialUEMessage
	dataHeaderLen := 16
	ngapPDU := pkt.Payload[dataHeaderLen:]
	// Find NAS-PDU IE (id=38) in the PDU.
	ieOffset := 5 // 3-byte NGAP header + 2-byte IE count
	for len(ngapPDU) > ieOffset+4 {
		ieID := binary.BigEndian.Uint16(ngapPDU[ieOffset : ieOffset+2])
		ieLen := int(ngapPDU[ieOffset+3])
		if ieID == IEID_NASPDU {
			// NAS-PDU is length-prefixed: 2-byte length + value.
			nasOffset := ieOffset + 4
			if len(ngapPDU) < nasOffset+2 {
				break
			}
			nasLen := int(binary.BigEndian.Uint16(ngapPDU[nasOffset : nasOffset+2]))
			nasValue := ngapPDU[nasOffset+2 : nasOffset+2+nasLen]
			if len(nasValue) != len(spec.NGAP.InitialNAS) {
				t.Errorf("NAS-PDU len=%d, want %d", len(nasValue), len(spec.NGAP.InitialNAS))
			}
			for i, b := range nasValue {
				if b != spec.NGAP.InitialNAS[i] {
					t.Errorf("NAS-PDU[%d]=0x%02x, want 0x%02x", i, b, spec.NGAP.InitialNAS[i])
				}
			}
			return
		}
		ieOffset += 4 + ieLen
	}
	t.Errorf("NAS-PDU IE (id=%d) not found in InitialUEMessage", IEID_NASPDU)
}

// TestNGAPPlan_EtherTypeIPv4 verifies EtherType is IPv4 (0x0800).
func TestNGAPPlan_EtherTypeIPv4(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	for i, pkt := range packets {
		if pkt.L2.EtherType != core.EtherTypeIPv4 {
			t.Errorf("packet %d: EtherType=0x%04x, want 0x%04x", i, pkt.L2.EtherType, core.EtherTypeIPv4)
		}
	}
}

// TestNGAPPlan_MACsCorrect verifies MAC addresses match the spec.
func TestNGAPPlan_MACsCorrect(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	// INIT (up): src=SrcMAC, dst=DstMAC
	if packets[0].L2.SrcMAC != spec.SrcMAC || packets[0].L2.DstMAC != spec.DstMAC {
		t.Errorf("INIT MACs: src=%s dst=%s, want %s %s", packets[0].L2.SrcMAC, packets[0].L2.DstMAC, spec.SrcMAC, spec.DstMAC)
	}
	// INIT-ACK (down): src=DstMAC, dst=SrcMAC
	if packets[1].L2.SrcMAC != spec.DstMAC || packets[1].L2.DstMAC != spec.SrcMAC {
		t.Errorf("INIT-ACK MACs: src=%s dst=%s, want %s %s", packets[1].L2.SrcMAC, packets[1].L2.DstMAC, spec.DstMAC, spec.SrcMAC)
	}
}

// TestNGAPPlan_SrcDstIPCorrect verifies IP addresses match the spec.
func TestNGAPPlan_SrcDstIPCorrect(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	// INIT (up): src=SrcIP, dst=DstIP
	if packets[0].L3.SrcIP != spec.SrcIP || packets[0].L3.DstIP != spec.DstIP {
		t.Errorf("INIT IPs: src=%s dst=%s, want %s %s", packets[0].L3.SrcIP, packets[0].L3.DstIP, spec.SrcIP, spec.DstIP)
	}
	// INIT-ACK (down): src=DstIP, dst=SrcIP
	if packets[1].L3.SrcIP != spec.DstIP || packets[1].L3.DstIP != spec.SrcIP {
		t.Errorf("INIT-ACK IPs: src=%s dst=%s, want %s %s", packets[1].L3.SrcIP, packets[1].L3.DstIP, spec.DstIP, spec.SrcIP)
	}
}

// TestNGAPPlan_RANUEIDDefault verifies default RANUENGAPID=1 is used.
func TestNGAPPlan_RANUEIDDefault(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.InitialUEMessage = true
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	pkt := packets[6] // InitialUEMessage
	dataHeaderLen := 16
	ngapPDU := pkt.Payload[dataHeaderLen:]
	ieOffset := 5
	if len(ngapPDU) < ieOffset+8 {
		t.Fatalf("NGAP-PDU too short: %d bytes", len(ngapPDU))
	}
	ieID := binary.BigEndian.Uint16(ngapPDU[ieOffset : ieOffset+2])
	if ieID != IEID_RANUENGAPID {
		t.Errorf("first IE id=%d, want %d (RANUENGAPID)", ieID, IEID_RANUENGAPID)
	}
	ieLen := int(ngapPDU[ieOffset+3])
	if ieLen != 4 {
		t.Errorf("RANUENGAPID IE len=%d, want 4", ieLen)
	}
	ranUE := binary.BigEndian.Uint32(ngapPDU[ieOffset+4 : ieOffset+8])
	if ranUE != 1 {
		t.Errorf("RANUENGAPID=%d, want 1", ranUE)
	}
}

// TestNGAPPlan_CustomRANUEID verifies custom RANUENGAPID is used.
func TestNGAPPlan_CustomRANUEID(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.InitialUEMessage = true
	spec.NGAP.RANUENGAPID = 42
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	pkt := packets[6] // InitialUEMessage
	dataHeaderLen := 16
	ngapPDU := pkt.Payload[dataHeaderLen:]
	ieOffset := 5
	ranUE := binary.BigEndian.Uint32(ngapPDU[ieOffset+4 : ieOffset+8])
	if ranUE != 42 {
		t.Errorf("RANUENGAPID=%d, want 42", ranUE)
	}
}

// TestNGAPPlan_DefaultPagingDRX verifies default paging DRX value=0 (vrf128).
func TestNGAPPlan_DefaultPagingDRX(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	pkt := packets[4] // NGSetupRequest
	dataHeaderLen := 16
	ngapPDU := pkt.Payload[dataHeaderLen:]
	// Find DefaultPagingDRX IE (id=21).
	ieOffset := 5
	for len(ngapPDU) > ieOffset+4 {
		ieID := binary.BigEndian.Uint16(ngapPDU[ieOffset : ieOffset+2])
		ieLen := int(ngapPDU[ieOffset+3])
		if ieID == IEID_DefaultPagingDRX {
			if len(ngapPDU) < ieOffset+4+1 {
				break
			}
			val := ngapPDU[ieOffset+4]
			if val != 0 {
				t.Errorf("DefaultPagingDRX=%d, want 0 (vrf128)", val)
			}
			return
		}
		ieOffset += 4 + ieLen
	}
	t.Errorf("DefaultPagingDRX IE (id=%d) not found", IEID_DefaultPagingDRX)
}

// TestNGAPPlan_CustomPagingDRX verifies custom paging DRX value.
func TestNGAPPlan_CustomPagingDRX(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.NGAP.DefaultPagingDRX = 2 // vrf512
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	pkt := packets[4] // NGSetupRequest
	dataHeaderLen := 16
	ngapPDU := pkt.Payload[dataHeaderLen:]
	ieOffset := 5
	for len(ngapPDU) > ieOffset+4 {
		ieID := binary.BigEndian.Uint16(ngapPDU[ieOffset : ieOffset+2])
		ieLen := int(ngapPDU[ieOffset+3])
		if ieID == IEID_DefaultPagingDRX {
			val := ngapPDU[ieOffset+4]
			if val != 2 {
				t.Errorf("DefaultPagingDRX=%d, want 2 (vrf512)", val)
			}
			return
		}
		ieOffset += 4 + ieLen
	}
	t.Errorf("DefaultPagingDRX IE (id=%d) not found", IEID_DefaultPagingDRX)
}

// TestNGAPPlan_Name verifies planner name.
func TestNGAPPlan_Name(t *testing.T) {
	p := NewPlanner()
	if p.Name() != "ngap" {
		t.Errorf("Name()=%q, want ngap", p.Name())
	}
}

// TestNGAPPlan_NilSpecRejected verifies Plan rejects a spec that fails Validate.
func TestNGAPPlan_NilSpecRejected(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	spec.SrcIP = "bad"
	_, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Error("Plan should reject invalid spec")
	}
}

// TestNGAPPlan_IPIDIncrements verifies IPID increments per packet.
func TestNGAPPlan_IPIDIncrements(t *testing.T) {
	p := NewPlanner()
	spec := validNGAPSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drain(ch)
	for i := 1; i < len(packets); i++ {
		if packets[i].L3.IPID != packets[i-1].L3.IPID+1 {
			t.Errorf("packet %d: IPID=%d, expected %d (previous+1)", i, packets[i].L3.IPID, packets[i-1].L3.IPID+1)
		}
	}
}
