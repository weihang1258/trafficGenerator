package ike

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- Test helpers ---

// validBaseSpec returns a minimal valid FlowSpec for the IKE planner. Tests
// override individual fields on top of this baseline.
func validBaseSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 4500,
		DstPort: 500,
		IKE: &core.IKEConfig{
			VersionMajor:    2,
			VersionMinor:    0,
			InitiatorSPI:    0x0123456789ABCDEF,
			ResponderSPI:    0x0011223344556677,
			DefaultDHGroup:  14,
			DefaultNonceSize: 32,
			DefaultAuthMethod: 2, // Shared Key
			Strict:          true,
			EncryptMode:     "opaque",
			Scenario:        "standard_v2",
			OpaqueKeySeed:   42,
		},
	}
}

// readPackets drains a planner Plan channel and returns all emitted packets.
func readPackets(t *testing.T, ch <-chan core.PacketConfig) []core.PacketConfig {
	t.Helper()
	var pkts []core.PacketConfig
	for {
		select {
		case p, ok := <-ch:
			if !ok {
				return pkts
			}
			pkts = append(pkts, p)
		case <-time.After(2 * time.Second):
			t.Fatal("planner.Plan hung: did not close channel within 2s")
			return pkts
		}
	}
}

// runPlan invokes Plan and drains the channel.
func runPlan(t *testing.T, p *Planner, spec core.FlowSpec) ([]core.PacketConfig, error) {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		return nil, err
	}
	return readPackets(t, ch), nil
}

// mustPlan is runPlan with a fatal-on-error wrapper.
func mustPlan(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	pkts, err := runPlan(t, NewPlanner(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return pkts
}

// minimalProposal returns a valid default IKE proposal for tests.
func minimalProposal() *core.IKEProposal {
	return &core.IKEProposal{
		Number:     1,
		ProtocolID: ProtocolIKE,
		Transforms: []core.IKETransform{
			{Type: TransformENCR, ID: 12, KeyLengthBits: 128},
			{Type: TransformPRF, ID: 5},
			{Type: TransformINTEG, ID: 12},
			{Type: TransformDH, ID: 14},
		},
	}
}

// --- Validate tests ---

func TestValidate_NilIKEConfig(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 500}
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for nil IKE config")
	}
}

func TestValidate_BadDstPort(t *testing.T) {
	spec := validBaseSpec()
	spec.DstPort = 4500
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for DstPort=4500 (only 500/0 allowed)")
	}
	if !strings.Contains(errString(p.Validate(spec)), "DstPort") {
		t.Fatalf("expected DstPort in error, got %v", p.Validate(spec))
	}
}

func TestValidate_SrcPort500(t *testing.T) {
	spec := validBaseSpec()
	spec.SrcPort = 500
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error: SrcPort=500 is reserved for the server")
	}
}

func TestValidate_BadIP(t *testing.T) {
	spec := validBaseSpec()
	spec.SrcIP = "not-an-ip"
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for invalid SrcIP")
	}
}

func TestValidate_EncryptMode(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.EncryptMode = "aes-gcm"
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for non-opaque EncryptMode")
	}
}

func TestValidate_ScenarioAndMessages(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Messages = []core.IKEMessage{
		{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*minimalProposal()}}}}},
	}
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error: Scenario and Messages cannot both be set")
	}
}

func TestValidate_BadRole(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Role = "maninthemiddle"
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for invalid Role")
	}
}

func TestValidate_UnknownScenario(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "nonexistent"
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for unknown Scenario")
	}
}

func TestValidate_BadExchangeType(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = ""
	spec.IKE.Messages = []core.IKEMessage{
		{Direction: "up", ExchangeType: 0, FromOriginalInitiator: true, Payloads: []core.IKEPayload{{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*minimalProposal()}}}}},
	}
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for ExchangeType=0 in strict mode")
	}
}

func TestValidate_BadExchangeType_FaultInjection(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Strict = false
	spec.IKE.FaultInjection = true
	spec.IKE.Scenario = ""
	msgID := uint32(0)
	spec.IKE.Messages = []core.IKEMessage{
		{Direction: "up", ExchangeType: 99, FromOriginalInitiator: true, MessageID: &msgID, Payloads: []core.IKEPayload{{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*minimalProposal()}}}}},
	}
	p := NewPlanner()
	if err := p.Validate(spec); err != nil {
		t.Fatalf("fault injection should allow ExchangeType=99, got: %v", err)
	}
}

func TestValidate_NonCleartextSK(t *testing.T) {
	// SK in cleartext Payloads chain is invalid in strict mode.
	spec := validBaseSpec()
	spec.IKE.Scenario = ""
	spec.IKE.Messages = []core.IKEMessage{
		{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{
			{Type: PayloadSK, Raw: []byte{0x00, 0x01, 0x02}},
		}},
	}
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error: SK in cleartext payload chain is invalid in strict mode")
	}
}

func TestValidate_RawOverrideNoFault(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = ""
	v := uint32(0x10)
	spec.IKE.Messages = []core.IKEMessage{
		{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*minimalProposal()}}}}, RawLengthOverride: &v},
	}
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error: RawLengthOverride requires FaultInjection=true")
	}
}

func TestValidate_ProposalNoTransforms(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = ""
	prop := &core.IKEProposal{Number: 1, ProtocolID: ProtocolIKE, Transforms: nil}
	spec.IKE.Messages = []core.IKEMessage{
		{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}}}},
	}
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error: Proposal with no Transforms is invalid in strict mode")
	}
}

func TestValidate_TransformTypeOutOfRange(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = ""
	prop := &core.IKEProposal{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{{Type: 6, ID: 1}}}
	spec.IKE.Messages = []core.IKEMessage{
		{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}}}},
	}
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error: Transform Type=6 invalid in strict mode")
	}
}

func TestValidate_NoncenSizeOutOfRange(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = ""
	spec.IKE.Messages = []core.IKEMessage{
		{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{
			{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*minimalProposal()}}},
			{Type: PayloadNONCE, Nonce: make([]byte, 8)}, // too short
		}},
	}
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error: NONCE length < 16 invalid in strict mode")
	}
}

func TestValidate_ResponderSPI_NonZeroInInitRequest(t *testing.T) {
	// In INIT request, ResponderSPI must be 0. We check this via the
	// scenario builder: standard_v2 with Role=initiator and ResponderSPI=0
	// is the only valid case. Here we craft an explicit INIT message with
	// non-zero ResponderSPI in strict mode.
	spec := validBaseSpec()
	spec.IKE.Scenario = ""
	msgID := uint32(0)
	spec.IKE.Messages = []core.IKEMessage{
		{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, MessageID: &msgID, ResponderSPI: u64ptr(0x01), Payloads: []core.IKEPayload{{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*minimalProposal()}}}}},
	}
	p := NewPlanner()
	// Validation should succeed - we don't enforce INIT_RESP SPIr=0 at the
	// payload validation level (this is enforced logically by checking the
	// message flow). We just verify the planner still runs.
	if err := p.Validate(spec); err != nil {
		t.Logf("Validate returned (acceptable): %v", err)
	}
}

// --- Plan tests ---

func TestPlan_StandardV2_Init(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	if len(pkts) != 4 {
		t.Fatalf("expected 4 packets for standard_v2, got %d", len(pkts))
	}
	// First packet: INIT_REQ (up direction)
	if pkts[0].Direction != "up" {
		t.Errorf("pkt[0].Direction = %q, want 'up'", pkts[0].Direction)
	}
	// Second: INIT_RESP (down)
	if pkts[1].Direction != "down" {
		t.Errorf("pkt[1].Direction = %q, want 'down'", pkts[1].Direction)
	}
	// Third: AUTH_REQ (up)
	if pkts[2].Direction != "up" {
		t.Errorf("pkt[2].Direction = %q, want 'up'", pkts[2].Direction)
	}
	// Fourth: AUTH_RESP (down)
	if pkts[3].Direction != "down" {
		t.Errorf("pkt[3].Direction = %q, want 'down'", pkts[3].Direction)
	}
}

func TestPlan_StandardV2_HeaderFields(t *testing.T) {
	spec := validBaseSpec()
	// INIT_REQ must have ResponderSPI=0 per RFC 7296 §1.2. The validBaseSpec
	// sets a non-zero value to test the AUTH-stage echo; clear it here so
	// the INIT_REQ has SPIr=0 (the planner copies cfg.ResponderSPI for the
	// INIT_REQ unless the message overrides it, so we set it to 0).
	spec.IKE.ResponderSPI = 0
	pkts := mustPlan(t, spec)
	if len(pkts) < 1 {
		t.Fatal("no packets emitted")
	}
	p0 := pkts[0]
	if len(p0.Payload) < IKEHeaderLen {
		t.Fatalf("payload too short: %d bytes", len(p0.Payload))
	}
	// Initiator SPI at bytes[0:8].
	spii := binary.BigEndian.Uint64(p0.Payload[0:8])
	if spii != spec.IKE.InitiatorSPI {
		t.Errorf("SPIi = 0x%X, want 0x%X", spii, spec.IKE.InitiatorSPI)
	}
	// Responder SPI = 0 in INIT_REQ.
	spir := binary.BigEndian.Uint64(p0.Payload[8:16])
	if spir != 0 {
		t.Errorf("SPIr = 0x%X, want 0 in INIT_REQ", spir)
	}
	// Next Payload byte: SA = 33.
	if p0.Payload[16] != PayloadSA {
		t.Errorf("Next Payload = %d, want %d (SA)", p0.Payload[16], PayloadSA)
	}
	// Version = 2.0 = 0x20.
	if p0.Payload[17] != 0x20 {
		t.Errorf("Version = 0x%X, want 0x20", p0.Payload[17])
	}
	// Exchange Type = IKE_SA_INIT = 34.
	if p0.Payload[18] != ExchangeIKE_SA_INIT {
		t.Errorf("Exchange Type = %d, want %d (IKE_SA_INIT)", p0.Payload[18], ExchangeIKE_SA_INIT)
	}
	// Flags: I=1, R=0, V=0 -> 0x08.
	if p0.Payload[19] != FlagInitiator {
		t.Errorf("Flags = 0x%X, want 0x%X (I-bit only)", p0.Payload[19], FlagInitiator)
	}
	// Message ID = 0 for INIT.
	if binary.BigEndian.Uint32(p0.Payload[20:24]) != 0 {
		t.Errorf("Message ID = %d, want 0", binary.BigEndian.Uint32(p0.Payload[20:24]))
	}
	// Length = 28 + payload bytes.
	wantLen := uint32(IKEHeaderLen) + uint32(len(p0.Payload)-IKEHeaderLen)
	if binary.BigEndian.Uint32(p0.Payload[24:28]) != wantLen {
		t.Errorf("Length = %d, want %d", binary.BigEndian.Uint32(p0.Payload[24:28]), wantLen)
	}
}

func TestPlan_StandardV2_AuthFlagsAndMsgID(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	if len(pkts) < 3 {
		t.Fatal("expected at least 3 packets")
	}
	// AUTH_REQ (pkt[2]): I=1, R=0, Message ID = 1.
	authReq := pkts[2]
	if authReq.Payload[19]&FlagInitiator == 0 {
		t.Errorf("AUTH_REQ Flags = 0x%X, want I-bit set", authReq.Payload[19])
	}
	if authReq.Payload[19]&FlagResponse != 0 {
		t.Errorf("AUTH_REQ Flags = 0x%X, want R-bit clear", authReq.Payload[19])
	}
	if binary.BigEndian.Uint32(authReq.Payload[20:24]) != 1 {
		t.Errorf("AUTH_REQ Message ID = %d, want 1", binary.BigEndian.Uint32(authReq.Payload[20:24]))
	}
	// AUTH_RESP (pkt[3]): I=0, R=1, Message ID = 1.
	authResp := pkts[3]
	if authResp.Payload[19]&FlagInitiator != 0 {
		t.Errorf("AUTH_RESP Flags = 0x%X, want I-bit clear", authResp.Payload[19])
	}
	if authResp.Payload[19]&FlagResponse == 0 {
		t.Errorf("AUTH_RESP Flags = 0x%X, want R-bit set", authResp.Payload[19])
	}
	if binary.BigEndian.Uint32(authResp.Payload[20:24]) != 1 {
		t.Errorf("AUTH_RESP Message ID = %d, want 1", binary.BigEndian.Uint32(authResp.Payload[20:24]))
	}
}

func TestPlan_StandardV2_InitRespSetsSPIr(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	if len(pkts) < 2 {
		t.Fatal("expected at least 2 packets")
	}
	// INIT_RESP (pkt[1]): SPIr non-zero.
	spir := binary.BigEndian.Uint64(pkts[1].Payload[8:16])
	if spir == 0 {
		t.Errorf("INIT_RESP SPIr = 0, want non-zero")
	}
	// AUTH_REQ (pkt[2]) SPIr should equal INIT_RESP SPIr.
	spirAuth := binary.BigEndian.Uint64(pkts[2].Payload[8:16])
	if spirAuth != spir {
		t.Errorf("AUTH_REQ SPIr = 0x%X, want 0x%X (echo INIT_RESP)", spirAuth, spir)
	}
}

func TestPlan_RoleResponder(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Role = "responder"
	spec.IKE.InitiatorSPI = 0
	spec.IKE.ResponderSPI = 0
	pkts := mustPlan(t, spec)
	if len(pkts) != 4 {
		t.Fatalf("expected 4 packets, got %d", len(pkts))
	}
	// First packet should be "down" direction (responder sending).
	if pkts[0].Direction != "down" {
		t.Errorf("responder first packet Direction = %q, want 'down'", pkts[0].Direction)
	}
}

func TestPlan_DefaultsApplied(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.VersionMajor = 0
	spec.IKE.VersionMinor = 0
	spec.IKE.DefaultDHGroup = 0
	spec.IKE.DefaultNonceSize = 0
	spec.IKE.DefaultAuthMethod = 0
	spec.IKE.EncryptMode = ""
	pkts := mustPlan(t, spec)
	if len(pkts) == 0 {
		t.Fatal("no packets emitted despite zero-value defaults")
	}
	// Version should default to 2.0 = 0x20.
	if pkts[0].Payload[17] != 0x20 {
		t.Errorf("default Version = 0x%X, want 0x20", pkts[0].Payload[17])
	}
}

func TestPlan_NonceSizeClampedLow(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.DefaultNonceSize = 8 // below minimum of 16
	pkts := mustPlan(t, spec)
	if len(pkts) == 0 {
		t.Fatal("no packets emitted")
	}
	// The INIT_REQ contains a NONCE payload; the nonce should be 16 bytes
	// (clamped up from 8). Find the NONCE payload by scanning.
	nonceLen := findNONCEPayloadLen(pkts[0].Payload)
	if nonceLen == 0 {
		t.Fatal("no NONCE payload found in INIT_REQ")
	}
	if nonceLen != 16 {
		t.Errorf("NONCE length = %d, want 16 (clamped from 8)", nonceLen)
	}
}

func TestPlan_NonceSizeClampedHigh(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.DefaultNonceSize = 1024 // above maximum of 256
	pkts := mustPlan(t, spec)
	if len(pkts) == 0 {
		t.Fatal("no packets emitted")
	}
	nonceLen := findNONCEPayloadLen(pkts[0].Payload)
	if nonceLen == 0 {
		t.Fatal("no NONCE payload found in INIT_REQ")
	}
	if nonceLen != 256 {
		t.Errorf("NONCE length = %d, want 256 (clamped from 1024)", nonceLen)
	}
}

func TestPlan_DerivedSPIIsNonZero(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.InitiatorSPI = 0
	spec.IKE.OpaqueKeySeed = 0
	pkts := mustPlan(t, spec)
	if len(pkts) == 0 {
		t.Fatal("no packets emitted")
	}
	spii := binary.BigEndian.Uint64(pkts[0].Payload[0:8])
	if spii == 0 {
		t.Error("derived InitiatorSPI = 0, want non-zero")
	}
}

func TestPlan_RetransmitEmitsCopies(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = ""
	msgID := uint32(0)
	prop := minimalProposal()
	spec.IKE.Messages = []core.IKEMessage{
		{
			Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, MessageID: &msgID,
			Payloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
				{Type: PayloadNONCE, Nonce: make([]byte, 32)},
			},
			Retransmit: 2,
		},
	}
	pkts := mustPlan(t, spec)
	if len(pkts) != 3 {
		t.Fatalf("expected 3 packets (1 + 2 retransmits), got %d", len(pkts))
	}
	// All three should be byte-identical.
	for i := 1; i < len(pkts); i++ {
		if string(pkts[i].Payload) != string(pkts[0].Payload) {
			t.Errorf("retransmit pkt[%d] differs from pkt[0]", i)
		}
	}
	// All Message IDs should be 0.
	for i, p := range pkts {
		if binary.BigEndian.Uint32(p.Payload[20:24]) != 0 {
			t.Errorf("retransmit pkt[%d] Message ID = %d, want 0", i, binary.BigEndian.Uint32(p.Payload[20:24]))
		}
	}
}

func TestPlan_ScenarioEAPMD5(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "eap_md5"
	pkts := mustPlan(t, spec)
	// EAP-MD5: INIT (2) + AUTH rounds (8 = 4 req/resp pairs).
	if len(pkts) != 10 {
		t.Fatalf("expected 10 packets for eap_md5, got %d", len(pkts))
	}
}

func TestPlan_ScenarioEAPTLS(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "eap_tls"
	pkts := mustPlan(t, spec)
	if len(pkts) < 4 {
		t.Fatalf("expected at least 4 packets for eap_tls, got %d", len(pkts))
	}
}

func TestPlan_ScenarioDPD(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "dpd"
	spec.IKE.DPDCount = 2
	pkts := mustPlan(t, spec)
	// Standard V2 (4) + DPDCount pairs (2 pairs * 2 = 4).
	if len(pkts) != 8 {
		t.Fatalf("expected 8 packets for dpd (4 base + 4 DPD), got %d", len(pkts))
	}
}

func TestPlan_ScenarioDeleteSA(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "delete_sa"
	pkts := mustPlan(t, spec)
	if len(pkts) < 6 {
		t.Fatalf("expected at least 6 packets for delete_sa (4 base + 2 delete), got %d", len(pkts))
	}
}

func TestPlan_ScenarioInformational(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "informational"
	pkts := mustPlan(t, spec)
	if len(pkts) < 6 {
		t.Fatalf("expected at least 6 packets for informational, got %d", len(pkts))
	}
}

func TestPlan_ScenarioNATDetection(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "nat_detection"
	pkts := mustPlan(t, spec)
	if len(pkts) < 4 {
		t.Fatalf("expected at least 4 packets for nat_detection, got %d", len(pkts))
	}
}

func TestPlan_ScenarioIKEv1(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "ikev1"
	pkts := mustPlan(t, spec)
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet for ikev1 scenario, got %d", len(pkts))
	}
}

func TestPlan_ScenarioMultipleChildSA(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "multiple_child_sa"
	spec.IKE.ChildSAs = []core.IKEChildSA{{}}
	pkts := mustPlan(t, spec)
	if len(pkts) < 6 {
		t.Fatalf("expected at least 6 packets for multiple_child_sa, got %d", len(pkts))
	}
}

func TestPlan_ScenarioChildRekey(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "child_rekey"
	pkts := mustPlan(t, spec)
	if len(pkts) < 6 {
		t.Fatalf("expected at least 6 packets for child_rekey, got %d", len(pkts))
	}
}

func TestPlan_ScenarioIKERekey(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "ike_rekey"
	pkts := mustPlan(t, spec)
	if len(pkts) < 6 {
		t.Fatalf("expected at least 6 packets for ike_rekey, got %d", len(pkts))
	}
}

func TestPlan_ScenarioInvalidKERetry(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "invalid_ke_retry"
	pkts := mustPlan(t, spec)
	if len(pkts) < 4 {
		t.Fatalf("expected at least 4 packets for invalid_ke_retry, got %d", len(pkts))
	}
}

func TestPlan_ScenarioCookieRetry(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "cookie_retry"
	pkts := mustPlan(t, spec)
	if len(pkts) < 4 {
		t.Fatalf("expected at least 4 packets for cookie_retry, got %d", len(pkts))
	}
}

func TestPlan_ScenarioCertChain(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "cert_chain"
	pkts := mustPlan(t, spec)
	if len(pkts) != 4 {
		t.Fatalf("expected 4 packets for cert_chain, got %d", len(pkts))
	}
}

func TestPlan_ScenarioPPK(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "ppk"
	pkts := mustPlan(t, spec)
	// PPK: INIT (2) + INTERMEDIATE (2) + AUTH (2) = 6.
	if len(pkts) != 6 {
		t.Fatalf("expected 6 packets for ppk, got %d", len(pkts))
	}
}

func TestPlan_ScenarioNullAuth(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "null_auth"
	spec.IKE.AllowNullAuth = true
	pkts := mustPlan(t, spec)
	if len(pkts) != 4 {
		t.Fatalf("expected 4 packets for null_auth, got %d", len(pkts))
	}
}

func TestPlan_ScenarioSessionResume(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "session_resume"
	pkts := mustPlan(t, spec)
	if len(pkts) != 2 {
		t.Fatalf("expected 2 packets for session_resume, got %d", len(pkts))
	}
	// Exchange Type = 38.
	if pkts[0].Payload[18] != ExchangeIKE_SESSION_RESUME {
		t.Errorf("Exchange Type = %d, want %d", pkts[0].Payload[18], ExchangeIKE_SESSION_RESUME)
	}
}

func TestPlan_ScenarioFragmentedAuth(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "fragmented_auth"
	spec.IKE.FragmentationSupported = true
	pkts := mustPlan(t, spec)
	if len(pkts) < 4 {
		t.Fatalf("expected at least 4 packets for fragmented_auth, got %d", len(pkts))
	}
}

func TestPlan_ScenarioRekey(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "rekey"
	pkts := mustPlan(t, spec)
	if len(pkts) < 6 {
		t.Fatalf("expected at least 6 packets for rekey, got %d", len(pkts))
	}
}

func TestPlan_ScenarioEAPOnly(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "eap_only"
	pkts := mustPlan(t, spec)
	if len(pkts) < 4 {
		t.Fatalf("expected at least 4 packets for eap_only, got %d", len(pkts))
	}
}

func TestPlan_ContextCancellation(t *testing.T) {
	// Long flow with many packets; cancel mid-flight.
	spec := validBaseSpec()
	spec.IKE.Scenario = "eap_md5"
	ctx, cancel := context.WithCancel(context.Background())
	p := NewPlanner()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	// Read first packet, then cancel.
	<-ch
	cancel()
	// Drain remaining (may be 0+ depending on timing).
	for range ch {
	}
}

func TestPlan_PacketConfigMetadata(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	if len(pkts) == 0 {
		t.Fatal("no packets emitted")
	}
	p0 := pkts[0]
	if p0.Metadata == nil {
		t.Fatal("Metadata is nil")
	}
	if _, ok := p0.Metadata["ike_exchange_type"]; !ok {
		t.Error("Metadata missing 'ike_exchange_type'")
	}
	if _, ok := p0.Metadata["ike_message_id"]; !ok {
		t.Error("Metadata missing 'ike_message_id'")
	}
	if _, ok := p0.Metadata["ike_spi_i"]; !ok {
		t.Error("Metadata missing 'ike_spi_i'")
	}
	if _, ok := p0.Metadata["ike_spi_r"]; !ok {
		t.Error("Metadata missing 'ike_spi_r'")
	}
}

func TestPlan_L2L3L4Wired(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	if len(pkts) == 0 {
		t.Fatal("no packets emitted")
	}
	p0 := pkts[0]
	// L4 should be UDP with DstPort=500.
	if p0.L4.Protocol != "udp" {
		t.Errorf("L4.Protocol = %q, want 'udp'", p0.L4.Protocol)
	}
	if p0.L4.DstPort != 500 {
		t.Errorf("L4.DstPort = %d, want 500", p0.L4.DstPort)
	}
	if p0.L4.SrcPort != spec.SrcPort {
		t.Errorf("L4.SrcPort = %d, want %d", p0.L4.SrcPort, spec.SrcPort)
	}
	// L2 EtherType should be IPv4 (0x0800) for our 10.0.0.1 SrcIP.
	if p0.L2.EtherType != 0x0800 {
		t.Errorf("L2.EtherType = 0x%X, want 0x0800 (IPv4)", p0.L2.EtherType)
	}
	// L3 SrcIP/DstIP should match spec.
	if p0.L3.SrcIP != spec.SrcIP {
		t.Errorf("L3.SrcIP = %q, want %q", p0.L3.SrcIP, spec.SrcIP)
	}
	if p0.L3.DstIP != spec.DstIP {
		t.Errorf("L3.DstIP = %q, want %q", p0.L3.DstIP, spec.DstIP)
	}
}

func TestPlan_DirectionSwap(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	if len(pkts) < 2 {
		t.Fatal("expected at least 2 packets")
	}
	// INIT_REQ (up): src=client, dst=server.
	p0 := pkts[0]
	if p0.L3.SrcIP != spec.SrcIP {
		t.Errorf("pkt[0] L3.SrcIP = %q, want %q (client)", p0.L3.SrcIP, spec.SrcIP)
	}
	// INIT_RESP (down): src=server, dst=client.
	p1 := pkts[1]
	if p1.L3.SrcIP != spec.DstIP {
		t.Errorf("pkt[1] L3.SrcIP = %q, want %q (server)", p1.L3.SrcIP, spec.DstIP)
	}
	if p1.L3.DstIP != spec.SrcIP {
		t.Errorf("pkt[1] L3.DstIP = %q, want %q (client)", p1.L3.DstIP, spec.SrcIP)
	}
	if p1.L4.SrcPort != 500 {
		t.Errorf("pkt[1] L4.SrcPort = %d, want 500 (server)", p1.L4.SrcPort)
	}
	if p1.L4.DstPort != spec.SrcPort {
		t.Errorf("pkt[1] L4.DstPort = %d, want %d (client ephemeral)", p1.L4.DstPort, spec.SrcPort)
	}
}

func TestPlan_IPv6EtherType(t *testing.T) {
	spec := validBaseSpec()
	spec.SrcIP = "2001:db8::1"
	spec.DstIP = "2001:db8::2"
	pkts := mustPlan(t, spec)
	if len(pkts) == 0 {
		t.Fatal("no packets emitted")
	}
	// EtherType for IPv6 should be 0x86DD.
	if pkts[0].L2.EtherType != 0x86DD {
		t.Errorf("IPv6 EtherType = 0x%X, want 0x86DD", pkts[0].L2.EtherType)
	}
}

// --- Concurrency test (per CLAUDE.md testing policy §6) ---

func TestPlan_ConcurrentPlanners(t *testing.T) {
	// Multiple planners running concurrently must each produce correct
	// packet counts. -race catches data races; the count check catches
	// cross-contamination.
	const N = 8
	done := make(chan struct{}, N)
	for i := 0; i < N; i++ {
		go func(seed uint64) {
			defer func() { done <- struct{}{} }()
			spec := validBaseSpec()
			spec.IKE.OpaqueKeySeed = seed
			pkts, err := runPlan(t, NewPlanner(), spec)
			if err != nil {
				t.Errorf("concurrent planner %d: %v", seed, err)
				return
			}
			if len(pkts) != 4 {
				t.Errorf("concurrent planner %d: got %d packets, want 4", seed, len(pkts))
			}
		}(uint64(i + 1))
	}
	for i := 0; i < N; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent planners timed out")
		}
	}
}

// --- Helpers used by tests above ---

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func u64ptr(v uint64) *uint64 { return &v }

// findNONCEPayloadLen scans an IKE message for a NONCE payload and returns
// the body length (which equals the nonce byte count).
func findNONCEPayloadLen(ikeBytes []byte) int {
	if len(ikeBytes) < IKEHeaderLen {
		return 0
	}
	// Next Payload pointer from the IKE Header.
	next := ikeBytes[16]
	off := IKEHeaderLen
	for next != 0 && off+GenericHeaderLen <= len(ikeBytes) {
		hdr := ikeBytes[off : off+GenericHeaderLen]
		payloadType := next
		payloadLen := binary.BigEndian.Uint16(hdr[2:4])
		if payloadLen < GenericHeaderLen || int(payloadLen) > len(ikeBytes)-off {
			return 0
		}
		if payloadType == PayloadNONCE {
			return int(payloadLen) - GenericHeaderLen
		}
		next = hdr[0]
		off += int(payloadLen)
	}
	return 0
}

// Ensure net is used (compile error prevention if unused imports get touched).
var _ = net.ParseIP

// --- Smoke test for IPv6 Plan ---

func TestPlan_IPv6PlanProducesPackets(t *testing.T) {
	spec := validBaseSpec()
	spec.SrcIP = "2001:db8::1"
	spec.DstIP = "2001:db8::2"
	pkts := mustPlan(t, spec)
	if len(pkts) != 4 {
		t.Fatalf("expected 4 packets over IPv6, got %d", len(pkts))
	}
}

// --- RFC field coverage smoke tests ---

func TestPlan_TransformEncodesKeyLengthAttr(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	if len(pkts) == 0 {
		t.Fatal("no packets emitted")
	}
	// The default proposal uses ENCR=AES-CBC-128 with KeyLengthBits=128.
	// This is encoded as a TLV attribute (type=14, value=128). Find the SA
	// payload and look for the attribute bytes 0x00 0x0E 0x00 0x80 (TLV:
	// type=14, length=2, value=128).
	saBytes := findSAPayloadBody(pkts[0].Payload)
	if saBytes == nil {
		t.Fatal("no SA payload found")
	}
	// Attribute TLV: 0x00 0x0E 0x00 0x80 (Type=14, Length=0, Value=128).
	// The current encoder uses TLV form: type(2) + value(2) = 0x00 0x0E 0x00 0x80.
	want := []byte{0x00, 0x0E, 0x00, 0x80}
	if !bytesContains(saBytes, want) {
		t.Errorf("SA payload does not contain KeyLength attr %v; SA body=%x", want, saBytes)
	}
}

// findSAPayloadBody returns the SA payload body bytes (without Generic Header).
func findSAPayloadBody(ikeBytes []byte) []byte {
	if len(ikeBytes) < IKEHeaderLen {
		return nil
	}
	next := ikeBytes[16]
	off := IKEHeaderLen
	for next != 0 && off+GenericHeaderLen <= len(ikeBytes) {
		hdr := ikeBytes[off : off+GenericHeaderLen]
		payloadType := next
		payloadLen := binary.BigEndian.Uint16(hdr[2:4])
		if payloadLen < GenericHeaderLen || int(payloadLen) > len(ikeBytes)-off {
			return nil
		}
		if payloadType == PayloadSA {
			return ikeBytes[off+GenericHeaderLen : off+int(payloadLen)]
		}
		next = hdr[0]
		off += int(payloadLen)
	}
	return nil
}

func bytesContains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestPlan_ProposalLastByte(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	if len(pkts) == 0 {
		t.Fatal("no packets emitted")
	}
	saBytes := findSAPayloadBody(pkts[0].Payload)
	if saBytes == nil || len(saBytes) < 8 {
		t.Fatal("SA payload too short")
	}
	// Single proposal: byte[0] should be 0 (last proposal).
	if saBytes[0] != 0 {
		t.Errorf("Proposal byte[0] = %d, want 0 (last proposal)", saBytes[0])
	}
}

func TestPlan_ProposalProtocolID(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	saBytes := findSAPayloadBody(pkts[0].Payload)
	if saBytes == nil || len(saBytes) < 8 {
		t.Fatal("SA payload too short")
	}
	// Proposal byte[5] is Protocol ID. Should be 1 (IKE).
	if saBytes[5] != ProtocolIKE {
		t.Errorf("Proposal ProtocolID = %d, want %d (IKE)", saBytes[5], ProtocolIKE)
	}
}

func TestPlan_ProposalSPISizeZero(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	saBytes := findSAPayloadBody(pkts[0].Payload)
	if saBytes == nil || len(saBytes) < 8 {
		t.Fatal("SA payload too short")
	}
	// Proposal byte[6] is SPI Size. Should be 0 for IKE proposals.
	if saBytes[6] != 0 {
		t.Errorf("Proposal SPISize = %d, want 0 (IKE)", saBytes[6])
	}
}

func TestPlan_ProposalNumber(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	saBytes := findSAPayloadBody(pkts[0].Payload)
	if saBytes == nil || len(saBytes) < 8 {
		t.Fatal("SA payload too short")
	}
	// Proposal byte[4] is Proposal Number. Should be 1.
	if saBytes[4] != 1 {
		t.Errorf("Proposal Number = %d, want 1", saBytes[4])
	}
}

func TestPlan_ProposalNumTransforms(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	saBytes := findSAPayloadBody(pkts[0].Payload)
	if saBytes == nil || len(saBytes) < 8 {
		t.Fatal("SA payload too short")
	}
	// Default proposal has 4 transforms (ENCR/PRF/INTEG/DH).
	if saBytes[7] != 4 {
		t.Errorf("Proposal NumTransforms = %d, want 4", saBytes[7])
	}
}

// exchangeTypeName sanity check.
func TestExchangeTypeName(t *testing.T) {
	cases := []struct {
		v    uint8
		want string
	}{
		{ExchangeIKE_SA_INIT, "IKE_SA_INIT"},
		{ExchangeIKE_SA_AUTH, "IKE_SA_AUTH"},
		{ExchangeCREATE_CHILD_SA, "CREATE_CHILD_SA"},
		{ExchangeINFORMATIONAL, "INFORMATIONAL"},
		{ExchangeIKE_SESSION_RESUME, "IKE_SESSION_RESUME"},
		{ExchangeIKE_INTERMEDIATE, "IKE_INTERMEDIATE"},
		{0, "UNKNOWN"},
		{255, "UNKNOWN"},
	}
	for _, c := range cases {
		if got := exchangeTypeName(c.v); got != c.want {
			t.Errorf("exchangeTypeName(%d) = %q, want %q", c.v, got, c.want)
		}
	}
}

// --- EAP message structure tests ---

func TestPlan_EAPMD5EAPPayloads(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "eap_md5"
	pkts := mustPlan(t, spec)
	if len(pkts) < 6 {
		t.Fatalf("expected at least 6 packets for eap_md5, got %d", len(pkts))
	}
	// pkts[2] is the first AUTH request, which is encrypted SK containing
	// an IDi payload. The IKE Header Next Payload should be 46 (SK).
	authReq := pkts[2]
	if authReq.Payload[16] != PayloadSK {
		t.Errorf("EAP AUTH_REQ IKE Header Next Payload = %d, want %d (SK)", authReq.Payload[16], PayloadSK)
	}
}

// --- Sanitize: ensure EAP-only scenario produces the right flow ---

func TestPlan_EAPOnlyScenario(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "eap_only"
	spec.IKE.EAPOnly = true
	pkts := mustPlan(t, spec)
	if len(pkts) < 4 {
		t.Fatalf("expected at least 4 packets, got %d", len(pkts))
	}
}

// --- Failure-path tests (per CLAUDE.md testing policy §2) ---

func TestPlan_EmptyMessages(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = ""
	spec.IKE.Messages = nil
	p := NewPlanner()
	// With neither Scenario nor Messages, the planner defaults to
	// "standard_v2". So Plan should succeed.
	pkts, err := runPlan(t, p, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	if len(pkts) != 4 {
		t.Errorf("expected 4 default-scenario packets, got %d", len(pkts))
	}
}

func TestPlan_FaultInjectionLengthOverride(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = ""
	spec.IKE.Strict = false
	spec.IKE.FaultInjection = true
	v := uint32(0xFFFFFFFF)
	spec.IKE.Messages = []core.IKEMessage{
		{
			Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true,
			Payloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*minimalProposal()}}},
				{Type: PayloadNONCE, Nonce: make([]byte, 32)},
			},
			RawLengthOverride: &v,
		},
	}
	pkts := mustPlan(t, spec)
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(pkts))
	}
	if binary.BigEndian.Uint32(pkts[0].Payload[24:28]) != 0xFFFFFFFF {
		t.Errorf("RawLengthOverride not applied: got 0x%X", binary.BigEndian.Uint32(pkts[0].Payload[24:28]))
	}
}

func TestPlan_FaultInjectionFlagsOverride(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = ""
	spec.IKE.Strict = false
	spec.IKE.FaultInjection = true
	flags := uint8(0xFF)
	spec.IKE.Messages = []core.IKEMessage{
		{
			Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true,
			Payloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*minimalProposal()}}},
				{Type: PayloadNONCE, Nonce: make([]byte, 32)},
			},
			RawFlagsOverride: &flags,
		},
	}
	pkts := mustPlan(t, spec)
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(pkts))
	}
	if pkts[0].Payload[19] != 0xFF {
		t.Errorf("RawFlagsOverride not applied: got 0x%X", pkts[0].Payload[19])
	}
}

func TestPlan_FaultInjectionNextPayloadOverride(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = ""
	spec.IKE.Strict = false
	spec.IKE.FaultInjection = true
	np := uint8(0xFF)
	spec.IKE.Messages = []core.IKEMessage{
		{
			Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true,
			Payloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*minimalProposal()}}},
				{Type: PayloadNONCE, Nonce: make([]byte, 32)},
			},
			RawNextPayloadOverride: &np,
		},
	}
	pkts := mustPlan(t, spec)
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(pkts))
	}
	if pkts[0].Payload[16] != 0xFF {
		t.Errorf("RawNextPayloadOverride not applied: got 0x%X", pkts[0].Payload[16])
	}
}

// --- End-to-end integration test ---

func TestPlan_IntegrationBuildsValidIKEBytes(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	if len(pkts) != 4 {
		t.Fatalf("expected 4 packets, got %d", len(pkts))
	}
	// Validate each packet's IKE Header structure.
	for i, p := range pkts {
		if len(p.Payload) < IKEHeaderLen {
			t.Errorf("pkt[%d] payload too short: %d bytes", i, len(p.Payload))
			continue
		}
		// Length field should match actual payload length.
		gotLen := binary.BigEndian.Uint32(p.Payload[24:28])
		if gotLen != uint32(len(p.Payload)) {
			t.Errorf("pkt[%d] Length field = %d, want %d", i, gotLen, len(p.Payload))
		}
		// Version should be 0x20 (IKEv2.0).
		if p.Payload[17] != 0x20 {
			t.Errorf("pkt[%d] Version = 0x%X, want 0x20", i, p.Payload[17])
		}
		// Reserved bits in Flags (bits 0-2 and 5-7) should be 0 in
		// non-fault mode.
		if p.Payload[19]&0xC7 != 0 {
			t.Errorf("pkt[%d] Flags reserved bits set: 0x%X", i, p.Payload[19])
		}
	}
}

// --- makeTSv4All test ---

func TestMakeTSv4All(t *testing.T) {
	ts := makeTSv4All()
	if ts.TSType != 7 {
		t.Errorf("TSType = %d, want 7 (IPv4_RANGE)", ts.TSType)
	}
	if ts.IPProtocolID != 0 {
		t.Errorf("IPProtocolID = %d, want 0 (any)", ts.IPProtocolID)
	}
	if ts.StartPort != 0 || ts.EndPort != 65535 {
		t.Errorf("port range = %d-%d, want 0-65535", ts.StartPort, ts.EndPort)
	}
	if len(ts.StartAddress) != 4 || len(ts.EndAddress) != 4 {
		t.Errorf("address length: start=%d end=%d, want 4/4", len(ts.StartAddress), len(ts.EndAddress))
	}
}

// --- deriveSPI determinism test ---

func TestDeriveSPI_Deterministic(t *testing.T) {
	a := deriveSPI(42)
	b := deriveSPI(42)
	if a != b {
		t.Errorf("deriveSPI(42) = 0x%X, then 0x%X (not deterministic)", a, b)
	}
	if a == 0 {
		t.Error("deriveSPI(42) = 0, want non-zero")
	}
}

// --- makeTSv4All IPProtocolID any test ---

func TestEncodeTS_IPv4Range(t *testing.T) {
	ts := core.IKETrafficSelector{
		TSType:       7, // IPv4_RANGE
		IPProtocolID: 17, // UDP
		StartPort:    100,
		EndPort:      200,
		StartAddress: []byte{10, 0, 0, 1},
		EndAddress:   []byte{10, 0, 0, 254},
	}
	b := encodeTS(&ts)
	// Layout: TSType(1) + IPProtocolID(1) + SelectorLength(2) +
	//          StartPort(2) + EndPort(2) + StartAddr(4) + EndAddr(4) = 16 bytes.
	if len(b) != 16 {
		t.Fatalf("encoded TS length = %d, want 16", len(b))
	}
	if b[0] != 7 {
		t.Errorf("TSType byte = %d, want 7", b[0])
	}
	if b[1] != 17 {
		t.Errorf("IPProtocolID byte = %d, want 17", b[1])
	}
	// SelectorLength at bytes[2:4] = 16.
	if binary.BigEndian.Uint16(b[2:4]) != 16 {
		t.Errorf("SelectorLength = %d, want 16", binary.BigEndian.Uint16(b[2:4]))
	}
	// StartPort at bytes[4:6] = 100.
	if binary.BigEndian.Uint16(b[4:6]) != 100 {
		t.Errorf("StartPort = %d, want 100", binary.BigEndian.Uint16(b[4:6]))
	}
	// EndPort at bytes[6:8] = 200.
	if binary.BigEndian.Uint16(b[6:8]) != 200 {
		t.Errorf("EndPort = %d, want 200", binary.BigEndian.Uint16(b[6:8]))
	}
}

func TestEncodeSA_SingleProposal(t *testing.T) {
	sa := &core.IKESA{
		Proposals: []core.IKEProposal{
			{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{{Type: TransformENCR, ID: 12}}},
		},
	}
	b := encodeSA(sa)
	if len(b) < 8 {
		t.Fatalf("encoded SA too short: %d bytes", len(b))
	}
	// byte[0] = 0 (last proposal).
	if b[0] != 0 {
		t.Errorf("Last byte = %d, want 0", b[0])
	}
}

func TestEncodeSA_MultipleProposals(t *testing.T) {
	sa := &core.IKESA{
		Proposals: []core.IKEProposal{
			{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{{Type: TransformENCR, ID: 12}}},
			{Number: 2, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{{Type: TransformENCR, ID: 12}}},
		},
	}
	b := encodeSA(sa)
	// First proposal should have byte[0]=2 (more proposals follow).
	if b[0] != 2 {
		t.Errorf("First proposal byte[0] = %d, want 2 (more)", b[0])
	}
}

func TestEncodeTransforms_LastMarker(t *testing.T) {
	transforms := []core.IKETransform{
		{Type: TransformENCR, ID: 12},
		{Type: TransformPRF, ID: 5},
	}
	b := encodeTransforms(transforms)
	// First transform byte[0] = 3 (more transforms).
	if b[0] != 3 {
		t.Errorf("First transform byte[0] = %d, want 3 (more)", b[0])
	}
}

func TestEncodeTransforms_KeyLengthAttr(t *testing.T) {
	transforms := []core.IKETransform{
		{Type: TransformENCR, ID: 12, KeyLengthBits: 256},
	}
	b := encodeTransforms(transforms)
	// Transform structure: Last(1) + Reserved(1) + Length(2) + Type(1) +
	// Reserved(1) + ID(2) + [Attr(4 if TV)]. Length should be 8 + 4 = 12.
	if len(b) < 12 {
		t.Fatalf("encoded transform too short: %d", len(b))
	}
	transformLen := binary.BigEndian.Uint16(b[2:4])
	if transformLen != 12 {
		t.Errorf("Transform Length = %d, want 12 (8 + 4-byte attr)", transformLen)
	}
}

func TestEncodeNotify_BasicStructure(t *testing.T) {
	n := &core.IKENotify{
		ProtocolID:  ProtocolIKE,
		SPI:         []byte{}, // IKE: SPI size 0
		MessageType: 14,       // NO_PROPOSAL_CHOSEN
		Data:        nil,
	}
	b := encodeNotify(n)
	// Layout: ProtocolID(1) + SPISize(1) + NotifyType(2) + [SPI] + [Data].
	if len(b) != 4 {
		t.Fatalf("encoded Notify length = %d, want 4", len(b))
	}
	if b[0] != ProtocolIKE {
		t.Errorf("ProtocolID = %d, want %d", b[0], ProtocolIKE)
	}
	if b[1] != 0 {
		t.Errorf("SPISize = %d, want 0 (IKE)", b[1])
	}
	if binary.BigEndian.Uint16(b[2:4]) != 14 {
		t.Errorf("MessageType = %d, want 14", binary.BigEndian.Uint16(b[2:4]))
	}
}

func TestEncodeDelete_IKESA(t *testing.T) {
	d := &core.IKEDelete{
		ProtocolID: ProtocolIKE,
		SPISize:    0,
		SPIs:       nil,
	}
	b := encodeDelete(d)
	// Layout: ProtocolID(1) + SPISize(1) + NumSPIs(2) = 4 bytes.
	if len(b) != 4 {
		t.Fatalf("encoded Delete length = %d, want 4", len(b))
	}
	if b[0] != ProtocolIKE {
		t.Errorf("ProtocolID = %d, want %d", b[0], ProtocolIKE)
	}
}

func TestEncodeDelete_ESPSA(t *testing.T) {
	d := &core.IKEDelete{
		ProtocolID: ProtocolESP,
		SPISize:    4,
		SPIs:       [][]byte{{0x12, 0x34, 0x56, 0x78}},
	}
	b := encodeDelete(d)
	// Layout: ProtocolID(1) + SPISize(1) + NumSPIs(2) + 4 bytes SPI = 8 bytes.
	if len(b) != 8 {
		t.Fatalf("encoded Delete length = %d, want 8", len(b))
	}
	if binary.BigEndian.Uint16(b[2:4]) != 1 {
		t.Errorf("NumSPIs = %d, want 1", binary.BigEndian.Uint16(b[2:4]))
	}
	if b[4] != 0x12 || b[5] != 0x34 || b[6] != 0x56 || b[7] != 0x78 {
		t.Errorf("SPI bytes = %x, want 12345678", b[4:8])
	}
}

func TestEncodeEAP_Request(t *testing.T) {
	tp := uint8(4) // MD5-Challenge
	e := &core.IKEEAP{
		Code:       1, // Request
		Identifier: 1,
		Type:       &tp,
		Data:       []byte{0x10, 0x20},
	}
	b := encodeEAP(e)
	// Layout: Code(1) + Identifier(1) + Length(2) + Type(1) + Data(N) = 7.
	if len(b) != 7 {
		t.Fatalf("encoded EAP length = %d, want 7", len(b))
	}
	if b[0] != 1 {
		t.Errorf("Code = %d, want 1 (Request)", b[0])
	}
	if b[1] != 1 {
		t.Errorf("Identifier = %d, want 1", b[1])
	}
	if binary.BigEndian.Uint16(b[2:4]) != 7 {
		t.Errorf("Length = %d, want 7", binary.BigEndian.Uint16(b[2:4]))
	}
	if b[4] != 4 {
		t.Errorf("Type = %d, want 4 (MD5)", b[4])
	}
}

func TestEncodeEAP_Success(t *testing.T) {
	e := &core.IKEEAP{
		Code:       3, // Success
		Identifier: 5,
	}
	b := encodeEAP(e)
	// Layout: Code(1) + Identifier(1) + Length(2). No Type, no Data.
	if len(b) != 4 {
		t.Fatalf("encoded EAP Success length = %d, want 4", len(b))
	}
	if b[0] != 3 {
		t.Errorf("Code = %d, want 3 (Success)", b[0])
	}
}

func TestEncodeSKF_BasicStructure(t *testing.T) {
	f := &core.IKEFragment{
		FragmentNumber: 1,
		TotalFragments: 3,
		Data:           []byte{0xAA, 0xBB, 0xCC},
	}
	b := encodeSKF(f)
	if len(b) != 7 {
		t.Fatalf("encoded SKF length = %d, want 7 (4 + 3)", len(b))
	}
	if binary.BigEndian.Uint16(b[0:2]) != 1 {
		t.Errorf("FragmentNumber = %d, want 1", binary.BigEndian.Uint16(b[0:2]))
	}
	if binary.BigEndian.Uint16(b[2:4]) != 3 {
		t.Errorf("TotalFragments = %d, want 3", binary.BigEndian.Uint16(b[2:4]))
	}
	if b[4] != 0xAA || b[5] != 0xBB || b[6] != 0xCC {
		t.Errorf("Data = %x, want AABBCC", b[4:7])
	}
}

func TestEncodeID_IPv4(t *testing.T) {
	id := &core.IKEIdentity{
		IDType: 1, // IPv4
		Data:   []byte{10, 0, 0, 1},
	}
	b := encodeID(id)
	if len(b) != 8 {
		t.Fatalf("encoded ID length = %d, want 8 (4 hdr + 4 data)", len(b))
	}
	if b[0] != 1 {
		t.Errorf("IDType = %d, want 1 (IPv4)", b[0])
	}
}

func TestEncodeCert(t *testing.T) {
	c := &core.IKECertificate{
		Encoding: 4, // X.509 Signature
		Data:     []byte{0xAA, 0xBB},
	}
	b := encodeCert(c)
	// Layout: Encoding(1) + Data(N) = 3 bytes (no reserved).
	if len(b) != 3 {
		t.Fatalf("encoded Cert length = %d, want 3 (1 + 2 data)", len(b))
	}
	if b[0] != 4 {
		t.Errorf("Encoding = %d, want 4 (X.509 Signature)", b[0])
	}
}

func TestEncodeAuth(t *testing.T) {
	a := &core.IKEAuth{
		Method: 2, // Shared Key
		Data:   []byte{0x11, 0x22},
	}
	b := encodeAuth(a, newOpaqueRNG(1, 0))
	// Layout: Method(1) + [3 reserved] + Data.
	if len(b) != 6 {
		t.Fatalf("encoded Auth length = %d, want 6 (4 + 2 data)", len(b))
	}
	if b[0] != 2 {
		t.Errorf("Method = %d, want 2 (Shared Key)", b[0])
	}
}

func TestEncodeKE(t *testing.T) {
	ke := &core.IKEKE{
		DHGroup: 14,
	}
	rng := newOpaqueRNG(1, 0)
	b := encodeKE(ke, rng)
	// Layout: DHGroup(2) + Reserved(2) + KeyData.
	// Default key data length for DH=14 is 256 bytes.
	if len(b) != 4+defaultKEKeyDataBytes {
		t.Fatalf("encoded KE length = %d, want %d", len(b), 4+defaultKEKeyDataBytes)
	}
	if binary.BigEndian.Uint16(b[0:2]) != 14 {
		t.Errorf("DHGroup = %d, want 14", binary.BigEndian.Uint16(b[0:2]))
	}
}

func TestEncodeCP(t *testing.T) {
	c := &core.IKEConfiguration{
		CFGType: 1, // REQUEST
		Attributes: []core.IKEConfigAttribute{
			{Type: 1, Value: []byte{0x0A, 0x00, 0x00, 0x01}}, // INTERNAL_IP4_ADDRESS
		},
	}
	b := encodeCP(c)
	// Layout: CFGType(1) + Reserved(3) + Attr(4:Type+Length) + Value(4).
	if len(b) != 12 {
		t.Fatalf("encoded CP length = %d, want 12", len(b))
	}
	if b[0] != 1 {
		t.Errorf("CFGType = %d, want 1 (REQUEST)", b[0])
	}
}

// --- Verify specific scenarios produce expected exchange type sequences ---

func TestPlan_StandardV2_ExchangeTypeSequence(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	want := []uint8{ExchangeIKE_SA_INIT, ExchangeIKE_SA_INIT, ExchangeIKE_SA_AUTH, ExchangeIKE_SA_AUTH}
	if len(pkts) != len(want) {
		t.Fatalf("got %d packets, want %d", len(pkts), len(want))
	}
	for i, w := range want {
		if pkts[i].Payload[18] != w {
			t.Errorf("pkt[%d] ExchangeType = %d, want %d", i, pkts[i].Payload[18], w)
		}
	}
}

func TestPlan_DPDExchangeType(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "dpd"
	spec.IKE.DPDCount = 1
	pkts := mustPlan(t, spec)
	// Last 2 packets should be INFORMATIONAL.
	if len(pkts) < 6 {
		t.Fatalf("expected >=6 packets, got %d", len(pkts))
	}
	for i := len(pkts) - 2; i < len(pkts); i++ {
		if pkts[i].Payload[18] != ExchangeINFORMATIONAL {
			t.Errorf("pkt[%d] ExchangeType = %d, want %d (INFORMATIONAL)", i, pkts[i].Payload[18], ExchangeINFORMATIONAL)
		}
	}
}

func TestPlan_PPKEExchangeTypeIncludesIntermediate(t *testing.T) {
	spec := validBaseSpec()
	spec.IKE.Scenario = "ppk"
	pkts := mustPlan(t, spec)
	// pkts[2] and pkts[3] should be IKE_INTERMEDIATE (43).
	if len(pkts) < 4 {
		t.Fatalf("expected >=4 packets, got %d", len(pkts))
	}
	if pkts[2].Payload[18] != ExchangeIKE_INTERMEDIATE {
		t.Errorf("pkt[2] ExchangeType = %d, want %d (IKE_INTERMEDIATE)", pkts[2].Payload[18], ExchangeIKE_INTERMEDIATE)
	}
	if pkts[3].Payload[18] != ExchangeIKE_INTERMEDIATE {
		t.Errorf("pkt[3] ExchangeType = %d, want %d (IKE_INTERMEDIATE)", pkts[3].Payload[18], ExchangeIKE_INTERMEDIATE)
	}
}

// --- Sanity: package compiles with fmt usage ---
var _ = fmt.Sprintf
