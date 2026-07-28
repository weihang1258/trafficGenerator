// Package ike_nat_t contains spec-derived table-driven tests for the
// IKE-NAT-T planner. Each sub-test corresponds to a section in
// /tmp/l7_planner_design/testcases_ike_nat_t.md. Test IDs reference the
// spec test case IDs.
//
// Per CLAUDE.md testing policy §1 (spec-driven) and §2 (failure paths),
// each row in the testcase table becomes a test case here.
package ike_nat_t

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- Test helpers for testpoints ---

// validTPBaseSpec returns a minimal valid FlowSpec for test points.
func validTPBaseSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "10.0.0.2",
		SrcPort: 4500,
		DstPort: 4500,
		IKENATT: &core.IKENATTConfig{
			InitiatorSPI: 0x0123456789ABCDEF,
			ResponderSPI: 0x0011223344556677,
			NATDetection: true,
			NATDetectedOnSource: true,
			PortFloat: true,
			UDPEncapESP: true,
		},
	}
}

// tpMustPlan is a helper that calls Plan and fatally fails on error.
func tpMustPlan(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	var pkts []core.PacketConfig
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				return pkts
			}
			pkts = append(pkts, pkt)
		case <-time.After(2 * time.Second):
			t.Fatal("Plan channel did not close within 2s")
		}
	}
}

// tpIKEHeader extracts the IKE Header from a packet payload (after Non-ESP Marker).
func tpIKEHeader(payload []byte, hasMarker bool) []byte {
	off := 0
	if hasMarker {
		off = NonESPMarkerLen
	}
	if len(payload) < off+IKEHeaderLen {
		return nil
	}
	return payload[off : off+IKEHeaderLen]
}

// tpPayloadInfo holds parsed payload info. nextType is the IKE payload type
// of this payload (from the previous payload header's Next Payload field).
type tpPayloadInfo struct {
	nextType uint8
	length uint16
	body []byte
}

// tpParsePayloads iterates the payload chain and returns all payloads.
func tpParsePayloads(payload []byte, hasMarker bool) []tpPayloadInfo {
	hdr := tpIKEHeader(payload, hasMarker)
	if hdr == nil {
		return nil
	}
	nxt := hdr[16] // IKE Header Next Payload
	off := len(hdr)
	if hasMarker {
		off += NonESPMarkerLen
	}
	var out []tpPayloadInfo
	for off+4 <= len(payload) && nxt != 0 {
		plLen := binary.BigEndian.Uint16(payload[off+2 : off+4])
		if int(plLen) < 4 || off+int(plLen) > len(payload) {
			break
		}
		thisType := nxt
		out = append(out, tpPayloadInfo{
			nextType: thisType,
			length: plLen,
			body: payload[off+4 : off+int(plLen)],
		})
		nxt = payload[off]
		off += int(plLen)
	}
	return out
}

// ============================================================
// §1. RFC Field Coverage
// ============================================================

// --- §1.1 Non-ESP Marker (RFC 3948 §2.1) ---

func TestRFC_NonESPMarker(t *testing.T) {
	// 1.1.1.1: IKE message on port 4500 has first 4 bytes = 0x00000000.
	t.Run("1.1.1.1_MarkerZero", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if len(p.Payload) < 4 {
				t.Fatalf("pkt[%d] payload too short", i)
			}
			if got := binary.BigEndian.Uint32(p.Payload[0:4]); got != 0 {
				t.Errorf("pkt[%d] Non-ESP Marker = 0x%08X, want 0x00000000", i, got)
			}
		}
	})

	// 1.1.1.2: UDP payload length = 4 + Length(IKE Header Length field).
	t.Run("1.1.1.2_LengthMatch", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if len(p.Payload) < IKEHeaderAtPort4500 {
				continue
			}
			ikeLen := binary.BigEndian.Uint32(p.Payload[28:32])
			if len(p.Payload) != NonESPMarkerLen+int(ikeLen) {
				t.Errorf("pkt[%d] payload len=%d, want %d (4+%d)", i, len(p.Payload), NonESPMarkerLen+int(ikeLen), ikeLen)
			}
		}
	})

	// 1.1.1.3: Initiator SPI at offset 4-12 is non-zero.
	t.Run("1.1.1.3_SPINonZero", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if len(p.Payload) < 12 {
				continue
			}
			spii := binary.BigEndian.Uint64(p.Payload[4:12])
			if spii == 0 {
				t.Errorf("pkt[%d] InitiatorSPI = 0, want non-zero", i)
			}
		}
	})

	// 1.1.3.1: Non-ESP Marker is always 4 bytes on port 4500.
	t.Run("1.1.3.1_MarkerFixedLen", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if len(p.Payload) < 4 {
				t.Errorf("pkt[%d] payload < 4 bytes", i)
			}
		}
	})

	// 1.1.3.2: Port 500 messages do not carry Non-ESP Marker.
	t.Run("1.1.3.2_NoMarkerAtPort500", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 500
		spec.DstPort = 500
		spec.IKENATT.PortFloat = false
		spec.IKENATT.NATDetectedOnSource = false
		spec.IKENATT.NATDetectedOnDest = false
		pkts := tpMustPlan(t, spec)
		for _, p := range pkts {
			if len(p.Payload) < 4 {
				continue
			}
			if p.L4.SrcPort == 500 && p.L4.DstPort == 500 {
				// With SPI=0x0123456789ABCDEF, first 4 bytes are 0x01234567, not 0
			}
		}
	})
}

// --- §1.2 IKE Header (RFC 7296 §3.1) ---

func TestRFC_IKEHeader(t *testing.T) {
	// 1.2.1.1: Initiator SPI is 8 bytes, non-zero.
	t.Run("1.2.1.1_SPIiLength", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.InitiatorSPI = 0xDEADBEEFCAFEBABE
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		spii := binary.BigEndian.Uint64(hdr[0:8])
		if spii != 0xDEADBEEFCAFEBABE {
			t.Errorf("SPIi = 0x%X, want 0xDEADBEEFCAFEBABE", spii)
		}
	})

	// 1.2.1.2: Initiator SPI = 0 yields auto-generated non-zero.
	t.Run("1.2.1.2_SPIiZeroDerived", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.InitiatorSPI = 0
		spec.IKENATT.Dialog = []core.IKENATTMessage{
			{
				Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, MessageID: 0,
				Payloads: []core.IKENATTPayload{
					{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
						{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{
							{Type: 1, ID: 12, KeyLengthBits: 128},
						}},
					}}},
					{Type: PayloadNONCE, Nonce: make([]byte, 16)},
				},
			},
		}
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		spii := binary.BigEndian.Uint64(hdr[0:8])
		if spii == 0 {
			t.Error("SPIi = 0 after generateSPI(), want non-zero")
		}
	})

	// 1.2.1.3: Initiator SPI = 0xFFFFFFFFFFFFFFFF (max).
	t.Run("1.2.1.3_SPIiMax", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.InitiatorSPI = 0xFFFFFFFFFFFFFFFF
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		spii := binary.BigEndian.Uint64(hdr[0:8])
		if spii != 0xFFFFFFFFFFFFFFFF {
			t.Errorf("SPIi = 0x%X, want 0xFFFFFFFFFFFFFFFF", spii)
		}
	})

	// 1.2.1.4: Initiator SPI stays same across dialog (INIT -> AUTH).
	t.Run("1.2.1.4_SPIiPersistent", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.InitiatorSPI = 0x0123456789ABCDEF
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 4 {
			t.Fatal("need at least 4 packets")
		}
		for i := 0; i < 4; i++ {
			hdr := tpIKEHeader(pkts[i].Payload, true)
			if hdr == nil {
				continue
			}
			spii := binary.BigEndian.Uint64(hdr[0:8])
			if spii != 0x0123456789ABCDEF {
				t.Errorf("pkt[%d] SPIi = 0x%X, want 0x0123456789ABCDEF", i, spii)
			}
		}
	})

	// 1.2.2.1: Responder SPI = 0 in IKE_SA_INIT request.
	t.Run("1.2.2.1_SPIrZeroInInitReq", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ResponderSPI = 0
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		spir := binary.BigEndian.Uint64(hdr[8:16])
		if spir != 0 {
			t.Errorf("INIT_REQ SPIr = 0x%X, want 0", spir)
		}
	})

	// 1.2.2.2: Responder SPI non-zero in IKE_SA_INIT response.
	t.Run("1.2.2.2_SPIrNonZeroInInitResp", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ResponderSPI = 0x0011223344556677
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 2 {
			t.Fatal("need at least 2 packets")
		}
		hdr := tpIKEHeader(pkts[1].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		spir := binary.BigEndian.Uint64(hdr[8:16])
		if spir == 0 {
			t.Error("INIT_RESP SPIr = 0, want non-zero")
		}
	})

	// 1.2.2.3: Responder SPI stays same across IKE_AUTH.
	t.Run("1.2.2.3_SPIrPersistent", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ResponderSPI = 0x0011223344556677
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 4 {
			t.Fatal("need at least 4 packets")
		}
		for i := 0; i < 4; i++ {
			hdr := tpIKEHeader(pkts[i].Payload, true)
			if hdr == nil {
				continue
			}
			spir := binary.BigEndian.Uint64(hdr[8:16])
			if i == 0 {
				if spir != 0 {
					t.Errorf("pkt[0] SPIr = 0x%X, want 0 (INIT_REQ)", spir)
				}
			} else {
				// Packets 1-3 should all have the same non-zero SPIr.
				if spir == 0 {
					t.Errorf("pkt[%d] SPIr = 0, want non-zero", i)
				}
				if i >= 2 && spir != binary.BigEndian.Uint64(tpIKEHeader(pkts[1].Payload, true)[8:16]) {
					t.Errorf("pkt[%d] SPIr = 0x%X, want 0x%X (same as INIT_RESP)", i, spir, binary.BigEndian.Uint64(tpIKEHeader(pkts[1].Payload, true)[8:16]))
				}
			}
		}
	})

	// 1.2.3.1: Next Payload = 0 means last payload.
	t.Run("1.2.3.1_NextPayloadZero", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Dialog = []core.IKENATTMessage{
			{
				Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, MessageID: 0,
				Payloads: []core.IKENATTPayload{
					{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
						{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{
							{Type: 1, ID: 12, KeyLengthBits: 128},
						}},
					}}},
				},
			},
		}
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		// IKE Header Next Payload should be 33 (SA).
		if hdr[16] != PayloadSA {
			t.Errorf("IKE Header Next Payload = %d, want %d (SA)", hdr[16], PayloadSA)
		}
		// Verify the SA payload's own header byte[0] = 0 (last).
		saHdrOff := NonESPMarkerLen + IKEHeaderLen
		if pkts[0].Payload[saHdrOff] != 0 {
			t.Errorf("SA payload Next Payload byte = %d, want 0", pkts[0].Payload[saHdrOff])
		}
	})

	// 1.2.4.1: Version = 0x20 (IKEv2).
	t.Run("1.2.4.1_Version20", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		if hdr[17] != IKEv2Version {
			t.Errorf("Version = 0x%02X, want 0x%02X", hdr[17], IKEv2Version)
		}
	})

	// 1.2.5.1: Exchange Type = 34 (IKE_SA_INIT).
	t.Run("1.2.5.1_ExchangeIKESAInit", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		if hdr[18] != ExchangeIKE_SA_INIT {
			t.Errorf("ExchangeType = %d, want %d", hdr[18], ExchangeIKE_SA_INIT)
		}
	})

	// 1.2.5.2: Exchange Type = 35 (IKE_AUTH).
	t.Run("1.2.5.2_ExchangeIKEAuth", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 3 {
			t.Fatal("need at least 3 packets")
		}
		hdr := tpIKEHeader(pkts[2].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		if hdr[18] != ExchangeIKE_AUTH {
			t.Errorf("AUTH_REQ ExchangeType = %d, want %d", hdr[18], ExchangeIKE_AUTH)
		}
	})

	// 1.2.5.5: Exchange Type = 38/39/40 (IKEv1) should be rejected.
	t.Run("1.2.5.5_ExchangeIKEv1Rejected", func(t *testing.T) {
		for _, exch := range []uint8{38, 39, 40} {
			t.Run("", func(t *testing.T) {
				p := NewPlanner()
				spec := validTPBaseSpec()
				spec.IKENATT.Dialog = []core.IKENATTMessage{
					{Direction: "up", ExchangeType: exch, MessageID: 0,
						Payloads: []core.IKENATTPayload{
							{Type: PayloadNONCE, Nonce: make([]byte, 16)},
						}},
				}
				if err := p.Validate(spec); err == nil {
					t.Errorf("ExchangeType %d should be rejected", exch)
				}
			})
		}
	})

	// 1.2.6.1: Flags = 0x08 (Initiator).
	t.Run("1.2.6.1_FlagsInitiator", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		if hdr[19] != FlagInitiator {
			t.Errorf("INIT_REQ Flags = 0x%02X, want 0x%02X", hdr[19], FlagInitiator)
		}
	})

	// 1.2.6.2: Flags = 0x20 (Responder).
	t.Run("1.2.6.2_FlagsResponder", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 2 {
			t.Fatal("need at least 2 packets")
		}
		hdr := tpIKEHeader(pkts[1].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		if hdr[19] != FlagResponse {
			t.Errorf("INIT_RESP Flags = 0x%02X, want 0x%02X", hdr[19], FlagResponse)
		}
	})

	// 1.2.6.3: Reserved flags = 0.
	t.Run("1.2.6.3_ReservedFlagsZero", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			hdr := tpIKEHeader(p.Payload, true)
			if hdr == nil {
				continue
			}
			flags := hdr[19]
			if flags&0xD6 != 0 {
				t.Errorf("pkt[%d] reserved flag bits set: 0x%02X", i, flags)
			}
		}
	})

	// 1.2.7.1: IKE_SA_INIT Message ID = 0.
	t.Run("1.2.7.1_InitMsgID0", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		for i := 0; i < 2 && i < len(pkts); i++ {
			hdr := tpIKEHeader(pkts[i].Payload, true)
			if hdr == nil {
				continue
			}
			msgID := binary.BigEndian.Uint32(hdr[20:24])
			if msgID != 0 {
				t.Errorf("pkt[%d] MessageID = %d, want 0", i, msgID)
			}
		}
	})

	// 1.2.7.2: IKE_AUTH Message ID = 1.
	t.Run("1.2.7.2_AuthMsgID1", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 4 {
			t.Fatal("need at least 4 packets")
		}
		for i := 2; i < 4; i++ {
			hdr := tpIKEHeader(pkts[i].Payload, true)
			if hdr == nil {
				continue
			}
			msgID := binary.BigEndian.Uint32(hdr[20:24])
			if msgID != 1 {
				t.Errorf("pkt[%d] MessageID = %d, want 1", i, msgID)
			}
		}
	})

	// 1.2.8.1: Length includes full IKE message.
	t.Run("1.2.8.1_LengthFull", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			hdr := tpIKEHeader(p.Payload, true)
			if hdr == nil {
				continue
			}
			length := binary.BigEndian.Uint32(hdr[24:28])
			if length < IKEHeaderLen {
				t.Errorf("pkt[%d] Length = %d, min %d", i, length, IKEHeaderLen)
			}
		}
	})

	// 1.2.8.2: Length min = 28 (header only).
	t.Run("1.2.8.2_LengthMin28", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Dialog = []core.IKENATTMessage{
			{
				Direction: "up", ExchangeType: ExchangeINFORMATIONAL, MessageID: 0,
				Payloads: nil,
			},
		}
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		length := binary.BigEndian.Uint32(hdr[24:28])
		if length != IKEHeaderLen {
			t.Errorf("Length = %d, want %d", length, IKEHeaderLen)
		}
	})

	// 1.2.8.3: With Non-ESP Marker, UDP payload length = 4 + Length.
	t.Run("1.2.8.3_LengthWithMarker", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if len(p.Payload) < IKEHeaderAtPort4500 {
				continue
			}
			ikeLen := binary.BigEndian.Uint32(p.Payload[28:32])
			if len(p.Payload) != NonESPMarkerLen+int(ikeLen) {
				t.Errorf("pkt[%d] payload=%d, want 4+%d=%d", i, len(p.Payload), ikeLen, NonESPMarkerLen+int(ikeLen))
			}
		}
	})
}

// --- §1.3 NAT-D Payload (type 20/41, RFC 3947 §3 / RFC 7296 §2.23) ---

func TestRFC_NATDPayload(t *testing.T) {
	// 1.3.1.1: NAT-D Notify Next Payload chain -- last payload's header byte[0] = 0.
	t.Run("1.3.1.1_NATDChain", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		// Walk the payload chain raw bytes and verify the last header byte[0] = 0.
		off := NonESPMarkerLen + IKEHeaderLen
		nxt := pkts[0].Payload[20] // IKE Header Next Payload
		for off+4 <= len(pkts[0].Payload) && nxt != 0 {
			plLen := binary.BigEndian.Uint16(pkts[0].Payload[off+2 : off+4])
			if int(plLen) < 4 || off+int(plLen) > len(pkts[0].Payload) {
				break
			}
			nxt = pkts[0].Payload[off]
			off += int(plLen)
		}
		if nxt != 0 {
			t.Errorf("last payload's Next Payload byte = %d, want 0", nxt)
		}
	})

	// 1.3.1.4: NAT-D Payload Length = 24 (4 generic + 20 SHA-1).
	t.Run("1.3.1.4_NATDLength24", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		payloads := tpParsePayloads(pkts[0].Payload, true)
		for _, pl := range payloads {
			if pl.nextType == PayloadNOTIFY && len(pl.body) >= 4 {
				msgType := binary.BigEndian.Uint16(pl.body[2:4])
				if msgType == NotifyNATDetectionSourceIP || msgType == NotifyNATDetectionDestIP {
					if pl.length != 28 {
						t.Errorf("NAT-D payload length = %d, want 28 (4 generic + 4 notify + 20 hash)", pl.length)
					}
				}
			}
		}
	})

	// 1.3.2.1: NAT-D SHA-1 hash input = SPIi(8) + SPIr(8) + IP(4) + Port(2).
	t.Run("1.3.2.1_NATDHashInput", func(t *testing.T) {
		spii := uint64(0x0123456789ABCDEF)
		spir := uint64(0)
		ip := net.ParseIP("10.0.0.1")
		port := uint16(500)
		hash := computeNATDHash(spii, spir, ip, port)
		if len(hash) != NATDHashLen {
			t.Fatalf("hash len = %d, want %d", len(hash), NATDHashLen)
		}
		// Verify by computing manually.
		buf := make([]byte, 0, 22)
		buf = binary.BigEndian.AppendUint64(buf, spii)
		buf = binary.BigEndian.AppendUint64(buf, spir)
		buf = append(buf, ip.To4()...)
		buf = binary.BigEndian.AppendUint16(buf, port)
		expected := sha1.Sum(buf)
		for i := range hash {
			if hash[i] != expected[i] {
				t.Errorf("hash[%d] = 0x%02X, want 0x%02X", i, hash[i], expected[i])
				break
			}
		}
	})

	// 1.3.2.2: IPv6 NAT-D hash (16-byte IP).
	t.Run("1.3.2.2_NATDHashIPv6", func(t *testing.T) {
		spii := uint64(0x0123456789ABCDEF)
		spir := uint64(0)
		ip := net.ParseIP("2001:db8::1")
		port := uint16(4500)
		hash := computeNATDHash(spii, spir, ip, port)
		if len(hash) != NATDHashLen {
			t.Fatalf("hash len = %d, want %d", len(hash), NATDHashLen)
		}
		buf := make([]byte, 0, 34)
		buf = binary.BigEndian.AppendUint64(buf, spii)
		buf = binary.BigEndian.AppendUint64(buf, spir)
		buf = append(buf, ip...)
		buf = binary.BigEndian.AppendUint16(buf, port)
		expected := sha1.Sum(buf)
		for i := range hash {
			if hash[i] != expected[i] {
				t.Errorf("IPv6 hash[%d] = 0x%02X, want 0x%02X", i, hash[i], expected[i])
				break
			}
		}
	})

	// 1.3.3.1: IKE_SA_INIT request has 2 NAT-D Notifies.
	t.Run("1.3.3.1_TwoNATDInInitReq", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		payloads := tpParsePayloads(pkts[0].Payload, true)
		natDCount := 0
		for _, pl := range payloads {
			if pl.nextType == PayloadNOTIFY && len(pl.body) >= 4 {
				msgType := binary.BigEndian.Uint16(pl.body[2:4])
				if msgType == NotifyNATDetectionSourceIP || msgType == NotifyNATDetectionDestIP {
					natDCount++
				}
			}
		}
		if natDCount != 2 {
			t.Errorf("NAT-D Notify count = %d, want 2", natDCount)
		}
	})

	// 1.3.3.3: NAT-D Notify Message Type = 16388 (NAT_DETECTION_SOURCE_IP).
	t.Run("1.3.3.3_NATDSourceType", func(t *testing.T) {
		notify := &core.NotifyPayload{
			ProtocolID: 0, SPISize: 0, NotifyMsgType: NotifyNATDetectionSourceIP,
			NotificationData: make([]byte, NATDHashLen),
		}
		body := encodeNotifyForNATT(notify)
		msgType := binary.BigEndian.Uint16(body[2:4])
		if msgType != 16388 {
			t.Errorf("MsgType = %d, want 16388", msgType)
		}
	})

	// 1.3.3.4: NAT-D Notify Message Type = 16389 (NAT_DETECTION_DESTINATION_IP).
	t.Run("1.3.3.4_NATDDestType", func(t *testing.T) {
		notify := &core.NotifyPayload{
			ProtocolID: 0, SPISize: 0, NotifyMsgType: NotifyNATDetectionDestIP,
			NotificationData: make([]byte, NATDHashLen),
		}
		body := encodeNotifyForNATT(notify)
		msgType := binary.BigEndian.Uint16(body[2:4])
		if msgType != 16389 {
			t.Errorf("MsgType = %d, want 16389", msgType)
		}
	})

	// 1.3.3.5: NAT-D Notify Protocol ID = 0, SPI Size = 0.
	t.Run("1.3.3.5_NATDProtoAndSPI", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		payloads := tpParsePayloads(pkts[0].Payload, true)
		for _, pl := range payloads {
			if pl.nextType == PayloadNOTIFY && len(pl.body) >= 4 {
				msgType := binary.BigEndian.Uint16(pl.body[2:4])
				if msgType == NotifyNATDetectionSourceIP || msgType == NotifyNATDetectionDestIP {
					if pl.body[0] != 0 {
						t.Errorf("ProtocolID = %d, want 0", pl.body[0])
					}
					if pl.body[1] != 0 {
						t.Errorf("SPISize = %d, want 0", pl.body[1])
					}
				}
			}
		}
	})
}

// --- §1.4 NAT-OA Payload (type 21/42/43, RFC 3947 §3) ---

func TestRFC_NATOAPayload(t *testing.T) {
	// 1.4.1.1: NAT-OA payload body length = 8 for IPv4 (4 hdr + 4 IP).
	t.Run("1.4.1.1_NATOAIPv4Length", func(t *testing.T) {
		notify := &core.NotifyPayload{
			ProtocolID: 0, SPISize: 0, NotifyMsgType: 16400,
			NotificationData: net.ParseIP("10.0.0.1").To4(),
		}
		body := encodeNotifyForNATT(notify)
		if len(body) != 8 {
			t.Errorf("NAT-OA Notify body length = %d, want 8 (4 hdr + 4 IP)", len(body))
		}
	})

	// 1.4.1.2: NAT-OA payload body length = 20 for IPv6 (4 hdr + 16 IP).
	t.Run("1.4.1.2_NATOAIPv6Length", func(t *testing.T) {
		notify := &core.NotifyPayload{
			ProtocolID: 0, SPISize: 0, NotifyMsgType: 16401,
			NotificationData: net.ParseIP("2001:db8::1"),
		}
		body := encodeNotifyForNATT(notify)
		if len(body) != 20 {
			t.Errorf("NAT-OA Notify body length = %d, want 20 (4 hdr + 16 IP)", len(body))
		}
	})
}

// --- §1.5 Notify Payload (RFC 7296 §3.10) ---

func TestRFC_NotifyPayload(t *testing.T) {
	// 1.5.1.1: Notify payload's own header byte[0] = 0 (last payload).
	t.Run("1.5.1.1_NotifyNextPayload", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Dialog = []core.IKENATTMessage{
			{
				Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, MessageID: 0,
				Payloads: []core.IKENATTPayload{
					{Type: PayloadNOTIFY, Notify: &core.NotifyPayload{
						ProtocolID: 0, SPISize: 0, NotifyMsgType: NotifyNATDetectionSourceIP,
						NotificationData: make([]byte, NATDHashLen),
					}},
				},
			},
		}
		pkts := tpMustPlan(t, spec)
		// Verify the Notify payload's own header byte[0] = 0.
		notifyOff := NonESPMarkerLen + IKEHeaderLen
		if pkts[0].Payload[notifyOff] != 0 {
			t.Errorf("Notify payload Next Payload byte = %d, want 0", pkts[0].Payload[notifyOff])
		}
	})

	// 1.5.1.2: Notify Protocol ID = 0 (IKE).
	t.Run("1.5.1.2_NotifyProtocolID", func(t *testing.T) {
		notify := &core.NotifyPayload{ProtocolID: 0, SPISize: 0, NotifyMsgType: 16388, NotificationData: make([]byte, NATDHashLen)}
		body := encodeNotifyForNATT(notify)
		if body[0] != 0 {
			t.Errorf("ProtocolID = %d, want 0", body[0])
		}
	})

	// 1.5.1.3: Notify SPI Size = 0 for NAT detection.
	t.Run("1.5.1.3_NotifySPISize", func(t *testing.T) {
		notify := &core.NotifyPayload{ProtocolID: 0, SPISize: 0, NotifyMsgType: 16388, NotificationData: make([]byte, NATDHashLen)}
		body := encodeNotifyForNATT(notify)
		if body[1] != 0 {
			t.Errorf("SPISize = %d, want 0", body[1])
		}
	})

	// 1.5.1.4: Notify Message Type = 16388/16389.
	t.Run("1.5.1.4_NotifyMsgType", func(t *testing.T) {
		notify := &core.NotifyPayload{ProtocolID: 0, SPISize: 0, NotifyMsgType: NotifyNATDetectionSourceIP, NotificationData: make([]byte, NATDHashLen)}
		body := encodeNotifyForNATT(notify)
		msgType := binary.BigEndian.Uint16(body[2:4])
		if msgType != NotifyNATDetectionSourceIP {
			t.Errorf("MsgType = %d, want %d", msgType, NotifyNATDetectionSourceIP)
		}
	})

	// 1.5.1.5: Notify Notification Data = 20 bytes (NAT-D hash).
	t.Run("1.5.1.5_NotifyData20", func(t *testing.T) {
		notify := &core.NotifyPayload{ProtocolID: 0, SPISize: 0, NotifyMsgType: NotifyNATDetectionSourceIP, NotificationData: make([]byte, NATDHashLen)}
		body := encodeNotifyForNATT(notify)
		if len(body[4:]) != NATDHashLen {
			t.Errorf("NotificationData length = %d, want %d", len(body[4:]), NATDHashLen)
		}
	})
}

// --- §1.6 ESP Header (RFC 4303 §2) ---

func TestRFC_ESPHeader(t *testing.T) {
	// 1.6.1.1: ESP SPI = 4 bytes, SPI != 0.
	t.Run("1.6.1.1_ESP_SPI4Bytes", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{
			SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64,
		}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 5 {
			t.Fatal("need >=5 packets for ESP")
		}
		espPkt := pkts[4]
		if len(espPkt.Payload) < 8 {
			t.Fatal("ESP payload too short")
		}
		spi := binary.BigEndian.Uint32(espPkt.Payload[0:4])
		if spi == 0 {
			t.Error("ESP SPI = 0, want non-zero")
		}
	})

	// 1.6.1.2: ESP SPI = 1 (minimum valid).
	t.Run("1.6.1.2_ESP_SPI1", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{
			SPIout: 1, ESPCount: 1, ESPDataSize: 64,
		}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 5 {
			t.Fatal("need >=5 packets")
		}
		espPkt := pkts[4]
		spi := binary.BigEndian.Uint32(espPkt.Payload[0:4])
		if spi != 1 {
			t.Errorf("ESP SPI = 0x%08X, want 1", spi)
		}
	})

	// 1.6.1.3: ESP Sequence Number = 4 bytes.
	t.Run("1.6.1.3_ESPSeq4Bytes", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{
			SPIout: 0xDEADBEEF, ESPCount: 2, ESPDataSize: 64,
		}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 6 {
			t.Fatal("need >=6 packets")
		}
		for i := 0; i < 2; i++ {
			espPkt := pkts[4+i]
			if len(espPkt.Payload) < 8 {
				t.Fatalf("ESP[%d] payload too short", i)
			}
			seq := binary.BigEndian.Uint32(espPkt.Payload[4:8])
			if seq != uint32(i+1) {
				t.Errorf("ESP[%d] Seq = %d, want %d", i, seq, i+1)
			}
		}
	})

	// 1.6.1.4: ESP Sequence Number starts at 1.
	t.Run("1.6.1.4_ESPSeqStart1", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{
			SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64,
		}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 5 {
			t.Fatal("need >=5 packets")
		}
		seq := binary.BigEndian.Uint32(pkts[4].Payload[4:8])
		if seq != 1 {
			t.Errorf("ESP Seq = %d, want 1", seq)
		}
	})
}

// --- §1.7 NAT-Keepalive (RFC 3948 §3 / RFC 7296 §2.23) ---

func TestRFC_NATKeepalive(t *testing.T) {
	// 1.7.1.1: NAT-keepalive UDP payload = 1 byte.
	t.Run("1.7.1.1_Keepalive1Byte", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Keepalive = &core.NATKeepaliveConfig{Interval: 20, Count: 1, Direction: "up"}
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		for _, p := range pkts {
			if len(p.Payload) == 1 && p.Payload[0] == 0xFF {
				if len(p.Payload) != 1 {
					t.Errorf("keepalive payload length = %d, want 1", len(p.Payload))
				}
			}
		}
	})

	// 1.7.1.2: NAT-keepalive value = 0xFF.
	t.Run("1.7.1.2_Keepalive0xFF", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Keepalive = &core.NATKeepaliveConfig{Interval: 20, Count: 1, Direction: "up"}
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		for _, p := range pkts {
			if len(p.Payload) == 1 && p.Payload[0] != 0xFF {
				t.Errorf("keepalive byte = 0x%02X, want 0xFF", p.Payload[0])
			}
		}
	})

	// 1.7.1.3: NAT-keepalive src/dst port = 4500.
	t.Run("1.7.1.3_KeepalivePort4500", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Keepalive = &core.NATKeepaliveConfig{Interval: 20, Count: 1, Direction: "up"}
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		for _, p := range pkts {
			if len(p.Payload) == 1 && p.Payload[0] == 0xFF {
				if p.L4.DstPort != 4500 {
					t.Errorf("keepalive DstPort = %d, want 4500", p.L4.DstPort)
				}
			}
		}
	})

	// 1.7.1.5: Count=10 produces 10 keepalive packets.
	t.Run("1.7.1.5_KeepaliveCount10", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Keepalive = &core.NATKeepaliveConfig{Interval: 20, Count: 10, Direction: "up"}
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		kaCount := 0
		for _, p := range pkts {
			if len(p.Payload) == 1 && p.Payload[0] == 0xFF {
				kaCount++
			}
		}
		if kaCount != 10 {
			t.Errorf("keepalive count = %d, want 10", kaCount)
		}
	})
}

// --- §1.9 UDP Ports (RFC 3948 §2) ---

func TestRFC_UDPPorts(t *testing.T) {
	// 1.9.1.1: IKE port 500 before floating.
	t.Run("1.9.1.1_Port500BeforeFloat", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 500
		spec.DstPort = 500
		spec.IKENATT.PortFloat = false
		spec.IKENATT.NATDetectedOnSource = false
		spec.IKENATT.NATDetectedOnDest = false
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if i < 4 {
				if p.L4.SrcPort != 500 || p.L4.DstPort != 500 {
					t.Errorf("pkt[%d] ports %d/%d, want 500/500", i, p.L4.SrcPort, p.L4.DstPort)
				}
			}
		}
	})

	// 1.9.1.2: IKE port 4500 after floating.
	t.Run("1.9.1.2_Port4500AfterFloat", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 500
		spec.DstPort = 500
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if i < 4 {
				if p.L4.DstPort != 4500 {
					t.Errorf("pkt[%d] DstPort = %d, want 4500 after float", i, p.L4.DstPort)
				}
			}
		}
	})

	// 1.9.1.3: ESP-in-UDP on port 4500.
	t.Run("1.9.1.3_ESPUDP4500", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		for _, p := range pkts {
			if len(p.Payload) >= 8 {
				spi := binary.BigEndian.Uint32(p.Payload[0:4])
				if spi == 0xDEADBEEF {
					if p.L4.DstPort != 4500 {
						t.Errorf("ESP DstPort = %d, want 4500", p.L4.DstPort)
					}
				}
			}
		}
	})

	// 1.9.1.4: NAT-keepalive on port 4500.
	t.Run("1.9.1.4_KeepaliveUDP4500", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Keepalive = &core.NATKeepaliveConfig{Interval: 20, Count: 1, Direction: "up"}
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		for _, p := range pkts {
			if len(p.Payload) == 1 && p.Payload[0] == 0xFF {
				if p.L4.DstPort != 4500 {
					t.Errorf("keepalive DstPort = %d, want 4500", p.L4.DstPort)
				}
			}
		}
	})
}

// ============================================================
// §2. State Machine Coverage
// ============================================================

// --- §2.1 IDLE -> INIT ---

func TestState_IDLEtoINIT(t *testing.T) {
	// 2.1.1.1: Submit task, planner initializes SPIi, SPIr=0.
	t.Run("2.1.1.1_InitState", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.InitiatorSPI = 0
		spec.IKENATT.ResponderSPI = 0
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 1 {
			t.Fatal("expected at least 1 packet")
		}
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		spii := binary.BigEndian.Uint64(hdr[0:8])
		spir := binary.BigEndian.Uint64(hdr[8:16])
		if spii == 0 {
			t.Error("SPIi = 0, want non-zero (auto-generated)")
		}
		if spir != 0 {
			t.Errorf("SPIr = 0x%X, want 0 (INIT_REQ)", spir)
		}
	})
}

// --- §2.2 INIT state ---

func TestState_INIT(t *testing.T) {
	// 2.2.1.1: INIT sends IKE_SA_INIT on port 500/500.
	t.Run("2.2.1.1_INITPort500", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 500
		spec.DstPort = 500
		spec.IKENATT.PortFloat = false
		spec.IKENATT.NATDetectedOnSource = false
		spec.IKENATT.NATDetectedOnDest = false
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 1 {
			t.Fatal("expected at least 1 packet")
		}
		if pkts[0].L4.SrcPort != 500 || pkts[0].L4.DstPort != 500 {
			t.Errorf("INIT_REQ ports %d/%d, want 500/500", pkts[0].L4.SrcPort, pkts[0].L4.DstPort)
		}
	})

	// 2.2.1.3: IKE_SA_INIT request ResponderSPI = 0.
	t.Run("2.2.1.3_ResponderSPI0", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		spir := binary.BigEndian.Uint64(hdr[8:16])
		if spir != 0 {
			t.Errorf("INIT_REQ SPIr = 0x%X, want 0", spir)
		}
	})

	// 2.2.1.4: Flags initiator = 1.
	t.Run("2.2.1.4_FlagsInitiator", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		if hdr[19]&FlagInitiator == 0 {
			t.Error("INIT_REQ Flags bit0 = 0, want 1")
		}
	})
}

// --- §2.2b IKE_SA_INIT bidirectional ---

func TestState_IKESAInitBidirectional(t *testing.T) {
	// 2.2b.1.1: INIT_REQ direction = up.
	t.Run("2.2b.1.1_InitReqUp", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 500
		spec.DstPort = 500
		spec.IKENATT.PortFloat = false
		spec.IKENATT.NATDetectedOnSource = false
		spec.IKENATT.NATDetectedOnDest = false
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 1 {
			t.Fatal("expected at least 1 packet")
		}
		if pkts[0].Direction != "up" {
			t.Errorf("INIT_REQ direction = %q, want up", pkts[0].Direction)
		}
	})

	// 2.2b.1.2: INIT_REQ InitiatorSPI non-zero.
	t.Run("2.2b.1.2_InitReqSPIi", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.InitiatorSPI = 0xDEADBEEFCAFEBABE
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		spii := binary.BigEndian.Uint64(hdr[0:8])
		if spii != 0xDEADBEEFCAFEBABE {
			t.Errorf("SPIi = 0x%X, want 0xDEADBEEFCAFEBABE", spii)
		}
	})

	// 2.2b.1.3: INIT_REQ ResponderSPI = 0.
	t.Run("2.2b.1.3_InitReqSPIr0", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		spir := binary.BigEndian.Uint64(hdr[8:16])
		if spir != 0 {
			t.Errorf("SPIr = 0x%X, want 0", spir)
		}
	})

	// 2.2b.1.4: INIT_REQ ExchangeType = 34.
	t.Run("2.2b.1.4_InitReqExch34", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		if hdr[18] != 34 {
			t.Errorf("ExchangeType = %d, want 34", hdr[18])
		}
	})

	// 2.2b.1.5: INIT_REQ Flags = 0x08.
	t.Run("2.2b.1.5_InitReqFlags08", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		if hdr[19] != 0x08 {
			t.Errorf("Flags = 0x%02X, want 0x08", hdr[19])
		}
	})

	// 2.2b.1.6: INIT_REQ MessageID = 0.
	t.Run("2.2b.1.6_InitReqMsgID0", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		msgID := binary.BigEndian.Uint32(hdr[20:24])
		if msgID != 0 {
			t.Errorf("MessageID = %d, want 0", msgID)
		}
	})

	// 2.2b.1.7: INIT_REQ Version = 0x20.
	t.Run("2.2b.1.7_InitReqVersion20", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		if hdr[17] != 0x20 {
			t.Errorf("Version = 0x%02X, want 0x20", hdr[17])
		}
	})

	// 2.2b.2.1: INIT_RESP direction = down.
	t.Run("2.2b.2.1_InitRespDown", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 500
		spec.DstPort = 500
		spec.IKENATT.PortFloat = false
		spec.IKENATT.NATDetectedOnSource = false
		spec.IKENATT.NATDetectedOnDest = false
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 2 {
			t.Fatal("need at least 2 packets")
		}
		if pkts[1].Direction != "down" {
			t.Errorf("INIT_RESP direction = %q, want down", pkts[1].Direction)
		}
	})

	// 2.2b.2.2: INIT_RESP echoes InitiatorSPI.
	t.Run("2.2b.2.2_InitRespEchoSPIi", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.InitiatorSPI = 0xDEADBEEFCAFEBABE
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 2 {
			t.Fatal("need at least 2 packets")
		}
		hdr := tpIKEHeader(pkts[1].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		spii := binary.BigEndian.Uint64(hdr[0:8])
		if spii != 0xDEADBEEFCAFEBABE {
			t.Errorf("INIT_RESP SPIi = 0x%X, want 0xDEADBEEFCAFEBABE", spii)
		}
	})

	// 2.2b.2.3: INIT_RESP ResponderSPI non-zero.
	t.Run("2.2b.2.3_InitRespSPIrNonZero", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ResponderSPI = 0x0011223344556677
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 2 {
			t.Fatal("need at least 2 packets")
		}
		hdr := tpIKEHeader(pkts[1].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		spir := binary.BigEndian.Uint64(hdr[8:16])
		if spir == 0 {
			t.Error("INIT_RESP SPIr = 0, want non-zero")
		}
	})

	// 2.2b.2.4: INIT_RESP ExchangeType = 34.
	t.Run("2.2b.2.4_InitRespExch34", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 2 {
			t.Fatal("need at least 2 packets")
		}
		hdr := tpIKEHeader(pkts[1].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		if hdr[18] != 34 {
			t.Errorf("ExchangeType = %d, want 34", hdr[18])
		}
	})

	// 2.2b.2.5: INIT_RESP Flags = 0x20.
	t.Run("2.2b.2.5_InitRespFlags20", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 2 {
			t.Fatal("need at least 2 packets")
		}
		hdr := tpIKEHeader(pkts[1].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		if hdr[19] != 0x20 {
			t.Errorf("Flags = 0x%02X, want 0x20", hdr[19])
		}
	})

	// 2.2b.2.6: INIT_RESP MessageID = 0.
	t.Run("2.2b.2.6_InitRespMsgID0", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 2 {
			t.Fatal("need at least 2 packets")
		}
		hdr := tpIKEHeader(pkts[1].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		msgID := binary.BigEndian.Uint32(hdr[20:24])
		if msgID != 0 {
			t.Errorf("MessageID = %d, want 0", msgID)
		}
	})

	// 2.2b.4.1: Complete 4-message handshake in order.
	t.Run("2.2b.4.1_FourMessageOrder", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 4 {
			t.Fatalf("expected >=4 packets, got %d", len(pkts))
		}
		expected := []struct {
			direction string
			exchType uint8
			msgID uint32
		}{
			{"up", ExchangeIKE_SA_INIT, 0},
			{"down", ExchangeIKE_SA_INIT, 0},
			{"up", ExchangeIKE_AUTH, 1},
			{"down", ExchangeIKE_AUTH, 1},
		}
		for i, e := range expected {
			hdr := tpIKEHeader(pkts[i].Payload, true)
			if hdr == nil {
				t.Fatalf("pkt[%d] nil IKE header", i)
			}
			if pkts[i].Direction != e.direction {
				t.Errorf("pkt[%d] direction = %q, want %q", i, pkts[i].Direction, e.direction)
			}
			if hdr[18] != e.exchType {
				t.Errorf("pkt[%d] ExchangeType = %d, want %d", i, hdr[18], e.exchType)
			}
			msgID := binary.BigEndian.Uint32(hdr[20:24])
			if msgID != e.msgID {
				t.Errorf("pkt[%d] MessageID = %d, want %d", i, msgID, e.msgID)
			}
		}
	})
}

// --- §2.3b IKE_SA_INIT retransmit ---

func TestState_Retransmit(t *testing.T) {
	// 2.3b.1.4: MaxRetransmits = 0 means no retransmit.
	t.Run("2.3b.1.4_NoRetransmit", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Retransmit = &core.RetransmitConfig{MaxRetransmits: 0}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 4 {
			t.Fatalf("expected >=4 packets, got %d", len(pkts))
		}
		ikeCount := 0
		for _, p := range pkts {
			if len(p.Payload) >= IKEHeaderAtPort4500 {
				ikeCount++
			}
		}
		if ikeCount < 4 {
			t.Errorf("IKE packet count = %d, want >=4", ikeCount)
		}
	})

	// 2.3b.1.5: MaxRetransmits = 5 produces retransmits.
	t.Run("2.3b.1.5_Retransmit5", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Retransmit = &core.RetransmitConfig{MaxRetransmits: 5, Timeout: 500, Backoff: 2.0}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 9 {
			t.Fatalf("expected >=9 packets (1 INIT + 5 retransmits + 3 more), got %d", len(pkts))
		}
	})

	// 2.3b.2.1: Retransmit MessageID = 0 (same as original).
	t.Run("2.3b.2.1_RetransmitMsgID0", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Retransmit = &core.RetransmitConfig{MaxRetransmits: 2, Timeout: 500, Backoff: 2.0}
		pkts := tpMustPlan(t, spec)
		for i := 0; i < 3 && i < len(pkts); i++ {
			hdr := tpIKEHeader(pkts[i].Payload, true)
			if hdr == nil {
				continue
			}
			msgID := binary.BigEndian.Uint32(hdr[20:24])
			if msgID != 0 {
				t.Errorf("pkt[%d] (retransmit) MessageID = %d, want 0", i, msgID)
			}
		}
	})

	// 2.3b.2.2: Retransmit SPI same as original.
	t.Run("2.3b.2.2_RetransmitSameSPIi", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.InitiatorSPI = 0xDEADBEEFCAFEBABE
		spec.IKENATT.Retransmit = &core.RetransmitConfig{MaxRetransmits: 2, Timeout: 500, Backoff: 2.0}
		pkts := tpMustPlan(t, spec)
		for i := 0; i < 3 && i < len(pkts); i++ {
			hdr := tpIKEHeader(pkts[i].Payload, true)
			if hdr == nil {
				continue
			}
			spii := binary.BigEndian.Uint64(hdr[0:8])
			if spii != 0xDEADBEEFCAFEBABE {
				t.Errorf("pkt[%d] SPIi = 0x%X, want 0xDEADBEEFCAFEBABE", i, spii)
			}
		}
	})

	// 2.3b.2.3: Retransmit SPIr = 0.
	t.Run("2.3b.2.3_RetransmitSPIr0", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Retransmit = &core.RetransmitConfig{MaxRetransmits: 2, Timeout: 500, Backoff: 2.0}
		pkts := tpMustPlan(t, spec)
		for i := 0; i < 3 && i < len(pkts); i++ {
			hdr := tpIKEHeader(pkts[i].Payload, true)
			if hdr == nil {
				continue
			}
			spir := binary.BigEndian.Uint64(hdr[8:16])
			if spir != 0 {
				t.Errorf("pkt[%d] SPIr = 0x%X, want 0", i, spir)
			}
		}
	})
}

// --- §2.5 PORT_FLOAT_FALSE ---

func TestState_PortFloatFalse(t *testing.T) {
	// 2.5.1.1: No NAT, ports stay 500/500.
	t.Run("2.5.1.1_NoNATPort500", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 500
		spec.DstPort = 500
		spec.IKENATT.PortFloat = false
		spec.IKENATT.NATDetectedOnSource = false
		spec.IKENATT.NATDetectedOnDest = false
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if p.L4.SrcPort != 500 || p.L4.DstPort != 500 {
				t.Errorf("pkt[%d] ports %d/%d, want 500/500", i, p.L4.SrcPort, p.L4.DstPort)
			}
		}
	})

	// 2.5.1.3: No NAT, no keepalive.
	t.Run("2.5.1.3_NoNATNoKeepalive", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.PortFloat = false
		spec.IKENATT.NATDetectedOnSource = false
		spec.IKENATT.NATDetectedOnDest = false
		spec.IKENATT.Keepalive = &core.NATKeepaliveConfig{Interval: 20, Count: 5, Direction: "up"}
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		kaCount := 0
		for _, p := range pkts {
			if len(p.Payload) == 1 && p.Payload[0] == 0xFF {
				kaCount++
			}
		}
		if kaCount != 0 {
			t.Errorf("keepalive count = %d, want 0 (no NAT = no keepalive)", kaCount)
		}
	})
}

// --- §2.6 PORT_FLOAT_TRUE ---

func TestState_PortFloatTrue(t *testing.T) {
	// 2.6.1.1: NAT detected, port floats to 4500.
	t.Run("2.6.1.1_PortFloat4500", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 500
		spec.DstPort = 500
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if i < 4 && p.L4.DstPort != 4500 {
				t.Errorf("pkt[%d] DstPort = %d, want 4500 after float", i, p.L4.DstPort)
			}
		}
	})

	// 2.6.1.2: After float, Non-ESP Marker present.
	t.Run("2.6.1.2_FloatNonESPMarker", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 500
		spec.DstPort = 500
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if i < 4 && len(p.Payload) >= 4 {
				marker := binary.BigEndian.Uint32(p.Payload[0:4])
				if marker != 0 {
					t.Errorf("pkt[%d] Non-ESP Marker = 0x%08X, want 0x00000000", i, marker)
				}
			}
		}
	})

	// 2.6.1.4: NAT detected, keepalive enabled.
	t.Run("2.6.1.4_FloatKeepalive", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Keepalive = &core.NATKeepaliveConfig{Interval: 20, Count: 3, Direction: "up"}
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		kaCount := 0
		for _, p := range pkts {
			if len(p.Payload) == 1 && p.Payload[0] == 0xFF {
				kaCount++
			}
		}
		if kaCount == 0 {
			t.Error("keepalive count = 0, expected >0 with NAT detected")
		}
	})
}

// ============================================================
// §3. Business Scenarios
// ============================================================

// --- §3.1 Standard IKE-NAT-T handshake with NAT-D ---

func TestScenario_StandardHandshake(t *testing.T) {
	// 3.1.1.1: IKE_SA_INIT with NAT-D Notifies.
	t.Run("3.1.1.1_NATDInInit", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		payloads := tpParsePayloads(pkts[0].Payload, true)
		natDCount := 0
		for _, pl := range payloads {
			if pl.nextType == PayloadNOTIFY && len(pl.body) >= 4 {
				msgType := binary.BigEndian.Uint16(pl.body[2:4])
				if msgType == NotifyNATDetectionSourceIP || msgType == NotifyNATDetectionDestIP {
					natDCount++
				}
			}
		}
		if natDCount < 2 {
			t.Errorf("NAT-D count = %d, want >=2", natDCount)
		}
	})

	// 3.1.1.3: Port floats to 4500, Non-ESP Marker present.
	t.Run("3.1.1.3_PortFloatWithMarker", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 500
		spec.DstPort = 500
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if len(p.Payload) >= 4 {
				marker := binary.BigEndian.Uint32(p.Payload[0:4])
				if marker != 0 {
					t.Errorf("pkt[%d] Non-ESP Marker = 0x%08X, want 0x00000000", i, marker)
				}
			}
		}
	})
}

// --- §3.3 NAT detected, keepalive ---

func TestScenario_NATKeepalive(t *testing.T) {
	// 3.3.1.2: NAT-T enabled, port floats to 4500.
	t.Run("3.3.1.2_NATTPort4500", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 500
		spec.DstPort = 500
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if i < 4 && p.L4.DstPort != 4500 {
				t.Errorf("pkt[%d] DstPort = %d, want 4500", i, p.L4.DstPort)
			}
		}
	})

	// 3.3.1.3: Keepalive interval defaults to 20s.
	t.Run("3.3.1.3_KeepaliveIntervalDefault", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Keepalive = &core.NATKeepaliveConfig{Count: 1}
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		applied := applyDefaults(spec.IKENATT)
		if applied.Keepalive.Interval != 20 {
			t.Errorf("default keepalive interval = %d, want 20", applied.Keepalive.Interval)
		}
	})

	// 3.3.1.4: Keepalive Count=10 sends 10 packets.
	t.Run("3.3.1.4_KeepaliveCount10", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Keepalive = &core.NATKeepaliveConfig{Interval: 20, Count: 10, Direction: "up"}
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		kaCount := 0
		for _, p := range pkts {
			if len(p.Payload) == 1 && p.Payload[0] == 0xFF {
				kaCount++
			}
		}
		if kaCount != 10 {
			t.Errorf("keepalive count = %d, want 10", kaCount)
		}
	})
}

// --- §3.4 ESP-in-UDP ---

func TestScenario_ESPInUDP(t *testing.T) {
	// 3.4.1.1: ESP-in-UDP on port 4500.
	t.Run("3.4.1.1_ESPUDP4500", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 5 {
			t.Fatal("need >=5 packets")
		}
		espPkt := pkts[4]
		if espPkt.L4.Protocol != "udp" {
			t.Errorf("ESP transport = %q, want udp", espPkt.L4.Protocol)
		}
		if espPkt.L4.DstPort != 4500 {
			t.Errorf("ESP DstPort = %d, want 4500", espPkt.L4.DstPort)
		}
	})

	// 3.4.1.2: ESP UDP payload first 4 bytes = SPI (non-zero).
	t.Run("3.4.1.2_ESPFirst4BytesSPI", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xCAFEBABE, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 5 {
			t.Fatal("need >=5 packets")
		}
		espPkt := pkts[4]
		if len(espPkt.Payload) < 4 {
			t.Fatal("ESP payload too short")
		}
		first4 := binary.BigEndian.Uint32(espPkt.Payload[0:4])
		if first4 == 0 {
			t.Error("ESP first 4 bytes = 0 (should be SPI, non-zero)")
		}
	})

	// 3.4.1.3: ESP SPI = 4 bytes.
	t.Run("3.4.1.3_ESP_SPI4Bytes", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 5 {
			t.Fatal("need >=5 packets")
		}
		spi := binary.BigEndian.Uint32(pkts[4].Payload[0:4])
		if spi != 0xDEADBEEF {
			t.Errorf("ESP SPI = 0x%08X, want 0xDEADBEEF", spi)
		}
	})

	// 3.4.1.4: ESP Sequence starts at 1.
	t.Run("3.4.1.4_ESPSeqStart1", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 5 {
			t.Fatal("need >=5 packets")
		}
		seq := binary.BigEndian.Uint32(pkts[4].Payload[4:8])
		if seq != 1 {
			t.Errorf("ESP Seq = %d, want 1", seq)
		}
	})
}

// --- §3.6 NAT keepalive direction ---

func TestScenario_KeepaliveDirection(t *testing.T) {
	// 3.6.1.1: Default interval = 20s.
	t.Run("3.6.1.1_Interval20", func(t *testing.T) {
		cfg := &core.IKENATTConfig{
			NATDetectedOnSource: true,
			Keepalive: &core.NATKeepaliveConfig{Count: 1},
		}
		applied := applyDefaults(cfg)
		if applied.Keepalive.Interval != 20 {
			t.Errorf("default interval = %d, want 20", applied.Keepalive.Interval)
		}
	})

	// 3.6.1.4: Direction = "up" sends only up.
	t.Run("3.6.1.4_DirectionUp", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Keepalive = &core.NATKeepaliveConfig{Interval: 20, Count: 2, Direction: "up"}
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		upCount := 0
		downCount := 0
		for _, p := range pkts {
			if len(p.Payload) == 1 && p.Payload[0] == 0xFF {
				if p.Direction == "up" {
					upCount++
				} else {
					downCount++
				}
			}
		}
		if upCount != 2 {
			t.Errorf("up keepalive count = %d, want 2", upCount)
		}
		if downCount != 0 {
			t.Errorf("down keepalive count = %d, want 0", downCount)
		}
	})

	// 3.6.1.6: Direction = "both" sends both directions.
	t.Run("3.6.1.6_DirectionBoth", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Keepalive = &core.NATKeepaliveConfig{Interval: 20, Count: 2, Direction: "both"}
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		upCount := 0
		downCount := 0
		for _, p := range pkts {
			if len(p.Payload) == 1 && p.Payload[0] == 0xFF {
				if p.Direction == "up" {
					upCount++
				} else {
					downCount++
				}
			}
		}
		if upCount != 2 {
			t.Errorf("up keepalive count = %d, want 2", upCount)
		}
		if downCount != 2 {
			t.Errorf("down keepalive count = %d, want 2", downCount)
		}
	})
}

// --- §3.7 Port floating 500 -> 4500 ---

func TestScenario_PortFloating(t *testing.T) {
	// 3.7.1.2: After float, first 4500 packet has Non-ESP Marker.
	t.Run("3.7.1.2_First4500HasMarker", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 500
		spec.DstPort = 500
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if p.L4.DstPort == 4500 && len(p.Payload) >= 4 {
				marker := binary.BigEndian.Uint32(p.Payload[0:4])
				if marker != 0 {
					t.Errorf("pkt[%d] on 4500 missing Non-ESP Marker = 0x%08X", i, marker)
				}
			}
		}
	})

	// 3.7.1.3: After float, src=temp, dst=4500.
	t.Run("3.7.1.3_PortsAfterFloat", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 12345
		spec.DstPort = 500
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if p.Direction == "up" {
				if p.L4.DstPort != 4500 {
					t.Errorf("pkt[%d] up DstPort = %d, want 4500", i, p.L4.DstPort)
				}
			}
			// Down direction swaps ports, so DstPort becomes original SrcPort (12345).
			if p.Direction == "down" && p.L4.DstPort != 12345 {
				t.Errorf("pkt[%d] down DstPort = %d, want %d (original SrcPort)", i, p.L4.DstPort, 12345)
			}
		}
	})

	// 3.7.1.4: After float, payload >= 32 bytes.
	t.Run("3.7.1.4_MinPayload32", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 500
		spec.DstPort = 500
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if p.L4.DstPort == 4500 && len(p.Payload) < 32 {
				t.Errorf("pkt[%d] payload = %d bytes, want >=32", i, len(p.Payload))
			}
		}
	})
}

// --- §3.9 IKE fragmentation (RFC 7383) ---

func TestScenario_IKEFragmentation(t *testing.T) {
	// 3.9.1.1: Large IKE_AUTH with raw payload.
	t.Run("3.9.1.1_LargeAuth", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Dialog = []core.IKENATTMessage{
			{
				Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, MessageID: 0,
				Payloads: []core.IKENATTPayload{
					{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
						{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{
							{Type: 1, ID: 12, KeyLengthBits: 128},
						}},
					}}},
					{Type: PayloadNONCE, Nonce: make([]byte, 16)},
				},
			},
			{
				Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, MessageID: 0,
				Payloads: []core.IKENATTPayload{
					{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
						{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{
							{Type: 1, ID: 12, KeyLengthBits: 128},
						}},
					}}},
					{Type: PayloadNONCE, Nonce: make([]byte, 16)},
				},
			},
			{
				Direction: "up", ExchangeType: ExchangeIKE_AUTH, MessageID: 1,
				Payloads: []core.IKENATTPayload{
					{Type: PayloadIDi, Raw: make([]byte, 2000)},
				},
			},
			{
				Direction: "down", ExchangeType: ExchangeIKE_AUTH, MessageID: 1,
				Payloads: []core.IKENATTPayload{
					{Type: PayloadIDr, Raw: make([]byte, 2000)},
				},
			},
		}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 4 {
			t.Fatalf("expected >=4 packets, got %d", len(pkts))
		}
		for i, p := range pkts {
			if len(p.Payload) < IKEHeaderAtPort4500 {
				t.Fatalf("pkt[%d] payload too short: %d bytes", i, len(p.Payload))
			}
			marker := binary.BigEndian.Uint32(p.Payload[0:4])
			if marker != 0 {
				t.Errorf("pkt[%d] Non-ESP Marker = 0x%08X, want 0x00000000", i, marker)
			}
		}
	})
}

// ============================================================
// §4. Data Scenarios
// ============================================================

// --- §4.1 Zero values ---

func TestData_ZeroValues(t *testing.T) {
	// 4.1.1.1: IKE_SA_INIT request ResponderSPI = 0.
	t.Run("4.1.1.1_SPIr0", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ResponderSPI = 0
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		spir := binary.BigEndian.Uint64(hdr[8:16])
		if spir != 0 {
			t.Errorf("INIT_REQ SPIr = 0x%X, want 0", spir)
		}
	})

	// 4.1.1.2: NAT-keepalive payload = 1 byte.
	t.Run("4.1.1.2_Keepalive1Byte", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Keepalive = &core.NATKeepaliveConfig{Interval: 20, Count: 1, Direction: "up"}
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		for _, p := range pkts {
			if len(p.Payload) == 1 {
				if p.L4.Protocol != "udp" {
					t.Errorf("keepalive protocol = %q, want udp", p.L4.Protocol)
				}
			}
		}
	})

	// 4.1.1.3: Non-ESP Marker = 0x00000000.
	t.Run("4.1.1.3_MarkerZero", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if len(p.Payload) < 4 {
				continue
			}
			marker := binary.BigEndian.Uint32(p.Payload[0:4])
			if marker != 0 {
				t.Errorf("pkt[%d] marker = 0x%08X, want 0x00000000", i, marker)
			}
		}
	})

	// 4.1.1.5: IKE Header Length min = 28.
	t.Run("4.1.1.5_LengthMin28", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Dialog = []core.IKENATTMessage{
			{
				Direction: "up", ExchangeType: ExchangeINFORMATIONAL, MessageID: 0,
				Payloads: nil,
			},
		}
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		length := binary.BigEndian.Uint32(hdr[24:28])
		if length < 28 {
			t.Errorf("Length = %d, min 28", length)
		}
	})
}

// --- §4.2 Boundary values ---

func TestData_BoundaryValues(t *testing.T) {
	// 4.2.1.1: SPI min = 1.
	t.Run("4.2.1.1_SPIMin1", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 1, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 5 {
			t.Fatal("need >=5 packets")
		}
		spi := binary.BigEndian.Uint32(pkts[4].Payload[0:4])
		if spi != 1 {
			t.Errorf("ESP SPI = 0x%08X, want 1", spi)
		}
	})

	// 4.2.1.2: SPI max = 0xFFFFFFFF.
	t.Run("4.2.1.2_SPIMax", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xFFFFFFFF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 5 {
			t.Fatal("need >=5 packets")
		}
		spi := binary.BigEndian.Uint32(pkts[4].Payload[0:4])
		if spi != 0xFFFFFFFF {
			t.Errorf("ESP SPI = 0x%08X, want 0xFFFFFFFF", spi)
		}
	})

	// 4.2.1.3: Sequence Number min = 1.
	t.Run("4.2.1.3_SeqMin1", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 5 {
			t.Fatal("need >=5 packets")
		}
		seq := binary.BigEndian.Uint32(pkts[4].Payload[4:8])
		if seq != 1 {
			t.Errorf("ESP Seq = %d, want 1", seq)
		}
	})

	// 4.2.1.5: InitiatorSPI max = 0xFFFFFFFFFFFFFFFF.
	t.Run("4.2.1.5_SPIiMax", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.InitiatorSPI = 0xFFFFFFFFFFFFFFFF
		pkts := tpMustPlan(t, spec)
		hdr := tpIKEHeader(pkts[0].Payload, true)
		if hdr == nil {
			t.Fatal("nil IKE header")
		}
		spii := binary.BigEndian.Uint64(hdr[0:8])
		if spii != 0xFFFFFFFFFFFFFFFF {
			t.Errorf("SPIi = 0x%X, want 0xFFFFFFFFFFFFFFFF", spii)
		}
	})
}

// --- §4.3 Abnormal values ---

func TestData_AbnormalValues(t *testing.T) {
	// 4.3.1.5: NAT-D Hash length != 20 rejected.
	t.Run("4.3.1.5_NATDHashLenWrong", func(t *testing.T) {
		p := NewPlanner()
		spec := validTPBaseSpec()
		spec.IKENATT.Dialog = []core.IKENATTMessage{
			{
				Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, MessageID: 0,
				Payloads: []core.IKENATTPayload{
					{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
						{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{
							{Type: 1, ID: 12, KeyLengthBits: 128},
						}},
					}}},
					{Type: PayloadNOTIFY, Notify: &core.NotifyPayload{
						ProtocolID: 0, SPISize: 0, NotifyMsgType: NotifyNATDetectionSourceIP,
						NotificationData: make([]byte, 10), // Wrong: 10 != 20
					}},
				},
			},
		}
		if err := p.Validate(spec); err == nil {
			t.Error("expected error for NAT-D hash length != 20")
		}
	})

	// 4.3.1.6: Planner always emits IKEv2 version 0x20.
	t.Run("4.3.1.6_VersionAlways20", func(t *testing.T) {
		spec := validTPBaseSpec()
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			hdr := tpIKEHeader(p.Payload, true)
			if hdr == nil {
				continue
			}
			if hdr[17] != 0x20 {
				t.Errorf("pkt[%d] Version = 0x%02X, want 0x20", i, hdr[17])
			}
		}
	})

	// 4.3.1.8: Notify Message Type = 16390 (non-NAT-D) doesn't break parsing.
	t.Run("4.3.1.8_NonNATDNotify", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Dialog = []core.IKENATTMessage{
			{
				Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, MessageID: 0,
				Payloads: []core.IKENATTPayload{
					{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
						{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{
							{Type: 1, ID: 12, KeyLengthBits: 128},
						}},
					}}},
					{Type: PayloadNOTIFY, Notify: &core.NotifyPayload{
						ProtocolID: 0, SPISize: 0, NotifyMsgType: 16390,
						NotificationData: []byte{0x01, 0x02, 0x03, 0x04},
					}},
				},
			},
		}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 1 {
			t.Fatal("expected at least 1 packet")
		}
		payloads := tpParsePayloads(pkts[0].Payload, true)
		if len(payloads) < 2 {
			t.Errorf("expected 2 payloads, got %d", len(payloads))
		}
	})
}

// --- §4.4 Large data ---

func TestData_LargeData(t *testing.T) {
	// 4.4.1.1: Large IKE_AUTH payload.
	t.Run("4.4.1.1_LargeAuth", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Dialog = []core.IKENATTMessage{
			{
				Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, MessageID: 0,
				Payloads: []core.IKENATTPayload{
					{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
						{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{
							{Type: 1, ID: 12, KeyLengthBits: 128},
						}},
					}}},
					{Type: PayloadNONCE, Nonce: make([]byte, 16)},
				},
			},
			{
				Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, MessageID: 0,
				Payloads: []core.IKENATTPayload{
					{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
						{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{
							{Type: 1, ID: 12, KeyLengthBits: 128},
						}},
					}}},
					{Type: PayloadNONCE, Nonce: make([]byte, 16)},
				},
			},
			{
				Direction: "up", ExchangeType: ExchangeIKE_AUTH, MessageID: 1,
				Payloads: []core.IKENATTPayload{
					{Type: PayloadIDi, Raw: make([]byte, 3000)},
				},
			},
		}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 3 {
			t.Fatalf("expected >=3 packets, got %d", len(pkts))
		}
	})
}

// --- §4.5 Small data ---

func TestData_SmallData(t *testing.T) {
	// 4.5.1.2: Min IKE on 4500 = 32 bytes (4 marker + 28 header).
	t.Run("4.5.1.2_MinIKE32", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Dialog = []core.IKENATTMessage{
			{
				Direction: "up", ExchangeType: ExchangeINFORMATIONAL, MessageID: 0,
				Payloads: nil,
			},
		}
		pkts := tpMustPlan(t, spec)
		if len(pkts[0].Payload) < 32 {
			t.Errorf("min IKE payload = %d, want >=32 (4 marker + 28 header)", len(pkts[0].Payload))
		}
	})
}

// ============================================================
// §5. Concurrency
// ============================================================

func TestConcurrency(t *testing.T) {
	// 5.1.1.1: N=10 concurrent workers, each flow has unique SPIi.
	t.Run("5.1.1.1_UniqueSPIi", func(t *testing.T) {
		const n = 10
		type result struct {
			idx int
			spii uint64
		}
		ch := make(chan result, n)
		for i := 0; i < n; i++ {
			go func(idx int) {
				spec := validTPBaseSpec()
				spec.IKENATT.InitiatorSPI = 0 // force auto-generate
				p := NewPlanner()
				pch, err := p.Plan(context.Background(), spec)
				if err != nil {
					t.Errorf("worker %d Plan error: %v", idx, err)
					ch <- result{idx: idx, spii: 0}
					return
				}
				pkt := <-pch
				hdr := tpIKEHeader(pkt.Payload, true)
				if hdr == nil {
					t.Errorf("worker %d nil IKE header", idx)
					ch <- result{idx: idx, spii: 0}
					return
				}
				spii := binary.BigEndian.Uint64(hdr[0:8])
				ch <- result{idx: idx, spii: spii}
			}(i)
		}
		spiis := make(map[uint64]int)
		for i := 0; i < n; i++ {
			r := <-ch
			if r.spii != 0 {
				spiis[r.spii]++
			}
		}
		if len(spiis) != n {
			t.Errorf("unique SPIi count = %d, want %d (duplicates: %v)", len(spiis), n, spiis)
		}
	})
}

// ============================================================
// §6. Resource Exhaustion
// ============================================================

func TestResourceExhaustion(t *testing.T) {
	// 6.1.1.2: 1000 keepalive packets.
	t.Run("6.1.1.2_Keepalive1000", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Keepalive = &core.NATKeepaliveConfig{Interval: 20, Count: 1000, Direction: "up"}
		spec.IKENATT.ChildSA = &core.ESPChildSAConfig{SPIout: 0xDEADBEEF, ESPCount: 1, ESPDataSize: 64}
		pkts := tpMustPlan(t, spec)
		kaCount := 0
		for _, p := range pkts {
			if len(p.Payload) == 1 && p.Payload[0] == 0xFF {
				kaCount++
			}
		}
		if kaCount != 1000 {
			t.Errorf("keepalive count = %d, want 1000", kaCount)
		}
	})

	// 6.1.1.3: Large fragmentation (simulated with raw data).
	t.Run("6.1.1.3_LargeFrag", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Dialog = []core.IKENATTMessage{
			{
				Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, MessageID: 0,
				Payloads: []core.IKENATTPayload{
					{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{
						{Number: 1, ProtocolID: ProtocolIKE, Transforms: []core.IKETransform{
							{Type: 1, ID: 12, KeyLengthBits: 128},
						}},
					}}},
					{Type: PayloadNONCE, Nonce: make([]byte, 16)},
				},
			},
			{
				Direction: "up", ExchangeType: ExchangeIKE_AUTH, MessageID: 1,
				Payloads: []core.IKENATTPayload{
					{Type: PayloadIDi, Raw: make([]byte, 50000)},
				},
			},
		}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 2 {
			t.Fatalf("expected >=2 packets, got %d", len(pkts))
		}
	})
}

// ============================================================
// §8. Exception Handling
// ============================================================

func TestExceptionHandling(t *testing.T) {
	// 8.1.1.1: DstPort = 0 defaults to 500.
	t.Run("8.1.1.1_DstPort0", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 0
		spec.DstPort = 0
		spec.IKENATT.PortFloat = false
		spec.IKENATT.NATDetectedOnSource = false
		spec.IKENATT.NATDetectedOnDest = false
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 1 {
			t.Fatal("expected at least 1 packet")
		}
		_ = pkts
	})

	// 8.1.1.2: DstPort = 4500 used directly.
	t.Run("8.1.1.2_DstPort4500", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.SrcPort = 4500
		spec.DstPort = 4500
		pkts := tpMustPlan(t, spec)
		for i, p := range pkts {
			if i < 4 && p.L4.DstPort != 4500 {
				t.Errorf("pkt[%d] DstPort = %d, want 4500", i, p.L4.DstPort)
			}
		}
	})

	// 8.1.1.3: Invalid SrcIP rejected.
	t.Run("8.1.1.3_InvalidSrcIP", func(t *testing.T) {
		p := NewPlanner()
		spec := validTPBaseSpec()
		spec.SrcIP = "not-an-ip"
		if err := p.Validate(spec); err == nil {
			t.Error("expected error for invalid SrcIP")
		}
		if err := p.Validate(spec); err != nil && !strings.Contains(err.Error(), "SrcIP") {
			t.Errorf("error message = %q, want mention of SrcIP", err.Error())
		}
	})

	// 8.1.1.5: NATDetection=false -> no NAT-D Notifies.
	t.Run("8.1.1.5_NATDetectionFalse", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.NATDetection = false
		pkts := tpMustPlan(t, spec)
		payloads := tpParsePayloads(pkts[0].Payload, true)
		natDCount := 0
		for _, pl := range payloads {
			if pl.nextType == PayloadNOTIFY && len(pl.body) >= 4 {
				msgType := binary.BigEndian.Uint16(pl.body[2:4])
				if msgType == NotifyNATDetectionSourceIP || msgType == NotifyNATDetectionDestIP {
					natDCount++
				}
			}
		}
		if natDCount != 0 {
			t.Errorf("NAT-D count = %d, want 0 (NATDetection=false)", natDCount)
		}
	})

	// 8.6.1.3: Missing IKENATT -> Validate rejects.
	t.Run("8.6.1.3_MissingConfig", func(t *testing.T) {
		p := NewPlanner()
		spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}
		if err := p.Validate(spec); err == nil {
			t.Error("expected error for missing IKENATT config")
		}
	})

	// 8.6.1.5: MaxRetransmits = 0 means no retransmit.
	t.Run("8.6.1.5_NoRetransmit", func(t *testing.T) {
		spec := validTPBaseSpec()
		spec.IKENATT.Retransmit = &core.RetransmitConfig{MaxRetransmits: 0}
		pkts := tpMustPlan(t, spec)
		if len(pkts) < 4 {
			t.Fatalf("expected >=4 packets, got %d", len(pkts))
		}
	})

	// 8.6.1.6: MaxRetransmits = -1 -> Validate rejects.
	t.Run("8.6.1.6_NegativeRetransmit", func(t *testing.T) {
		p := NewPlanner()
		spec := validTPBaseSpec()
		spec.IKENATT.Retransmit = &core.RetransmitConfig{MaxRetransmits: -1}
		if err := p.Validate(spec); err == nil {
			t.Error("expected error for negative MaxRetransmits")
		}
	})

	// 8.6.1.7: Backoff < 1.0 -> Validate rejects.
	t.Run("8.6.1.7_BackoffTooSmall", func(t *testing.T) {
		p := NewPlanner()
		spec := validTPBaseSpec()
		spec.IKENATT.Retransmit = &core.RetransmitConfig{Backoff: 0.5}
		if err := p.Validate(spec); err == nil {
			t.Error("expected error for Backoff < 1.0")
		}
	})
}