package l2tp

// Failing-first regression tests for the L2TP AVP encoding bugs:
//  1. AVPs are 4-byte alignment-padded by buildAVPs, but RFC 2661 §4.1 / RFC
//     3931 §5.1 define NO inter-AVP padding, and Wireshark's packet-l2tp.c
//     advances by the declared Length only (no padding skip). The trailing
//     padding zeros are misparsed as a zero-length AVP -> "AVP length must be
//     >= 6, got 0".
//  2. The AVP Length field is 10 bits (mask 0x03FF, max 1023), but the planner
//     uses a 12-bit mask (0x0FFF, max 4095), corrupting reserved bits 10-11
//     for large AVPs.
//
// These tests scan AVPs EXACTLY as Wireshark does (10-bit mask, advance by
// declared length, no padding skip) and assert spec compliance.

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// wiresharkScanAVPs mimics packet-l2tp.c process_control_avps: it walks AVPs
// starting at headerSize, masking Length with 0x03FF (10 bits) and advancing
// idx by the declared length with NO 4-byte padding skip. It returns the list
// of (declaredLen, attrType) seen and a non-nil error string the moment
// Wireshark would emit "AVP length must be >= 6, got N" or hit trailing bytes.
func wiresharkScanAVPs(t *testing.T, payload []byte, headerSize int) (avps []struct {
	declaredLen int
	attrType    uint16
}, err string) {
	t.Helper()
	idx := headerSize
	length := len(payload)
	for idx < length {
		if idx+6 > length {
			return avps, "trailing bytes (padding garbage) read as AVP header"
		}
		mh := binary.BigEndian.Uint16(payload[idx : idx+2])
		avpLen := int(mh & 0x03FF) // Wireshark AVP_LENGTH mask (10 bits)
		attrType := binary.BigEndian.Uint16(payload[idx+4 : idx+6])
		if avpLen < 6 {
			return avps, "AVP length must be >= 6, got 0 (Wireshark error)"
		}
		if idx+avpLen > length {
			return avps, "AVP declared length overruns payload"
		}
		avps = append(avps, struct {
			declaredLen int
			attrType    uint16
		}{avpLen, attrType})
		idx += avpLen // Wireshark advances by declared length ONLY (no padding)
	}
	return avps, ""
}

// TestAVPFix_NoPaddingWiresharkClean is the primary regression test: a SCCRQ
// (which contains a 10-byte Framing Caps AVP, not a multiple of 4) must parse
// cleanly under the Wireshark scan with NO "length must be >= 6, got 0" error
// and idx must land exactly on len(payload).
func TestAVPFix_NoPaddingWiresharkClean(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 1701,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		L2TP: &core.L2TPConfig{
			Version: VersionL2TPv2, Role: "lac", HostName: "vpn1",
			Scenarios: []core.L2TPStep{{Type: stepSCCRQ}},
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	var configs []core.PacketConfig
	for c := range ch {
		configs = append(configs, c)
	}
	avps, scanErr := wiresharkScanAVPs(t, configs[0].Payload, v2ControlHeaderSize)
	if scanErr != "" {
		t.Fatalf("Wireshark scan error: %s (saw %d AVPs before failure)", scanErr, len(avps))
	}
	// SCCRQ auto-AVPs: Message Type(0) + Protocol Version(2) + Framing Caps(3)
	// + Bearer Caps(4) + Host Name(7) + Vendor Name(8) + Assigned Tunnel ID(9)
	// + Receive Window Size(10) + Tie Breaker(5) = 9 AVPs (Firmware Rev only
	// when set). Verify at least the Framing Caps AVP is present.
	var sawFraming bool
	for _, a := range avps {
		if a.attrType == attrFramingCaps {
			sawFraming = true
			if a.declaredLen != 10 {
				t.Errorf("Framing Caps AVP declared length = %d, want 10", a.declaredLen)
			}
		}
	}
	if !sawFraming {
		t.Errorf("Framing Caps AVP (type 3) not found among %d AVPs", len(avps))
	}
}

// TestAVPFix_TightlyPacked asserts two consecutive AVPs are packed with NO
// padding gap, even when the first AVP's total length is not a multiple of 4.
func TestAVPFix_TightlyPacked(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1234, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version: VersionL2TPv2,
			Scenarios: []core.L2TPStep{
				{Type: stepHELLO, AVPs: []core.L2TPAVP{
					// First AVP: 6 header + 1 value = 7 bytes (not mult of 4).
					{Mandatory: false, AttrType: 200, Value: []byte{0xAA}},
					// Second AVP: 6 header + 2 value = 8 bytes.
					{Mandatory: false, AttrType: 201, Value: []byte{0xBB, 0xCC}},
				}},
			},
		},
	}
	configs := mustPlan(t, p, spec)
	payload := configs[0].Payload
	// Control header (12) + Message Type AVP (8) + AVP200 (7) + AVP201 (8) = 35.
	// With the old (buggy) padding, AVP200 would be padded to 8 -> total 36.
	if len(payload) != 12+8+7+8 {
		t.Errorf("payload length = %d, want %d (tightly packed, no padding)", len(payload), 12+8+7+8)
	}
	// Find AVP200 offset, then assert AVP201 starts exactly 7 bytes later.
	off := v2ControlHeaderSize + 8 // after header + Message Type AVP
	mh200 := binary.BigEndian.Uint16(payload[off : off+2])
	if int(mh200&0x03FF) != 7 {
		t.Fatalf("AVP200 declared length = %d, want 7", mh200&0x03FF)
	}
	off201 := off + 7 // NO padding
	if off201+6 > len(payload) {
		t.Fatalf("AVP201 header out of bounds at off=%d", off201)
	}
	mh201 := binary.BigEndian.Uint16(payload[off201 : off201+2])
	attr201 := binary.BigEndian.Uint16(payload[off201+4 : off201+6])
	if attr201 != 201 {
		t.Errorf("byte after AVP200 is not AVP201: attrType=%d (padding gap present)", attr201)
	}
	if int(mh201&0x03FF) != 8 {
		t.Errorf("AVP201 declared length = %d, want 8", mh201&0x03FF)
	}
	// Confirm the byte after AVP200's 7 bytes is AVP201's first word, not a
	// padding byte followed by AVP201. If padding were present, AVP201 would
	// start at off+8 instead and the byte at off+7 would be 0x00 with a
	// different attrType at off+8. We already read attr201 from off+7 above;
	// also verify AVP201's value bytes follow immediately.
	if off201+8 > len(payload) {
		t.Fatalf("AVP201 value out of bounds")
	}
	if payload[off201+6] != 0xBB || payload[off201+7] != 0xCC {
		t.Errorf("AVP201 value = %02x %02x, want BB CC", payload[off201+6], payload[off201+7])
	}
}

// TestAVPFix_LengthFieldIs10Bit asserts the Length field uses the 10-bit mask
// (0x03FF, max 1023), not 12 bits. Reserved bits 10-14 must stay 0.
func TestAVPFix_LengthFieldIs10Bit(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1234, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version: VersionL2TPv2,
			Scenarios: []core.L2TPStep{
				{Type: stepHELLO, AVPs: []core.L2TPAVP{
					// Value of 1017 bytes => total length 1023 = 0x3FF (max 10-bit).
					{Mandatory: false, AttrType: 200, Value: make([]byte, 1017)},
				}},
			},
		},
	}
	configs := mustPlan(t, p, spec)
	payload := configs[0].Payload
	off := v2ControlHeaderSize + 8 // after header + Message Type AVP
	mh := binary.BigEndian.Uint16(payload[off : off+2])
	declared := int(mh & 0x03FF)
	if declared != 1023 {
		t.Errorf("max 10-bit AVP declared length = %d, want 1023", declared)
	}
	// Reserved bits 10-14 must be 0. Mask them out and check only M(0x8000),
	// H(0x4000), and Length(0x03FF) bits are set.
	reserved := mh & 0x3C00 // bits 14-10 (excl M=0x8000, H=0x4000)... actually bits 13-10
	if reserved != 0 {
		t.Errorf("reserved bits set in AVP flags: 0x%04x (bits 13-10 must be 0)", mh)
	}
}

// TestAVPFix_MaxLength1023Rejected asserts a value that would exceed the 10-bit
// Length max (1023) is rejected at validation. 6 + 1018 = 1024 > 1023.
func TestAVPFix_MaxLength1023Rejected(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1234, DstPort: 1701,
		L2TP: &core.L2TPConfig{
			Version: VersionL2TPv2,
			CustomAVPs: []core.L2TPAVP{
				{AttrType: 99, Value: make([]byte, 1018)}, // 6+1018 = 1024 > 1023
			},
			Scenarios: []core.L2TPStep{{Type: stepSCCRQ}},
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Errorf("Validate accepted 1024-byte AVP (exceeds 10-bit max 1023); want error")
	}
}
