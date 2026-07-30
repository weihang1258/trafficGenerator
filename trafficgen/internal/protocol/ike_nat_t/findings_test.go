// Package ike_nat_t — failing tests for the Transform Attribute AF-bit bug.
//
// Per RFC 7296 §3.3.5, the Key Length attribute (type 14) is a fixed-length
// attribute and MUST use the TV (short) form with AF=1:
//   AF(1 bit)=1 | Attribute Type(15 bits)=14 | Attribute Value(2 bytes)
// For AES-128 this is 0x80 0x0E 0x00 0x80.
//
// The buggy encoder at planner.go:1017 emitted AF=0 (TLV long form):
//   0x00 0x0E 0x00 0x80
// which makes Wireshark parse the following 2 bytes (0x00 0x80) as a 128-byte
// Attribute Length, swallowing all subsequent transforms (PRF/INTEG/DH) as
// attribute value — producing a Malformed Packet on IKE_SA_INIT.
//
// This is the same root cause as the IKE package bug fixed in
// internal/protocol/ike/planner.go:1209 (same RFC, same line, same fix).
package ike_nat_t

import (
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// findSAPayloadBodyNATT walks the IKE payload chain (after the Non-ESP Marker
// and IKE Header) and returns the SA payload body bytes (without the 4-byte
// Generic Payload Header).
func findSAPayloadBodyNATT(payload []byte) []byte {
	if len(payload) < NonESPMarkerLen+IKEHeaderLen {
		return nil
	}
	// IKE Header byte 16 (offset from header start) = Next Payload type.
	next := payload[NonESPMarkerLen+16]
	off := NonESPMarkerLen + IKEHeaderLen
	for next != 0 && off+4 <= len(payload) {
		plLen := binary.BigEndian.Uint16(payload[off+2 : off+4])
		if int(plLen) < 4 || off+int(plLen) > len(payload) {
			return nil
		}
		if next == PayloadSA {
			return payload[off+4 : off+int(plLen)]
		}
		next = payload[off]
		off += int(plLen)
	}
	return nil
}

// nattBytesContains reports whether needle occurs in haystack.
func nattBytesContains(haystack, needle []byte) bool {
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

// TestF1_EncodeTransforms_KeyLengthAttr_TVForm asserts the Key Length attribute
// is encoded in TV form (AF=1) per RFC 7296 §3.3.5. Fails against AF=0 code.
func TestF1_EncodeTransforms_KeyLengthAttr_TVForm(t *testing.T) {
	transforms := []core.IKETransform{
		{Type: 1, ID: 12, KeyLengthBits: 256}, // ENCR_AES_CBC, 256-bit key
	}
	b := encodeTransforms(transforms)
	// Transform: Last(1)+Reserved(1)+Length(2)+Type(1)+Reserved(1)+ID(2)+Attr(4) = 12.
	if len(b) < 12 {
		t.Fatalf("encoded transform too short: %d bytes", len(b))
	}
	transformLen := binary.BigEndian.Uint16(b[2:4])
	if transformLen != 12 {
		t.Errorf("Transform Length = %d, want 12 (8 + 4-byte TV attr)", transformLen)
	}
	// RFC 7296 §3.3.5: AF=1 for fixed-length attributes.
	// Bytes [8:10] = 0x80 0x0E (AF=1, type=14); [10:12] = value (256 = 0x0100).
	if b[8]>>7 != 1 {
		t.Errorf("Key Length attr AF bit = %d, want 1 (TV form); attr bytes = %x", b[8]>>7, b[8:12])
	}
	if b[8]&0x7F != 0x00 || b[9] != 0x0E {
		t.Errorf("Key Length attr type bytes = %x, want 80 0E (AF=1 | type=14)", b[8:10])
	}
	if val := binary.BigEndian.Uint16(b[10:12]); val != 256 {
		t.Errorf("Key Length attr value = %d, want 256", val)
	}
}

// TestF1_EncodeTransforms_KeyLengthAttr_AES128 asserts the exact AES-128 wire
// bytes 0x80 0x0E 0x00 0x80 (the default scenario). Fails against AF=0 code
// which emits 0x00 0x0E 0x00 0x80.
func TestF1_EncodeTransforms_KeyLengthAttr_AES128(t *testing.T) {
	transforms := []core.IKETransform{
		{Type: 1, ID: 12, KeyLengthBits: 128},
	}
	b := encodeTransforms(transforms)
	if len(b) < 12 {
		t.Fatalf("encoded transform too short: %d bytes", len(b))
	}
	want := []byte{0x80, 0x0E, 0x00, 0x80}
	got := b[8:12]
	if !nattBytesContains(got, want) {
		t.Errorf("Key Length attr bytes = %x, want %x (AF=1 TV form per RFC 7296 §3.3.5)", got, want)
	}
}

// TestF1_EncodeTransforms_KeyLengthAttr_ZeroKeyLength verifies that a transform
// with KeyLengthBits=0 does NOT emit any attribute (negative path). This guards
// against an over-broad fix that always emits an attribute.
func TestF1_EncodeTransforms_KeyLengthAttr_ZeroKeyLength(t *testing.T) {
	transforms := []core.IKETransform{
		{Type: 2, ID: 5, KeyLengthBits: 0}, // PRF_HMAC_SHA2_256, no Key Length
	}
	b := encodeTransforms(transforms)
	// No attribute → transform length = 8.
	if len(b) != 8 {
		t.Errorf("transform with KeyLengthBits=0: encoded length = %d, want 8 (no attr)", len(b))
	}
	transformLen := binary.BigEndian.Uint16(b[2:4])
	if transformLen != 8 {
		t.Errorf("transform with KeyLengthBits=0: Length field = %d, want 8", transformLen)
	}
}

// TestF1_EncodeTransforms_RawAttributesPreserved verifies that pre-set
// RawAttributes are not clobbered by the Key Length auto-encoding path. This
// guards the `len(attrs) == 0` guard at planner.go:1016.
func TestF1_EncodeTransforms_RawAttributesPreserved(t *testing.T) {
	raw := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	transforms := []core.IKETransform{
		{Type: 1, ID: 12, KeyLengthBits: 128, RawAttributes: raw},
	}
	b := encodeTransforms(transforms)
	if len(b) < 12 {
		t.Fatalf("encoded transform too short: %d bytes", len(b))
	}
	got := b[8:12]
	if !nattBytesContains(got, raw) {
		t.Errorf("RawAttributes not preserved: got %x, want %x", got, raw)
	}
	// Ensure the auto-generated AF=1 bytes did NOT overwrite RawAttributes.
	if b[8] == 0x80 && b[9] == 0x0E {
		t.Errorf("RawAttributes overwritten by auto Key Length encoding: got %x", got)
	}
}

// TestF1_Plan_KeyLengthAttrInSAPayload is an integration test: the default
// scenario's IKE_SA_INIT packet must contain the TV-form Key Length attribute
// 0x80 0x0E 0x00 0x80 in its SA payload. Fails against AF=0 code.
func TestF1_Plan_KeyLengthAttrInSAPayload(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	if len(pkts) == 0 {
		t.Fatal("no packets emitted")
	}
	saBytes := findSAPayloadBodyNATT(pkts[0].Payload)
	if saBytes == nil {
		t.Fatal("no SA payload found in IKE_SA_INIT request")
	}
	// TV form: 0x80 0x0E (AF=1, type=14) + 0x00 0x80 (value=128).
	want := []byte{0x80, 0x0E, 0x00, 0x80}
	if !nattBytesContains(saBytes, want) {
		t.Errorf("SA payload missing TV-form Key Length attr %x; SA body=%x", want, saBytes)
	}
	// The AF=0 (buggy) sequence 0x00 0x0E 0x00 0x80 must NOT be present.
	buggy := []byte{0x00, 0x0E, 0x00, 0x80}
	if nattBytesContains(saBytes, buggy) {
		t.Errorf("SA payload contains AF=0 (TLV) Key Length attr %x — violates RFC 7296 §3.3.5; SA body=%x", buggy, saBytes)
	}
}

// TestF1_Plan_MultiTransformBoundaryNotSwallowed is the critical boundary test:
// with 4 transforms (ENCR+attr, PRF, INTEG, DH), all 4 must be parseable with
// correct lengths and last-substructure markers. Under the AF=0 bug, Wireshark
// reads the ENCR attribute's value bytes as a 128-byte length and swallows
// PRF/INTEG/DH. This test walks the transform chain in the SA payload and
// verifies each transform is intact.
func TestF1_Plan_MultiTransformBoundaryNotSwallowed(t *testing.T) {
	spec := validBaseSpec()
	pkts := mustPlan(t, spec)
	if len(pkts) == 0 {
		t.Fatal("no packets emitted")
	}
	saBytes := findSAPayloadBodyNATT(pkts[0].Payload)
	if saBytes == nil {
		t.Fatal("no SA payload found")
	}
	// SA payload body = Proposal Substructure.
	// Proposal: Last(1)+Reserved(1)+Length(2)+Number(1)+ProtocolID(1)+SPISize(1)+NumTransforms(1)+[SPI]+[Transforms]
	if len(saBytes) < 8 {
		t.Fatalf("SA payload body too short: %d bytes", len(saBytes))
	}
	spiLen := int(saBytes[6])
	numTransforms := int(saBytes[7])
	if numTransforms < 4 {
		t.Fatalf("expected >=4 transforms in default proposal, got %d", numTransforms)
	}
	transformsStart := 8 + spiLen
	off := transformsStart
	// Walk the transform chain. Each: Last(1)+Reserved(1)+Length(2)+Type(1)+Reserved(1)+ID(2)+[attrs].
	type txf struct {
		last uint8
		tlen uint16
		ttype uint8
		tid   uint16
	}
	var parsed []txf
	for off+8 <= len(saBytes) {
		last := saBytes[off]
		tlen := binary.BigEndian.Uint16(saBytes[off+2 : off+4])
		ttype := saBytes[off+4]
		tid := binary.BigEndian.Uint16(saBytes[off+6 : off+8])
		if int(tlen) < 8 || off+int(tlen) > len(saBytes) {
			t.Fatalf("transform at offset %d: invalid Length %d (off+tlen=%d > saLen=%d)",
				off, tlen, off+int(tlen), len(saBytes))
		}
		parsed = append(parsed, txf{last, tlen, ttype, tid})
		off += int(tlen)
		if last == 0 {
			break // last transform
		}
	}
	if len(parsed) < 4 {
		t.Fatalf("only %d transforms parsed (boundary swallowed?); expected >=4", len(parsed))
	}
	// Expected: ENCR(len=12,attr) + PRF(len=8) + INTEG(len=8) + DH(len=8).
	wantLens := []uint16{12, 8, 8, 8}
	wantTypes := []uint8{1, 2, 3, 4} // ENCR, PRF, INTEG, DH
	wantLasts := []uint8{3, 3, 3, 0} // 3=More, 0=Last
	for i := 0; i < 4; i++ {
		if parsed[i].tlen != wantLens[i] {
			t.Errorf("transform[%d] Length = %d, want %d (boundary swallowed?)", i, parsed[i].tlen, wantLens[i])
		}
		if parsed[i].ttype != wantTypes[i] {
			t.Errorf("transform[%d] Type = %d, want %d", i, parsed[i].ttype, wantTypes[i])
		}
		if parsed[i].last != wantLasts[i] {
			t.Errorf("transform[%d] Last marker = %d, want %d", i, parsed[i].last, wantLasts[i])
		}
	}
	// ENCR transform (index 0) must carry the TV-form Key Length attribute.
	encr := parsed[0]
	encrBytes := saBytes[transformsStart : transformsStart+int(encr.tlen)]
	if int(encr.tlen) < 12 {
		t.Fatalf("ENCR transform too short for attribute: %d bytes", encr.tlen)
	}
	attrBytes := encrBytes[8:12]
	wantAttr := []byte{0x80, 0x0E, 0x00, 0x80}
	if !nattBytesContains(attrBytes, wantAttr) {
		t.Errorf("ENCR transform attr bytes = %x, want %x (TV form AF=1)", attrBytes, wantAttr)
	}
}
