package snmp

// BER structure tests for SNMP PDU encoding. Per RFC 3416 §4.2, every
// standard PDU type is `[N] IMPLICIT SEQUENCE { ... }` -- the context-specific
// tag (0xA0-0xA8) REPLACES the SEQUENCE tag, so the PDU body must be the
// concatenated fields directly, NOT wrapped in an extra inner SEQUENCE.
//
// Wireshark reports "expected INTEGER tag:2 but found SEQUENCE tag:16" when
// the PDU body starts with 0x30 (SEQUENCE) instead of 0x02 (INTEGER). These
// tests verify the on-wire structure matches what Wireshark/Tshark expects.

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// parseBerLength reads a BER length field starting at buf[0]. Returns the
// parsed length and the number of bytes consumed (1 for short form, 1+n for
// long form).
func parseBerLength(buf []byte) (length int, consumed int, err error) {
	if len(buf) < 1 {
		return 0, 0, errString("empty length field")
	}
	b := buf[0]
	if b < 0x80 {
		return int(b), 1, nil
	}
	n := int(b & 0x7F)
	if n == 0 {
		return 0, 0, errString("indefinite length not supported")
	}
	if 1+n > len(buf) {
		return 0, 0, errString("truncated long-form length")
	}
	length = 0
	for i := 0; i < n; i++ {
		length = (length << 8) | int(buf[1+i])
	}
	return length, 1 + n, nil
}

// parseTLV parses one TLV at the start of buf. Returns tag, value bytes, and
// the remaining buffer after this TLV.
func parseTLV(buf []byte) (tag byte, value []byte, rest []byte, err error) {
	if len(buf) < 2 {
		return 0, nil, nil, errString("short TLV")
	}
	tag = buf[0]
	length, lc, err := parseBerLength(buf[1:])
	if err != nil {
		return 0, nil, nil, err
	}
	start := 1 + lc
	end := start + length
	if end > len(buf) {
		return 0, nil, nil, errString("TLV length exceeds buffer")
	}
	return tag, buf[start:end], buf[end:], nil
}

// integerFromTLV decodes a BER INTEGER value (already stripped of tag+length)
// as a non-negative uint32. Used for request-id / non-repeaters /
// max-repetitions verification.
func integerFromTLV(value []byte) uint32 {
	if len(value) == 0 {
		return 0
	}
	var v uint32
	for _, b := range value {
		v = (v << 8) | uint32(b)
	}
	return v
}

// findPDUInV1V2c walks the outer SNMPv1/v2c message SEQUENCE and returns the
// PDU bytes (starting at the PDU tag). The message layout is:
//   SEQUENCE { version INTEGER, community OCTET STRING, PDU }
func findPDUInV1V2c(msg []byte) ([]byte, error) {
	// Outer SEQUENCE.
	tag, body, _, err := parseTLV(msg)
	if err != nil {
		return nil, err
	}
	if tag != TagSequence {
		return nil, errString("outer message is not SEQUENCE")
	}
	// Skip version INTEGER.
	_, _, body, err = parseTLV(body)
	if err != nil {
		return nil, err
	}
	// Skip community OCTET STRING.
	_, _, body, err = parseTLV(body)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, errString("no PDU in message")
	}
	return body, nil // body starts at the PDU tag
}

// TestBER_GetBulkPDUStructure: RFC 3416 §4.2.3 GetBulkRequest-PDU is
// [5] IMPLICIT SEQUENCE { request-id INTEGER, non-repeaters INTEGER,
// max-repetitions INTEGER, variable-bindings VarBindList }.
//
// The PDU tag (0xA5) replaces the SEQUENCE tag, so the bytes immediately
// after the PDU tag+length must be an INTEGER (0x02), NOT a SEQUENCE (0x30).
// This test reproduces the Wireshark error "expected INTEGER tag:2 but found
// SEQUENCE tag:16".
func TestBER_GetBulkPDUStructure(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.PDUType = PDUGetBulkRequest
	spec.SNMP.RequestID = 0x12345678
	spec.SNMP.NonRepeaters = 2
	spec.SNMP.MaxRepetitions = 10
	cfgs := mustPlan(t, p, spec)
	if len(cfgs) < 1 {
		t.Fatal("expected at least 1 packet")
	}

	pduBytes, err := findPDUInV1V2c(cfgs[0].Payload)
	if err != nil {
		t.Fatalf("findPDUInV1V2c: %v", err)
	}

	// PDU tag must be 0xA5 (GetBulkRequest).
	pduTag := pduBytes[0]
	if pduTag != TagGetBulkRequest {
		t.Fatalf("PDU tag = 0x%02x, want 0xA5", pduTag)
	}

	// Parse PDU TLV. The value must be the fields directly (no inner SEQUENCE).
	_, pduValue, _, err := parseTLV(pduBytes)
	if err != nil {
		t.Fatalf("parseTLV(PDU): %v", err)
	}

	// The first byte of the PDU value must be INTEGER tag (0x02), NOT
	// SEQUENCE (0x30). This is exactly what Wireshark checks.
	if pduValue[0] != TagInteger {
		t.Errorf("first byte after PDU header = 0x%02x (tag %d), want 0x%02x (INTEGER) -- "+
			"Wireshark would report 'expected INTEGER tag:2 but found tag:%d'",
			pduValue[0], pduValue[0], TagInteger, pduValue[0])
	}

	// Parse the 4 fields in order: request-id INTEGER, non-repeaters INTEGER,
	// max-repetitions INTEGER, variable-bindings SEQUENCE.
	tag1, val1, rest, err := parseTLV(pduValue)
	if err != nil {
		t.Fatalf("parse field 1 (request-id): %v", err)
	}
	if tag1 != TagInteger {
		t.Errorf("field 1 tag = 0x%02x, want 0x02 (INTEGER) for request-id", tag1)
	}
	if got := integerFromTLV(val1); got != 0x12345678 {
		t.Errorf("request-id = 0x%x, want 0x12345678", got)
	}

	tag2, val2, rest, err := parseTLV(rest)
	if err != nil {
		t.Fatalf("parse field 2 (non-repeaters): %v", err)
	}
	if tag2 != TagInteger {
		t.Errorf("field 2 tag = 0x%02x, want 0x02 (INTEGER) for non-repeaters", tag2)
	}
	if got := integerFromTLV(val2); got != 2 {
		t.Errorf("non-repeaters = %d, want 2", got)
	}

	tag3, val3, rest, err := parseTLV(rest)
	if err != nil {
		t.Fatalf("parse field 3 (max-repetitions): %v", err)
	}
	if tag3 != TagInteger {
		t.Errorf("field 3 tag = 0x%02x, want 0x02 (INTEGER) for max-repetitions", tag3)
	}
	if got := integerFromTLV(val3); got != 10 {
		t.Errorf("max-repetitions = %d, want 10", got)
	}

	tag4, _, _, err := parseTLV(rest)
	if err != nil {
		t.Fatalf("parse field 4 (varbinds): %v", err)
	}
	if tag4 != TagSequence {
		t.Errorf("field 4 tag = 0x%02x, want 0x30 (SEQUENCE) for variable-bindings", tag4)
	}
}

// TestBER_GetRequestPDUStructure: RFC 3416 §4.2.1 GetRequest-PDU is
// [0] IMPLICIT PDU, where PDU ::= SEQUENCE { request-id INTEGER,
// error-status INTEGER, error-index INTEGER, variable-bindings VarBindList }.
// Same IMPLICIT tagging: PDU tag 0xA0 directly wraps the 4 fields.
func TestBER_GetRequestPDUStructure(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.PDUType = PDUGetRequest
	spec.SNMP.RequestID = 42
	cfgs := mustPlan(t, p, spec)

	pduBytes, err := findPDUInV1V2c(cfgs[0].Payload)
	if err != nil {
		t.Fatalf("findPDUInV1V2c: %v", err)
	}
	if pduBytes[0] != TagGetRequest {
		t.Fatalf("PDU tag = 0x%02x, want 0xA0", pduBytes[0])
	}
	_, pduValue, _, err := parseTLV(pduBytes)
	if err != nil {
		t.Fatalf("parseTLV(PDU): %v", err)
	}
	if pduValue[0] != TagInteger {
		t.Errorf("first byte after PDU header = 0x%02x, want 0x02 (INTEGER) for request-id", pduValue[0])
	}

	// Verify 3 INTEGERs + 1 SEQUENCE.
	tag1, _, rest, err := parseTLV(pduValue)
	if err != nil {
		t.Fatalf("field 1: %v", err)
	}
	if tag1 != TagInteger {
		t.Errorf("field 1 tag = 0x%02x, want INTEGER", tag1)
	}
	tag2, _, rest, err := parseTLV(rest)
	if err != nil {
		t.Fatalf("field 2: %v", err)
	}
	if tag2 != TagInteger {
		t.Errorf("field 2 tag = 0x%02x, want INTEGER (error-status)", tag2)
	}
	tag3, _, rest, err := parseTLV(rest)
	if err != nil {
		t.Fatalf("field 3: %v", err)
	}
	if tag3 != TagInteger {
		t.Errorf("field 3 tag = 0x%02x, want INTEGER (error-index)", tag3)
	}
	tag4, _, _, err := parseTLV(rest)
	if err != nil {
		t.Fatalf("field 4: %v", err)
	}
	if tag4 != TagSequence {
		t.Errorf("field 4 tag = 0x%02x, want SEQUENCE (varbinds)", tag4)
	}
}

// TestBER_V1TrapPDUStructure: RFC 1157 §4.1.6 Trap-PDU is
// [4] IMPLICIT SEQUENCE { enterprise OBJECT IDENTIFIER, agent-addr IpAddress,
// generic-trap INTEGER, specific-trap INTEGER, time-stamp TimeTicks,
// variable-bindings VarBindList }.
// PDU tag 0xA4 directly wraps the 6 fields (no inner SEQUENCE).
func TestBER_V1TrapPDUStructure(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv1
	spec.SNMP.PDUType = PDUTrapV1
	spec.SNMP.Enterprise = "1.3.6.1.4.1.3.1.1"
	spec.SNMP.AgentAddr = "192.168.1.1"
	spec.SNMP.GenericTrap = 6
	spec.SNMP.SpecificTrap = 1
	spec.SNMP.TimeStamp = 100
	cfgs := mustPlan(t, p, spec)

	pduBytes, err := findPDUInV1V2c(cfgs[0].Payload)
	if err != nil {
		t.Fatalf("findPDUInV1V2c: %v", err)
	}
	if pduBytes[0] != TagTrapV1 {
		t.Fatalf("PDU tag = 0x%02x, want 0xA4", pduBytes[0])
	}
	_, pduValue, _, err := parseTLV(pduBytes)
	if err != nil {
		t.Fatalf("parseTLV(PDU): %v", err)
	}
	// First byte must be OID tag (0x06), NOT SEQUENCE (0x30).
	if pduValue[0] != TagOID {
		t.Errorf("first byte after PDU header = 0x%02x, want 0x06 (OID) for enterprise", pduValue[0])
	}

	// Verify 6 fields: OID, IpAddress, INTEGER, INTEGER, TimeTicks, SEQUENCE.
	tag1, _, rest, err := parseTLV(pduValue)
	if err != nil {
		t.Fatalf("field 1 (enterprise): %v", err)
	}
	if tag1 != TagOID {
		t.Errorf("field 1 tag = 0x%02x, want 0x06 (OID)", tag1)
	}
	tag2, _, rest, err := parseTLV(rest)
	if err != nil {
		t.Fatalf("field 2 (agent-addr): %v", err)
	}
	if tag2 != TagIpAddress {
		t.Errorf("field 2 tag = 0x%02x, want 0x40 (IpAddress)", tag2)
	}
	tag3, _, rest, err := parseTLV(rest)
	if err != nil {
		t.Fatalf("field 3 (generic-trap): %v", err)
	}
	if tag3 != TagInteger {
		t.Errorf("field 3 tag = 0x%02x, want 0x02 (INTEGER)", tag3)
	}
	tag4, _, rest, err := parseTLV(rest)
	if err != nil {
		t.Fatalf("field 4 (specific-trap): %v", err)
	}
	if tag4 != TagInteger {
		t.Errorf("field 4 tag = 0x%02x, want 0x02 (INTEGER)", tag4)
	}
	tag5, _, rest, err := parseTLV(rest)
	if err != nil {
		t.Fatalf("field 5 (time-stamp): %v", err)
	}
	if tag5 != TagTimeTicks {
		t.Errorf("field 5 tag = 0x%02x, want 0x43 (TimeTicks)", tag5)
	}
	tag6, _, _, err := parseTLV(rest)
	if err != nil {
		t.Fatalf("field 6 (varbinds): %v", err)
	}
	if tag6 != TagSequence {
		t.Errorf("field 6 tag = 0x%02x, want 0x30 (SEQUENCE)", tag6)
	}
}

// TestBER_NoExtraSequenceInPDU: explicitly verify that the PDU value does NOT
// start with a SEQUENCE tag (0x30). This is the exact Wireshark failure. We
// check all PDU types that go through encodePDUWithTag.
func TestBER_NoExtraSequenceInPDU(t *testing.T) {
	tests := []struct {
		name    string
		pduType uint8
		tag     byte
	}{
		{"GetRequest", PDUGetRequest, TagGetRequest},
		{"GetNextRequest", PDUGetNextRequest, TagGetNextRequest},
		{"SetRequest", PDUSetRequest, TagSetRequest},
		{"GetBulkRequest", PDUGetBulkRequest, TagGetBulkRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := NewPlanner()
			spec := validSNMPSpec()
			spec.SNMP.PDUType = tc.pduType
			if tc.pduType == PDUGetBulkRequest {
				spec.SNMP.NonRepeaters = 1
				spec.SNMP.MaxRepetitions = 3
			}
			cfgs := mustPlan(t, p, spec)

			pduBytes, err := findPDUInV1V2c(cfgs[0].Payload)
			if err != nil {
				t.Fatalf("findPDUInV1V2c: %v", err)
			}
			if pduBytes[0] != tc.tag {
				t.Fatalf("PDU tag = 0x%02x, want 0x%02x", pduBytes[0], tc.tag)
			}
			_, pduValue, _, err := parseTLV(pduBytes)
			if err != nil {
				t.Fatalf("parseTLV(PDU): %v", err)
			}
			if pduValue[0] == TagSequence {
				t.Errorf("PDU value starts with SEQUENCE (0x30) -- extra inner SEQUENCE detected; "+
					"Wireshark would report 'expected INTEGER tag:2 but found SEQUENCE tag:16'")
			}
		})
	}
}

// TestBER_ResponsePDUStructure: Response PDU (tag 0xA2) must also have no
// inner SEQUENCE. RFC 3416 §4.2.2 Response-PDU ::= [2] IMPLICIT PDU.
func TestBER_ResponsePDUStructure(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.IsResponse = true
	spec.SNMP.ResponseError = 0
	spec.SNMP.ResponseErrorIndex = 0
	spec.SNMP.ResponseValues = []core.SNMPVarBind{
		{Name: "1.3.6.1.2.1.1.1.0", Type: TagOctetString, StrValue: "test"},
	}
	cfgs := mustPlan(t, p, spec)
	if len(cfgs) < 2 {
		t.Fatal("expected 2 packets (request + response)")
	}

	pduBytes, err := findPDUInV1V2c(cfgs[1].Payload)
	if err != nil {
		t.Fatalf("findPDUInV1V2c: %v", err)
	}
	if pduBytes[0] != TagResponse {
		t.Fatalf("PDU tag = 0x%02x, want 0xA2 (Response)", pduBytes[0])
	}
	_, pduValue, _, err := parseTLV(pduBytes)
	if err != nil {
		t.Fatalf("parseTLV(PDU): %v", err)
	}
	if pduValue[0] != TagInteger {
		t.Errorf("first byte = 0x%02x, want 0x02 (INTEGER) for request-id; "+
			"extra SEQUENCE would cause Wireshark BER error", pduValue[0])
	}
}

// Suppress unused-import warning for binary when tests evolve.
var _ = binary.BigEndian
var _ = bytes.Equal
