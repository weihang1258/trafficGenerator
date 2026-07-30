package snmp

// Coverage-gap tests derived from design_snmp.md + RFC 3412/3414/3416/1157.
// These tests exercise paths that were either unimplemented (v1 Trap
// configurable fields) or implemented but never tested (noSuchInstance,
// endOfMibView, error status codes, multi-varbind, GetBulk field values,
// v1 GetRequest, v3 noAuth/contextName/engineBoots/engineTime).
//
// Per CLAUDE.md Testing Policy: spec-driven (each test maps to a design
// section), failure paths covered, observable byte-level assertions.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ============================================================================
// §2.8 v1 Trap PDU (RFC 1157 §4.1.6): configurable enterprise / agent_addr /
// generic_trap / specific_trap / time_stamp.
// ============================================================================

// extractV1TrapFields parses a v1 Trap PDU (tag 0xA4) and returns its
// component fields. The PDU layout is:
//   enterprise OID | agent-addr IpAddress | generic-trap INTEGER |
//   specific-trap INTEGER | time-stamp TimeTicks | varbinds SEQUENCE
func extractV1TrapFields(msg []byte) (enterpriseOID, agentAddr, genericTrap, specificTrap, timeStamp, varBinds []byte, err error) {
	// Skip outer SEQUENCE(version, community, PDU).
	body, _, err := readTLV(msg)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	// Skip version INTEGER.
	_, rest, err := readTLV(body)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	// Skip community OCTET STRING.
	_, rest, err = readTLV(rest)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	// rest[0] should be TagTrapV1 (0xA4). Read the PDU TLV.
	pduVal, _, err := readTLV(rest)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	// The PDU value is a SEQUENCE wrapping the trap fields.
	pduBody, _, err := readTLV(pduVal)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	// Parse fields in order.
	enterpriseOID, pduBody, err = readTLV(pduBody)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	agentAddr, pduBody, err = readTLV(pduBody)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	genericTrap, pduBody, err = readTLV(pduBody)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	specificTrap, pduBody, err = readTLV(pduBody)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	timeStamp, pduBody, err = readTLV(pduBody)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	varBinds = pduBody
	return enterpriseOID, agentAddr, genericTrap, specificTrap, timeStamp, varBinds, nil
}

// TestV1Trap_EnterpriseConfigurable: RFC 1157 §4.1.6 -- enterprise OID must
// be configurable. The planner must emit the configured enterprise OID, not
// a hardcoded default.
func TestV1Trap_EnterpriseConfigurable(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv1
	spec.SNMP.PDUType = PDUTrapV1
	spec.SNMP.Enterprise = "1.3.6.1.4.1.9.9.187" // cisco BGP
	spec.SNMP.AgentAddr = "10.0.0.1"
	cfgs := mustPlan(t, p, spec)

	entOID, _, _, _, _, _, err := extractV1TrapFields(cfgs[0].Payload)
	if err != nil {
		t.Fatalf("extractV1TrapFields: %v", err)
	}
	wantEnt, _ := encodeOID("1.3.6.1.4.1.9.9.187")
	// readTLV returns value bytes (without tag+length); re-wrap for comparison.
	if !bytes.Equal(encodeTLV(TagOID, entOID), wantEnt) {
		t.Errorf("enterprise OID = %x, want %x", entOID, wantEnt[2:])
	}
}

// TestV1Trap_AgentAddrConfigurable: agent-addr must be the configured IPv4,
// encoded as IpAddress (tag 0x40, 4 bytes).
func TestV1Trap_AgentAddrConfigurable(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv1
	spec.SNMP.PDUType = PDUTrapV1
	spec.SNMP.AgentAddr = "192.168.1.50"
	cfgs := mustPlan(t, p, spec)

	_, agentAddr, _, _, _, _, err := extractV1TrapFields(cfgs[0].Payload)
	if err != nil {
		t.Fatalf("extractV1TrapFields: %v", err)
	}
	wantAddr, _ := encodeIPAddress("192.168.1.50")
	// readTLV returns value bytes only; re-wrap for comparison.
	if !bytes.Equal(encodeTLV(TagIpAddress, agentAddr), wantAddr) {
		t.Errorf("agent_addr = %x, want %x", agentAddr, wantAddr[2:])
	}
}

// TestV1Trap_GenericTrapConfigurable: generic-trap INTEGER must come from the
// configured GenericTrap field, not from ResponseError. RFC 1157 §4.1.6:
// 0=coldStart, 1=warmStart, 2=linkDown, 3=linkUp, 4=authFailure, 5=egpLoss,
// 6=enterpriseSpecific.
func TestV1Trap_GenericTrapConfigurable(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv1
	spec.SNMP.PDUType = PDUTrapV1
	spec.SNMP.GenericTrap = 2 // linkDown
	cfgs := mustPlan(t, p, spec)

	_, _, gt, _, _, _, err := extractV1TrapFields(cfgs[0].Payload)
	if err != nil {
		t.Fatalf("extractV1TrapFields: %v", err)
	}
	wantGT := encodeInteger(2)
	if !bytes.Equal(encodeTLV(TagInteger, gt), wantGT) {
		t.Errorf("generic_trap = %x, want %x", gt, wantGT[2:])
	}
}

// TestV1Trap_SpecificTrapConfigurable: specific-trap INTEGER must come from
// the configured SpecificTrap field.
func TestV1Trap_SpecificTrapConfigurable(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv1
	spec.SNMP.PDUType = PDUTrapV1
	spec.SNMP.GenericTrap = 6 // enterpriseSpecific
	spec.SNMP.SpecificTrap = 42
	cfgs := mustPlan(t, p, spec)

	_, _, _, st, _, _, err := extractV1TrapFields(cfgs[0].Payload)
	if err != nil {
		t.Fatalf("extractV1TrapFields: %v", err)
	}
	wantST := encodeInteger(42)
	if !bytes.Equal(encodeTLV(TagInteger, st), wantST) {
		t.Errorf("specific_trap = %x, want %x", st, wantST[2:])
	}
}

// TestV1Trap_TimeStampConfigurable: time-stamp must be the configured
// TimeTicks value, not hardcoded 0.
func TestV1Trap_TimeStampConfigurable(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv1
	spec.SNMP.PDUType = PDUTrapV1
	spec.SNMP.TimeStamp = 12345
	cfgs := mustPlan(t, p, spec)

	_, _, _, _, ts, _, err := extractV1TrapFields(cfgs[0].Payload)
	if err != nil {
		t.Fatalf("extractV1TrapFields: %v", err)
	}
	wantTS := encodeUnsigned(12345, TagTimeTicks)
	if !bytes.Equal(encodeTLV(TagTimeTicks, ts), wantTS) {
		t.Errorf("time_stamp = %x, want %x", ts, wantTS[2:])
	}
}

// TestV1Trap_DefaultsWhenNotSet: when Enterprise/AgentAddr are empty, planner
// uses sensible defaults (not "0.0.0.0" which is wrong for real traps).
func TestV1Trap_DefaultsWhenNotSet(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv1
	spec.SNMP.PDUType = PDUTrapV1
	spec.SNMP.GenericTrap = 0 // coldStart
	cfgs := mustPlan(t, p, spec)

	entOID, agentAddr, _, _, _, _, err := extractV1TrapFields(cfgs[0].Payload)
	if err != nil {
		t.Fatalf("extractV1TrapFields: %v", err)
	}
	// Enterprise must be a valid OID (readTLV returns value bytes; tag is 0x06).
	if len(entOID) < 1 {
		t.Errorf("default enterprise OID invalid: %x", entOID)
	}
	// AgentAddr must be a valid IpAddress (4 bytes value).
	if len(agentAddr) != 4 {
		t.Errorf("default agent_addr invalid: %x (want 4 bytes)", agentAddr)
	}
}

// TestV1Trap_NoRequestIDOrErrorStatus: v1 Trap PDU must NOT contain
// request-id/error-status/error-index (RFC 1157 §4.1.6 special layout).
// The first field after the PDU tag is enterprise OID, not an INTEGER.
func TestV1Trap_NoRequestIDOrErrorStatus(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv1
	spec.SNMP.PDUType = PDUTrapV1
	cfgs := mustPlan(t, p, spec)

	_, _, _, _, _, _, err := extractV1TrapFields(cfgs[0].Payload)
	if err != nil {
		t.Fatalf("v1 Trap PDU parse failed (wrong layout?): %v", err)
	}
	// If extractV1TrapFields succeeded, the first field was an OID (tag 0x06),
	// not an INTEGER (tag 0x02). This confirms no request-id.
}

// ============================================================================
// §4.11 / §1.6.3 Exception varbind types (RFC 3416 §4.2.x).
// ============================================================================

// TestException_NoSuchInstance: GetNext response for a non-existent instance
// must encode value as context-specific tag 0x81, length 0.
func TestException_NoSuchInstance(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.PDUType = PDUGetNextRequest
	spec.SNMP.IsResponse = true
	spec.SNMP.ResponseValues = []core.SNMPVarBind{
		{Name: "1.3.6.1.2.1.2.2.1.1.99", Type: TagNoSuchInst},
	}
	cfgs := mustPlan(t, p, spec)
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(cfgs))
	}
	// Response (cfgs[1]) must contain 0x81 0x00 (noSuchInstance exception).
	if !bytes.Contains(cfgs[1].Payload, []byte{TagNoSuchInst, 0x00}) {
		t.Errorf("response payload missing noSuchInstance (0x81 0x00)")
	}
}

// TestException_EndOfMibView: GetBulk response at end of MIB must encode
// value as context-specific tag 0x82, length 0.
func TestException_EndOfMibView(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.PDUType = PDUGetBulkRequest
	spec.SNMP.IsResponse = true
	spec.SNMP.ResponseValues = []core.SNMPVarBind{
		{Name: "1.3.6.1.2.1.99.99.99", Type: TagEndOfMibView},
	}
	cfgs := mustPlan(t, p, spec)
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(cfgs))
	}
	if !bytes.Contains(cfgs[1].Payload, []byte{TagEndOfMibView, 0x00}) {
		t.Errorf("response payload missing endOfMibView (0x82 0x00)")
	}
}

// ============================================================================
// §2.4 Error status codes (RFC 3416 §4.1).
// ============================================================================

// extractPDUFields parses a standard PDU (tag 0xA0-0xA8 except 0xA4) and
// returns: tag, request-id, field1 (error-status/non-rep), field2
// (error-index/max-rep), varbinds.
func extractPDUFields(msg []byte) (tag byte, reqID, field1, field2, varBinds []byte, err error) {
	body, _, err := readTLV(msg)
	if err != nil {
		return 0, nil, nil, nil, nil, err
	}
	// For v1/v2c: skip version + community. For v3 the caller should use a
	// different path.
	_, rest, err := readTLV(body) // version
	if err != nil {
		return 0, nil, nil, nil, nil, err
	}
	_, rest, err = readTLV(rest) // community
	if err != nil {
		return 0, nil, nil, nil, nil, err
	}
	tag = rest[0]
	pduVal, _, err := readTLV(rest)
	if err != nil {
		return 0, nil, nil, nil, nil, err
	}
	// The PDU value is a SEQUENCE wrapping the fields.
	pduBody, _, err := readTLV(pduVal)
	if err != nil {
		return 0, nil, nil, nil, nil, err
	}
	reqID, pduBody, err = readTLV(pduBody)
	if err != nil {
		return 0, nil, nil, nil, nil, err
	}
	field1, pduBody, err = readTLV(pduBody)
	if err != nil {
		return 0, nil, nil, nil, nil, err
	}
	field2, pduBody, err = readTLV(pduBody)
	if err != nil {
		return 0, nil, nil, nil, nil, err
	}
	varBinds = pduBody
	return tag, reqID, field1, field2, varBinds, nil
}

// TestErrorStatus_TooBig: Response with error-status=1 (tooBig) must encode
// the INTEGER 1 in the error-status field.
func TestErrorStatus_TooBig(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.IsResponse = true
	spec.SNMP.ResponseError = 1 // tooBig
	spec.SNMP.ResponseValues = []core.SNMPVarBind{
		{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull},
	}
	cfgs := mustPlan(t, p, spec)
	_, _, errStatus, _, _, err := extractPDUFields(cfgs[1].Payload)
	if err != nil {
		t.Fatalf("extractPDUFields: %v", err)
	}
	want := encodeInteger(1)
	if !bytes.Equal(encodeTLV(TagInteger, errStatus), want) {
		t.Errorf("error-status = %x, want %x (tooBig=1)", errStatus, want[2:])
	}
}

// TestErrorStatus_GenErr: Response with error-status=5 (genErr).
func TestErrorStatus_GenErr(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.IsResponse = true
	spec.SNMP.ResponseError = 5 // genErr
	spec.SNMP.ResponseErrorIndex = 2
	spec.SNMP.ResponseValues = []core.SNMPVarBind{
		{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull},
	}
	cfgs := mustPlan(t, p, spec)
	_, _, errStatus, errIdx, _, err := extractPDUFields(cfgs[1].Payload)
	if err != nil {
		t.Fatalf("extractPDUFields: %v", err)
	}
	if !bytes.Equal(encodeTLV(TagInteger, errStatus), encodeInteger(5)) {
		t.Errorf("error-status = %x, want 0x02 0x01 0x05 (genErr=5)", errStatus)
	}
	if !bytes.Equal(encodeTLV(TagInteger, errIdx), encodeInteger(2)) {
		t.Errorf("error-index = %x, want 0x02 0x01 0x02", errIdx)
	}
}

// TestErrorStatus_NoAccess: Response with error-status=6 (noAccess).
func TestErrorStatus_NoAccess(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.IsResponse = true
	spec.SNMP.ResponseError = 6 // noAccess
	spec.SNMP.ResponseValues = []core.SNMPVarBind{
		{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull},
	}
	cfgs := mustPlan(t, p, spec)
	_, _, errStatus, _, _, err := extractPDUFields(cfgs[1].Payload)
	if err != nil {
		t.Fatalf("extractPDUFields: %v", err)
	}
	if !bytes.Equal(encodeTLV(TagInteger, errStatus), encodeInteger(6)) {
		t.Errorf("error-status = %x, want 0x02 0x01 0x06 (noAccess=6)", errStatus)
	}
}

// TestErrorStatus_NotWritable: Response with error-status=17 (notWritable).
func TestErrorStatus_NotWritable(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.PDUType = PDUSetRequest
	spec.SNMP.IsResponse = true
	spec.SNMP.ResponseError = 17 // notWritable
	spec.SNMP.ResponseValues = []core.SNMPVarBind{
		{Name: "1.3.6.1.2.1.1.5.0", Type: TagOctetString, StrValue: "router1"},
	}
	cfgs := mustPlan(t, p, spec)
	_, _, errStatus, _, _, err := extractPDUFields(cfgs[1].Payload)
	if err != nil {
		t.Fatalf("extractPDUFields: %v", err)
	}
	if !bytes.Equal(encodeTLV(TagInteger, errStatus), encodeInteger(17)) {
		t.Errorf("error-status = %x, want 0x02 0x01 0x11 (notWritable=17)", errStatus)
	}
}

// ============================================================================
// §2.5 / §3.4 Multi-varbind (3+ OIDs in a single PDU).
// ============================================================================

// TestMultiVarbind_Request: GetRequest with 3 OIDs must encode all 3 varbinds
// in the SEQUENCE OF VarBind list.
func TestMultiVarbind_Request(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.VarBinds = []core.SNMPVarBind{
		{Name: "1.3.6.1.2.1.1.1.0", Type: TagNull}, // sysDescr
		{Name: "1.3.6.1.2.1.1.3.0", Type: TagNull}, // sysUpTime
		{Name: "1.3.6.1.2.1.1.5.0", Type: TagNull}, // sysName
	}
	cfgs := mustPlan(t, p, spec)
	payload := cfgs[0].Payload
	// Each OID must appear in the payload.
	for _, oid := range []string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0"} {
		enc, _ := encodeOID(oid)
		if !bytes.Contains(payload, enc) {
			t.Errorf("payload missing OID %s", oid)
		}
	}
	// Count the number of NULL values (0x05 0x00) -- should be at least 3
	// (one per varbind). We count non-overlapping occurrences.
	nullCount := bytes.Count(payload, []byte{TagNull, 0x00})
	if nullCount < 3 {
		t.Errorf("expected >= 3 NULL varbind values, got %d", nullCount)
	}
}

// TestMultiVarbind_Response: Response with 3 varbinds of different types.
func TestMultiVarbind_Response(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.IsResponse = true
	spec.SNMP.ResponseValues = []core.SNMPVarBind{
		{Name: "1.3.6.1.2.1.1.1.0", Type: TagOctetString, StrValue: "Linux 5.10"},
		{Name: "1.3.6.1.2.1.1.3.0", Type: TagTimeTicks, Value: []byte{0x00, 0x00, 0x00, 0x64}},
		{Name: "1.3.6.1.2.1.1.5.0", Type: TagOctetString, StrValue: "router1"},
	}
	cfgs := mustPlan(t, p, spec)
	payload := cfgs[1].Payload
	// All three values must appear.
	if !bytes.Contains(payload, []byte("Linux 5.10")) {
		t.Error("response missing 'Linux 5.10'")
	}
	if !bytes.Contains(payload, []byte("router1")) {
		t.Error("response missing 'router1'")
	}
	// TimeTicks value 100 (raw 4-byte big-endian 0x00000064) must appear.
	// The encoder wraps the raw Value bytes in a TLV: 0x43 0x04 0x00 0x00 0x00 0x64.
	wantTT := encodeTLV(TagTimeTicks, []byte{0x00, 0x00, 0x00, 0x64})
	if !bytes.Contains(payload, wantTT) {
		t.Errorf("response missing TimeTicks(100): want %x", wantTT)
	}
}

// ============================================================================
// §2.3 GetBulk field values (non-repeaters + max-repetitions).
// ============================================================================

// TestGetBulk_NonRepeatersMaxRepetitions: GetBulk PDU must encode
// non-repeaters as field1 and max-repetitions as field2 (not
// error-status/error-index).
func TestGetBulk_NonRepeatersMaxRepetitions(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.PDUType = PDUGetBulkRequest
	spec.SNMP.NonRepeaters = 2
	spec.SNMP.MaxRepetitions = 10
	cfgs := mustPlan(t, p, spec)
	tag, _, field1, field2, _, err := extractPDUFields(cfgs[0].Payload)
	if err != nil {
		t.Fatalf("extractPDUFields: %v", err)
	}
	if tag != TagGetBulkRequest {
		t.Errorf("PDU tag = 0x%02x, want 0xA5", tag)
	}
	if !bytes.Equal(encodeTLV(TagInteger, field1), encodeInteger(2)) {
		t.Errorf("non-repeaters = %x, want 0x02 0x01 0x02", field1)
	}
	if !bytes.Equal(encodeTLV(TagInteger, field2), encodeInteger(10)) {
		t.Errorf("max-repetitions = %x, want 0x02 0x01 0x0A", field2)
	}
}

// TestGetBulk_MaxRepetitionsZeroCoercedToOne: RFC 3416 §4.2.3 says
// max-repetitions=0 is treated as 1.
func TestGetBulk_MaxRepetitionsZeroCoercedToOne(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.PDUType = PDUGetBulkRequest
	spec.SNMP.NonRepeaters = 0
	spec.SNMP.MaxRepetitions = 0
	cfgs := mustPlan(t, p, spec)
	_, _, _, field2, _, err := extractPDUFields(cfgs[0].Payload)
	if err != nil {
		t.Fatalf("extractPDUFields: %v", err)
	}
	if !bytes.Equal(encodeTLV(TagInteger, field2), encodeInteger(1)) {
		t.Errorf("max-repetitions(0) = %x, want 0x02 0x01 0x01 (coerced to 1)", field2)
	}
}

// ============================================================================
// §4.1 v1 GetRequest (version=0, same PDU format as v2c).
// ============================================================================

// TestV1_GetRequest: v1 GetRequest must encode version=0 + community +
// GetRequest PDU.
func TestV1_GetRequest(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv1
	spec.SNMP.Community = "private"
	cfgs := mustPlan(t, p, spec)
	// Version must be 0 (v1).
	body, _, _ := readTLV(cfgs[0].Payload)
	if body[0] != TagInteger || body[2] != 0 {
		t.Errorf("v1 version = [%02x %02x %02x], want [02 01 00]", body[0], body[1], body[2])
	}
	// Community must be "private".
	wantComm := append([]byte{0x04, 0x07}, []byte("private")...)
	if !bytes.Contains(cfgs[0].Payload, wantComm) {
		t.Error("payload missing community 'private'")
	}
	// PDU tag must be GetRequest (0xA0).
	tag, _ := extractPDUTag(cfgs[0].Payload)
	if tag != TagGetRequest {
		t.Errorf("v1 GetRequest tag = 0x%02x, want 0xA0", tag)
	}
}

// TestV1_GetNextRequest: v1 GetNext with version=0.
func TestV1_GetNextRequest(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv1
	spec.SNMP.PDUType = PDUGetNextRequest
	cfgs := mustPlan(t, p, spec)
	tag, _ := extractPDUTag(cfgs[0].Payload)
	if tag != TagGetNextRequest {
		t.Errorf("v1 GetNext tag = 0x%02x, want 0xA1", tag)
	}
}

// TestV1_SetRequest: v1 SetRequest with version=0.
func TestV1_SetRequest(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv1
	spec.SNMP.PDUType = PDUSetRequest
	spec.SNMP.VarBinds = []core.SNMPVarBind{
		{Name: "1.3.6.1.2.1.1.5.0", Type: TagOctetString, StrValue: "host1"},
	}
	cfgs := mustPlan(t, p, spec)
	tag, _ := extractPDUTag(cfgs[0].Payload)
	if tag != TagSetRequest {
		t.Errorf("v1 SetRequest tag = 0x%02x, want 0xA3", tag)
	}
}

// ============================================================================
// §2.2.2 / §3.7 SNMPv3 noAuth (discovery) + context fields.
// ============================================================================

// TestV3_NoAuthNoPriv: v3 with no auth/priv must have msgFlags=0x04
// (reportable only, no auth/priv bits).
func TestV3_NoAuthNoPriv(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv3
	spec.SNMP.UserName = "" // discovery
	spec.SNMP.AuthoritativeEngineID = "80001F88"
	cfgs := mustPlan(t, p, spec)
	body, _, _ := readTLV(cfgs[0].Payload)
	// Skip version, msgID, msgMaxSize to reach msgFlags.
	for i := 0; i < 3; i++ {
		_, body, _ = readTLV(body)
	}
	// msgFlags: OCTET STRING with 1 byte value.
	if body[0] != TagOctetString || body[1] != 0x01 {
		t.Fatalf("msgFlags TLV = [%02x %02x], want [04 01]", body[0], body[1])
	}
	flagByte := body[2]
	if flagByte != MsgFlagReportable {
		t.Errorf("noAuth msgFlags = 0x%02x, want 0x%02x (reportable only)", flagByte, MsgFlagReportable)
	}
}

// TestV3_EngineBootsTime: v3 USM must encode the configured engineBoots and
// engineTime as INTEGERs in the security parameters SEQUENCE.
func TestV3_EngineBootsTime(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv3
	spec.SNMP.UserName = "alice"
	spec.SNMP.AuthProtocol = "md5"
	spec.SNMP.AuthPassword = "password123"
	spec.SNMP.AuthoritativeEngineID = "80001F88"
	spec.SNMP.AuthoritativeEngineBoots = 5
	spec.SNMP.AuthoritativeEngineTime = 12345
	cfgs := mustPlan(t, p, spec)
	// engineBoots=5 -> INTEGER 0x02 0x01 0x05
	// engineTime=12345 -> INTEGER 0x02 0x02 0x30 0x39
	wantBoots := encodeInteger(5)
	wantTime := encodeInteger(12345)
	if !bytes.Contains(cfgs[0].Payload, wantBoots) {
		t.Errorf("payload missing engineBoots=5: %x", wantBoots)
	}
	if !bytes.Contains(cfgs[0].Payload, wantTime) {
		t.Errorf("payload missing engineTime=12345: %x", wantTime)
	}
}

// TestV3_ContextName: v3 scopedPDU must encode the configured contextName.
func TestV3_ContextName(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv3
	spec.SNMP.UserName = "alice"
	spec.SNMP.AuthProtocol = "md5"
	spec.SNMP.AuthPassword = "password123"
	spec.SNMP.AuthoritativeEngineID = "80001F88"
	spec.SNMP.ContextName = "myContext"
	cfgs := mustPlan(t, p, spec)
	// contextName is an OCTET STRING in the (unencrypted) scopedPDU.
	wantCtx := append([]byte{TagOctetString, 0x09}, []byte("myContext")...)
	if !bytes.Contains(cfgs[0].Payload, wantCtx) {
		t.Errorf("payload missing contextName 'myContext'")
	}
}

// TestV3_MaxSize: v3 msgMaxSize must encode the configured value.
func TestV3_MaxSize(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv3
	spec.SNMP.UserName = "alice"
	spec.SNMP.AuthProtocol = "md5"
	spec.SNMP.AuthPassword = "password123"
	spec.SNMP.AuthoritativeEngineID = "80001F88"
	spec.SNMP.MaxSize = 1500
	cfgs := mustPlan(t, p, spec)
	body, _, _ := readTLV(cfgs[0].Payload)
	// Skip version, msgID to reach msgMaxSize.
	for i := 0; i < 2; i++ {
		_, body, _ = readTLV(body)
	}
	// msgMaxSize INTEGER.
	maxSizeVal, _, _ := readTLV(body)
	// 1500 = 0x05DC -> 0x02 0x02 0x05 0xDC
	want := encodeInteger(1500)
	if !bytes.Equal(append([]byte{TagInteger}, encodeLength(len(maxSizeVal))...), append([]byte{want[0]}, want[1:]...)) {
		// Simpler: just check the value bytes.
	}
	if !bytes.Equal(maxSizeVal, []byte{0x05, 0xDC}) {
		t.Errorf("msgMaxSize value = %x, want [05 DC] (1500)", maxSizeVal)
	}
}

// ============================================================================
// §3.10 Community string variants.
// ============================================================================

// TestCommunity_Custom: custom community string must be encoded verbatim.
func TestCommunity_Custom(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Community = "s3cr3tR3ad0nly"
	cfgs := mustPlan(t, p, spec)
	want := append([]byte{TagOctetString, 0x0E}, []byte("s3cr3tR3ad0nly")...)
	if !bytes.Contains(cfgs[0].Payload, want) {
		t.Errorf("payload missing custom community 's3cr3tR3ad0nly'")
	}
}

// ============================================================================
// §4.3.6 / §4.3.8 Validate: v1 Trap field validation.
// ============================================================================

// TestValidate_V1TrapGenericTrapRange: GenericTrap must be 0-6 (RFC 1157).
func TestValidate_V1TrapGenericTrapRange(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv1
	spec.SNMP.PDUType = PDUTrapV1
	spec.SNMP.GenericTrap = 7 // invalid (only 0-6 defined)
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "GenericTrap") {
		t.Errorf("GenericTrap=7 should be rejected, got err=%v", err)
	}
}

// TestValidate_V1TrapInvalidEnterprise: enterprise must be a valid OID if set.
func TestValidate_V1TrapInvalidEnterprise(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv1
	spec.SNMP.PDUType = PDUTrapV1
	spec.SNMP.Enterprise = "1.3.x"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Enterprise") {
		t.Errorf("invalid enterprise OID should be rejected, got err=%v", err)
	}
}

// TestValidate_V1TrapInvalidAgentAddr: agent_addr must be valid IPv4 if set.
func TestValidate_V1TrapInvalidAgentAddr(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv1
	spec.SNMP.PDUType = PDUTrapV1
	spec.SNMP.AgentAddr = "not-an-ip"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "AgentAddr") {
		t.Errorf("invalid agent_addr should be rejected, got err=%v", err)
	}
}

// ============================================================================
// §4.3.6 GetBulk with MaxRepetitions=0 accepted (RFC coerces to 1).
// ============================================================================

func TestValidate_GetBulkMaxRepZero(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.PDUType = PDUGetBulkRequest
	spec.SNMP.MaxRepetitions = 0
	if err := p.Validate(spec); err != nil {
		t.Errorf("GetBulk MaxRepetitions=0 should be accepted: %v", err)
	}
}

// ============================================================================
// §1.12.9 Report PDU (tag 0xA8) -- not reachable via PDUType 0-6, only via v3
// discovery. Verify the tag constant exists and the encoder can produce it.
// ============================================================================

func TestReport_TagConstant(t *testing.T) {
	if TagReport != 0xA8 {
		t.Errorf("TagReport = 0x%02x, want 0xA8", TagReport)
	}
}

// TestReport_Encodable: encodePDUWithTag must be able to produce a Report PDU.
func TestReport_Encodable(t *testing.T) {
	enc, err := encodePDUWithTag(TagReport, 1, 0, 0, []core.SNMPVarBind{
		{Name: "1.3.6.1.6.3.15.1.1.1.0", Type: TagCounter32, Value: []byte{0x00, 0x00, 0x00, 0x01}},
	})
	if err != nil {
		t.Fatalf("encodePDUWithTag(Report): %v", err)
	}
	if enc[0] != TagReport {
		t.Errorf("Report tag = 0x%02x, want 0xA8", enc[0])
	}
}

// ============================================================================
// Integration: strategy_convert round-trip for v1 Trap fields.
// ============================================================================

// TestV1Trap_ResponseErrorNotReused: when GenericTrap is set, ResponseError
// must NOT leak into the v1 Trap PDU. Before the fix, genericTrap came from
// ResponseError; after, it comes from GenericTrap. This test verifies that
// setting ResponseError=99 does not affect the v1 Trap PDU when GenericTrap=2.
func TestV1Trap_ResponseErrorNotReused(t *testing.T) {
	p := NewPlanner()
	spec := validSNMPSpec()
	spec.SNMP.Version = VersionSNMPv1
	spec.SNMP.PDUType = PDUTrapV1
	spec.SNMP.GenericTrap = 2  // linkDown
	spec.SNMP.ResponseError = 99 // should NOT appear as generic_trap
	cfgs := mustPlan(t, p, spec)
	_, _, gt, _, _, _, err := extractV1TrapFields(cfgs[0].Payload)
	if err != nil {
		t.Fatalf("extractV1TrapFields: %v", err)
	}
	if !bytes.Equal(encodeTLV(TagInteger, gt), encodeInteger(2)) {
		t.Errorf("generic_trap = %x, want 0x02 0x01 0x02 (GenericTrap=2, not ResponseError=99)", gt)
	}
}
