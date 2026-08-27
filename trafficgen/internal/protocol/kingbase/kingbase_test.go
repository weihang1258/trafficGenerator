package kingbase

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func hex(b []byte) string {
	const hextable = "0123456789abcdef"
	r := make([]byte, len(b)*2)
	for i, v := range b {
		r[i*2] = hextable[v>>4]
		r[i*2+1] = hextable[v&0x0f]
	}
	return string(r)
}

// --- Builder tests ---

func TestBuildStartupMessage(t *testing.T) {
	params := map[string]string{"user": "test", "database": "test"}
	msg := buildStartupMessage(ProtocolV3, params)
	// Format: [int32 length][int32 protocol_version][key\0value\0...]\0
	if len(msg) < 9 {
		t.Fatalf("startup message too short: %d", len(msg))
	}
	length := binary.BigEndian.Uint32(msg[0:4])
	if int(length) != len(msg) {
		t.Fatalf("length field=%d != msg len=%d", length, len(msg))
	}
	protoVer := binary.BigEndian.Uint32(msg[4:8])
	if protoVer != ProtocolV3 {
		t.Fatalf("protocol_version=0x%08x want 0x%08x", protoVer, ProtocolV3)
	}
	// Body starts after the 8-byte header and carries the params
	body := msg[8:]
	if !containsNullTerminated(body, "user") {
		t.Fatal("startup body missing 'user' key")
	}
	if !containsNullTerminated(body, "database") {
		t.Fatal("startup body missing 'database' key")
	}
}

func TestBuildStartupMessageMinParams(t *testing.T) {
	// Empty params — should still produce valid message with just version + terminator
	msg := buildStartupMessage(ProtocolV3, nil)
	if len(msg) < 9 {
		t.Fatalf("startup message too short: %d", len(msg))
	}
	length := binary.BigEndian.Uint32(msg[0:4])
	if int(length) != len(msg) {
		t.Fatalf("length field=%d != msg len=%d", length, len(msg))
	}
	protoVer := binary.BigEndian.Uint32(msg[4:8])
	if protoVer != ProtocolV3 {
		t.Fatalf("protocol_version=0x%08x want 0x%08x", protoVer, ProtocolV3)
	}
	// After version, there should be no user/database params, just terminator
	rest := msg[8:]
	if len(rest) != 1 || rest[0] != 0 {
		t.Fatalf("empty params body should be just null terminator, got %x", rest)
	}
}

func TestBuildStartupMessageDefaultUser(t *testing.T) {
	// When both user and database are empty, buildEventPayload defaults user to "test"
	// Test the raw builder with empty params to verify it produces valid output
	msg := buildStartupMessage(ProtocolV3, map[string]string{})
	length := binary.BigEndian.Uint32(msg[0:4])
	if int(length) != len(msg) {
		t.Fatalf("length field=%d != msg len=%d", length, len(msg))
	}
}

func TestBuildTypedMessage(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	msg := buildTypedMessage('Q', payload)
	if len(msg) != 5+len(payload) {
		t.Fatalf("length=%d want %d", len(msg), 5+len(payload))
	}
	if msg[0] != 'Q' {
		t.Fatalf("type byte=0x%02x want 'Q'", msg[0])
	}
	length := binary.BigEndian.Uint32(msg[1:5])
	if int(length) != 4+len(payload) {
		t.Fatalf("length field=%d want %d", length, 4+len(payload))
	}
	for i, b := range payload {
		if msg[5+i] != b {
			t.Fatalf("payload[%d]=0x%02x want 0x%02x", i, msg[5+i], b)
		}
	}
}

func TestBuildTypedMessageNilPayload(t *testing.T) {
	msg := buildTypedMessage('X', nil)
	if len(msg) != 5 {
		t.Fatalf("length=%d want 5", len(msg))
	}
	if msg[0] != 'X' {
		t.Fatalf("type byte=0x%02x want 'X'", msg[0])
	}
	length := binary.BigEndian.Uint32(msg[1:5])
	if length != 4 {
		t.Fatalf("length field=%d want 4", length)
	}
}

func TestBuildAuthRequest(t *testing.T) {
	msg := buildAuthRequest(authCleartext)
	if msg[0] != typeAuth {
		t.Fatalf("type byte=0x%02x want 0x52", msg[0])
	}
	code := binary.BigEndian.Uint32(msg[5:9])
	if code != 3 {
		t.Fatalf("auth code=%d want 3 (cleartext)", code)
	}
}

func TestBuildAuthOk(t *testing.T) {
	msg := buildAuthOk()
	if msg[0] != typeAuth {
		t.Fatalf("type byte=0x%02x want 0x52", msg[0])
	}
	code := binary.BigEndian.Uint32(msg[5:9])
	if code != 0 {
		t.Fatalf("auth code=%d want 0 (ok)", code)
	}
}

func TestBuildPasswordMessage(t *testing.T) {
	msg := buildPasswordMessage("testpass")
	if msg[0] != typePassword {
		t.Fatalf("type byte=0x%02x want 0x70", msg[0])
	}
	// Password should be null-terminated
	payload := msg[5:]
	if string(payload[:len(payload)-1]) != "testpass" {
		t.Fatalf("password=%q want testpass", string(payload[:len(payload)-1]))
	}
	if payload[len(payload)-1] != 0 {
		t.Fatal("password missing null terminator")
	}
}

func TestBuildParameterStatus(t *testing.T) {
	msg := buildParameterStatus("server_version", "15.0")
	if msg[0] != typeParameter {
		t.Fatalf("type byte=0x%02x want 0x53", msg[0])
	}
	payload := msg[5:]
	// Check key\0value\0 pattern
	if !containsNullTerminated(payload, "server_version") {
		t.Fatal("parameter status missing 'server_version' key")
	}
	if !containsNullTerminated(payload, "15.0") {
		t.Fatal("parameter status missing '15.0' value")
	}
}

func TestBuildReadyForQuery(t *testing.T) {
	msg := buildReadyForQuery(rfqIdle)
	if msg[0] != typeReadyForQuery {
		t.Fatalf("type byte=0x%02x want 0x5a", msg[0])
	}
	if msg[5] != rfqIdle {
		t.Fatalf("status byte=0x%02x want 'I'", msg[5])
	}
}

func TestBuildQueryMessage(t *testing.T) {
	msg := buildQueryMessage("SELECT 1")
	if msg[0] != typeQuery {
		t.Fatalf("type byte=0x%02x want 0x51", msg[0])
	}
	payload := msg[5:]
	if string(payload[:len(payload)-1]) != "SELECT 1" {
		t.Fatalf("sql=%q want SELECT 1", string(payload[:len(payload)-1]))
	}
	if payload[len(payload)-1] != 0 {
		t.Fatal("query missing null terminator")
	}
}

func TestBuildRowDescription(t *testing.T) {
	msg := buildRowDescription()
	if msg[0] != typeRowDesc {
		t.Fatalf("type byte=0x%02x want 0x54", msg[0])
	}
	// Field count = 1
	fieldCount := binary.BigEndian.Uint16(msg[5:7])
	if fieldCount != 1 {
		t.Fatalf("field_count=%d want 1", fieldCount)
	}
}

func TestBuildDataRow(t *testing.T) {
	msg := buildDataRow()
	if msg[0] != typeDataRow {
		t.Fatalf("type byte=0x%02x want 0x44", msg[0])
	}
	// Column count = 1
	colCount := binary.BigEndian.Uint16(msg[5:7])
	if colCount != 1 {
		t.Fatalf("column_count=%d want 1", colCount)
	}
}

func TestBuildCommandComplete(t *testing.T) {
	msg := buildCommandComplete("SELECT 1")
	if msg[0] != typeCmdComplete {
		t.Fatalf("type byte=0x%02x want 0x43", msg[0])
	}
	payload := msg[5:]
	if string(payload[:len(payload)-1]) != "SELECT 1" {
		t.Fatalf("tag=%q want SELECT 1", string(payload[:len(payload)-1]))
	}
}

func TestBuildErrorResponse(t *testing.T) {
	msg := buildErrorResponse("ERROR", "28P01", "invalid password")
	if msg[0] != typeError {
		t.Fatalf("type byte=0x%02x want 0x45", msg[0])
	}
	payload := msg[5:]
	// Should contain 'S' severity, 'C' code, 'M' message fields
	if !containsNullTerminated(payload, "ERROR") {
		t.Fatal("error response missing severity 'ERROR'")
	}
	if !containsNullTerminated(payload, "28P01") {
		t.Fatal("error response missing code '28P01'")
	}
	if !containsNullTerminated(payload, "invalid password") {
		t.Fatal("error response missing message")
	}
}

func TestBuildTerminateMessage(t *testing.T) {
	msg := buildTerminateMessage()
	if msg[0] != typeTerminate {
		t.Fatalf("type byte=0x%02x want 0x58", msg[0])
	}
	if len(msg) != 5 {
		t.Fatalf("length=%d want 5 (type + 4-byte length)", len(msg))
	}
}

func TestApplyTruncateStartup(t *testing.T) {
	startup := buildStartupMessage(ProtocolV3, map[string]string{"user": "test"})
	originalLen := len(startup)
	truncated, err := applyTruncateStartup(startup, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(truncated) != originalLen-4 {
		t.Fatalf("truncated length=%d want %d", len(truncated), originalLen-4)
	}
}

func TestApplyTruncateStartupZero(t *testing.T) {
	startup := buildStartupMessage(ProtocolV3, map[string]string{"user": "test"})
	truncated, err := applyTruncateStartup(startup, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(truncated) != len(startup) {
		t.Fatalf("truncated length=%d want %d (unchanged)", len(truncated), len(startup))
	}
}

func TestApplyTruncateStartupOverTruncate(t *testing.T) {
	startup := buildStartupMessage(ProtocolV3, map[string]string{"user": "test"})
	_, err := applyTruncateStartup(startup, len(startup))
	if err == nil {
		t.Fatal("expected error for over-truncation")
	}
}

func TestApplyTruncateStartupNegative(t *testing.T) {
	startup := buildStartupMessage(ProtocolV3, map[string]string{"user": "test"})
	truncated, err := applyTruncateStartup(startup, -1)
	if err != nil {
		t.Fatal(err)
	}
	if len(truncated) != len(startup) {
		t.Fatalf("negative truncation should return unchanged, got len=%d", len(truncated))
	}
}

// --- Validate tests ---

func TestValidateKingBaseConfigRequired(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{})
	if err == nil || err.Error() != "kingbase: config is required" {
		t.Fatalf("err=%v want config is required", err)
	}
}

func TestValidateKingBaseWireProfileRequired(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{KingBase: &core.KingBaseConfig{}})
	if err == nil || err.Error() != "kingbase: wire_profile is required" {
		t.Fatalf("err=%v want wire_profile is required", err)
	}
}

func TestValidateKingBaseUnknownProfile(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		KingBase: &core.KingBaseConfig{
			WireProfile: "unknown_profile",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s"},
			},
		},
	})
	if err == nil || err.Error() != `kingbase: unknown wire profile "unknown_profile"` {
		t.Fatalf("err=%v want unknown profile", err)
	}
}

func TestValidateKingBaseNativePending(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_native_pending",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s"},
			},
		},
	})
	if err == nil || err.Error() != `kingbase: wire profile "kingbase_native_pending" has no fixed payload (native pending)` {
		t.Fatalf("err=%v want native pending", err)
	}
}

func TestValidateKingBaseEmptyEvents(t *testing.T) {
	// S1: empty events should be valid
	err := (Planner{}).Validate(core.FlowSpec{
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events:      []core.KingBaseEvent{},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateKingBaseNonStandardPort(t *testing.T) {
	// N2: nonstandard port rejected
	err := (Planner{}).Validate(core.FlowSpec{
		DstPort: 54322,
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s"},
			},
		},
	})
	if err == nil || err.Error() != "kingbase: destination port 54322 is not the default 54321" {
		t.Fatalf("err=%v want port error", err)
	}
}

func TestValidateKingBaseDefaultPort(t *testing.T) {
	// Port 0 should be accepted (defaulted later)
	err := (Planner{}).Validate(core.FlowSpec{
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateKingBaseStandardPort(t *testing.T) {
	// Port 54321 should be accepted
	err := (Planner{}).Validate(core.FlowSpec{
		DstPort: 54321,
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateKingBaseQueryBeforeReady(t *testing.T) {
	// N4: query before ready rejected
	err := (Planner{}).Validate(core.FlowSpec{
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "query", Direction: "c2s", SQL: "SELECT 1"},
			},
		},
	})
	if err == nil || !contains(err.Error(), "state") {
		t.Fatalf("err=%v want state error", err)
	}
}

func TestValidateKingBasePasswordBeforeReady(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "password", Direction: "c2s"},
			},
		},
	})
	if err == nil || !contains(err.Error(), "state") {
		t.Fatalf("err=%v want state error", err)
	}
}

func TestValidateKingBaseBadIP(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		SrcIP: "not-an-ip",
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s"},
			},
		},
	})
	if err == nil || err.Error() != "kingbase: invalid source IP" {
		t.Fatalf("err=%v want invalid source IP", err)
	}
}

func TestValidateKingBaseBadDstIP(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		DstIP: "not-an-ip",
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s"},
			},
		},
	})
	if err == nil || err.Error() != "kingbase: invalid destination IP" {
		t.Fatalf("err=%v want invalid destination IP", err)
	}
}

func TestValidateKingBaseInvalidKind(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "bogus", Direction: "c2s"},
			},
		},
	})
	if err == nil || !contains(err.Error(), "invalid kind") {
		t.Fatalf("err=%v want invalid kind", err)
	}
}

func TestValidateKingBaseInvalidDirection(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "bogus"},
			},
		},
	})
	if err == nil || !contains(err.Error(), "invalid direction") {
		t.Fatalf("err=%v want invalid direction", err)
	}
}

func TestValidateKingBaseEmptySQL(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s"},
				{Kind: "auth_request", Direction: "s2c"},
				{Kind: "auth_response", Direction: "c2s"},
				{Kind: "ready", Direction: "s2c"},
				{Kind: "query", Direction: "c2s", SQL: ""},
			},
		},
	})
	if err == nil || !contains(err.Error(), "non-empty sql") {
		t.Fatalf("err=%v want non-empty sql", err)
	}
}

func TestValidateKingBaseWireFaultTruncate(t *testing.T) {
	// N5: wire_fault truncate_startup causes error
	err := (Planner{}).Validate(core.FlowSpec{
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s"},
			},
			WireFault: []byte(`{"kind":"truncate_startup","value":1}`),
		},
	})
	if err == nil || !contains(err.Error(), "length") {
		t.Fatalf("err=%v want length error", err)
	}
}

func TestValidateKingBaseWireFaultMessageLimit(t *testing.T) {
	// N6: wire_fault message_limit causes error
	err := (Planner{}).Validate(core.FlowSpec{
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s"},
			},
			WireFault: []byte(`{"kind":"message_limit","value":"over_limit"}`),
		},
	})
	if err == nil || !contains(err.Error(), "limit") {
		t.Fatalf("err=%v want limit error", err)
	}
}

func TestValidateKingBaseWireFaultNil(t *testing.T) {
	err := checkWireFault(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateKingBaseWireFaultEmpty(t *testing.T) {
	var raw []byte
	err := checkWireFault(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateKingBaseWireFaultUnknown(t *testing.T) {
	raw := []byte(`{"kind":"bogus","value":1}`)
	err := checkWireFault(raw)
	if err == nil || err.Error() != `kingbase: wire fault: unknown kind "bogus"` {
		t.Fatalf("err=%v want unknown kind", err)
	}
}

func TestValidateKingBaseValid(t *testing.T) {
	// S3-style valid config
	err := (Planner{}).Validate(core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 54321,
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s", User: "test", Database: "test"},
				{Kind: "auth_request", Direction: "s2c"},
				{Kind: "auth_response", Direction: "c2s"},
				{Kind: "ready", Direction: "s2c"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateKingBaseValidPGReference(t *testing.T) {
	// Alternative profile should also be valid
	err := (Planner{}).Validate(core.FlowSpec{
		KingBase: &core.KingBaseConfig{
			WireProfile: "postgresql_v3_compatible_reference",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateKingBaseSessionEmpty(t *testing.T) {
	// Empty session events should be valid (S1)
	err := (Planner{}).Validate(core.FlowSpec{
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Sessions: []core.KingBaseSession{
				{Events: []core.KingBaseEvent{}},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateKingBaseSessionStateError(t *testing.T) {
	// Query before ready in a session
	err := (Planner{}).Validate(core.FlowSpec{
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Sessions: []core.KingBaseSession{
				{
					SrcPort: 12345,
					Events: []core.KingBaseEvent{
						{Kind: "query", Direction: "c2s", SQL: "SELECT 1"},
					},
				},
			},
		},
	})
	if err == nil || !contains(err.Error(), "state") {
		t.Fatalf("err=%v want state error", err)
	}
}

// --- Plan tests ---

func collectPackets(ch <-chan core.PacketConfig, max int) []core.PacketConfig {
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
		if len(pkts) >= max {
			break
		}
	}
	return pkts
}

func TestPlanKingBaseConnect(t *testing.T) {
	// S1: empty events, 7 packets (handshake + teardown only)
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 54321,
		Count:   1,
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events:      []core.KingBaseEvent{},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 10)
	if len(packets) != 7 {
		t.Fatalf("packet_count=%d want 7", len(packets))
	}
	// 0: SYN, 1: SYN-ACK, 2: ACK, 3-6: teardown
	if packets[0].L4.Flags != 0x02 {
		t.Fatalf("pkt[0] flags=%02x want SYN", packets[0].L4.Flags)
	}
	if packets[0].L4.DstPort != 54321 {
		t.Fatalf("pkt[0] dst_port=%d want 54321", packets[0].L4.DstPort)
	}
	// No payload since no events
	for i := 3; i < 7; i++ {
		if len(packets[i].Payload) != 0 {
			t.Fatalf("pkt[%d] has payload but should be empty", i)
		}
	}
}

func TestPlanKingBaseStartup(t *testing.T) {
	// S2: startup only, 8 packets
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 54321,
		Count:   1,
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s", User: "test", Database: "test"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 10)
	if len(packets) != 8 {
		t.Fatalf("packet_count=%d want 8", len(packets))
	}
	// pkt[3]: startup message (c2s, no type byte)
	if packets[3].Direction != "up" {
		t.Fatalf("pkt[3] direction=%q want up", packets[3].Direction)
	}
	if packets[3].L4.DstPort != 54321 {
		t.Fatalf("pkt[3] dst_port=%d want 54321", packets[3].L4.DstPort)
	}
	if len(packets[3].Payload) == 0 {
		t.Fatal("pkt[3] payload is empty")
	}
	// Startup message has no type byte — first 4 bytes are length, next 4 are protocol version
	payload := packets[3].Payload
	protoVer := binary.BigEndian.Uint32(payload[4:8])
	if protoVer != ProtocolV3 {
		t.Fatalf("pkt[3] protocol_version=0x%08x want 0x%08x", protoVer, ProtocolV3)
	}
}

func TestPlanKingBaseAuthSuccess(t *testing.T) {
	// S3: startup + auth_request + auth_response + ready, 11 packets
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 54321,
		Count:   1,
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s", User: "test", Database: "test"},
				{Kind: "auth_request", Direction: "s2c"},
				{Kind: "auth_response", Direction: "c2s"},
				{Kind: "ready", Direction: "s2c"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 15)
	if len(packets) != 11 {
		t.Fatalf("packet_count=%d want 11", len(packets))
	}
	// pkt[3]: startup (c2s)
	if packets[3].Direction != "up" {
		t.Fatalf("pkt[3] direction=%q want up", packets[3].Direction)
	}
	// pkt[4]: auth_request (s2c) — hex check: 52 (R)
	if packets[4].Direction != "down" {
		t.Fatalf("pkt[4] direction=%q want down", packets[4].Direction)
	}
	if len(packets[4].Payload) == 0 {
		t.Fatal("pkt[4] payload is empty")
	}
	if packets[4].Payload[0] != 0x52 {
		t.Fatalf("pkt[4] first byte=0x%02x want 0x52 (R=AuthRequest)", packets[4].Payload[0])
	}
	// pkt[5]: auth_response (c2s) — hex check: 70 (p)
	if packets[5].Direction != "up" {
		t.Fatalf("pkt[5] direction=%q want up", packets[5].Direction)
	}
	if packets[5].Payload[0] != 0x70 {
		t.Fatalf("pkt[5] first byte=0x%02x want 0x70 (p=PasswordMessage)", packets[5].Payload[0])
	}
	// pkt[6]: ready (s2c) — hex check: 5a (Z)
	if packets[6].Direction != "down" {
		t.Fatalf("pkt[6] direction=%q want down", packets[6].Direction)
	}
	if packets[6].Payload[0] != 0x5a {
		t.Fatalf("pkt[6] first byte=0x%02x want 0x5a (Z=ReadyForQuery)", packets[6].Payload[0])
	}
}

func TestPlanKingBaseQuerySuccess(t *testing.T) {
	// S4: full query cycle, 16 packets
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 54321,
		Count:   1,
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s", User: "test", Database: "test"},
				{Kind: "auth_request", Direction: "s2c"},
				{Kind: "auth_response", Direction: "c2s"},
				{Kind: "ready", Direction: "s2c"},
				{Kind: "query", Direction: "c2s", SQL: "SELECT 1"},
				{Kind: "row_description", Direction: "s2c"},
				{Kind: "data_row", Direction: "s2c"},
				{Kind: "command_complete", Direction: "s2c", Tag: "SELECT 1"},
				{Kind: "ready", Direction: "s2c"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 16 {
		t.Fatalf("packet_count=%d want 16", len(packets))
	}
	// pkt[7]: query (c2s) — hex check: 51 (Q)
	if packets[7].Direction != "up" {
		t.Fatalf("pkt[7] direction=%q want up", packets[7].Direction)
	}
	if packets[7].Payload[0] != 0x51 {
		t.Fatalf("pkt[7] first byte=0x%02x want 0x51 (Q=Query)", packets[7].Payload[0])
	}
	// pkt[8]: row_description (s2c) — hex check: 54 (T)
	if packets[8].Direction != "down" {
		t.Fatalf("pkt[8] direction=%q want down", packets[8].Direction)
	}
	if packets[8].Payload[0] != 0x54 {
		t.Fatalf("pkt[8] first byte=0x%02x want 0x54 (T=RowDescription)", packets[8].Payload[0])
	}
	// pkt[9]: data_row (s2c) — hex check: 44 (D)
	if packets[9].Direction != "down" {
		t.Fatalf("pkt[9] direction=%q want down", packets[9].Direction)
	}
	if packets[9].Payload[0] != 0x44 {
		t.Fatalf("pkt[9] first byte=0x%02x want 0x44 (D=DataRow)", packets[9].Payload[0])
	}
	// pkt[10]: command_complete (s2c) — hex check: 43 (C)
	if packets[10].Direction != "down" {
		t.Fatalf("pkt[10] direction=%q want down", packets[10].Direction)
	}
	if packets[10].Payload[0] != 0x43 {
		t.Fatalf("pkt[10] first byte=0x%02x want 0x43 (C=CommandComplete)", packets[10].Payload[0])
	}
	// pkt[11]: ready (s2c) — hex check: 5a (Z)
	if packets[11].Direction != "down" {
		t.Fatalf("pkt[11] direction=%q want down", packets[11].Direction)
	}
	if packets[11].Payload[0] != 0x5a {
		t.Fatalf("pkt[11] first byte=0x%02x want 0x5a (Z=ReadyForQuery)", packets[11].Payload[0])
	}
}

func TestPlanKingBaseQueryError(t *testing.T) {
	// S5: query with error response, 14 packets
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 54321,
		Count:   1,
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s", User: "test", Database: "test"},
				{Kind: "auth_request", Direction: "s2c"},
				{Kind: "auth_response", Direction: "c2s"},
				{Kind: "ready", Direction: "s2c"},
				{Kind: "query", Direction: "c2s", SQL: "SELECT missing_column FROM missing_table"},
				{Kind: "query_error", Direction: "s2c"},
				{Kind: "ready", Direction: "s2c"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 20)
	if len(packets) != 14 {
		t.Fatalf("packet_count=%d want 14", len(packets))
	}
	// pkt[7]: query (c2s) — hex check: 51 (Q)
	if packets[7].Payload[0] != 0x51 {
		t.Fatalf("pkt[7] first byte=0x%02x want 0x51 (Q=Query)", packets[7].Payload[0])
	}
	// pkt[8]: query_error (s2c) — hex check: 45 (E)
	if packets[8].Direction != "down" {
		t.Fatalf("pkt[8] direction=%q want down", packets[8].Direction)
	}
	if packets[8].Payload[0] != 0x45 {
		t.Fatalf("pkt[8] first byte=0x%02x want 0x45 (E=ErrorResponse)", packets[8].Payload[0])
	}
	// pkt[9]: ready (s2c) — hex check: 5a (Z)
	if packets[9].Payload[0] != 0x5a {
		t.Fatalf("pkt[9] first byte=0x%02x want 0x5a (Z=ReadyForQuery)", packets[9].Payload[0])
	}
}

func TestPlanKingBaseIPv4(t *testing.T) {
	// S6: IPv4, 11 packets
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 54321,
		Count:   1,
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s", User: "test", Database: "test"},
				{Kind: "auth_request", Direction: "s2c"},
				{Kind: "auth_response", Direction: "c2s"},
				{Kind: "ready", Direction: "s2c"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 15)
	if len(packets) != 11 {
		t.Fatalf("packet_count=%d want 11", len(packets))
	}
	if packets[3].L3.SrcIP != "10.0.0.1" {
		t.Fatalf("pkt[3] src_ip=%q want 10.0.0.1", packets[3].L3.SrcIP)
	}
	if packets[3].L4.DstPort != 54321 {
		t.Fatalf("pkt[3] dst_port=%d want 54321", packets[3].L4.DstPort)
	}
}

func TestPlanKingBaseIPv6(t *testing.T) {
	// S7: IPv6, 11 packets
	spec := core.FlowSpec{
		SrcIP:   "2001:db8::1",
		DstIP:   "2001:db8::2",
		SrcPort: 12345,
		DstPort: 54321,
		Count:   1,
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s", User: "test", Database: "test"},
				{Kind: "auth_request", Direction: "s2c"},
				{Kind: "auth_response", Direction: "c2s"},
				{Kind: "ready", Direction: "s2c"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 15)
	if len(packets) != 11 {
		t.Fatalf("packet_count=%d want 11", len(packets))
	}
	if packets[3].L3.SrcIP != "2001:db8::1" {
		t.Fatalf("pkt[3] src_ip=%q want 2001:db8::1", packets[3].L3.SrcIP)
	}
	if packets[3].L4.DstPort != 54321 {
		t.Fatalf("pkt[3] dst_port=%d want 54321", packets[3].L4.DstPort)
	}
}

func TestPlanKingBaseMultiSession(t *testing.T) {
	// S8: two sessions, 22 packets, distinct src ports 12345 and 12346
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 54321,
		Count:   1,
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Sessions: []core.KingBaseSession{
				{
					SrcPort: 12345,
					Events: []core.KingBaseEvent{
						{Kind: "startup", Direction: "c2s", User: "test", Database: "test"},
						{Kind: "auth_request", Direction: "s2c"},
						{Kind: "auth_response", Direction: "c2s"},
						{Kind: "ready", Direction: "s2c"},
					},
				},
				{
					SrcPort: 12346,
					Events: []core.KingBaseEvent{
						{Kind: "startup", Direction: "c2s", User: "test", Database: "test"},
						{Kind: "auth_request", Direction: "s2c"},
						{Kind: "auth_response", Direction: "c2s"},
						{Kind: "ready", Direction: "s2c"},
					},
				},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 30)
	if len(packets) != 22 {
		t.Fatalf("packet_count=%d want 22", len(packets))
	}
	// First session starts at pkt[0], second session at pkt[11]
	if packets[0].L4.SrcPort != 12345 {
		t.Fatalf("pkt[0] src_port=%d want 12345", packets[0].L4.SrcPort)
	}
	if packets[11].L4.SrcPort != 12346 {
		t.Fatalf("pkt[11] src_port=%d want 12346", packets[11].L4.SrcPort)
	}
	has12345, has12346 := false, false
	for _, p := range packets {
		if p.L4.SrcPort == 12345 {
			has12345 = true
		}
		if p.L4.SrcPort == 12346 {
			has12346 = true
		}
	}
	if !has12345 {
		t.Fatal("src port 12345 not found")
	}
	if !has12346 {
		t.Fatal("src port 12346 not found")
	}
}

func TestPlanKingBaseLengthBoundary(t *testing.T) {
	// S9: min params, 8 packets
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 54321,
		Count:   1,
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s", User: "u", Database: "d"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 10)
	if len(packets) != 8 {
		t.Fatalf("packet_count=%d want 8", len(packets))
	}
	if len(packets[3].Payload) == 0 {
		t.Fatal("pkt[3] payload is empty")
	}
	if packets[3].L4.DstPort != 54321 {
		t.Fatalf("pkt[3] dst_port=%d want 54321", packets[3].L4.DstPort)
	}
}

func TestPlanKingBaseDefaultPort(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		Count:   1,
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s", User: "test", Database: "test"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	packets := collectPackets(ch, 10)
	if len(packets) != 8 {
		t.Fatalf("packet_count=%d want 8", len(packets))
	}
	if packets[3].L4.DstPort != 54321 {
		t.Fatalf("dst_port=%d want 54321 (default)", packets[3].L4.DstPort)
	}
}

func TestPlanKingBaseContextCancel(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "20.0.0.1",
		KingBase: &core.KingBaseConfig{
			WireProfile: "kingbase_es_v8_pg_compatible",
			Events: []core.KingBaseEvent{
				{Kind: "startup", Direction: "c2s"},
			},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range ch {
		count++
	}
}

// --- Layer Generator tests ---

func TestKingBaseGeneratorName(t *testing.T) {
	g := &KingBaseGenerator{}
	if g.Name() != "kingbase" {
		t.Fatalf("Name=%q want kingbase", g.Name())
	}
}

func TestKingBaseGeneratorGenerate(t *testing.T) {
	cfg := &core.KingBaseConfig{
		WireProfile: "kingbase_es_v8_pg_compatible",
		Events: []core.KingBaseEvent{
			{Kind: "startup", Direction: "c2s", User: "test", Database: "test"},
			{Kind: "auth_request", Direction: "s2c"},
			{Kind: "auth_response", Direction: "c2s"},
			{Kind: "ready", Direction: "s2c"},
		},
	}
	var events []layers.MessageEvent
	emit := func(ev layers.MessageEvent) error {
		events = append(events, ev)
		return nil
	}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{KingBase: cfg},
		EmitMsg: emit,
	}
	ctx := context.Background()
	g := &KingBaseGenerator{}
	err := g.Generate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("events=%d want 4", len(events))
	}
	// First: startup up
	if !events[0].Up {
		t.Fatalf("event[0] Up=false want true")
	}
	if len(events[0].Bytes) == 0 {
		t.Fatal("event[0] bytes empty")
	}
	// Startup message has no type byte
	if events[0].Bytes[0] == 0x52 || events[0].Bytes[0] == 0x70 {
		t.Fatalf("event[0] first byte=0x%02x, startup has no type byte", events[0].Bytes[0])
	}
	// Second: auth_request down
	if events[1].Up {
		t.Fatalf("event[1] Up=true want false")
	}
	if events[1].Bytes[0] != 0x52 {
		t.Fatalf("event[1] first byte=0x%02x want 0x52 (R)", events[1].Bytes[0])
	}
	// Third: auth_response up
	if !events[2].Up {
		t.Fatalf("event[2] Up=false want true")
	}
	if events[2].Bytes[0] != 0x70 {
		t.Fatalf("event[2] first byte=0x%02x want 0x70 (p)", events[2].Bytes[0])
	}
	// Fourth: ready down
	if events[3].Up {
		t.Fatalf("event[3] Up=true want false")
	}
	if events[3].Bytes[0] != 0x5a {
		t.Fatalf("event[3] first byte=0x%02x want 0x5a (Z)", events[3].Bytes[0])
	}
}

func TestKingBaseGeneratorGenerateSessions(t *testing.T) {
	cfg := &core.KingBaseConfig{
		WireProfile: "kingbase_es_v8_pg_compatible",
		Sessions: []core.KingBaseSession{
			{
				SrcPort: 12345,
				Events: []core.KingBaseEvent{
					{Kind: "startup", Direction: "c2s", User: "test", Database: "test"},
					{Kind: "ready", Direction: "s2c"},
				},
			},
		},
	}
	var events []layers.MessageEvent
	emit := func(ev layers.MessageEvent) error {
		events = append(events, ev)
		return nil
	}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{KingBase: cfg},
		EmitMsg: emit,
	}
	ctx := context.Background()
	g := &KingBaseGenerator{}
	err := g.Generate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d want 2", len(events))
	}
}

func TestKingBaseGeneratorGenerateEmptyEvents(t *testing.T) {
	cfg := &core.KingBaseConfig{
		WireProfile: "kingbase_es_v8_pg_compatible",
		Events:      []core.KingBaseEvent{},
	}
	var events []layers.MessageEvent
	emit := func(ev layers.MessageEvent) error {
		events = append(events, ev)
		return nil
	}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{KingBase: cfg},
		EmitMsg: emit,
	}
	ctx := context.Background()
	g := &KingBaseGenerator{}
	err := g.Generate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("events=%d want 0", len(events))
	}
}

func TestKingBaseGeneratorGenerateNilConfig(t *testing.T) {
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	ctx := context.Background()
	g := &KingBaseGenerator{}
	err := g.Generate(ctx, req)
	if err == nil || err.Error() != "kingbase: config is required" {
		t.Fatalf("err=%v want config is required", err)
	}
}

func TestKingBaseGeneratorGenerateNilReq(t *testing.T) {
	g := &KingBaseGenerator{}
	err := g.Generate(context.Background(), nil)
	if err == nil || err.Error() != "kingbase generator: EmitMsg is nil" {
		t.Fatalf("err=%v want EmitMsg is nil", err)
	}
}

func TestKingBaseGeneratorGenerateNilEmitMsg(t *testing.T) {
	req := &layers.GenRequest{Meta: layers.FlowMeta{}}
	g := &KingBaseGenerator{}
	err := g.Generate(context.Background(), req)
	if err == nil || err.Error() != "kingbase generator: EmitMsg is nil" {
		t.Fatalf("err=%v want EmitMsg is nil", err)
	}
}

func TestKingBaseGeneratorGenerateContextCancel(t *testing.T) {
	cfg := &core.KingBaseConfig{
		WireProfile: "kingbase_es_v8_pg_compatible",
		Events: []core.KingBaseEvent{
			{Kind: "startup", Direction: "c2s"},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{KingBase: cfg},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	g := &KingBaseGenerator{}
	err := g.Generate(ctx, req)
	if err == nil {
		t.Fatalf("expected context error")
	}
}

func TestKingBaseRegister(t *testing.T) {
	gen, err := layers.NewLayerGenerator("kingbase")
	if err != nil {
		t.Fatalf("NewLayerGenerator(kingbase): %v", err)
	}
	if gen == nil {
		t.Fatalf("generator is nil")
	}
	if gen.Name() != "kingbase" {
		t.Fatalf("name=%q want kingbase", gen.Name())
	}
}

// --- helpers ---

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func containsNullTerminated(b []byte, s string) bool {
	return bytes.Contains(b, append([]byte(s), 0))
}