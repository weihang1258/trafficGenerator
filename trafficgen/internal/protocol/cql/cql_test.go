package cql

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func hexStr(b []byte) string {
	return hex.EncodeToString(b)
}

func parseHex(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func cqlConfig(profile string) *core.CQLConfig {
	return &core.CQLConfig{WireProfile: profile}
}

// --- Builder tests ---

func TestBuildFrameStartup(t *testing.T) {
	ev := core.CQLEvent{
		Kind: "startup", Direction: "c2s",
		Options: map[string]interface{}{"CQL_VERSION": "3.0.0"},
	}
	frame, err := buildFrame(ReqV4, RespV4, ev)
	if err != nil {
		t.Fatal(err)
	}
	want := parseHex("04 00 00 00 01 00 00 00 16 00 01 00 0b 43 51 4c 5f 56 45 52 53 49 4f 4e 00 05 33 2e 30 2e 30")
	if hexStr(frame) != hexStr(want) {
		t.Fatalf("frame=%s want=%s", hexStr(frame), hexStr(want))
	}
}

func TestBuildFrameReady(t *testing.T) {
	ev := core.CQLEvent{Kind: "ready", Direction: "s2c"}
	frame, err := buildFrame(ReqV4, RespV4, ev)
	if err != nil {
		t.Fatal(err)
	}
	want := parseHex("84 00 00 00 02 00 00 00 00")
	if hexStr(frame) != hexStr(want) {
		t.Fatalf("frame=%s want=%s", hexStr(frame), hexStr(want))
	}
}

func TestBuildFrameOptions(t *testing.T) {
	ev := core.CQLEvent{Kind: "options", Direction: "c2s"}
	frame, err := buildFrame(ReqV4, RespV4, ev)
	if err != nil {
		t.Fatal(err)
	}
	want := parseHex("04 00 00 00 05 00 00 00 00")
	if hexStr(frame) != hexStr(want) {
		t.Fatalf("frame=%s want=%s", hexStr(frame), hexStr(want))
	}
}

func TestBuildFrameSupported(t *testing.T) {
	ev := core.CQLEvent{
		Kind: "supported", Direction: "s2c",
		Options: map[string]interface{}{
			"CQL_VERSION": []interface{}{"3.0.0"},
			"COMPRESSION": []interface{}{"snappy", "lz4"},
		},
	}
	frame, err := buildFrame(ReqV4, RespV4, ev)
	if err != nil {
		t.Fatal(err)
	}
	want := parseHex("84 00 00 00 06 00 00 00 34 00 02 00 0b 43 51 4c 5f 56 45 52 53 49 4f 4e 00 01 00 05 33 2e 30 2e 30 00 0b 43 4f 4d 50 52 45 53 53 49 4f 4e 00 02 00 06 73 6e 61 70 70 79 00 03 6c 7a 34")
	// Map iteration order is nondeterministic, so compare structurally:
	// version+response, opcode, and total length only.
	if frame[0] != 0x84 || frame[4] != 0x06 {
		t.Fatalf("frame header version/opcode = %02x/%02x want 84/06", frame[0], frame[4])
	}
	if len(frame) != len(want) {
		t.Fatalf("len=%d want %d", len(frame), len(want))
	}
	if got := int(binary.BigEndian.Uint32(frame[5:9])); got != 52 {
		t.Fatalf("body_len=%d want 52", got)
	}
	// Body starts with the string multimap count.
	if got := binary.BigEndian.Uint16(frame[9:11]); got != 2 {
		t.Fatalf("map_count=%d want 2", got)
	}
}

func TestBuildFrameAuthenticate(t *testing.T) {
	ev := core.CQLEvent{
		Kind: "authenticate", Direction: "s2c",
		Mechanism: "org.apache.cassandra.auth.PasswordAuthenticator",
	}
	frame, err := buildFrame(ReqV4, RespV4, ev)
	if err != nil {
		t.Fatal(err)
	}
	want := parseHex("84 00 00 00 03 00 00 00 31 00 2f 6f 72 67 2e 61 70 61 63 68 65 2e 63 61 73 73 61 6e 64 72 61 2e 61 75 74 68 2e 50 61 73 73 77 6f 72 64 41 75 74 68 65 6e 74 69 63 61 74 6f 72")
	if hexStr(frame) != hexStr(want) {
		t.Fatalf("frame=%s want=%s", hexStr(frame), hexStr(want))
	}
}

func TestBuildFrameAuthResponseEmpty(t *testing.T) {
	ev := core.CQLEvent{Kind: "auth_response", Direction: "c2s", Bytes: []byte{}}
	frame, err := buildFrame(ReqV4, RespV4, ev)
	if err != nil {
		t.Fatal(err)
	}
	want := parseHex("04 00 00 00 0f 00 00 00 04 00 00 00 00")
	if hexStr(frame) != hexStr(want) {
		t.Fatalf("frame=%s want=%s", hexStr(frame), hexStr(want))
	}
}

func TestBuildFrameAuthSuccessEmpty(t *testing.T) {
	ev := core.CQLEvent{Kind: "auth_success", Direction: "s2c", Bytes: []byte{}}
	frame, err := buildFrame(ReqV4, RespV4, ev)
	if err != nil {
		t.Fatal(err)
	}
	want := parseHex("84 00 00 00 10 00 00 00 04 00 00 00 00")
	if hexStr(frame) != hexStr(want) {
		t.Fatalf("frame=%s want=%s", hexStr(frame), hexStr(want))
	}
}

func TestBuildFrameQuery(t *testing.T) {
	ev := core.CQLEvent{
		Kind: "query", Direction: "c2s",
		Query:       "INSERT INTO ks.t (k) VALUES (1)",
		Consistency: 1,
		QueryFlags:  0,
	}
	frame, err := buildFrame(ReqV4, RespV4, ev)
	if err != nil {
		t.Fatal(err)
	}
	want := parseHex("04 00 00 00 07 00 00 00 26 00 00 00 1f 49 4e 53 45 52 54 20 49 4e 54 4f 20 6b 73 2e 74 20 28 6b 29 20 56 41 4c 55 45 53 20 28 31 29 00 01 00")
	if hexStr(frame) != hexStr(want) {
		t.Fatalf("frame=%s want=%s", hexStr(frame), hexStr(want))
	}
}

func TestBuildFrameResultVoid(t *testing.T) {
	ev := core.CQLEvent{Kind: "result", Direction: "s2c"}
	frame, err := buildFrame(ReqV4, RespV4, ev)
	if err != nil {
		t.Fatal(err)
	}
	want := parseHex("84 00 00 00 08 00 00 00 04 00 00 00 01")
	if hexStr(frame) != hexStr(want) {
		t.Fatalf("frame=%s want=%s", hexStr(frame), hexStr(want))
	}
}

func TestBuildFramePrepare(t *testing.T) {
	ev := core.CQLEvent{
		Kind: "prepare", Direction: "c2s",
		Query: "SELECT v FROM ks.t WHERE k = ?",
	}
	frame, err := buildFrame(ReqV4, RespV4, ev)
	if err != nil {
		t.Fatal(err)
	}
	want := parseHex("04 00 00 00 09 00 00 00 22 00 00 00 1e 53 45 4c 45 43 54 20 76 20 46 52 4f 4d 20 6b 73 2e 74 20 57 48 45 52 45 20 6b 20 3d 20 3f")
	if hexStr(frame) != hexStr(want) {
		t.Fatalf("frame=%s want=%s", hexStr(frame), hexStr(want))
	}
}

func TestBuildFrameExecute(t *testing.T) {
	ev := core.CQLEvent{
		Kind: "execute", Direction: "c2s",
		PreparedID:  "pid-1",
		Consistency: 1,
		QueryFlags:  0,
	}
	frame, err := buildFrame(ReqV4, RespV4, ev)
	if err != nil {
		t.Fatal(err)
	}
	want := parseHex("04 00 00 00 0a 00 00 00 0a 00 05 70 69 64 2d 31 00 01 00")
	if hexStr(frame) != hexStr(want) {
		t.Fatalf("frame=%s want=%s", hexStr(frame), hexStr(want))
	}
}

func TestBuildFrameError(t *testing.T) {
	ev := core.CQLEvent{
		Kind: "error", Direction: "s2c",
		Code:    0,
		Message: "server error",
	}
	frame, err := buildFrame(ReqV4, RespV4, ev)
	if err != nil {
		t.Fatal(err)
	}
	want := parseHex("84 00 00 00 00 00 00 00 12 00 00 00 00 00 0c 73 65 72 76 65 72 20 65 72 72 6f 72")
	if hexStr(frame) != hexStr(want) {
		t.Fatalf("frame=%s want=%s", hexStr(frame), hexStr(want))
	}
}

func TestBuildFrameV5Tracing(t *testing.T) {
	// cql_v5_tracing: startup with v5 version, query with flags=2 (tracing)
	ev := core.CQLEvent{
		Kind: "startup", Direction: "c2s",
		Options: map[string]interface{}{"CQL_VERSION": "5.0.0"},
	}
	frame, err := buildFrame(ReqV5, RespV5, ev)
	if err != nil {
		t.Fatal(err)
	}
	want := parseHex("05 00 00 00 01 00 00 00 16 00 01 00 0b 43 51 4c 5f 56 45 52 53 49 4f 4e 00 05 35 2e 30 2e 30")
	if hexStr(frame) != hexStr(want) {
		t.Fatalf("frame=%s want=%s", hexStr(frame), hexStr(want))
	}
}

func TestBuildFrameV5QueryWithFlags(t *testing.T) {
	ev := core.CQLEvent{
		Kind: "query", Direction: "c2s",
		Query: "SELECT 1", Consistency: 1, QueryFlags: 2,
		Flags: 2, // tracing flag
	}
	frame, err := buildFrame(ReqV5, RespV5, ev)
	if err != nil {
		t.Fatal(err)
	}
	// v5 version, tracing flag set in header, QUERY opcode, flags=2 in body.
	want := parseHex("05 02 00 00 07 00 00 00 12 00 00 00 08 53 45 4c 45 43 54 20 31 00 01 00 00 00 02")
	if hexStr(frame) != hexStr(want) {
		t.Fatalf("frame=%s want=%s", hexStr(frame), hexStr(want))
	}
	if frame[0] != 0x05 || frame[1] != 0x02 || frame[4] != 0x07 {
		t.Fatalf("v5/flag/opcode=%02x/%02x/%02x want 05/02/07", frame[0], frame[1], frame[4])
	}
}

func TestBuildFrameV5Result(t *testing.T) {
	ev := core.CQLEvent{Kind: "result", Direction: "s2c"}
	frame, err := buildFrame(ReqV5, RespV5, ev)
	if err != nil {
		t.Fatal(err)
	}
	want := parseHex("85 00 00 00 08 00 00 00 04 00 00 00 01")
	if hexStr(frame) != hexStr(want) {
		t.Fatalf("frame=%s want=%s", hexStr(frame), hexStr(want))
	}
}

func TestBuildFrameUnknownKind(t *testing.T) {
	ev := core.CQLEvent{Kind: "bogus"}
	_, err := buildFrame(ReqV4, RespV4, ev)
	if err == nil {
		t.Fatal("expected error for unknown kind")
	}
}

// --- Validate tests ---

func TestValidateCQLConfigRequired(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{})
	if err == nil || err.Error() != "cql: config is required" {
		t.Fatalf("err=%v want config is required", err)
	}
}

func TestValidateCQLWireProfileRequired(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{CQL: &core.CQLConfig{Events: []core.CQLEvent{{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}}}}})
	if err == nil || err.Error() != "cql: wire_profile is required" {
		t.Fatalf("err=%v want wire_profile is required", err)
	}
}

func TestValidateCQLUnknownProfile(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v3",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), `unsupported wire profile version "cql_v3"`) {
		t.Fatalf("err=%v want unsupported wire profile version", err)
	}
}

func TestValidateCQLAllowsEmptyEvents(t *testing.T) {
	// P0b-2：空 events+sessions = connect-only 会话（TCP 9042 握手+挥手，7 包，
	// has_payload=false），与 cql_connect 用例契约一致。不再拒绝空 events。
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{WireProfile: "cql_v4"},
	})
	if err != nil {
		t.Fatalf("empty events should be valid (connect-only), got %v", err)
	}
}

func TestValidateCQLMutuallyExclusive(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
			},
			Sessions: []core.CQLSession{
				{Events: []core.CQLEvent{{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}}}},
			},
		},
	})
	if err == nil || err.Error() != "cql: events and sessions are mutually exclusive" {
		t.Fatalf("err=%v want mutually exclusive", err)
	}
}

func TestValidateCQLUnknownKind(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "bogus", Direction: "c2s"},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Fatalf("err=%v want unknown kind", err)
	}
}

func TestValidateCQLBadDirection(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "bogus"},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid direction") {
		t.Fatalf("err=%v want invalid direction", err)
	}
}

func TestValidateCQLStartupWrongDirection(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "s2c"},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "must be c2s") {
		t.Fatalf("err=%v want must be c2s", err)
	}
}

func TestValidateCQLReadyWrongDirection(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "ready", Direction: "c2s"},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "must be s2c") {
		t.Fatalf("err=%v want must be s2c", err)
	}
}

func TestValidateCQLSessionEmpty(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Sessions: []core.CQLSession{
				{Events: []core.CQLEvent{}},
			},
		},
	})
	if err == nil {
		t.Fatal("expected error for empty session")
	}
}

func TestValidateCQLBadIP(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
			},
		},
		SrcIP: "not-an-ip",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Fatalf("err=%v want invalid source IP", err)
	}
}

func TestValidateCQLBadDstIP(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
			},
		},
		DstIP: "not-an-ip",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid destination IP") {
		t.Fatalf("err=%v want invalid destination IP", err)
	}
}

func TestValidateCQLWireFault(t *testing.T) {
	raw := []byte(`{"kind":"opcode","value":255}`)
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
			},
			WireFault: raw,
		},
	})
	if err == nil {
		t.Fatal("expected error for wire_fault")
	}
}

func TestValidateCQLValidStartupReady(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
				{Kind: "ready", Direction: "s2c"},
			},
		},
		SrcIP: "10.0.0.1",
		DstIP: "20.0.0.1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateCQLValidV5(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v5",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
				{Kind: "ready", Direction: "s2c"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateCQLValidAuthProfile(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4_auth",
			Events: []core.CQLEvent{
				{Kind: "authenticate", Direction: "s2c", Mechanism: "org.apache.cassandra.auth.PasswordAuthenticator"},
				{Kind: "auth_response", Direction: "c2s"},
				{Kind: "auth_success", Direction: "s2c"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateCQLValidOptionsSupported(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "options", Direction: "c2s"},
				{Kind: "supported", Direction: "s2c"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateCQLValidQueryResult(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
				{Kind: "ready", Direction: "s2c"},
				{Kind: "query", Direction: "c2s", Query: "SELECT 1"},
				{Kind: "result", Direction: "s2c"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateCQLValidPrepareExecute(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
				{Kind: "ready", Direction: "s2c"},
				{Kind: "prepare", Direction: "c2s", Query: "SELECT v FROM ks.t WHERE k = ?"},
				{Kind: "execute", Direction: "c2s", PreparedID: "pid-1"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateCQLValidError(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "error", Direction: "s2c", Code: 0, Message: "server error"},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateCQLValidSessions(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Sessions: []core.CQLSession{
				{Events: []core.CQLEvent{{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}}, {Kind: "ready", Direction: "s2c"}}},
				{Events: []core.CQLEvent{{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}}, {Kind: "ready", Direction: "s2c"}}},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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

func TestPlanCQLStartupReady(t *testing.T) {
	// S1: startup + ready → 9 packets (3 handshake + 2 data + 4 teardown)
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 9042, Count: 1,
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
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
	if len(packets) != 9 {
		t.Fatalf("packet_count=%d want 9", len(packets))
	}
	// 0: SYN, 1: SYN-ACK, 2: ACK, 3: startup data, 4: ready data, 5-8: teardown
	if packets[0].L4.Flags != 0x02 {
		t.Fatalf("pkt[0] flags=%02x want SYN", packets[0].L4.Flags)
	}
	if packets[3].L4.DstPort != 9042 {
		t.Fatalf("pkt[3] dst_port=%d want 9042", packets[3].L4.DstPort)
	}
	if packets[3].Direction != "up" {
		t.Fatalf("pkt[3] direction=%q want up", packets[3].Direction)
	}
	if len(packets[3].Payload) == 0 {
		t.Fatal("pkt[3] payload is empty")
	}
	// pkt[4]: ready response down
	if packets[4].Direction != "down" {
		t.Fatalf("pkt[4] direction=%q want down", packets[4].Direction)
	}
	if packets[4].L4.SrcPort != 9042 {
		t.Fatalf("pkt[4] src_port=%d want 9042", packets[4].L4.SrcPort)
	}
	// Verify startup frame hex
	want := parseHex("04 00 00 00 01 00 00 00 16 00 01 00 0b 43 51 4c 5f 56 45 52 53 49 4f 4e 00 05 33 2e 30 2e 30")
	if hexStr(packets[3].Payload) != hexStr(want) {
		t.Fatalf("pkt[3] payload=%s want=%s", hexStr(packets[3].Payload), hexStr(want))
	}
	// Verify ready frame hex
	wantReady := parseHex("84 00 00 00 02 00 00 00 00")
	if hexStr(packets[4].Payload) != hexStr(wantReady) {
		t.Fatalf("pkt[4] payload=%s want=%s", hexStr(packets[4].Payload), hexStr(wantReady))
	}
}

func TestPlanCQLOptionsSupported(t *testing.T) {
	// S2: options + supported → 9 packets
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 9042, Count: 1,
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "options", Direction: "c2s"},
				{Kind: "supported", Direction: "s2c", Options: map[string]interface{}{
					"CQL_VERSION": []interface{}{"3.0.0"},
					"COMPRESSION": []interface{}{"snappy", "lz4"},
				}},
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
	if len(packets) != 9 {
		t.Fatalf("packet_count=%d want 9", len(packets))
	}
	// pkt[3]: options up
	if packets[3].Direction != "up" {
		t.Fatalf("pkt[3] direction=%q want up", packets[3].Direction)
	}
	// pkt[4]: supported down
	if packets[4].Direction != "down" {
		t.Fatalf("pkt[4] direction=%q want down", packets[4].Direction)
	}
}

func TestPlanCQLAuthEmptySASL(t *testing.T) {
	// S3: AUTHENTICATE + AUTH_RESPONSE + AUTH_SUCCESS → 10 packets
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 9042, Count: 1,
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4_auth",
			Events: []core.CQLEvent{
				{Kind: "authenticate", Direction: "s2c", Mechanism: "org.apache.cassandra.auth.PasswordAuthenticator"},
				{Kind: "auth_response", Direction: "c2s", Bytes: []byte{}},
				{Kind: "auth_success", Direction: "s2c", Bytes: []byte{}},
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
	if len(packets) != 10 {
		t.Fatalf("packet_count=%d want 10", len(packets))
	}
	// pkt[3]: authenticate down
	if packets[3].Direction != "down" {
		t.Fatalf("pkt[3] direction=%q want down", packets[3].Direction)
	}
	if packets[3].L4.SrcPort != 9042 {
		t.Fatalf("pkt[3] src_port=%d want 9042", packets[3].L4.SrcPort)
	}
	// pkt[4]: auth_response up
	if packets[4].Direction != "up" {
		t.Fatalf("pkt[4] direction=%q want up", packets[4].Direction)
	}
	// pkt[5]: auth_success down
	if packets[5].Direction != "down" {
		t.Fatalf("pkt[5] direction=%q want down", packets[5].Direction)
	}
}

func TestPlanCQLQueryVoid(t *testing.T) {
	// S4: startup + ready + query + result + ready → 12 packets
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 9042, Count: 1,
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
				{Kind: "ready", Direction: "s2c"},
				{Kind: "query", Direction: "c2s", Query: "INSERT INTO ks.t (k) VALUES (1)", Consistency: 1, QueryFlags: 0},
				{Kind: "result", Direction: "s2c"},
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
	if len(packets) != 12 {
		t.Fatalf("packet_count=%d want 12", len(packets))
	}
	// pkt[5]: query up
	if packets[5].Direction != "up" {
		t.Fatalf("pkt[5] direction=%q want up", packets[5].Direction)
	}
	// pkt[6]: result down
	if packets[6].Direction != "down" {
		t.Fatalf("pkt[6] direction=%q want down", packets[6].Direction)
	}
	// pkt[7]: ready down
	if packets[7].Direction != "down" {
		t.Fatalf("pkt[7] direction=%q want down", packets[7].Direction)
	}
}

func TestPlanCQLPrepareExecute(t *testing.T) {
	// S5: prepare + execute → 9 packets
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 9042, Count: 1,
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
				{Kind: "ready", Direction: "s2c"},
				{Kind: "prepare", Direction: "c2s", Query: "SELECT v FROM ks.t WHERE k = ?"},
				{Kind: "execute", Direction: "c2s", PreparedID: "pid-1", Consistency: 1, QueryFlags: 0},
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
	if len(packets) != 11 {
		t.Fatalf("packet_count=%d want 11 (handshake 3 + startup/ready/prepare/execute 4 + teardown 4)", len(packets))
	}
	// pkt[5]: prepare up, pkt[6]: execute up
	if packets[5].Direction != "up" {
		t.Fatalf("pkt[5] direction=%q want up", packets[5].Direction)
	}
	if packets[6].Direction != "up" {
		t.Fatalf("pkt[4] direction=%q want up", packets[4].Direction)
	}
}

func TestPlanCQLErrorServer(t *testing.T) {
	// S6: ERROR response → 8 packets
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 9042, Count: 1,
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "error", Direction: "s2c", Code: 0, Message: "server error"},
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
	if len(packets) != 8 {
		t.Fatalf("packet_count=%d want 8", len(packets))
	}
	// pkt[3]: error down
	if packets[3].Direction != "down" {
		t.Fatalf("pkt[3] direction=%q want down", packets[3].Direction)
	}
	if packets[3].L4.SrcPort != 9042 {
		t.Fatalf("pkt[3] src_port=%d want 9042", packets[3].L4.SrcPort)
	}
}

func TestPlanCQLIPv6(t *testing.T) {
	// S7: IPv6 transport
	spec := core.FlowSpec{
		SrcIP: "2001:db8::1", DstIP: "2001:db8::2", SrcPort: 12345, DstPort: 9042, Count: 1,
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
				{Kind: "ready", Direction: "s2c"},
				{Kind: "query", Direction: "c2s", Query: "SELECT 1", Consistency: 1, QueryFlags: 0},
				{Kind: "result", Direction: "s2c"},
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
	if len(packets) != 11 {
		t.Fatalf("packet_count=%d want 11", len(packets))
	}
	if packets[3].L3.SrcIP != "2001:db8::1" {
		t.Fatalf("pkt[3] src_ip=%q want 2001:db8::1", packets[3].L3.SrcIP)
	}
}

func TestPlanCQLV5HandshakeOnly(t *testing.T) {
	// S8 (D-CQL-1 B2 transition档): v5 profile carries the pre-handshake
	// unframed face only (OPTIONS/SUPPORTED/STARTUP/READY); post-handshake
	// messages need the v5 envelope (G-CQL-3).
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 9042, Count: 1,
		CQL: &core.CQLConfig{
			WireProfile: "cql_v5",
			Events: []core.CQLEvent{
				{Kind: "options", Direction: "c2s"},
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "5.0.0"}},
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
	if len(packets) != 10 {
		t.Fatalf("packet_count=%d want 10", len(packets))
	}
	// pkt[3]: options v5, pkt[4]: startup v5
	if packets[3].Payload[0] != 0x05 {
		t.Fatalf("pkt[3] version=%02x want 05", packets[3].Payload[0])
	}
	if packets[4].Payload[0] != 0x05 {
		t.Fatalf("pkt[4] version=%02x want 05", packets[4].Payload[0])
	}
}

// G-CQL-3 (B2): v5 post-handshake message rejected instead of emitting a
// bare v4-shaped frame.
func TestValidateCQLV5PostHandshakeRejected(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v5",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "5.0.0"}},
				{Kind: "ready", Direction: "s2c"},
				{Kind: "query", Direction: "c2s", Query: "SELECT 1", Consistency: 1},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "envelope") {
		t.Fatalf("err=%v want envelope rejection", err)
	}
}

// G-CQL-6: STARTUP without CQL_VERSION is rejected (§4.1.1 mandatory).
func TestValidateCQLStartupRequiresCQLVersion(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s"},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "CQL_VERSION") {
		t.Fatalf("err=%v want CQL_VERSION mandatory rejection", err)
	}
}

// G-CQL-6: v4 rejects the v5-only beta flag; warning is response-only.
func TestValidateCQLFlagGates(t *testing.T) {
	beta := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "options", Direction: "c2s", Flags: FlagBeta},
			},
		},
	})
	if beta == nil || !strings.Contains(beta.Error(), "beta") {
		t.Fatalf("beta err=%v want beta rejection", beta)
	}
	warn := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "options", Direction: "c2s", Flags: FlagWarning},
			},
		},
	})
	if warn == nil || !strings.Contains(warn.Error(), "warning") {
		t.Fatalf("warning err=%v want warning rejection", warn)
	}
}

// G-CQL-6: auth ordering — AUTH_RESPONSE without AUTHENTICATE is rejected;
// a query mid-auth is rejected; AUTH_SUCCESS opens the ready gate.
func TestValidateCQLAuthOrdering(t *testing.T) {
	noAuth := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4_auth",
			Events: []core.CQLEvent{
				{Kind: "auth_response", Direction: "c2s"},
			},
		},
	})
	if noAuth == nil || !strings.Contains(noAuth.Error(), "state") {
		t.Fatalf("err=%v want auth ordering rejection", noAuth)
	}
	midAuth := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4_auth",
			Events: []core.CQLEvent{
				{Kind: "authenticate", Direction: "s2c", Mechanism: "org.apache.cassandra.auth.PasswordAuthenticator"},
				{Kind: "query", Direction: "c2s", Query: "SELECT 1", Consistency: 1},
			},
		},
	})
	if midAuth == nil || !strings.Contains(midAuth.Error(), "state") {
		t.Fatalf("err=%v want mid-auth query rejection", midAuth)
	}
	ok := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4_auth",
			Events: []core.CQLEvent{
				{Kind: "authenticate", Direction: "s2c", Mechanism: "org.apache.cassandra.auth.PasswordAuthenticator"},
				{Kind: "auth_response", Direction: "c2s"},
				{Kind: "auth_success", Direction: "s2c"},
				{Kind: "query", Direction: "c2s", Query: "SELECT 1", Consistency: 1},
			},
		},
	})
	if ok != nil {
		t.Fatalf("auth-then-query should be valid, got %v", ok)
	}
}

// W1/G-CQL-2: the v4 QUERY flags field is one byte; the v5 one is four.
func TestBuildQueryFlagsWidthByProfile(t *testing.T) {
	ev := core.CQLEvent{Kind: "query", Direction: "c2s", Query: "SELECT 1", Consistency: 1, QueryFlags: 0}
	v4, err := buildFrame(ReqV4, RespV4, ev)
	if err != nil {
		t.Fatal(err)
	}
	if got := int(binary.BigEndian.Uint32(v4[5:9])); got != 15 {
		t.Fatalf("v4 query body len=%d want 15 (4+8+2+1)", got)
	}
	if v4[len(v4)-1] != 0x00 {
		t.Fatalf("v4 query last byte=%02x want the 1-byte flags 0x00", v4[len(v4)-1])
	}
	ev.QueryFlags = 2
	v5, err := buildFrame(ReqV5, RespV5, ev)
	if err != nil {
		t.Fatal(err)
	}
	if got := int(binary.BigEndian.Uint32(v5[5:9])); got != 18 {
		t.Fatalf("v5 query body len=%d want 18 (4+8+2+4)", got)
	}
	if binary.BigEndian.Uint32(v5[len(v5)-4:]) != 2 {
		t.Fatalf("v5 query flags tail=%x want 00000002", v5[len(v5)-4:])
	}
}

func TestPlanCQLMultiSession(t *testing.T) {
	// S9: two independent sessions → 18 packets
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 9042, Count: 1,
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Sessions: []core.CQLSession{
				{SrcPort: 12345, Events: []core.CQLEvent{
					{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
					{Kind: "ready", Direction: "s2c"},
				}},
				{SrcPort: 12346, Events: []core.CQLEvent{
					{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
					{Kind: "ready", Direction: "s2c"},
				}},
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
	if len(packets) != 18 {
		t.Fatalf("packet_count=%d want 18", len(packets))
	}
	// First session starts at pkt[0], second at pkt[9]
	if packets[0].L4.SrcPort != 12345 {
		t.Fatalf("pkt[0] src_port=%d want 12345", packets[0].L4.SrcPort)
	}
	if packets[9].L4.SrcPort != 12346 {
		t.Fatalf("pkt[9] src_port=%d want 12346", packets[9].L4.SrcPort)
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

func TestPlanCQLLengthBoundary(t *testing.T) {
	// S10: zero-length OPTIONS body
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 9042, Count: 1,
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "options", Direction: "c2s"},
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
	if len(packets) != 8 {
		t.Fatalf("packet_count=%d want 8", len(packets))
	}
	// pkt[3]: OPTIONS frame (9 bytes: 9-byte header + 0-length body)
	if len(packets[3].Payload) != 9 {
		t.Fatalf("pkt[3] payload len=%d want 9", len(packets[3].Payload))
	}
}

func TestPlanCQLDefaultPort(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", Count: 1,
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
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
	if len(packets) != 8 {
		t.Fatalf("packet_count=%d want 8", len(packets))
	}
	if packets[3].L4.DstPort != 9042 {
		t.Fatalf("dst_port=%d want 9042 (default)", packets[3].L4.DstPort)
	}
}

func TestPlanCQLContextCancel(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
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

func TestCQLGeneratorName(t *testing.T) {
	g := &CQLGenerator{}
	if g.Name() != "cql" {
		t.Fatalf("Name=%q want cql", g.Name())
	}
}

func TestCQLGeneratorGenerate(t *testing.T) {
	cfg := &core.CQLConfig{
		WireProfile: "cql_v4",
		Events: []core.CQLEvent{
			{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
			{Kind: "ready", Direction: "s2c"},
		},
	}
	var events []layers.MessageEvent
	emit := func(ev layers.MessageEvent) error {
		events = append(events, ev)
		return nil
	}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{CQL: cfg},
		EmitMsg: emit,
	}
	ctx := context.Background()
	g := &CQLGenerator{}
	err := g.Generate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d want 2", len(events))
	}
	// First: startup up
	if !events[0].Up {
		t.Fatalf("event[0] Up=false want true")
	}
	if len(events[0].Bytes) == 0 {
		t.Fatal("event[0] bytes empty")
	}
	// Verify startup hex
	want := parseHex("04 00 00 00 01 00 00 00 16 00 01 00 0b 43 51 4c 5f 56 45 52 53 49 4f 4e 00 05 33 2e 30 2e 30")
	if hexStr(events[0].Bytes) != hexStr(want) {
		t.Fatalf("event[0] bytes=%s want=%s", hexStr(events[0].Bytes), hexStr(want))
	}
	// Second: ready down
	if events[1].Up {
		t.Fatalf("event[1] Up=true want false")
	}
}

func TestCQLGeneratorGenerateSessions(t *testing.T) {
	cfg := &core.CQLConfig{
		WireProfile: "cql_v4",
		Sessions: []core.CQLSession{
			{Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
				{Kind: "ready", Direction: "s2c"},
			}},
			{Events: []core.CQLEvent{
				{Kind: "options", Direction: "c2s"},
			}},
		},
	}
	var events []layers.MessageEvent
	emit := func(ev layers.MessageEvent) error {
		events = append(events, ev)
		return nil
	}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{CQL: cfg},
		EmitMsg: emit,
	}
	ctx := context.Background()
	g := &CQLGenerator{}
	err := g.Generate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("events=%d want 3", len(events))
	}
}

func TestCQLGeneratorGenerateNilConfig(t *testing.T) {
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	ctx := context.Background()
	g := &CQLGenerator{}
	err := g.Generate(ctx, req)
	if err == nil || err.Error() != "cql: config is required" {
		t.Fatalf("err=%v want config is required", err)
	}
}

func TestCQLGeneratorGenerateNilReq(t *testing.T) {
	g := &CQLGenerator{}
	err := g.Generate(context.Background(), nil)
	if err == nil || err.Error() != "cql generator: EmitMsg is nil" {
		t.Fatalf("err=%v want EmitMsg is nil", err)
	}
}

func TestCQLGeneratorGenerateNilEmitMsg(t *testing.T) {
	req := &layers.GenRequest{Meta: layers.FlowMeta{}}
	g := &CQLGenerator{}
	err := g.Generate(context.Background(), req)
	if err == nil || err.Error() != "cql generator: EmitMsg is nil" {
		t.Fatalf("err=%v want EmitMsg is nil", err)
	}
}

func TestCQLGeneratorGenerateContextCancel(t *testing.T) {
	cfg := &core.CQLConfig{
		WireProfile: "cql_v4",
		Events: []core.CQLEvent{
			{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{CQL: cfg},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	g := &CQLGenerator{}
	err := g.Generate(ctx, req)
	if err == nil {
		t.Fatalf("expected context error")
	}
}

func TestCQLRegister(t *testing.T) {
	gen, err := layers.NewLayerGenerator("cql")
	if err != nil {
		t.Fatalf("NewLayerGenerator(cql): %v", err)
	}
	if gen == nil {
		t.Fatalf("generator is nil")
	}
	if gen.Name() != "cql" {
		t.Fatalf("name=%q want cql", gen.Name())
	}
}

func TestStringMapBodyDeterministicOrder(t *testing.T) {
	// CQL STARTUP/SUPPORTED 的 string map / multimap 必须确定性编码；Go map 迭代
	// 随机，逐字节断言依赖排序。sortedKeys 恒把 CQL_VERSION 放最前（契约约定），其余
	// 按字典序：故 CQL_VERSION 先于 COMPRESSION。
	opts := map[string]interface{}{"COMPRESSION": "snappy", "CQL_VERSION": "5.0.0"}
	body := buildStringMapBody(opts)
	want := parseHex("00 02 00 0b 43 51 4c 5f 56 45 52 53 49 4f 4e 00 05 35 2e 30 2e 30 00 0b 43 4f 4d 50 52 45 53 53 49 4f 4e 00 06 73 6e 61 70 70 79")
	if hexStr(body) != hexStr(want) {
		t.Fatalf("string map body not deterministic: got %s want %s", hexStr(body), hexStr(want))
	}
}

func TestVersionForProfileRejectsUnknownWithVersionKeyword(t *testing.T) {
	// cql_neg_version：cql_v3 未登记，错误须含 "version" 关键词。
	_, _, err := versionForProfile("cql_v3")
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("err=%v want version keyword", err)
	}
}

func TestPlannerEmptyEventsProducesConnectFlow(t *testing.T) {
	// P0b-2：空 events = connect-only 会话，Plan 产 3 握手 + 0 应用帧 + 4 挥手 = 7 包。
	ch, err := (Planner{}).Plan(context.Background(), core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 9042,
		CQL: &core.CQLConfig{WireProfile: "cql_v4"},
	})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for range ch {
		count++
	}
	if count != 7 {
		t.Fatalf("packets=%d want 7 (connect-only)", count)
	}
}

// W1/G-CQL-2: v4 writes the QUERY/EXECUTE flags as one byte, so a value above
// 0xFF cannot be represented — it must be rejected, never silently truncated
// (design §2 query_flags row: 未登记高位拒绝).
func TestValidateCQLV4QueryFlagsOverflow(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
				{Kind: "ready", Direction: "s2c"},
				{Kind: "query", Direction: "c2s", Query: "SELECT 1", Consistency: 1, QueryFlags: 0x100},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "flags") {
		t.Fatalf("err=%v want v4 query_flags overflow rejection", err)
	}
	// 0xFF is the largest representable v4 value and stays legal.
	ok := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v4",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "3.0.0"}},
				{Kind: "ready", Direction: "s2c"},
				{Kind: "query", Direction: "c2s", Query: "SELECT 1", Consistency: 1, QueryFlags: 0xFF},
			},
		},
	})
	if ok != nil {
		t.Fatalf("0xFF should be legal on v4, got %v", ok)
	}
	// v5 keeps the full [int] range.
	v5ok := (Planner{}).Validate(core.FlowSpec{
		CQL: &core.CQLConfig{
			WireProfile: "cql_v5",
			Events: []core.CQLEvent{
				{Kind: "startup", Direction: "c2s", Options: map[string]interface{}{"CQL_VERSION": "5.0.0"}},
				{Kind: "ready", Direction: "s2c"},
			},
		},
	})
	if v5ok != nil {
		t.Fatalf("v5 handshake-only should stay valid, got %v", v5ok)
	}
}
