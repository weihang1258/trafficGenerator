package postgresql

// Unit tests for the PostgreSQL planner. Tests here cover Validate / Plan
// behavior at the API level; atomic field-level tests live in
// planner_testpoints_test.go.

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/testutil"
)

// drain collects all configs from the channel.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// validPGSpec returns a minimal spec with default trust auth and one
// SELECT query. Used as the base for most tests; individual tests override
// fields. EmitHandshake/EmitTeardown default to true via fillDefaults;
// callers use validPGSpecNoHandshake() to suppress them.
func validPGSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 5432,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		PostgreSQL: &core.PostgreSQLConfig{
			Operations: []core.PGOperation{
				{Kind: "query", SQL: "SELECT 1"},
			},
		},
	}
}

// validPGSpecNoHandshake disables handshake/teardown so packet indices
// are predictable for tests that don't care about TCP plumbing.
func validPGSpecNoHandshake() core.FlowSpec {
	spec := validPGSpec()
	f := false
	spec.PostgreSQL.EmitHandshake = &f
	spec.PostgreSQL.EmitTeardown = &f
	return spec
}

// mustPlan is a helper that fails the test if Plan returns an error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return ch
}

// --- Validate ---

func TestPGValidate_ValidSpec(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(validPGSpec()); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestPGValidate_NilConfigRejected(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	spec.PostgreSQL = nil
	err := p.Validate(spec)
	if err == nil {
		t.Fatalf("nil PG config should be rejected: got nil error")
	}
	if !strings.Contains(err.Error(), "postgresql:") || !strings.Contains(err.Error(), "config") {
		t.Errorf("err=%v, want contains 'postgresql:' and 'config'", err)
	}
}

func TestPGValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	spec.SrcIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "postgresql:") || !strings.Contains(err.Error(), "SrcIP") {
		t.Errorf("err=%v, want contains 'postgresql:' and 'SrcIP'", err)
	}
}

func TestPGValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	spec.DstIP = "not-an-ip"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "DstIP") {
		t.Errorf("err=%v, want contains 'DstIP'", err)
	}
}

func TestPGValidate_MSSBelowMin(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	testutil.EnsureTCP(&spec).MSS = 100
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MSS") {
		t.Errorf("err=%v, want contains 'MSS'", err)
	}
}

func TestPGValidate_MSSZeroOK(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	testutil.EnsureTCP(&spec).MSS = 0
	if err := p.Validate(spec); err != nil {
		t.Errorf("MSS=0 should be accepted: %v", err)
	}
}

func TestPGValidate_BadProtocolVersion(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	spec.PostgreSQL.ProtocolVersion = 0x00040000
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "ProtocolVersion") {
		t.Errorf("err=%v, want contains 'ProtocolVersion'", err)
	}
}

func TestPGValidate_V3ProtocolOK(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	spec.PostgreSQL.ProtocolVersion = 0x00030000
	if err := p.Validate(spec); err != nil {
		t.Errorf("v3 protocol should be accepted: %v", err)
	}
}

func TestPGValidate_V3PipelineProtocolOK(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	spec.PostgreSQL.ProtocolVersion = 0x00030001
	if err := p.Validate(spec); err != nil {
		t.Errorf("v3.1 protocol should be accepted: %v", err)
	}
}

func TestPGValidate_BadAuthMethod(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	spec.PostgreSQL.AuthMethod = "bogus_method"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "AuthMethod") {
		t.Errorf("err=%v, want contains 'AuthMethod'", err)
	}
}

func TestPGValidate_AllAuthMethodsAccepted(t *testing.T) {
	methods := []string{"trust", "cleartext", "md5", "scram-sha-256", "gss", "sspi", "TRUST", "MD5"}
	for _, m := range methods {
		p := NewPlanner()
		spec := validPGSpec()
		spec.PostgreSQL.AuthMethod = m
		if err := p.Validate(spec); err != nil {
			t.Errorf("AuthMethod=%q: %v", m, err)
		}
	}
}

func TestPGValidate_MD5SaltWrongLength(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	spec.PostgreSQL.MD5Salt = []byte{0x01, 0x02, 0x03} // 3 bytes, must be 4
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MD5Salt") {
		t.Errorf("err=%v, want contains 'MD5Salt'", err)
	}
}

func TestPGValidate_MD5SaltExactly4OK(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	spec.PostgreSQL.MD5Salt = []byte{0x01, 0x02, 0x03, 0x04}
	if err := p.Validate(spec); err != nil {
		t.Errorf("MD5Salt 4 bytes should be accepted: %v", err)
	}
}

// --- Plan: structure ---

// TestPGPlan_Handshake verifies the first 3 packets are SYN, SYN-ACK, ACK
// with correct directions and flags (mirrors POP3/FTP pattern).
func TestPGPlan_Handshake(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validPGSpec()))
	if len(cfgs) < 3 {
		t.Fatalf("len=%d, want >= 3 (handshake)", len(cfgs))
	}
	if cfgs[0].Direction != "up" || cfgs[0].L4.Flags != 0x02 {
		t.Errorf("cfg[0]: dir=%s flags=%x, want up/SYN", cfgs[0].Direction, cfgs[0].L4.Flags)
	}
	if len(cfgs[0].L4.TCPOptions) == 0 {
		t.Errorf("cfg[0]: SYN should carry TCP options (MSS, WinScale, SACK)")
	}
	if cfgs[1].Direction != "down" || cfgs[1].L4.Flags != 0x12 {
		t.Errorf("cfg[1]: dir=%s flags=%x, want down/SYN-ACK", cfgs[1].Direction, cfgs[1].L4.Flags)
	}
	if len(cfgs[1].L4.TCPOptions) == 0 {
		t.Errorf("cfg[1]: SYN-ACK should carry TCP options")
	}
	if cfgs[2].Direction != "up" || cfgs[2].L4.Flags != 0x10 {
		t.Errorf("cfg[2]: dir=%s flags=%x, want up/ACK", cfgs[2].Direction, cfgs[2].L4.Flags)
	}
}

// TestPGPlan_Teardown verifies the last 4 packets are FIN-ACK, ACK,
// FIN-ACK, ACK in the standard order.
func TestPGPlan_Teardown(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validPGSpec()))
	n := len(cfgs)
	if n < 4 {
		t.Fatalf("len=%d, want >= 4", n)
	}
	if cfgs[n-4].Direction != "up" || cfgs[n-4].L4.Flags != 0x11 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want up/FIN-ACK", n-4, cfgs[n-4].Direction, cfgs[n-4].L4.Flags)
	}
	if cfgs[n-3].Direction != "down" || cfgs[n-3].L4.Flags != 0x10 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want down/ACK", n-3, cfgs[n-3].Direction, cfgs[n-3].L4.Flags)
	}
	if cfgs[n-2].Direction != "down" || cfgs[n-2].L4.Flags != 0x11 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want down/FIN-ACK", n-2, cfgs[n-2].Direction, cfgs[n-2].L4.Flags)
	}
	if cfgs[n-1].Direction != "up" || cfgs[n-1].L4.Flags != 0x10 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want up/ACK", n-1, cfgs[n-1].Direction, cfgs[n-1].L4.Flags)
	}
}

// TestPGPlan_NoHandshake verifies EmitHandshake=false suppresses the
// TCP 3-way handshake. Packets start with the StartupMessage.
func TestPGPlan_NoHandshake(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	f := false
	spec.PostgreSQL.EmitHandshake = &f
	spec.PostgreSQL.EmitTeardown = &f
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatalf("len=%d, want >= 1", len(cfgs))
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("cfg[0] should be 'up' (StartupMessage); got %s", cfgs[0].Direction)
	}
	if cfgs[0].L4.Flags != 0x18 {
		t.Errorf("cfg[0] should be PSH-ACK (0x18); got 0x%x", cfgs[0].L4.Flags)
	}
}

// TestPGPlan_StartupIsFirstDataPacket verifies that with no handshake,
// the first packet is the StartupMessage (no type byte, length-prefixed
// protocol version 0x00030000).
func TestPGPlan_StartupIsFirstDataPacket(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatalf("len=%d, want >= 1", len(cfgs))
	}
	payload := cfgs[0].Payload
	// First 4 bytes are big-endian length (includes self).
	if len(payload) < 8 {
		t.Fatalf("payload too short: %d", len(payload))
	}
	// Length should equal len(payload) - actually it's a prefix.
	// Length includes itself (4) + rest. So payload length should match.
	length := uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
	if int(length) != len(payload) {
		t.Errorf("length prefix=%d, want %d", length, len(payload))
	}
	// Next 4 bytes: protocol version.
	ver := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
	if ver != 0x00030000 {
		t.Errorf("protocol version=0x%08X, want 0x00030000", ver)
	}
}

// TestPGPlan_AuthOkTrustEmitsImmediately verifies that with trust auth,
// the server sends AuthenticationOk (R, 0) right after the StartupMessage.
func TestPGPlan_AuthOkTrustEmitsImmediately(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	cfgs := drain(mustPlan(t, p, spec))
	// 0=Startup(up), 1=AuthOk(down)
	if len(cfgs) < 2 {
		t.Fatalf("len=%d, want >= 2", len(cfgs))
	}
	if cfgs[1].Direction != "down" {
		t.Fatalf("cfg[1] should be 'down' (AuthOk); got %s", cfgs[1].Direction)
	}
	payload := cfgs[1].Payload
	if len(payload) != 9 {
		t.Errorf("AuthOk payload len=%d, want 9 (1 type + 4 length + 4 sub)", len(payload))
	}
	if payload[0] != 'R' {
		t.Errorf("AuthOk type byte=0x%X, want 'R'", payload[0])
	}
	// Sub-type should be 0 (AuthenticationOk).
	sub := uint32(payload[5])<<24 | uint32(payload[6])<<16 | uint32(payload[7])<<8 | uint32(payload[8])
	if sub != 0 {
		t.Errorf("AuthOk sub-type=%d, want 0", sub)
	}
}

// TestPGPlan_MD5AuthExchange verifies md5 auth: AuthMD5(down) →
// Password(up) → AuthOk(down).
func TestPGPlan_MD5AuthExchange(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.AuthMethod = "md5"
	spec.PostgreSQL.Username = "alice"
	spec.PostgreSQL.Password = "secret"
	cfgs := drain(mustPlan(t, p, spec))
	// 0=Startup, 1=AuthMD5(down), 2=Password(up), 3=AuthOk(down)
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4", len(cfgs))
	}
	// AuthMD5 packet: type=R, length, sub=5, salt=4 bytes.
	if cfgs[1].Payload[0] != 'R' {
		t.Errorf("AuthMD5 type=0x%X, want 'R'", cfgs[1].Payload[0])
	}
	sub := uint32(cfgs[1].Payload[5])<<24 | uint32(cfgs[1].Payload[6])<<16 | uint32(cfgs[1].Payload[7])<<8 | uint32(cfgs[1].Payload[8])
	if sub != 5 {
		t.Errorf("AuthMD5 sub=%d, want 5", sub)
	}
	// Password packet: type='p', length, 'md5' + 32 hex chars.
	if cfgs[2].Payload[0] != 'p' {
		t.Errorf("Password type=0x%X, want 'p'", cfgs[2].Payload[0])
	}
	pwd := string(cfgs[2].Payload[5 : len(cfgs[2].Payload)-1])
	if !strings.HasPrefix(pwd, "md5") || len(pwd) != 3+32 {
		t.Errorf("Password=%q, want 'md5' + 32 hex chars", pwd)
	}
}

// TestPGPlan_CleartextAuthExchange verifies cleartext auth: AuthCleartext
// (R, sub=3) → Password (p, plaintext) → AuthOk.
func TestPGPlan_CleartextAuthExchange(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.AuthMethod = "cleartext"
	spec.PostgreSQL.Password = "mysecret"
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4", len(cfgs))
	}
	if cfgs[1].Payload[0] != 'R' {
		t.Errorf("AuthCleartext type=0x%X, want 'R'", cfgs[1].Payload[0])
	}
	sub := uint32(cfgs[1].Payload[5])<<24 | uint32(cfgs[1].Payload[6])<<16 | uint32(cfgs[1].Payload[7])<<8 | uint32(cfgs[1].Payload[8])
	if sub != 3 {
		t.Errorf("AuthCleartext sub=%d, want 3", sub)
	}
	if cfgs[2].Direction != "up" || cfgs[2].Payload[0] != 'p' {
		t.Errorf("cfg[2]: dir=%s type=0x%X, want up/'p'", cfgs[2].Direction, cfgs[2].Payload[0])
	}
	// Cleartext password (no 'md5' prefix).
	pwd := string(cfgs[2].Payload[5 : len(cfgs[2].Payload)-1])
	if pwd != "mysecret" {
		t.Errorf("password=%q, want 'mysecret'", pwd)
	}
}

// TestPGPlan_SCRAMAuth4Steps verifies scram-sha-256 emits 4 auth frames:
// AuthSASL, client-up SASLInitial, server-down SASLContinue, client-up
// SASLResponse, server-down SASLFinal + AuthOk.
func TestPGPlan_SCRAMAuth4Steps(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.AuthMethod = "scram-sha-256"
	cfgs := drain(mustPlan(t, p, spec))
	// 0=Startup, 1=AuthSASL(down), 2=SASLInitial(up),
	// 3=SASLContinue(down), 4=SASLResponse(up),
	// 5=SASLFinal(down), 6=AuthOk(down)
	if len(cfgs) < 7 {
		t.Fatalf("len=%d, want >= 7 (full SCRAM exchange)", len(cfgs))
	}
	// AuthSASL: type='R', sub=10.
	if cfgs[1].Payload[0] != 'R' {
		t.Errorf("AuthSASL type=0x%X, want 'R'", cfgs[1].Payload[0])
	}
	// SASLInitialResponse and SASLResponse are both 'p' (PasswordMessage
	// family) per the PostgreSQL frontend protocol.
	if cfgs[2].Payload[0] != 'p' {
		t.Errorf("SASLInitial type=0x%X, want 'p'", cfgs[2].Payload[0])
	}
	if cfgs[3].Payload[0] != 'R' {
		t.Errorf("SASLContinue type=0x%X, want 'R'", cfgs[3].Payload[0])
	}
	if cfgs[4].Payload[0] != 'p' {
		t.Errorf("SASLResponse type=0x%X, want 'p'", cfgs[4].Payload[0])
	}
}

// TestPGPlan_ParameterStatusBeforeReadyForQuery verifies that the planner
// emits ParameterStatus (S) messages before BackendKeyData (K) before
// ReadyForQuery (Z) — the canonical post-auth ordering.
func TestPGPlan_ParameterStatusBeforeReadyForQuery(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	cfgs := drain(mustPlan(t, p, spec))
	// Find the first S, K, Z packets.
	var sIdx, kIdx, zIdx = -1, -1, -1
	for i, c := range cfgs {
		if len(c.Payload) == 0 {
			continue
		}
		switch c.Payload[0] {
		case 'S':
			if sIdx == -1 {
				sIdx = i
			}
		case 'K':
			if kIdx == -1 {
				kIdx = i
			}
		case 'Z':
			if zIdx == -1 {
				zIdx = i
			}
		}
	}
	if sIdx == -1 || kIdx == -1 || zIdx == -1 {
		t.Fatalf("missing S/K/Z (sIdx=%d kIdx=%d zIdx=%d)", sIdx, kIdx, zIdx)
	}
	if !(sIdx < kIdx && kIdx < zIdx) {
		t.Errorf("order: S=%d K=%d Z=%d; want S < K < Z", sIdx, kIdx, zIdx)
	}
}

// TestPGPlan_QueryOperationRoundtrip verifies that a "query" operation
// emits Q (up), then RowDescription + DataRow + CommandComplete +
// ReadyForQuery (all down).
func TestPGPlan_QueryOperationRoundtrip(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	cfgs := drain(mustPlan(t, p, spec))
	// Find Q (up).
	var qIdx = -1
	for i, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'Q' {
			qIdx = i
			break
		}
	}
	if qIdx == -1 {
		t.Fatalf("no Query (Q) packet found")
	}
	// After Q, expect T, D, C, Z (in that order).
	want := []byte{'T', 'D', 'C', 'Z'}
	got := make([]byte, 0, 4)
	for i := qIdx + 1; i < len(cfgs) && len(got) < 4; i++ {
		got = append(got, cfgs[i].Payload[0])
	}
	if !equalBytes(got[:4], want) {
		t.Errorf("after Q got=%v, want %v", got[:4], want)
	}
}

// TestPGPlan_FlowIDShared verifies all packets share one flow ID.
func TestPGPlan_FlowIDShared(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validPGSpec()))
	flowID := cfgs[0].FlowID
	if flowID == "" {
		t.Fatal("FlowID empty")
	}
	for i, c := range cfgs {
		if c.FlowID != flowID {
			t.Errorf("cfg[%d].FlowID=%q, want %q", i, c.FlowID, flowID)
		}
	}
}

// TestPGPlan_IPIDIncrementsPerPacket verifies IP ID is unique per packet.
func TestPGPlan_IPIDIncrementsPerPacket(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validPGSpec()))
	seen := make(map[uint16]bool)
	for i, c := range cfgs {
		if seen[c.L3.IPID] {
			t.Errorf("cfg[%d] IPID=%d duplicated", i, c.L3.IPID)
		}
		seen[c.L3.IPID] = true
	}
}

// TestPGPlan_PipelineModeTrueAccepted verifies that Pipeline=true with a
// v3.1 protocol version doesn't crash; the planner still emits the same
// per-operation frames.
func TestPGPlan_PipelineModeTrueAccepted(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.ProtocolVersion = 0x00030001
	spec.PostgreSQL.Pipeline = true
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "parse", Statement: "s1", SQL: "SELECT 1"},
		{Kind: "bind", Portal: "p1", Statement: "s1", ParamCount: 0},
		{Kind: "describe", Mode: "statement", Statement: "s1"},
		{Kind: "execute", Portal: "p1"},
		{Kind: "sync"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 10 {
		t.Fatalf("len=%d, want >= 10 (extended-query 5 ops with responses)", len(cfgs))
	}
}

// TestPGPlan_EmptyOperationsStillCompletes verifies the planner finishes
// cleanly when Operations is empty: still emits handshake, Startup,
// AuthOk, ParameterStatus*, BackendKeyData, ReadyForQuery, teardown.
func TestPGPlan_EmptyOperationsStillCompletes(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	spec.PostgreSQL.Operations = nil
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + startup(1) + authok(1) + 7 params + BKD(1) + RFQ(1)
	// + teardown(4) = 18
	if len(cfgs) != 18 {
		t.Fatalf("len=%d, want 18", len(cfgs))
	}
}

// TestPGPlan_InitialSeqOverride verifies that spec.TCP.InitialSeq fixes
// the client ISN for reproducible tests.
func TestPGPlan_InitialSeqOverride(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	testutil.EnsureTCP(&spec).InitialSeq = 0x12345678
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L4.Seq != 0x12345678 {
		t.Errorf("cfg[0] (SYN) Seq=0x%X, want 0x12345678", cfgs[0].L4.Seq)
	}
}

// TestPGPlan_MSSSegmentation verifies long payloads split at MSS
// boundaries.
func TestPGPlan_MSSSegmentation(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	testutil.EnsureTCP(&spec).MSS = 536 // MinMSS = 536 per RFC 879
	// Use a giant parameter value in bind to force segmentation. The
	// bind body is ~2066 bytes; with MSS=536 expect 4 segments.
	spec.PostgreSQL.AuthMethod = "trust"
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "parse", Statement: "s1", SQL: "SELECT $1", ParamCount: 1},
		{Kind: "bind", Portal: "p1", Statement: "s1", ParamCount: 1, ParamValues: []string{strings.Repeat("x", 2048)}},
		{Kind: "execute", Portal: "p1"},
		{Kind: "sync"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find all "up" PSH-ACK packets; verify no payload exceeds MSS.
	var upPayloadLens []int
	for _, c := range cfgs {
		if c.Direction == "up" && c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			upPayloadLens = append(upPayloadLens, len(c.Payload))
			if len(c.Payload) > 536 {
				t.Errorf("up payload len=%d exceeds MSS 536", len(c.Payload))
			}
		}
	}
	// Without segmentation, there'd be 4 up data packets (parse, bind,
	// execute, sync). With bind segmented into 4, expect 7 total.
	if len(upPayloadLens) < 7 {
		t.Errorf("expected at least 7 up data packets (bind segmented), got %d (%v)", len(upPayloadLens), upPayloadLens)
	}
	// At least 3 segments should be exactly MSS-sized (the chunked parts
	// of the bind message).
	mssSized := 0
	for _, l := range upPayloadLens {
		if l == 536 {
			mssSized++
		}
	}
	if mssSized < 3 {
		t.Errorf("expected at least 3 MSS-sized segments, got %d", mssSized)
	}
}

// TestPGPlan_DstPortDefaultsTo5432 verifies the planner uses the user's
// DstPort=5432 for PostgreSQL.
func TestPGPlan_DstPortDefaultsTo5432(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.Direction == "up" && c.L4.DstPort != 5432 {
			t.Errorf("cfg[%d] up DstPort=%d, want 5432", i, c.L4.DstPort)
		}
		if c.Direction == "down" && c.L4.SrcPort != 5432 {
			t.Errorf("cfg[%d] down SrcPort=%d, want 5432", i, c.L4.SrcPort)
		}
	}
}

// TestPGPlan_QueryReturnsTransactionStatusIdle verifies SELECT returns
// rfqIdle status byte in the ReadyForQuery.
func TestPGPlan_QueryReturnsTransactionStatusIdle(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	cfgs := drain(mustPlan(t, p, spec))
	// Find the last 'Z' (ReadyForQuery) packet.
	var lastZ []byte
	for i := len(cfgs) - 1; i >= 0; i-- {
		c := cfgs[i]
		if len(c.Payload) > 0 && c.Payload[0] == 'Z' {
			lastZ = c.Payload
			break
		}
	}
	if lastZ == nil {
		t.Fatalf("no Z packet found")
	}
	// payload: 'Z' + length(4) + status(1). status byte is at offset 5.
	if len(lastZ) < 6 {
		t.Fatalf("Z payload too short: %d", len(lastZ))
	}
	if lastZ[5] != 'I' {
		t.Errorf("status byte=0x%X, want 'I' (idle)", lastZ[5])
	}
}

// TestPGPlan_BeginSwitchesToInTrans verifies that a BEGIN query flips
// the ReadyForQuery status to 'T' (in transaction).
func TestPGPlan_BeginSwitchesToInTrans(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "query", SQL: "BEGIN"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find all Z packets; expect at least 2 (after auth + after BEGIN).
	var statuses []byte
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == 'Z' {
			statuses = append(statuses, c.Payload[5])
		}
	}
	if len(statuses) < 2 {
		t.Fatalf("expected >= 2 Z packets, got %d", len(statuses))
	}
	if statuses[len(statuses)-1] != 'T' {
		t.Errorf("last status byte=0x%X, want 'T' (in trans)", statuses[len(statuses)-1])
	}
}

// TestPGPlan_CommitReturnsToIdle verifies that COMMIT returns to idle.
func TestPGPlan_CommitReturnsToIdle(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "query", SQL: "BEGIN"},
		{Kind: "query", SQL: "SELECT 1"},
		{Kind: "query", SQL: "COMMIT"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	var statuses []byte
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == 'Z' {
			statuses = append(statuses, c.Payload[5])
		}
	}
	last := statuses[len(statuses)-1]
	if last != 'I' {
		t.Errorf("final status byte=0x%X, want 'I' (idle after COMMIT)", last)
	}
}

// TestPGPlan_ParseOperationRoundtrip verifies parse: P(up) → 1(down).
func TestPGPlan_ParseOperationRoundtrip(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "parse", Statement: "s1", SQL: "SELECT 1"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// After auth: parse up (P) followed by parse-complete (1).
	var sawP, saw1 bool
	for _, c := range cfgs {
		if len(c.Payload) == 0 {
			continue
		}
		if c.Payload[0] == 'P' && c.Direction == "up" {
			sawP = true
		}
		if c.Payload[0] == '1' && c.Direction == "down" {
			saw1 = true
		}
	}
	if !sawP {
		t.Error("no Parse (P) packet found")
	}
	if !saw1 {
		t.Error("no ParseComplete (1) packet found")
	}
}

// TestPGPlan_TerminateSendsX verifies terminate operation emits X (no
// server response).
func TestPGPlan_TerminateSendsX(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "terminate"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	sawX := false
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == 'X' && c.Direction == "up" {
			sawX = true
		}
	}
	if !sawX {
		t.Error("no Terminate (X) packet found")
	}
}

// TestPGPlan_SyncReturnsReadyForQuery verifies sync emits S(up) → Z(down).
func TestPGPlan_SyncReturnsReadyForQuery(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "sync"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// First user-op sync: should be the S up packet.
	var sawS, sawZ bool
	for _, c := range cfgs {
		if len(c.Payload) == 0 {
			continue
		}
		if c.Payload[0] == 'S' && c.Direction == "up" {
			sawS = true
		}
		if c.Payload[0] == 'Z' && c.Direction == "down" {
			sawZ = true
		}
	}
	if !sawS || !sawZ {
		t.Errorf("Sync: sawS=%v sawZ=%v, want both true", sawS, sawZ)
	}
}

// TestPGPlan_EmitAsServerNotification verifies EmitAsServer=true with
// Kind="notification" emits a NotificationResponse (A) down.
func TestPGPlan_EmitAsServerNotification(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "notification", EmitAsServer: true, NotifyChannel: "ch", NotifyPayload: "hi"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	sawA := false
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == 'A' && c.Direction == "down" {
			sawA = true
		}
	}
	if !sawA {
		t.Error("no NotificationResponse (A) found")
	}
}

// TestPGPlan_ReplicationStartEmitsCopyBoth verifies replication-start
// emits W (CopyBothResponse) and CopyData frames.
func TestPGPlan_ReplicationStartEmitsCopyBoth(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "replication-start", ReplicationSlot: "s1", ReplicationLSN: "0/1000000"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	sawW := false
	sawD := false
	for _, c := range cfgs {
		if len(c.Payload) == 0 {
			continue
		}
		if c.Payload[0] == 'W' && c.Direction == "down" {
			sawW = true
		}
		if c.Payload[0] == 'd' && c.Direction == "down" {
			sawD = true
		}
	}
	if !sawW {
		t.Error("no CopyBothResponse (W) found")
	}
	if !sawD {
		t.Error("no CopyData (d) frame found")
	}
}

// TestPGPlan_NilPostgresFails verifies that Plan rejects a nil
// PostgreSQL config instead of silently producing 0 packet configs.
// A nil config used to yield an empty channel, which made tasks report
// "completed" with 0 packets (the engine 0-config guard at worker.go
// now surfaces this as "planner produced 0 packet configs"; the planner
// itself must fail fast with a descriptive error).
func TestPGPlan_NilPostgresFails(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	spec.PostgreSQL = nil
	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatalf("Plan with nil PostgreSQL config: got nil error, want error")
	}
	if !strings.Contains(err.Error(), "postgresql:") || !strings.Contains(err.Error(), "config") {
		t.Errorf("err=%v, want contains 'postgresql:' and 'config'", err)
	}
	if ch != nil {
		t.Errorf("Plan returned non-nil channel with error; want nil")
	}
}

// TestPGPlan_StartupParamsInMessage verifies that user-provided
// StartupParams (e.g. custom "database") appear in the StartupMessage.
func TestPGPlan_StartupParamsInMessage(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.StartupParams = map[string]string{
		"user":            "alice",
		"database":        "mydb",
		"client_encoding": "UTF8",
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatalf("len=%d", len(cfgs))
	}
	payload := cfgs[0].Payload
	if !strings.Contains(string(payload), "database") || !strings.Contains(string(payload), "mydb") {
		t.Errorf("StartupMessage should contain database=mydb: %q", payload)
	}
	if !strings.Contains(string(payload), "alice") {
		t.Errorf("StartupMessage should contain user=alice: %q", payload)
	}
}

// --- helpers ---

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}