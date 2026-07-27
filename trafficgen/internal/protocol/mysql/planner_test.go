package mysql

// Unit tests for the MySQL planner. Tests here cover Validate / Plan
// behavior at the API level; atomic field-level tests live in
// planner_testpoints_test.go.

import (
	"context"
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

// validMySQLSpec returns a minimal spec with a single COM_PING command.
// Used as the base for most tests; individual tests override fields.
func validMySQLSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 3306,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		MySQL: &core.MySQLConfig{
			ServerVersion: "8.0.36",
			AuthPlugin:    "mysql_native_password",
			Username:      "root",
			Password:      "secret",
			Commands: []core.MySQLCommand{
				{Opcode: 0x0f, ReplyMode: "ok"}, // COM_PING
			},
		},
	}
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

// --- Validate tests ---

func TestMySQLValidate_ValidSpec(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(validMySQLSpec()); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestMySQLValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.SrcIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "mysql:") || !strings.Contains(err.Error(), "SrcIP") {
		t.Errorf("err=%v, want contains 'mysql:' and 'SrcIP'", err)
	}
}

func TestMySQLValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.DstIP = "not-an-ip"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "DstIP") {
		t.Errorf("err=%v, want contains 'DstIP'", err)
	}
}

func TestMySQLValidate_MSSBelowMin(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.TCP = &core.TCPConfig{MSS: 100}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MSS") {
		t.Errorf("err=%v, want contains 'MSS'", err)
	}
}

func TestMySQLValidate_BadAuthPlugin(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.AuthPlugin = "bogus_plugin"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "AuthPlugin") {
		t.Errorf("err=%v, want contains 'AuthPlugin'", err)
	}
}

func TestMySQLValidate_BadScrambleLen(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Scramble = []byte{0x01, 0x02, 0x03} // not 20 bytes
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Scramble") {
		t.Errorf("err=%v, want contains 'Scramble'", err)
	}
}

func TestMySQLValidate_MaxPacketSizeTooBig(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.MaxPacketSize = uint32(MaxPacketBytes) + 1
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MaxPacketSize") {
		t.Errorf("err=%v, want contains 'MaxPacketSize'", err)
	}
}

func TestMySQLValidate_UnknownOpcode(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{{Opcode: 0xff}}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Opcode") {
		t.Errorf("err=%v, want contains 'Opcode'", err)
	}
}

func TestMySQLValidate_BadBodyEncoding(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{{Opcode: 0x03, BodyEncoding: "rot13"}}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "BodyEncoding") {
		t.Errorf("err=%v, want contains 'BodyEncoding'", err)
	}
}

func TestMySQLValidate_BadReplyMode(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{{Opcode: 0x03, ReplyMode: "nonexistent"}}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "ReplyMode") {
		t.Errorf("err=%v, want contains 'ReplyMode'", err)
	}
}

func TestMySQLValidate_COMStmtExecuteNoStmtID(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{{Opcode: 0x1b, ReplyMode: "binary-result"}}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "StmtID") {
		t.Errorf("err=%v, want contains 'StmtID'", err)
	}
}

func TestMySQLValidate_NilMySQL(t *testing.T) {
	// Validate tolerates spec.MySQL == nil (planner still emits greeting+auth).
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("nil MySQL should not error: %v", err)
	}
}

// --- Plan structure tests ---

func TestMySQLPlan_HandshakeGreetingAuthPingQuit(t *testing.T) {
	// Default spec with COM_PING -> TCP handshake(3) + greeting(1) +
	// client handshake response(1) + auth OK(1) + COM_PING(1) + OK(1) +
	// teardown(4) = 12 packets.
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	if len(cfgs) != 12 {
		t.Fatalf("len=%d, want 12", len(cfgs))
	}
	// Verify handshake structure.
	if cfgs[0].Direction != "up" || cfgs[0].L4.Flags != 0x02 {
		t.Errorf("cfg[0] should be SYN up: %+v", cfgs[0])
	}
	if cfgs[1].Direction != "down" || cfgs[1].L4.Flags != 0x12 {
		t.Errorf("cfg[1] should be SYN-ACK down: %+v", cfgs[1])
	}
	if cfgs[2].Direction != "up" || cfgs[2].L4.Flags != 0x10 {
		t.Errorf("cfg[2] should be ACK up: %+v", cfgs[2])
	}
	// cfgs[3] = greeting (down).
	if cfgs[3].Direction != "down" || cfgs[3].L4.Flags != 0x18 {
		t.Errorf("cfg[3] should be PSH-ACK down (greeting): %+v", cfgs[3])
	}
	// cfgs[4] = client handshake response (up).
	if cfgs[4].Direction != "up" || cfgs[4].L4.Flags != 0x18 {
		t.Errorf("cfg[4] should be PSH-ACK up (handshake resp): %+v", cfgs[4])
	}
	// cfgs[5] = server auth OK (down).
	if cfgs[5].Direction != "down" || cfgs[5].L4.Flags != 0x18 {
		t.Errorf("cfg[5] should be PSH-ACK down (auth OK): %+v", cfgs[5])
	}
	// cfgs[6] = COM_PING (up).
	if cfgs[6].Direction != "up" || cfgs[6].L4.Flags != 0x18 {
		t.Errorf("cfg[6] should be PSH-ACK up (COM_PING): %+v", cfgs[6])
	}
	// cfgs[7] = OK reply (down).
	if cfgs[7].Direction != "down" || cfgs[7].L4.Flags != 0x18 {
		t.Errorf("cfg[7] should be PSH-ACK down (OK reply): %+v", cfgs[7])
	}
	// cfgs[8..11] = TCP 4-way teardown.
	if cfgs[8].Direction != "up" || cfgs[8].L4.Flags != 0x11 {
		t.Errorf("cfg[8] should be FIN-ACK up: %+v", cfgs[8])
	}
}

func TestMySQLPlan_ServerBypassAuthSkipsGreetingAndResponse(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.ServerBypassAuth = true
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + greeting(1) + COM_PING(1) + OK(1) + teardown(4) = 10.
	if len(cfgs) != 10 {
		t.Fatalf("len=%d, want 10 (ServerBypassAuth)", len(cfgs))
	}
}

func TestMySQLPlan_NoHandshakeSkipsThreeWay(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.TCP = &core.TCPConfig{Handshake: false, Termination: true}
	cfgs := drain(mustPlan(t, p, spec))
	// No handshake: greeting(1) + response(1) + auth OK(1) + ping(1) + OK(1) + teardown(4) = 9.
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9 (no handshake)", len(cfgs))
	}
}

func TestMySQLPlan_NoTerminationSkipsFourWay(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.TCP = &core.TCPConfig{Handshake: true, Termination: false}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + greeting(1) + response(1) + auth OK(1) + ping(1) + OK(1) = 8.
	if len(cfgs) != 8 {
		t.Fatalf("len=%d, want 8 (no teardown)", len(cfgs))
	}
}

func TestMySQLPlan_GreetingSeqZero(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	// Greeting packet's seq byte (4th byte of payload) must be 0x00.
	if len(cfgs[3].Payload) < 4 {
		t.Fatalf("greeting payload too short: %d", len(cfgs[3].Payload))
	}
	if cfgs[3].Payload[3] != 0x00 {
		t.Errorf("greeting seq=%d, want 0", cfgs[3].Payload[3])
	}
}

func TestMySQLPlan_HandshakeResponseSeqOne(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	if len(cfgs[4].Payload) < 4 {
		t.Fatalf("handshake response payload too short: %d", len(cfgs[4].Payload))
	}
	if cfgs[4].Payload[3] != 0x01 {
		t.Errorf("handshake response seq=%d, want 1", cfgs[4].Payload[3])
	}
}

func TestMySQLPlan_AuthOKSeqTwo(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	if len(cfgs[5].Payload) < 4 {
		t.Fatalf("auth OK payload too short: %d", len(cfgs[5].Payload))
	}
	if cfgs[5].Payload[3] != 0x02 {
		t.Errorf("auth OK seq=%d, want 2", cfgs[5].Payload[3])
	}
}

func TestMySQLPlan_CommandSeqResetsToZero(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	// COM_PING packet is cfgs[6]; its seq byte must be 0 (per-command reset).
	if cfgs[6].Payload[3] != 0x00 {
		t.Errorf("command seq=%d, want 0 (per-command reset)", cfgs[6].Payload[3])
	}
}

func TestMySQLPlan_ReplySeqStartsAtOne(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	// OK reply is cfgs[7]; its seq must be 1 (server reply for command 0).
	if cfgs[7].Payload[3] != 0x01 {
		t.Errorf("reply seq=%d, want 1", cfgs[7].Payload[3])
	}
}

func TestMySQLPlan_DstPortDefaultAppliedByStrategyConvert(t *testing.T) {
	// Validate doesn't fill defaults (per convention); the planner relies
	// on the strategy_convert.go pre-pass to set DstPort=3306 when absent.
	// Here we ensure Validate doesn't reject a 0 dst_port (Plan would
	// emit, but we won't drain - just check no error).
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.DstPort = 0
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate should not reject dst_port=0: %v", err)
	}
}

func TestMySQLPlan_PacketIndexMonotonic(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validMySQLSpec()))
	for i, c := range cfgs {
		if c.PacketIndex != uint64(i) {
			t.Errorf("cfgs[%d].PacketIndex=%d, want %d", i, c.PacketIndex, i)
		}
	}
}

func TestMySQLPlan_GroupIDMetadataPropagated(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.GroupID = &core.StrategyConfig{Strategy: "fixed", Value: "shard-1"}
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.Metadata == nil {
			t.Errorf("cfgs[%d].Metadata is nil", i)
			continue
		}
		if g, _ := c.Metadata["group_id"].(string); g != "shard-1" {
			t.Errorf("cfgs[%d].Metadata[group_id]=%q, want 'shard-1'", i, g)
		}
	}
}

func TestMySQLPlan_FlowIDContainsFourTuple(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].FlowID == "" {
		t.Errorf("FlowID is empty")
	}
	// FlowID format: srcIP-dstIP-srcPort-dstPort.
	want := "10.0.0.1-10.0.0.2-50000-3306"
	if cfgs[0].FlowID != want {
		t.Errorf("FlowID=%q, want %q", cfgs[0].FlowID, want)
	}
}
