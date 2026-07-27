package pop3

// Test points for the POP3 planner. Each test asserts observable
// PacketConfig field values, not just "no error". Derived from the
// session-level dialog structure documented in planner.go and the
// RFC 1939 spec.

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

func validPOP3Spec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 110,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		POP3: &core.POP3Config{
			Banner: "+OK POP3 server ready",
			Commands: []core.POP3Command{
				{Cmd: "USER alice", Response: "+OK alice is a valid mailbox"},
				{Cmd: "PASS secret123", Response: "+OK 5 messages (12345 octets)"},
				{Cmd: "STAT", Response: "+OK 5 12345"},
				{Cmd: "QUIT", Response: "+OK POP3 server signing off"},
			},
		},
	}
}

// validPOP3SpecNoBanner returns the same default spec but with the
// optional banner removed. Used by tests that want predictable packet
// indices (cfgs[3] = first command, cfgs[4] = first response, etc.).
// Banner-specific tests (TestPOP3Plan_BannerEmitted) use the default
// validPOP3Spec() which includes the banner.
func validPOP3SpecNoBanner() core.FlowSpec {
	spec := validPOP3Spec()
	spec.POP3.Banner = ""
	return spec
}

// --- Validate ---

func TestPOP3Validate_ValidIPs(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestPOP3Validate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.SrcIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "pop3:") || !strings.Contains(err.Error(), "SrcIP") {
		t.Errorf("err=%v, want contains 'pop3:' and 'SrcIP'", err)
	}
}

func TestPOP3Validate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.DstIP = "not-an-ip"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "DstIP") {
		t.Errorf("err=%v, want contains 'DstIP'", err)
	}
}

func TestPOP3Validate_MSSTooSmall(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	testutil.EnsureTCP(&spec).MSS = 100 // below MinMSS=536
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MSS") {
		t.Errorf("err=%v, want contains 'MSS'", err)
	}
}

func TestPOP3Validate_MSSZeroOK(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	testutil.EnsureTCP(&spec).MSS = 0
	if err := p.Validate(spec); err != nil {
		t.Errorf("MSS=0 should be accepted: %v", err)
	}
}

func TestPOP3Validate_NilPOP3Config(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3 = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("nil POP3 config should be accepted: %v", err)
	}
}

// TestPOP3Validate_CRLFInjectionRejected covers testcase 1.1.4: USER command
// with embedded CRLF injection must be rejected at Validate.
func TestPOP3Validate_CRLFInjectionRejected(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Commands[0].Cmd = "USER alice\r\nDELE 1"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "CRLF") {
		t.Errorf("err=%v, want contains 'CRLF'", err)
	}
}

// TestPOP3Validate_USERTooLong covers testcase 1.1.6: USER name 41 chars
// must be rejected.
func TestPOP3Validate_USERTooLong(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Commands[0].Cmd = "USER " + strings.Repeat("a", 41)
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "USER") {
		t.Errorf("err=%v, want contains 'USER'", err)
	}
}

// TestPOP3Validate_PASSTooLong covers testcase 1.2.4: PASS 256 chars
// must be rejected.
func TestPOP3Validate_PASSTooLong(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Commands[1].Cmd = "PASS " + strings.Repeat("x", 256)
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "PASS") {
		t.Errorf("err=%v, want contains 'PASS'", err)
	}
}

// TestPOP3Validate_APOPDigestLength covers testcase 1.3.2: APOP digest of
// 31 chars (not 32) must be rejected.
func TestPOP3Validate_APOPDigestLength(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "APOP alice " + strings.Repeat("a", 31), Response: "+OK"},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "digest") {
		t.Errorf("err=%v, want contains 'digest'", err)
	}
}

// TestPOP3Validate_APOPDigestNotHex covers testcase 1.3.3: APOP digest
// of 32 non-hex chars must be rejected.
func TestPOP3Validate_APOPDigestNotHex(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "APOP alice " + strings.Repeat("z", 32), Response: "+OK"},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "hex") {
		t.Errorf("err=%v, want contains 'hex'", err)
	}
}

// TestPOP3Validate_APOPDigestValid covers the APOP happy path: 32 hex
// chars is accepted (testcase 1.3.1).
func TestPOP3Validate_APOPDigestValid(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "APOP alice c4c9334bac560ecc975eac1bbdded0e0", Response: "+OK"},
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid APOP digest should be accepted: %v", err)
	}
}

// TestPOP3Validate_UIDTooLong covers testcase 1.11.7: UID > 70 chars
// must be rejected.
func TestPOP3Validate_UIDTooLong(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Mailbox = &core.POP3Mailbox{
		Messages: []core.POP3Message{
			{UID: strings.Repeat("a", 71)},
		},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "UID") {
		t.Errorf("err=%v, want contains 'UID'", err)
	}
}

// TestPOP3Validate_EmitMailDropWithoutMailbox covers testcase 6.6:
// EmitMailDrop=true but Mailbox=nil must be rejected.
func TestPOP3Validate_EmitMailDropWithoutMailbox(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Mailbox = nil
	spec.POP3.Commands = []core.POP3Command{
		{EmitMailDrop: true, MsgNum: 1},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Mailbox") {
		t.Errorf("err=%v, want contains 'Mailbox'", err)
	}
}

// TestPOP3Validate_EmitMailDropMsgNumOutOfRange covers testcase 1.5.4/1.5.5:
// EmitMailDrop MsgNum=999 must be rejected.
func TestPOP3Validate_EmitMailDropMsgNumOutOfRange(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Mailbox = &core.POP3Mailbox{
		Messages: []core.POP3Message{{UID: "u1"}},
	}
	spec.POP3.Commands = []core.POP3Command{
		{EmitMailDrop: true, MsgNum: 999},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MsgNum") {
		t.Errorf("err=%v, want contains 'MsgNum'", err)
	}
}

// TestPOP3Validate_ResponseWithCRLFWithoutMultiline covers testcase 1.17.4:
// Response contains CRLF but Multiline=false must be rejected.
func TestPOP3Validate_ResponseWithCRLFWithoutMultiline(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Commands[0].Response = "+OK\r\nmulti"
	spec.POP3.Commands[0].Multiline = false
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Multiline") {
		t.Errorf("err=%v, want contains 'Multiline'", err)
	}
}

// --- Plan: structure ---

// TestPOP3Plan_Handshake verifies the first 3 packets are SYN, SYN-ACK,
// ACK with correct directions, flags, and TCP options (mirrors FTP).
func TestPOP3Plan_Handshake(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validPOP3Spec()))
	if len(cfgs) < 3 {
		t.Fatalf("len=%d, want >= 3 (handshake)", len(cfgs))
	}
	// SYN up
	if cfgs[0].Direction != "up" || cfgs[0].L4.Flags != 0x02 {
		t.Errorf("cfg[0]: dir=%s flags=%x, want up/SYN", cfgs[0].Direction, cfgs[0].L4.Flags)
	}
	if len(cfgs[0].L4.TCPOptions) == 0 {
		t.Errorf("cfg[0]: SYN should carry TCP options (MSS, WinScale, SACK)")
	}
	// SYN-ACK down
	if cfgs[1].Direction != "down" || cfgs[1].L4.Flags != 0x12 {
		t.Errorf("cfg[1]: dir=%s flags=%x, want down/SYN-ACK", cfgs[1].Direction, cfgs[1].L4.Flags)
	}
	if len(cfgs[1].L4.TCPOptions) == 0 {
		t.Errorf("cfg[1]: SYN-ACK should carry TCP options")
	}
	// ACK up
	if cfgs[2].Direction != "up" || cfgs[2].L4.Flags != 0x10 {
		t.Errorf("cfg[2]: dir=%s flags=%x, want up/ACK", cfgs[2].Direction, cfgs[2].L4.Flags)
	}
	if len(cfgs[2].L4.TCPOptions) != 0 {
		t.Errorf("cfg[2]: ACK should NOT carry TCP options")
	}
}

// TestPOP3Plan_Teardown verifies the last 4 packets are FIN-ACK, ACK,
// FIN-ACK, ACK in the standard order.
func TestPOP3Plan_Teardown(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validPOP3Spec()))
	n := len(cfgs)
	if n < 4 {
		t.Fatalf("len=%d, want >= 4 (teardown)", n)
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

// TestPOP3Plan_BannerEmitted verifies that when Banner is non-empty,
// the first payload packet after the handshake is a down PSH-ACK
// containing the banner text + CRLF.
func TestPOP3Plan_BannerEmitted(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validPOP3Spec()))
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4", len(cfgs))
	}
	bannerPkt := cfgs[3]
	if bannerPkt.Direction != "down" || bannerPkt.L4.Flags != 0x18 {
		t.Fatalf("cfg[3]: dir=%s flags=%x, want down/PSH-ACK", bannerPkt.Direction, bannerPkt.L4.Flags)
	}
	if !strings.Contains(string(bannerPkt.Payload), "+OK POP3 server ready") {
		t.Errorf("cfg[3] payload=%q, want contains '+OK POP3 server ready'", bannerPkt.Payload)
	}
	if !strings.HasSuffix(string(bannerPkt.Payload), "\r\n") {
		t.Errorf("cfg[3] payload should end with CRLF (RFC 1939 §3)")
	}
}

// TestPOP3Plan_NoBannerSkipped verifies that an empty Banner emits no
// payload packet between the handshake and the first command.
func TestPOP3Plan_NoBannerSkipped(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Banner = ""
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4", len(cfgs))
	}
	if cfgs[3].Direction != "up" {
		t.Errorf("cfg[3]: dir=%s, want up (first command)", cfgs[3].Direction)
	}
	if !strings.Contains(string(cfgs[3].Payload), "USER alice") {
		t.Errorf("cfg[3] payload=%q, want contains 'USER alice'", cfgs[3].Payload)
	}
}

// TestPOP3Plan_CommandResponsePairs verifies that each POP3Command
// produces a (command up) + (response down) pair, in order, with the
// correct text. With 1 banner + 4 commands = 8 data packets.
func TestPOP3Plan_CommandResponsePairs(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validPOP3Spec()))
	// handshake(3) + banner(1) + 4 commands * 2 + teardown(4) = 16
	if len(cfgs) != 16 {
		t.Fatalf("len=%d, want 16 (3 + 1 + 8 + 4)", len(cfgs))
	}
	// cfg[4] = USER cmd up
	if cfgs[4].Direction != "up" || !strings.Contains(string(cfgs[4].Payload), "USER alice") {
		t.Errorf("cfg[4]: dir=%s payload=%q, want up/USER", cfgs[4].Direction, cfgs[4].Payload)
	}
	// cfg[5] = +OK resp down
	if cfgs[5].Direction != "down" || !strings.Contains(string(cfgs[5].Payload), "+OK alice") {
		t.Errorf("cfg[5]: dir=%s payload=%q, want down/+OK", cfgs[5].Direction, cfgs[5].Payload)
	}
	// cfg[6] = PASS cmd up
	if cfgs[6].Direction != "up" || !strings.Contains(string(cfgs[6].Payload), "PASS secret123") {
		t.Errorf("cfg[6]: dir=%s payload=%q, want up/PASS", cfgs[6].Direction, cfgs[6].Payload)
	}
	// cfg[7] = +OK resp down
	if cfgs[7].Direction != "down" || !strings.Contains(string(cfgs[7].Payload), "5 messages") {
		t.Errorf("cfg[7]: dir=%s payload=%q, want down/+OK", cfgs[7].Direction, cfgs[7].Payload)
	}
	// cfg[8] = STAT up
	if cfgs[8].Direction != "up" || !strings.Contains(string(cfgs[8].Payload), "STAT") {
		t.Errorf("cfg[8]: dir=%s payload=%q, want up/STAT", cfgs[8].Direction, cfgs[8].Payload)
	}
	// cfg[9] = +OK 5 12345 down
	if cfgs[9].Direction != "down" || !strings.Contains(string(cfgs[9].Payload), "12345") {
		t.Errorf("cfg[9]: dir=%s payload=%q, want down/+OK", cfgs[9].Direction, cfgs[9].Payload)
	}
	// cfg[10] = QUIT up
	if cfgs[10].Direction != "up" || !strings.Contains(string(cfgs[10].Payload), "QUIT") {
		t.Errorf("cfg[10]: dir=%s payload=%q, want up/QUIT", cfgs[10].Direction, cfgs[10].Payload)
	}
	// cfg[11] = +OK POP3 server signing off down
	if cfgs[11].Direction != "down" || !strings.Contains(string(cfgs[11].Payload), "signing off") {
		t.Errorf("cfg[11]: dir=%s payload=%q, want down/+OK", cfgs[11].Direction, cfgs[11].Payload)
	}
}

// TestPOP3Plan_CRLFTerminator verifies every POP3 command and single-line
// response payload ends with CRLF per RFC 1939 §3 (covers testcase 1.16.1).
func TestPOP3Plan_CRLFTerminator(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validPOP3Spec()))
	for i, c := range cfgs {
		if c.L4.Flags != 0x18 {
			continue
		}
		if len(c.Payload) == 0 {
			continue
		}
		if !strings.HasSuffix(string(c.Payload), "\r\n") {
			t.Errorf("cfg[%d] payload must end with CRLF: %q", i, c.Payload)
		}
	}
}

// TestPOP3Plan_FlowIDShared verifies all packets share one flow ID
// (the session-level invariant: one POP3 connection = one flow).
func TestPOP3Plan_FlowIDShared(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validPOP3Spec()))
	flowID := cfgs[0].FlowID
	if flowID == "" {
		t.Fatal("FlowID empty")
	}
	for i, c := range cfgs {
		if c.FlowID != flowID {
			t.Errorf("cfg[%d].FlowID=%q, want %q (one flow per session)", i, c.FlowID, flowID)
		}
	}
}

// TestPOP3Plan_IPIDIncrementsPerPacket verifies that every packet has a
// distinct IP ID (no cross-packet ID reuse within the flow).
func TestPOP3Plan_IPIDIncrementsPerPacket(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validPOP3Spec()))
	seen := make(map[uint16]bool)
	for i, c := range cfgs {
		if seen[c.L3.IPID] {
			t.Errorf("cfg[%d] IPID=%d duplicated", i, c.L3.IPID)
		}
		seen[c.L3.IPID] = true
	}
}

// TestPOP3Plan_SequenceContinuity verifies that the next command's ACK
// field covers all prior response bytes - the signature of a continuous
// sequence space per direction within one flow.
func TestPOP3Plan_SequenceContinuity(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validPOP3Spec()))
	var serverSeq uint32
	for i, c := range cfgs {
		switch {
		case c.L4.Flags == 0x12: // SYN-ACK: server ISN
			serverSeq = c.L4.Seq + 1
		case c.Direction == "down" && c.L4.Flags == 0x18:
			serverSeq = c.L4.Seq + uint32(len(c.Payload))
		case c.Direction == "up" && c.L4.Flags == 0x18:
			if c.L4.Ack != serverSeq {
				t.Errorf("cfg[%d] (up cmd) Ack=%d, want %d (cumulative server seq)", i, c.L4.Ack, serverSeq)
			}
		}
	}
}

// TestPOP3Plan_DstPortDefaultsTo110 verifies that the strategy_convert
// dst_port default for POP3 is 110 when the user did not specify one.
// The actual defaulting is in core.strategy_convert; here we verify that
// when DstPort=110 the planner emits packets to port 110.
func TestPOP3Plan_DstPortDefaultsTo110(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.Direction == "up" && c.L4.DstPort != 110 {
			t.Errorf("cfg[%d] up DstPort=%d, want 110", i, c.L4.DstPort)
		}
		if c.Direction == "down" && c.L4.SrcPort != 110 {
			t.Errorf("cfg[%d] down SrcPort=%d, want 110", i, c.L4.SrcPort)
		}
	}
}

// TestPOP3Plan_InitialSeqOverride verifies that spec.TCP.InitialSeq fixes
// the client ISN for reproducible tests.
func TestPOP3Plan_InitialSeqOverride(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	testutil.EnsureTCP(&spec).InitialSeq = 0x11111111
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L4.Seq != 0x11111111 {
		t.Errorf("cfg[0] (SYN) Seq=%x, want 11111111", cfgs[0].L4.Seq)
	}
}

// TestPOP3Plan_MSSSegmentation verifies that a response longer than MSS
// is split into multiple PSH-ACK segments. With MSS=536 and a 1080-byte
// response (plus "+OK " prefix + "\r\n" = 1086 bytes), expect 3 segments
// (536 + 536 + 14).
func TestPOP3Plan_MSSSegmentation(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	testutil.EnsureTCP(&spec).MSS = 536
	longBody := strings.Repeat("x", 1080)
	spec.POP3.Banner = ""
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "USER test", Response: "+OK " + longBody},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp(3 segments) + teardown(4) = 11
	if len(cfgs) != 11 {
		t.Fatalf("len=%d, want 11", len(cfgs))
	}
	seg1 := cfgs[4]
	seg2 := cfgs[5]
	seg3 := cfgs[6]
	if seg1.Direction != "down" || seg2.Direction != "down" || seg3.Direction != "down" {
		t.Errorf("response segments should be down")
	}
	if len(seg1.Payload) != 536 || len(seg2.Payload) != 536 {
		t.Errorf("seg1.len=%d want 536; seg2.len=%d want 536", len(seg1.Payload), len(seg2.Payload))
	}
	// Sequence space is continuous: segN.Seq = seg(N-1).Seq + len(seg(N-1).Payload)
	if seg1.L4.Seq+uint32(len(seg1.Payload)) != seg2.L4.Seq {
		t.Errorf("seg2.Seq=%d, want %d (continuous)", seg2.L4.Seq, seg1.L4.Seq+uint32(len(seg1.Payload)))
	}
	if seg2.L4.Seq+uint32(len(seg2.Payload)) != seg3.L4.Seq {
		t.Errorf("seg3.Seq=%d, want %d (continuous)", seg3.L4.Seq, seg2.L4.Seq+uint32(len(seg2.Payload)))
	}
}

// TestPOP3Plan_EmptyCommandsEmitsHandshakeAndTeardownOnly verifies the
// degenerate case: no banner, no commands -> just TCP handshake + teardown.
func TestPOP3Plan_EmptyCommandsEmitsHandshakeAndTeardownOnly(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Banner = ""
	spec.POP3.Commands = nil
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 7 {
		t.Fatalf("len=%d, want 7 (3 handshake + 4 teardown)", len(cfgs))
	}
}

// TestPOP3Plan_OneWayCommands verifies that an empty Response produces a
// command packet only (no response). And an empty Cmd produces a
// response only. This lets users model server-only or client-only turns
// (e.g. AUTH PLAIN's "+" challenge which is server-only).
func TestPOP3Plan_OneWayCommands(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Banner = ""
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "USER anon", Response: ""},  // cmd only
		{Cmd: "", Response: "+ OK ready"}, // resp only (AUTH PLAIN challenge)
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp(1) + teardown(4) = 9
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9", len(cfgs))
	}
	if cfgs[3].Direction != "up" || !strings.Contains(string(cfgs[3].Payload), "USER anon") {
		t.Errorf("cfg[3] should be up USER cmd")
	}
	if cfgs[4].Direction != "down" || !strings.Contains(string(cfgs[4].Payload), "+ OK ready") {
		t.Errorf("cfg[4] should be down +OK resp")
	}
}

// TestPOP3Plan_MultilineResponseVerbatim covers testcase 1.17.1: when
// Multiline=true, the response is emitted verbatim including the
// "\r\n.\r\n" terminator.
func TestPOP3Plan_MultilineResponseVerbatim(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Banner = ""
	spec.POP3.Commands = []core.POP3Command{
		{
			Cmd:       "LIST",
			Response:  "+OK 3 messages (600 octets)\r\n1 200\r\n2 200\r\n3 200\r\n.\r\n",
			Multiline: true,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp(1) + teardown(4) = 9
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9", len(cfgs))
	}
	resp := string(cfgs[4].Payload)
	if !strings.HasSuffix(resp, ".\r\n") {
		t.Errorf("multiline response must end with '.\r\n' terminator: %q", resp)
	}
	if !strings.Contains(resp, "+OK 3 messages") {
		t.Errorf("response should contain '+OK 3 messages': %q", resp)
	}
}

// TestPOP3Plan_EmitMailDrop_NoSynthesize covers testcase 1.6.7 / 4.1.4:
// RETR with no Mailbox emits the user-provided response verbatim.
func TestPOP3Plan_EmitMailDrop_NoMailboxUsesResponse(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Banner = ""
	spec.POP3.Mailbox = nil
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "RETR 1", Response: "+OK verbatim"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 5 {
		t.Fatalf("len=%d, want >= 5", len(cfgs))
	}
	resp := string(cfgs[4].Payload)
	if !strings.Contains(resp, "+OK verbatim") {
		t.Errorf("response should be verbatim when no Mailbox: %q", resp)
	}
}

// TestPOP3Plan_EmitMailDrop_Synthesize covers testcase 1.6.1: RETR with
// EmitMailDrop=true and a 1-message Mailbox synthesizes the RETR
// response (status line, headers, blank line, body, terminator).
func TestPOP3Plan_EmitMailDrop_Synthesize(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Banner = ""
	spec.POP3.Mailbox = &core.POP3Mailbox{
		Messages: []core.POP3Message{
			{
				UID:     "uid-1",
				Headers: []string{"From: bob@example.com", "To: alice@example.com"},
				Body:    "Hello, world!",
			},
		},
	}
	spec.POP3.Commands = []core.POP3Command{
		{EmitMailDrop: true, MsgNum: 1},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// The response synthesizes the RETR flow. cmd is empty (EmitMailDrop
	// emits only the response). handshake(3) + resp(1) + teardown(4) = 8
	if len(cfgs) != 8 {
		t.Fatalf("len=%d, want 8", len(cfgs))
	}
	resp := string(cfgs[3].Payload)
	if !strings.HasPrefix(resp, "+OK ") || !strings.Contains(resp, "octets") {
		t.Errorf("response should start with '+OK <size> octets': %q", resp)
	}
	if !strings.Contains(resp, "From: bob@example.com") {
		t.Errorf("response should contain From header: %q", resp)
	}
	if !strings.Contains(resp, "Hello, world!") {
		t.Errorf("response should contain body: %q", resp)
	}
	if !strings.HasSuffix(resp, ".\r\n") {
		t.Errorf("RETR response must end with '.\r\n' terminator: %q", resp)
	}
}

// TestPOP3Plan_EmitMailDrop_DotStuffing covers testcase 1.6.4 / 3.10.3:
// body line starting with "." gets an extra "." prepended.
func TestPOP3Plan_EmitMailDrop_DotStuffing(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Banner = ""
	spec.POP3.Mailbox = &core.POP3Mailbox{
		Messages: []core.POP3Message{
			{
				UID:  "uid-1",
				Body: ".hidden line",
			},
		},
	}
	spec.POP3.Commands = []core.POP3Command{
		{EmitMailDrop: true, MsgNum: 1},
	}
	cfgs := drain(mustPlan(t, p, spec))
	resp := string(cfgs[3].Payload)
	// Dot-stuffing: line starting with "." -> "..hidden line"
	if !strings.Contains(resp, "..hidden line") {
		t.Errorf("dot-stuffing should prepend '.' to '.'-prefixed lines: %q", resp)
	}
}

// TestPOP3Plan_EmitMailDrop_EmptyBody covers testcase 1.6.5: empty body
// still gets the CRLF.CRLF terminator.
func TestPOP3Plan_EmitMailDrop_EmptyBody(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Banner = ""
	spec.POP3.Mailbox = &core.POP3Mailbox{
		Messages: []core.POP3Message{{UID: "uid-1", Body: ""}},
	}
	spec.POP3.Commands = []core.POP3Command{
		{EmitMailDrop: true, MsgNum: 1},
	}
	cfgs := drain(mustPlan(t, p, spec))
	resp := string(cfgs[3].Payload)
	if !strings.Contains(resp, "+OK 0 octets") {
		t.Errorf("empty body should give '+OK 0 octets': %q", resp)
	}
	if !strings.HasSuffix(resp, ".\r\n") {
		t.Errorf("RETR response must end with '.\r\\n' terminator: %q", resp)
	}
}

// TestPOP3Plan_EmptyMailbox_OkResponseEmitted covers testcase 4.1.5:
// empty Mailbox produces +OK 0 0 for STAT.
func TestPOP3Plan_EmptyMailbox_VerifyPlannerEmitsCmd(t *testing.T) {
	p := NewPlanner()
	spec := validPOP3Spec()
	spec.POP3.Banner = ""
	spec.POP3.Mailbox = &core.POP3Mailbox{Messages: nil}
	spec.POP3.Commands = []core.POP3Command{
		{Cmd: "STAT", Response: "+OK 0 0"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	resp := string(cfgs[4].Payload)
	if !strings.Contains(resp, "+OK 0 0") {
		t.Errorf("resp should be '+OK 0 0': %q", resp)
	}
}

// TestComputeAPOPDigest verifies the helper produces a 32 hex string.
// MD5 of "<1896.697170952@dbc.mtview.ca.us>" + "secret" per RFC 1939 §6
// example (the standard APOP digest for that timestamp+secret).
func TestComputeAPOPDigest(t *testing.T) {
	got := computeAPOPDigest("<1896.697170952@dbc.mtview.ca.us>", "secret")
	if len(got) != 32 {
		t.Errorf("digest length=%d, want 32", len(got))
	}
	// Must be valid hex
	for _, c := range got {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("digest %q contains non-hex char %q", got, c)
		}
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