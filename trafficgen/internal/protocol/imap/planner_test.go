package imap

// Structural tests for the IMAP planner. Each test asserts observable
// PacketConfig field values, derived from the session-level dialog
// structure documented in planner.go and the RFC 9051 spec.

import (
	"context"
	"encoding/base64"
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

// validIMAPSpec returns a default IMAP flow spec used by most tests.
// Banner is empty so packet indices are predictable:
//
//	cfgs[0..2]   = TCP handshake
//	cfgs[3]      = first command (up)
//	cfgs[4]      = first response (down)
//	...
//	cfgs[n-4..n] = TCP teardown
func validIMAPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 143,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		IMAP: &core.IMAPConfig{
			Banner: "",
			Commands: []core.IMAPCommand{
				{Tag: "A001", Cmd: "LOGIN alice secret", Responses: []string{"A001 OK LOGIN completed"}},
				{Tag: "A002", Cmd: "SELECT INBOX", Responses: []string{"* 1 EXISTS", "A002 OK SELECT completed"}},
				{Tag: "A003", Cmd: "LOGOUT", Responses: []string{"* BYE IMAP4rev2 Server logging out", "A003 OK LOGOUT completed"}},
			},
		},
	}
}

// validIMAPSpecWithBanner returns a default spec with the banner set.
// Used by banner-specific tests.
func validIMAPSpecWithBanner() core.FlowSpec {
	spec := validIMAPSpec()
	spec.IMAP.Banner = "* OK [CAPABILITY IMAP4rev2 STARTTLS AUTH=PLAIN] imap.example.com ready"
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

func TestIMAPValidate_ValidIPs(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestIMAPValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.SrcIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "imap:") || !strings.Contains(err.Error(), "SrcIP") {
		t.Errorf("err=%v, want contains 'imap:' and 'SrcIP'", err)
	}
}

func TestIMAPValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.DstIP = "not-an-ip"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "DstIP") {
		t.Errorf("err=%v, want contains 'DstIP'", err)
	}
}

func TestIMAPValidate_MSSTooSmall(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	testutil.EnsureTCP(&spec).MSS = 100 // below MinMSS=536
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MSS") {
		t.Errorf("err=%v, want contains 'MSS'", err)
	}
}

func TestIMAPValidate_MSSZeroOK(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	testutil.EnsureTCP(&spec).MSS = 0
	if err := p.Validate(spec); err != nil {
		t.Errorf("MSS=0 should be accepted: %v", err)
	}
}

func TestIMAPValidate_NilIMAPConfig(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("nil IMAP config should be accepted: %v", err)
	}
}

// TestIMAPValidate_CRLFInjectionRejected covers CRLF injection protection:
// a Cmd with embedded CRLF must be rejected at Validate.
func TestIMAPValidate_CRLFInjectionRejected(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands[0].Cmd = "LOGIN alice\r\nA002 NOOP"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "CRLF") {
		t.Errorf("err=%v, want contains 'CRLF'", err)
	}
}

// TestIMAPValidate_ResponseWithCRLFRejected: Responses entries with CRLF
// are rejected (the user must split multi-line responses into multiple
// entries or use LiteralBody).
func TestIMAPValidate_ResponseWithCRLFRejected(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands[0].Responses = []string{"A001 OK\r\nextra"}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "CRLF") {
		t.Errorf("err=%v, want contains 'CRLF'", err)
	}
}

// TestIMAPValidate_TagTooLong covers the RFC 9051 §2.2.1 tag length cap.
func TestIMAPValidate_TagTooLong(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands[0].Tag = strings.Repeat("a", MaxTagLen+1)
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Tag") {
		t.Errorf("err=%v, want contains 'Tag'", err)
	}
}

// TestIMAPValidate_TagWithSpace: a tag containing a space is rejected
// per RFC 9051 §2.2.1 (tag is atom-char + tag-char; SP is a separator).
func TestIMAPValidate_TagWithSpace(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands[0].Tag = "A 001"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "Tag") {
		t.Errorf("err=%v, want contains 'Tag'", err)
	}
}

// TestIMAPValidate_LiteralBodyAndB64Mutex: LiteralBody and LiteralBodyB64
// are mutually exclusive.
func TestIMAPValidate_LiteralBodyAndB64Mutex(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands[0].LiteralBody = "hello"
	spec.IMAP.Commands[0].LiteralBodyB64 = base64.StdEncoding.EncodeToString([]byte("hello"))
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("err=%v, want contains 'mutually exclusive'", err)
	}
}

// TestIMAPValidate_LiteralBodyB64Invalid: invalid base64 is rejected.
func TestIMAPValidate_LiteralBodyB64Invalid(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands[0].LiteralBodyB64 = "!!!not-base64!!!"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Errorf("err=%v, want contains 'decode'", err)
	}
}

// TestIMAPValidate_EmitIDLEWithoutIDLEConfig: EmitIDLE=true but IDLE=nil
// is rejected.
func TestIMAPValidate_EmitIDLEWithoutIDLEConfig(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands[0].EmitIDLE = true
	spec.IMAP.IDLE = nil
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "IDLE") {
		t.Errorf("err=%v, want contains 'IDLE'", err)
	}
}

// TestIMAPValidate_CancelAfterExceedsResponses: CancelAfterResponses > len(Responses)
// is rejected (cancel would never fire).
func TestIMAPValidate_CancelAfterExceedsResponses(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands[0].CancelAfterResponses = 99
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "CancelAfterResponses") {
		t.Errorf("err=%v, want contains 'CancelAfterResponses'", err)
	}
}

// TestIMAPValidate_ServerTimeoutBehaviorInvalid: an unknown
// ServerTimeoutBehavior value is rejected.
func TestIMAPValidate_ServerTimeoutBehaviorInvalid(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.IDLE = &core.IMAPIDLE{ServerTimeoutBehavior: "bogus"}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "ServerTimeoutBehavior") {
		t.Errorf("err=%v, want contains 'ServerTimeoutBehavior'", err)
	}
}

// TestIMAPValidate_AllowUTF8MailboxFalseRejectsNonASCII: when
// AllowUTF8Mailbox=false, non-ASCII bytes in Cmd are rejected.
func TestIMAPValidate_AllowUTF8MailboxFalseRejectsNonASCII(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.AllowUTF8Mailbox = false
	spec.IMAP.Commands[0].Cmd = "SELECT 收发室"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "non-ASCII") {
		t.Errorf("err=%v, want contains 'non-ASCII'", err)
	}
}

// TestIMAPValidate_AllowUTF8MailboxTrueAcceptsNonASCII: when
// AllowUTF8Mailbox=true, non-ASCII bytes in Cmd are accepted.
func TestIMAPValidate_AllowUTF8MailboxTrueAcceptsNonASCII(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.AllowUTF8Mailbox = true
	spec.IMAP.Commands[0].Cmd = "SELECT 收发室"
	if err := p.Validate(spec); err != nil {
		t.Errorf("AllowUTF8Mailbox=true should accept non-ASCII: %v", err)
	}
}

// --- Plan: structure ---

// TestIMAPPlan_Handshake verifies the first 3 packets are SYN, SYN-ACK,
// ACK with correct directions, flags, and TCP options (mirrors
// FTP/POP3).
func TestIMAPPlan_Handshake(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validIMAPSpec()))
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

// TestIMAPPlan_Teardown verifies the last 4 packets are FIN-ACK, ACK,
// FIN-ACK, ACK in the standard order.
func TestIMAPPlan_Teardown(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validIMAPSpec()))
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

// TestIMAPPlan_BannerEmitted verifies that when Banner is non-empty,
// the first payload packet after the handshake is a down PSH-ACK
// containing the banner text + CRLF.
func TestIMAPPlan_BannerEmitted(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validIMAPSpecWithBanner()))
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4", len(cfgs))
	}
	bannerPkt := cfgs[3]
	if bannerPkt.Direction != "down" || bannerPkt.L4.Flags != 0x18 {
		t.Fatalf("cfg[3]: dir=%s flags=%x, want down/PSH-ACK", bannerPkt.Direction, bannerPkt.L4.Flags)
	}
	if !strings.Contains(string(bannerPkt.Payload), "IMAP4rev2") {
		t.Errorf("cfg[3] payload=%q, want contains 'IMAP4rev2'", bannerPkt.Payload)
	}
	if !strings.HasSuffix(string(bannerPkt.Payload), "\r\n") {
		t.Errorf("cfg[3] payload should end with CRLF (RFC 9051 §2.2)")
	}
}

// TestIMAPPlan_NoBannerSkipped verifies that an empty Banner emits no
// payload packet between the handshake and the first command.
func TestIMAPPlan_NoBannerSkipped(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4", len(cfgs))
	}
	if cfgs[3].Direction != "up" {
		t.Errorf("cfg[3]: dir=%s, want up (first command)", cfgs[3].Direction)
	}
	if !strings.Contains(string(cfgs[3].Payload), "LOGIN alice") {
		t.Errorf("cfg[3] payload=%q, want contains 'LOGIN alice'", cfgs[3].Payload)
	}
}

// TestIMAPPlan_CommandResponsePairs verifies that each IMAPCommand
// produces a (command up) + (responses down) pair, in order, with the
// correct text. With 3 commands (1 cmd up + 1 resp down + 1 cmd up +
// 2 resp down + 1 cmd up + 2 resp down) = 8 data packets.
func TestIMAPPlan_CommandResponsePairs(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validIMAPSpec()))
	// handshake(3) + 3 cmds + 5 responses + teardown(4) = 15
	if len(cfgs) != 15 {
		t.Fatalf("len=%d, want 15 (3 + 3 + 5 + 4)", len(cfgs))
	}
	// cfg[3] = LOGIN cmd up
	if cfgs[3].Direction != "up" || !strings.Contains(string(cfgs[3].Payload), "A001 LOGIN alice secret") {
		t.Errorf("cfg[3]: dir=%s payload=%q, want up/A001 LOGIN", cfgs[3].Direction, cfgs[3].Payload)
	}
	// cfg[4] = OK LOGIN resp down
	if cfgs[4].Direction != "down" || !strings.Contains(string(cfgs[4].Payload), "A001 OK LOGIN") {
		t.Errorf("cfg[4]: dir=%s payload=%q, want down/A001 OK", cfgs[4].Direction, cfgs[4].Payload)
	}
	// cfg[5] = SELECT cmd up
	if cfgs[5].Direction != "up" || !strings.Contains(string(cfgs[5].Payload), "A002 SELECT INBOX") {
		t.Errorf("cfg[5]: dir=%s payload=%q, want up/A002 SELECT", cfgs[5].Direction, cfgs[5].Payload)
	}
	// cfg[6] = * 1 EXISTS down
	if cfgs[6].Direction != "down" || !strings.Contains(string(cfgs[6].Payload), "* 1 EXISTS") {
		t.Errorf("cfg[6]: dir=%s payload=%q, want down/* 1 EXISTS", cfgs[6].Direction, cfgs[6].Payload)
	}
	// cfg[7] = A002 OK SELECT down
	if cfgs[7].Direction != "down" || !strings.Contains(string(cfgs[7].Payload), "A002 OK SELECT") {
		t.Errorf("cfg[7]: dir=%s payload=%q, want down/A002 OK", cfgs[7].Direction, cfgs[7].Payload)
	}
}

// TestIMAPPlan_CRLFTerminator verifies every IMAP command and single-line
// response payload ends with CRLF per RFC 9051 §2.2.1.
func TestIMAPPlan_CRLFTerminator(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validIMAPSpec()))
	for i, c := range cfgs {
		if c.L4.Flags != 0x18 {
			continue
		}
		if len(c.Payload) == 0 {
			continue
		}
		// Literal body segments (which are PSH-ACK but contain only
		// raw bytes, not CRLF-terminated) are exempt - they're
		// payloads inside a FETCH response. We detect them by checking
		// if the payload is just binary bytes without any printable
		// IMAP syntax. For the structural test we only enforce CRLF
		// on payloads that look like IMAP lines (start with a tag,
		// "*", or "+").
		s := string(c.Payload)
		if strings.HasPrefix(s, "*") || strings.HasPrefix(s, "+") ||
			(len(s) > 0 && (s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z') || (s[0] >= '0' && s[0] <= '9')) {
			if !strings.HasSuffix(s, "\r\n") {
				t.Errorf("cfg[%d] payload must end with CRLF: %q", i, c.Payload)
			}
		}
	}
}

// TestIMAPPlan_FlowIDShared verifies all packets share one flow ID
// (the session-level invariant: one IMAP connection = one flow).
func TestIMAPPlan_FlowIDShared(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validIMAPSpec()))
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

// TestIMAPPlan_IPIDIncrementsPerPacket verifies that every packet has a
// distinct IP ID (no cross-packet ID reuse within the flow).
func TestIMAPPlan_IPIDIncrementsPerPacket(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validIMAPSpec()))
	seen := make(map[uint16]bool)
	for i, c := range cfgs {
		if seen[c.L3.IPID] {
			t.Errorf("cfg[%d] IPID=%d duplicated", i, c.L3.IPID)
		}
		seen[c.L3.IPID] = true
	}
}

// TestIMAPPlan_SequenceContinuity verifies that the next command's ACK
// field covers all prior response bytes - the signature of a continuous
// sequence space per direction within one flow.
func TestIMAPPlan_SequenceContinuity(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validIMAPSpec()))
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

// TestIMAPPlan_DstPortDefaultsTo143 verifies that the strategy_convert
// dst_port default for IMAP is 143 when the user did not specify one.
// The actual defaulting is in core.strategy_convert; here we verify that
// when DstPort=143 the planner emits packets to port 143.
func TestIMAPPlan_DstPortDefaultsTo143(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.Direction == "up" && c.L4.DstPort != 143 {
			t.Errorf("cfg[%d] up DstPort=%d, want 143", i, c.L4.DstPort)
		}
		if c.Direction == "down" && c.L4.SrcPort != 143 {
			t.Errorf("cfg[%d] down SrcPort=%d, want 143", i, c.L4.SrcPort)
		}
	}
}

// TestIMAPPlan_InitialSeqOverride verifies that spec.TCP.InitialSeq fixes
// the client ISN for reproducible tests.
func TestIMAPPlan_InitialSeqOverride(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	testutil.EnsureTCP(&spec).InitialSeq = 0x11111111
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L4.Seq != 0x11111111 {
		t.Errorf("cfg[0] (SYN) Seq=%x, want 11111111", cfgs[0].L4.Seq)
	}
}

// TestIMAPPlan_MSSSegmentation verifies that a response longer than MSS
// is split into multiple PSH-ACK segments. With MSS=536 and a 1080-byte
// response (plus "+OK " prefix + "\r\n" = 1086 bytes), expect 3 segments
// (536 + 536 + 14).
func TestIMAPPlan_MSSSegmentation(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	testutil.EnsureTCP(&spec).MSS = 536
	longBody := strings.Repeat("x", 1080)
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "NOOP", Responses: []string{"* OK " + longBody}},
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

// TestIMAPPlan_EmptyCommandsEmitsHandshakeAndTeardownOnly verifies the
// degenerate case: no banner, no commands -> just TCP handshake + teardown.
func TestIMAPPlan_EmptyCommandsEmitsHandshakeAndTeardownOnly(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = nil
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 7 {
		t.Fatalf("len=%d, want 7 (3 handshake + 4 teardown)", len(cfgs))
	}
}

// TestIMAPPlan_OneWayCommands verifies that an empty Responses slice
// produces a command packet only (no response). And an empty Cmd
// produces responses only. This lets users model server-only or
// client-only turns (e.g. AUTH PLAIN's "+" challenge which is server-only).
func TestIMAPPlan_OneWayCommands(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "NOOP", Responses: nil}, // cmd only
		{Tag: "A002", Cmd: "", Responses: []string{"+ "}}, // resp only (AUTH challenge)
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp(1) + teardown(4) = 9
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9", len(cfgs))
	}
	if cfgs[3].Direction != "up" || !strings.Contains(string(cfgs[3].Payload), "A001 NOOP") {
		t.Errorf("cfg[3] should be up A001 NOOP cmd")
	}
	if cfgs[4].Direction != "down" || !strings.Contains(string(cfgs[4].Payload), "+ ") {
		t.Errorf("cfg[4] should be down + resp")
	}
}

// TestIMAPPlan_MultiResponsePerCommand verifies a single command can
// produce multiple server responses (untagged + tagged).
func TestIMAPPlan_MultiResponsePerCommand(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag: "A001",
			Cmd: "SELECT INBOX",
			Responses: []string{
				"* 5 EXISTS",
				"* 2 RECENT",
				"* OK [UIDVALIDITY 1234567890] Uidvalidity",
				"* OK [UIDNEXT 6] Predicted next UID",
				"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
				"A001 OK [READ-WRITE] SELECT completed",
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + 6 responses + teardown(4) = 14
	if len(cfgs) != 14 {
		t.Fatalf("len=%d, want 14", len(cfgs))
	}
	// All 6 responses should be down PSH-ACK.
	for i := 4; i <= 9; i++ {
		if cfgs[i].Direction != "down" || cfgs[i].L4.Flags != 0x18 {
			t.Errorf("cfg[%d] should be down/PSH-ACK, got %s/%x", i, cfgs[i].Direction, cfgs[i].L4.Flags)
		}
	}
	if !strings.Contains(string(cfgs[4].Payload), "* 5 EXISTS") {
		t.Errorf("cfg[4] should be '* 5 EXISTS': %q", cfgs[4].Payload)
	}
	if !strings.Contains(string(cfgs[9].Payload), "A001 OK [READ-WRITE]") {
		t.Errorf("cfg[9] should be 'A001 OK [READ-WRITE]': %q", cfgs[9].Payload)
	}
}

// TestIMAPPlan_AutoTagIncrement verifies that an empty Tag auto-
// increments to A001, A002, A003, ... per RFC 9051 §2.2.1.
func TestIMAPPlan_AutoTagIncrement(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Cmd: "NOOP", Responses: []string{"A001 OK NOOP completed"}},
		{Cmd: "NOOP", Responses: []string{"A002 OK NOOP completed"}},
		{Cmd: "NOOP", Responses: []string{"A003 OK NOOP completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + 3 cmds + 3 resps + teardown(4) = 13
	if len(cfgs) != 13 {
		t.Fatalf("len=%d, want 13", len(cfgs))
	}
	if !strings.HasPrefix(string(cfgs[3].Payload), "A001 NOOP") {
		t.Errorf("cfg[3] should start with 'A001 NOOP': %q", cfgs[3].Payload)
	}
	if !strings.HasPrefix(string(cfgs[5].Payload), "A002 NOOP") {
		t.Errorf("cfg[5] should start with 'A002 NOOP': %q", cfgs[5].Payload)
	}
	if !strings.HasPrefix(string(cfgs[7].Payload), "A003 NOOP") {
		t.Errorf("cfg[7] should start with 'A003 NOOP': %q", cfgs[7].Payload)
	}
}

// TestIMAPPlan_TagMismatchReplayed verifies that the planner does NOT
// validate tag matching between command and tagged response - it just
// replays the user's dialog verbatim (edge case C-IMAP-1.4).
func TestIMAPPlan_TagMismatchReplayed(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "NOOP", Responses: []string{"B002 OK NOOP completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp(1) + teardown(4) = 9
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9", len(cfgs))
	}
	if !strings.Contains(string(cfgs[3].Payload), "A001 NOOP") {
		t.Errorf("cfg[3] should contain 'A001 NOOP': %q", cfgs[3].Payload)
	}
	if !strings.Contains(string(cfgs[4].Payload), "B002 OK NOOP") {
		t.Errorf("cfg[4] should contain 'B002 OK NOOP' (mismatched tag replayed): %q", cfgs[4].Payload)
	}
}

// TestIMAPPlan_PipelinedCommands verifies the PipelinedCommands flag
// (edge case C-IMAP-1.5): all commands emitted first, then all responses.
func TestIMAPPlan_PipelinedCommands(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.PipelinedCommands = true
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "LOGIN alice secret", Responses: []string{"A001 OK LOGIN completed"}},
		{Tag: "A002", Cmd: "SELECT INBOX", Responses: []string{"* 1 EXISTS", "A002 OK SELECT completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + 2 cmds up + 3 resps down + teardown(4) = 12
	if len(cfgs) != 12 {
		t.Fatalf("len=%d, want 12 (pipelined: 3 + 2 + 3 + 4)", len(cfgs))
	}
	// cfg[3] = A001 LOGIN up
	if cfgs[3].Direction != "up" || !strings.Contains(string(cfgs[3].Payload), "A001 LOGIN") {
		t.Errorf("cfg[3]: dir=%s payload=%q, want up/A001 LOGIN", cfgs[3].Direction, cfgs[3].Payload)
	}
	// cfg[4] = A002 SELECT up
	if cfgs[4].Direction != "up" || !strings.Contains(string(cfgs[4].Payload), "A002 SELECT") {
		t.Errorf("cfg[4]: dir=%s payload=%q, want up/A002 SELECT (pipelined)", cfgs[4].Direction, cfgs[4].Payload)
	}
	// cfg[5] = A001 OK LOGIN down
	if cfgs[5].Direction != "down" || !strings.Contains(string(cfgs[5].Payload), "A001 OK LOGIN") {
		t.Errorf("cfg[5]: dir=%s payload=%q, want down/A001 OK LOGIN (first response)", cfgs[5].Direction, cfgs[5].Payload)
	}
	// cfg[6] = * 1 EXISTS down
	if cfgs[6].Direction != "down" || !strings.Contains(string(cfgs[6].Payload), "* 1 EXISTS") {
		t.Errorf("cfg[6]: dir=%s payload=%q, want down/* 1 EXISTS", cfgs[6].Direction, cfgs[6].Payload)
	}
	// cfg[7] = A002 OK SELECT down
	if cfgs[7].Direction != "down" || !strings.Contains(string(cfgs[7].Payload), "A002 OK SELECT") {
		t.Errorf("cfg[7]: dir=%s payload=%q, want down/A002 OK SELECT", cfgs[7].Direction, cfgs[7].Payload)
	}
}

// TestIMAPPlan_NonPipelinedDefault verifies the default (non-pipelined)
// behavior: each command is followed by its responses before the next
// command.
func TestIMAPPlan_NonPipelinedDefault(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.PipelinedCommands = false
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "LOGIN alice secret", Responses: []string{"A001 OK LOGIN completed"}},
		{Tag: "A002", Cmd: "SELECT INBOX", Responses: []string{"* 1 EXISTS", "A002 OK SELECT completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd1(1) + resp1(1) + cmd2(1) + resp2(2) + teardown(4) = 12
	if len(cfgs) != 12 {
		t.Fatalf("len=%d, want 12 (non-pipelined: 3 + 1+1 + 1+2 + 4)", len(cfgs))
	}
	// cfg[3] = A001 LOGIN up
	if cfgs[3].Direction != "up" || !strings.Contains(string(cfgs[3].Payload), "A001 LOGIN") {
		t.Errorf("cfg[3]: dir=%s payload=%q, want up/A001 LOGIN", cfgs[3].Direction, cfgs[3].Payload)
	}
	// cfg[4] = A001 OK LOGIN down (immediately after cmd)
	if cfgs[4].Direction != "down" || !strings.Contains(string(cfgs[4].Payload), "A001 OK LOGIN") {
		t.Errorf("cfg[4]: dir=%s payload=%q, want down/A001 OK LOGIN", cfgs[4].Direction, cfgs[4].Payload)
	}
	// cfg[5] = A002 SELECT up (next command, not pipelined)
	if cfgs[5].Direction != "up" || !strings.Contains(string(cfgs[5].Payload), "A002 SELECT") {
		t.Errorf("cfg[5]: dir=%s payload=%q, want up/A002 SELECT", cfgs[5].Direction, cfgs[5].Payload)
	}
}

// TestIMAPPlan_LiteralPlaceholder verifies that a response containing
// "{N}" is replaced with the actual literal body length and the literal
// body is emitted as a separate PSH-ACK segment.
func TestIMAPPlan_LiteralPlaceholder(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:         "A001",
			Cmd:         "FETCH 1 BODY[]",
			Responses:   []string{"* 1 FETCH (BODY[] {13})", "A001 OK FETCH completed"},
			LiteralBody: "Hello, world!",
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp header(1) + literal body(1) + CRLF(1) + OK(1) + teardown(4) = 12
	if len(cfgs) != 12 {
		t.Fatalf("len=%d, want 12", len(cfgs))
	}
	// cfg[4] = "* 1 FETCH (BODY[] {13})\r\n"
	if cfgs[4].Direction != "down" {
		t.Errorf("cfg[4] should be down")
	}
	if !strings.Contains(string(cfgs[4].Payload), "{13}") {
		t.Errorf("cfg[4] should contain '{13}': %q", cfgs[4].Payload)
	}
	if !strings.HasSuffix(string(cfgs[4].Payload), "\r\n") {
		t.Errorf("cfg[4] should end with CRLF: %q", cfgs[4].Payload)
	}
	// cfg[5] = literal body bytes
	if cfgs[5].Direction != "down" {
		t.Errorf("cfg[5] should be down (literal body)")
	}
	if string(cfgs[5].Payload) != "Hello, world!" {
		t.Errorf("cfg[5] payload=%q, want 'Hello, world!'", cfgs[5].Payload)
	}
	// cfg[6] = trailing CRLF
	if string(cfgs[6].Payload) != "\r\n" {
		t.Errorf("cfg[6] payload=%q, want '\\r\\n' (trailing CRLF)", cfgs[6].Payload)
	}
	// cfg[7] = A001 OK FETCH completed
	if cfgs[7].Direction != "down" || !strings.Contains(string(cfgs[7].Payload), "A001 OK FETCH") {
		t.Errorf("cfg[7]: dir=%s payload=%q, want down/A001 OK FETCH", cfgs[7].Direction, cfgs[7].Payload)
	}
}

// TestIMAPPlan_LiteralZeroBytes verifies the C-IMAP-1.6 edge case: a
// zero-length literal produces "{0}\r\n\r\n" (no body segment).
func TestIMAPPlan_LiteralZeroBytes(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:         "A001",
			Cmd:         "FETCH 1 BODY[]",
			Responses:   []string{"* 1 FETCH (BODY[] {0})", "A001 OK FETCH completed"},
			LiteralBody: "",
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp header(1) + [no body] + CRLF(1) + OK(1) + teardown(4) = 11
	if len(cfgs) != 11 {
		t.Fatalf("len=%d, want 11 (zero-length literal produces no body segment)", len(cfgs))
	}
	if !strings.Contains(string(cfgs[4].Payload), "{0}") {
		t.Errorf("cfg[4] should contain '{0}': %q", cfgs[4].Payload)
	}
}

// TestIMAPPlan_LiteralBodyB64 verifies that LiteralBodyB64 is decoded
// and used as the literal body.
func TestIMAPPlan_LiteralBodyB64(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	body := "From: alice@example.com\r\nSubject: Test\r\n\r\nHello"
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:            "A001",
			Cmd:            "FETCH 1 BODY[]",
			Responses:      []string{"* 1 FETCH (BODY[] {" + itoa(len(body)) + "})", "A001 OK FETCH completed"},
			LiteralBodyB64: base64.StdEncoding.EncodeToString([]byte(body)),
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp header(1) + literal body(1) + CRLF(1) + OK(1) + teardown(4) = 12
	if len(cfgs) != 12 {
		t.Fatalf("len=%d, want 12", len(cfgs))
	}
	if string(cfgs[5].Payload) != body {
		t.Errorf("cfg[5] payload=%q, want %q (decoded base64)", cfgs[5].Payload, body)
	}
}

// TestIMAPPlan_LiteralBodyLargeMSSSegmentation verifies that a large
// literal body is segmented by MSS (edge case C-IMAP-1.1: all segments
// are PSH-ACK).
func TestIMAPPlan_LiteralBodyLargeMSSSegmentation(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	testutil.EnsureTCP(&spec).MSS = 536
	// 1000-byte literal body -> 2 segments (536 + 464)
	body := strings.Repeat("x", 1000)
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:         "A001",
			Cmd:         "FETCH 1 BODY[]",
			Responses:   []string{"* 1 FETCH (BODY[] {1000})", "A001 OK FETCH completed"},
			LiteralBody: body,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp header(1) + literal body(2 segs) + CRLF(1) + OK(1) + teardown(4) = 13
	if len(cfgs) != 13 {
		t.Fatalf("len=%d, want 13 (MSS-segmented literal body)", len(cfgs))
	}
	// cfg[5] and cfg[6] are the literal body segments - both PSH-ACK.
	if cfgs[5].L4.Flags != 0x18 || cfgs[6].L4.Flags != 0x18 {
		t.Errorf("literal body segments should be PSH-ACK (0x18), got %x and %x", cfgs[5].L4.Flags, cfgs[6].L4.Flags)
	}
	// First segment is 536 bytes.
	if len(cfgs[5].Payload) != 536 {
		t.Errorf("cfg[5] payload len=%d, want 536", len(cfgs[5].Payload))
	}
	// Second segment is 464 bytes.
	if len(cfgs[6].Payload) != 464 {
		t.Errorf("cfg[6] payload len=%d, want 464", len(cfgs[6].Payload))
	}
}

// TestIMAPPlan_UIDCacheInvalidation verifies the C-IMAP-1.9 edge case:
// when UIDCacheInvalidation=true, the planner synthesizes the
// "* OK [HIGHESTMODSEQ 1] cache invalidated" response after the command's
// normal responses.
func TestIMAPPlan_UIDCacheInvalidation(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:                   "A001",
			Cmd:                   "SELECT INBOX",
			Responses:             []string{"* OK [UIDVALIDITY 5678]", "* 1 EXISTS", "A001 OK SELECT completed"},
			UIDCacheInvalidation:  true,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + 3 resps + 1 invalidation resp + teardown(4) = 12
	if len(cfgs) != 12 {
		t.Fatalf("len=%d, want 12 (UIDCacheInvalidation adds 1 resp)", len(cfgs))
	}
	// cfg[7] should be the invalidation response.
	if cfgs[7].Direction != "down" {
		t.Errorf("cfg[7] should be down")
	}
	if !strings.Contains(string(cfgs[7].Payload), "HIGHESTMODSEQ 1") {
		t.Errorf("cfg[7] should contain 'HIGHESTMODSEQ 1': %q", cfgs[7].Payload)
	}
	if !strings.Contains(string(cfgs[7].Payload), "cache invalidated") {
		t.Errorf("cfg[7] should contain 'cache invalidated': %q", cfgs[7].Payload)
	}
}

// TestIMAPPlan_CancelAfterResponses verifies the C-IMAP-1.3 edge case:
// after the CancelAfterResponses-th response, the client sends "*\r\n"
// to cancel the in-progress AUTHENTICATE.
func TestIMAPPlan_CancelAfterResponses(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:                 "A001",
			Cmd:                 "AUTHENTICATE PLAIN",
			Responses:           []string{"+ ", "A001 NO AUTHENTICATE cancelled"},
			CancelAfterResponses: 1,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp1(1) + cancel(1) + resp2(1) + teardown(4) = 11
	if len(cfgs) != 11 {
		t.Fatalf("len=%d, want 11 (cancel adds 1 up packet)", len(cfgs))
	}
	// cfg[3] = A001 AUTHENTICATE PLAIN up
	if !strings.Contains(string(cfgs[3].Payload), "AUTHENTICATE PLAIN") {
		t.Errorf("cfg[3] should contain 'AUTHENTICATE PLAIN': %q", cfgs[3].Payload)
	}
	// cfg[4] = "+ " down
	if !strings.HasPrefix(string(cfgs[4].Payload), "+ ") {
		t.Errorf("cfg[4] should start with '+ ': %q", cfgs[4].Payload)
	}
	// cfg[5] = "*\r\n" up (cancel)
	if cfgs[5].Direction != "up" || string(cfgs[5].Payload) != "*\r\n" {
		t.Errorf("cfg[5]: dir=%s payload=%q, want up/'*\\r\\n' (cancel)", cfgs[5].Direction, cfgs[5].Payload)
	}
	// cfg[6] = A001 NO AUTHENTICATE cancelled down
	if cfgs[6].Direction != "down" || !strings.Contains(string(cfgs[6].Payload), "A001 NO AUTHENTICATE cancelled") {
		t.Errorf("cfg[6]: dir=%s payload=%q, want down/A001 NO AUTHENTICATE cancelled", cfgs[6].Direction, cfgs[6].Payload)
	}
}

// TestIMAPPlan_IDLEBasic verifies the IDLE mode (RFC 2177): the planner
// emits IDLE cmd, "+ idling" continuation, pushes, DONE, done response.
func TestIMAPPlan_IDLEBasic(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.IDLE = &core.IMAPIDLE{
		PushResponses: []string{"* 2 EXISTS", "* 1 EXPUNGE"},
		DoneResponse:  "A001 OK IDLE terminated",
	}
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:      "A001",
			Cmd:      "IDLE",
			Responses: []string{"+ idling"},
			EmitIDLE: true,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + IDLE cmd(1) + "+ idling" resp(1) + [EmitIDLE:
	//   IDLE cmd(1) + "+ idling"(1) + 2 pushes(2) + DONE(1) + done resp(1)] + teardown(4)
	// = 3 + 1 + 1 + 6 + 4 = 15
	// Note: the user-provided Responses ("+ idling") is emitted first
	// (as the cmd's normal response), THEN the EmitIDLE sequence
	// (which re-emits IDLE + "+ idling" + pushes + DONE + done resp).
	if len(cfgs) != 15 {
		t.Fatalf("len=%d, want 15 (IDLE basic)", len(cfgs))
	}
}

// TestIMAPPlan_IDLEServerTimeoutCloseAfterIdle verifies the
// C-IMAP-1.2 edge case: ServerTimeoutBehavior="close_after_idle"
// emits "* BYE IDLE timeout" after the done response.
func TestIMAPPlan_IDLEServerTimeoutCloseAfterIdle(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.IDLE = &core.IMAPIDLE{
		PushResponses:         nil,
		DoneResponse:          "A001 OK IDLE terminated",
		ServerTimeoutBehavior: "close_after_idle",
	}
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:      "A001",
			Cmd:      "IDLE",
			Responses: []string{"+ idling"},
			EmitIDLE: true,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find the BYE packet.
	var byePkt *core.PacketConfig
	for i := range cfgs {
		if strings.Contains(string(cfgs[i].Payload), "BYE IDLE timeout") {
			byePkt = &cfgs[i]
			break
		}
	}
	if byePkt == nil {
		t.Fatalf("no '* BYE IDLE timeout' packet found")
	}
	if byePkt.Direction != "down" {
		t.Errorf("BYE packet should be down, got %s", byePkt.Direction)
	}
}

// TestIMAPPlan_IDLEServerTimeoutNone verifies that
// ServerTimeoutBehavior="none" does NOT emit the BYE packet.
func TestIMAPPlan_IDLEServerTimeoutNone(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.IDLE = &core.IMAPIDLE{
		PushResponses:         nil,
		DoneResponse:          "A001 OK IDLE terminated",
		ServerTimeoutBehavior: "none",
	}
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:      "A001",
			Cmd:      "IDLE",
			Responses: []string{"+ idling"},
			EmitIDLE: true,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if strings.Contains(string(c.Payload), "BYE IDLE timeout") {
			t.Errorf("cfg[%d]: ServerTimeoutBehavior='none' should NOT emit BYE: %q", i, c.Payload)
		}
	}
}

// TestIMAPPlan_AllowUTF8MailboxTrue verifies that when
// AllowUTF8Mailbox=true, non-ASCII bytes in Cmd are emitted verbatim.
func TestIMAPPlan_AllowUTF8MailboxTrue(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.AllowUTF8Mailbox = true
	spec.IMAP.Commands = []core.IMAPCommand{
		{Tag: "A001", Cmd: "SELECT 收发室", Responses: []string{"A001 OK SELECT completed"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// cfg[3] = "A001 SELECT 收发室\r\n" up
	if cfgs[3].Direction != "up" {
		t.Errorf("cfg[3] should be up")
	}
	payload := string(cfgs[3].Payload)
	if !strings.HasPrefix(payload, "A001 SELECT ") {
		t.Errorf("cfg[3] should start with 'A001 SELECT ': %q", payload)
	}
	if !strings.Contains(payload, "收发室") {
		t.Errorf("cfg[3] should contain '收发室' (UTF-8 verbatim): %q", payload)
	}
	if !strings.HasSuffix(payload, "\r\n") {
		t.Errorf("cfg[3] should end with CRLF: %q", payload)
	}
}

// TestIMAPPlan_CommandWithLiteralPlaceholder verifies that a client
// command containing "{N}" (e.g. APPEND INBOX {100}) followed by a
// LiteralBody emits the literal body as additional PSH-ACK segments up.
func TestIMAPPlan_CommandWithLiteralPlaceholder(t *testing.T) {
	p := NewPlanner()
	spec := validIMAPSpec()
	spec.IMAP.Commands = []core.IMAPCommand{
		{
			Tag:         "A001",
			Cmd:         "APPEND INBOX {100}",
			Responses:   []string{"+ Ready for literal data", "* 1 EXISTS", "A001 OK APPEND completed"},
			LiteralBody: strings.Repeat("x", 100),
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + literal body up(1) + 3 resps down(3) + teardown(4) = 12
	if len(cfgs) != 12 {
		t.Fatalf("len=%d, want 12 (APPEND with literal)", len(cfgs))
	}
	// cfg[3] = "A001 APPEND INBOX {100}\r\n" up
	if !strings.Contains(string(cfgs[3].Payload), "APPEND INBOX {100}") {
		t.Errorf("cfg[3] should contain 'APPEND INBOX {100}': %q", cfgs[3].Payload)
	}
	// cfg[4] = literal body up (100 bytes of 'x')
	if cfgs[4].Direction != "up" {
		t.Errorf("cfg[4] should be up (literal body)")
	}
	if len(cfgs[4].Payload) != 100 {
		t.Errorf("cfg[4] payload len=%d, want 100", len(cfgs[4].Payload))
	}
	if string(cfgs[4].Payload) != strings.Repeat("x", 100) {
		t.Errorf("cfg[4] payload should be 100 'x' bytes")
	}
}

// TestHasLiteralPlaceholder verifies the helper detects {N} placeholders.
func TestHasLiteralPlaceholder(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"* 1 FETCH (BODY[] {13})", true},
		{"APPEND INBOX {100}", true},
		{"{0}", true},
		{"{999999999999}", true},
		{"A001 NOOP", false},
		{"* OK [UIDVALIDITY 1234]", false},
		{"{} ", false},            // empty digits
		{"{abc}", false},          // non-digits
		{"{12", false},            // no closing brace
		{"", false},               // empty
		{"* 1 FETCH (BODY[] {13}) extra {45}", true}, // first placeholder
	}
	for _, c := range cases {
		got := hasLiteralPlaceholder(c.s)
		if got != c.want {
			t.Errorf("hasLiteralPlaceholder(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

// TestReplaceLiteralPlaceholder verifies the helper replaces the first
// {N} placeholder with {<newLen>}\r\n.
func TestReplaceLiteralPlaceholder(t *testing.T) {
	cases := []struct {
		s      string
		newLen int
		want   string
	}{
		{"* 1 FETCH (BODY[] {13})", 100, "* 1 FETCH (BODY[] {100}\r\n)"},
		{"APPEND INBOX {0}", 0, "APPEND INBOX {0}\r\n"},
		{"A001 NOOP", 100, "A001 NOOP"}, // no placeholder
	}
	for _, c := range cases {
		got := replaceLiteralPlaceholder(c.s, c.newLen)
		if got != c.want {
			t.Errorf("replaceLiteralPlaceholder(%q, %d) = %q, want %q", c.s, c.newLen, got, c.want)
		}
	}
}

// TestHasNonASCII verifies the helper detects non-ASCII bytes.
func TestHasNonASCII(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"hello", false},
		{"INBOX", false},
		{"收发室", true},
		{"\xff\xfe", true},
		{"", false},
		{"mixed 收 text", true},
	}
	for _, c := range cases {
		got := hasNonASCII(c.s)
		if got != c.want {
			t.Errorf("hasNonASCII(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

// itoa is a tiny helper to avoid importing strconv just for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
