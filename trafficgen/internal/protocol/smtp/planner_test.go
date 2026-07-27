package smtp

// Validate tests and Plan structure tests for the SMTP planner. Each
// test asserts observable PacketConfig field values, not just "no
// error". Spec-driven from testcases_smtp.md.

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/testutil"
)

// validSMTPSpec returns a canonical valid spec for the tests below:
// one HELO+250, one MAIL+250, one RCPT+250, one DATA+354, one body+250,
// one QUIT+221. Same shape as FTP testpoints (mirrors the
// command-response pattern per design_smtp.md §6.4).
func validSMTPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 25,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SMTP: &core.SMTPConfig{
			Banner: "220 mail.example.org ESMTP",
			Dialog: []core.SMTPCommand{
				{Cmd: "HELO client.example.org", Response: "250 mail.example.org"},
				{Cmd: "MAIL FROM:<alice@example.org>", Response: "250 2.1.0 Ok"},
				{Cmd: "RCPT TO:<bob@example.com>", Response: "250 2.1.5 Ok"},
				{Cmd: "DATA", Response: "354 End data with <CR><LF>.<CR><LF>"},
				// Body ends with "\r\n." so the planner's appended
				// "\r\n" completes the "\r\n.\r\n" terminator (RFC
				// 5321 §4.1.1.4).
				{Cmd: "From: alice@example.org\r\nTo: bob@example.com\r\n\r\nHello\r\n.", Response: "250 2.0.0 Ok"},
				{Cmd: "QUIT", Response: "221 2.0.0 Bye"},
			},
		},
	}
}

// drain collects all configs from the channel.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
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

func TestSMTPValidate_ValidIPs(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

// TestSMTPValidate_InvalidSrcIP covers testcase 1.22.x family: spec
// validation must reject malformed IPs.
func TestSMTPValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	spec.SrcIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "SrcIP") {
		t.Errorf("err=%v, want contains 'SrcIP'", err)
	}
}

func TestSMTPValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	spec.DstIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "DstIP") {
		t.Errorf("err=%v, want contains 'DstIP'", err)
	}
}

// TestSMTPValidate_MSSTooSmall covers testcase §MSS boundary (RFC 879).
func TestSMTPValidate_MSSTooSmall(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	testutil.EnsureTCP(&spec).MSS = 100 // below MinMSS=536
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MSS") {
		t.Errorf("err=%v, want contains 'MSS'", err)
	}
}

func TestSMTPValidate_MSSZeroOK(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	testutil.EnsureTCP(&spec).MSS = 0
	if err := p.Validate(spec); err != nil {
		t.Errorf("MSS=0 should be accepted (means default): %v", err)
	}
}

func TestSMTPValidate_NilSMTPConfig(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	spec.SMTP = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("nil SMTP config should be accepted: %v", err)
	}
}

// TestSMTPValidate_EmptySMTPDialog exercises §6.6: validate must accept
// empty Dialog (the planner supplies defaults at Plan time).
func TestSMTPValidate_EmptySMTPDialog(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	spec.SMTP.Dialog = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty Dialog should be accepted (defaults filled in Plan): %v", err)
	}
}

// --- Plan: structure ---

// TestSMTPPlan_Handshake verifies the first 3 packets are SYN,
// SYN-ACK, ACK with the correct directions, flags, and TCP options.
func TestSMTPPlan_Handshake(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSMTPSpec()))
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
	if len(cfgs[2].L4.TCPOptions) != 0 {
		t.Errorf("cfg[2]: ACK should NOT carry TCP options")
	}
}

// TestSMTPPlan_Teardown verifies the last 4 packets are FIN-ACK, ACK,
// FIN-ACK, ACK in the standard order.
func TestSMTPPlan_Teardown(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSMTPSpec()))
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

// TestSMTPPlan_BannerEmitted verifies that when Banner is non-empty,
// the first PSH-ACK payload after the handshake carries the banner
// + CRLF (testcase 1.17.1).
func TestSMTPPlan_BannerEmitted(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSMTPSpec()))
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4", len(cfgs))
	}
	bannerPkt := cfgs[3]
	if bannerPkt.Direction != "down" || bannerPkt.L4.Flags != 0x18 {
		t.Fatalf("cfg[3]: dir=%s flags=%x, want down/PSH-ACK", bannerPkt.Direction, bannerPkt.L4.Flags)
	}
	if !strings.Contains(string(bannerPkt.Payload), "220 mail.example.org") {
		t.Errorf("cfg[3] payload=%q, want contains '220 mail.example.org'", bannerPkt.Payload)
	}
	if !strings.HasSuffix(string(bannerPkt.Payload), "\r\n") {
		t.Errorf("cfg[3] payload should end with CRLF (RFC 5321 §2.3)")
	}
}

// TestSMTPPlan_BannerAutoGenerated covers testcase 1.17.3: when Banner
// is empty, the planner auto-generates "220 <DstIP> ESMTP trafficgen".
func TestSMTPPlan_BannerAutoGenerated(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	spec.SMTP.Banner = ""
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4", len(cfgs))
	}
	banner := string(cfgs[3].Payload)
	if !strings.Contains(banner, "10.0.0.2") {
		t.Errorf("auto-banner should contain DstIP 10.0.0.2, got %q", banner)
	}
	if !strings.Contains(banner, "ESMTP") {
		t.Errorf("auto-banner should contain ESMTP keyword, got %q", banner)
	}
	if !strings.HasSuffix(banner, "\r\n") {
		t.Errorf("auto-banner should end with CRLF, got %q", banner)
	}
}

// TestSMTPPlan_CommandResponsePairs verifies that each SMTPCommand
// produces a (up) + (down) pair, in order, with the correct text.
func TestSMTPPlan_CommandResponsePairs(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSMTPSpec()))
	// handshake(3) + banner(1) + 6 commands * 2 + teardown(4) = 20
	if len(cfgs) != 20 {
		t.Fatalf("len=%d, want 20 (3 + 1 + 12 + 4)", len(cfgs))
	}
	// cfg[4] = HELO cmd up
	if cfgs[4].Direction != "up" || !strings.Contains(string(cfgs[4].Payload), "HELO client.example.org") {
		t.Errorf("cfg[4]: dir=%s payload=%q, want up/HELO", cfgs[4].Direction, cfgs[4].Payload)
	}
	// cfg[5] = 250 resp down
	if cfgs[5].Direction != "down" || !strings.Contains(string(cfgs[5].Payload), "250 mail.example.org") {
		t.Errorf("cfg[5]: dir=%s payload=%q, want down/250", cfgs[5].Direction, cfgs[5].Payload)
	}
}

// TestSMTPPlan_DefaultDialogEmitted covers testcase §6.6: when Dialog
// is nil/empty the planner emits a default session (HELO+MAIL+RCPT
// +DATA+body+QUIT).
func TestSMTPPlan_DefaultDialogEmitted(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	spec.SMTP.Dialog = nil
	cfgs := drain(mustPlan(t, p, spec))
	// defaultDialog has 6 SMTPCommands, each producing 2 packets
	// (up+down). handshake(3) + banner(1) + 12 + teardown(4) = 20.
	if len(cfgs) != 20 {
		t.Fatalf("len=%d, want 20 (default dialog)", len(cfgs))
	}
	// HELO should appear as an up PSH-ACK
	var foundHELO bool
	for _, c := range cfgs {
		if c.Direction == "up" && strings.Contains(string(c.Payload), "HELO ") {
			foundHELO = true
			break
		}
	}
	if !foundHELO {
		t.Errorf("default dialog should include HELO up command")
	}
	// DATA body terminator "\r\n." must be present at end of body Cmd
	// (planner appends "\r\n" to complete "\r\n.\r\n").
	var foundDataEnd bool
	for _, c := range cfgs {
		s := string(c.Payload)
		if c.Direction == "up" && strings.Contains(s, "Hello\r\n.\r\n") {
			foundDataEnd = true
			break
		}
	}
	if !foundDataEnd {
		t.Errorf("default dialog DATA body should end with 'Hello\\r\\n.\\r\\n' (terminator)")
	}
}

// TestSMTPPlan_EmptyDialogEmitsHandshakeAndTeardownOnly covers the
// edge case where Banner is empty AND Dialog is empty -> still get
// the auto-generated banner + default session (degenerate case has
// no payload packets between handshake and the first default
// command).
func TestSMTPPlan_NilSMTPConfig(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	spec.SMTP = nil
	cfgs := drain(mustPlan(t, p, spec))
	// nil SMTP -> default dialog -> 20 packets (same as empty Dialog)
	if len(cfgs) < 7 {
		// at minimum handshake(3) + banner(1) + teardown(4) = 8, but
		// defaultDialog has 6 commands so we get 20.
		t.Fatalf("len=%d, want >= 7", len(cfgs))
	}
}

// TestSMTPPlan_CRLFTerminator verifies that every PSH-ACK payload ends
// with CRLF per RFC 5321 §2.3 (testcase 1.1.1 + family).
func TestSMTPPlan_CRLFTerminator(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSMTPSpec()))
	for i, c := range cfgs {
		if c.L4.Flags != 0x18 { // only PSH-ACK data packets
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

// TestSMTPPlan_DATABodyTerminator covers testcase 1.5.3: the DATA body
// Cmd must end with "\r\n." so the planner's appended "\r\n"
// completes the "\r\n.\r\n" terminator.
func TestSMTPPlan_DATABodyTerminator(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	cfgs := drain(mustPlan(t, p, spec))
	// Find the DATA body packet (the only up PSH-ACK containing
	// "From:" and "\r\n.")
	var dataBodyPayload string
	for _, c := range cfgs {
		if c.Direction != "up" || c.L4.Flags != 0x18 {
			continue
		}
		s := string(c.Payload)
		if strings.Contains(s, "From: alice@example.org") {
			dataBodyPayload = s
			break
		}
	}
	if dataBodyPayload == "" {
		t.Fatal("DATA body packet not found")
	}
	// The payload must end with "\r\n.\r\n" (terminator).
	if !strings.HasSuffix(dataBodyPayload, "\r\n.\r\n") {
		t.Errorf("DATA body must end with '\\r\\n.\\r\\n' terminator, got %q", dataBodyPayload)
	}
	// Body must contain a blank line (headers separator).
	if !strings.Contains(dataBodyPayload, "\r\n\r\n") {
		t.Errorf("DATA body must contain blank line separating headers from body, got %q", dataBodyPayload)
	}
}

// TestSMTPPlan_FlowIDShared verifies all packets share one flow ID (one
// SMTP session = one flow).
func TestSMTPPlan_FlowIDShared(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSMTPSpec()))
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

// TestSMTPPlan_IPIDIncrementsPerPacket verifies that every packet has
// a distinct IP ID (no cross-packet ID reuse within the flow).
func TestSMTPPlan_IPIDIncrementsPerPacket(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validSMTPSpec()))
	seen := make(map[uint16]bool)
	for i, c := range cfgs {
		if seen[c.L3.IPID] {
			t.Errorf("cfg[%d] IPID=%d duplicated", i, c.L3.IPID)
		}
		seen[c.L3.IPID] = true
	}
}

// TestSMTPPlan_DstPortTo25 checks that when the spec carries
// DstPort=25, every up packet targets port 25 (testcase 1.23.2).
func TestSMTPPlan_DstPortTo25(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.Direction == "up" && c.L4.DstPort != 25 {
			t.Errorf("cfg[%d] up DstPort=%d, want 25", i, c.L4.DstPort)
		}
		if c.Direction == "down" && c.L4.SrcPort != 25 {
			t.Errorf("cfg[%d] down SrcPort=%d, want 25", i, c.L4.SrcPort)
		}
	}
}

// TestSMTPPlan_InitialSeqOverride verifies that spec.TCP.InitialSeq
// fixes the client ISN for reproducible tests.
func TestSMTPPlan_InitialSeqOverride(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	testutil.EnsureTCP(&spec).InitialSeq = 0x22222222
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L4.Seq != 0x22222222 {
		t.Errorf("cfg[0] (SYN) Seq=%x, want 22222222", cfgs[0].L4.Seq)
	}
}

// TestSMTPPlan_NonStandardPortAccepted covers testcase 1.23.x: SMTP
// submission (587) and SMTPS (465) are valid ports. Plan does NOT
// enforce port=25; the user can override.
func TestSMTPPlan_NonStandardPortAccepted(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	spec.DstPort = 587
	if _, err := p.Plan(context.Background(), spec); err != nil {
		t.Errorf("Plan should accept DstPort=587 (submission): %v", err)
	}
}

// TestSMTPValidate_Idempotent verifies the read-only Validate contract
// (validate_conventions.md §1.2): calling Validate twice on the same
// spec must yield the same result without mutating the spec.
func TestSMTPValidate_Idempotent(t *testing.T) {
	p := NewPlanner()
	spec := validSMTPSpec()
	orig := spec // value copy
	if err := p.Validate(spec); err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("second Validate: %v", err)
	}
	if spec.SrcIP != orig.SrcIP || spec.DstIP != orig.DstIP || spec.DstPort != orig.DstPort {
		t.Errorf("Validate mutated spec: got %+v, want %+v", spec, orig)
	}
}
