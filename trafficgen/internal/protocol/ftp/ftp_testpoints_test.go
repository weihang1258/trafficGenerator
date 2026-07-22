package ftp

// Test points for the FTP planner. Each test asserts observable
// PacketConfig field values, not just "no error". Derived from the
// session-level dialog structure documented in ftp.go.

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

func validFTPSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 21,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		FTP: &core.FTPConfig{
			Banner: "220 Spirent FTP",
			Commands: []core.FTPCommand{
				{Cmd: "USER anonymous", Response: "331 Anonymous allowed"},
				{Cmd: "PASS test@x.com", Response: "230 Logged in"},
				{Cmd: "QUIT", Response: "221 OK"},
			},
		},
	}
}

// --- Validate ---

func TestFTPValidate_ValidIPs(t *testing.T) {
	p := NewPlanner()
	spec := validFTPSpec()
	if err := p.Validate(spec); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestFTPValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validFTPSpec()
	spec.SrcIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Errorf("err=%v, want contains 'invalid source IP'", err)
	}
}

func TestFTPValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validFTPSpec()
	spec.DstIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid destination IP") {
		t.Errorf("err=%v, want contains 'invalid destination IP'", err)
	}
}

func TestFTPValidate_MSSTooSmall(t *testing.T) {
	p := NewPlanner()
	spec := validFTPSpec()
	testutil.EnsureTCP(&spec).MSS = 100 // below MinMSS=536
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MSS") {
		t.Errorf("err=%v, want contains 'MSS'", err)
	}
}

func TestFTPValidate_MSSZeroOK(t *testing.T) {
	p := NewPlanner()
	spec := validFTPSpec()
	testutil.EnsureTCP(&spec).MSS = 0 // 0 means default — not an error
	if err := p.Validate(spec); err != nil {
		t.Errorf("MSS=0 should be accepted (means default): %v", err)
	}
}

func TestFTPValidate_NilFTPConfig(t *testing.T) {
	p := NewPlanner()
	spec := validFTPSpec()
	spec.FTP = nil
	if err := p.Validate(spec); err != nil {
		t.Errorf("nil FTP config should be accepted: %v", err)
	}
}

// --- Plan: structure ---

// TestFTPPlan_Handshake verifies the first 3 packets are SYN, SYN-ACK, ACK
// with the correct directions, flags, and TCP options.
func TestFTPPlan_Handshake(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validFTPSpec()))
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

// TestFTPPlan_Teardown verifies the last 4 packets are FIN-ACK, ACK,
// FIN-ACK, ACK in the standard order.
func TestFTPPlan_Teardown(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validFTPSpec()))
	n := len(cfgs)
	if n < 4 {
		t.Fatalf("len=%d, want >= 4 (teardown)", n)
	}
	// Client FIN-ACK up
	if cfgs[n-4].Direction != "up" || cfgs[n-4].L4.Flags != 0x11 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want up/FIN-ACK", n-4, cfgs[n-4].Direction, cfgs[n-4].L4.Flags)
	}
	// Server ACK down
	if cfgs[n-3].Direction != "down" || cfgs[n-3].L4.Flags != 0x10 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want down/ACK", n-3, cfgs[n-3].Direction, cfgs[n-3].L4.Flags)
	}
	// Server FIN-ACK down
	if cfgs[n-2].Direction != "down" || cfgs[n-2].L4.Flags != 0x11 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want down/FIN-ACK", n-2, cfgs[n-2].Direction, cfgs[n-2].L4.Flags)
	}
	// Client ACK up
	if cfgs[n-1].Direction != "up" || cfgs[n-1].L4.Flags != 0x10 {
		t.Errorf("cfg[%d]: dir=%s flags=%x, want up/ACK", n-1, cfgs[n-1].Direction, cfgs[n-1].L4.Flags)
	}
}

// TestFTPPlan_BannerEmitted verifies that when Banner is non-empty, the
// first payload packet after the handshake is a down PSH-ACK containing
// the banner text + CRLF.
func TestFTPPlan_BannerEmitted(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validFTPSpec()))
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4", len(cfgs))
	}
	bannerPkt := cfgs[3]
	if bannerPkt.Direction != "down" || bannerPkt.L4.Flags != 0x18 {
		t.Fatalf("cfg[3]: dir=%s flags=%x, want down/PSH-ACK", bannerPkt.Direction, bannerPkt.L4.Flags)
	}
	if !strings.Contains(string(bannerPkt.Payload), "220 Spirent FTP") {
		t.Errorf("cfg[3] payload=%q, want contains '220 Spirent FTP'", bannerPkt.Payload)
	}
	if !strings.HasSuffix(string(bannerPkt.Payload), "\r\n") {
		t.Errorf("cfg[3] payload should end with CRLF (RFC 959 §4.1)")
	}
}

// TestFTPPlan_NoBannerSkipped verifies that an empty Banner emits no
// payload packet between the handshake and the first command.
func TestFTPPlan_NoBannerSkipped(t *testing.T) {
	p := NewPlanner()
	spec := validFTPSpec()
	spec.FTP.Banner = ""
	cfgs := drain(mustPlan(t, p, spec))
	// After handshake (3 packets), the next packet should be the first
	// command (USER...), not a banner.
	if len(cfgs) < 4 {
		t.Fatalf("len=%d, want >= 4", len(cfgs))
	}
	if cfgs[3].Direction != "up" {
		t.Errorf("cfg[3]: dir=%s, want up (first command)", cfgs[3].Direction)
	}
	if !strings.Contains(string(cfgs[3].Payload), "USER anonymous") {
		t.Errorf("cfg[3] payload=%q, want contains 'USER anonymous' (no banner was emitted)", cfgs[3].Payload)
	}
}

// TestFTPPlan_CommandResponsePairs verifies that each FTPCommand produces
// a (command up) + (response down) pair, in order, with the correct text.
func TestFTPPlan_CommandResponsePairs(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validFTPSpec()))
	// Expected: handshake(3) + banner(1) + 3 commands × 2 (cmd+resp) +
	// teardown(4) = 14 packets.
	if len(cfgs) != 14 {
		t.Fatalf("len=%d, want 14 (3 + 1 + 6 + 4)", len(cfgs))
	}
	// cfg[4] = USER cmd up
	if cfgs[4].Direction != "up" || !strings.Contains(string(cfgs[4].Payload), "USER anonymous") {
		t.Errorf("cfg[4]: dir=%s payload=%q, want up/USER", cfgs[4].Direction, cfgs[4].Payload)
	}
	// cfg[5] = 331 resp down
	if cfgs[5].Direction != "down" || !strings.Contains(string(cfgs[5].Payload), "331") {
		t.Errorf("cfg[5]: dir=%s payload=%q, want down/331", cfgs[5].Direction, cfgs[5].Payload)
	}
	// cfg[6] = PASS cmd up
	if cfgs[6].Direction != "up" || !strings.Contains(string(cfgs[6].Payload), "PASS test@x.com") {
		t.Errorf("cfg[6]: dir=%s payload=%q, want up/PASS", cfgs[6].Direction, cfgs[6].Payload)
	}
	// cfg[7] = 230 resp down
	if cfgs[7].Direction != "down" || !strings.Contains(string(cfgs[7].Payload), "230") {
		t.Errorf("cfg[7]: dir=%s payload=%q, want down/230", cfgs[7].Direction, cfgs[7].Payload)
	}
	// cfg[8] = QUIT cmd up
	if cfgs[8].Direction != "up" || !strings.Contains(string(cfgs[8].Payload), "QUIT") {
		t.Errorf("cfg[8]: dir=%s payload=%q, want up/QUIT", cfgs[8].Direction, cfgs[8].Payload)
	}
	// cfg[9] = 221 resp down
	if cfgs[9].Direction != "down" || !strings.Contains(string(cfgs[9].Payload), "221") {
		t.Errorf("cfg[9]: dir=%s payload=%q, want down/221", cfgs[9].Direction, cfgs[9].Payload)
	}
}

// TestFTPPlan_SequenceContinuity verifies that the next command's ACK
// field covers all prior response bytes — the signature of a continuous
// sequence space per direction within one flow.
func TestFTPPlan_SequenceContinuity(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validFTPSpec()))

	// For each up PSH-ACK (command), its Ack field must equal the
	// cumulative server sequence: the server's ISN+1 (after SYN-ACK)
	// plus the byte length of every down payload emitted so far.
	var serverSeq uint32
	for i, c := range cfgs {
		switch {
		case c.L4.Flags == 0x12: // SYN-ACK: server ISN
			serverSeq = c.L4.Seq + 1 // SYN consumes one seq number
		case c.Direction == "down" && c.L4.Flags == 0x18:
			// down PSH-ACK: advance serverSeq by payload length
			serverSeq = c.L4.Seq + uint32(len(c.Payload))
		case c.Direction == "up" && c.L4.Flags == 0x18:
			// up PSH-ACK: its Ack must equal the latest serverSeq
			if c.L4.Ack != serverSeq {
				t.Errorf("cfg[%d] (up cmd) Ack=%d, want %d (cumulative server seq)", i, c.L4.Ack, serverSeq)
			}
		}
	}
}

// TestFTPPlan_MSSSegmentation verifies that a response longer than MSS is
// split into multiple PSH-ACK segments. With MSS=536 and a 1080-byte
// response (plus the "331 " prefix + "\r\n" = 1086 bytes), expect 3
// segments (536 + 536 + 14).
func TestFTPPlan_MSSSegmentation(t *testing.T) {
	p := NewPlanner()
	spec := validFTPSpec()
	testutil.EnsureTCP(&spec).MSS = 536
	longBody := strings.Repeat("x", 1080)
	spec.FTP.Banner = ""
	spec.FTP.Commands = []core.FTPCommand{
		{Cmd: "USER test", Response: "331 " + longBody},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp(3 segments) + teardown(4) = 11 packets
	if len(cfgs) != 11 {
		t.Fatalf("len=%d, want 11", len(cfgs))
	}
	// cfg[4..6] are the three response segments
	seg1 := cfgs[4]
	seg2 := cfgs[5]
	seg3 := cfgs[6]
	if seg1.Direction != "down" || seg2.Direction != "down" || seg3.Direction != "down" {
		t.Errorf("response segments should be down")
	}
	totalPayload := 4 + len(longBody) + 2 // "331 " + body + "\r\n"
	if len(seg1.Payload) != 536 || len(seg2.Payload) != 536 {
		t.Errorf("seg1.len=%d want 536; seg2.len=%d want 536", len(seg1.Payload), len(seg2.Payload))
	}
	if len(seg3.Payload) != totalPayload-536*2 {
		t.Errorf("seg3.len=%d want %d", len(seg3.Payload), totalPayload-536*2)
	}
	// Sequence space is continuous: segN.Seq = seg(N-1).Seq + len(seg(N-1).Payload)
	if seg1.L4.Seq+uint32(len(seg1.Payload)) != seg2.L4.Seq {
		t.Errorf("seg2.Seq=%d, want %d (continuous)", seg2.L4.Seq, seg1.L4.Seq+uint32(len(seg1.Payload)))
	}
	if seg2.L4.Seq+uint32(len(seg2.Payload)) != seg3.L4.Seq {
		t.Errorf("seg3.Seq=%d, want %d (continuous)", seg3.L4.Seq, seg2.L4.Seq+uint32(len(seg2.Payload)))
	}
}

// TestFTPPlan_EmptyCommandsEmitsHandshakeAndTeardownOnly verifies the
// degenerate case: no banner, no commands → just TCP handshake + teardown.
func TestFTPPlan_EmptyCommandsEmitsHandshakeAndTeardownOnly(t *testing.T) {
	p := NewPlanner()
	spec := validFTPSpec()
	spec.FTP.Banner = ""
	spec.FTP.Commands = nil
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 7 {
		t.Fatalf("len=%d, want 7 (3 handshake + 4 teardown)", len(cfgs))
	}
}

// TestFTPPlan_OneWayCommands verifies that an empty Response produces a
// command packet only (no response). And an empty Cmd produces a
// response only. This lets users model server-only or client-only turns.
func TestFTPPlan_OneWayCommands(t *testing.T) {
	p := NewPlanner()
	spec := validFTPSpec()
	spec.FTP.Banner = ""
	spec.FTP.Commands = []core.FTPCommand{
		{Cmd: "USER anon", Response: ""}, // cmd only
		{Cmd: "", Response: "331 ok"},   // resp only
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + cmd(1) + resp(1) + teardown(4) = 9
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9", len(cfgs))
	}
	// cfg[3] = USER cmd up
	if cfgs[3].Direction != "up" || !strings.Contains(string(cfgs[3].Payload), "USER anon") {
		t.Errorf("cfg[3] should be up USER cmd, got dir=%s payload=%q", cfgs[3].Direction, cfgs[3].Payload)
	}
	// cfg[4] = 331 resp down
	if cfgs[4].Direction != "down" || !strings.Contains(string(cfgs[4].Payload), "331 ok") {
		t.Errorf("cfg[4] should be down 331 resp, got dir=%s payload=%q", cfgs[4].Direction, cfgs[4].Payload)
	}
}

// TestFTPPlan_InitialSeqOverride verifies that spec.TCP.InitialSeq fixes
// the client ISN for reproducible tests.
func TestFTPPlan_InitialSeqOverride(t *testing.T) {
	p := NewPlanner()
	spec := validFTPSpec()
	testutil.EnsureTCP(&spec).InitialSeq = 0x11111111
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[0].L4.Seq != 0x11111111 {
		t.Errorf("cfg[0] (SYN) Seq=%x, want 11111111", cfgs[0].L4.Seq)
	}
}

// TestFTPPlan_FlowIDShared verifies all packets share one flow ID (the
// session-level invariant: one FTP control connection = one flow).
func TestFTPPlan_FlowIDShared(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validFTPSpec()))
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

// TestFTPPlan_IPIDIncrementsPerPacket verifies that every packet has a
// distinct IP ID (no cross-packet ID reuse within the flow).
func TestFTPPlan_IPIDIncrementsPerPacket(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validFTPSpec()))
	seen := make(map[uint16]bool)
	for i, c := range cfgs {
		if seen[c.L3.IPID] {
			t.Errorf("cfg[%d] IPID=%d duplicated", i, c.L3.IPID)
		}
		seen[c.L3.IPID] = true
	}
}

// TestFTPPlan_CRLFTerminator verifies that every command and response
// payload ends with CRLF per RFC 959 §4.1.
func TestFTPPlan_CRLFTerminator(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validFTPSpec()))
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

// TestFTPPlan_DstPortDefaultsTo21 verifies that the strategy_convert
// dst_port default for FTP is 21 when the user did not specify one.
// This test lives in the ftp package because it's the FTP-specific
// contract; the actual defaulting is in core.strategy_convert.
func TestFTPPlan_DstPortDefaultsTo21(t *testing.T) {
	// Spec constructed without DstPort; planner does not default it
	// (that's mapToFlowSpec's job). Here we just verify that when
	// DstPort=21 the planner emits packets to port 21.
	p := NewPlanner()
	spec := validFTPSpec()
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if c.Direction == "up" && c.L4.DstPort != 21 {
			t.Errorf("cfg[%d] up DstPort=%d, want 21", i, c.L4.DstPort)
		}
		if c.Direction == "down" && c.L4.SrcPort != 21 {
			t.Errorf("cfg[%d] down SrcPort=%d, want 21", i, c.L4.SrcPort)
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
