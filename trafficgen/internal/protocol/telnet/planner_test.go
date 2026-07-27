package telnet

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

// mustPlan is a helper that fails the test if Plan returns an error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) <-chan core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return ch
}

// validTelnetSpec returns a minimal valid spec for tests. Uses port 23
// (RFC 854 default) and a 1-event dialog so tests can layer on top.
func validTelnetSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 23,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		Telnet: &core.TelnetConfig{
			Dialog: []core.TelnetEvent{
				{Type: "data", Direction: "down", Data: "login: "},
				{Type: "data", Direction: "up", Data: "alice\r\n"},
			},
		},
	}
}

// --- Validate tests ---

func TestTelnetValidate_ValidSpec(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(validTelnetSpec()); err != nil {
		t.Errorf("valid spec: %v", err)
	}
}

func TestTelnetValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.SrcIP = "not-an-ip"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "telnet:") {
		t.Errorf("err=%v, want contains 'telnet:'", err)
	}
	if err == nil || !strings.Contains(err.Error(), "SrcIP") {
		t.Errorf("err=%v, want contains 'SrcIP'", err)
	}
}

func TestTelnetValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.DstIP = "bad"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "telnet:") {
		t.Errorf("err=%v, want contains 'telnet:'", err)
	}
	if err == nil || !strings.Contains(err.Error(), "DstIP") {
		t.Errorf("err=%v, want contains 'DstIP'", err)
	}
}

func TestTelnetValidate_EmptyIPs(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.SrcIP = ""
	spec.DstIP = ""
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty IPs should skip validation: %v", err)
	}
}

func TestTelnetValidate_MSSTooSmall(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	testutil.EnsureTCP(&spec).MSS = 100 // below MinMSS=536
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "MSS") {
		t.Errorf("err=%v, want contains 'MSS'", err)
	}
}

func TestTelnetValidate_MSSTooLarge(t *testing.T) {
	// MSS=65535 is uint16 max (legal). Any value > 65535 is not representable
	// in the uint16 MSS field at all - so the planner cannot validate that
	// case via this field. Instead verify the boundary 65535 is accepted and
	// the bound 0xFFFF is the practical maximum.
	p := NewPlanner()
	spec := validTelnetSpec()
	testutil.EnsureTCP(&spec).MSS = 65535
	if err := p.Validate(spec); err != nil {
		t.Errorf("MSS=65535 should be accepted: %v", err)
	}
}

func TestTelnetValidate_MSSZeroOK(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	testutil.EnsureTCP(&spec).MSS = 0
	if err := p.Validate(spec); err != nil {
		t.Errorf("MSS=0 should be accepted (means default): %v", err)
	}
}

func TestTelnetValidate_NilTelnetConfig(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.Telnet = nil
	// nil TelnetConfig is valid - planner uses defaultDialog()
	if err := p.Validate(spec); err != nil {
		t.Errorf("nil Telnet config should be accepted: %v", err)
	}
}

func TestTelnetValidate_Idempotent(t *testing.T) {
	// Per validate_conventions.md §1.2 - Validate must be idempotent
	// (no spec mutation). Two calls must return identical results.
	p := NewPlanner()
	spec := validTelnetSpec()
	err1 := p.Validate(spec)
	err2 := p.Validate(spec)
	if (err1 == nil) != (err2 == nil) {
		t.Errorf("Validate not idempotent: err1=%v err2=%v", err1, err2)
	}
	if err1 != nil && err1.Error() != err2.Error() {
		t.Errorf("Validate error messages differ: err1=%q err2=%q", err1, err2)
	}
}

// --- Plan: structure (handshake, dialog, teardown) ---

func TestTelnetPlan_Handshake(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validTelnetSpec()))
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
	// ACK up
	if cfgs[2].Direction != "up" || cfgs[2].L4.Flags != 0x10 {
		t.Errorf("cfg[2]: dir=%s flags=%x, want up/ACK", cfgs[2].Direction, cfgs[2].L4.Flags)
	}
	if len(cfgs[2].L4.TCPOptions) != 0 {
		t.Errorf("cfg[2]: ACK should NOT carry TCP options")
	}
}

func TestTelnetPlan_Teardown(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validTelnetSpec()))
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

// TestTelnetPlan_PacketStructure verifies packet count = handshake (3) +
// dialog PSH-ACKs + teardown (4).
func TestTelnetPlan_PacketStructure(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validTelnetSpec()))
	// 3 handshake + 2 dialog (down "login: ", up "alice\r\n") + 4 teardown = 9
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9 (3+2+4)", len(cfgs))
	}
}

func TestTelnetPlan_ValidateFail(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.SrcIP = "not-an-ip"
	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if ch != nil {
		t.Error("expected nil channel on validate fail")
	}
}

func TestTelnetPlan_DefaultChannelCap(t *testing.T) {
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), validTelnetSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if cap(ch) != 256 {
		t.Errorf("cap(ch)=%d, want 256", cap(ch))
	}
	drain(ch)
}

func TestTelnetPlan_FlowID(t *testing.T) {
	p := NewPlanner()
	cfgs := drain(mustPlan(t, p, validTelnetSpec()))
	want := "10.0.0.1-10.0.0.2-50000-23"
	if cfgs[0].FlowID != want {
		t.Errorf("FlowID=%q, want %q", cfgs[0].FlowID, want)
	}
}

// TestTelnetPlan_DefaultDialog verifies that a nil TelnetConfig triggers
// defaultDialog() (per design_telnet.md §6.6): WILL SGA down, DO SGA up,
// "login: " down, "alice\r\n" up, "$ " down, "exit\r\n" up.
func TestTelnetPlan_DefaultDialog(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.Telnet = nil
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 6 dialog + 4 teardown = 13
	if len(cfgs) != 13 {
		t.Fatalf("len=%d, want 13 (3+6+4)", len(cfgs))
	}
	// cfg[3] = WILL SGA down: 0xFF 0xFB 0x03
	if cfgs[3].Direction != "down" {
		t.Errorf("cfg[3] dir=%s, want down", cfgs[3].Direction)
	}
	want := []byte{0xFF, 0xFB, 0x03}
	if !bytesEqual(cfgs[3].Payload, want) {
		t.Errorf("cfg[3] payload=%v, want %v (IAC WILL SGA)", cfgs[3].Payload, want)
	}
	// cfg[4] = DO SGA up: 0xFF 0xFD 0x03
	if cfgs[4].Direction != "up" {
		t.Errorf("cfg[4] dir=%s, want up", cfgs[4].Direction)
	}
	want = []byte{0xFF, 0xFD, 0x03}
	if !bytesEqual(cfgs[4].Payload, want) {
		t.Errorf("cfg[4] payload=%v, want %v (IAC DO SGA)", cfgs[4].Payload, want)
	}
	// cfg[5] = "login: " down
	if cfgs[5].Direction != "down" {
		t.Errorf("cfg[5] dir=%s, want down", cfgs[5].Direction)
	}
	if string(cfgs[5].Payload) != "login: " {
		t.Errorf("cfg[5] payload=%q, want %q", cfgs[5].Payload, "login: ")
	}
}

// TestTelnetPlan_Banner verifies the optional banner is emitted as the
// first PSH-ACK down, right after the handshake ACK.
func TestTelnetPlan_Banner(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.Telnet.Banner = "Welcome to Telnet Server"
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 1 banner + 2 dialog + 4 teardown = 10
	if len(cfgs) != 10 {
		t.Fatalf("len=%d, want 10 (3+1+2+4)", len(cfgs))
	}
	// cfg[3] = banner PSH-ACK down
	if cfgs[3].Direction != "down" {
		t.Errorf("cfg[3] dir=%s, want down", cfgs[3].Direction)
	}
	if string(cfgs[3].Payload) != "Welcome to Telnet Server" {
		t.Errorf("cfg[3] payload=%q, want banner", cfgs[3].Payload)
	}
	if cfgs[3].L4.Flags != 0x18 {
		t.Errorf("cfg[3] flags=%x, want 0x18 (PSH|ACK)", cfgs[3].L4.Flags)
	}
}

func TestTelnetPlan_EmptyBannerSkipped(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.Telnet.Banner = ""
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 2 dialog + 4 teardown = 9 (no banner)
	if len(cfgs) != 9 {
		t.Errorf("len=%d, want 9 (empty banner skipped)", len(cfgs))
	}
}

// TestTelnetPlan_DirectionDefaultUp verifies that an event with empty
// Direction defaults to "up" (client -> server).
func TestTelnetPlan_DirectionDefaultUp(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.Telnet.Dialog = []core.TelnetEvent{
		{Type: "data", Data: "hello\r\n"}, // no Direction
	}
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 1 dialog + 4 teardown = 8
	if len(cfgs) != 8 {
		t.Fatalf("len=%d, want 8", len(cfgs))
	}
	if cfgs[3].Direction != "up" {
		t.Errorf("cfg[3] dir=%s, want up (default)", cfgs[3].Direction)
	}
}

// TestTelnetPlan_UnknownDirectionDefaultsUp verifies that an unrecognized
// Direction value falls back to "up".
func TestTelnetPlan_UnknownDirectionDefaultsUp(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.Telnet.Dialog = []core.TelnetEvent{
		{Type: "data", Direction: "sideways", Data: "x"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[3].Direction != "up" {
		t.Errorf("cfg[3] dir=%s, want up (unknown direction defaults up)", cfgs[3].Direction)
	}
}

// TestTelnetPlan_EmptyDataEventSkipped verifies that a data event with
// empty Data produces no PSH-ACK (per testcases §4.1.1).
func TestTelnetPlan_EmptyDataEventSkipped(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.Telnet.Dialog = []core.TelnetEvent{
		{Type: "data", Direction: "up", Data: ""},
		{Type: "data", Direction: "up", Data: "real\r\n"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 1 dialog (empty one skipped) + 4 teardown = 8
	if len(cfgs) != 8 {
		t.Errorf("len=%d, want 8 (empty data event skipped)", len(cfgs))
	}
	if string(cfgs[3].Payload) != "real\r\n" {
		t.Errorf("cfg[3] payload=%q, want 'real\\r\\n'", cfgs[3].Payload)
	}
}

// TestTelnetPlan_UnknownTypeSkipped verifies that an unknown event Type
// with empty Data produces no PSH-ACK (per testcases §4.3.11).
func TestTelnetPlan_UnknownTypeSkipped(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.Telnet.Dialog = []core.TelnetEvent{
		{Type: "unknown_type", Direction: "up"},
		{Type: "data", Direction: "up", Data: "real\r\n"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 1 dialog (unknown skipped) + 4 teardown = 8
	if len(cfgs) != 8 {
		t.Errorf("len=%d, want 8 (unknown type skipped)", len(cfgs))
	}
}

// TestTelnetPlan_SeqAdvances verifies that PSH-ACK segments advance the
// sender's sequence number by the payload byte length.
func TestTelnetPlan_SeqAdvances(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.TCP = &core.TCPConfig{InitialSeq: 1000}
	spec.Telnet.Dialog = []core.TelnetEvent{
		{Type: "data", Direction: "up", Data: "hello\r\n"}, // 7 bytes
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Layout (3 handshake + 1 dialog + 4 teardown = 8 packets):
	//   cfg[0] = SYN up (clientSeq=1000 -> 1001 after consume)
	//   cfg[1] = SYN-ACK down
	//   cfg[2] = ACK up (clientSeq=1001)
	//   cfg[3] = PSH-ACK up "hello\r\n" (seq=1001, 7 bytes data)
	//             After: clientSeq = 1001 + 7 = 1008
	//   cfg[4] = FIN-ACK up (seq=1008; consumes 1 byte -> clientSeq=1009)
	//   cfg[5] = ACK down (server ACKs client FIN, ack=1009)
	//   cfg[6] = FIN-ACK down (serverSeq; consumes 1 byte)
	//   cfg[7] = ACK up (seq=1009, ack covers server FIN)
	if len(cfgs) != 8 {
		t.Fatalf("len=%d, want 8", len(cfgs))
	}
	if cfgs[3].L4.Seq != 1001 {
		t.Errorf("cfg[3] (PSH-ACK) seq=%d, want 1001", cfgs[3].L4.Seq)
	}
	if cfgs[3].L4.Ack != cfgs[1].L4.Seq+1 {
		t.Errorf("cfg[3] ack=%d, want %d (serverSeq+1 after SYN-ACK)", cfgs[3].L4.Ack, cfgs[1].L4.Seq+1)
	}
	if cfgs[4].L4.Seq != 1008 {
		t.Errorf("cfg[4] (FIN-ACK) seq=%d, want 1008 (1001 + 7 bytes data)", cfgs[4].L4.Seq)
	}
	if cfgs[4].L4.Flags != 0x11 {
		t.Errorf("cfg[4] flags=%x, want 0x11 (FIN-ACK)", cfgs[4].L4.Flags)
	}
	// Client's final ACK (cfg[7]) seq=1009 (FIN consumed 1 byte)
	if cfgs[7].L4.Seq != 1009 {
		t.Errorf("cfg[7] (final ACK) seq=%d, want 1009 (1008 + 1 FIN)", cfgs[7].L4.Seq)
	}
}

// TestTelnetPlan_LongDataSegmentedByMSS verifies that a data event larger
// than MSS gets segmented into multiple PSH-ACK segments.
func TestTelnetPlan_LongDataSegmentedByMSS(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	// Use MSS=600 (above MinMSS=536 floor). 600-byte data -> segment into
	// 600 (one segment, < MSS). Use 1200 bytes to force 2 segments.
	testutil.EnsureTCP(&spec).MSS = 600
	longData := strings.Repeat("A", 1200)
	spec.Telnet.Dialog = []core.TelnetEvent{
		{Type: "data", Direction: "up", Data: longData},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 2 data segments (600+600) + 4 teardown = 9
	if len(cfgs) != 9 {
		t.Fatalf("len=%d, want 9 (3+2+4)", len(cfgs))
	}
	// cfg[3,4] are the 2 segments
	wantLens := []int{600, 600}
	for i, want := range wantLens {
		if len(cfgs[3+i].Payload) != want {
			t.Errorf("cfg[%d] payload len=%d, want %d", 3+i, len(cfgs[3+i].Payload), want)
		}
	}
}

// --- IAC escape tests ---

// TestTelnetPlan_DataWithFFEscaped verifies that 0xFF bytes in data events
// are doubled to 0xFF 0xFF per RFC 854 §3.
func TestTelnetPlan_DataWithFFEscaped(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.Telnet.Dialog = []core.TelnetEvent{
		{Type: "data", Direction: "up", Data: "\xFF"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs[3].Payload) != 2 {
		t.Errorf("payload len=%d, want 2 (0xFF 0xFF)", len(cfgs[3].Payload))
	}
	if cfgs[3].Payload[0] != 0xFF || cfgs[3].Payload[1] != 0xFF {
		t.Errorf("payload=%v, want [FF FF]", cfgs[3].Payload)
	}
}

// TestTelnetPlan_DataWithMultipleFF verifies that multiple 0xFF bytes are
// each escaped (per testcases §1.3.2: 3 0xFF -> 6 0xFF).
func TestTelnetPlan_DataWithMultipleFF(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.Telnet.Dialog = []core.TelnetEvent{
		{Type: "data", Direction: "up", Data: "\xFF\xFF\xFF"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs[3].Payload) != 6 {
		t.Errorf("payload len=%d, want 6 (3 0xFF -> 6 0xFF)", len(cfgs[3].Payload))
	}
	want := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	if !bytesEqual(cfgs[3].Payload, want) {
		t.Errorf("payload=%v, want %v", cfgs[3].Payload, want)
	}
}

// TestTelnetPlan_DataFFFollowedByByte verifies that 0xFF followed by a
// non-command byte is escaped properly (0xFF 0xFF <byte>) per testcases
// §1.3.3.
func TestTelnetPlan_DataFFFollowedByByte(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.Telnet.Dialog = []core.TelnetEvent{
		{Type: "data", Direction: "up", Data: "\xFFB"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	want := []byte{0xFF, 0xFF, 'B'}
	if !bytesEqual(cfgs[3].Payload, want) {
		t.Errorf("payload=%v, want %v", cfgs[3].Payload, want)
	}
}

// TestTelnetPlan_BannerFFEscaped verifies that 0xFF bytes in the banner
// are also escaped.
func TestTelnetPlan_BannerFFEscaped(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec()
	spec.Telnet.Banner = "\xFFhi"
	spec.Telnet.Dialog = nil
	cfgs := drain(mustPlan(t, p, spec))
	// cfg[3] = banner PSH-ACK down
	want := []byte{0xFF, 0xFF, 'h', 'i'}
	if !bytesEqual(cfgs[3].Payload, want) {
		t.Errorf("banner payload=%v, want %v", cfgs[3].Payload, want)
	}
}

// bytesEqual is a small helper to avoid pulling in bytes package for one
// call. Returns true if a and b have the same length and contents.
func bytesEqual(a, b []byte) bool {
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
