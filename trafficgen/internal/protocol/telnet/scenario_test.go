package telnet

// Scenario-mode tests (design_telnet.md §4 + RFC 854/855).
//
// These tests assert the Scenario field auto-generates RFC-correct Telnet
// dialogs. Each scenario is derived from the design's business scenarios
// (§4) and the RFC 854 §3 / RFC 855 §3 wire-format rules:
//   - IAC WILL/WONT/DO/DONT = 0xFF <cmd> <option> (3 bytes)
//   - SB sub-option = 0xFF 0xFA <opt> <data with 0xFF escaped> 0xFF 0xF0
//   - Synch = IAC IP + IAC DM = 0xFF 0xF4 0xFF 0xF2
//   - NVT data: 0xFF bytes doubled to 0xFF 0xFF
//
// Failure-path coverage (CLAUDE.md §2): login_fail (auth failure),
// option_reject (WONT/DONT refusal), synch (out-of-band interrupt).
// Each test asserts observable byte sequences, not just packet counts.

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// scenarioSpec returns a FlowSpec with the given scenario and defaults
// suitable for assertions (fixed InitialSeq, port 23).
func scenarioSpec(scenario string) core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 23,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		TCP:    &core.TCPConfig{InitialSeq: 1000},
		Telnet: &core.TelnetConfig{Scenario: scenario},
	}
}

// dialogPayloadsForScenario drains the planner and returns the dialog
// payloads (skips 3 handshake + 4 teardown packets).
func dialogPayloadsForScenario(t *testing.T, spec core.FlowSpec) [][]byte {
	t.Helper()
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	if len(cfgs) < 7 {
		t.Fatalf("len=%d, want >= 7", len(cfgs))
	}
	return extractPayloads(cfgs[3 : len(cfgs)-4])
}

// findPayload returns the first payload containing needle, or nil.
func findPayload(payloads [][]byte, needle []byte) []byte {
	for _, p := range payloads {
		if bytesContains(p, needle) {
			return p
		}
	}
	return nil
}

func bytesContains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// =====================================================================
// login_full scenario (design §4 场景 1)
// =====================================================================

// TestScenario_LoginFull_Negotiation verifies the login_full scenario
// emits the RFC 855 option negotiation: WILL ECHO down, DO ECHO up,
// WILL SGA down, DO SGA up, WILL TTYPE up, DO TTYPE down, WILL NAWS up,
// DO NAWS down.
func TestScenario_LoginFull_Negotiation(t *testing.T) {
	spec := scenarioSpec("login_full")
	payloads := dialogPayloadsForScenario(t, spec)

	// WILL ECHO down (0xFF 0xFB 0x01)
	if findPayload(payloads, []byte{0xFF, 0xFB, 0x01}) == nil {
		t.Errorf("missing IAC WILL ECHO (FF FB 01)")
	}
	// DO ECHO up (0xFF 0xFD 0x01)
	if findPayload(payloads, []byte{0xFF, 0xFD, 0x01}) == nil {
		t.Errorf("missing IAC DO ECHO (FF FD 01)")
	}
	// WILL SGA down (0xFF 0xFB 0x03)
	if findPayload(payloads, []byte{0xFF, 0xFB, 0x03}) == nil {
		t.Errorf("missing IAC WILL SGA (FF FB 03)")
	}
	// DO SGA up (0xFF 0xFD 0x03)
	if findPayload(payloads, []byte{0xFF, 0xFD, 0x03}) == nil {
		t.Errorf("missing IAC DO SGA (FF FD 03)")
	}
	// WILL TTYPE up (0xFF 0xFB 0x18)
	if findPayload(payloads, []byte{0xFF, 0xFB, 0x18}) == nil {
		t.Errorf("missing IAC WILL TTYPE (FF FB 18)")
	}
	// DO TTYPE down (0xFF 0xFD 0x18)
	if findPayload(payloads, []byte{0xFF, 0xFD, 0x18}) == nil {
		t.Errorf("missing IAC DO TTYPE (FF FD 18)")
	}
	// WILL NAWS up (0xFF 0xFB 0x1F)
	if findPayload(payloads, []byte{0xFF, 0xFB, 0x1F}) == nil {
		t.Errorf("missing IAC WILL NAWS (FF FB 1F)")
	}
	// DO NAWS down (0xFF 0xFD 0x1F)
	if findPayload(payloads, []byte{0xFF, 0xFD, 0x1F}) == nil {
		t.Errorf("missing IAC DO NAWS (FF FD 1F)")
	}
}

// TestScenario_LoginFull_SubOptions verifies the login_full scenario
// emits SB TTYPE SEND (down), SB TTYPE IS "xterm" (up), SB NAWS 80x24 (up).
func TestScenario_LoginFull_SubOptions(t *testing.T) {
	spec := scenarioSpec("login_full")
	payloads := dialogPayloadsForScenario(t, spec)

	// SB TTYPE SEND = FF FA 18 01 FF F0
	ttypeSend := []byte{0xFF, 0xFA, 0x18, 0x01, 0xFF, 0xF0}
	if findPayload(payloads, ttypeSend) == nil {
		t.Errorf("missing SB TTYPE SEND (FF FA 18 01 FF F0)")
	}
	// SB TTYPE IS "xterm" = FF FA 18 00 'x' 't' 'e' 'r' 'm' FF F0
	ttypeIs := []byte{0xFF, 0xFA, 0x18, 0x00, 'x', 't', 'e', 'r', 'm', 0xFF, 0xF0}
	if findPayload(payloads, ttypeIs) == nil {
		t.Errorf("missing SB TTYPE IS xterm")
	}
	// SB NAWS 80x24 = FF FA 1F 00 50 00 18 FF F0
	naws := []byte{0xFF, 0xFA, 0x1F, 0x00, 0x50, 0x00, 0x18, 0xFF, 0xF0}
	if findPayload(payloads, naws) == nil {
		t.Errorf("missing SB NAWS 80x24 (FF FA 1F 00 50 00 18 FF F0)")
	}
}

// TestScenario_LoginFull_AuthFlow verifies login_full emits "login: " down,
// username up, "Password: " down, password up, then a shell prompt "$ ".
func TestScenario_LoginFull_AuthFlow(t *testing.T) {
	spec := scenarioSpec("login_full")
	spec.Telnet.Username = "alice"
	spec.Telnet.Password = "secret123"
	payloads := dialogPayloadsForScenario(t, spec)

	if findPayload(payloads, []byte("login: ")) == nil {
		t.Errorf("missing 'login: ' prompt")
	}
	if findPayload(payloads, []byte("alice\r\n")) == nil {
		t.Errorf("missing username 'alice\\r\\n'")
	}
	if findPayload(payloads, []byte("Password: ")) == nil {
		t.Errorf("missing 'Password: ' prompt")
	}
	if findPayload(payloads, []byte("secret123\r\n")) == nil {
		t.Errorf("missing password 'secret123\\r\\n'")
	}
	if findPayload(payloads, []byte("$ ")) == nil {
		t.Errorf("missing shell prompt '$ '")
	}
}

// TestScenario_LoginFull_CommandsAndLogout verifies the scenario emits
// the configured commands and a final "exit\r\n" + "logout\r\n".
func TestScenario_LoginFull_CommandsAndLogout(t *testing.T) {
	spec := scenarioSpec("login_full")
	spec.Telnet.Commands = []string{"ls -la", "whoami"}
	payloads := dialogPayloadsForScenario(t, spec)

	if findPayload(payloads, []byte("ls -la\r\n")) == nil {
		t.Errorf("missing command 'ls -la\\r\\n'")
	}
	if findPayload(payloads, []byte("whoami\r\n")) == nil {
		t.Errorf("missing command 'whoami\\r\\n'")
	}
	if findPayload(payloads, []byte("exit\r\n")) == nil {
		t.Errorf("missing 'exit\\r\\n' logout command")
	}
	if findPayload(payloads, []byte("logout\r\n")) == nil {
		t.Errorf("missing 'logout\\r\\n' server farewell")
	}
}

// TestScenario_LoginFull_Order verifies the negotiation appears before
// the login prompt, which appears before the commands.
func TestScenario_LoginFull_Order(t *testing.T) {
	spec := scenarioSpec("login_full")
	spec.Telnet.Commands = []string{"whoami"}
	payloads := dialogPayloadsForScenario(t, spec)

	idxWillEcho := -1
	idxLogin := -1
	idxWhoami := -1
	idxExit := -1
	for i, p := range payloads {
		if idxWillEcho == -1 && bytesContains(p, []byte{0xFF, 0xFB, 0x01}) {
			idxWillEcho = i
		}
		if idxLogin == -1 && bytesContains(p, []byte("login: ")) {
			idxLogin = i
		}
		if idxWhoami == -1 && bytesContains(p, []byte("whoami\r\n")) {
			idxWhoami = i
		}
		if idxExit == -1 && bytesContains(p, []byte("exit\r\n")) {
			idxExit = i
		}
	}
	if idxWillEcho < 0 || idxLogin < 0 || idxWhoami < 0 || idxExit < 0 {
		t.Fatalf("missing markers: willEcho=%d login=%d whoami=%d exit=%d",
			idxWillEcho, idxLogin, idxWhoami, idxExit)
	}
	if !(idxWillEcho < idxLogin && idxLogin < idxWhoami && idxWhoami < idxExit) {
		t.Errorf("order wrong: willEcho=%d login=%d whoami=%d exit=%d (want willEcho<login<whoami<exit)",
			idxWillEcho, idxLogin, idxWhoami, idxExit)
	}
}

// TestScenario_LoginFull_Defaults verifies default username/password
// when TelnetConfig.Username/Password are empty.
func TestScenario_LoginFull_Defaults(t *testing.T) {
	spec := scenarioSpec("login_full")
	// No Username/Password set -> defaults "alice"/"secret123"
	payloads := dialogPayloadsForScenario(t, spec)
	if findPayload(payloads, []byte("alice\r\n")) == nil {
		t.Errorf("missing default username 'alice\\r\\n'")
	}
	if findPayload(payloads, []byte("secret123\r\n")) == nil {
		t.Errorf("missing default password 'secret123\\r\\n'")
	}
}

// =====================================================================
// login_fail scenario (failure path, CLAUDE.md §2)
// =====================================================================

// TestScenario_LoginFail_AuthFailure verifies the login_fail scenario
// emits login prompt + wrong password + "Login incorrect" re-prompt.
func TestScenario_LoginFail_AuthFailure(t *testing.T) {
	spec := scenarioSpec("login_fail")
	payloads := dialogPayloadsForScenario(t, spec)

	if findPayload(payloads, []byte("login: ")) == nil {
		t.Errorf("missing 'login: ' prompt")
	}
	// The (wrong) password is still sent
	if findPayload(payloads, []byte("\r\n")) == nil {
		t.Errorf("missing password CRLF")
	}
	// Server rejects
	if findPayload(payloads, []byte("Login incorrect")) == nil {
		t.Errorf("missing 'Login incorrect' rejection message")
	}
	// Re-prompt appears after failure
	count := 0
	for _, p := range payloads {
		if bytesContains(p, []byte("login: ")) {
			count++
		}
	}
	if count < 2 {
		t.Errorf("expected >= 2 'login: ' prompts (initial + re-prompt), got %d", count)
	}
}

// =====================================================================
// multi_command scenario
// =====================================================================

// TestScenario_MultiCommand_ExecutesAll verifies each configured command
// appears in the dialog with its response.
func TestScenario_MultiCommand_ExecutesAll(t *testing.T) {
	spec := scenarioSpec("multi_command")
	spec.Telnet.Commands = []string{"ls -la", "whoami", "date", "uname -a"}
	payloads := dialogPayloadsForScenario(t, spec)

	for _, cmd := range spec.Telnet.Commands {
		if findPayload(payloads, []byte(cmd+"\r\n")) == nil {
			t.Errorf("missing command %q", cmd+"\r\\n")
		}
	}
}

// TestScenario_MultiCommand_DefaultCommands verifies default commands when
// none configured.
func TestScenario_MultiCommand_DefaultCommands(t *testing.T) {
	spec := scenarioSpec("multi_command")
	payloads := dialogPayloadsForScenario(t, spec)
	// Default ["ls -la", "whoami"]
	if findPayload(payloads, []byte("ls -la\r\n")) == nil {
		t.Errorf("missing default command 'ls -la\\r\\n'")
	}
	if findPayload(payloads, []byte("whoami\r\n")) == nil {
		t.Errorf("missing default command 'whoami\\r\\n'")
	}
}

// =====================================================================
// long_output scenario (MSS segmentation, CLAUDE.md §5)
// =====================================================================

// TestScenario_LongOutput_MSSSegmentation verifies the server response is
// larger than one MSS, producing multiple PSH-ACK segments.
func TestScenario_LongOutput_MSSSegmentation(t *testing.T) {
	spec := scenarioSpec("long_output")
	// Use a small MSS to force segmentation without huge payloads.
	spec.TCP.MSS = 600
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	dialog := cfgs[3 : len(cfgs)-4]
	// At least one command is sent; the server response is the long output.
	// Count PSH-ACK down segments that carry data > 0.
	downDataSegs := 0
	for _, c := range dialog {
		if c.Direction == "down" && len(c.Payload) > 0 {
			downDataSegs++
		}
	}
	if downDataSegs < 2 {
		t.Errorf("expected >= 2 down data segments (MSS-segmented long output), got %d", downDataSegs)
	}
	// Verify total down payload bytes exceed MSS (600) — the long output.
	totalDown := 0
	for _, c := range dialog {
		if c.Direction == "down" {
			totalDown += len(c.Payload)
		}
	}
	if totalDown <= 600 {
		t.Errorf("total down payload bytes=%d, want > 600 (MSS) for long_output", totalDown)
	}
}

// =====================================================================
// option_reject scenario (failure path: WONT/DONT refusal, RFC 855 §3)
// =====================================================================

// TestScenario_OptionReject_RefusalPath verifies the scenario emits a
// WILL that is answered by DONT (refusal), and a DO that is answered
// by WONT (refusal).
func TestScenario_OptionReject_RefusalPath(t *testing.T) {
	spec := scenarioSpec("option_reject")
	payloads := dialogPayloadsForScenario(t, spec)

	// Look for a DONT (0xFF 0xFE) — refusal of a WILL.
	foundDont := false
	foundWont := false
	for _, p := range payloads {
		if len(p) >= 3 && p[0] == 0xFF && p[1] == 0xFE {
			foundDont = true
		}
		if len(p) >= 3 && p[0] == 0xFF && p[1] == 0xFC {
			foundWont = true
		}
	}
	if !foundDont {
		t.Errorf("missing IAC DONT (refusal path, FF FE)")
	}
	if !foundWont {
		t.Errorf("missing IAC WONT (refusal path, FF FC)")
	}
}

// =====================================================================
// synch scenario (RFC 854 §3 SYNCH = IP + DM)
// =====================================================================

// TestScenario_Synch_IPPlusDM verifies the scenario emits the SYNCH
// signal: IAC IP (0xFF 0xF4) followed by IAC DM (0xFF 0xF2).
func TestScenario_Synch_IPPlusDM(t *testing.T) {
	spec := scenarioSpec("synch")
	payloads := dialogPayloadsForScenario(t, spec)

	// Either the 4-byte combined form or two separate 2-byte payloads.
	combined := []byte{0xFF, 0xF4, 0xFF, 0xF2}
	ipOnly := []byte{0xFF, 0xF4}
	dmOnly := []byte{0xFF, 0xF2}
	if findPayload(payloads, combined) != nil {
		return
	}
	// Otherwise expect separate IP and DM payloads.
	if findPayload(payloads, ipOnly) == nil {
		t.Errorf("missing IAC IP (FF F4) for SYNCH")
	}
	if findPayload(payloads, dmOnly) == nil {
		t.Errorf("missing IAC DM (FF F2) for SYNCH")
	}
}

// =====================================================================
// Validation + backward compatibility
// =====================================================================

// TestScenario_UnknownRejected verifies an unknown scenario is rejected
// by Validate.
func TestScenario_UnknownRejected(t *testing.T) {
	p := NewPlanner()
	spec := scenarioSpec("bogus_scenario")
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for unknown scenario, got nil")
	}
	if !strings.Contains(err.Error(), "telnet:") {
		t.Errorf("err=%v, want contains 'telnet:'", err)
	}
}

// TestScenario_EmptyIsManualMode verifies empty Scenario falls back to
// manual Dialog mode (backward compatible).
func TestScenario_EmptyIsManualMode(t *testing.T) {
	p := NewPlanner()
	spec := validTelnetSpec() // Scenario empty, Dialog set
	if err := p.Validate(spec); err != nil {
		t.Errorf("empty scenario should be manual mode: %v", err)
	}
	cfgs := drain(mustPlan(t, p, spec))
	// 3 handshake + 2 dialog + 4 teardown = 9 (unchanged)
	if len(cfgs) != 9 {
		t.Errorf("len=%d, want 9 (manual mode unchanged)", len(cfgs))
	}
}

// TestScenario_DialogIgnoredInScenarioMode verifies that when Scenario is
// set, a non-empty Dialog is ignored (scenario wins) — the synthesized
// dialog is used, not the user-provided one.
func TestScenario_DialogIgnoredInScenarioMode(t *testing.T) {
	spec := scenarioSpec("login_full")
	// Plant a distinctive marker that the scenario would never emit.
	spec.Telnet.Dialog = []core.TelnetEvent{
		{Type: "data", Direction: "up", Data: "ZZZ_MARKER_ZZZ\r\n"},
	}
	payloads := dialogPayloadsForScenario(t, spec)
	if findPayload(payloads, []byte("ZZZ_MARKER_ZZZ")) != nil {
		t.Errorf("manual Dialog marker found in scenario mode — Dialog should be ignored")
	}
}
