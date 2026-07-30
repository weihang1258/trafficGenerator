package telnet

// Scenario-mode dialog generation (RFC 854/855 full interactive session).
//
// When TelnetConfig.Scenario is set, the planner synthesizes the full
// Telnet dialog for that scenario from the RFC 854 NVT + IAC model and the
// RFC 855 option-negotiation state machine, with correct IAC escaping. The
// user supplies only the session parameters (Username, Password, Commands,
// TerminalType, WindowCols/Rows); the per-scenario event sequence is
// applied by the planner's existing emit loop (see telnet.go Plan).
//
// Supported scenarios (design_telnet.md §4):
//   login_full    - full session: option negotiation (WILL/DO Echo, SGA,
//                   TTYPE, NAWS) + SB TTYPE SEND/IS + SB NAWS + login +
//                   multi-command exec + logout (design §4 场景 1+3).
//   login_fail    - authentication failure path: negotiation + login +
//                   wrong password -> "Login incorrect" + re-prompt
//                   (failure path, CLAUDE.md §2).
//   multi_command - post-login multiple command executions, each with a
//                   one-line server response + shell prompt (design §4
//                   场景 3).
//   long_output   - server response larger than MSS, forcing multiple
//                   PSH-ACK segments (tests MSS segmentation, CLAUDE.md §5).
//   option_reject - option negotiation refusal: server WILL NEW-ENVIRON
//                   -> client DONT (reject), client WILL LINEMODE ->
//                   server DONT (reject). RFC 855 §3 refusal path
//                   (failure path, CLAUDE.md §2).
//   synch         - SYNCH signal (IAC IP + IAC DM, RFC 854 §3) interrupting
//                   a long server output (design §4 场景 8).
//
// The planner does NOT implement option-negotiation state tracking (RFC
// 1143 Q method); the scenario emits the negotiation verbatim. This matches
// the trafficgen contract: synthesize test packets modeling a realistic
// session, not a real Telnet server.

import (
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// scenarioLongOutputBytes is the size of the server response in the
// long_output scenario. 8192 bytes with default MSS 1460 -> 6 segments,
// exercising MSS segmentation.
const scenarioLongOutputBytes = 8192

// validateScenario validates the prerequisites for a scenario. Called from
// Planner.Validate when cfg.Scenario != "". Returns an error for an unknown
// scenario. Field-level requirements are minimal because the scenario
// builder supplies sensible defaults.
func validateScenario(cfg *core.TelnetConfig) error {
	switch cfg.Scenario {
	case "login_full", "login_fail", "multi_command",
		"long_output", "option_reject", "synch":
		// Known scenario.
	default:
		return fmt.Errorf("telnet: unknown scenario %q (want login_full/login_fail/multi_command/long_output/option_reject/synch)", cfg.Scenario)
	}
	return nil
}

// buildScenarioDialog synthesizes the TelnetEvent sequence for the
// configured scenario. The returned dialog replaces the manual Dialog in
// scenario mode. Terminal type and window size fall back to TelnetConfig
// fields, then to planner defaults ("xterm", 80x24).
func buildScenarioDialog(cfg *core.TelnetConfig) []core.TelnetEvent {
	username := cfg.Username
	if username == "" {
		username = "alice"
	}
	password := cfg.Password
	if password == "" {
		password = "secret123"
	}
	terminalType := cfg.TerminalType
	if terminalType == "" {
		terminalType = DefaultTerminalType
	}
	cols := cfg.WindowCols
	if cols == 0 {
		cols = DefaultWindowCols
	}
	rows := cfg.WindowRows
	if rows == 0 {
		rows = DefaultWindowRows
	}
	commands := cfg.Commands
	if len(commands) == 0 {
		commands = []string{"ls -la", "whoami"}
	}

	switch cfg.Scenario {
	case "login_full":
		return loginFullDialog(username, password, terminalType, cols, rows, commands)
	case "login_fail":
		return loginFailDialog(username, password, terminalType, cols, rows)
	case "multi_command":
		return multiCommandDialog(username, password, terminalType, cols, rows, commands)
	case "long_output":
		return longOutputDialog(username, password, terminalType, cols, rows)
	case "option_reject":
		return optionRejectDialog(username, password, terminalType, cols, rows)
	case "synch":
		return synchDialog(username, password, terminalType, cols, rows)
	}
	return nil
}

// negotiationDialog returns the standard option-negotiation prefix used by
// most scenarios (design §4 场景 1):
//
//	S: IAC WILL ECHO      C: IAC DO ECHO
//	S: IAC WILL SGA       C: IAC DO SGA
//	C: IAC WILL TTYPE     S: IAC DO TTYPE
//	C: IAC WILL NAWS      S: IAC DO NAWS
//	S: IAC SB TTYPE SEND  C: IAC SB TTYPE IS <type>
//	C: IAC SB NAWS <w> <h>
func negotiationDialog(terminalType string, cols, rows uint16) []core.TelnetEvent {
	return []core.TelnetEvent{
		{Type: "will", Direction: "down", Option: OptEcho},   // S: WILL ECHO
		{Type: "do", Direction: "up", Option: OptEcho},       // C: DO ECHO
		{Type: "will", Direction: "down", Option: OptSGA},    // S: WILL SGA
		{Type: "do", Direction: "up", Option: OptSGA},        // C: DO SGA
		{Type: "will", Direction: "up", Option: OptTType},    // C: WILL TTYPE
		{Type: "do", Direction: "down", Option: OptTType},    // S: DO TTYPE
		{Type: "will", Direction: "up", Option: OptNAWS},     // C: WILL NAWS
		{Type: "do", Direction: "down", Option: OptNAWS},     // S: DO NAWS
		{Type: "ttype_send", Direction: "down"},              // S: SB TTYPE SEND
		{Type: "ttype_is", Direction: "up", Value: terminalType}, // C: SB TTYPE IS
		{Type: "naws", Direction: "up", Cols: cols, Rows: rows}, // C: SB NAWS
	}
}

// loginFullDialog builds the login_full scenario: negotiation + login
// (with password echo-off toggle) + multi-command exec + logout.
func loginFullDialog(username, password, terminalType string, cols, rows uint16, commands []string) []core.TelnetEvent {
	ev := negotiationDialog(terminalType, cols, rows)

	// Login phase.
	ev = append(ev,
		core.TelnetEvent{Type: "data", Direction: "down", Data: "login: "},
		core.TelnetEvent{Type: "data", Direction: "up", Data: username + "\r\n"},
		core.TelnetEvent{Type: "data", Direction: "down", Data: "Password: "},
		// Server turns echo off for password entry (design §4 场景 2).
		core.TelnetEvent{Type: "wont", Direction: "down", Option: OptEcho},
		core.TelnetEvent{Type: "dont", Direction: "up", Option: OptEcho},
		core.TelnetEvent{Type: "data", Direction: "up", Data: password + "\r\n"},
		// Server restores echo.
		core.TelnetEvent{Type: "will", Direction: "down", Option: OptEcho},
		core.TelnetEvent{Type: "do", Direction: "up", Option: OptEcho},
	)

	// Shell prompt + commands.
	ev = append(ev, core.TelnetEvent{Type: "data", Direction: "down", Data: "$ "})
	for _, cmd := range commands {
		ev = append(ev,
			core.TelnetEvent{Type: "data", Direction: "up", Data: cmd + "\r\n"},
			core.TelnetEvent{Type: "data", Direction: "down", Data: commandResponse(cmd) + "$ "},
		)
	}

	// Logout.
	ev = append(ev,
		core.TelnetEvent{Type: "data", Direction: "up", Data: "exit\r\n"},
		core.TelnetEvent{Type: "data", Direction: "down", Data: "logout\r\n"},
	)
	return ev
}

// loginFailDialog builds the login_fail scenario: negotiation + login with
// a wrong password, server rejects with "Login incorrect" and re-prompts.
// No shell prompt or commands (auth never succeeds).
func loginFailDialog(username, password, terminalType string, cols, rows uint16) []core.TelnetEvent {
	ev := negotiationDialog(terminalType, cols, rows)

	ev = append(ev,
		core.TelnetEvent{Type: "data", Direction: "down", Data: "login: "},
		core.TelnetEvent{Type: "data", Direction: "up", Data: username + "\r\n"},
		core.TelnetEvent{Type: "data", Direction: "down", Data: "Password: "},
		core.TelnetEvent{Type: "wont", Direction: "down", Option: OptEcho},
		core.TelnetEvent{Type: "dont", Direction: "up", Option: OptEcho},
		core.TelnetEvent{Type: "data", Direction: "up", Data: password + "\r\n"},
		core.TelnetEvent{Type: "will", Direction: "down", Option: OptEcho},
		core.TelnetEvent{Type: "do", Direction: "up", Option: OptEcho},
		// Server rejects and re-prompts.
		core.TelnetEvent{Type: "data", Direction: "down", Data: "Login incorrect\r\nlogin: "},
	)
	return ev
}

// multiCommandDialog builds the multi_command scenario: minimal negotiation
// (SGA only) + login + multiple commands each with a response + logout.
func multiCommandDialog(username, password, terminalType string, cols, rows uint16, commands []string) []core.TelnetEvent {
	ev := negotiationDialog(terminalType, cols, rows)

	ev = append(ev,
		core.TelnetEvent{Type: "data", Direction: "down", Data: "login: "},
		core.TelnetEvent{Type: "data", Direction: "up", Data: username + "\r\n"},
		core.TelnetEvent{Type: "data", Direction: "down", Data: "Password: "},
		core.TelnetEvent{Type: "wont", Direction: "down", Option: OptEcho},
		core.TelnetEvent{Type: "dont", Direction: "up", Option: OptEcho},
		core.TelnetEvent{Type: "data", Direction: "up", Data: password + "\r\n"},
		core.TelnetEvent{Type: "will", Direction: "down", Option: OptEcho},
		core.TelnetEvent{Type: "do", Direction: "up", Option: OptEcho},
		core.TelnetEvent{Type: "data", Direction: "down", Data: "$ "},
	)
	for _, cmd := range commands {
		ev = append(ev,
			core.TelnetEvent{Type: "data", Direction: "up", Data: cmd + "\r\n"},
			core.TelnetEvent{Type: "data", Direction: "down", Data: commandResponse(cmd) + "$ "},
		)
	}
	ev = append(ev,
		core.TelnetEvent{Type: "data", Direction: "up", Data: "exit\r\n"},
		core.TelnetEvent{Type: "data", Direction: "down", Data: "logout\r\n"},
	)
	return ev
}

// longOutputDialog builds the long_output scenario: negotiation + login +
// one command whose server response is large enough to span multiple
// PSH-ACK segments (scenarioLongOutputBytes, > default MSS 1460).
func longOutputDialog(username, password, terminalType string, cols, rows uint16) []core.TelnetEvent {
	ev := negotiationDialog(terminalType, cols, rows)
	ev = append(ev,
		core.TelnetEvent{Type: "data", Direction: "down", Data: "login: "},
		core.TelnetEvent{Type: "data", Direction: "up", Data: username + "\r\n"},
		core.TelnetEvent{Type: "data", Direction: "down", Data: "Password: "},
		core.TelnetEvent{Type: "wont", Direction: "down", Option: OptEcho},
		core.TelnetEvent{Type: "dont", Direction: "up", Option: OptEcho},
		core.TelnetEvent{Type: "data", Direction: "up", Data: password + "\r\n"},
		core.TelnetEvent{Type: "will", Direction: "down", Option: OptEcho},
		core.TelnetEvent{Type: "do", Direction: "up", Option: OptEcho},
		core.TelnetEvent{Type: "data", Direction: "down", Data: "$ "},
		core.TelnetEvent{Type: "data", Direction: "up", Data: "cat bigfile.txt\r\n"},
		// Large server response -> MSS-segmented into multiple PSH-ACKs.
		core.TelnetEvent{Type: "data", Direction: "down", Data: strings.Repeat("A", scenarioLongOutputBytes) + "\r\n$ "},
		core.TelnetEvent{Type: "data", Direction: "up", Data: "exit\r\n"},
		core.TelnetEvent{Type: "data", Direction: "down", Data: "logout\r\n"},
	)
	return ev
}

// optionRejectDialog builds the option_reject scenario: negotiation (SGA
// accepted) then a WILL that is refused with DONT and a DO that is refused
// with WONT (RFC 855 §3 refusal path), then a simple login.
func optionRejectDialog(username, password, terminalType string, cols, rows uint16) []core.TelnetEvent {
	ev := []core.TelnetEvent{
		// SGA accepted both directions.
		{Type: "will", Direction: "down", Option: OptSGA},
		{Type: "do", Direction: "up", Option: OptSGA},
		// Client offers NEW-ENVIRON; server refuses with DONT.
		{Type: "will", Direction: "up", Option: OptNewEnviron},
		{Type: "dont", Direction: "down", Option: OptNewEnviron},
		// Server offers LINEMODE; client refuses with DONT.
		{Type: "will", Direction: "down", Option: OptLinemode},
		{Type: "dont", Direction: "up", Option: OptLinemode},
		// Client offers TTYPE; server accepts (one accepted option).
		{Type: "will", Direction: "up", Option: OptTType},
		{Type: "do", Direction: "down", Option: OptTType},
		{Type: "ttype_send", Direction: "down"},
		{Type: "ttype_is", Direction: "up", Value: terminalType},
	}
	ev = append(ev,
		core.TelnetEvent{Type: "data", Direction: "down", Data: "login: "},
		core.TelnetEvent{Type: "data", Direction: "up", Data: username + "\r\n"},
		core.TelnetEvent{Type: "data", Direction: "down", Data: "Password: "},
		core.TelnetEvent{Type: "wont", Direction: "down", Option: OptEcho},
		core.TelnetEvent{Type: "dont", Direction: "up", Option: OptEcho},
		core.TelnetEvent{Type: "data", Direction: "up", Data: password + "\r\n"},
		core.TelnetEvent{Type: "will", Direction: "down", Option: OptEcho},
		core.TelnetEvent{Type: "do", Direction: "up", Option: OptEcho},
		core.TelnetEvent{Type: "data", Direction: "down", Data: "$ "},
		core.TelnetEvent{Type: "data", Direction: "up", Data: "exit\r\n"},
		core.TelnetEvent{Type: "data", Direction: "down", Data: "logout\r\n"},
	)
	return ev
}

// synchDialog builds the synch scenario: negotiation + login + a long
// server output interrupted by the client sending IAC IP + IAC DM (the
// SYNCH signal, RFC 854 §3), then the server prints "^C" and a new prompt.
func synchDialog(username, password, terminalType string, cols, rows uint16) []core.TelnetEvent {
	ev := negotiationDialog(terminalType, cols, rows)
	ev = append(ev,
		core.TelnetEvent{Type: "data", Direction: "down", Data: "login: "},
		core.TelnetEvent{Type: "data", Direction: "up", Data: username + "\r\n"},
		core.TelnetEvent{Type: "data", Direction: "down", Data: "Password: "},
		core.TelnetEvent{Type: "wont", Direction: "down", Option: OptEcho},
		core.TelnetEvent{Type: "dont", Direction: "up", Option: OptEcho},
		core.TelnetEvent{Type: "data", Direction: "up", Data: password + "\r\n"},
		core.TelnetEvent{Type: "will", Direction: "down", Option: OptEcho},
		core.TelnetEvent{Type: "do", Direction: "up", Option: OptEcho},
		core.TelnetEvent{Type: "data", Direction: "down", Data: "$ "},
		// Client starts a long-running command.
		core.TelnetEvent{Type: "data", Direction: "up", Data: "yes\r\n"},
		// Server begins streaming output.
		core.TelnetEvent{Type: "data", Direction: "down", Data: strings.Repeat("y\r\n", 2000)},
		// Client interrupts with SYNCH (IP + DM).
		core.TelnetEvent{Type: "ip", Direction: "up"},
		core.TelnetEvent{Type: "dm", Direction: "up"},
		// Server acknowledges interrupt and re-prompts.
		core.TelnetEvent{Type: "data", Direction: "down", Data: "^C\r\n$ "},
		core.TelnetEvent{Type: "data", Direction: "up", Data: "exit\r\n"},
		core.TelnetEvent{Type: "data", Direction: "down", Data: "logout\r\n"},
	)
	return ev
}

// commandResponse returns a canned one-line server response for a command,
// used by login_full and multi_command scenarios. The response mirrors a
// realistic shell output so pcap payloads are observable and distinguishable.
func commandResponse(cmd string) string {
	switch {
	case strings.HasPrefix(cmd, "ls"):
		return "total 8\r\ndrwxr-xr-x 2 alice alice 4096 Jul 30 10:00 .\r\n"
	case strings.HasPrefix(cmd, "whoami"):
		return "alice\r\n"
	case strings.HasPrefix(cmd, "date"):
		return "Wed Jul 30 10:00:00 UTC 2026\r\n"
	case strings.HasPrefix(cmd, "uname"):
		return "Linux host 5.10.0 #1 SMP x86_64 GNU/Linux\r\n"
	case strings.HasPrefix(cmd, "pwd"):
		return "/home/alice\r\n"
	default:
		return "\r\n"
	}
}
