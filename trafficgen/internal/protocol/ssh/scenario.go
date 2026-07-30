// Package ssh scenario.go - scenario-mode dialog generation.
//
// When SSHConfig.Scenario is set, the planner synthesizes the AuthMethods
// and Channels lists for a complete SSH session from the RFC 4253 transport
// state machine (§7 KEX, §8 keys, §10 service, RFC 4252 user-auth) and the
// RFC 4254 connection layer (§5 channel open, §6 channel requests/data). The
// user supplies only the scenario name (and optional Command/Stdout/Stderr);
// the full ordered message sequence is generated automatically.
//
// Supported scenarios:
//
//   exec            - password auth + CHANNEL_OPEN(session) +
//                     CHANNEL_REQUEST(exec) + CHANNEL_DATA(stdout) +
//                     CHANNEL_EOF + CHANNEL_CLOSE (both sides).
//   shell           - password auth + pty-req + shell + interactive data +
//                     EOF + close.
//   pty-exec        - password auth + pty-req + exec + stdout + EOF + close.
//   publickey       - publickey probe + USERAUTH_FAILURE + signed publickey
//                     request + USERAUTH_SUCCESS + exec session.
//   auth_fail_retry - password request + USERAUTH_FAILURE + password retry
//                     + USERAUTH_SUCCESS + exec session.
//   long_output     - exec with multiple CHANNEL_DATA packets (stdout) +
//                     CHANNEL_EXTENDED_DATA (stderr) + EOF + close.
//
// Encryption is NOT implemented: the post-NEWKEYS BPP payloads are encoded
// with the real message structure (so Wireshark can dissect message_number
// and field lengths) but the bytes are not cryptographically valid.
package ssh

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// validateScenario validates the scenario name. Scenario-specific parameter
// requirements are minimal (all scenarios have working defaults); this only
// guards against an unknown name so the planner does not silently fall back
// to a default dialog under a misleading label.
func validateScenario(cfg *core.SSHConfig) error {
	switch cfg.Scenario {
	case "exec", "shell", "pty-exec", "publickey", "auth_fail_retry", "long_output":
		return nil
	default:
		return fmt.Errorf("unknown SSH scenario: %q (want exec/shell/pty-exec/publickey/auth_fail_retry/long_output)", cfg.Scenario)
	}
}

// scenarioCommand resolves the exec command, defaulting to "uname -a".
func scenarioCommand(cfg *core.SSHConfig) string {
	if cfg.Command != "" {
		return cfg.Command
	}
	return "uname -a"
}

// scenarioStdout resolves the stdout payload, defaulting to a representative
// single-line output.
func scenarioStdout(cfg *core.SSHConfig) []byte {
	if len(cfg.Stdout) > 0 {
		return cfg.Stdout
	}
	return []byte("Linux srv 5.4.0-generic #1 SMP x86_64 GNU/Linux\n")
}

// scenarioStderr resolves the stderr payload (empty by default).
func scenarioStderr(cfg *core.SSHConfig) []byte {
	return cfg.Stderr
}

// dummyPublicKeyBlob returns a representative RSA public key blob (294 bytes
// for a 2048-bit key). This is wire-shaped filler, not a real key.
func dummyPublicKeyBlob() []byte {
	return make([]byte, 294)
}

// dummySignature returns a representative signature blob (256 bytes for an
// RSA-SHA2-512 signature). Wire-shaped filler.
func dummySignature() []byte {
	return make([]byte, 256)
}

// passwordAuth returns a USERAUTH_REQUEST(password) + USERAUTH_SUCCESS pair.
func passwordAuth(user, pass string) []core.SSHMessage {
	return []core.SSHMessage{
		{Type: "userauth_request", MethodName: "password", Username: user, Password: pass},
		{Type: "userauth_success"},
	}
}

// execChannels builds the channel dialog for an exec session: open session,
// confirm, exec request, stdout data (down), EOF (down), close (down),
// EOF (up), close (up). Per RFC 4254 §6.5 the exec request carries the
// command; per §6.1 CHANNEL_DATA carries the command's stdout; per §6.3/§6.4
// EOF then close terminate the channel (both sides per RFC 4254 §5.3).
func execChannels(cfg *core.SSHConfig) []core.ChannelEntry {
	cmd := scenarioCommand(cfg)
	out := scenarioStdout(cfg)
	return []core.ChannelEntry{
		{Type: "channel_open", ChannelType: "session", InitialWindowSize: DefaultChanWin, MaximumPacketSize: DefaultChanPkt},
		{Type: "channel_open_confirmation", RecipientChannel: 0, SenderChannel: 0, InitialWindowSize: DefaultChanWin, MaximumPacketSize: DefaultChanPkt},
		{Type: "channel_request", RecipientChannel: 0, RequestType: "exec", WantReply: true, Command: cmd},
		{Type: "channel_data", RecipientChannel: 0, Direction: "down", Data: out},
		{Type: "channel_eof", RecipientChannel: 0, Direction: "down"},
		{Type: "channel_close", RecipientChannel: 0, Direction: "down"},
		{Type: "channel_eof", RecipientChannel: 0, Direction: "up"},
		{Type: "channel_close", RecipientChannel: 0, Direction: "up"},
	}
}

// shellChannels builds the channel dialog for an interactive shell session:
// open session, confirm, pty-req (RFC 4254 §6.2), shell request (§6.7),
// client command data (up), server output data (down), EOF, close.
func shellChannels(cfg *core.SSHConfig) []core.ChannelEntry {
	out := scenarioStdout(cfg)
	return []core.ChannelEntry{
		{Type: "channel_open", ChannelType: "session", InitialWindowSize: DefaultChanWin, MaximumPacketSize: DefaultChanPkt},
		{Type: "channel_open_confirmation", RecipientChannel: 0, SenderChannel: 0, InitialWindowSize: DefaultChanWin, MaximumPacketSize: DefaultChanPkt},
		{Type: "channel_request", RecipientChannel: 0, RequestType: "pty-req", WantReply: true, Term: "xterm", WidthChars: 80, HeightRows: 24, WidthPixels: 0, HeightPixels: 0, TTYModes: []byte{}},
		{Type: "channel_request", RecipientChannel: 0, RequestType: "shell", WantReply: true},
		{Type: "channel_data", RecipientChannel: 0, Direction: "up", Data: []byte("ls -la\r")},
		{Type: "channel_data", RecipientChannel: 0, Direction: "down", Data: out},
		{Type: "channel_eof", RecipientChannel: 0, Direction: "down"},
		{Type: "channel_close", RecipientChannel: 0, Direction: "down"},
		{Type: "channel_eof", RecipientChannel: 0, Direction: "up"},
		{Type: "channel_close", RecipientChannel: 0, Direction: "up"},
	}
}

// ptyExecChannels builds the channel dialog for a PTY-backed exec session:
// open, confirm, pty-req, exec request, stdout data, EOF, close.
func ptyExecChannels(cfg *core.SSHConfig) []core.ChannelEntry {
	cmd := scenarioCommand(cfg)
	out := scenarioStdout(cfg)
	return []core.ChannelEntry{
		{Type: "channel_open", ChannelType: "session", InitialWindowSize: DefaultChanWin, MaximumPacketSize: DefaultChanPkt},
		{Type: "channel_open_confirmation", RecipientChannel: 0, SenderChannel: 0, InitialWindowSize: DefaultChanWin, MaximumPacketSize: DefaultChanPkt},
		{Type: "channel_request", RecipientChannel: 0, RequestType: "pty-req", WantReply: true, Term: "xterm", WidthChars: 80, HeightRows: 24, WidthPixels: 0, HeightPixels: 0, TTYModes: []byte{}},
		{Type: "channel_request", RecipientChannel: 0, RequestType: "exec", WantReply: true, Command: cmd},
		{Type: "channel_data", RecipientChannel: 0, Direction: "down", Data: out},
		{Type: "channel_eof", RecipientChannel: 0, Direction: "down"},
		{Type: "channel_close", RecipientChannel: 0, Direction: "down"},
		{Type: "channel_eof", RecipientChannel: 0, Direction: "up"},
		{Type: "channel_close", RecipientChannel: 0, Direction: "up"},
	}
}

// longOutputChannels builds the channel dialog for an exec session with
// multi-packet stdout and an optional stderr (CHANNEL_EXTENDED_DATA,
// data_type_code=1 per RFC 4254 §6.2). The stdout is split into multiple
// CHANNEL_DATA messages so the data plane shows segmented output.
func longOutputChannels(cfg *core.SSHConfig) []core.ChannelEntry {
	cmd := scenarioCommand(cfg)
	out := scenarioStdout(cfg)
	// Split stdout into up to 3 segments to model multi-packet output.
	var segs [][]byte
	if len(out) > 0 {
		third := len(out) / 3
		if third == 0 {
			third = len(out)
		}
		for i := 0; i < len(out); i += third {
			end := i + third
			if end > len(out) {
				end = len(out)
			}
			segs = append(segs, out[i:end])
			if len(segs) == 2 {
				// Last segment takes the remainder.
				segs = append(segs, out[end:])
				break
			}
		}
	}
	entries := []core.ChannelEntry{
		{Type: "channel_open", ChannelType: "session", InitialWindowSize: DefaultChanWin, MaximumPacketSize: DefaultChanPkt},
		{Type: "channel_open_confirmation", RecipientChannel: 0, SenderChannel: 0, InitialWindowSize: DefaultChanWin, MaximumPacketSize: DefaultChanPkt},
		{Type: "channel_request", RecipientChannel: 0, RequestType: "exec", WantReply: true, Command: cmd},
	}
	for _, seg := range segs {
		if len(seg) == 0 {
			continue
		}
		entries = append(entries, core.ChannelEntry{
			Type: "channel_data", RecipientChannel: 0, Direction: "down", Data: seg,
		})
	}
	if stderr := scenarioStderr(cfg); len(stderr) > 0 {
		entries = append(entries, core.ChannelEntry{
			Type: "channel_extended_data", RecipientChannel: 0, DataTypeCode: 1, Direction: "down", Data: stderr,
		})
	}
	entries = append(entries,
		core.ChannelEntry{Type: "channel_eof", RecipientChannel: 0, Direction: "down"},
		core.ChannelEntry{Type: "channel_close", RecipientChannel: 0, Direction: "down"},
		core.ChannelEntry{Type: "channel_eof", RecipientChannel: 0, Direction: "up"},
		core.ChannelEntry{Type: "channel_close", RecipientChannel: 0, Direction: "up"},
	)
	return entries
}

// buildScenarioAuth synthesizes the AuthMethods list for the configured
// scenario. Returns nil (no override) when Scenario is empty.
func buildScenarioAuth(cfg *core.SSHConfig) []core.SSHMessage {
	const user, pass = "alice", "secret"
	switch cfg.Scenario {
	case "exec", "shell", "pty-exec", "long_output":
		return passwordAuth(user, pass)
	case "publickey":
		// RFC 4252 §7: client may probe with has_signature=false to learn
		// whether the server will accept the key. The server responds with
		// USERAUTH_FAILURE (or PK_OK via USERAUTH_SUCCESS for a probe); the
		// client then sends the signed request.
		blob := dummyPublicKeyBlob()
		return []core.SSHMessage{
			{Type: "userauth_request", MethodName: "publickey", Username: user, HasSignature: false, PublicKeyAlgorithm: "ssh-rsa", PublicKeyBlob: blob},
			{Type: "userauth_failure", AuthMethodsThatCanContinue: "publickey", PartialSuccess: false},
			{Type: "userauth_request", MethodName: "publickey", Username: user, HasSignature: true, PublicKeyAlgorithm: "ssh-rsa", PublicKeyBlob: blob, Signature: dummySignature()},
			{Type: "userauth_success"},
		}
	case "auth_fail_retry":
		return []core.SSHMessage{
			{Type: "userauth_request", MethodName: "password", Username: user, Password: "wrong"},
			{Type: "userauth_failure", AuthMethodsThatCanContinue: "publickey,password", PartialSuccess: false},
			{Type: "userauth_request", MethodName: "password", Username: user, Password: pass},
			{Type: "userauth_success"},
		}
	default:
		return nil
	}
}

// buildScenarioChannels synthesizes the Channels list for the configured
// scenario. Returns nil (no override) when Scenario is empty.
func buildScenarioChannels(cfg *core.SSHConfig) []core.ChannelEntry {
	switch cfg.Scenario {
	case "exec", "publickey", "auth_fail_retry":
		return execChannels(cfg)
	case "shell":
		return shellChannels(cfg)
	case "pty-exec":
		return ptyExecChannels(cfg)
	case "long_output":
		return longOutputChannels(cfg)
	default:
		return nil
	}
}
