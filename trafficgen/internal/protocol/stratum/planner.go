// Package stratum planner: negative-path validation (11 wire_fault kinds,
// design §7 一行一注入 — 与设计 §7 表/用例 §5 表三方同序) plus the session
// state machine and correlation checks (§5). Every rejected spec must surface
// as a task error — never a completed/0-packet or TCP-shell fake success.
package stratum

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Validate checks a stratum flow spec. cfg == nil (bare {"stratum":{}} layer)
// passes: the generator emits the default baseline session (subscribe only).
func Validate(spec core.FlowSpec) error {
	cfg := spec.Stratum
	if cfg == nil {
		return nil
	}
	if cfg.WireFault != "" {
		if err := validateWireFault(cfg.WireFault); err != nil {
			return err
		}
	}
	for si, sess := range cfg.Sessions {
		if err := validateSession(sess, si, cfg.Extensions); err != nil {
			return err
		}
	}
	return nil
}

// validateSession walks one session's events enforcing the miner-side state
// machine (design §5) and the per-message param shapes (§3). State tracked:
// subscribed / authorized / extranonce2 size / seen jobs / open request ids.
func validateSession(sess core.StratumSession, si int, extensions []string) error {
	prefix := fmt.Sprintf("stratum: sessions[%d]", si)
	subscribed := false
	authorized := false
	jobs := map[string]bool{}
	firstApp := true
	for ei, ev := range sess.Events {
		ep := fmt.Sprintf("%s.events[%d]", prefix, ei)
		// State machine: first application message must be subscribe or
		// configure (BIP310's configure is the sanctioned exception).
		if firstApp {
			switch ev.Kind {
			case "subscribe", "configure":
			case "":
				return fmt.Errorf("%s: missing kind", ep)
			default:
				return fmt.Errorf("%s: first application message must be subscribe or configure (state machine)", ep)
			}
			firstApp = false
		}
		if ev.Kind == "" {
			return fmt.Errorf("%s: missing kind", ep)
		}
		switch ev.Kind {
		case "subscribe":
			if len(ev.ID) == 0 || string(ev.ID) == "null" {
				return fmt.Errorf("%s: subscribe request id must be a JSON number (id: %s)", ep, string(ev.ID))
			}
			if ev.Extranonce2Size != 0 && (ev.Extranonce2Size < 0 || ev.Extranonce2Size > 64) {
				return fmt.Errorf("%s: extranonce2_size out of range (params)", ep)
			}
			if err := checkHexField(ep, "extranonce1", ev.Extranonce1, 0); err != nil {
				return err
			}
			subscribed = true
		case "extranonce_subscribe":
			if len(ev.ID) == 0 || string(ev.ID) == "null" {
				return fmt.Errorf("%s: extranonce_subscribe request id must be a JSON number (id: %s)", ep, string(ev.ID))
			}
		case "authorize":
			if !subscribed {
				return fmt.Errorf("%s: authorize before subscribe (state)", ep)
			}
			if ev.Username == "" {
				return fmt.Errorf("%s: authorize params must be [username, password] (params)", ep)
			}
			if ev.Result != nil && string(ev.Result) == "false" {
				// 拒绝路径（正例 4 形态）：authorize 拒绝后不得 submit。
				authorized = false
			} else {
				authorized = true
			}
		case "set_difficulty":
			if len(ev.Difficulty) > 0 && !isJSONNumber(ev.Difficulty) {
				return fmt.Errorf("%s: set_difficulty params[0] must be a JSON number (params)", ep)
			}
		case "notify":
			if len(ev.ID) > 0 && string(ev.ID) != "null" {
				return fmt.Errorf("%s: notify must carry id null (id: %s)", ep, string(ev.ID))
			}
			if err := checkHexField(ep, "prevhash", ev.Prevhash, 64); err != nil {
				return err
			}
			if err := checkHexField(ep, "coinb1", ev.Coinb1, 0); err != nil {
				return err
			}
			if err := checkHexField(ep, "coinb2", ev.Coinb2, 0); err != nil {
				return err
			}
			for mi, m := range ev.MerkleBranch {
				if err := checkHexField(ep, fmt.Sprintf("merkle_branch[%d]", mi), m, 64); err != nil {
					return err
				}
			}
			if err := checkHexField(ep, "version", ev.Version, 8); err != nil {
				return err
			}
			if err := checkHexField(ep, "nbits", ev.Nbits, 8); err != nil {
				return err
			}
			if err := checkHexField(ep, "ntime", ev.Ntime, 8); err != nil {
				return err
			}
			jobs[ev.JobID] = true
		case "set_extranonce":
			if ev.Extranonce1 == "" {
				return fmt.Errorf("%s: set_extranonce params must be [extranonce1, extranonce2_size] — 2 elements (params; 1-element form is the ethash dialect)", ep)
			}
			if err := checkHexField(ep, "extranonce1", ev.Extranonce1, 0); err != nil {
				return err
			}
		case "submit":
			if !subscribed {
				return fmt.Errorf("%s: submit before subscribe (state)", ep)
			}
			if !authorized {
				return fmt.Errorf("%s: submit before authorize (state)", ep)
			}
			if !jobs[ev.JobID] {
				return fmt.Errorf("%s: submit job_id %q not from this session's notify (job)", ep, ev.JobID)
			}
			if ev.Username != "" && ev.Username != lastAuthUser(sess.Events[:ei]) {
				return fmt.Errorf("%s: submit username %q does not match the authorized user (job)", ep, ev.Username)
			}
			if len(ev.Extranonce2) > 0 {
				size := currentEn2Size(sess.Events[:ei])
				if size > 0 && len(ev.Extranonce2) != 2*size {
					return fmt.Errorf("%s: submit extranonce2 length must be exactly 2×extranonce2_size (got %d hex, size %d)", ep, len(ev.Extranonce2), size)
				}
				if err := checkHexField(ep, "extranonce2", ev.Extranonce2, 0); err != nil {
					return err
				}
			}
			if err := checkHexField(ep, "ntime", ev.Ntime, 8); err != nil {
				return err
			}
			if err := checkHexField(ep, "nonce", ev.Nonce, 8); err != nil {
				return err
			}
			if ev.VersionBits != "" {
				if !versionRollingActive(sess.Events[:ei], extensions) {
					return fmt.Errorf("%s: submit 6th param version_bits requires active version-rolling (params)", ep)
				}
				if err := checkHexField(ep, "version_bits", ev.VersionBits, 8); err != nil {
					return err
				}
			}
		case "get_version":
			// 矿池→矿机反向请求；id must be a number.
			if len(ev.ID) == 0 || string(ev.ID) == "null" {
				return fmt.Errorf("%s: client.get_version request id must be a JSON number (id: %s)", ep, string(ev.ID))
			}
		case "show_message":
			if len(ev.ID) > 0 && string(ev.ID) != "null" {
				return fmt.Errorf("%s: show_message must carry id null (id: %s)", ep, string(ev.ID))
			}
		case "configure":
		case "set_version_mask":
			if len(ev.ID) > 0 && string(ev.ID) != "null" {
				return fmt.Errorf("%s: set_version_mask must carry id null (id: %s)", ep, string(ev.ID))
			}
			if err := checkHexField(ep, "mask", ev.Mask, 8); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: unknown event kind %q (unknown)", ep, ev.Kind)
		}
	}
	return nil
}

// lastAuthUser returns the most recent authorize event's username.
func lastAuthUser(events []core.StratumEvent) string {
	u := ""
	for _, ev := range events {
		if ev.Kind == "authorize" && ev.Username != "" {
			if ev.Result == nil || string(ev.Result) != "false" {
				u = ev.Username
			}
		}
	}
	return u
}

// currentEn2Size returns the effective extranonce2 size, applying the same
// defaults as the generator (subscribe unset → 4, set_extranonce unset → 8)
// so the submit 2×size check matches the emitted wire.
func currentEn2Size(events []core.StratumEvent) int {
	size := 0
	for _, ev := range events {
		switch ev.Kind {
		case "subscribe":
			size = ev.Extranonce2Size
			if size == 0 {
				size = 4
			}
		case "set_extranonce":
			size = ev.Extranonce2Size
			if size == 0 {
				size = 8
			}
		}
	}
	return size
}

// versionRollingActive reports whether mining.configure (version-rolling)
// has appeared in the session or is declared at the config level.
func versionRollingActive(events []core.StratumEvent, extensions []string) bool {
	for _, ext := range extensions {
		if ext == "version-rolling" {
			return true
		}
	}
	for _, ev := range events {
		if ev.Kind == "configure" {
			return true
		}
	}
	return false
}

// checkHexField enforces the hex field rules (design §3.1): ASCII lowercase
// hex, even length, no 0x prefix; width>0 additionally pins the length.
func checkHexField(prefix, name, val string, width int) error {
	if val == "" {
		return nil
	}
	if strings.HasPrefix(val, "0x") || strings.HasPrefix(val, "0X") {
		return fmt.Errorf("%s: %s must not carry the 0x prefix (hex)", prefix, name)
	}
	if len(val)%2 != 0 {
		return fmt.Errorf("%s: %s length %d is odd (hex)", prefix, name, len(val))
	}
	for i := 0; i < len(val); i++ {
		c := val[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("%s: %s contains non-hex character %q (hex)", prefix, name, c)
		}
	}
	if width > 0 && len(val) != width {
		return fmt.Errorf("%s: %s length must be exactly %d hex characters (hex)", prefix, name, width)
	}
	return nil
}

func isJSONNumber(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E') {
			return false
		}
	}
	return true
}

// validateWireFault dispatches the 11 sanctioned single-injection faults
// (design §7; each error carries the row's 主锚词 so error_contains matches).
func validateWireFault(kind string) error {
	switch kind {
	case "json":
		return fmt.Errorf("stratum: wire fault json: line content is not valid json")
	case "framing":
		return fmt.Errorf("stratum: wire fault framing: line framing error (missing LF / CRLF / private length prefix)")
	case "method":
		return fmt.Errorf("stratum: wire fault method: unknown method or direction violation (unknown method or miner sending a notification)")
	case "params":
		return fmt.Errorf("stratum: wire fault params: params element count/type/position error")
	case "hex":
		return fmt.Errorf("stratum: wire fault hex: hex field width/charset/prefix violation")
	case "state":
		return fmt.Errorf("stratum: wire fault state: session state machine violation")
	case "id":
		return fmt.Errorf("stratum: wire fault id: id correlation error (mismatch / pseudo id / open-transaction reuse)")
	case "job":
		return fmt.Errorf("stratum: wire fault job: job correlation error (job_id not from this session or username mismatch)")
	case "carrier":
		return fmt.Errorf("stratum: wire fault carrier: carrier/layer-chain/port error (tcp carrier required)")
	case "address_family":
		return fmt.Errorf("stratum: wire fault address_family: ip address family mismatch (IPv6 address on an IPv4 chain or vice versa)")
	case "propagation":
		return fmt.Errorf("stratum: wire fault propagation: known error must propagate as a task error, never a fake success")
	default:
		return fmt.Errorf("stratum: unknown wire_fault kind %q", kind)
	}
}
