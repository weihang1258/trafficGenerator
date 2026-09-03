// Package ethmining planner: negative-path validation (10 wire_fault kinds,
// design §7 一行一注入 — 与设计 §7 表/用例 §5 表三方同序) plus the session
// state machine and correlation checks (§5). Every rejected spec must surface
// as a task error — never a completed/0-packet or TCP-shell fake success.
package ethmining

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Validate checks an ethmining flow spec. cfg == nil (bare {"ethmining":{}}
// layer) passes: the generator emits the default baseline session
// (subscribe only, design §1/§6 baseline).
func Validate(spec core.FlowSpec) error {
	cfg := spec.ETHMining
	if cfg == nil {
		return nil
	}
	if cfg.WireFault != "" {
		if err := validateWireFault(cfg.WireFault); err != nil {
			return err
		}
	}
	if cfg.HexPrefix != "" && cfg.HexPrefix != "0x" {
		return fmt.Errorf("ethmining: hex_prefix must be empty or \"0x\" (got %q)", cfg.HexPrefix)
	}
	for si, sess := range cfg.Sessions {
		if err := validateSession(sess, si, cfg.HexPrefix); err != nil {
			return err
		}
	}
	return nil
}

// validateSession walks one session's events enforcing the miner-side state
// machine (design §5) and the per-message param shapes (§3). State tracked:
// subscribed / authorized / current extranonce (≤3 bytes hex) / seen jobs /
// authorized username / open request ids.
func validateSession(sess core.ETHMiningSession, si int, hexPrefix string) error {
	prefix := fmt.Sprintf("ethmining: sessions[%d]", si)
	subscribed := false
	authorized := false
	authUser := ""
	var extranonce string
	jobs := map[string]bool{}
	firstApp := true
	closed := false
	ids := map[string]bool{}
	strip := stripPrefix(hexPrefix)
	for ei, ev := range sess.Events {
		ep := fmt.Sprintf("%s.events[%d]", prefix, ei)
		if closed {
			return fmt.Errorf("%s: event after close (state)", ep)
		}
		// State machine: first application message MUST be subscribe
		// (spec §III: "Miner sends data first").
		if firstApp {
			firstApp = false
			if ev.Kind != "subscribe" {
				return fmt.Errorf("%s: first application message must be subscribe (state machine, spec §III), got %q", ep, ev.Kind)
			}
		}
		if ev.Kind == "" {
			return fmt.Errorf("%s: missing kind", ep)
		}
		switch ev.Kind {
		case "subscribe":
			if len(ev.ID) == 0 || string(ev.ID) == "null" {
				return fmt.Errorf("%s: subscribe request id must be a JSON number (id: %s)", ep, string(ev.ID))
			}
			ids[string(ev.ID)] = true
			if ev.UserAgent == "" {
				return fmt.Errorf("%s: subscribe params[0] user_agent is required (params; 2-element form [ua,proto])", ep)
			}
			if ev.Protocol == "" {
				return fmt.Errorf("%s: subscribe params[1] protocol is required (params; 2-element form [ua,proto])", ep)
			}
			if ev.Protocol != FixtureProtocol {
				return fmt.Errorf("%s: subscribe params[1] protocol must be %q (got %q)", ep, FixtureProtocol, ev.Protocol)
			}
			if ev.SubscriptionID != "" {
				if err := checkHexField(ep, "subscription_id", ev.SubscriptionID, 0, strip); err != nil {
					return err
				}
			}
			if ev.Extranonce != "" {
				if err := checkExtranonceField(ep, "extranonce", ev.Extranonce, strip); err != nil {
					return err
				}
				extranonce = stripHexPrefix(ev.Extranonce, strip)
			} else {
				extranonce = FixtureExtranonce
			}
			subscribed = true
		case "extranonce_subscribe":
			if !subscribed {
				return fmt.Errorf("%s: extranonce_subscribe before subscribe (state)", ep)
			}
			if len(ev.ID) == 0 || string(ev.ID) == "null" {
				return fmt.Errorf("%s: extranonce_subscribe request id must be a JSON number (id: %s)", ep, string(ev.ID))
			}
			ids[string(ev.ID)] = true
		case "authorize":
			if !subscribed {
				return fmt.Errorf("%s: authorize before subscribe (state, spec §III initial handshake)", ep)
			}
			if len(ev.ID) == 0 || string(ev.ID) == "null" {
				return fmt.Errorf("%s: authorize request id must be a JSON number (id: %s)", ep, string(ev.ID))
			}
			ids[string(ev.ID)] = true
			if ev.Username == "" {
				return fmt.Errorf("%s: authorize params must be [username, password] (params; 2-element form)", ep)
			}
			if ev.Password == "" {
				return fmt.Errorf("%s: authorize params must be [username, password] (params; 2-element form)", ep)
			}
			authUser = ev.Username
			if ev.Result != nil && string(ev.Result) == "false" {
				// 拒绝路径（正例 4 形态）：authorize 拒绝后不得 submit。
				authorized = false
				authUser = ""
			} else {
				authorized = true
			}
		case "set_difficulty":
			if !subscribed {
				return fmt.Errorf("%s: set_difficulty before subscribe (state)", ep)
			}
			if len(ev.Difficulty) > 0 && !isJSONNumber(ev.Difficulty) {
				return fmt.Errorf("%s: set_difficulty params[0] must be a JSON number (params, decimal fixed point)", ep)
			}
		case "notify":
			if !subscribed {
				return fmt.Errorf("%s: notify before subscribe (state)", ep)
			}
			if len(ev.ID) > 0 && string(ev.ID) != "null" {
				return fmt.Errorf("%s: notify must carry id null (id: %s)", ep, string(ev.ID))
			}
			if ev.JobID == "" {
				return fmt.Errorf("%s: notify params[0] job_id is required (params; 4-element form)", ep)
			}
			if err := checkHexField(ep, "job_id", ev.JobID, 0, strip); err != nil {
				return err
			}
			if err := checkHexField(ep, "seed_hash", ev.SeedHash, 64, strip); err != nil {
				return err
			}
			if err := checkHexField(ep, "header_hash", ev.HeaderHash, 64, strip); err != nil {
				return err
			}
			jobs[stripHexPrefix(ev.JobID, strip)] = true
		case "set_extranonce":
			if !subscribed {
				return fmt.Errorf("%s: set_extranonce before subscribe (state)", ep)
			}
			// Bitcoin stratum's 2-element form [en, size] is the wrong
			// dialect for ethash; refuse early so the negative case
			// (params anchor) hits both params and method axes.
			if ev.NewExtranonce == "" {
				return fmt.Errorf("%s: set_extranonce params must be [extranonce] — 1 element (params; 2-element form is the bitcoin stratum dialect)", ep)
			}
			if err := checkExtranonceField(ep, "new_extranonce", ev.NewExtranonce, strip); err != nil {
				return err
			}
			extranonce = stripHexPrefix(ev.NewExtranonce, strip)
		case "submit":
			if !subscribed {
				return fmt.Errorf("%s: submit before subscribe (state)", ep)
			}
			if !authorized {
				return fmt.Errorf("%s: submit before authorize (state, spec §III initial handshake)", ep)
			}
			if len(ev.ID) == 0 || string(ev.ID) == "null" {
				return fmt.Errorf("%s: submit request id must be a JSON number (id: %s)", ep, string(ev.ID))
			}
			ids[string(ev.ID)] = true
			if ev.JobID == "" {
				return fmt.Errorf("%s: submit params[1] job_id is required (params; 3-element form)", ep)
			}
			jobKey := stripHexPrefix(ev.JobID, strip)
			if !jobs[jobKey] {
				return fmt.Errorf("%s: submit job_id %q not from this session's notify (job correlation, spec §III)", ep, ev.JobID)
			}
			if ev.Username != "" && ev.Username != authUser {
				return fmt.Errorf("%s: submit username %q does not match the authorized user (job correlation, spec §III)", ep, ev.Username)
			}
			if ev.MinerNonce == "" {
				return fmt.Errorf("%s: submit params[2] miner_nonce is required (params; 3-element form)", ep)
			}
			if err := checkMinerNonce(ep, "miner_nonce", ev.MinerNonce, extranonce, strip); err != nil {
				return err
			}
		case "close":
			closed = true
		default:
			return fmt.Errorf("%s: unknown event kind %q (unknown method or direction violation)", ep, ev.Kind)
		}
	}
	return nil
}

// stripPrefix returns the configured prefix for hex data fields ("" or
// "0x"); used to normalize before validation against the spec's no-prefix
// value domain.
func stripPrefix(p string) string { return p }

// stripHexPrefix removes the configured prefix from a hex data field (if
// present). Spec §3.1 default is no prefix; the "0x" dialect variant adds
// the prefix uniformly.
func stripHexPrefix(s, prefix string) string {
	if prefix == "" {
		return s
	}
	if strings.HasPrefix(s, prefix) {
		return s[len(prefix):]
	}
	return s
}

// checkExtranonceField enforces spec §3.3: ≤3 bytes (≤6 hex chars), even
// length, hex charset, prefix uniform.
func checkExtranonceField(prefix, name, val, hexPrefix string) error {
	body := stripHexPrefix(val, hexPrefix)
	if len(body) == 0 {
		return nil
	}
	if len(body)%2 != 0 {
		return fmt.Errorf("%s: %s length %d is odd (hex)", prefix, name, len(body))
	}
	if len(body) > 6 {
		return fmt.Errorf("%s: %s length %d hex exceeds 3-byte max (extranonce ≤3 bytes per spec §III)", prefix, name, len(body))
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("%s: %s contains non-hex character %q (hex)", prefix, name, c)
		}
	}
	return nil
}

// checkMinerNonce enforces spec §III "provided extranonce was X bytes…
// minernonce is 8-X bytes": byte count = 8 − len(extranonce)/2.
func checkMinerNonce(prefix, name, val, extranonce, hexPrefix string) error {
	body := stripHexPrefix(val, hexPrefix)
	if len(body) == 0 {
		return nil
	}
	if len(body)%2 != 0 {
		return fmt.Errorf("%s: %s length %d is odd (hex)", prefix, name, len(body))
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("%s: %s contains non-hex character %q (hex)", prefix, name, c)
		}
	}
	enBytes := len(extranonce) / 2
	nonceBytes := len(body) / 2
	want := 8 - enBytes
	if nonceBytes != want {
		return fmt.Errorf("%s: %s length must be %d hex chars (%d bytes) to complement %d-byte extranonce (got %d hex), spec §III", prefix, name, 2*want, want, enBytes, len(body))
	}
	return nil
}

// checkHexField enforces the hex field rules (design §3.1): ASCII lowercase
// hex, even length, prefix uniform; width>0 additionally pins the length.
func checkHexField(prefix, name, val string, width int, hexPrefix string) error {
	if val == "" {
		return nil
	}
	body := stripHexPrefix(val, hexPrefix)
	if len(body)%2 != 0 {
		return fmt.Errorf("%s: %s length %d is odd (hex)", prefix, name, len(body))
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("%s: %s contains non-hex character %q (hex)", prefix, name, c)
		}
	}
	if width > 0 && len(body) != width {
		return fmt.Errorf("%s: %s length must be exactly %d hex characters (hex, spec §3.7 %d-byte field)", prefix, name, width, width/2)
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

// validateWireFault dispatches the 10 sanctioned single-injection faults
// (design §7; each error carries the row's 主锚词 so error_contains matches).
func validateWireFault(kind string) error {
	switch kind {
	case "json":
		return fmt.Errorf("ethmining: wire fault json: line content is not valid json")
	case "framing":
		return fmt.Errorf("ethmining: wire fault framing: line framing error (missing LF / CRLF / private length prefix)")
	case "method":
		return fmt.Errorf("ethmining: wire fault method: unknown method or direction violation (unknown method, miner sending notify, or pool sending submit)")
	case "params":
		return fmt.Errorf("ethmining: wire fault params: params element count/type/position error (subscribe 1-element, authorize 1-element, notify 3-element, submit 2-element, set_extranonce 2-element, clean_jobs non-bool, set_difficulty string param)")
	case "hex":
		return fmt.Errorf("ethmining: wire fault hex: hex field width/charset/prefix violation (seed_hash not 64, non-hex char, extranonce >3 bytes, complement mismatch, odd length, mixed 0x prefix)")
	case "state":
		return fmt.Errorf("ethmining: wire fault state: session state machine violation (first message not subscribe, submit before authorize, event after close)")
	case "id":
		return fmt.Errorf("ethmining: wire fault id: id correlation error (mismatch / pseudo id / session-internal id reuse)")
	case "job":
		return fmt.Errorf("ethmining: wire fault job: job correlation error (job_id not from this session's notify, or worker name mismatch)")
	case "carrier":
		return fmt.Errorf("ethmining: wire fault carrier: carrier/layer-chain/port error (tcp carrier required, mixed address family)")
	case "propagation":
		return fmt.Errorf("ethmining: wire fault propagation: known error must propagate as a task error, never a fake success")
	default:
		return fmt.Errorf("ethmining: unknown wire_fault kind %q", kind)
	}
}
