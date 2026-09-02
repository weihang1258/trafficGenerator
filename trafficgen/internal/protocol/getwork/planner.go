// Package getwork planner: negative-path validation (17 wire_fault kinds,
// design §7 一行一注入 — 与设计 §7 表/用例 §5 表三方同序) plus structural
// config checks. Every rejected spec must surface as a task error — never a
// completed/0-packet or TCP/HTTP-shell fake success.
package getwork

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Validate checks a getwork flow spec. cfg == nil (bare {"getwork":{}} layer)
// passes: the generator emits the default baseline session.
func Validate(spec core.FlowSpec) error {
	cfg := spec.GetWork
	if cfg == nil {
		return nil
	}
	if err := validateWireFault(cfg.WireFault); err != nil {
		return err
	}
	for si, sess := range cfg.Sessions {
		if err := validateSession(sess, si); err != nil {
			return err
		}
	}
	return nil
}

// validateSession structurally checks one session's events: kind/method/
// params shapes, work correlation, and result kinds. These mirror the
// wire-fault families so a hand-written config typo fails with the same
// anchors.
func validateSession(sess core.GetWorkSession, si int) error {
	hasWork := false
	for ei, ev := range sess.Events {
		prefix := fmt.Sprintf("getwork: sessions[%d].events[%d]", si, ei)
		switch ev.Kind {
		case "request":
			if ev.Method != "getwork" {
				return fmt.Errorf("%s: unknown method %q (supported: getwork; the submit IS a getwork call with a single data param)", prefix, ev.Method)
			}
			if err := validateParams(ev, hasWork, prefix); err != nil {
				return err
			}
		case "response":
			switch ev.ResultKind {
			case "", "work", "true", "false", "object", "error_object":
			default:
				return fmt.Errorf("%s: unknown result_kind %q", prefix, ev.ResultKind)
			}
			switch ev.Status {
			case 0, 200, 401, 500:
			default:
				return fmt.Errorf("%s: invalid status %d (supported: 200, 401, 500)", prefix, ev.Status)
			}
			if ev.Status == 401 && ev.ResultKind != "" && ev.ResultKind != "error_object" {
				return fmt.Errorf("%s: status 401 carries no JSON body (result_kind must be empty)", prefix)
			}
			if ev.ResultKind == "work" || (ev.ResultKind == "" && ev.Status != 401 && ev.Status != 500) {
				hasWork = true
			}
		case "":
			return fmt.Errorf("%s: missing kind (request|response)", prefix)
		default:
			return fmt.Errorf("%s: unknown kind %q (request|response)", prefix, ev.Kind)
		}
	}
	return nil
}

// validateParams checks the two getwork call forms (design §3.2, G-2):
// apply = [] only; submit = exactly ["<data 256 hex>"] (nonce-correlated
// with the session's latest work).
func validateParams(ev core.GetWorkEvent, hasWork bool, prefix string) error {
	if ev.ParamsFrom != "" {
		if ev.ParamsFrom != "work.data_nonce_modified" {
			return fmt.Errorf("%s: unknown params_from %q (supported: work.data_nonce_modified)", prefix, ev.ParamsFrom)
		}
		if !hasWork {
			return fmt.Errorf("%s: params_from requires a prior work response in the session (no work to correlate)", prefix)
		}
		if len(ev.Params) > 0 {
			return fmt.Errorf("%s: params and params_from are mutually exclusive", prefix)
		}
		return nil
	}
	var params []json.RawMessage
	if len(ev.Params) > 0 {
		if err := json.Unmarshal(ev.Params, &params); err != nil {
			return fmt.Errorf("%s: getwork params must be an array: %v", prefix, err)
		}
	}
	switch len(params) {
	case 0: // apply
		return nil
	case 1: // submit: ["<data>"]
		var data string
		if err := json.Unmarshal(params[0], &data); err != nil {
			return fmt.Errorf("%s: getwork submit params[0] (data) must be a hex string", prefix)
		}
		if !isHex(data) {
			return fmt.Errorf("%s: getwork data must be hexadecimal", prefix)
		}
		if len(data) != 256 {
			return fmt.Errorf("%s: getwork data length must be exactly 256 hex characters (128B), got %d", prefix, len(data))
		}
		if !hasWork {
			return fmt.Errorf("%s: submit data has no correlation with the session's latest work (no prior work response)", prefix)
		}
		if !strings.HasPrefix(data, FixtureDataWork[:FixtureSubmitPos]) && !strings.HasPrefix(data, FixtureDataWork2[:FixtureSubmitPos]) {
			return fmt.Errorf("%s: submit data does not correlate with the session's latest work (first 152 hex must match)", prefix)
		}
	default:
		return fmt.Errorf("%s: getwork params accepts at most one data element (submit form [data]), got %d", prefix, len(params))
	}
	return nil
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// validateWireFault dispatches the 17 sanctioned single-injection faults
// (design §7; each error carries the row's 主锚词 so error_contains matches).
func validateWireFault(wf *core.GetWorkWireFault) error {
	if wf == nil {
		return nil
	}
	switch wf.Kind {
	case "bad_json":
		return fmt.Errorf("getwork: wire fault bad_json: request body is not valid json")
	case "body_truncated":
		return fmt.Errorf("getwork: wire fault body_truncated: body truncated (content-length exceeds the actual body bytes)")
	case "content_length_mismatch":
		return fmt.Errorf("getwork: wire fault content_length_mismatch: content-length header does not match the body byte count")
	case "unknown_method":
		v := wf.Value
		if v == "" {
			v = "getblocktemplate"
		}
		return fmt.Errorf("getwork: wire fault unknown_method: method %q is not supported (BIP 22 getblocktemplate is an explicit boundary; only getwork)", v)
	case "getwork_params_nonempty":
		return fmt.Errorf("getwork: wire fault getwork_params_nonempty: getwork apply params must be an empty array (nonempty rejected)")
	case "submit_two_params":
		return fmt.Errorf("getwork: wire fault submit_two_params: getwork submit params accepts exactly one data element (two params rejected)")
	case "data_not_hex":
		return fmt.Errorf("getwork: wire fault data_not_hex: getwork data must be hexadecimal (non-hex rejected)")
	case "data_length":
		return fmt.Errorf("getwork: wire fault data_length: getwork data length must be exactly 256 hex characters (128B)")
	case "field_missing":
		return fmt.Errorf("getwork: wire fault field_missing: work required field missing: hash1")
	case "submit_work_uncorrelated":
		return fmt.Errorf("getwork: wire fault submit_work_uncorrelated: submit data correlation with the session's latest work failed (first 152 hex mismatch)")
	case "id_mismatch":
		return fmt.Errorf("getwork: wire fault id_mismatch: response id does not match the request id")
	case "cross_session_work":
		return fmt.Errorf("getwork: wire fault cross_session_work: submit references another session's work (cross-session work consumption rejected)")
	case "udp_carrier":
		return fmt.Errorf("getwork: wire fault udp_carrier: unsupported carrier (getwork requires TCP; UDP rejected)")
	case "port_undeclared":
		return fmt.Errorf("getwork: wire fault port_undeclared: non-default port not explicitly declared (8332/80 must be explicit)")
	case "address_family":
		return fmt.Errorf("getwork: wire fault address_family: address family mismatch (IPv6 address on an IPv4 layer chain or vice versa)")
	case "http_method_get":
		return fmt.Errorf("getwork: wire fault http_method_get: getwork requests must use post (GET carrier rejected)")
	case "error_propagation":
		v := wf.Value
		if v == "" {
			v = "bad_json"
		}
		return fmt.Errorf("getwork: wire fault error_propagation: injected fault (%s) must propagate as a task error, never a fake success", v)
	default:
		return fmt.Errorf("getwork: unknown wire_fault kind %q", wf.Kind)
	}
}
