// Package gbt planner: negative-path validation (28 wire_fault kinds,
// design §7 一行一注入) plus structural config checks. Every rejected spec
// must surface as a task error — never a completed/0-packet or TCP/HTTP-shell
// fake success.
package gbt

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Validate checks a gbt flow spec. cfg == nil (bare {"gbt":{}} layer) passes:
// the generator emits the default baseline session.
func Validate(spec core.FlowSpec) error {
	cfg := spec.GBT
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
// params shapes and result kinds. These mirror the wire-fault families so a
// hand-written config typo fails with the same anchors.
func validateSession(sess core.GBTSession, si int) error {
	for ei, ev := range sess.Events {
		prefix := fmt.Sprintf("gbt: sessions[%d].events[%d]", si, ei)
		switch ev.Kind {
		case "request":
			switch ev.Method {
			case "getblocktemplate", "submitblock":
			case "":
				return fmt.Errorf("%s: request missing method", prefix)
			default:
				return fmt.Errorf("%s: unknown method %q (supported: getblocktemplate, submitblock)", prefix, ev.Method)
			}
			if err := validateParams(ev.Method, ev.Params, prefix); err != nil {
				return err
			}
		case "response":
			switch ev.ResultKind {
			case "", "template", "accepted_null", "reject_reason", "proposal_true", "proposal_reject", "error_object":
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
		case "":
			return fmt.Errorf("%s: missing kind (request|response)", prefix)
		default:
			return fmt.Errorf("%s: unknown kind %q (request|response)", prefix, ev.Kind)
		}
		if ev.Template == "refresh" {
			// refresh derives from the session's latest template; a refresh
			// before any template response has no base.
			seen := false
			for _, p := range sess.Events[:ei] {
				if p.Kind == "response" && p.ResultKind == "template" {
					seen = true
				}
			}
			if !seen {
				return fmt.Errorf("%s: refresh template requires a prior template response in the session", prefix)
			}
		}
	}
	return nil
}

// validateParams checks the two methods' params shapes (BIP 22):
// getblocktemplate params = [] or [options object]; submitblock params =
// [hexdata string] or [hexdata, workid string].
func validateParams(method string, raw json.RawMessage, prefix string) error {
	var params []json.RawMessage
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &params); err != nil {
			return fmt.Errorf("%s: %s params must be an array: %v", prefix, method, err)
		}
	}
	switch method {
	case "getblocktemplate":
		if len(params) > 1 {
			return fmt.Errorf("%s: getblocktemplate params accepts at most one options object", prefix)
		}
		if len(params) == 1 {
			var obj map[string]interface{}
			if err := json.Unmarshal(params[0], &obj); err != nil {
				return fmt.Errorf("%s: getblocktemplate params[0] must be an options object, got %s", prefix, jsonKind(params[0]))
			}
			for _, k := range sortedKeys(obj) {
				switch k {
				case "rules", "capabilities", "mode", "longpollid", "data":
				default:
					return fmt.Errorf("%s: unknown options member %q", prefix, k)
				}
			}
			if m, ok := obj["mode"]; ok {
				s, _ := m.(string)
				if s != "template" && s != "proposal" {
					return fmt.Errorf("%s: mode value %q invalid (template|proposal)", prefix, s)
				}
			}
		}
	case "submitblock":
		switch {
		case len(params) == 0:
			return fmt.Errorf("%s: submitblock params missing hexdata (params must be [hexdata] or [hexdata, workid])", prefix)
		case len(params) > 2:
			return fmt.Errorf("%s: submitblock params accepts at most [hexdata, workid] (got %d)", prefix, len(params))
		default:
			var s string
			if err := json.Unmarshal(params[0], &s); err != nil {
				return fmt.Errorf("%s: submitblock params[0] (hexdata) must be a hex string", prefix)
			}
			if !isHex(s) {
				return fmt.Errorf("%s: submitblock hexdata must be hexadecimal", prefix)
			}
		}
	}
	return nil
}

func jsonKind(raw json.RawMessage) string {
	r := strings.TrimSpace(string(raw))
	if r == "" {
		return "empty"
	}
	switch r[0] {
	case '"':
		return "string"
	case '[':
		return "array"
	case '{':
		return "object"
	case 't', 'f':
		return "bool"
	case 'n':
		return "null"
	}
	return "number"
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

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}

// validateWireFault dispatches the 28 sanctioned single-injection faults
// (design §7; each error carries the row's 主锚词 so error_contains matches).
func validateWireFault(wf *core.GBTWireFault) error {
	if wf == nil {
		return nil
	}
	switch wf.Kind {
	case "bad_json":
		return fmt.Errorf("gbt: wire fault bad_json: request body is not valid json")
	case "body_truncated":
		return fmt.Errorf("gbt: wire fault body_truncated: body truncated (content-length exceeds the actual body bytes)")
	case "content_length_mismatch":
		return fmt.Errorf("gbt: wire fault content_length_mismatch: content-length header does not match the body byte count")
	case "unknown_method":
		v := wf.Value
		if v == "" {
			v = "getwork"
		}
		return fmt.Errorf("gbt: wire fault unknown_method: method %q is not supported (only getblocktemplate and submitblock; getwork is a separate family)", v)
	case "template_params_nonobject":
		return fmt.Errorf("gbt: wire fault template_params_nonobject: getblocktemplate params[0] must be an options object, got %s", jsonKind(json.RawMessage(wf.Value)))
	case "submitblock_no_hexdata":
		return fmt.Errorf("gbt: wire fault submitblock_no_hexdata: submitblock params missing hexdata (empty params array)")
	case "submitblock_third_param":
		return fmt.Errorf("gbt: wire fault submitblock_third_param: submitblock params exceed the BIP 22 form [hexdata, workid]")
	case "prevhash_length":
		return fmt.Errorf("gbt: wire fault prevhash_length: previousblockhash length must be exactly 64 hex characters")
	case "bits_length":
		return fmt.Errorf("gbt: wire fault bits_length: bits length must be exactly 8 hex characters")
	case "noncerange_length":
		return fmt.Errorf("gbt: wire fault noncerange_length: noncerange length must be exactly 16 hex characters")
	case "target_length":
		return fmt.Errorf("gbt: wire fault target_length: target length must be exactly 64 hex characters")
	case "field_missing":
		return fmt.Errorf("gbt: wire fault field_missing: template required field missing: height")
	case "workid_mismatch":
		return fmt.Errorf("gbt: wire fault workid_mismatch: submitblock workid does not match the session's latest template workid")
	case "id_mismatch":
		return fmt.Errorf("gbt: wire fault id_mismatch: response id does not match the request id")
	case "longpollid_missing":
		return fmt.Errorf("gbt: wire fault longpollid_missing: longpoll request params missing longpollid (BIP 22)")
	case "longpollid_stale":
		return fmt.Errorf("gbt: wire fault longpollid_stale: longpollid is not the session's latest template id (stale)")
	case "height_nonincrement":
		return fmt.Errorf("gbt: wire fault height_nonincrement: refreshed template height must increment by exactly 1")
	case "mode_invalid":
		v := wf.Value
		if v == "" {
			v = "template-x"
		}
		return fmt.Errorf("gbt: wire fault mode_invalid: options mode %q invalid (template|proposal)", v)
	case "unknown_rule":
		v := wf.Value
		if v == "" {
			v = "taproot"
		}
		return fmt.Errorf("gbt: wire fault unknown_rule: rule %q is not in the supported set {segwit}", v)
	case "bip9_field":
		return fmt.Errorf("gbt: wire fault bip9_field: unsupported template field vbavailable/vbrequired (BIP 9 out of scope)")
	case "witness_commitment":
		return fmt.Errorf("gbt: wire fault witness_commitment: unsupported template field default_witness_commitment (BIP 145 out of scope)")
	case "coinbasetxn_form":
		return fmt.Errorf("gbt: wire fault coinbasetxn_form: unsupported coinbasetxn template form (coinbaseaux/coinbasevalue only)")
	case "line_profile":
		v := wf.Value
		if v == "" {
			v = "jsonrpc-line"
		}
		return fmt.Errorf("gbt: wire fault line_profile: unsupported carrier profile %q (gbt is HTTP JSON-RPC only; no TCP line carrier)", v)
	case "udp_carrier":
		return fmt.Errorf("gbt: wire fault udp_carrier: unsupported carrier (gbt requires TCP; UDP rejected)")
	case "port_undeclared":
		return fmt.Errorf("gbt: wire fault port_undeclared: non-default port not explicitly declared (8332/18332 must be explicit)")
	case "address_family":
		return fmt.Errorf("gbt: wire fault address_family: address family mismatch (IPv6 address on an IPv4 layer chain or vice versa)")
	case "http_method_get":
		return fmt.Errorf("gbt: wire fault http_method_get: gbt requests must use post (GET carrier rejected)")
	case "error_propagation":
		v := wf.Value
		if v == "" {
			v = "bad_json"
		}
		return fmt.Errorf("gbt: wire fault error_propagation: injected fault (%s) must propagate as a task error, never a fake success", v)
	default:
		return fmt.Errorf("gbt: unknown wire_fault kind %q", wf.Kind)
	}
}
