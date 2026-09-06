// Package onvif planner: structural config validation (service/operation
// domains, per-operation mandatory parameters, duration format, token/int
// ranges, auth-required boundary, action-override rules, same_as_response
// closure) plus the 38-value wire_fault dispatch (design §7 — one row one
// injection, 主锚词 pinned). Every rejected spec surfaces as a task error.
package onvif

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Validate checks an onvif flow spec.
func Validate(spec core.FlowSpec) error {
	cfg := spec.ONVIF
	if cfg == nil {
		return nil
	}
	if err := validateWireFault(cfg.WireFault); err != nil {
		return err
	}
	if cfg.Profile != "" && cfg.Profile != "onvif_soap12_http" {
		return fmt.Errorf("onvif: profile %q is not registered (main profile onvif_soap12_http; https/wsdiscovery are boundary-only)", cfg.Profile)
	}
	if cfg.SoapVersion != "" && cfg.SoapVersion != "1.2" {
		return fmt.Errorf("onvif: soap_version must be 1.2 (Core Spec 5.7 pins SOAP 1.2 bindings; envelope namespace is not negotiable)")
	}
	for si, sess := range cfg.Sessions {
		for ei, ev := range sess.Events {
			if err := validateEvent(ev, cfg, si, ei, sess.Events); err != nil {
				return err
			}
		}
	}
	return nil
}

// durationRe validates xs:duration lexical form: P[nY][nM][nD][T[nH][nM][n.nS]].
// The leading "-" (for negative durations) is stripped by the caller.
var durationRe = regexp.MustCompile(`^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$`)

// validateEvent checks one transaction structurally. The event-level
// wire_fault dispatch (design §7) runs first so a negative case surfaces its
// pinned 主锚词 regardless of what else the event carries.
func validateEvent(ev core.ONVIFEvent, cfg *core.ONVIFConfig, si, ei int, sessEvents []core.ONVIFEvent) error {
	if err := validateWireFault(ev.WireFault); err != nil {
		return err
	}
	ep := fmt.Sprintf("onvif: sessions[%d].events[%d]", si, ei)
	if ev.Kind != "" && ev.Kind != "request" {
		return fmt.Errorf(`%s: kind must be "request" (got %q)`, ep, ev.Kind)
	}
	svc, ok := services[ev.Service]
	if !ok {
		return fmt.Errorf("%s: service %q is unknown (the four services are device/media/ptz/events; imaging and others are out of scope)", ep, ev.Service)
	}
	if !svc.Ops[ev.Operation] {
		return fmt.Errorf("%s: operation %q is not in the %s-service WSDL operation set (unknown operation)", ep, ev.Operation, ev.Service)
	}
	// Action override rules (design §3.3 D-1/D-5).
	if ev.Action != "" {
		tail := ev.Action[strings.LastIndex(ev.Action, "/")+1:]
		if tail == ev.Operation+"Response" || strings.HasSuffix(tail, "Response") {
			return fmt.Errorf("%s: request action %q already carries the Response suffix (the derived response action would double it; action suffix rule)", ep, ev.Action)
		}
		want := ev.Operation
		if tail != want && tail != want+"Request" {
			return fmt.Errorf("%s: declared action %q does not match the body operation %q (action/operation mismatch)", ep, ev.Action, ev.Operation)
		}
	}
	// MessageID form.
	if ev.MessageID != "" && ev.MessageID != "auto" && !strings.HasPrefix(ev.MessageID, "urn:uuid:") {
		return fmt.Errorf("%s: message_id %q must be \"auto\" or a urn:uuid: form", ep, ev.MessageID)
	}
	p := ev.Parameters
	getStr := func(k string) string {
		if p == nil {
			return ""
		}
		s, _ := p[k].(string)
		return s
	}
	// Per-operation mandatory parameters (WSDL).
	switch ev.Operation {
	case "GetStreamUri":
		if p == nil {
			return fmt.Errorf("%s: GetStreamUri requires the stream_setup and profile_token parameters (missing parameter)", ep)
		}
		if _, ok := p["stream_setup"].(map[string]interface{}); !ok {
			return fmt.Errorf("%s: GetStreamUri is missing the mandatory stream_setup parameter (parameter missing)", ep)
		}
		if getStr("profile_token") == "" {
			return fmt.Errorf("%s: GetStreamUri is missing the mandatory profile_token parameter (parameter missing)", ep)
		}
	case "GetSnapshotUri", "ContinuousMove", "Stop":
		if getStr("profile_token") == "" {
			return fmt.Errorf("%s: %s is missing the mandatory profile_token parameter (parameter missing)", ep, ev.Operation)
		}
	case "PullMessages":
		if p == nil {
			return fmt.Errorf("%s: PullMessages requires the timeout and message_limit parameters (missing parameter)", ep)
		}
		if _, ok := p["timeout"]; !ok {
			return fmt.Errorf("%s: PullMessages is missing the mandatory timeout parameter (parameter missing)", ep)
		}
		if _, ok := p["message_limit"]; !ok {
			return fmt.Errorf("%s: PullMessages is missing the mandatory message_limit parameter (parameter missing)", ep)
		}
	}
	// Duration format (xs:duration) on timeout / initial_termination_time
	// (relative form).
	for _, d := range []string{getStr("timeout"), getStr("initial_termination_time")} {
		if d == "" {
			continue
		}
		if !isDurationOrDateTime(d) {
			return fmt.Errorf("%s: %q is not an xs:duration or dateTime value (parameter duration form)", ep, d)
		}
	}
	// ProfileToken maxLength 64 (common.xsd tt:ReferenceToken).
	if tok := getStr("profile_token"); len(tok) > 64 {
		return fmt.Errorf("%s: profile_token is %d bytes, exceeds the tt:ReferenceToken maxLength of 64 (token length)", ep, len(tok))
	}
	// MessageLimit xs:int range (accepts both JSON number forms: float64
	// from encoding/json into interface{}, and json.Number from
	// UseNumber decoders).
	if p != nil {
		ml, ok := messageLimitValue(p["message_limit"])
		if ok && (ml > 2147483647 || ml < -2147483648) {
			return fmt.Errorf("%s: message_limit %d is out of the xs:int 32-bit range (limit range)", ep, ml)
		}
	}
	// Auth-required boundary (READ_SYSTEM ops: auth declaration or an
	// explicit error-response declaration).
	if requiresAuth(ev.Operation) && ev.Auth == nil {
		status := 200
		if ev.Response != nil && ev.Response.HTTPStatus != 0 {
			status = ev.Response.HTTPStatus
		}
		if status == 200 {
			return fmt.Errorf("%s: %s is a READ_SYSTEM operation and carries neither an auth declaration nor an error-response declaration (auth credential required)", ep, ev.Operation)
		}
	}
	// same_as_response closure (both the to-reference and parameter refs —
	// resolveRef reports the exact violation).
	if _, err := ResolveEvent(sessEvents[ei], sessEvents, ei); err != nil {
		return fmt.Errorf("%s: %v", ep, err)
	}
	return nil
}

// isDurationOrDateTime accepts xs:duration forms (PT5S/PT1M/PT0S/PT10S...)
// and absolute dateTime forms (2026-09-02T00:00:00Z).
func isDurationOrDateTime(s string) bool {
	if strings.HasPrefix(s, "P") || strings.HasPrefix(s, "-P") {
		return durationLoose(s)
	}
	return strings.Contains(s, "T") && len(s) >= 19
}

// durationLoose validates the xs:duration lexical shape without a regex
// lookahead (Go RE2): [-]P[nY][nM][nD][T[nH][nM][n.nS]] with at least one
// component.
func durationLoose(s string) bool {
	t := strings.TrimPrefix(s, "-")
	t = strings.TrimPrefix(t, "P")
	if t == "" {
		return false
	}
	timePart := false
	any := false
	i := 0
	for i < len(t) {
		if t[i] == 'T' {
			if timePart {
				return false
			}
			timePart = true
			i++
			continue
		}
		start := i
		for i < len(t) && (t[i] >= '0' && t[i] <= '9' || t[i] == '.') {
			i++
		}
		if i == start || i >= len(t) {
			return false
		}
		unit := t[i]
		if timePart {
			if unit != 'H' && unit != 'M' && unit != 'S' {
				return false
			}
		} else {
			if unit != 'Y' && unit != 'M' && unit != 'D' {
				return false
			}
		}
		any = true
		i++
	}
	return any
}

// validateWireFault dispatches the 38 sanctioned single-injection faults
// (design §7; each error carries the row's 主锚词).
func validateWireFault(wf string) error {
	switch wf {
	case "":
		return nil
	case "soap_envelope_ns":
		return fmt.Errorf("onvif: wire fault soap_envelope_ns: envelope namespace must be http://www.w3.org/2003/05/soap-envelope (SOAP 1.2 pinned; the 1.1 envelope namespace is a wire-format error)")
	case "soap_truncated":
		return fmt.Errorf("onvif: wire fault soap_truncated: the envelope xml must be well-formed and closed (truncated xml rejected)")
	case "soap_body_missing":
		return fmt.Errorf("onvif: wire fault soap_body_missing: the s:Body element is mandatory (envelope without a body rejected)")
	case "soap_header_order":
		return fmt.Errorf("onvif: wire fault soap_header_order: the s:Header element must precede the s:Body (header order rejected)")
	case "content_type":
		return fmt.Errorf("onvif: wire fault content_type: Content-Type must be application/soap+xml (text/xml is the SOAP 1.1 media type; content-type rejected)")
	case "charset_missing":
		return fmt.Errorf("onvif: wire fault charset_missing: Content-Type must carry charset=utf-8 (missing charset parameter)")
	case "charset_wrong":
		return fmt.Errorf("onvif: wire fault charset_wrong: charset must be utf-8 (gbk and others rejected; charset encoding)")
	case "action_mismatch":
		return fmt.Errorf("onvif: wire fault action_mismatch: the declared action does not match the body operation (action mismatch rejected)")
	case "action_suffix":
		return fmt.Errorf("onvif: wire fault action_suffix: the request action must not already carry the Response suffix (action derivation rule)")
	case "addressing_action":
		return fmt.Errorf("onvif: wire fault addressing_action: the request must carry a wsa:Action header (addressing action required)")
	case "addressing_message_id":
		return fmt.Errorf("onvif: wire fault addressing_message_id: the request must carry a wsa:MessageID header (message addressing required)")
	case "addressing_relates":
		return fmt.Errorf("onvif: wire fault addressing_relates: the response wsa:RelatesTo must equal the request wsa:MessageID (relates correlation)")
	case "addressing_ns":
		return fmt.Errorf("onvif: wire fault addressing_ns: the wsa namespace must be http://www.w3.org/2005/08/addressing (addressing namespace)")
	case "operation_unknown":
		return fmt.Errorf("onvif: wire fault operation_unknown: the operation is outside the WSDL operation set (unknown operation)")
	case "operation_ns":
		return fmt.Errorf("onvif: wire fault operation_ns: the operation/service namespace pair does not match the WSDL (namespace mismatch)")
	case "service_unknown":
		return fmt.Errorf("onvif: wire fault service_unknown: the service is outside the four supported services (unknown service)")
	case "parameter_stream_setup":
		return fmt.Errorf("onvif: wire fault parameter_stream_setup: GetStreamUri is missing the mandatory stream_setup parameter (parameter missing)")
	case "parameter_profile_token":
		return fmt.Errorf("onvif: wire fault parameter_profile_token: the operation is missing the mandatory profile_token parameter (parameter missing)")
	case "parameter_timeout":
		return fmt.Errorf("onvif: wire fault parameter_timeout: PullMessages is missing the mandatory timeout parameter (parameter missing)")
	case "parameter_message_limit":
		return fmt.Errorf("onvif: wire fault parameter_message_limit: PullMessages is missing the mandatory message_limit parameter (parameter missing)")
	case "parameter_duration":
		return fmt.Errorf("onvif: wire fault parameter_duration: the timeout value is not an xs:duration form (parameter duration)")
	case "auth_missing":
		return fmt.Errorf("onvif: wire fault auth_missing: a READ_SYSTEM transaction carries neither credentials nor an error-response declaration (auth credential required)")
	case "token_nonce":
		return fmt.Errorf("onvif: wire fault token_nonce: the UsernameToken must carry a Nonce (nonce+created are both mandatory; token nonce)")
	case "token_created":
		return fmt.Errorf("onvif: wire fault token_created: the UsernameToken must carry a Created timestamp (nonce+created are both mandatory; token created)")
	case "carrier_layer":
		return fmt.Errorf("onvif: wire fault carrier_layer: the [tcp,http,onvif] chain requires the http carrier layer (layer carrier missing)")
	case "carrier_port":
		return fmt.Errorf("onvif: wire fault carrier_port: the port/carrier declaration conflicts with the plaintext profile (port carrier conflict)")
	case "carrier_wsdiscovery":
		return fmt.Errorf("onvif: wire fault carrier_wsdiscovery: WS-Discovery UDP 3702 is a boundary-only carrier and must not be configured as the main chain (carrier discovery)")
	case "fault_code":
		return fmt.Errorf("onvif: wire fault fault_code: the Fault response must carry s:Code (fault code required)")
	case "fault_reason":
		return fmt.Errorf("onvif: wire fault fault_reason: the Fault response must carry s:Reason (fault reason required)")
	case "fault_value":
		return fmt.Errorf("onvif: wire fault fault_value: the Code/Value is outside the SOAP 1.2 value set (code value rejected)")
	case "fault_subcode":
		return fmt.Errorf("onvif: wire fault fault_subcode: the Subcode value must carry the ter: prefix/namespace (subcode namespace)")
	case "length_truncation":
		return fmt.Errorf("onvif: wire fault length_truncation: the envelope byte count must match the declared length (length truncation)")
	case "length_content_length":
		return fmt.Errorf("onvif: wire fault length_content_length: Content-Length must equal the rendered envelope bytes (content-length mismatch)")
	case "subscription_source":
		return fmt.Errorf("onvif: wire fault subscription_source: the PullMessages wsa:To reference must point at a CreatePullPointSubscription event of the same session (subscription reference)")
	case "subscription_cross_session":
		return fmt.Errorf("onvif: wire fault subscription_cross_session: the subscription reference must not cross sessions (correlation session isolation)")
	case "token_range":
		return fmt.Errorf("onvif: wire fault token_range: profile_token exceeds the tt:ReferenceToken maxLength of 64 (token length)")
	case "message_limit_range":
		return fmt.Errorf("onvif: wire fault message_limit_range: message_limit is outside the xs:int 32-bit range (limit range)")
	case "wsnt_ns":
		return fmt.Errorf("onvif: wire fault wsnt_ns: the wsnt namespace must be http://docs.oasis-open.org/wsn/b-2 (wsnt namespace)")
	default:
		return fmt.Errorf("onvif: unknown wire_fault %q", wf)
	}
}

// messageLimitValue coerces the PullMessages message_limit parameter to an
// int64 (both encoding/json float64 and UseNumber json.Number forms).
func messageLimitValue(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	}
	return 0, false
}
