// Package doh planner: negative-path validation (26 wire_fault kinds,
// design §7 — one row one injection, 与设计 §7 表/用例 §5 表三方同序) plus
// structural config checks (QNAME 255/63 bounds, dns_id/TTL ranges, qtype/
// qclass tokens, method domain, GET Content-Type prohibition). Every rejected
// spec must surface as a task error — never a completed/0-packet or TCP/HTTP
// shell fake success.
package doh

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Validate checks a doh flow spec. cfg == nil (bare {"doh":{}} layer) passes:
// the generator emits the default baseline transaction.
func Validate(spec core.FlowSpec) error {
	cfg := spec.DOH
	if cfg == nil {
		return nil
	}
	if err := validateWireFault(cfg.WireFault); err != nil {
		return err
	}
	if cfg.Profile != "" && cfg.Profile != "doh_http1_plain" {
		return fmt.Errorf("doh: profile %q is not registered (main profile doh_http1_plain; https/http2/http3 are boundary-only)", cfg.Profile)
	}
	if cfg.Method != "" && cfg.Method != "POST" && cfg.Method != "GET" {
		return fmt.Errorf("doh: method must be POST or GET (got %q, wire fault method)", cfg.Method)
	}
	for si, sess := range cfg.Sessions {
		if err := validateSession(sess, si); err != nil {
			return err
		}
	}
	return nil
}

func validateSession(sess core.DOHSession, si int) error {
	prefix := fmt.Sprintf("doh: sessions[%d]", si)
	if sess.Method != "" && sess.Method != "POST" && sess.Method != "GET" {
		return fmt.Errorf("%s: method must be POST or GET (got %q, wire fault method)", prefix, sess.Method)
	}
	for ei, ev := range sess.Events {
		if err := validateEvent(ev, fmt.Sprintf("%s.events[%d]", prefix, ei)); err != nil {
			return err
		}
	}
	return nil
}

func validateEvent(ev core.DOHEvent, ep string) error {
	if ev.Kind != "" && ev.Kind != "query" {
		return fmt.Errorf("%s: kind must be \"query\" (got %q)", ep, ev.Kind)
	}
	if ev.DNSID < 0 || ev.DNSID > 65535 {
		return fmt.Errorf("%s: dns_id %d out of 16-bit range 0..65535 (wire fault dns_id_range)", ep, ev.DNSID)
	}
	if ev.Method != "" && ev.Method != "POST" && ev.Method != "GET" {
		return fmt.Errorf("%s: method must be POST or GET (got %q, wire fault method)", ep, ev.Method)
	}
	qname, err := EncodeQName(ev.Name)
	if err != nil {
		return fmt.Errorf("%s: %v (wire fault qname)", ep, err)
	}
	if len(qname) > 255 {
		return fmt.Errorf("%s: qname encoding is %d bytes, exceeds the 255-byte bound (wire fault qname)", ep, len(qname))
	}
	if _, err := ParseQType(ev.QType); err != nil {
		return fmt.Errorf("%s: %v (wire fault qtype_token)", ep, err)
	}
	if _, err := ParseQClass(ev.QClass); err != nil {
		return fmt.Errorf("%s: %v (wire fault qtype_token)", ep, err)
	}
	// GET 事务无 body 载体，禁携 Content-Type（会话级头覆盖泄漏，设计 §3.1）。
	if ev.Method == "GET" && ev.HTTP != nil {
		if hasHeader(ev.HTTP.RequestHeaders, "Content-Type") {
			return fmt.Errorf("%s: GET transaction must not carry a Content-Type header (no body carrier; content-type prohibited; wire fault get_content_type)", ep)
		}
	}
	if ev.Response != nil {
		if err := validateResponse(*ev.Response, ep); err != nil {
			return err
		}
	}
	return nil
}

func validateResponse(resp core.DOHResponse, ep string) error {
	if resp.Status < 0 || resp.Status > 599 {
		return fmt.Errorf("%s: response.status %d out of HTTP range", ep, resp.Status)
	}
	if _, err := ParseRCode(resp.RCode); err != nil {
		return fmt.Errorf("%s: %v", ep, err)
	}
	for ai, ans := range resp.Answers {
		if err := validateAnswer(ans, fmt.Sprintf("%s.response.answers[%d]", ep, ai)); err != nil {
			return err
		}
	}
	for ai, ans := range resp.Authority {
		if err := validateAnswer(ans, fmt.Sprintf("%s.response.authority[%d]", ep, ai)); err != nil {
			return err
		}
	}
	return nil
}

func validateAnswer(ans core.DOHAnswer, ap string) error {
	if ans.TTL < 0 || ans.TTL > 4294967295 {
		return fmt.Errorf("%s: ttl %d out of 32-bit range (wire fault ttl_range)", ap, ans.TTL)
	}
	if _, err := ParseQType(ans.Type); err != nil {
		return fmt.Errorf("%s: %v", ap, err)
	}
	if _, err := ParseQClass(ans.Class); err != nil {
		return fmt.Errorf("%s: %v", ap, err)
	}
	if ans.Name != "" {
		qn, err := EncodeQName(ans.Name)
		if err != nil {
			return fmt.Errorf("%s: %v", ap, err)
		}
		if len(qn) > 255 {
			return fmt.Errorf("%s: answer name exceeds 255 bytes", ap)
		}
	}
	// RDATA shape per type (RDLENGTH is always computed from the real RDATA,
	// so a mismatch is unrepresentable; malformed literals are config errors).
	switch t := ans.Type; t {
	case "A":
		if _, err := BuildA(ans.RData); err != nil {
			return fmt.Errorf("%s: %v", ap, err)
		}
	case "AAAA":
		if _, err := BuildAAAA(ans.RData); err != nil {
			return fmt.Errorf("%s: %v", ap, err)
		}
	case "TXT":
		strs := ans.TXTStrings
		if len(strs) == 0 {
			strs = []string{ans.RData}
		}
		if _, err := BuildTXT(strs); err != nil {
			return fmt.Errorf("%s: %v", ap, err)
		}
	case "CNAME", "NS", "PTR":
		if ans.RData == "" {
			return fmt.Errorf("%s: %s rdata (target name) is required", ap, t)
		}
		if _, err := EncodeQName(ans.RData); err != nil {
			return fmt.Errorf("%s: %v", ap, err)
		}
	case "MX":
		if ans.RData == "" {
			return fmt.Errorf("%s: MX rdata (exchange name) is required", ap)
		}
		if _, err := EncodeQName(ans.RData); err != nil {
			return fmt.Errorf("%s: %v", ap, err)
		}
	case "SOA":
		if ans.MName == "" || ans.RName == "" {
			return fmt.Errorf("%s: SOA requires mname and rname", ap)
		}
		if _, err := EncodeQName(ans.MName); err != nil {
			return fmt.Errorf("%s: %v", ap, err)
		}
		if _, err := EncodeQName(ans.RName); err != nil {
			return fmt.Errorf("%s: %v", ap, err)
		}
	case "HTTPS", "SVCB":
		if ans.Target != "" && ans.Target != "." {
			if _, err := EncodeQName(ans.Target); err != nil {
				return fmt.Errorf("%s: %v", ap, err)
			}
		}
		for pi, p := range ans.Params {
			if _, err := BuildSvcParam(p.Key, p.ValueHex); err != nil {
				return fmt.Errorf("%s.params[%d]: %v", ap, pi, err)
			}
		}
	}
	return nil
}

func hasHeader(headers map[string]string, name string) bool {
	for k := range headers {
		if equalFold(k, name) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 32
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// validateWireFault dispatches the 26 sanctioned single-injection faults
// (design §7; each error carries the row's 主锚词 so error_contains matches).
func validateWireFault(wf string) error {
	switch wf {
	case "":
		return nil
	case "query_missing":
		return fmt.Errorf("doh: wire fault query_missing: GET request must carry the dns query parameter (dns parameter missing)")
	case "base64":
		return fmt.Errorf("doh: wire fault base64: dns parameter is not base64url (base64 alphabet violation)")
	case "padding":
		return fmt.Errorf("doh: wire fault padding: dns parameter must not carry base64 padding (base64url unpadded)")
	case "b64_short":
		return fmt.Errorf("doh: wire fault b64_short: base64 decode yields fewer than 12 bytes (decode underflow)")
	case "dns_header_short":
		return fmt.Errorf("doh: wire fault dns_header_short: POST body shorter than the 12-byte dns header (dns body length)")
	case "qdcount":
		return fmt.Errorf("doh: wire fault qdcount: QDCOUNT=0 rejected — the question section is required (question count)")
	case "qname":
		return fmt.Errorf("doh: wire fault qname: QNAME exceeds 255 bytes or a label exceeds 63 (qname overflow)")
	case "question_truncated":
		return fmt.Errorf("doh: wire fault question_truncated: question missing the root label terminator or QTYPE/QCLASS truncated (question wire)")
	case "content_type":
		return fmt.Errorf("doh: wire fault content_type: Content-Type must be application/dns-message (content-type media)")
	case "method":
		return fmt.Errorf("doh: wire fault method: HTTP method must be GET or POST (method domain)")
	case "content_length":
		return fmt.Errorf("doh: wire fault content_length: Content-Length must equal the dns body bytes (content-length body)")
	case "layer_chain":
		return fmt.Errorf("doh: wire fault layer_chain: the [tcp,http,doh] chain requires the http carrier layer (carrier missing)")
	case "port_conflict":
		return fmt.Errorf("doh: wire fault port_conflict: port/carrier declaration conflicts with the plaintext profile (port conflict)")
	case "response_id":
		return fmt.Errorf("doh: wire fault response_id: response dns id must echo the request id (id mismatch)")
	case "response_question":
		return fmt.Errorf("doh: wire fault response_question: response question mismatched or 2xx without dns body (question body)")
	case "wire_over_max":
		return fmt.Errorf("doh: wire fault wire_over_max: dns message exceeds the 65535-byte length bound (length max)")
	case "opcode_nonzero":
		return fmt.Errorf("doh: wire fault opcode_nonzero: Opcode must be 0 QUERY (opcode value)")
	case "get_content_type":
		return fmt.Errorf("doh: wire fault get_content_type: GET transaction must not carry Content-Type (content-type get header)")
	case "response_qr":
		return fmt.Errorf("doh: wire fault response_qr: response must set QR=1 (response qr flag)")
	case "z_nonzero":
		return fmt.Errorf("doh: wire fault z_nonzero: the reserved Z bits must be 0 (z flag value)")
	case "rdlength_mismatch":
		return fmt.Errorf("doh: wire fault rdlength_mismatch: RDLENGTH must equal the RDATA byte count (rdlength answer)")
	case "ancount_mismatch":
		return fmt.Errorf("doh: wire fault ancount_mismatch: ANCOUNT must equal the answer count (ancount count)")
	case "qdcount_multi":
		return fmt.Errorf("doh: wire fault qdcount_multi: QDCOUNT>1 rejected — this version carries exactly one question (qdcount question)")
	case "dns_id_range":
		return fmt.Errorf("doh: wire fault dns_id_range: dns id out of the 16-bit range (id value)")
	case "ttl_range":
		return fmt.Errorf("doh: wire fault ttl_range: ttl out of the 32-bit range (ttl value)")
	case "qtype_token":
		return fmt.Errorf("doh: wire fault qtype_token: qtype/qclass must be a token or numeric value (qtype value token)")
	default:
		return fmt.Errorf("doh: unknown wire_fault %q", wf)
	}
}

// MaxDNSWire is the RFC 8484 §6 message-size bound enforced by the builder.
const MaxDNSWire = 65535
