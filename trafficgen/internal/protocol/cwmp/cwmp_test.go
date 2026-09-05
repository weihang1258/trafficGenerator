// Package cwmp test suite (spec-driven: design v2.2.2 / testcase v3.1.1).
// Each test maps to a row in docs/protocol-designs/64-cwmp-testcase.md §2
// (112 positive + 38 negative = 150) or §7 negative families. Byte-level
// assertions pin the wire format (envelope NS / faultcode / status / event
// code / OUI / length bounds); negative cases route through Validate and
// pin the error_contains anchor word from design §7.
package cwmp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// BuildInformPayload renders the soap:Body inner XML only; namespace
// declarations live on the envelope (§3.1 SOAP 1.1 envelope pinned:
// xmlns:soap=http://schemas.xmlsoap.org/soap/envelope/, xmlns:cwmp=urn:
// dslforum-org:cwmp-1-0, mustUnderstand=1 on cwmp:ID).
func TestBuildInformPayload_ExactBytes(t *testing.T) {
	payload := BuildInformPayload(FixtureDeviceID(),
		[]core.CWMPSOAPEvent{{Code: "2 PERIODIC"}}, nil, FixtureCurrentTime, nil, nil)
	env := string(BuildEnvelope(FixtureNamespace, "1", payload))
	// Pin the SOAP 1.1 envelope namespace literal.
	if !strings.Contains(env, SOAPEnvelopeNS) {
		t.Errorf("envelope missing SOAP 1.1 namespace %q", SOAPEnvelopeNS)
	}
	// Pin the CWMP namespace declaration.
	if !strings.Contains(env, `xmlns:cwmp="`+FixtureNamespace+`"`) {
		t.Errorf("envelope missing CWMP namespace declaration %q", FixtureNamespace)
	}
	// Pin the Event code 2 PERIODIC (empty CommandKey self-closes, #44).
	if !strings.Contains(payload, "<EventStruct><EventCode>2 PERIODIC</EventCode><CommandKey/></EventStruct>") {
		t.Errorf("EventStruct for 2 PERIODIC not pinned: %s", payload)
	}
	// DeviceIdStruct members unqualified (§3.5).
	if !strings.Contains(payload, "<OUI>001122</OUI>") {
		t.Errorf("OUI not rendered: %s", payload)
	}
}

// BuildEnvelope must contain mustUnderstand="1" on cwmp:ID (§3.2).
func TestBuildEnvelope_MustUnderstand1(t *testing.T) {
	body := string(BuildEnvelope(FixtureNamespace, "1", "<cwmp:Test/>"))
	if !strings.Contains(body, `cwmp:ID soap:mustUnderstand="1"`) {
		t.Errorf("envelope missing mustUnderstand=1: %s", body)
	}
	if !strings.Contains(body, ">1</cwmp:ID>") {
		t.Errorf("envelope missing ID body")
	}
}

// Empty POST has no SOAPAction / no Content-Type (§3.3).
func TestBuildRequest_EmptyPostNoHeaders(t *testing.T) {
	b := string(BuildRequest("POST", "/", "192.0.2.1:7547", "", "", "", SOAPActionOmit, nil, "", nil, "close"))
	if strings.Contains(b, "SOAPAction:") {
		t.Errorf("empty POST must not carry SOAPAction header: %s", b)
	}
	if strings.Contains(b, "Content-Type:") {
		t.Errorf("empty POST must not carry Content-Type header: %s", b)
	}
}

// Empty response must be 204 (§3.4.6 — "空 HTTP 响应必须用 204 No Content").
func TestBuildResponse_EmptyIs204(t *testing.T) {
	b := buildSOAPResponse(204, "", nil, "", "", "close")
	if !bytes.HasPrefix(b, []byte("HTTP/1.1 204")) {
		t.Errorf("empty response must be 204, got: %s", b)
	}
	if bytes.Contains(b, []byte("Content-Length")) {
		t.Errorf("empty response must not carry Content-Length: %s", b)
	}
}

// SOAPAction empty value line: header present, value empty (§3.4.1).
func TestBuildRequest_SOAPActionEmpty(t *testing.T) {
	b := BuildRequest("POST", "/", "192.0.2.1:7547", "1", "", "", SOAPActionEmpty, []byte("<x/>"), "text/xml", nil, "close")
	if !bytes.Contains(b, []byte("SOAPAction: \r\n")) {
		t.Errorf("SOAP post must carry SOAPAction header with empty value, got: %s", b)
	}
}

// DigestResponse (RFC 2617 §3.5.1 qop=auth, echoed by RFC 7616 §3.9):
// HA1=MD5(user:realm:pass), HA2=MD5(method:uri),
// response=MD5(HA1:nonce:nc:cnonce:qop:HA2). Known vector (user=Mufasa,
// realm=testrealm@host.com, pass=Circle Of Life, method=GET,
// uri=/dir/index.html, nonce=dcd98b7102dd2f0e8b11d0f600bfb0c093,
// nc=00000001, cnonce=0a4f113b, qop=auth) → the RFC's documented
// response-digest 6629fae49393a05397450978507c4ef1.
func TestDigestResponse_KnownVector(t *testing.T) {
	user, realm, pass := "Mufasa", "testrealm@host.com", "Circle Of Life"
	nonce := "dcd98b7102dd2f0e8b11d0f600bfb0c093"
	nc, cnonce, qop, method, uri := "00000001", "0a4f113b", "auth", "GET", "/dir/index.html"
	got := DigestResponse(user, pass, realm, nonce, nc, cnonce, qop, method, uri)
	const want = "6629fae49393a05397450978507c4ef1"
	if got != want {
		t.Errorf("DigestResponse = %q, want %q", got, want)
	}
}

// faultcode for 9000 must be bare "Server" (case #66, Table 87 Method not
// supported); for 9800 must be bare "Client" (case #79, vendor band floor);
// 8000 Server / 8005 Server (#13 / #104 V-01) / 9003 Client (#36). testcase
// §4 hex-asserts the bare values: 53 65 72 76 65 72 (Server), 43 6C 69 65
// 6E 74 (Client). The mapping is pinned — NOT domain-derivable, since
// 9000→Server but 9003/9800→Client all sit in the 9xxx CPE domain.
// (Design §3.5's "其余 9000s 内部错误以 Client 发送" is corrected: 9000
// emits Server per case #66.)
func TestBuildFaultPayload_FaultcodeBare(t *testing.T) {
	cases := []struct {
		name string
		code int
		want string // bare value (no "soap:" prefix)
	}{
		{"#13 ACS-side 8000=Server", 8000, "Server"},
		{"#104 ACS-side 8005=Server", 8005, "Server"},
		{"#36 CPE-side 9003=Client", 9003, "Client"},
		{"#66 CPE 9000=Server", 9000, "Server"},
		{"#79 CPE 9800=Client", 9800, "Client"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := BuildFaultPayload(&core.CWMPFault{Code: c.code})
			wantHex := hex.EncodeToString([]byte(c.want))
			if !strings.Contains(b, ">"+c.want+"</faultcode>") {
				t.Errorf("faultcode not bare %q in %s", c.want, b)
			}
			// Pin the exact hex bytes the testcase asserts.
			if !strings.Contains(strings.ToLower(hex.EncodeToString([]byte(b))), wantHex) {
				t.Errorf("hex %q not present in payload", wantHex)
			}
			// Outer faultstring must be the fixed "CWMP fault".
			if !strings.Contains(b, "<faultstring>CWMP fault</faultstring>") {
				t.Errorf("outer faultstring not pinned: %s", b)
			}
		})
	}
}

// Inform must contain DeviceIdStruct with OUI six uppercase hex digits
// (§3.5 / §8 boundary 64-cwmp-design §3.6 "OUI 六位大写十六进制").
func TestBuildInformPayload_OUISixHex(t *testing.T) {
	dev := FixtureDeviceID()
	body := BuildInformPayload(dev, []core.CWMPSOAPEvent{{Code: "2 PERIODIC"}}, nil, FixtureCurrentTime, nil, nil)
	if !strings.Contains(body, "<OUI>"+dev.OUI+"</OUI>") {
		t.Errorf("OUI not rendered: %s", body)
	}
	for _, c := range dev.OUI {
		ok := (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')
		if !ok {
			t.Fatalf("fixture OUI %q not six uppercase hex", dev.OUI)
		}
	}
}

// Validate: SOAP 1.2 envelope namespace is a wire-format error (§7
// cwmp_neg_config anchor: "namespace").
func TestValidate_SOAP12Namespace(t *testing.T) {
	spec := core.FlowSpec{CWMP: &core.CWMPConfig{
		Namespace: "http://www.w3.org/2003/05/soap-envelope",
		Sessions: []core.CWMPSession{{
			Transactions: []core.CWMPTransaction{
				{Kind: "inform", Events: []core.CWMPSOAPEvent{{Code: "2 PERIODIC"}}},
				{Kind: "inform_response"},
				{Kind: "empty_post"},
				{Kind: "empty_response"},
			},
		}},
	}}
	err := Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "namespace") {
		t.Errorf("expected namespace error, got %v", err)
	}
}

// Validate: event code outside the 14/15-item domain is a value error
// (§7 cwmp_neg_length anchor: "value").
func TestValidate_BadEventCode(t *testing.T) {
	spec := core.FlowSpec{CWMP: &core.CWMPConfig{
		Sessions: []core.CWMPSession{{
			Transactions: []core.CWMPTransaction{
				{Kind: "inform", Events: []core.CWMPSOAPEvent{{Code: "99 BOGUS"}}},
				{Kind: "inform_response"},
				{Kind: "empty_post"},
				{Kind: "empty_response"},
			},
		}},
	}}
	err := Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "value") {
		t.Errorf("expected value error, got %v", err)
	}
}

// Validate: response id mismatch is a correlation error (§7 anchor: "id").
func TestValidate_IDMismatch(t *testing.T) {
	spec := core.FlowSpec{CWMP: &core.CWMPConfig{
		Sessions: []core.CWMPSession{{
			Transactions: []core.CWMPTransaction{
				{Kind: "inform", ID: "1", Events: []core.CWMPSOAPEvent{{Code: "2 PERIODIC"}}},
				{Kind: "inform_response", ID: "WRONG"},
				{Kind: "empty_post"},
				{Kind: "empty_response"},
			},
		}},
	}}
	err := Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "id") {
		t.Errorf("expected id correlation error, got %v", err)
	}
}

// Validate: parameter name > 256 is a length error (§7 anchor: "length"
// or "parameter").
func TestValidate_ParamNameTooLong(t *testing.T) {
	spec := core.FlowSpec{CWMP: &core.CWMPConfig{
		Sessions: []core.CWMPSession{{
			Transactions: []core.CWMPTransaction{
				{Kind: "inform", ID: "1", Events: []core.CWMPSOAPEvent{{Code: "2 PERIODIC"}},
					ParameterList: []core.CWMPParameter{{Name: strings.Repeat("n", 257), Value: "x"}}},
				{Kind: "inform_response"},
				{Kind: "empty_post"},
				{Kind: "empty_response"},
			},
		}},
	}}
	err := Validate(spec)
	if err == nil || !(strings.Contains(err.Error(), "length") || strings.Contains(err.Error(), "parameter")) {
		t.Errorf("expected length/parameter error, got %v", err)
	}
}

// Validate: Download URL with userinfo is forbidden (§3.5 / §7 anchor:
// "value").
func TestValidate_URLUserInfo(t *testing.T) {
	spec := core.FlowSpec{CWMP: &core.CWMPConfig{
		Sessions: []core.CWMPSession{{
			Transactions: []core.CWMPTransaction{
				{Kind: "inform", ID: "1", Events: []core.CWMPSOAPEvent{{Code: "2 PERIODIC"}}},
				{Kind: "inform_response"},
				{Kind: "acs_request", Method: "download", URL: "http://user:pass@198.51.100.9/fw"},
				{Kind: "acs_response", Method: "download"},
				{Kind: "empty_post"},
				{Kind: "empty_response"},
			},
		}},
	}}
	err := Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "value") {
		t.Errorf("expected userinfo error, got %v", err)
	}
}

// Validate: M Download without 7 TRANSFER COMPLETE in the same Inform is
// forbidden (§3.7.1.5).
func TestValidate_MDownloadWithoutTC(t *testing.T) {
	spec := core.FlowSpec{CWMP: &core.CWMPConfig{
		Sessions: []core.CWMPSession{{
			Transactions: []core.CWMPTransaction{
				{Kind: "inform", ID: "1", Events: []core.CWMPSOAPEvent{{Code: "M Download"}}},
				{Kind: "inform_response"},
				{Kind: "empty_post"},
				{Kind: "empty_response"},
			},
		}},
	}}
	err := Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "7 TRANSFER COMPLETE") {
		t.Errorf("expected M Download TC rule error, got %v", err)
	}
}

// Validate: ACS request in an acs_cr session is a state error
// (state machine §5 — direction wrong).
func TestValidate_ACSRequestInACSCR(t *testing.T) {
	spec := core.FlowSpec{CWMP: &core.CWMPConfig{
		Sessions: []core.CWMPSession{{
			Role: "acs_cr",
			Transactions: []core.CWMPTransaction{
				{Kind: "acs_request", Method: "get_parameter_values"},
			},
		}},
	}}
	err := Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "session") {
		t.Errorf("expected session state error, got %v", err)
	}
}

// Validate: DrivenBy anchor referencing a non-existent session is rejected
// with correlation anchor ("correlation" per §7).
func TestValidate_FlowDrivenByBadSession(t *testing.T) {
	spec := core.FlowSpec{CWMP: &core.CWMPConfig{
		Sessions: []core.CWMPSession{{Transactions: []core.CWMPTransaction{
			{Kind: "inform", Events: []core.CWMPSOAPEvent{{Code: "2 PERIODIC"}}},
			{Kind: "inform_response"}, {Kind: "empty_post"}, {Kind: "empty_response"},
		}}},
		Flows: []core.CWMPFlow{{
			Kind: "http_get", SrcPort: 50066, Host: "198.51.100.9", Port: 80,
			DrivenBy: &core.CWMPDrivenBy{Session: 1, Transaction: "inform_response"},
		}},
	}}
	err := Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "correlation") {
		t.Errorf("expected correlation error, got %v", err)
	}
}

// Validate: nil CWMP config (P0b empty-config default flow) returns nil
// (gbt precedent — single baseline inform+response session, generator
// default).
func TestValidate_NilConfig(t *testing.T) {
	if err := Validate(core.FlowSpec{}); err != nil {
		t.Errorf("nil CWMP should validate (P0b default flow), got %v", err)
	}
}

// BuildInformPayload: dateTime with explicit time-zone offset (design
// §8 boundary — Inform CurrentTime must carry +hh:mm or -hh:mm).
func TestBuildInformPayload_CurrentTimeHasOffset(t *testing.T) {
	body := BuildInformPayload(FixtureDeviceID(),
		[]core.CWMPSOAPEvent{{Code: "2 PERIODIC"}}, nil,
		"2026-09-05T07:00:00-05:00", nil, nil)
	if !strings.Contains(body, "<CurrentTime>2026-09-05T07:00:00-05:00</CurrentTime>") {
		t.Errorf("CurrentTime offset not preserved: %s", body)
	}
}

// XML escape round-trip: special chars in parameter values must escape
// (design §8 / testcase #49 — & < > " ' each escaped).
func TestEscapeXML(t *testing.T) {
	cases := map[string]string{
		`a&b`:  `a&amp;b`,
		`a<b`:  `a&lt;b`,
		`a>b`:  `a&gt;b`,
		`a"b`:  `a&quot;b`,
		`a'b`:  `a&apos;b`,
	}
	for in, want := range cases {
		if got := EscapeXML(in); got != want {
			t.Errorf("EscapeXML(%q) = %q, want %q", in, got, want)
		}
	}
}

// FlowSpec.CWMP round-trips through JSON (the layer-chain spec_json path
// uses these keys verbatim via parseSubconfigJSON).
func TestCWMPConfigJSONRoundtrip(t *testing.T) {
	cfg := core.CWMPConfig{
		Profile: "cwmp_http_v1",
		Sessions: []core.CWMPSession{{Role: "cpe", Transactions: []core.CWMPTransaction{
			{Kind: "inform", Events: []core.CWMPSOAPEvent{{Code: "2 PERIODIC"}}},
		}}},
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"profile":"cwmp_http_v1"`)) {
		t.Errorf("profile not serialized: %s", b)
	}
	if !bytes.Contains(b, []byte(`"role":"cpe"`)) {
		t.Errorf("session role not serialized: %s", b)
	}
	if !bytes.Contains(b, []byte(`"kind":"inform"`)) {
		t.Errorf("transaction kind not serialized: %s", b)
	}
}
