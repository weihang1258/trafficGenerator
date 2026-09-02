package gbt

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestFixtureByteTable asserts the design doc §3.4 fixture byte-count table
// against this builder (GBt design v2.0.0; every length is a pinned constant).
func TestFixtureByteTable(t *testing.T) {
	base := BaseTemplateState()

	// Request bodies (bitcoin-cli form).
	req := func(id, method string, params string) []byte {
		return BuildRequestJSON(json.RawMessage(id), method, json.RawMessage(params), false)
	}
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"base request body id=1", len(req(`1`, "getblocktemplate", `[]`)), 64},
		{"rules request body id=1", len(req(`1`, "getblocktemplate", `[{"rules":["segwit"]}]`)), 84},
		{"longpoll request body id=2", len(req(`2`, "getblocktemplate", `[{"longpollid":"lp-1000-1"}]`)), 90},
		{"proposal request body id=3", len(req(`3`, "getblocktemplate", `[{"mode":"proposal","data":"`+FixtureTxData+`"}]`)), 295},
		{"submitblock single id=4", len(req(`4`, "submitblock", `["`+FixtureSubmitHexdata+`"]`)), 221},
		{"submitblock workid id=4", len(req(`4`, "submitblock", `["`+FixtureSubmitHexdata+`","w-1"]`)), 227},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %dB want %dB", c.name, c.got, c.want)
		}
	}

	// Response bodies.
	resp := func(id string, result []byte) []byte {
		return BuildResponseJSON(json.RawMessage(id), result, false)
	}
	cases = []struct {
		name string
		got  int
		want int
	}{
		{"full template response id=1", len(resp(`1`, BuildTemplateFull(base))), 607},
		{"plain template response id=1", len(resp(`1`, BuildTemplatePlain(FixtureHeight))), 488},
		{"tx1 template response id=1", len(resp(`1`, BuildTemplateTx1(FixtureHeight))), 884},
		{"big template response id=1", len(resp(`1`, BuildTemplateBig())), 5512},
		{"accepted null id=4", len(resp(`4`, []byte(`null`))), 35},
		{"true id=3", len(resp(`3`, []byte(`true`))), 35},
		{"reject reason id=4", len(resp(`4`, []byte(quoteJSON(FixtureReason)))), 51},
		{"error id=5", len(BuildErrorJSON(json.RawMessage(`5`), FixtureErrorCode, FixtureErrorMessage)), 89},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %dB want %dB", c.name, c.got, c.want)
		}
	}

	// Template JSON sizes themselves.
	if got := len(BuildTemplateFull(base)); got != 576 {
		t.Errorf("full template: got %dB want 576B", got)
	}
	if got := len(BuildTemplatePlain(FixtureHeight)); got != 457 {
		t.Errorf("plain template: got %dB want 457B", got)
	}
	if got := len(BuildTemplateTx1(FixtureHeight)); got != 853 {
		t.Errorf("tx1 template: got %dB want 853B", got)
	}
	if got := len(BuildTemplateBig()); got != 5481 {
		t.Errorf("big template: got %dB want 5481B", got)
	}

	// HTTP frame totals.
	body := req(`1`, "getblocktemplate", `[]`)
	httpReq := BuildHTTPRequest("HTTP/1.1", "POST", "/", "198.51.100.77:8332", "dXNlcjpwYXNz", body, "keep-alive")
	if len(httpReq) != 220 {
		t.Errorf("http request total: got %dB want 220B", len(httpReq))
	}
	tplResp := resp(`1`, BuildTemplateFull(base))
	httpResp := BuildHTTPResponse("HTTP/1.1", 200, tplResp, "keep-alive")
	if len(httpResp) != 703 {
		t.Errorf("http response total: got %dB want 703B", len(httpResp))
	}
	// Big template HTTP total = 5608B (96 head + 5512 body).
	bigResp := BuildHTTPResponse("HTTP/1.1", 200, BuildResponseJSON(json.RawMessage(`1`), BuildTemplateBig(), false), "keep-alive")
	if len(bigResp) != 5609 {
		t.Errorf("big http response total: got %dB want 5609B (97B header: CL 4 digits)", len(bigResp))
	}
}

// TestFixtureHexBaselines asserts the doc §3 hex literals.
func TestFixtureHexBaselines(t *testing.T) {
	base := BaseTemplateState()
	body := BuildRequestJSON(json.RawMessage(`1`), "getblocktemplate", json.RawMessage(`[]`), false)
	wantReq := `7B226A736F6E727063223A22312E30222C226964223A312C226D6574686F64223A22676574626C6F636B74656D706C617465222C22706172616D73223A5B5D7D`
	if got := strings.ToUpper(string(toHex(body))); got != wantReq {
		t.Errorf("req body hex mismatch:\n got %s\nwant %s", got, wantReq)
	}

	full := BuildResponseJSON(json.RawMessage(`1`), BuildTemplateFull(base), false)
	hexFull := strings.ToUpper(string(toHex(full)))
	prefix := `7B22726573756C74223A7B2276657273696F6E223A3533363837303931322C2270726576696F7573626C6F636B68617368223A223131313131313131313131313131313131313131313131313131313131313131313131313131313131313131`
	suffix := `226361706162696C6974696573223A5B2270726F706F73616C225D2C22776F726B6964223A22772D31227D2C226572726F72223A6E756C6C2C226964223A317D`
	if !strings.HasPrefix(hexFull, prefix) {
		t.Errorf("full response hex prefix mismatch")
	}
	if !strings.HasSuffix(hexFull, suffix) {
		t.Errorf("full response hex suffix mismatch")
	}

	acc := BuildResponseJSON(json.RawMessage(`4`), []byte(`null`), false)
	wantAcc := `7B22726573756C74223A6E756C6C2C226572726F72223A6E756C6C2C226964223A347D`
	if got := strings.ToUpper(string(toHex(acc))); got != wantAcc {
		t.Errorf("accepted hex mismatch: got %s", got)
	}
	errObj := BuildErrorJSON(json.RawMessage(`5`), FixtureErrorCode, FixtureErrorMessage)
	wantErr := `7B22726573756C74223A6E756C6C2C226572726F72223A7B22636F6465223A2D312C226D657373616765223A22676574626C6F636B74656D706C6174653A20756E737570706F727465642072756C65227D2C226964223A357D`
	if got := strings.ToUpper(string(toHex(errObj))); got != wantErr {
		t.Errorf("error hex mismatch: got %s", got)
	}
}

// TestTemplateKeysetOrder asserts the 18-key member order via JSON unmarshal
// + key order scan (json.RawMessage preserves order for map-free decoding).
func TestTemplateKeysetOrder(t *testing.T) {
	full := string(BuildTemplateFull(BaseTemplateState()))
	wantOrder := []string{"version", "previousblockhash", "transactions", "coinbaseaux",
		"coinbasevalue", "target", "mintime", "mutable", "noncerange", "sigoplimit",
		"sizelimit", "curtime", "bits", "height", "longpollid", "longpolluri",
		"capabilities", "workid"}
	pos := 0
	for _, k := range wantOrder {
		i := strings.Index(full[pos:], `"`+k+`":`)
		if i < 0 {
			t.Fatalf("key %q not found in order (after pos %d)", k, pos)
		}
		pos += i + len(k) + 3
	}
	// Valid JSON.
	var v map[string]interface{}
	if err := json.Unmarshal([]byte(full), &v); err != nil {
		t.Fatalf("full template not valid JSON: %v", err)
	}
	if len(v) != 18 {
		t.Errorf("full template keys: got %d want 18", len(v))
	}

	plain := string(BuildTemplatePlain(FixtureHeight))
	var pv map[string]interface{}
	if err := json.Unmarshal([]byte(plain), &pv); err != nil {
		t.Fatalf("plain template not valid JSON: %v", err)
	}
	if len(pv) != 14 {
		t.Errorf("plain template keys: got %d want 14", len(pv))
	}

	tx1 := string(BuildTemplateTx1(FixtureHeight))
	if !strings.Contains(tx1, `"transactions":[{"data":`) {
		t.Errorf("tx1 template transactions element order wrong")
	}

	big := string(BuildTemplateBig())
	var bv struct {
		Transactions []map[string]interface{} `json:"transactions"`
	}
	if err := json.Unmarshal([]byte(big), &bv); err != nil {
		t.Fatalf("big template not valid JSON: %v", err)
	}
	if len(bv.Transactions) != 3 {
		t.Errorf("big template transactions: got %d want 3", len(bv.Transactions))
	}
	for _, tx := range bv.Transactions {
		if got, _ := tx["data"].(string); len(got) != 1480 {
			t.Errorf("big tx data: got %d hex want 1480", len(got))
		}
	}
}

// TestRefreshDerivation: height+1, curtime+600, longpollid=lp-<h>-1.
func TestRefreshDerivation(t *testing.T) {
	base := BaseTemplateState()
	next := base.Refresh()
	if next.Height != 1001 || next.CurTime != 1756685700 || next.LongpollID != "lp-1001-1" {
		t.Errorf("refresh state: %+v", next)
	}
	// Refresh keeps longpolluri/workid.
	if next.LongpollURI != base.LongpollURI || next.WorkID != base.WorkID {
		t.Errorf("refresh lost longpolluri/workid: %+v", next)
	}
}

// TestSubstituteFromTokens: workid_from/longpollid_from replaced from state.
func TestSubstituteFromTokens(t *testing.T) {
	st := BaseTemplateState()
	params := json.RawMessage(`["` + FixtureSubmitHexdata + `","workid_from"]`)
	out := string(substituteFromTokens(params, st))
	if !strings.Contains(out, `"w-1"`) {
		t.Errorf("workid_from not substituted: %s", out)
	}
	params2 := json.RawMessage(`[{"longpollid":"longpollid_from"}]`)
	out2 := string(substituteFromTokens(params2, st))
	if !strings.Contains(out2, `"lp-1000-1"`) {
		t.Errorf("longpollid_from not substituted: %s", out2)
	}
}

// TestLongpollPath: URI → request path.
func TestLongpollPath(t *testing.T) {
	cases := map[string]string{
		"http://198.51.100.77:8332/longpoll": "/longpoll",
		"http://example.com":                 "/",
		"198.51.100.77:8332/x":               "/x",
	}
	for in, want := range cases {
		if got := longpollPath(in); got != want {
			t.Errorf("longpollPath(%q) = %q want %q", in, got, want)
		}
	}
}

// TestHTTP401Shape: no body, WWW-Authenticate, CL=0.
func TestHTTP401Shape(t *testing.T) {
	r := BuildHTTP401("HTTP/1.1", "jsonrpc", "keep-alive")
	s := string(r)
	if !strings.Contains(s, "HTTP/1.1 401 Authorization Required\r\n") {
		t.Errorf("401 status line wrong: %q", s[:50])
	}
	if !strings.Contains(s, `WWW-Authenticate: Basic realm="jsonrpc"`) {
		t.Errorf("401 WWW-Authenticate missing")
	}
	if !strings.Contains(s, "Content-Length: 0") {
		t.Errorf("401 Content-Length: 0 missing")
	}
	if strings.Contains(s, "Content-Type") {
		t.Errorf("401 must not carry Content-Type (empty body)")
	}
}

func toHex(b []byte) []byte {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexDigits[c>>4], hexDigits[c&0x0f])
	}
	return out
}
