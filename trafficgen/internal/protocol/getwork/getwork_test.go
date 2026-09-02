package getwork

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestFixtureHexBaselines asserts the doc §3.4 / testcase §3 fixture values
// and hex literals (every length is a pinned constant).
func TestFixtureHexBaselines(t *testing.T) {
	// Fixture widths (G-1: data = 256 hex; hash1 = 128 hex).
	if len(FixtureDataWork) != 256 {
		t.Errorf("data_work: got %d hex want 256", len(FixtureDataWork))
	}
	// data_work2 differs from data_work at hex chars [8:12): work1 has
	// "1111" there (positions 8-11), work2 has "1112" (the second 1
	// differs at position 10, making 1111→1112).
	if len(FixtureDataWork2) != 256 || FixtureDataWork2[:8] != FixtureDataWork[:8] || FixtureDataWork2[8:12] != "1112" {
		t.Errorf("data_work2 variant shape wrong: %.16s vs %.16s", FixtureDataWork2, FixtureDataWork)
	}
	if len(FixtureTarget) != 64 || !strings.HasPrefix(FixtureTarget, "00000000ffff") {
		t.Errorf("target: got %d hex, prefix %s", len(FixtureTarget), FixtureTarget[:12])
	}
	if FixtureTarget[12:] != strings.Repeat("00", 26) {
		t.Errorf("target boundary tail not all zero")
	}
	if len(FixtureMidstate) != 64 || FixtureMidstate != strings.Repeat("33", 32) {
		t.Errorf("midstate wrong")
	}
	if len(FixtureHash1) != 128 || !strings.HasPrefix(FixtureHash1, "00000080") || !strings.HasSuffix(FixtureHash1, "80020000") {
		t.Errorf("hash1 wrong: %s…%s", FixtureHash1[:8], FixtureHash1[len(FixtureHash1)-8:])
	}
	// Nonce correlation: submit = work with chars [152:160) replaced.
	sub := SubmitData(FixtureDataWork)
	if sub == FixtureDataWork || sub[:152] != FixtureDataWork[:152] || sub[152:160] != FixtureSubmitNonce || sub[160:] != FixtureDataWork[160:] {
		t.Errorf("submit data derivation wrong")
	}

	// Request body (1.0 form, id=1): 39B, exact hex.
	body := BuildRequestJSON(json.RawMessage(`1`), "getwork", json.RawMessage(`[]`), false)
	wantReq := `7B226964223A312C226D6574686F64223A22676574776F726B222C22706172616D73223A5B5D7D`
	if got := strings.ToUpper(hexOf(body)); got != wantReq {
		t.Errorf("req body hex mismatch:\n got %s\nwant %s", got, wantReq)
	}
	if len(body) != 39 {
		t.Errorf("apply request body: got %dB want 39B", len(body))
	}

	// Submit body (id=2, params=[data_submit]): 297B, hex prefix/suffix.
	sbody := BuildRequestJSON(json.RawMessage(`2`), "getwork", json.RawMessage(`["`+SubmitData(FixtureDataWork)+`"]`), false)
	if len(sbody) != 297 {
		t.Errorf("submit request body: got %dB want 297B", len(sbody))
	}
	if !strings.HasPrefix(string(sbody), `{"id":2,"method":"getwork","params":["`) || !strings.HasSuffix(string(sbody), `"]}`) {
		t.Errorf("submit body shape wrong")
	}

	// Work response body (id=1): 591B, pinned member order + tail.
	wbody := BuildResponseJSON(json.RawMessage(`1`), BuildWorkObject("fixture_work"), false)
	if len(wbody) != 591 {
		t.Errorf("work response body: got %dB want 591B", len(wbody))
	}
	wantPrefix := `{"result":{"data":"` + FixtureDataWork[:16]
	if !strings.HasPrefix(string(wbody), wantPrefix) {
		t.Errorf("work response prefix wrong")
	}
	if !strings.HasSuffix(string(wbody), FixtureHash1[len(FixtureHash1)-8:]+`"},"error":null,"id":1}`) {
		t.Errorf("work response tail (hash1 tail + error/id) wrong")
	}
	if strings.Count(string(wbody), `"data":`) != 1 || strings.Contains(string(wbody), "job_id") {
		t.Errorf("work object must carry exactly the 4 pinned members, no job_id")
	}

	// Boolean / object / error bodies (id=2/3 fixtures).
	tbody := BuildResponseJSON(json.RawMessage(`2`), []byte(`true`), false)
	if string(tbody) != `{"result":true,"error":null,"id":2}` || len(tbody) != 35 {
		t.Errorf("true body wrong: %s (%d)", tbody, len(tbody))
	}
	fbody := BuildResponseJSON(json.RawMessage(`2`), []byte(`false`), false)
	if len(fbody) != 36 {
		t.Errorf("false body: got %dB want 36B", len(fbody))
	}
	obody := BuildResponseJSON(json.RawMessage(`2`), BuildObjectResult("", ""), false)
	if string(obody) != `{"result":{"status":"accepted","share_id":"sh-0001"},"error":null,"id":2}` || len(obody) != 73 {
		t.Errorf("object body wrong: %s (%d)", obody, len(obody))
	}
	ebody := BuildErrorJSON(json.RawMessage(`3`), FixtureErrorCode, FixtureErrorMsg)
	wantErr := `7B22726573756C74223A6E756C6C2C226572726F72223A7B22636F6465223A2D33323630312C226D657373616765223A226D6574686F64206E6F7420666F756E64227D2C226964223A337D`
	if got := strings.ToUpper(hexOf(ebody)); got != wantErr {
		t.Errorf("error body hex mismatch:\n got %s\nwant %s", got, wantErr)
	}
	if len(ebody) != 75 {
		t.Errorf("error body: got %dB want 75B", len(ebody))
	}

	// String id (rpc-001): 47B. Large id: 48B.
	sid := BuildRequestJSON(json.RawMessage(`"rpc-001"`), "getwork", json.RawMessage(`[]`), false)
	if len(sid) != 47 {
		t.Errorf("string id body: got %dB want 47B", len(sid))
	}
	lid := BuildRequestJSON(json.RawMessage(`2147483647`), "getwork", json.RawMessage(`[]`), false)
	if len(lid) != 48 {
		t.Errorf("large id body: got %dB want 48B", len(lid))
	}

	// 2.0 form: request body 55B with leading jsonrpc member; response same.
	body20 := BuildRequestJSON(json.RawMessage(`1`), "getwork", json.RawMessage(`[]`), true)
	if len(body20) != 55 || !strings.HasPrefix(string(body20), `{"jsonrpc":"2.0","id":1,`) {
		t.Errorf("2.0 request body wrong: %s (%d)", body20, len(body20))
	}
	resp20 := BuildResponseJSON(json.RawMessage(`1`), []byte(`true`), true)
	if !strings.HasPrefix(string(resp20), `{"jsonrpc":"2.0","result":true`) {
		t.Errorf("2.0 response form wrong: %s", resp20)
	}
}

// TestHTTPFrames asserts the pinned header orders and totals (request 195B
// baseline; work response 687B; 401 shape).
func TestHTTPFrames(t *testing.T) {
	body := BuildRequestJSON(json.RawMessage(`1`), "getwork", json.RawMessage(`[]`), false)
	req := BuildHTTPRequest("HTTP/1.1", "POST", "/", "198.51.100.76:8332", FixtureAuthB64, body, "keep-alive")
	if len(req) != 195 {
		t.Errorf("baseline request: got %dB want 195B", len(req))
	}
	s := string(req)
	// Pinned header order: request line → Host → Authorization → CT → CL → Connection.
	order := []string{
		"POST / HTTP/1.1\r\n",
		"Host: 198.51.100.76:8332\r\n",
		"Authorization: Basic dXNlcjpwYXNz\r\n",
		"Content-Type: application/json\r\n",
		"Content-Length: 39\r\n",
		"Connection: keep-alive\r\n\r\n",
	}
	pos := 0
	for _, h := range order {
		i := strings.Index(s[pos:], h)
		if i < 0 {
			t.Fatalf("header out of order or missing: %q", h)
		}
		pos += i + len(h)
	}

	wbody := BuildResponseJSON(json.RawMessage(`1`), BuildWorkObject("fixture_work"), false)
	resp := BuildHTTPResponse("HTTP/1.1", 200, wbody, "keep-alive")
	if len(resp) != 687 {
		t.Errorf("baseline work response: got %dB want 687B", len(resp))
	}

	// 401: no body, WWW-Authenticate, CL=0, no Content-Type.
	r401 := string(BuildHTTP401("HTTP/1.1", "jsonrpc", "keep-alive"))
	if !strings.Contains(r401, "HTTP/1.1 401 Authorization Required\r\n") ||
		!strings.Contains(r401, `WWW-Authenticate: Basic realm="jsonrpc"`) ||
		!strings.Contains(r401, "Content-Length: 0") || strings.Contains(r401, "Content-Type") {
		t.Errorf("401 shape wrong: %q", r401)
	}

	// 500: status phrase + error body.
	ebody := BuildErrorJSON(json.RawMessage(`3`), FixtureErrorCode, FixtureErrorMsg)
	r500 := BuildHTTPResponse("HTTP/1.1", 500, ebody, "keep-alive")
	if !strings.HasPrefix(string(r500), "HTTP/1.1 500 Internal Server Error\r\n") {
		t.Errorf("500 status line wrong")
	}

	// HTTP/1.0: no Host header.
	req10 := BuildHTTPRequest("HTTP/1.0", "POST", "/", "x", "", body, "close")
	if strings.Contains(string(req10), "Host:") {
		t.Errorf("HTTP/1.0 request must omit Host")
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
