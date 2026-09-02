// Package getwork implements the Bitcoin legacy getwork JSON-RPC-over-HTTP
// terminal layer (getwork 终结层, [ip→tcp→http→getwork] 链).
//
// Wire-format authority: docs/protocol-designs/76-getwork-design.md v2.0.0
// §3 — HTTP header orders are pinned, JSON member orders are pinned
// (bitcoind legacy form: request {"id","method","params"} with NO jsonrpc
// member; response {"result","error","id"}; the 2.0 observation form
// prepends "jsonrpc":"2.0" to both). The work object's four members are
// emitted in the pinned order data/target/midstate/hash1 with widths
// 256/64/64/128 hex (data = 128B: 80B block header zero-padded — the
// v1.0.0 "128 hex" figure is void, G-1). All fixture constants
// (data/target/midstate/hash1/auth base64/error object) are pinned by the
// design doc §3.4 and mirrored here; the unit test asserts the doc's hex
// baselines against this builder.
package getwork

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Fixture constants (design §3.4 — 全量钉死).
const (
	FixtureAuthB64   = "dXNlcjpwYXNz" // base64("user:pass")
	FixtureErrorCode = -32601
	FixtureErrorMsg  = "method not found"
	FixtureStatus    = "accepted"
	FixtureShareID   = "sh-0001"
	FixtureSubmitPos = 152 // nonce 4B = data hex chars [152:160)
)

// Fixture string values built with strings.Repeat (not const-able).
var (
	// FixtureDataWork = 00000020 + "11"×32 + "22"×32 + 66dead00 + 1b0404cb +
	// 00000000(nonce) + "00"×48 → 256 hex (128B).
	FixtureDataWork = "00000020" + strings.Repeat("11", 32) + strings.Repeat("22", 32) +
		"66dead00" + "1b0404cb" + "00000000" + strings.Repeat("00", 48)
	// FixtureSubmitNonce replaces data hex chars [152:160) on submit
	// (work.data_nonce_modified derivation).
	FixtureSubmitNonce = "2f9f2e1d"
	// FixtureDataWork2 is the distinct-work variant: data hex chars [8:12)
	// "1111"→"1112" (每请求新 work 正例). "1112" replaces the first TWO
	// "11" pairs of the run, so "1112" + "11"×30 keeps the total 256.
	FixtureDataWork2 = "00000020" + "1112" + strings.Repeat("11", 30) + strings.Repeat("22", 32) +
		"66dead00" + "1b0404cb" + "00000000" + strings.Repeat("00", 48)
	FixtureTarget   = "00000000ffff" + strings.Repeat("00", 26) // 64 hex (边界 fixture)
	FixtureMidstate = strings.Repeat("33", 32)                  // 64 hex
	FixtureHash1    = "00000080" + strings.Repeat("00", 56) + "80020000"
)

// SubmitData derives the submit data from a work data: same bytes with the
// 4B nonce field (hex chars [152:160)) replaced by the fixture submit nonce
// (design §3.3 nonce 位关联). Returns the input unchanged when it is too
// short (the planner rejects that before this is called).
func SubmitData(work string) string {
	if len(work) < FixtureSubmitPos+8 {
		return work
	}
	return work[:FixtureSubmitPos] + FixtureSubmitNonce + work[FixtureSubmitPos+8:]
}

// quoteJSON renders a Go string as a JSON string literal (ASCII fixture
// values only — no escaping beyond the mandatory quotes is needed; non-ASCII
// or control bytes fall back to encoding/json).
func quoteJSON(s string) string {
	if isASCIIPlain(s) {
		return `"` + s + `"`
	}
	b, _ := json.Marshal(s)
	return string(b)
}

func isASCIIPlain(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// BuildRequestJSON builds the request body. Legacy 1.0 form (default):
// {"id":<id>,"method":<m>,"params":<p>} — id first, NO jsonrpc member.
// 2.0 observation form: {"jsonrpc":"2.0","id":…,…}. id/params embed
// verbatim.
func BuildRequestJSON(id json.RawMessage, method string, params json.RawMessage, jsonrpc2 bool) []byte {
	if len(params) == 0 {
		params = json.RawMessage(`[]`)
	}
	var b strings.Builder
	b.WriteString(`{`)
	if jsonrpc2 {
		b.WriteString(`"jsonrpc":"2.0",`)
	}
	b.WriteString(`"id":`)
	b.Write(id)
	b.WriteString(`,"method":`)
	b.WriteString(quoteJSON(method))
	b.WriteString(`,"params":`)
	b.Write(params)
	b.WriteString(`}`)
	return []byte(b.String())
}

// BuildResponseJSON builds the response body {"result":R,"error":null,"id":N}
// (legacy form; jsonrpc2 prepends "jsonrpc":"2.0" as the FIRST member).
// result embeds verbatim (work object bytes, true/false/null, or an object).
func BuildResponseJSON(id json.RawMessage, result []byte, jsonrpc2 bool) []byte {
	var b strings.Builder
	b.WriteString(`{`)
	if jsonrpc2 {
		b.WriteString(`"jsonrpc":"2.0",`)
	}
	b.WriteString(`"result":`)
	b.Write(result)
	b.WriteString(`,"error":null,"id":`)
	b.Write(id)
	b.WriteString(`}`)
	return []byte(b.String())
}

// BuildErrorJSON builds the error-response body
// {"result":null,"error":{"code":C,"message":"M"},"id":N} (legacy form; the
// 2.0 form is not exercised by the fixture set — error responses are 1.0).
func BuildErrorJSON(id json.RawMessage, code int, message string) []byte {
	var b strings.Builder
	b.WriteString(`{"result":null,"error":{"code":`)
	b.WriteString(strconv.Itoa(code))
	b.WriteString(`,"message":`)
	b.WriteString(quoteJSON(message))
	b.WriteString(`},"id":`)
	b.Write(id)
	b.WriteString(`}`)
	return []byte(b.String())
}

// BuildWorkObject builds the work object in the pinned member order
// data/target/midstate/hash1 with the fixture widths 256/64/64/128 hex.
// variant "fixture_work2" swaps in the distinct-work data (每请求新 work).
func BuildWorkObject(variant string) []byte {
	data := FixtureDataWork
	if variant == "fixture_work2" {
		data = FixtureDataWork2
	}
	return []byte(`{"data":` + quoteJSON(data) +
		`,"target":` + quoteJSON(FixtureTarget) +
		`,"midstate":` + quoteJSON(FixtureMidstate) +
		`,"hash1":` + quoteJSON(FixtureHash1) + `}`)
}

// BuildObjectResult builds the third accepted form {"status":S,"share_id":I}
// (fixture accepted / sh-0001).
func BuildObjectResult(status, shareID string) []byte {
	if status == "" {
		status = FixtureStatus
	}
	if shareID == "" {
		shareID = FixtureShareID
	}
	return []byte(`{"status":` + quoteJSON(status) + `,"share_id":` + quoteJSON(shareID) + `}`)
}

// StatusText maps the fixture's three status codes to their reason phrases.
func StatusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 401:
		return "Authorization Required"
	case 500:
		return "Internal Server Error"
	}
	return "Unknown"
}

// BuildHTTPRequest builds a complete HTTP request. Header order pinned by
// design §3.1: POST 行 → Host（HTTP/1.0 省略）→ [Authorization] →
// Content-Type → Content-Length → Connection. host is the pre-formed
// host:port literal; authB64 empty = header omitted.
func BuildHTTPRequest(version, method, uri, host, authB64 string, body []byte, connection string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", method, uri, version)
	if version != "HTTP/1.0" {
		fmt.Fprintf(&b, "Host: %s\r\n", host)
	}
	if authB64 != "" {
		fmt.Fprintf(&b, "Authorization: Basic %s\r\n", authB64)
	}
	b.WriteString("Content-Type: application/json\r\n")
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(&b, "Connection: %s\r\n\r\n", connection)
	b.Write(body)
	return []byte(b.String())
}

// BuildHTTPResponse builds a 200/500 response: 状态行 → Content-Type →
// Content-Length → Connection.
func BuildHTTPResponse(version string, status int, body []byte, connection string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %d %s\r\n", version, status, StatusText(status))
	b.WriteString("Content-Type: application/json\r\n")
	fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(&b, "Connection: %s\r\n\r\n", connection)
	b.Write(body)
	return []byte(b.String())
}

// BuildHTTP401 builds the no-credentials response: 状态行 401 →
// WWW-Authenticate → Content-Length: 0 → Connection（空 body）。
func BuildHTTP401(version, realm, connection string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "%s 401 %s\r\n", version, StatusText(401))
	fmt.Fprintf(&b, "WWW-Authenticate: Basic realm=%s\r\n", quoteJSON(realm))
	b.WriteString("Content-Length: 0\r\n")
	fmt.Fprintf(&b, "Connection: %s\r\n\r\n", connection)
	return []byte(b.String())
}
