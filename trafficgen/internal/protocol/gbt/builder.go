// Package gbt implements the BIP 22/23 getblocktemplate/submitblock
// JSON-RPC-over-HTTP terminal layer (GBT 终结层, [ip→tcp→http→gbt] 链).
//
// Wire-format authority: docs/protocol-designs/77-gbt-design.md v2.0.0 §3 —
// HTTP header orders are pinned, JSON member orders are pinned
// (bitcoin-cli form: request {"jsonrpc":"1.0","id",..,"method",..,"params"},
// response {"result","error","id"} with no jsonrpc member), and the block
// template's 18 top-level keys are emitted in BIP 22 document order. All
// fixture constants (prevhash/target/bits/noncerange/coinbasevalue/…) are
// pinned by the design doc §3.4 and mirrored here; the unit test asserts the
// doc's byte-count table (64/84/90/295/221/227/607/488/884/5512/35/51/89/
// 220/703) against this builder.
package gbt

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Fixture constants (design §3.4 — 全量钉死).
const (
	FixtureVersion         = 536870912  // 0x20000000
	FixtureCoinbaseValue   = 5000000000 // 50 BTC in satoshis
	FixtureMinTime         = 1756684800
	FixtureCurTime         = 1756685100
	FixtureHeight          = 1000
	FixtureSigopLimit      = 80000
	FixtureSizeLimit       = 4000000
	FixturePrevHash        = "1111111111111111111111111111111111111111111111111111111111111111" // "11"×32
	FixtureTarget          = "00000000ffff0000000000000000000000000000000000000000000000000000"  // "00000000ffff"+"00"×26
	FixtureBits            = "1d00ffff"
	FixtureNonceRange      = "00000000ffffffff"
	FixtureFlags           = "706f6f6c31" // coinbaseaux.flags 矿池标签 hex
	FixtureLongpollID      = "lp-1000-1"
	FixtureLongpollURI     = "http://198.51.100.77:8332/longpoll"
	FixtureWorkID          = "w-1"
	FixtureReason          = "prev-blk-not-found"
	FixtureErrorCode       = -1
	FixtureErrorMessage    = "getblocktemplate: unsupported rule"
	RefreshCurTimeDelta    = 600
)

// Fixture string values built with strings.Repeat (not const-able).
var (
	FixtureTxData        = "02" + strings.Repeat("ab", 99) + "aa" // 202 hex
	FixtureTxID          = strings.Repeat("22", 32)
	FixtureTxHash        = strings.Repeat("33", 32)
	FixtureTxDataBig     = strings.Repeat("ff", 740) // 1480 hex chars (740 bytes on wire)
	FixtureSubmitHexdata = strings.Repeat("aa", 80)  // 160 hex
)

var (
	fixtureMutable      = []string{"time", "transactions", "prevblock"}
	fixtureCapabilities = []string{"proposal"}
)

// TemplateState is the session's latest-template view (workid/longpollid
// derivation source; refresh base).
type TemplateState struct {
	Height      int
	CurTime     int
	LongpollID  string
	LongpollURI string
	WorkID      string
}

// BaseTemplateState returns the v2.0.0 base fixture state (height=1000).
func BaseTemplateState() TemplateState {
	return TemplateState{
		Height:      FixtureHeight,
		CurTime:     FixtureCurTime,
		LongpollID:  FixtureLongpollID,
		LongpollURI: FixtureLongpollURI,
		WorkID:      FixtureWorkID,
	}
}

// Refresh derives the next template state: height+1, curtime+600,
// longpollid=lp-<height>-1 (design §6 auto-derivation ③).
func (s TemplateState) Refresh() TemplateState {
	next := s
	next.Height = s.Height + 1
	next.CurTime = s.CurTime + RefreshCurTimeDelta
	next.LongpollID = fmt.Sprintf("lp-%d-1", next.Height)
	return next
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

// jsonStringArray renders a JSON array of strings (["a","b"]).
func jsonStringArray(vals []string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = quoteJSON(v)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// BuildTemplateFull builds the 18-key template JSON (576B for the base
// fixture) in the pinned BIP 22 member order.
func BuildTemplateFull(s TemplateState) []byte {
	var b strings.Builder
	b.WriteString(`{"version":`)
	b.WriteString(strconv.Itoa(FixtureVersion))
	b.WriteString(`,"previousblockhash":`)
	b.WriteString(quoteJSON(FixturePrevHash))
	b.WriteString(`,"transactions":[]`)
	b.WriteString(`,"coinbaseaux":{"flags":`)
	b.WriteString(quoteJSON(FixtureFlags))
	b.WriteString(`},"coinbasevalue":`)
	b.WriteString(strconv.FormatInt(FixtureCoinbaseValue, 10))
	b.WriteString(`,"target":`)
	b.WriteString(quoteJSON(FixtureTarget))
	b.WriteString(`,"mintime":`)
	b.WriteString(strconv.Itoa(FixtureMinTime))
	b.WriteString(`,"mutable":`)
	b.WriteString(jsonStringArray(fixtureMutable))
	b.WriteString(`,"noncerange":`)
	b.WriteString(quoteJSON(FixtureNonceRange))
	b.WriteString(`,"sigoplimit":`)
	b.WriteString(strconv.Itoa(FixtureSigopLimit))
	b.WriteString(`,"sizelimit":`)
	b.WriteString(strconv.Itoa(FixtureSizeLimit))
	b.WriteString(`,"curtime":`)
	b.WriteString(strconv.Itoa(s.CurTime))
	b.WriteString(`,"bits":`)
	b.WriteString(quoteJSON(FixtureBits))
	b.WriteString(`,"height":`)
	b.WriteString(strconv.Itoa(s.Height))
	b.WriteString(`,"longpollid":`)
	b.WriteString(quoteJSON(s.LongpollID))
	b.WriteString(`,"longpolluri":`)
	b.WriteString(quoteJSON(s.LongpollURI))
	b.WriteString(`,"capabilities":`)
	b.WriteString(jsonStringArray(fixtureCapabilities))
	b.WriteString(`,"workid":`)
	b.WriteString(quoteJSON(s.WorkID))
	b.WriteString(`}`)
	return []byte(b.String())
}

// buildTemplateRequired builds the 14 required keys (no optional family:
// longpollid/longpolluri/capabilities/workid) — the "plain" template (457B).
func buildTemplateRequired(height int) string {
	var b strings.Builder
	b.WriteString(`{"version":`)
	b.WriteString(strconv.Itoa(FixtureVersion))
	b.WriteString(`,"previousblockhash":`)
	b.WriteString(quoteJSON(FixturePrevHash))
	b.WriteString(`,"transactions":[]`)
	b.WriteString(`,"coinbaseaux":{"flags":`)
	b.WriteString(quoteJSON(FixtureFlags))
	b.WriteString(`},"coinbasevalue":`)
	b.WriteString(strconv.FormatInt(FixtureCoinbaseValue, 10))
	b.WriteString(`,"target":`)
	b.WriteString(quoteJSON(FixtureTarget))
	b.WriteString(`,"mintime":`)
	b.WriteString(strconv.Itoa(FixtureMinTime))
	b.WriteString(`,"mutable":`)
	b.WriteString(jsonStringArray(fixtureMutable))
	b.WriteString(`,"noncerange":`)
	b.WriteString(quoteJSON(FixtureNonceRange))
	b.WriteString(`,"sigoplimit":`)
	b.WriteString(strconv.Itoa(FixtureSigopLimit))
	b.WriteString(`,"sizelimit":`)
	b.WriteString(strconv.Itoa(FixtureSizeLimit))
	b.WriteString(`,"curtime":`)
	b.WriteString(strconv.Itoa(FixtureCurTime))
	b.WriteString(`,"bits":`)
	b.WriteString(quoteJSON(FixtureBits))
	b.WriteString(`,"height":`)
	b.WriteString(strconv.Itoa(height))
	b.WriteString(`}`)
	return b.String()
}

// BuildTemplatePlain builds the 14-required-key template (457B, height=1000
// base). Plain templates update the session state's height/curtime only.
func BuildTemplatePlain(height int) []byte {
	return []byte(buildTemplateRequired(height))
}

// buildTxElement builds one transactions[] element (6 keys, pinned order:
// data,txid,hash,depends,fee,sigops).
func buildTxElement(data, txid, hash string, fee, sigops int) string {
	return `{"data":` + quoteJSON(data) +
		`,"txid":` + quoteJSON(txid) +
		`,"hash":` + quoteJSON(hash) +
		`,"depends":[],"fee":` + strconv.Itoa(fee) +
		`,"sigops":` + strconv.Itoa(sigops) + `}`
}

// fixtureTx is the standard 1-tx element (data 202 hex, fee 1000, sigops 1).
func fixtureTx() string {
	return buildTxElement(FixtureTxData, FixtureTxID, FixtureTxHash, 1000, 1)
}

// BuildTemplateTx1 builds the plain template with one transaction (853B).
func BuildTemplateTx1(height int) []byte {
	s := buildTemplateRequired(height)
	return []byte(strings.Replace(s, `"transactions":[]`,
		`"transactions":[`+fixtureTx()+`]`, 1))
}

// BuildTemplateBig builds the plain template with 3 large transactions
// (3×740-hex data; 5481B — the 跨 4 MSS 段 variant).
func BuildTemplateBig() []byte {
	s := buildTemplateRequired(FixtureHeight)
	tx := buildTxElement(FixtureTxDataBig, FixtureTxID, FixtureTxHash, 1000, 1)
	return []byte(strings.Replace(s, `"transactions":[]`,
		`"transactions":[`+tx+`,`+tx+`,`+tx+`]`, 1))
}

// BuildRequestJSON builds the request body (bitcoin-cli form default:
// {"jsonrpc":"1.0","id":N,"method":..,"params":..}; jsonrpc2 form swaps the
// version literal — both keep the same member order). id/params embed
// verbatim.
func BuildRequestJSON(id json.RawMessage, method string, params json.RawMessage, jsonrpc2 bool) []byte {
	version := `"1.0"`
	if jsonrpc2 {
		version = `"2.0"`
	}
	if len(params) == 0 {
		params = json.RawMessage(`[]`)
	}
	var b strings.Builder
	b.WriteString(`{"jsonrpc":`)
	b.WriteString(version)
	b.WriteString(`,"id":`)
	b.Write(id)
	b.WriteString(`,"method":`)
	b.WriteString(quoteJSON(method))
	b.WriteString(`,"params":`)
	b.Write(params)
	b.WriteString(`}`)
	return []byte(b.String())
}

// BuildResponseJSON builds the response body {"result":R,"error":null,"id":N}
// (no jsonrpc member — bitcoin-cli form; jsonrpc2 form prepends
// "jsonrpc":"2.0"). result embeds verbatim (template bytes, null, true, or a
// quoted reason string — use quoteJSON for the string forms).
func BuildResponseJSON(id json.RawMessage, result []byte, jsonrpc2 bool) []byte {
	if len(result) == 0 {
		result = []byte(`null`)
	}
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
// {"result":null,"error":{"code":C,"message":"M"},"id":N}.
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
// design §3.1: 请求行 → Host（HTTP/1.0 省略）→ [Authorization] →
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
