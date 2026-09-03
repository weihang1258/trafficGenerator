// Package ethmining implements the Ethereum Stratum v1 terminal layer
// (ethash 挖矿 stratum, [tcp→ethmining] 链): newline-delimited JSON over a
// plain TCP stream — one JSON object per line, LF (0x0a) delimited, compact
// serialization with pinned member order (requests/notifications
// id,method,params; responses id,result,error). Distinct from Bitcoin
// stratum: notify carries 4 params (job_id/seed_hash/header_hash/clean_jobs),
// submit carries 3 params (worker/job_id/minernonce), set_extranonce is the
// 1-element ethash dialect, and extranonce (≤3 bytes) ‖ minernonce is
// hard-pinned to 8 bytes total. No dissector exists, so all assertions run
// on tcp.payload / frames (design §2 实测基线).
//
// Wire-format authority: docs/protocol-designs/73-ethmining-design.md v2.0.2
// §3 (NiceHash EthereumStratum_NiceHash_v1.0.0 R2 + extranonce subscribe
// extension). All fixture constants are pinned by the design §3/testcase §3
// spec-verbatim tables and mirrored here; the unit test asserts the doc's
// line hex baselines.
package ethmining

import (
	"encoding/json"
	"strings"
)

// Fixture constants (design §3 / testcase §3 — 全量钉死, spec verbatim).
const (
	FixtureUserAgent  = "MinerName/1.0.0"
	FixtureProtocol   = "EthereumStratum/1.0.0"
	FixtureSubID      = "ae6812eb4cd7735a302a8a9dd95cf71f" // spec §III verbatim
	FixtureSubIDS2    = "b7c31e0a55d29f7f1e9a04c8d2b6a3f4" // 第二会话 fixture
	FixtureExtranonce = "080c"                            // 2B 基线 (spec §III)
	FixtureExtranonce3 = "a2eea0"                         // 3B 满值 (spec §IV)
	FixtureExtranonceS2 = "1f0a"                          // 第二会话 fixture
	FixtureUsername   = "test"
	FixtureUsername2  = "test2"
	FixturePassword   = "password" // spec §IV verbatim
	FixturePassword2  = "x"
	FixtureLongUser   = "00112233445566778899aabbccddeeff00112233.rig-north-01-cabinet3-slot7" // 68 字符
	FixtureLongPass   = "x"
	FixtureJobA       = "bf0488aa" // spec §III verbatim
	FixtureJobB       = "bf0488ab" // fixture 钉死
	FixtureSeedHash   = "abad8f99f3918bf903c6a909d9bbc0fdfa5a2f4b9cb1196175ec825c6610126c" // spec §III
	FixtureHeaderHashA = "645cf20198c2f3861e947d4f67e3ab63b7b2e24dcc9095bd9123e7b33371f6cc" // spec §III
	FixtureHeaderHashB = "fc12eb20c58158071c956316cdcd12a22dd8bf126ac4aee559f0ffe4df11f279" // spec §IV
	FixtureMinerNonce6 = "6a909d9bbc0f" // 6B (spec §III, 配 2B extranonce)
	FixtureMinerNonce5 = "cfae7df760"   // 5B (spec §IV, 配 3B extranonce)
	FixtureMinerNonce6B = "68765fccd712" // lifecycle 第二笔 submit (fixture)
	FixtureDifficulty  = `0.5`           // spec §III verbatim
	FixtureDifficulty2 = `5000012.0`     // 大值变体 fixture
	FixtureDifficultyS2 = `2.0`          // 第二会话 fixture
	// 错误三元组 (spec verbatim / 标准惯例 fixture).
	FixtureErrJobNotFound  = "Job not found"
	FixtureErrUnauthorized = "Unauthorized user"
	FixtureErrNotSupported = "Not supported."
	FixtureErrCodeSubmit   = -1 // submit 拒绝 (spec §III)
	FixtureErrCodeAuth     = 24 // authorize 拒绝 (标准 stratum 惯例)
	FixtureErrCodeExt      = 20 // extranonce.subscribe 不支持 (ext)
)

// LineLongJobID returns the MSS-pressure job_id (testcase §4 用例 18:
// job_id = "a3"×750 → 1500 hex chars; notify line 1691B crosses MSS 1460).
func LineLongJobID() string { return strings.Repeat("a3", 750) }

func intStr(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// quoteJSON renders a Go string as a JSON string literal (ASCII fixture
// values only; non-ASCII/control bytes fall back to encoding/json).
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

// ---- line builders (compact JSON + LF; member order pinned) ----

// BuildSubscribeReq: {"id":<id>,"method":"mining.subscribe","params":["<ua>","<proto>"]}\n
func BuildSubscribeReq(id json.RawMessage, ua, proto string) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`1`)
	}
	if ua == "" {
		ua = FixtureUserAgent
	}
	if proto == "" {
		proto = FixtureProtocol
	}
	return ln(`{"id":` + string(id) + `,"method":"mining.subscribe","params":[` + quoteJSON(ua) + `,` + quoteJSON(proto) + `]}`)
}

// BuildSubscribeResp: {"id":<id>,"result":[["mining.notify","<subid>","<proto>"],"<en>"],"error":null}\n
func BuildSubscribeResp(id json.RawMessage, subID, proto, extranonce string) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`1`)
	}
	if subID == "" {
		subID = FixtureSubID
	}
	if proto == "" {
		proto = FixtureProtocol
	}
	if extranonce == "" {
		extranonce = FixtureExtranonce
	}
	return ln(`{"id":` + string(id) + `,"result":[["mining.notify",` + quoteJSON(subID) + `,` + quoteJSON(proto) + `],` + quoteJSON(extranonce) + `],"error":null}`)
}

// BuildExtranonceSubscribeReq: {"id":<id>,"method":"mining.extranonce.subscribe","params":[]}\n
func BuildExtranonceSubscribeReq(id json.RawMessage) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`2`)
	}
	return ln(`{"id":` + string(id) + `,"method":"mining.extranonce.subscribe","params":[]}`)
}

// BuildTrueResp: {"id":<id>,"result":true,"error":null}\n
func BuildTrueResp(id json.RawMessage) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`2`)
	}
	return ln(`{"id":` + string(id) + `,"result":true,"error":null}`)
}

// BuildAuthorizeReq: {"id":<id>,"method":"mining.authorize","params":["<user>","<pass>"]}\n
func BuildAuthorizeReq(id json.RawMessage, user, pass string) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`2`)
	}
	return ln(`{"id":` + string(id) + `,"method":"mining.authorize","params":[` + quoteJSON(user) + `,` + quoteJSON(pass) + `]}`)
}

// BuildErrorResp builds the result:false + error triple form:
// {"id":<id>,"result":false,"error":[<code>,"<msg>",null]}\n
func BuildErrorResp(id json.RawMessage, code int, msg string) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`2`)
	}
	return ln(`{"id":` + string(id) + `,"result":false,"error":[` + intStr(code) + `,` + quoteJSON(msg) + `,null]}`)
}

// BuildSetDifficulty: {"id":null,"method":"mining.set_difficulty","params":[<difficulty>]}\n
// difficulty embeds verbatim (JSON number, decimal fixed point).
func BuildSetDifficulty(difficulty json.RawMessage) []byte {
	if len(difficulty) == 0 {
		difficulty = json.RawMessage(FixtureDifficulty)
	}
	return ln(`{"id":null,"method":"mining.set_difficulty","params":[` + string(difficulty) + `]}`)
}

// BuildNotify: {"id":null,"method":"mining.notify","params":["<job>","<seed>","<header>",<clean>]}\n
// (4 elements, pinned order — spec §III).
func BuildNotify(jobID, seedHash, headerHash string, clean bool) []byte {
	cleanStr := "false"
	if clean {
		cleanStr = "true"
	}
	return ln(`{"id":null,"method":"mining.notify","params":[` +
		quoteJSON(jobID) + `,` + quoteJSON(seedHash) + `,` + quoteJSON(headerHash) + `,` +
		cleanStr + `]}`)
}

// BuildSetExtranonce: {"id":null,"method":"mining.set_extranonce","params":["<en>"]}\n
// (1 element — the ethash dialect, spec §III; bitcoin's 2-element form is
// rejected by the planner).
func BuildSetExtranonce(extranonce string) []byte {
	if extranonce == "" {
		extranonce = FixtureExtranonce3
	}
	return ln(`{"id":null,"method":"mining.set_extranonce","params":[` + quoteJSON(extranonce) + `]}`)
}

// BuildSubmitReq: {"id":<id>,"method":"mining.submit","params":["<user>","<job>","<nonce>"]}\n
// (3 elements — spec §III; minernonce bytes = 8 − extranonce bytes).
func BuildSubmitReq(id json.RawMessage, user, jobID, minerNonce string) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`3`)
	}
	return ln(`{"id":` + string(id) + `,"method":"mining.submit","params":[` + quoteJSON(user) + `,` + quoteJSON(jobID) + `,` + quoteJSON(minerNonce) + `]}`)
}

// ln appends the line terminator (single LF — design §3.1: CR is not part
// of this protocol; CRLF is a negative case).
func ln(s string) []byte { return []byte(s + "\n") }
