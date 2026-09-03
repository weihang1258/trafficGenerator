// Package stratum implements the Bitcoin Stratum v1 terminal layer
// (stratum 终结层, [tcp→stratum] 链): newline-delimited JSON over a plain TCP
// stream — one JSON object per line, LF (0x0a) delimited, compact serialization
// with pinned member order (requests id,method,params; responses
// id,result,error). No dissector exists for this protocol, so all assertions
// run on tcp.payload / frames (design §2 实测基线).
//
// Wire-format authority: docs/protocol-designs/75-stratum-design.md v2.1.1
// §3 — 11 message kinds (7 mining.* + client.get_version/show_message +
// BIP310 configure/set_version_mask), notify 9 params, submit 5(+1) params,
// set_extranonce 2 params, prevhash wire order = byte-reversed display order,
// hex fields lowercase even-length no 0x prefix, difficulty decimal fixed
// point. All fixture constants are pinned by the design §8 / testcase §3 and
// mirrored here; the unit test asserts the doc's line hex baselines.
package stratum

import (
	"encoding/json"
	"strings"
)

// Fixture constants (design §8 / testcase §3 — 全量钉死).
const (
	FixtureUserAgent = "MinerName/1.0.0"
	// FixtureExtranonce1 values per session (基线 / 会话 2 / 矿机 C / 轮换 / 重连).
	FixtureExtranonce1     = "ea02567c"
	FixtureExtranonce1S2   = "ea02567d"
	FixtureExtranonce1S3   = "ea02567e"
	FixtureExtranonce1Rot  = "b3f10a44"
	FixtureExtranonce1Reco = "ea02567f"
	FixtureExtranonce2     = "1a2b3c4d"         // 8 hex (2×4)
	FixtureExtranonce2Sz8  = "1a2b3c4d5e6f7081" // 16 hex (2×8)
	FixtureUsername1       = "alice.rig1"
	FixtureUsername2       = "alice.rig2"
	FixtureUsername3       = "alice.rig3"
	FixturePassword        = "x"
	FixtureJobA            = "3"
	FixtureJobB            = "4"
	FixtureVersion         = "20000000" // 4B 内部小端形态
	FixtureNbits           = "a13c2c17"
	FixtureNtime           = "64f50123"
	FixtureNonce           = "9c5a2b1d"
	// FixturePrevhashDisplay / FixturePrevhashWire = 展示序/线序一对
	// （线序 = 逐字节反转，线上携带值 — 参考实现 util.reverse_hash）.
	FixturePrevhashDisplay = "0000000000000000000234c4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4"
	FixturePrevhashWire    = "b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5c43402000000000000000000"
	FixtureCoinb1          = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1603aa1a0b2f706f6f6c2e746573742f"
	FixtureCoinb2          = "1603018e0c2f706f6f6c2e746573742f00000000"
	FixtureMerkleStep      = "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233"
	FixtureDifficulty      = `16384`
	FixtureDifficulty2     = `32768`
	FixtureSubID1          = "7f1a2b3c" // 会话 1 set_difficulty 订阅标识
	FixtureSubID2          = "9d8e7f6a" // 会话 1 notify 订阅标识
	FixtureSubID1S2        = "1c2d3e4f"
	FixtureSubID2S2        = "5a6b7c8d"
	FixtureSubID1S3        = "3e4f5a6b"
	FixtureSubID2S3        = "7c8d9e0f"
	// BIP310 (stratum_bip310_ext).
	FixtureMinerMask  = "ffffffff"
	FixtureMinBitCnt  = 16
	FixtureServerMask = "1fffe000" // 响应交集掩码 server & miner
	FixturePushMask   = "00003000"
	FixtureVersionBit = "18000000" // submit 第 6 参
	// 错误三元组文案（wiki 标题形态，fixture 钉死）.
	FixtureErrUnauthorized = "Unauthorized worker"
	FixtureErrJobNotFound  = "Job not found"
	FixtureShowMessage     = "Maintenance in 10 minutes"
)

// Fixture subscriptions arrays (JSON literals, embedded verbatim).
var (
	FixtureSubsS1 = json.RawMessage(`[["mining.set_difficulty","` + FixtureSubID1 + `"],["mining.notify","` + FixtureSubID2 + `"]]`)
	FixtureSubsS2 = json.RawMessage(`[["mining.set_difficulty","` + FixtureSubID1S2 + `"],["mining.notify","` + FixtureSubID2S2 + `"]]`)
	FixtureSubsS3 = json.RawMessage(`[["mining.set_difficulty","` + FixtureSubID1S3 + `"],["mining.notify","` + FixtureSubID2S3 + `"]]`)
)

// Fixture configure params/result (BIP310 verbatim 形态).
var (
	FixtureCfgParams = json.RawMessage(`{"version-rolling.mask":"` + FixtureMinerMask + `","version-rolling.min-bit-count":` +
		intStr(FixtureMinBitCnt) + `}`)
	FixtureCfgResult = json.RawMessage(`{"version-rolling":true,"version-rolling.mask":"` + FixtureServerMask + `"}`)
)

// LineLongCoinb1Pad appends the MSS pressure padding (design §8: coinb1_long
// = coinb1 + "6d"×665 → 1444 hex total).
func LineLongCoinb1Pad() string { return strings.Repeat("6d", 665) }

func intStr(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
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

// hexStringArray renders ["a","b"] from raw hex step strings.
func hexStringArray(steps []string) string {
	if len(steps) == 0 {
		return `[]`
	}
	parts := make([]string, len(steps))
	for i, s := range steps {
		parts[i] = quoteJSON(s)
	}
	return `[` + strings.Join(parts, ",") + `]`
}

// ---- line builders (compact JSON + LF; member order pinned) ----

// BuildSubscribeReq: {"id":<id>,"method":"mining.subscribe","params":["<ua>"]}\n
func BuildSubscribeReq(id json.RawMessage, ua string) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`1`)
	}
	if ua == "" {
		ua = FixtureUserAgent
	}
	return ln(`{"id":` + string(id) + `,"method":"mining.subscribe","params":[` + quoteJSON(ua) + `]}`)
}

// BuildSubscribeResp: {"id":<id>,"result":[<subs>,"<en1>",<size>],"error":null}\n
func BuildSubscribeResp(id json.RawMessage, subs json.RawMessage, en1 string, size int) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`1`)
	}
	if len(subs) == 0 {
		subs = FixtureSubsS1
	}
	if en1 == "" {
		en1 = FixtureExtranonce1
	}
	if size == 0 {
		size = 4
	}
	return ln(`{"id":` + string(id) + `,"result":[` + string(subs) + `,` + quoteJSON(en1) + `,` + intStr(size) + `],"error":null}`)
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

// BuildNotify: {"id":null,"method":"mining.notify","params":["<job>","<prevhash>",
// "<coinb1>","<coinb2>",[<merkle>],"<version>","<nbits>","<ntime>",<clean>]}\n
// (9 elements, pinned order — wiki §mining.notify; prevhash 线序).
func BuildNotify(jobID, prevhash, coinb1, coinb2 string, merkle []string, version, nbits, ntime string, clean bool) []byte {
	cleanStr := "false"
	if clean {
		cleanStr = "true"
	}
	return ln(`{"id":null,"method":"mining.notify","params":[` +
		quoteJSON(jobID) + `,` + quoteJSON(prevhash) + `,` + quoteJSON(coinb1) + `,` + quoteJSON(coinb2) + `,` +
		hexStringArray(merkle) + `,` + quoteJSON(version) + `,` + quoteJSON(nbits) + `,` + quoteJSON(ntime) + `,` +
		cleanStr + `]}`)
}

// BuildSetExtranonce: {"id":null,"method":"mining.set_extranonce","params":["<en1>",<size>]}\n
// (2 elements — the ethash 1-element dialect is rejected by the planner).
func BuildSetExtranonce(en1 string, size int) []byte {
	if en1 == "" {
		en1 = FixtureExtranonce1Rot
	}
	if size == 0 {
		size = 8
	}
	return ln(`{"id":null,"method":"mining.set_extranonce","params":[` + quoteJSON(en1) + `,` + intStr(size) + `]}`)
}

// BuildSubmitReq: {"id":<id>,"method":"mining.submit","params":["<user>","<job>",
// "<en2>","<ntime>","<nonce>"[,"<version_bits>"]]}\n (5 params; the 6th
// version_bits param is appended only when version-rolling is active).
func BuildSubmitReq(id json.RawMessage, user, jobID, en2, ntime, nonce, versionBits string) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`3`)
	}
	params := quoteJSON(user) + `,` + quoteJSON(jobID) + `,` + quoteJSON(en2) + `,` + quoteJSON(ntime) + `,` + quoteJSON(nonce)
	if versionBits != "" {
		params += `,` + quoteJSON(versionBits)
	}
	return ln(`{"id":` + string(id) + `,"method":"mining.submit","params":[` + params + `]}`)
}

// BuildGetVersionReq: {"id":<id>,"method":"client.get_version","params":[]}\n
// (the ONLY pool→miner request; direction reversed).
func BuildGetVersionReq(id json.RawMessage) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`8`)
	}
	return ln(`{"id":` + string(id) + `,"method":"client.get_version","params":[]}`)
}

// BuildVersionResp: {"id":<id>,"result":"<version>","error":null}\n
func BuildVersionResp(id json.RawMessage, version string) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`8`)
	}
	if version == "" {
		version = FixtureUserAgent
	}
	return ln(`{"id":` + string(id) + `,"result":` + quoteJSON(version) + `,"error":null}`)
}

// BuildShowMessage: {"id":null,"method":"client.show_message","params":["<msg>"]}\n
func BuildShowMessage(msg string) []byte {
	if msg == "" {
		msg = FixtureShowMessage
	}
	return ln(`{"id":null,"method":"client.show_message","params":[` + quoteJSON(msg) + `]}`)
}

// BuildConfigureReq: {"id":<id>,"method":"mining.configure","params":[<exts>,<params>]}\n
// (BIP310: [0] extension-name array, [1] extension-parameter map — both
// REQUIRED; both embed verbatim).
func BuildConfigureReq(id json.RawMessage, exts, params json.RawMessage) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`5`)
	}
	if len(exts) == 0 {
		exts = json.RawMessage(`["version-rolling"]`)
	}
	if len(params) == 0 {
		params = FixtureCfgParams
	}
	return ln(`{"id":` + string(id) + `,"method":"mining.configure","params":[` + string(exts) + `,` + string(params) + `]}`)
}

// BuildConfigureResp: {"id":<id>,"result":<result map>,"error":null}\n
func BuildConfigureResp(id json.RawMessage, result json.RawMessage) []byte {
	if len(id) == 0 {
		id = json.RawMessage(`5`)
	}
	if len(result) == 0 {
		result = FixtureCfgResult
	}
	return ln(`{"id":` + string(id) + `,"result":` + string(result) + `,"error":null}`)
}

// BuildSetVersionMask: {"id":null,"method":"mining.set_version_mask","params":["<mask>"]}\n
func BuildSetVersionMask(mask string) []byte {
	if mask == "" {
		mask = FixturePushMask
	}
	return ln(`{"id":null,"method":"mining.set_version_mask","params":[` + quoteJSON(mask) + `]}`)
}

// ln appends the line terminator (single LF — design §3.1: CR is not part of
// this protocol; CRLF is a negative case).
func ln(s string) []byte { return []byte(s + "\n") }
