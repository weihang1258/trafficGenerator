package stratum

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestLineHexBaselines asserts the testcase §3 line-byte table (the byte
// authority for cases/stratum.json). Every line length is a pinned constant
// per design §3.13.
func TestLineHexBaselines(t *testing.T) {
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"subscribe request (id=1, ua=MinerName/1.0.0)", BuildSubscribeReq(json.RawMessage(`1`), ""),
			`7B226964223A312C226D6574686F64223A226D696E696E672E737562736372696265222C22706172616D73223A5B224D696E65724E616D652F312E302E30225D7D0A`},
		{"subscribe response (id=1, sub S1, en1=ea02567c, size=4)", BuildSubscribeResp(json.RawMessage(`1`), nil, "", 0),
			`7B226964223A312C22726573756C74223A5B5B5B226D696E696E672E7365745F646966666963756C7479222C223766316132623363225D2C5B226D696E696E672E6E6F74696679222C223964386537663661225D5D2C226561303235363763222C345D2C226572726F72223A6E756C6C7D0A`},
		{"subscribe response (id=1, size=8)", BuildSubscribeResp(json.RawMessage(`1`), nil, "", 8),
			`7B226964223A312C22726573756C74223A5B5B5B226D696E696E672E7365745F646966666963756C7479222C223766316132623363225D2C5B226D696E696E672E6E6F74696679222C223964386537663661225D5D2C226561303235363763222C385D2C226572726F72223A6E756C6C7D0A`},
		{"extranonce.subscribe request (id=2)", BuildExtranonceSubscribeReq(json.RawMessage(`2`)),
			`7B226964223A322C226D6574686F64223A226D696E696E672E65787472616E6F6E63652E737562736372696265222C22706172616D73223A5B5D7D0A`},
		{"response true (id=2)", BuildTrueResp(json.RawMessage(`2`)),
			`7B226964223A322C22726573756C74223A747275652C226572726F72223A6E756C6C7D0A`},
		{"authorize request (id=2, alice.rig1, x)", BuildAuthorizeReq(json.RawMessage(`2`), FixtureUsername1, FixturePassword),
			`7B226964223A322C226D6574686F64223A226D696E696E672E617574686F72697A65222C22706172616D73223A5B22616C6963652E72696731222C2278225D7D0A`},
		{"authorize response false (id=2, 24)", BuildErrorResp(json.RawMessage(`2`), 24, FixtureErrUnauthorized),
			`7B226964223A322C22726573756C74223A66616C73652C226572726F72223A5B32342C22556E617574686F72697A656420776F726B6572222C6E756C6C5D7D0A`},
		{"set_difficulty 16384", BuildSetDifficulty(nil),
			`7B226964223A6E756C6C2C226D6574686F64223A226D696E696E672E7365745F646966666963756C7479222C22706172616D73223A5B31363338345D7D0A`},
		{"set_difficulty 32768", BuildSetDifficulty(json.RawMessage(FixtureDifficulty2)),
			`7B226964223A6E756C6C2C226D6574686F64223A226D696E696E672E7365745F646966666963756C7479222C22706172616D73223A5B33323736385D7D0A`},
		{"set_extranonce (b3f10a44, 4)", BuildSetExtranonce(FixtureExtranonce1Rot, 4),
			`7B226964223A6E756C6C2C226D6574686F64223A226D696E696E672E7365745F65787472616E6F6E6365222C22706172616D73223A5B226233663130613434222C345D7D0A`},
		{"submit accept (id=3, alice.rig1, job 3, 8hex en2, ntime, nonce)", BuildSubmitReq(json.RawMessage(`3`), FixtureUsername1, FixtureJobA, FixtureExtranonce2, FixtureNtime, FixtureNonce, ""),
			`7B226964223A332C226D6574686F64223A226D696E696E672E7375626D6974222C22706172616D73223A5B22616C6963652E72696731222C2233222C223161326233633464222C223634663530313233222C223963356132623164225D7D0A`},
		{"submit reject (id=3, error 21)", BuildErrorResp(json.RawMessage(`3`), 21, FixtureErrJobNotFound),
			`7B226964223A332C22726573756C74223A66616C73652C226572726F72223A5B32312C224A6F62206E6F7420666F756E64222C6E756C6C5D7D0A`},
		{"submit 6 params (id=6, version_bits)", BuildSubmitReq(json.RawMessage(`6`), FixtureUsername1, FixtureJobA, FixtureExtranonce2, FixtureNtime, FixtureNonce, FixtureVersionBit),
			`7B226964223A362C226D6574686F64223A226D696E696E672E7375626D6974222C22706172616D73223A5B22616C6963652E72696731222C2233222C223161326233633464222C223634663530313233222C223963356132623164222C223138303030303030225D7D0A`},
		{"client.get_version request (id=8)", BuildGetVersionReq(json.RawMessage(`8`)),
			`7B226964223A382C226D6574686F64223A22636C69656E742E6765745F76657273696F6E222C22706172616D73223A5B5D7D0A`},
		{"client.get_version response (id=8)", BuildVersionResp(json.RawMessage(`8`), ""),
			`7B226964223A382C22726573756C74223A224D696E65724E616D652F312E302E30222C226572726F72223A6E756C6C7D0A`},
		{"client.show_message", BuildShowMessage(""),
			`7B226964223A6E756C6C2C226D6574686F64223A22636C69656E742E73686F775F6D657373616765222C22706172616D73223A5B224D61696E74656E616E636520696E203130206D696E75746573225D7D0A`},
		{"mining.configure request (id=5)", BuildConfigureReq(json.RawMessage(`5`), nil, nil),
			`7B226964223A352C226D6574686F64223A226D696E696E672E636F6E666967757265222C22706172616D73223A5B5B2276657273696F6E2D726F6C6C696E67225D2C7B2276657273696F6E2D726F6C6C696E672E6D61736B223A226666666666666666222C2276657273696F6E2D726F6C6C696E672E6D696E2D6269742D636F756E74223A31367D5D7D0A`},
		{"mining.configure response (id=5)", BuildConfigureResp(json.RawMessage(`5`), nil),
			`7B226964223A352C22726573756C74223A7B2276657273696F6E2D726F6C6C696E67223A747275652C2276657273696F6E2D726F6C6C696E672E6D61736B223A223166666665303030227D2C226572726F72223A6E756C6C7D0A`},
		{"set_version_mask 00003000", BuildSetVersionMask(""),
			`7B226964223A6E756C6C2C226D6574686F64223A226D696E696E672E7365745F76657273696F6E5F6D61736B222C22706172616D73223A5B223030303033303030225D7D0A`},
		{"notify (job 3, clean=false) basic shape", BuildNotify(FixtureJobA, FixturePrevhashWire, FixtureCoinb1, FixtureCoinb2,
			[]string{FixtureMerkleStep}, FixtureVersion, FixtureNbits, FixtureNtime, false),
			`7B226964223A6E756C6C2C226D6574686F64223A226D696E696E672E6E6F74696679222C22706172616D73223A5B2233222C22` +
				strings.ToUpper(hexOf([]byte(FixturePrevhashWire))) +
				`222C22` + strings.ToUpper(hexOf([]byte(FixtureCoinb1))) + `222C22` + strings.ToUpper(hexOf([]byte(FixtureCoinb2))) +
				`222C5B22` + strings.ToUpper(hexOf([]byte(FixtureMerkleStep))) + `225D2C223230303030303030222C226131336332633137222C223634663530313233222C66616C73655D7D0A`},
	}
	for _, c := range cases {
		if got := strings.ToUpper(hexOf(c.got)); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
}

// TestLineLengths locks the doc §3.13 line-length formulas (P0b invariant).
func TestLineLengths(t *testing.T) {
	type expect struct {
		name string
		got  int
		want int
	}
	cases := []expect{
		{"subscribe request", len(BuildSubscribeReq(json.RawMessage(`1`), "")), 66},
		{"subscribe response (size 4)", len(BuildSubscribeResp(json.RawMessage(`1`), nil, "", 0)), 114},
		{"subscribe response (size 8)", len(BuildSubscribeResp(json.RawMessage(`1`), nil, "", 8)), 114},
		{"extranonce.subscribe request", len(BuildExtranonceSubscribeReq(json.RawMessage(`2`))), 60},
		{"response true (id=2)", len(BuildTrueResp(json.RawMessage(`2`))), 36},
		{"authorize request", len(BuildAuthorizeReq(json.RawMessage(`2`), FixtureUsername1, FixturePassword)), 65},
		{"authorize response false (24)", len(BuildErrorResp(json.RawMessage(`2`), 24, FixtureErrUnauthorized)), 64},
		{"set_difficulty 16384", len(BuildSetDifficulty(nil)), 62},
		{"set_difficulty 32768", len(BuildSetDifficulty(json.RawMessage(FixtureDifficulty2))), 62},
		{"set_extranonce (b3f10a44,4)", len(BuildSetExtranonce(FixtureExtranonce1Rot, 4)), 69},
		{"submit request (id=3, 8hex en2)", len(BuildSubmitReq(json.RawMessage(`3`), FixtureUsername1, FixtureJobA, FixtureExtranonce2, FixtureNtime, FixtureNonce, "")), 95},
		{"submit response false (21)", len(BuildErrorResp(json.RawMessage(`3`), 21, FixtureErrJobNotFound)), 58},
		{"submit 6 params (id=6)", len(BuildSubmitReq(json.RawMessage(`6`), FixtureUsername1, FixtureJobA, FixtureExtranonce2, FixtureNtime, FixtureNonce, FixtureVersionBit)), 106},
		{"get_version request (id=8)", len(BuildGetVersionReq(json.RawMessage(`8`))), 51},
		{"get_version response (id=8)", len(BuildVersionResp(json.RawMessage(`8`), "")), 49},
		{"show_message", len(BuildShowMessage("")), 82},
		{"configure request (id=5)", len(BuildConfigureReq(json.RawMessage(`5`), nil, nil)), 139},
		{"configure response (id=5)", len(BuildConfigureResp(json.RawMessage(`5`), nil)), 90},
		{"set_version_mask 00003000", len(BuildSetVersionMask("")), 69},
		{"notify job 3 clean=false", len(BuildNotify(FixtureJobA, FixturePrevhashWire, FixtureCoinb1, FixtureCoinb2,
			[]string{FixtureMerkleStep}, FixtureVersion, FixtureNbits, FixtureNtime, false)), 387},
		{"notify empty merkle clean=true", len(BuildNotify(FixtureJobA, FixturePrevhashWire, FixtureCoinb1, FixtureCoinb2,
			nil, FixtureVersion, FixtureNbits, FixtureNtime, true)), 320},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %dB want %dB", c.name, c.got, c.want)
		}
	}
}

// TestNotifyShapeAndLongForm asserts the doc §3.13 387B / 320B bases and the
// large coinb1 variant (1717B = 75+1+64+1444+40+64+8+8+8+5+LF; §8 boundary).
func TestNotifyShapeAndLongForm(t *testing.T) {
	long := BuildNotify(FixtureJobA, FixturePrevhashWire, FixtureCoinb1+LineLongCoinb1Pad(), FixtureCoinb2,
		[]string{FixtureMerkleStep}, FixtureVersion, FixtureNbits, FixtureNtime, false)
	if len(long) != 1717 {
		t.Errorf("long notify: got %dB want 1717B (coinb1_long=1444 hex)", len(long))
	}
	// Default notify carries 1 merkle step; empty-merkle variant is
	// 67B shorter (64+3 brackets/quotes).
	empty := BuildNotify(FixtureJobA, FixturePrevhashWire, FixtureCoinb1, FixtureCoinb2, nil, FixtureVersion, FixtureNbits, FixtureNtime, true)
	if len(empty) != 320 {
		t.Errorf("empty merkle notify: got %dB want 320B", len(empty))
	}
	if !strings.Contains(string(empty), `[]`) {
		t.Errorf("empty merkle branch must serialize as []")
	}
}

// TestPrevhashWireOrder locks the display→wire byte reversal invariant
// (design §3.1 + reference impl util.reverse_hash).
func TestPrevhashWireOrder(t *testing.T) {
	if len(FixturePrevhashDisplay) != 64 || len(FixturePrevhashWire) != 64 {
		t.Fatalf("prevhash fixture length wrong")
	}
	// wire = display with byte order reversed (per §3.1 "reverse_hash" utility).
	// Convert hex→bytes, reverse bytes, convert back to hex.
	got := FixturePrevhashWire
	want := reverseHex(FixturePrevhashDisplay)
	if got != want {
		t.Errorf("prevhash wire mismatch:\n got %s\nwant %s", got, want)
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

// reverseHex converts a hex string to bytes, reverses byte order, and
// converts back (design §3.1 reverse_hash semantics).
func reverseHex(s string) string {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		fmt.Sscanf(s[2*i:2*i+2], "%02x", &b[i])
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return hexOf(b)
}
