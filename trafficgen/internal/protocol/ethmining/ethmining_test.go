package ethmining

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestLineHexBaselines locks the testcase §3 / design §3.11 line-byte table.
func TestLineHexBaselines(t *testing.T) {
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"subscribe request (id=1)", BuildSubscribeReq(json.RawMessage(`1`), "", ""),
			`7B226964223A312C226D6574686F64223A226D696E696E672E737562736372696265222C22706172616D73223A5B224D696E65724E616D652F312E302E30222C22457468657265756D5374726174756D2F312E302E30225D7D0A`},
		{"subscribe response (id=1, sub, 080c)", BuildSubscribeResp(json.RawMessage(`1`), "", "", ""),
			`7B226964223A312C22726573756C74223A5B5B226D696E696E672E6E6F74696679222C226165363831326562346364373733356133303261386139646439356366373166222C22457468657265756d5374726174756d2f312e302e30225D2C2230383063225D2C226572726F72223A6E756C6C7D0A`},
		{"subscribe response (id=1, 3B a2eea0)", BuildSubscribeResp(json.RawMessage(`1`), "", "", FixtureExtranonce3),
			`7B226964223A312C22726573756C74223A5B5B226D696E696E672E6E6F74696679222C226165363831326562346364373733356133303261386139646439356366373166222C22457468657265756d5374726174756d2f312e302e30225D2C22613265656130225D2C226572726F72223A6E756C6C7D0A`},
		{"extranonce.subscribe request (id=2)", BuildExtranonceSubscribeReq(json.RawMessage(`2`)),
			`7B226964223A322C226D6574686F64223A226D696E696E672E65787472616E6F6E63652E737562736372696265222C22706172616D73223A5B5D7D0A`},
		{"response true (id=2)", BuildTrueResp(json.RawMessage(`2`)),
			`7B226964223A322C22726573756C74223A747275652C226572726F72223A6E756C6C7D0A`},
		{"authorize request (id=2, test/password)", BuildAuthorizeReq(json.RawMessage(`2`), FixtureUsername, FixturePassword),
			`7B226964223A322C226D6574686F64223A226D696E696E672E617574686F72697A65222C22706172616D73223A5B2274657374222C2270617373776f7264225D7D0A`},
		{"auth response false (24, Unauthorized user)", BuildErrorResp(json.RawMessage(`2`), 24, FixtureErrUnauthorized),
			`7B226964223A322C22726573756C74223A66616C73652C226572726F72223A5B32342C22556E617574686F72697A65642075736572222C6E756C6C5D7D0A`},
		{"set_difficulty 0.5", BuildSetDifficulty(json.RawMessage(`0.5`)),
			`7B226964223A6E756C6C2C226D6574686F64223A226D696E696E672E7365745F646966666963756C7479222C22706172616D73223A5B302E355D7D0A`},
		{"submit accept (id=3, 6B nonce)", BuildSubmitReq(json.RawMessage(`3`), FixtureUsername, FixtureJobA, FixtureMinerNonce6),
			`7B226964223A332C226D6574686F64223A226D696E696E672E7375626D6974222C22706172616D73223A5B2274657374222C226266303438386161222C22366139303964396262633066225D7D0A`},
		{"submit (id=3, 5B nonce)", BuildSubmitReq(json.RawMessage(`3`), FixtureUsername, FixtureJobA, FixtureMinerNonce5),
			`7B226964223A332C226D6574686F64223A226D696E696E672E7375626D6974222C22706172616D73223A5B2274657374222c226266303438386161222c2263666165376466373630225d7d0a`},
		{"submit ok response (id=3)", BuildTrueResp(json.RawMessage(`3`)),
			`7B226964223A332C22726573756C74223A747275652c226572726F72223A6e756c6c7d0a`},
		{"submit rej response (id=3, -1)", BuildErrorResp(json.RawMessage(`3`), -1, FixtureErrJobNotFound),
			`7B226964223A332C22726573756C74223A66616c73652c226572726f72223A5b2d312c224a6f62206e6f7420666f756e64222c6e756c6c5d7d0a`},
		{"set_extranonce (a2eea0)", BuildSetExtranonce(FixtureExtranonce3),
			`7B226964223A6E756C6C2C226D6574686F64223A226D696E696E672E7365745F65787472616E6F6E6365222C22706172616D73223A5B22613265656130225D7d0a`},
		{"notify (jobA, seedhash, headerhashA, clean=false)", BuildNotify(FixtureJobA, FixtureSeedHash, FixtureHeaderHashA, false),
			`7B226964223A6E756C6C2C226D6574686F64223A226D696E696E672E6E6F74696679222C22706172616D73223A5B226266303438386161222c2261626164386639396633393138626639303363366139303964396262633066646661356132663462396362313139363137356563383235633636313031323663222c2236343563663230313938633266333836316539343764346636376533616236336237623265323464636339303935626439313233653762333333373166366363222c66616c73655d7d0a`},
		{"notify (jobA, seedhash, headerhashA, clean=true)", BuildNotify(FixtureJobA, FixtureSeedHash, FixtureHeaderHashA, true),
			`7B226964223A6E756C6C2C226D6574686F64223A226D696E696E672E6E6F74696679222C22706172616D73223A5B226266303438386161222c2261626164386639396633393138626639303363366139303964396262633066646661356132663462396362313139363137356563383235633636313031323663222c2236343563663230313938633266333836316539343764346636376533616236336237623265323464636339303935626439313233653762333333373166366363222c747275655d7d0a`},
	}
	for _, c := range cases {
		if got := hexOf(c.got); !strings.EqualFold(got, c.want) {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
		if c.name == "submit rej response (id=3, -1)" {
			// id 3 error submit response must include the `2d31` ("-1") literal
			if !strings.Contains(strings.ToUpper(hexOf(c.got)), "2D31") {
				t.Errorf("submit reject response must carry -1 literal")
			}
		}
	}
}

// TestLineLengths locks design §3.11 line-length formulas (P0b invariant).
func TestLineLengths(t *testing.T) {
	type expect struct {
		name string
		got  int
		want int
	}
	cases := []expect{
		{"subscribe request", len(BuildSubscribeReq(json.RawMessage(`1`), "", "")), 90},
		{"subscribe response (2B 080c)", len(BuildSubscribeResp(json.RawMessage(`1`), "", "", "")), 117},
		{"subscribe response (3B a2eea0)", len(BuildSubscribeResp(json.RawMessage(`1`), "", "", FixtureExtranonce3)), 119},
		{"extranonce.subscribe request", len(BuildExtranonceSubscribeReq(json.RawMessage(`2`))), 60},
		{"response true (id=2)", len(BuildTrueResp(json.RawMessage(`2`))), 36},
		{"authorize request", len(BuildAuthorizeReq(json.RawMessage(`2`), FixtureUsername, FixturePassword)), 66},
		{"authorize response false (24)", len(BuildErrorResp(json.RawMessage(`2`), 24, FixtureErrUnauthorized)), 62},
		{"set_difficulty 0.5", len(BuildSetDifficulty(json.RawMessage(`0.5`))), 60},
		{"set_difficulty 5000012.0", len(BuildSetDifficulty(json.RawMessage(`5000012.0`))), 66},
		{"set_extranonce (a2eea0)", len(BuildSetExtranonce(FixtureExtranonce3)), 65},
		{"submit request (id=3, 6B nonce)", len(BuildSubmitReq(json.RawMessage(`3`), FixtureUsername, FixtureJobA, FixtureMinerNonce6)), 78},
		{"submit request (id=3, 5B nonce)", len(BuildSubmitReq(json.RawMessage(`3`), FixtureUsername, FixtureJobA, FixtureMinerNonce5)), 76},
		{"submit response true (id=3)", len(BuildTrueResp(json.RawMessage(`3`))), 36},
		{"submit response false (-1)", len(BuildErrorResp(json.RawMessage(`3`), -1, FixtureErrJobNotFound)), 58},
		{"notify jobA clean=false", len(BuildNotify(FixtureJobA, FixtureSeedHash, FixtureHeaderHashA, false)), 199},
		{"notify jobA clean=true", len(BuildNotify(FixtureJobA, FixtureSeedHash, FixtureHeaderHashA, true)), 198},
		{"notify MSS jobA (1500 hex)", len(BuildNotify(LineLongJobID(), FixtureSeedHash, FixtureHeaderHashA, false)), 1691},
		{"long username authorize", len(BuildAuthorizeReq(json.RawMessage(`2`), FixtureLongUser, FixtureLongPass)), 123},
		{"long username submit (6B)", len(BuildSubmitReq(json.RawMessage(`2`), FixtureLongUser, FixtureJobA, FixtureMinerNonce6)), 142},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %dB want %dB", c.name, c.got, c.want)
		}
	}
}

// TestLinePackingAndMSSBound asserts design §3.1 pack 条款 (259B 2-LF) and
// the 1691B notify MSS split boundary (design §8, testcase §4 用例 17/18).
func TestLinePackingAndMSSBound(t *testing.T) {
	// pack: set_difficulty(60) + notify(199) = 259 with exactly 2 LF boundaries.
	diff := BuildSetDifficulty(json.RawMessage(`0.5`))
	notify := BuildNotify(FixtureJobA, FixtureSeedHash, FixtureHeaderHashA, false)
	if len(diff)+len(notify) != 259 {
		t.Errorf("pack baseline set_difficulty+notify: got %d want 259", len(diff)+len(notify))
	}
	// 2 LF boundaries across the two lines (each line is one LF).
	combined := append(diff, notify...)
	lfCount := strings.Count(string(combined), "\n")
	if lfCount != 2 {
		t.Errorf("pack 259B segment should contain 2 LF boundaries, got %d", lfCount)
	}
	// MSS boundary: LineLongJobID() is 1500 hex; notify 1691 spans 1460+231.
	longID := LineLongJobID()
	if len(longID) != 1500 {
		t.Fatalf("LineLongJobID length: got %d want 1500", len(longID))
	}
	long := BuildNotify(longID, FixtureSeedHash, FixtureHeaderHashA, false)
	if len(long) != 1691 {
		t.Errorf("long notify (1500 hex job_id): got %dB want 1691B", len(long))
	}
}

// TestComplementAndExtranonceMax asserts spec §III "8 − extranonce_bytes"
// (2→6, 3→5) on the representative variants.
func TestComplementAndExtranonceMax(t *testing.T) {
	// 2B extranonce (080c) ↔ 6B minernonce (12 hex)
	if got := len(FixtureExtranonce)/2 + len(FixtureMinerNonce6)/2; got != 8 {
		t.Errorf("2B extranonce + 6B minernonce must complement to 8B total nonce, got %d", got)
	}
	// 3B extranonce (a2eea0) ↔ 5B minernonce (10 hex)
	if got := len(FixtureExtranonce3)/2 + len(FixtureMinerNonce5)/2; got != 8 {
		t.Errorf("3B extranonce + 5B minernonce must complement to 8B total nonce, got %d", got)
	}
	if len(FixtureExtranonce) > 6 || len(FixtureExtranonce3) > 6 {
		t.Errorf("extranonce exceeds 3-byte (6 hex) max")
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
