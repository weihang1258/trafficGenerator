package doh

// 字节级断言，逐条对应设计契约 v2.2.1 §3（docs/protocol-designs/
// 66-doh-design.md）：
//   - §3.2 DNS header 12B 大端 + flags 值域（01 00 / 81 80 / 85 80）
//   - §3.3 Question/Answer 编码（QNAME label、A/AAAA/TXT/MX/SOA/HTTPS）
//   - §3.4 base64url 无填充（长度公式 ceil(L*4/3)：33→44、19→26、20→27、
//     17→23、271→362）
//   - §3.5 长度公式（www.example.com 查询 33B；+A 答案响应 64B）
//   - §3.1 HTTP 帧钉死头序（POST/GET/2xx/非 2xx 四形态）
//   - §3.6 Cache-Control max-age = 答案最小 TTL / SOA MINIMUM / 0
import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// baselineQuery 是 www.example.com A RD=1 ID=0x1234 的查询 wire（§3.5 例：
// 12+17+4=33B）。逐字节钉死，与公式互证。
const baselineQueryHex = "1234" + // ID
	"0100" + // flags: RD=1
	"0001" + // QDCOUNT
	"0000" + // ANCOUNT
	"0000" + // NSCOUNT
	"0000" + // ARCOUNT
	"03777777076578616d706c6503636f6d00" + // QNAME www.example.com
	"0001" + // QTYPE A
	"0001" // QCLASS IN

// baselineResponseHex 是上查询 + 一条 A(192.0.2.1, TTL 300) 答案的响应
// wire（§3.5 例：12+21+31=64B；flags 0x8180 = QR|RD|RA）。
const baselineResponseHex = "1234" +
	"8180" + // flags: QR=1 RD echo RA=1
	"0001" +
	"0001" +
	"0000" +
	"0000" +
	"03777777076578616d706c6503636f6d00" +
	"0001" +
	"0001" +
	"03777777076578616d706c6503636f6d00" + // answer NAME (完整 QNAME，不压缩)
	"0001" + // TYPE A
	"0001" + // CLASS IN
	"0000012c" + // TTL 300
	"0004" + // RDLENGTH
	"c0000201" // RDATA 192.0.2.1

func baselineQuery() QuerySpec {
	qn, err := EncodeQName(FixtureName)
	if err != nil {
		panic(err)
	}
	return QuerySpec{ID: 0x1234, Name: FixtureName, QName: qn, QType: 1, QClass: 1, RD: true}
}

// ---- §3.2/§3.5 DNS wire ----

func TestEncodeQueryWireBaseline(t *testing.T) {
	w := EncodeQueryWire(baselineQuery())
	if got := hex.EncodeToString(w); got != baselineQueryHex {
		t.Fatalf("query wire:\n got %s\nwant %s", got, baselineQueryHex)
	}
	if len(w) != 33 {
		t.Fatalf("www.example.com query = %d bytes, want 33 (12+17+4, §3.5)", len(w))
	}
}

func TestEncodeQueryWireRDFalse(t *testing.T) {
	q := baselineQuery()
	q.RD = false
	w := EncodeQueryWire(q)
	if w[2] != 0x00 || w[3] != 0x00 {
		t.Fatalf("RD=0 flags = %02x %02x, want 00 00", w[2], w[3])
	}
}

func TestEncodeResponseWireBaseline(t *testing.T) {
	q := baselineQuery()
	a, _ := BuildA(FixtureA)
	rr, err := EncodeRR(q.QName, 1, 1, 300, a)
	if err != nil {
		t.Fatalf("EncodeRR: %v", err)
	}
	w := EncodeResponseWire(ResponseSpec{ID: q.ID, Query: q, RA: true, Answers: []EncodedRR{rr}})
	if got := hex.EncodeToString(w); got != baselineResponseHex {
		t.Fatalf("response wire:\n got %s\nwant %s", got, baselineResponseHex)
	}
	if len(w) != 64 {
		t.Fatalf("+A response = %d bytes, want 64 (§3.5)", len(w))
	}
	// 响应 ID 回带请求 ID（§3.2 ID 行为）。
	if w[0] != 0x12 || w[1] != 0x34 {
		t.Fatalf("response ID = %02x%02x, want echo 1234", w[0], w[1])
	}
}

// §3.2：AA/TC/RA bit 布局——0x8180 基础上 AA(0x0400)→0x8580、TC(0x0200)→
// 0x8380；RA=0 → 0x8100。
func TestEncodeResponseWireFlagBits(t *testing.T) {
	build := func(aa, tc, ra bool) []byte {
		q := baselineQuery()
		return EncodeResponseWire(ResponseSpec{ID: q.ID, Query: q, AA: aa, TC: tc, RA: ra})
	}
	for _, tc := range []struct {
		aa, tc, ra bool
		hi, lo     byte
	}{
		{false, false, true, 0x81, 0x80},
		{true, false, true, 0x85, 0x80},
		{false, true, true, 0x83, 0x80},
		{false, false, false, 0x81, 0x00},
	} {
		w := build(tc.aa, tc.tc, tc.ra)
		if w[2] != tc.hi || w[3] != tc.lo {
			t.Errorf("flags(aa=%v,tc=%v,ra=%v) = %02x %02x, want %02x %02x",
				tc.aa, tc.tc, tc.ra, w[2], w[3], tc.hi, tc.lo)
		}
	}
}

// §3.2：RCODE 低 4 bit 进 flags，ANCOUNT/NSCOUNT 随答案/权威区数。
func TestEncodeResponseWireCounts(t *testing.T) {
	q := baselineQuery()
	a, _ := BuildA(FixtureA)
	rr, _ := EncodeRR(q.QName, 1, 1, 60, a)
	for _, tc := range []struct {
		rcode      uint8
		answers    int
		authority  int
		wantLoFlag byte
	}{
		{0, 0, 0, 0x80},
		{3, 0, 0, 0x83}, // NXDOMAIN, 空答案
		{2, 2, 1, 0x82},
	} {
		spec := ResponseSpec{ID: q.ID, Query: q, RCode: tc.rcode, RA: true}
		for i := 0; i < tc.answers; i++ {
			spec.Answers = append(spec.Answers, rr)
		}
		for i := 0; i < tc.authority; i++ {
			spec.Authority = append(spec.Authority, rr)
		}
		w := EncodeResponseWire(spec)
		if w[3]&0x0F != tc.wantLoFlag&0x0F {
			t.Errorf("rcode=%d flags lo = %02x, low nibble %x", tc.rcode, w[3], w[3]&0x0F)
		}
		if an := int(w[6])<<8 | int(w[7]); an != tc.answers {
			t.Errorf("rcode=%d ANCOUNT = %d, want %d", tc.rcode, an, tc.answers)
		}
		if ns := int(w[8])<<8 | int(w[9]); ns != tc.authority {
			t.Errorf("rcode=%d NSCOUNT = %d, want %d", tc.rcode, ns, tc.authority)
		}
		if ar := int(w[10])<<8 | int(w[11]); ar != 0 {
			t.Errorf("rcode=%d ARCOUNT = %d, want 0 (无 EDNS OPT)", tc.rcode, ar)
		}
	}
}

// ---- §3.3 QNAME 与 RDATA ----

func TestEncodeQName(t *testing.T) {
	for _, tc := range []struct {
		name string
		want string // hex
	}{
		{"", "00"},
		{".", "00"},
		{"com", "03636f6d00"},
		{"www.example.com", "03777777076578616d706c6503636f6d00"},
		{"a.b.c", "01610162016300"},
	} {
		got, err := EncodeQName(tc.name)
		if err != nil {
			t.Fatalf("EncodeQName(%q): %v", tc.name, err)
		}
		if hex.EncodeToString(got) != tc.want {
			t.Errorf("EncodeQName(%q) = %s, want %s", tc.name, hex.EncodeToString(got), tc.want)
		}
	}
}

func TestEncodeQNameErrors(t *testing.T) {
	if _, err := EncodeQName(strings.Repeat("a", 64) + ".com"); err == nil {
		t.Error("64-byte label must be rejected (63 bound)")
	}
	if _, err := EncodeQName("www..com"); err == nil {
		t.Error("empty label must be rejected")
	}
	if _, err := EncodeQName("www.example.com."); err == nil {
		t.Error("trailing dot must be rejected (隐式根)")
	}
}

// §2.3.4 255 上界由调用方检查（planner 已测）；63 边界标签本身可通过。
func TestEncodeQNameLabel63(t *testing.T) {
	name := strings.Repeat("a", 63) + ".com"
	qn, err := EncodeQName(name)
	if err != nil {
		t.Fatalf("63-byte label must encode: %v", err)
	}
	// 展示长 67 → QNAME_len 69（§3.5 公式：len+2，与标签数无关）。
	if len(qn) != 69 {
		t.Fatalf("QNAME_len = %d, want 69", len(qn))
	}
}

func TestBuildAAndAAAA(t *testing.T) {
	a, err := BuildA("192.0.2.1")
	if err != nil || hex.EncodeToString(a) != "c0000201" {
		t.Fatalf("BuildA = %x err %v, want c0000201", a, err)
	}
	if _, err := BuildA("2001:db8::1"); err == nil {
		t.Error("IPv6 literal in A rdata must be rejected")
	}
	aaaa, err := BuildAAAA("2001:db8::1")
	if err != nil || len(aaaa) != 16 || hex.EncodeToString(aaaa[:4]) != "20010db8" {
		t.Fatalf("BuildAAAA = %x err %v", aaaa, err)
	}
	if _, err := BuildAAAA("192.0.2.1"); err == nil {
		t.Error("IPv4 literal in AAAA rdata must be rejected")
	}
	if _, err := BuildA("not-an-ip"); err == nil {
		t.Error("unparseable A rdata must be rejected")
	}
}

func TestBuildTXT(t *testing.T) {
	rd, err := BuildTXT([]string{"hello", "world"})
	if err != nil {
		t.Fatalf("BuildTXT: %v", err)
	}
	if hex.EncodeToString(rd) != "0568656c6c6f05776f726c64" {
		t.Fatalf("TXT rdata = %x, want 05 hello 05 world", rd)
	}
	if _, err := BuildTXT([]string{strings.Repeat("x", 256)}); err == nil {
		t.Error("256-byte TXT string must be rejected (255 bound)")
	}
	// 255 边界通过。
	if _, err := BuildTXT([]string{strings.Repeat("x", 255)}); err != nil {
		t.Fatalf("255-byte TXT string must encode: %v", err)
	}
}

func TestBuildSvcParam(t *testing.T) {
	// key=1 (alpn) value "h2" → 0001 0002 6832。
	sp, err := BuildSvcParam(1, "6832")
	if err != nil || hex.EncodeToString(sp) != "000100026832" {
		t.Fatalf("SvcParam = %x err %v, want 0001 0002 6832", sp, err)
	}
	// 空值 → 零长度。
	sp0, err := BuildSvcParam(2, "")
	if err != nil || hex.EncodeToString(sp0) != "00020000" {
		t.Fatalf("empty SvcParam = %x err %v, want 0002 0000", sp0, err)
	}
	if _, err := BuildSvcParam(65536, ""); err == nil {
		t.Error("key >65535 must be rejected")
	}
	if _, err := BuildSvcParam(1, "zz"); err == nil {
		t.Error("non-hex value must be rejected")
	}
}

// ---- §3.4 base64url ----

func TestBase64URL(t *testing.T) {
	for _, tc := range []struct {
		wireLen   int
		wantChars int
	}{
		{33, 44},  // www.example.com 查询（§3.4 例）
		{19, 26},  // residue 1
		{20, 27},  // residue 2
		{17, 23},  // residue 2（b64_short 边界 fixture 用）
		{271, 362}, // total255 wire（§2.3.4 边界正例）
	} {
		wire := make([]byte, tc.wireLen)
		for i := range wire {
			wire[i] = byte(i)
		}
		b64 := Base64URL(wire)
		if len(b64) != tc.wantChars {
			t.Errorf("wire %dB → %d chars, want %d (ceil(L*4/3))", tc.wireLen, len(b64), tc.wantChars)
		}
		if strings.ContainsAny(b64, "+/=") {
			t.Errorf("b64 %q contains standard-alphabet or padding chars", b64)
		}
	}
	// 实值：33B 基线查询的完整参数值钉死（python urlsafe_b64encode 无填充互证）。
	w := EncodeQueryWire(baselineQuery())
	if got, want := Base64URL(w), "EjQBAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"; got != want {
		t.Fatalf("baseline b64 = %q, want %q", got, want)
	}
}

// ---- §3.1 HTTP 帧 ----

func TestBuildPOSTRequest(t *testing.T) {
	w := EncodeQueryWire(baselineQuery())
	frame := BuildPOSTRequest("/dns-query", "198.51.100.66", w, "keep-alive", nil)
	s := string(frame)
	// 头序钉死：Host, Content-Type, Accept, Content-Length, Connection。
	wantHead := "POST /dns-query HTTP/1.1\r\n" +
		"Host: 198.51.100.66\r\n" +
		"Content-Type: application/dns-message\r\n" +
		"Accept: application/dns-message\r\n" +
		"Content-Length: 33\r\n" +
		"Connection: keep-alive\r\n\r\n"
	if !strings.HasPrefix(s, wantHead) {
		t.Fatalf("POST head:\n%q\nwant prefix\n%q", s, wantHead)
	}
	if !strings.HasSuffix(s, string(w)) {
		t.Fatal("POST body must be the DNS wire verbatim (§6 used directly)")
	}
}

func TestBuildGETRequest(t *testing.T) {
	w := EncodeQueryWire(baselineQuery())
	frame := BuildGETRequest("/dns-query", "198.51.100.66", Base64URL(w), "", "close", nil)
	s := string(frame)
	want := "GET /dns-query?dns=EjQBAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB HTTP/1.1\r\n" +
		"Host: 198.51.100.66\r\n" +
		"Accept: application/dns-message\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: close\r\n\r\n"
	if s != want {
		t.Fatalf("GET frame:\n%q\nwant\n%q", s, want)
	}
	if strings.Contains(s, "Content-Type") {
		t.Error("GET must not carry Content-Type (无 body)")
	}
	if !strings.HasSuffix(s, "\r\n\r\n") || len(frame) != len(want) {
		t.Fatal("GET must have no body")
	}
}

func TestBuildGETRequestExtraQuery(t *testing.T) {
	frame := BuildGETRequest("/dns-query", "h", "AA", "x=1", "close", nil)
	if !strings.Contains(string(frame), "GET /dns-query?dns=AA&x=1 HTTP/1.1") {
		t.Fatalf("extra query param must append with &: %q", string(frame[:40]))
	}
}

func TestBuild2xxResponse(t *testing.T) {
	q := baselineQuery()
	a, _ := BuildA(FixtureA)
	rr, _ := EncodeRR(q.QName, 1, 1, 300, a)
	w := EncodeResponseWire(ResponseSpec{ID: q.ID, Query: q, RA: true, Answers: []EncodedRR{rr}})
	frame := Build2xxResponse(200, w, 300, nil)
	s := string(frame)
	want := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/dns-message\r\n" +
		"Content-Length: 64\r\n" +
		"Cache-Control: max-age=300\r\n\r\n"
	if !strings.HasPrefix(s, want) {
		t.Fatalf("2xx head:\n%q\nwant prefix\n%q", s, want)
	}
	if !strings.HasSuffix(s, string(w)) {
		t.Fatal("2xx body must be the DNS wire verbatim")
	}
	if strings.Contains(s[:len(s)-len(string(w))], "Connection") {
		t.Error("2xx response must not carry Connection")
	}
}

// 非 2xx 确定性规则（§3.1 + §4.2.1）：状态行 + Content-Length: 0，无
// Content-Type、无 Cache-Control、无 DNS wire。
func TestBuildErrorResponse(t *testing.T) {
	for _, code := range []int{400, 404, 415} {
		frame := BuildErrorResponse(code)
		want := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", code, StatusText(code))
		if string(frame) != want {
			t.Errorf("%d response = %q, want %q", code, frame, want)
		}
		if strings.Contains(string(frame), "Content-Type") || strings.Contains(string(frame), "Cache-Control") {
			t.Errorf("%d response must not carry Content-Type/Cache-Control", code)
		}
	}
}

func TestStatusText(t *testing.T) {
	for _, tc := range []struct {
		code int
		want string
	}{
		{200, "OK"}, {400, "Bad Request"}, {404, "Not Found"},
		{415, "Unsupported Media Type"},
	} {
		if StatusText(tc.code) != tc.want {
			t.Errorf("StatusText(%d) = %q, want %q", tc.code, StatusText(tc.code), tc.want)
		}
	}
}

// ---- 头覆盖语义（§3.1 Content-Type 行：同值替换、空值删除、新名排序追加）----

func TestHeaderOverrides(t *testing.T) {
	w := EncodeQueryWire(baselineQuery())
	frame := BuildPOSTRequest("/dns-query", "198.51.100.66", w, "keep-alive",
		map[string]string{
			"content-type": "text/plain",    // 同名（大小写不敏感）原位替换
			"Accept":       "",              // 空值删除
			"X-B":          "2",             // 新名
			"X-A":          "1",             // 新名（排序在 X-B 前）
		})
	s := string(frame)
	if !strings.Contains(s, "Content-Type: text/plain\r\n") {
		t.Errorf("case-insensitive same-name override must replace the value in place (original name spelling kept): %q", s[:200])
	}
	if strings.Contains(s, "application/dns-message") {
		t.Error("overridden Content-Type value must fully replace the default")
	}
	if strings.Contains(s, "Accept") {
		t.Error("empty-value override must remove the header")
	}
	ia, ib := strings.Index(s, "X-A:"), strings.Index(s, "X-B:")
	if ia < 0 || ib < 0 || ia > ib {
		t.Errorf("new headers must append sorted: X-A at %d, X-B at %d", ia, ib)
	}
	// Host 覆盖（§3.1 Host 行：显式配置优先于 dst_ip）。
	frame2 := BuildPOSTRequest("/dns-query", "198.51.100.66", w, "keep-alive",
		map[string]string{"Host": "dns.example.net"})
	if !strings.Contains(string(frame2), "Host: dns.example.net\r\n") ||
		strings.Count(string(frame2), "Host:") != 1 {
		t.Error("Host override must replace, not duplicate")
	}
}

// ---- token 解析（§3.3 QTYPE/QCLASS 值域 + §3.2 RCODE）----

func TestParseTokens(t *testing.T) {
	for tok, want := range map[string]uint16{"A": 1, "a": 1, "AAAA": 28, "HTTPS": 65, "TXT": 16, "MX": 15} {
		v, err := ParseQType(tok)
		if err != nil || v != want {
			t.Errorf("ParseQType(%q) = %d err %v, want %d", tok, v, err, want)
		}
	}
	if v, _ := ParseQType(""); v != 1 {
		t.Errorf("empty qtype must default A(1), got %d", v)
	}
	if v, err := ParseQType("99"); err != nil || v != 99 {
		t.Errorf("numeric qtype passthrough: %d %v", v, err)
	}
	if v, err := ParseQType("65535"); err != nil || v != 65535 {
		t.Errorf("16-bit numeric qtype: %d %v", v, err)
	}
	if _, err := ParseQType("65536"); err == nil {
		t.Error("qtype >16-bit must be rejected")
	}
	if _, err := ParseQType("BOGUS"); err == nil {
		t.Error("non-numeric unknown token must be rejected (wire_fault qtype_token)")
	}
	for tok, want := range map[string]uint16{"IN": 1, "in": 1, "CHAOS": 3, "ANY": 255} {
		v, err := ParseQClass(tok)
		if err != nil || v != want {
			t.Errorf("ParseQClass(%q) = %d err %v, want %d", tok, v, err, want)
		}
	}
	if v, _ := ParseQClass(""); v != 1 {
		t.Errorf("empty qclass must default IN(1), got %d", v)
	}
	if v, err := ParseQClass("254"); err != nil || v != 254 {
		t.Errorf("numeric qclass passthrough: %d %v", v, err)
	}
	if _, err := ParseQClass("NOPE"); err == nil {
		t.Error("unknown qclass token must be rejected")
	}
	for tok, want := range map[string]uint8{"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5} {
		v, err := ParseRCode(tok)
		if err != nil || v != want {
			t.Errorf("ParseRCode(%q) = %d err %v, want %d", tok, v, err, want)
		}
	}
	if v, err := ParseRCode("15"); err != nil || v != 15 {
		t.Errorf("rcode 15 (4bit 上界): %d %v", v, err)
	}
	if _, err := ParseRCode("16"); err == nil {
		t.Error("rcode >15 must be rejected")
	}
	if _, err := ParseRCode("BADCODE"); err == nil {
		t.Error("unknown rcode token must be rejected")
	}
}
