package ldap

// LDAP planner tests, derived from /tmp/l7_planner_design/testcases_ldap.md
// (§2 BER 编码器 / §3 消息构建 / §4 Plan 层 / §5 Validate) and the reference
// pcap /home/pcap_auto/llcj_mirror/IP-TCP-20.7.2.35-30.7.2.35-49169-389-11-7-2955-3721.pcap
// (AD RootDSE 会话: searchRequest 351B / searchResDone 23B / unbind 12B 可逐字节复现;
// SASL GSS-API bindRequest/bindResponse 密文不可复现, planner 输出 simple 认证普通 BER).
//
// Model: one TCP flow = handshake → Rounds bind/search exchanges → teardown.
// Per round messageID = Base+3r (bind) / +3r+1 (search) / +3r+2 (unbind,
// last round only); responses echo the request messageID.

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- helpers ---

func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return drain(ch)
}

func ldapSpec(cfg *core.LDAPConfig) core.FlowSpec {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 36165, DstPort: 389,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
	}
	spec.LDAP = cfg
	return spec
}

func hexStr(b []byte) string { return hex.EncodeToString(b) }

// tcpData returns (flags, payload) of TCP frames carrying payload, in order.
func tcpData(cfgs []core.PacketConfig) []struct {
	flags   uint8
	dir     string
	payload []byte
} {
	var out []struct {
		flags   uint8
		dir     string
		payload []byte
	}
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" && len(c.Payload) > 0 {
			out = append(out, struct {
				flags   uint8
				dir     string
				payload []byte
			}{c.L4.Flags, c.Direction, append([]byte(nil), c.Payload...)})
		}
	}
	return out
}

func tcpFlags(cfgs []core.PacketConfig) []uint8 {
	var out []uint8
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" {
			out = append(out, c.L4.Flags)
		}
	}
	return out
}

// ldapMsgInfo parses a BER LDAPMessage and returns messageID and op tag.
func ldapMsgInfo(payload []byte) (mid int, op byte, ok bool) {
	if len(payload) < 8 || payload[0] != 0x30 || payload[1] != 0x84 {
		return 0, 0, false
	}
	ln := int(payload[2])<<24 | int(payload[3])<<16 | int(payload[4])<<8 | int(payload[5])
	if len(payload) != 6+ln {
		return 0, 0, false
	}
	i := 6
	if payload[i] != 0x02 {
		return 0, 0, false
	}
	ml := int(payload[i+1])
	for k := 0; k < ml; k++ {
		mid = mid<<8 | int(payload[i+2+k])
	}
	i += 2 + ml
	if i >= len(payload) {
		return 0, 0, false
	}
	return mid, payload[i], true
}

// opContent returns the hex of the protocolOp content (after the op tag and
// its length). Used to assert field bytes without magic offsets.
func opContent(payload []byte) string {
	if len(payload) < 10 || payload[1] != 0x84 {
		return ""
	}
	ml := int(payload[7])
	contentAt := 6 + 2 + ml + 6 // msg hdr + mid + op hdr
	if contentAt >= len(payload) {
		return ""
	}
	return hexStr(payload[contentAt:])
}

// reference pcap bytes (see testcases_ldap.md §3).
const refSearchRequest = "3084000001590202097763840000014f04000a01000a0100020100020178010100870b6f626a656374636c61737330840000012b0411737562736368656d61537562656e747279040d6473536572766963654e616d65040e6e616d696e67436f6e7465787473041464656661756c744e616d696e67436f6e746578740413736368656d614e616d696e67436f6e74657874041a636f6e66696775726174696f6e4e616d696e67436f6e746578740417726f6f74446f6d61696e4e616d696e67436f6e746578740410737570706f72746564436f6e74726f6c0414737570706f727465644c44415056657273696f6e0415737570706f727465644c444150506f6c69636965730417737570706f727465645341534c4d656368616e69736d73040b646e73486f73744e616d65040f6c646170536572766963654e616d65040a7365727665724e616d650415737570706f727465644361706162696c6974696573"

const refSearchResDone = "308400000011020209776584000000070a010004000400"
const refUnbind = "308400000006020209814200"
const bindAnon = "30840000001002010160840000000702010304008000"
const bindRespOK = "3084000000100201016184000000070a010004000400"

// --- §2 BER 编码器 ---

func TestBerInt(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{0, "020100"},
		{127, "02017f"},
		{128, "02020080"},
		{0x7FFF, "02027fff"},
		{0x8000, "0203008000"},
	}
	for _, c := range cases {
		if got := hexStr(berInt(c.n)); got != c.want {
			t.Errorf("berInt(%d) = %s, want %s", c.n, got, c.want)
		}
	}
}

func TestBerWrap(t *testing.T) {
	if got := hexStr(berWrap(0x30, make([]byte, 17))); got[:12] != "308400000011" {
		t.Errorf("berWrap(0x30,17B) head = %s", got[:12])
	}
	if got := hexStr(berWrap(0x42, nil)); got != "428400000000" {
		t.Errorf("berWrap(0x42,nil) = %s", got)
	}
	if got := hexStr(berWrap(0x63, make([]byte, 345))); got[:12] != "638400000159" {
		t.Errorf("berWrap(0x63,345B) head = %s", got[:12])
	}
}

// --- §3 消息构建 ---

func TestBindRequest_Anonymous(t *testing.T) {
	// testcases_ldap.md §3 1.3: mid=1, version 3, 匿名 simple 认证.
	cfg := &core.LDAPConfig{}
	got := hexStr(buildBindRequest(1, cfg))
	if got != bindAnon {
		t.Errorf("bindRequest = %s, want %s", got, bindAnon)
	}
}

func TestBindRequest_SimpleAuth(t *testing.T) {
	// mid=5, dn=cn=admin,dc=example,dc=com, password=secret.
	cfg := &core.LDAPConfig{BindDN: "cn=admin,dc=example,dc=com", BindPassword: "secret"}
	got := opContent(buildBindRequest(5, cfg))
	want := "020103041a636e3d61646d696e2c64633d6578616d706c652c64633d636f6d8006736563726574"
	if got != want {
		t.Errorf("bindRequest simple auth op content = %s, want %s", got, want)
	}
}

func TestBindResponse(t *testing.T) {
	// testcases_ldap.md §3 1.4: mid=1, resultCode 0.
	cfg := &core.LDAPConfig{}
	if got := hexStr(buildBindResponse(1, cfg)); got != bindRespOK {
		t.Errorf("bindResponse = %s, want %s", got, bindRespOK)
	}
	// 3.3: resultCode 49 → 0a 01 31.
	cfg49 := &core.LDAPConfig{ResultCode: 49}
	got := opContent(buildBindResponse(1, cfg49))
	if want := "0a013104000400"; got != want {
		t.Errorf("bindResponse rc=49 op content = %s, want %s", got, want)
	}
}

func TestSearchRequest_Reference(t *testing.T) {
	// testcases_ldap.md §3 1.5: MessageIDBase=2423 + time_limit=120(参考
	// pcap) + 其余默认 → 351B 与参考 pcap frame 4 逐字节一致.
	cfg := &core.LDAPConfig{MessageIDBase: 2423, TimeLimit: 120}
	got := hexStr(buildSearchRequest(2423, cfg))
	if got != refSearchRequest {
		t.Errorf("searchRequest len %d, want %d (byte mismatch)", len(got)/2, len(refSearchRequest)/2)
	}
}

func TestSearchRequest_PresentFilter(t *testing.T) {
	// 1.6: base=dc=example,dc=com, scope=2 → 字段字节.
	cfg := &core.LDAPConfig{SearchBaseDN: "dc=example,dc=com", SearchScope: 2, TimeLimit: 120}
	got := opContent(buildSearchRequest(1, cfg))
	want := "041164633d6578616d706c652c64633d636f6d0a01020a0100020100020178010100870b6f626a656374636c617373"
	if got[:len(want)] != want {
		t.Errorf("searchRequest fields = %s, want %s", got, want)
	}
}

func TestSearchRequest_EqualityFilter(t *testing.T) {
	// 1.7: filter_type=equality, cn=admin → a3 assertion. equalityMatch [3]
	// 是隐式标签,直接承载 AttributeValueAssertion 的字段(OCTET STRING
	// attributeDescription + assertionValue),无嵌套 SEQUENCE;构造值恒
	// 0x84 长形式(与参考 pcap 的 LDAP 层编码一致);filter 在 attributes 之前.
	cfg := &core.LDAPConfig{FilterType: "equality", SearchFilter: "cn", FilterValue: "admin"}
	got := hexStr(buildSearchRequest(1, cfg))
	want := "a3840000000b0402636e040561646d696e"
	if !containsStr(got, want) {
		t.Errorf("searchRequest equality filter missing %s in %s", want, got)
	}
}

func TestSearchRequest_EmptyAttributes(t *testing.T) {
	cfg := &core.LDAPConfig{Attributes: []string{}}
	got := buildSearchRequest(1, cfg)
	if !hasSuffixHex(got, "308400000000") {
		t.Errorf("searchRequest with empty attrs = %s, want trailing empty SEQUENCE", hexStr(got))
	}
}

func TestSearchResEntry_Small(t *testing.T) {
	// testcases_ldap.md §3 1.8: mid=1, base=dc=example,dc=com, [objectclass]
	// → 68B 完整消息.
	cfg := &core.LDAPConfig{SearchBaseDN: "dc=example,dc=com", Attributes: []string{"objectclass"}}
	got := hexStr(buildSearchResEntry(1, cfg))
	want := "30840000004802010164840000003f041164633d6578616d706c652c64633d636f6d308400000026308400000020040b6f626a656374636c61737331840000000d040b6f626a656374636c617373"
	if got != want {
		t.Errorf("searchResEntry = %s, want %s", got, want)
	}
}

func TestSearchResEntry_Default(t *testing.T) {
	// 默认 15 属性 → 801B;断言前缀 + 长度.
	cfg := &core.LDAPConfig{}
	got := buildSearchResEntry(1, cfg)
	if len(got) != 801 {
		t.Errorf("searchResEntry len = %d, want 801", len(got))
	}
	if hexStr(got)[:34] != "30840000031b0201016484000003120400" {
		t.Errorf("searchResEntry head = %s", hexStr(got)[:34])
	}
}

func TestSearchResDone_Reference(t *testing.T) {
	// 1.9: mid=2423 → 23B 与参考 pcap 逐字节一致.
	cfg := &core.LDAPConfig{}
	if got := hexStr(buildSearchResDone(2423, cfg)); got != refSearchResDone {
		t.Errorf("searchResDone = %s, want %s", got, refSearchResDone)
	}
}

func TestUnbind_Reference(t *testing.T) {
	// 1.10: mid=2433 → 12B 与参考 pcap 逐字节一致.
	if got := hexStr(buildUnbind(2433)); got != refUnbind {
		t.Errorf("unbind = %s, want %s", got, refUnbind)
	}
}

// --- §4 Plan 层 ---

func TestPlan_TCPFlow(t *testing.T) {
	// 1.12: SYN/SYN-ACK/ACK 握手 → 6 个 PSH-ACK 数据 → FIN-ACK×2 + ACK×2 拆除.
	cfgs := mustPlan(t, &Planner{}, ldapSpec(&core.LDAPConfig{}))
	wantFlags := []uint8{0x02, 0x12, 0x10, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x11, 0x10, 0x11, 0x10}
	got := tcpFlags(cfgs)
	if len(got) != len(wantFlags) {
		t.Fatalf("tcp frames = %d, want %d", len(got), len(wantFlags))
	}
	for i := range wantFlags {
		if got[i] != wantFlags[i] {
			t.Errorf("frame[%d] flags = 0x%02x, want 0x%02x", i, got[i], wantFlags[i])
		}
	}
	// 数据帧: messageID 序列与 op 序列 (1.11).
	data := tcpData(cfgs)
	wantMid := []int{1, 1, 2, 2, 2, 3}
	wantOp := []byte{0x60, 0x61, 0x63, 0x64, 0x65, 0x42}
	wantDir := []string{"up", "down", "up", "down", "down", "up"}
	for i := range wantMid {
		mid, op, ok := ldapMsgInfo(data[i].payload)
		if !ok {
			t.Fatalf("data[%d] not parseable", i)
		}
		if mid != wantMid[i] || op != wantOp[i] {
			t.Errorf("data[%d] mid=%d op=0x%02x, want mid=%d op=0x%02x", i, mid, op, wantMid[i], wantOp[i])
		}
		if data[i].dir != wantDir[i] {
			t.Errorf("data[%d] direction = %s, want %s", i, data[i].dir, wantDir[i])
		}
	}
	// 默认 searchRequest(mid=2)以 15 属性列表结尾.
	last := data[2].payload
	if !hasSuffixHex(last, "0415737570706f727465644361706162696c6974696573") {
		t.Errorf("searchRequest missing supportedCapabilities attr")
	}
}

func TestPlan_MSSSegmentation(t *testing.T) {
	// 大数据包按 MSS 分段: MSS=100 → 350B searchRequest 分 4 段.
	spec := ldapSpec(&core.LDAPConfig{})
	spec.TCP = &core.TCPConfig{MSS: 100}
	cfgs := mustPlan(t, &Planner{}, spec)
	data := tcpData(cfgs)
	// 第 3 条消息(searchRequest)为 350B → 4 个 PSH-ACK 段(100/100/100/50).
	var segs [][]byte
	for i, d := range data {
		if i >= 2 && i < 2+4 {
			segs = append(segs, d.payload)
		}
	}
	if len(segs) != 4 {
		t.Fatalf("searchRequest segments = %d, want 4", len(segs))
	}
	for i, s := range segs {
		wantLen := 100
		if i == 3 {
			wantLen = 50
		}
		if len(s) != wantLen {
			t.Errorf("segment[%d] len = %d, want %d", i, len(s), wantLen)
		}
	}
}

func TestPlan_Rounds2(t *testing.T) {
	// 3.1: Rounds=2 → 11 个数据消息; messageID [1,1,2,2,2, 4,4,5,5,5, 6].
	cfgs := mustPlan(t, &Planner{}, ldapSpec(&core.LDAPConfig{Rounds: 2}))
	data := tcpData(cfgs)
	wantMid := []int{1, 1, 2, 2, 2, 4, 4, 5, 5, 5, 6}
	wantOp := []byte{0x60, 0x61, 0x63, 0x64, 0x65, 0x60, 0x61, 0x63, 0x64, 0x65, 0x42}
	if len(data) != len(wantMid) {
		t.Fatalf("data messages = %d, want %d", len(data), len(wantMid))
	}
	for i := range wantMid {
		mid, op, ok := ldapMsgInfo(data[i].payload)
		if !ok {
			t.Fatalf("data[%d] not parseable", i)
		}
		if mid != wantMid[i] || op != wantOp[i] {
			t.Errorf("data[%d] mid=%d op=0x%02x, want mid=%d op=0x%02x", i, mid, op, wantMid[i], wantOp[i])
		}
	}
}

func TestPlan_NoUnbind(t *testing.T) {
	// 3.2: Unbind=false → 无 0x42 消息.
	f := false
	cfgs := mustPlan(t, &Planner{}, ldapSpec(&core.LDAPConfig{Unbind: &f}))
	data := tcpData(cfgs)
	if len(data) != 5 {
		t.Fatalf("data messages = %d, want 5", len(data))
	}
	for _, d := range data {
		_, op, _ := ldapMsgInfo(d.payload)
		if op == 0x42 {
			t.Errorf("unexpected unbindRequest")
		}
	}
}

func TestPlan_ResultCode49(t *testing.T) {
	// 3.3: ResultCode=49 → bindResponse 与 searchResDone 含 0a 01 31.
	cfgs := mustPlan(t, &Planner{}, ldapSpec(&core.LDAPConfig{ResultCode: 49}))
	data := tcpData(cfgs)
	for i, d := range data {
		_, op, _ := ldapMsgInfo(d.payload)
		if op == 0x61 || op == 0x65 {
			if !hasSuffixHex(d.payload, "0a013104000400") {
				t.Errorf("data[%d] op=0x%02x missing resultCode 49", i, op)
			}
		}
	}
}

func TestPlan_IPv6(t *testing.T) {
	// 3.4: IPv6 主机 → EtherType 0x86DD, TCP proto 6.
	spec := ldapSpec(&core.LDAPConfig{})
	spec.SrcIP = "3ffe::200:ff:fe00:71"
	spec.DstIP = "3ffe::200:ff:fe00:7"
	cfgs := mustPlan(t, &Planner{}, spec)
	for i, c := range cfgs {
		if c.L2.EtherType != 0x86DD {
			t.Errorf("frame[%d] EtherType = 0x%04x, want 0x86DD", i, c.L2.EtherType)
		}
		if c.L4.Protocol != "tcp" {
			t.Errorf("frame[%d] L4 = %s, want tcp", i, c.L4.Protocol)
		}
	}
}

func TestPlan_DefaultPort(t *testing.T) {
	// 4.1: DstPort 省略 → 389.
	spec := ldapSpec(&core.LDAPConfig{})
	spec.DstPort = 0
	cfgs := mustPlan(t, &Planner{}, spec)
	if cfgs[0].L4.DstPort != 389 {
		t.Errorf("DstPort = %d, want 389", cfgs[0].L4.DstPort)
	}
}

func TestPlan_BigAttributes(t *testing.T) {
	// 4.2: 100 个 20 字符属性 → 2251B, 30 84 长形式头.
	attrs := make([]string, 100)
	for i := range attrs {
		attrs[i] = "aaaaaaaaaaaaaaaaaaaa"
	}
	cfg := &core.LDAPConfig{Attributes: attrs}
	got := buildSearchRequest(1, cfg)
	if len(got) != 2251 {
		t.Errorf("searchRequest len = %d, want 2251", len(got))
	}
	if hexStr(got)[:30] != "3084000008c50201016384000008bc" {
		t.Errorf("searchRequest head = %s", hexStr(got)[:30])
	}
}

// --- §5 Validate ---

func TestValidate_Errors(t *testing.T) {
	p := &Planner{}
	cases := []struct {
		name string
		cfg  *core.LDAPConfig
		want string
	}{
		{"version 1", &core.LDAPConfig{Version: 1}, "version"},
		{"scope 3", &core.LDAPConfig{SearchScope: 3}, "scope"},
		{"filter substring", &core.LDAPConfig{FilterType: "substring"}, "filter type"},
		{"result_code 128", &core.LDAPConfig{ResultCode: 128}, "ENUMERATED"},
		{"message id overflow", &core.LDAPConfig{MessageIDBase: 0x7FFB, Rounds: 2}, "message id"},
		{"size_limit negative", &core.LDAPConfig{SizeLimit: -1}, "size_limit"},
		{"time_limit negative", &core.LDAPConfig{TimeLimit: -1}, "time_limit"},
	}
	for _, c := range cases {
		err := p.Validate(ldapSpec(c.cfg))
		if err == nil || !containsStr(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want containing %q", c.name, err, c.want)
		}
	}
	// 2.6: 无配置 / 非法 IP.
	spec := ldapSpec(nil)
	if err := p.Validate(spec); err == nil || !containsStr(err.Error(), "required") {
		t.Errorf("nil config: err = %v, want 'required'", err)
	}
	spec = ldapSpec(&core.LDAPConfig{})
	spec.SrcIP = "bad"
	if err := p.Validate(spec); err == nil || !containsStr(err.Error(), "invalid source IP") {
		t.Errorf("bad src IP: err = %v", err)
	}
}

func TestValidate_Acceptance(t *testing.T) {
	p := &Planner{}
	cases := []struct {
		name string
		cfg  *core.LDAPConfig
	}{
		{"version 2", &core.LDAPConfig{Version: 2}},
		{"scope 2", &core.LDAPConfig{SearchScope: 2}},
		{"equality", &core.LDAPConfig{FilterType: "equality", SearchFilter: "cn", FilterValue: "admin"}},
		{"message id at bound", &core.LDAPConfig{MessageIDBase: 0x7FFA, Rounds: 2}},
		{"defaults", &core.LDAPConfig{}},
	}
	for _, c := range cases {
		if err := p.Validate(ldapSpec(c.cfg)); err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
	}
}

// --- helpers for byte substring ---

func hasSuffixHex(b []byte, hexSuffix string) bool {
	want, err := hex.DecodeString(hexSuffix)
	if err != nil {
		panic(err)
	}
	return len(b) >= len(want) && hexStr(b[len(b)-len(want):]) == hexSuffix
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
