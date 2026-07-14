package replay

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/pcapparser"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// ---------------------------------------------------------------------------
// ipMatch unit tests
// ---------------------------------------------------------------------------

// RU21: exact match.
func TestIPMatch_Exact(t *testing.T) {
	if !ipMatch("10.0.0.1", "10.0.0.1") {
		t.Error("exact match failed")
	}
}

// RU22: CIDR match.
func TestIPMatch_CIDRMatch(t *testing.T) {
	if !ipMatch("10.0.0.0/8", "10.1.2.3") {
		t.Error("CIDR match failed")
	}
}

// RU23: CIDR does not match.
func TestIPMatch_CIDRNoMatch(t *testing.T) {
	if ipMatch("10.0.0.0/8", "192.168.1.1") {
		t.Error("CIDR should not match outside subnet")
	}
}

// RU24: invalid CIDR pattern returns false.
func TestIPMatch_InvalidCIDR(t *testing.T) {
	if ipMatch("notacidr", "10.0.0.1") {
		t.Error("invalid CIDR should return false")
	}
}

// RU25: valid CIDR pattern but invalid IP string returns false.
func TestIPMatch_InvalidIP(t *testing.T) {
	if ipMatch("10.0.0.0/8", "notanip") {
		t.Error("invalid IP should return false")
	}
}

// RU26: empty pattern with valid IP -- pattern != ipStr, ParseCIDR fails.
func TestIPMatch_EmptyPattern(t *testing.T) {
	if ipMatch("", "10.0.0.1") {
		t.Error("empty pattern should return false")
	}
}

// ---------------------------------------------------------------------------
// matchRule unit tests
// ---------------------------------------------------------------------------

// RU7: m.SrcIP set, m.DstIP empty, and flow's SrcIP/DstIP don't match m.SrcIP.
func TestMatchRule_OnlySrcIPFail(t *testing.T) {
	flow := storage.FlowModel{SrcIP: "C", DstIP: "C", L4Protocol: "tcp"}
	m := FlowMatcher{Protocol: "tcp", SrcIP: "A"} // DstIP empty (wildcard)
	if matchRule(m, flow) {
		t.Error("expected false: src IP A does not match flow (C, C)")
	}
}

// RU11: no IPs set, ports match -> true.
func TestMatchRule_NoIPSet(t *testing.T) {
	flow := testFlow() // SrcIP=10.0.0.1, DstIP=10.0.0.2, SrcPort=1234, DstPort=80
	m := FlowMatcher{SrcPort: 1234, DstPort: 80}
	if !matchRule(m, flow) {
		t.Error("expected true: no IPs set, ports match")
	}
}

// RU12: both ports match as a pair.
func TestMatchRule_BothPortPair(t *testing.T) {
	flow := testFlow() // SrcPort=1234, DstPort=80
	m := FlowMatcher{SrcPort: 1234, DstPort: 80}
	if !matchRule(m, flow) {
		t.Error("expected true: port pair matches forward")
	}
}

// RU13: both ports set, neither pair matches.
func TestMatchRule_BothPortNoPair(t *testing.T) {
	flow := storage.FlowModel{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 3, DstPort: 4, L4Protocol: "tcp"}
	m := FlowMatcher{SrcPort: 1, DstPort: 2}
	if matchRule(m, flow) {
		t.Error("expected false: port pair does not match")
	}
}

// RU14: ports cross-match (matcher's src matches flow's dst, etc.).
func TestMatchRule_PortCrossMatch(t *testing.T) {
	flow := storage.FlowModel{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1234, DstPort: 80, L4Protocol: "tcp"}
	m := FlowMatcher{SrcPort: 80, DstPort: 1234}
	if !matchRule(m, flow) {
		t.Error("expected true: ports cross-match")
	}
}

// RU19: both ports zero (wildcard) -> match.
func TestMatchRule_NoPortSet(t *testing.T) {
	flow := testFlow()
	m := FlowMatcher{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"} // ports zero (wildcard)
	if !matchRule(m, flow) {
		t.Error("expected true: zero ports are wildcards")
	}
}

// RU20: all fields empty/zero -> match (wildcard).
func TestMatchRule_AllWildcard(t *testing.T) {
	flow := testFlow()
	m := FlowMatcher{} // all empty/zero
	if !matchRule(m, flow) {
		t.Error("expected true: all-wildcard matcher matches any flow")
	}
}

// ---------------------------------------------------------------------------
// fieldSpecFor unit tests
// ---------------------------------------------------------------------------

// RU28: src_ip -> offset == layout.SrcIP, layer l3, width 4.
func TestFieldSpecFor_SrcIP(t *testing.T) {
	layout := testLayout(t)
	spec, ok := fieldSpecFor(layout, "src_ip")
	if !ok {
		t.Fatal("fieldSpecFor src_ip returned ok=false")
	}
	if spec.offset != layout.SrcIP {
		t.Errorf("offset = %d, want %d", spec.offset, layout.SrcIP)
	}
	if spec.layer != "l3" {
		t.Errorf("layer = %q, want l3", spec.layer)
	}
	if spec.width != 4 {
		t.Errorf("width = %d, want 4", spec.width)
	}
}

// RU30: src_port -> offset == layout.SrcPort, layer l4, width 2.
func TestFieldSpecFor_SrcPort(t *testing.T) {
	layout := testLayout(t)
	spec, ok := fieldSpecFor(layout, "src_port")
	if !ok {
		t.Fatal("fieldSpecFor src_port returned ok=false")
	}
	if spec.offset != layout.SrcPort {
		t.Errorf("offset = %d, want %d", spec.offset, layout.SrcPort)
	}
	if spec.layer != "l4" {
		t.Errorf("layer = %q, want l4", spec.layer)
	}
	if spec.width != 2 {
		t.Errorf("width = %d, want 2", spec.width)
	}
}

// RU32: src_mac -> layer l2, width 6.
func TestFieldSpecFor_SrcMAC(t *testing.T) {
	layout := testLayout(t)
	spec, ok := fieldSpecFor(layout, "src_mac")
	if !ok {
		t.Fatal("fieldSpecFor src_mac returned ok=false")
	}
	if spec.offset != layout.SrcMAC {
		t.Errorf("offset = %d, want %d", spec.offset, layout.SrcMAC)
	}
	if spec.layer != "l2" {
		t.Errorf("layer = %q, want l2", spec.layer)
	}
	if spec.width != 6 {
		t.Errorf("width = %d, want 6", spec.width)
	}
}

// RU34: ttl -> layer l3, width 1.
func TestFieldSpecFor_TTL(t *testing.T) {
	layout := testLayout(t)
	spec, ok := fieldSpecFor(layout, "ttl")
	if !ok {
		t.Fatal("fieldSpecFor ttl returned ok=false")
	}
	if spec.offset != layout.TTL {
		t.Errorf("offset = %d, want %d", spec.offset, layout.TTL)
	}
	if spec.layer != "l3" {
		t.Errorf("layer = %q, want l3", spec.layer)
	}
	if spec.width != 1 {
		t.Errorf("width = %d, want 1", spec.width)
	}
}

// RU35: dscp -> offset == layout.DSCPECN, layer l3, width 1.
func TestFieldSpecFor_DSCP(t *testing.T) {
	layout := testLayout(t)
	spec, ok := fieldSpecFor(layout, "dscp")
	if !ok {
		t.Fatal("fieldSpecFor dscp returned ok=false")
	}
	if spec.offset != layout.DSCPECN {
		t.Errorf("offset = %d, want %d (DSCPECN)", spec.offset, layout.DSCPECN)
	}
	if spec.layer != "l3" {
		t.Errorf("layer = %q, want l3", spec.layer)
	}
	if spec.width != 1 {
		t.Errorf("width = %d, want 1", spec.width)
	}
}

// RU36: ecn -> offset == layout.DSCPECN (same byte as dscp).
func TestFieldSpecFor_ECN(t *testing.T) {
	layout := testLayout(t)
	spec, ok := fieldSpecFor(layout, "ecn")
	if !ok {
		t.Fatal("fieldSpecFor ecn returned ok=false")
	}
	if spec.offset != layout.DSCPECN {
		t.Errorf("offset = %d, want %d (DSCPECN = same byte as dscp)", spec.offset, layout.DSCPECN)
	}
	if spec.layer != "l3" {
		t.Errorf("layer = %q, want l3", spec.layer)
	}
	if spec.width != 1 {
		t.Errorf("width = %d, want 1", spec.width)
	}
}

// RU38: seq -> layer l4, width 4.
func TestFieldSpecFor_Seq(t *testing.T) {
	layout := testLayout(t)
	spec, ok := fieldSpecFor(layout, "seq")
	if !ok {
		t.Fatal("fieldSpecFor seq returned ok=false")
	}
	if spec.offset != layout.Seq {
		t.Errorf("offset = %d, want %d", spec.offset, layout.Seq)
	}
	if spec.layer != "l4" {
		t.Errorf("layer = %q, want l4", spec.layer)
	}
	if spec.width != 4 {
		t.Errorf("width = %d, want 4", spec.width)
	}
}

// RU42: unknown target -> ok=false.
func TestFieldSpecFor_Unknown(t *testing.T) {
	layout := testLayout(t)
	_, ok := fieldSpecFor(layout, "unknown")
	if ok {
		t.Error("fieldSpecFor unknown returned ok=true, want false")
	}
}

// ---------------------------------------------------------------------------
// encodeValue unit tests
// ---------------------------------------------------------------------------

// RU43: src_mac MAC address.
func TestEncodeValue_MAC(t *testing.T) {
	b, err := encodeValue("src_mac", "aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatalf("encodeValue: %v", err)
	}
	want := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	if len(b) != len(want) {
		t.Fatalf("len = %d, want %d", len(b), len(want))
	}
	for i := range want {
		if b[i] != want[i] {
			t.Errorf("byte %d = 0x%02x, want 0x%02x", i, b[i], want[i])
		}
	}
}

// RU44: invalid MAC -> error.
func TestEncodeValue_InvalidMAC(t *testing.T) {
	_, err := encodeValue("src_mac", "notamac")
	if err == nil {
		t.Fatal("expected error for invalid MAC")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "invalid MAC") {
		t.Errorf("error = %q, want substring 'invalid MAC'", errStr)
	}
}

// RU45: IPv4 address.
func TestEncodeValue_IPv4(t *testing.T) {
	b, err := encodeValue("src_ip", "10.0.0.1")
	if err != nil {
		t.Fatalf("encodeValue: %v", err)
	}
	want := net.ParseIP("10.0.0.1").To4()
	if len(b) != 4 || b[0] != want[0] || b[1] != want[1] || b[2] != want[2] || b[3] != want[3] {
		t.Errorf("bytes = %v, want %v", b, want)
	}
}

// RU46: invalid IP -> error.
func TestEncodeValue_InvalidIP(t *testing.T) {
	_, err := encodeValue("src_ip", "notanip")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "invalid IP") {
		t.Errorf("error = %q, want substring 'invalid IP'", errStr)
	}
}

// RU47: IPv6 -> error.
func TestEncodeValue_IPv6(t *testing.T) {
	_, err := encodeValue("src_ip", "::1")
	if err == nil {
		t.Fatal("expected error for IPv6")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "IPv6 not supported") {
		t.Errorf("error = %q, want substring 'IPv6 not supported'", errStr)
	}
}

// RU49: port value.
func TestEncodeValue_Port(t *testing.T) {
	b, err := encodeValue("src_port", "80")
	if err != nil {
		t.Fatalf("encodeValue: %v", err)
	}
	want := binary.BigEndian.AppendUint16(nil, 80)
	if len(b) != 2 || b[0] != want[0] || b[1] != want[1] {
		t.Errorf("bytes = %v, want %v", b, want)
	}
}

// RU52: TTL value.
func TestEncodeValue_TTL(t *testing.T) {
	b, err := encodeValue("ttl", "64")
	if err != nil {
		t.Fatalf("encodeValue: %v", err)
	}
	if len(b) != 1 || b[0] != 0x40 {
		t.Errorf("bytes = %v, want [0x40]", b)
	}
}

// RU55: DSCP value shifted left 2.
func TestEncodeValue_DSCP(t *testing.T) {
	b, err := encodeValue("dscp", "46")
	if err != nil {
		t.Fatalf("encodeValue: %v", err)
	}
	if len(b) != 1 || b[0] != 0xb8 {
		t.Errorf("bytes = 0x%02x, want 0xb8 (46<<2)", b[0])
	}
}

// RU57: ECN value masked to low 2 bits.
func TestEncodeValue_ECN(t *testing.T) {
	b, err := encodeValue("ecn", "3")
	if err != nil {
		t.Fatalf("encodeValue: %v", err)
	}
	if len(b) != 1 || b[0] != 0x03 {
		t.Errorf("bytes = 0x%02x, want 0x03 (3&0x03)", b[0])
	}
}

// RU59: seq value 4 bytes big-endian.
func TestEncodeValue_Seq(t *testing.T) {
	b, err := encodeValue("seq", "1000")
	if err != nil {
		t.Fatalf("encodeValue: %v", err)
	}
	want := binary.BigEndian.AppendUint32(nil, 1000)
	if len(b) != 4 || b[0] != want[0] || b[1] != want[1] || b[2] != want[2] || b[3] != want[3] {
		t.Errorf("bytes = %v, want %v", b, want)
	}
}

// RU63: window value.
func TestEncodeValue_Window(t *testing.T) {
	b, err := encodeValue("window", "65535")
	if err != nil {
		t.Fatalf("encodeValue: %v", err)
	}
	if len(b) != 2 || b[0] != 0xff || b[1] != 0xff {
		t.Errorf("bytes = %v, want [0xff 0xff]", b)
	}
}

// RU64: unknown target -> error.
func TestEncodeValue_Unknown(t *testing.T) {
	_, err := encodeValue("unknown", "foo")
	if err == nil {
		t.Fatal("expected error for unsupported target")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "unsupported target") {
		t.Errorf("error = %q, want substring 'unsupported target'", errStr)
	}
}

// ---------------------------------------------------------------------------
// resolveStrategyValue unit tests
// ---------------------------------------------------------------------------

// RU65: fixed strategy with string value.
func TestResolveStrategyValue_Fixed(t *testing.T) {
	v, err := resolveStrategyValue(core.StrategyConfig{Strategy: "fixed", Value: "10.0.0.1"})
	if err != nil {
		t.Fatalf("resolveStrategyValue: %v", err)
	}
	if v != "10.0.0.1" {
		t.Errorf("got %q, want %q", v, "10.0.0.1")
	}
}

// RU66: fixed strategy with nil value -> error.
func TestResolveStrategyValue_FixedNil(t *testing.T) {
	_, err := resolveStrategyValue(core.StrategyConfig{Strategy: "fixed", Value: nil})
	if err == nil {
		t.Fatal("expected error for nil value")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "missing value") {
		t.Errorf("error = %q, want substring 'missing value'", errStr)
	}
}

// RU67: fixed strategy with int value -> fmt.Sprintf("%v", 42) = "42".
func TestResolveStrategyValue_FixedInt(t *testing.T) {
	v, err := resolveStrategyValue(core.StrategyConfig{Strategy: "fixed", Value: 42})
	if err != nil {
		t.Fatalf("resolveStrategyValue: %v", err)
	}
	if v != "42" {
		t.Errorf("got %q, want %q", v, "42")
	}
}

// RU68: list strategy returns first element.
func TestResolveStrategyValue_List(t *testing.T) {
	v, err := resolveStrategyValue(core.StrategyConfig{Strategy: "list", List: []string{"a", "b"}})
	if err != nil {
		t.Fatalf("resolveStrategyValue: %v", err)
	}
	if v != "a" {
		t.Errorf("got %q, want %q", v, "a")
	}
}

// RU69: empty list -> error.
func TestResolveStrategyValue_ListEmpty(t *testing.T) {
	_, err := resolveStrategyValue(core.StrategyConfig{Strategy: "list", List: []string{}})
	if err == nil {
		t.Fatal("expected error for empty list")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "list strategy empty") {
		t.Errorf("error = %q, want substring 'list strategy empty'", errStr)
	}
}

// RU70: inc strategy -> error (not supported for flow-level rules).
func TestResolveStrategyValue_Inc(t *testing.T) {
	_, err := resolveStrategyValue(core.StrategyConfig{Strategy: "inc"})
	if err == nil {
		t.Fatal("expected error for inc strategy")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "not supported") {
		t.Errorf("error = %q, want substring 'not supported'", errStr)
	}
}

// RU72: unknown strategy -> error.
func TestResolveStrategyValue_Unknown(t *testing.T) {
	_, err := resolveStrategyValue(core.StrategyConfig{Strategy: "unknown"})
	if err == nil {
		t.Fatal("expected error for unknown strategy")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "not supported") {
		t.Errorf("error = %q, want substring 'not supported'", errStr)
	}
}

// ---------------------------------------------------------------------------
// computeFlowPatches unit tests
// ---------------------------------------------------------------------------

// RU73: no rules -> empty patches, no error.
func TestComputeFlowPatches_NoRules(t *testing.T) {
	layout := testLayout(t)
	flow := testFlow()
	patches, err := computeFlowPatches(flow, layout, nil)
	if err != nil {
		t.Fatalf("computeFlowPatches: %v", err)
	}
	if len(patches) != 0 {
		t.Errorf("patches = %d, want 0", len(patches))
	}
}

// RU74: rule does not match flow -> empty patches.
func TestComputeFlowPatches_RuleNotMatch(t *testing.T) {
	layout := testLayout(t)
	flow := testFlow() // tcp
	rules := []RewriteRule{{
		Match: FlowMatcher{Protocol: "udp"},
		Kind:  "field", Target: "ttl", Apply: "set",
		Strategy: core.StrategyConfig{Strategy: "fixed", Value: "128"},
	}}
	patches, err := computeFlowPatches(flow, layout, rules)
	if err != nil {
		t.Fatalf("computeFlowPatches: %v", err)
	}
	if len(patches) != 0 {
		t.Errorf("patches = %d, want 0 (rule should not match)", len(patches))
	}
}

// RU84: two different fields at the same offset (non-dscp/ecn) is unreachable
// via fieldSpecFor because each field maps to a distinct offset.
func TestComputeFlowPatches_DiffFieldSameOffset(t *testing.T) {
	t.Skip("unreachable: fieldSpecFor gives each field a distinct offset except dscp/ecn which merge")
}

// RU85: two rules with different fields at different offsets -> 2 patches.
func TestComputeFlowPatches_NewFieldNewOffset(t *testing.T) {
	layout := testLayout(t)
	flow := testFlow()
	rules := []RewriteRule{
		{Kind: "field", Target: "ttl", Apply: "set", Strategy: core.StrategyConfig{Strategy: "fixed", Value: "128"}},
		{Kind: "field", Target: "src_ip", Apply: "set", Strategy: core.StrategyConfig{Strategy: "fixed", Value: "11.0.0.1"}},
	}
	patches, err := computeFlowPatches(flow, layout, rules)
	if err != nil {
		t.Fatalf("computeFlowPatches: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("patches = %d, want 2", len(patches))
	}
	gotFields := map[string]bool{}
	for _, p := range patches {
		gotFields[p.Field] = true
	}
	if !gotFields["ttl"] {
		t.Error("missing ttl patch")
	}
	if !gotFields["src_ip"] {
		t.Error("missing src_ip patch")
	}
}

// ---------------------------------------------------------------------------
// applyIPMap unit tests
// ---------------------------------------------------------------------------

// RU88: src IP in mapping -> src_ip patch.
func TestApplyIPMap_SrcExact(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcIP: 26, DstIP: 30}
	flow := storage.FlowModel{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}
	patches, err := applyIPMap(map[string]string{"10.0.0.1": "192.168.1.1"}, flow, layout)
	if err != nil {
		t.Fatalf("applyIPMap: %v", err)
	}
	var found bool
	for _, p := range patches {
		if p.Field == "src_ip" {
			found = true
			want := net.ParseIP("192.168.1.1").To4()
			if len(p.Bytes) != 4 || p.Bytes[0] != want[0] || p.Bytes[1] != want[1] || p.Bytes[2] != want[2] || p.Bytes[3] != want[3] {
				t.Errorf("src_ip bytes = %v, want %v", p.Bytes, want)
			}
		}
	}
	if !found {
		t.Error("no src_ip patch")
	}
}

// RU89: src IP not in mapping -> no src patch.
func TestApplyIPMap_SrcNotFound(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcIP: 26, DstIP: 30}
	flow := storage.FlowModel{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}
	patches, err := applyIPMap(map[string]string{"10.0.0.3": "192.168.1.1"}, flow, layout)
	if err != nil {
		t.Fatalf("applyIPMap: %v", err)
	}
	for _, p := range patches {
		if p.Field == "src_ip" {
			t.Error("unexpected src_ip patch (src IP not in mapping)")
		}
	}
}

// RU90: layout.SrcIP is negative -> no src patch.
func TestApplyIPMap_SrcLayoutNeg(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcIP: -1, DstIP: 30}
	flow := storage.FlowModel{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}
	patches, err := applyIPMap(map[string]string{"10.0.0.1": "192.168.1.1"}, flow, layout)
	if err != nil {
		t.Fatalf("applyIPMap: %v", err)
	}
	for _, p := range patches {
		if p.Field == "src_ip" {
			t.Error("unexpected src_ip patch (layout.SrcIP < 0)")
		}
	}
}

// RU91: mapping value is not a valid IP -> error.
func TestApplyIPMap_EncodeFail(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcIP: 26, DstIP: 30}
	flow := storage.FlowModel{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}
	_, err := applyIPMap(map[string]string{"10.0.0.1": "notanip"}, flow, layout)
	if err == nil {
		t.Fatal("expected error for invalid IP mapping value")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "ipmap src") {
		t.Errorf("error = %q, want substring 'ipmap src'", errStr)
	}
}

// RU96: both src and dst in mapping -> 2 patches.
func TestApplyIPMap_BothFound(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcIP: 26, DstIP: 30}
	flow := storage.FlowModel{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}
	patches, err := applyIPMap(map[string]string{"10.0.0.1": "192.168.1.1", "10.0.0.2": "192.168.1.2"}, flow, layout)
	if err != nil {
		t.Fatalf("applyIPMap: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("patches = %d, want 2 (src + dst)", len(patches))
	}
	gotFields := map[string]bool{}
	for _, p := range patches {
		gotFields[p.Field] = true
	}
	if !gotFields["src_ip"] {
		t.Error("missing src_ip patch")
	}
	if !gotFields["dst_ip"] {
		t.Error("missing dst_ip patch")
	}
}

// ---------------------------------------------------------------------------
// lookupIPMap unit tests
// ---------------------------------------------------------------------------

// RU97: invalid IP string -> false.
func TestLookupIPMap_InvalidIP(t *testing.T) {
	_, ok := lookupIPMap(map[string]string{"10.0.0.1": "11.0.0.1"}, "notanip")
	if ok {
		t.Error("expected false for invalid IP")
	}
}

// RU98: exact match -> found.
func TestLookupIPMap_ExactMatch(t *testing.T) {
	v, ok := lookupIPMap(map[string]string{"10.0.0.1": "11.0.0.1"}, "10.0.0.1")
	if !ok {
		t.Fatal("expected true (exact match)")
	}
	if v != "11.0.0.1" {
		t.Errorf("got %q, want %q", v, "11.0.0.1")
	}
}

// RU100: CIDR key match -> translate with host offset preserved.
func TestLookupIPMap_CIDRKeyMatch(t *testing.T) {
	v, ok := lookupIPMap(map[string]string{"10.0.0.0/8": "192.168.0.0/16"}, "10.0.0.5")
	if !ok {
		t.Fatal("expected true (CIDR match)")
	}
	if v != "192.168.0.5" {
		t.Errorf("got %q, want %q (host offset 5 preserved)", v, "192.168.0.5")
	}
}

// RU101: mapping contains non-CIDR key alongside exact match -> skip non-CIDR.
func TestLookupIPMap_NonCIDRKey(t *testing.T) {
	v, ok := lookupIPMap(map[string]string{"foo": "99.99.99.99", "10.0.0.1": "11.0.0.1"}, "10.0.0.1")
	if !ok {
		t.Fatal("expected true (exact match)")
	}
	if v != "11.0.0.1" {
		t.Errorf("got %q, want %q", v, "11.0.0.1")
	}
}

// RU102: CIDR does not contain the IP -> false.
func TestLookupIPMap_CIDRNotContain(t *testing.T) {
	_, ok := lookupIPMap(map[string]string{"10.0.0.0/8": "192.168.0.0/16"}, "192.168.1.1")
	if ok {
		t.Error("expected false (192.168.1.1 not in 10.0.0.0/8)")
	}
}

// RU103: most specific CIDR wins.
func TestLookupIPMap_MostSpecificWins(t *testing.T) {
	v, ok := lookupIPMap(map[string]string{
		"10.0.0.0/8":  "10.8.0.1",
		"10.0.0.0/24": "10.0.0.99",
	}, "10.0.0.5")
	if !ok {
		t.Fatal("expected true (CIDR match)")
	}
	if v != "10.0.0.99" {
		t.Errorf("got %q, want %q (/24 should win over /8)", v, "10.0.0.99")
	}
}

// RU104: less specific CIDR returned when only it matches.
func TestLookupIPMap_LessSpecificSkipped(t *testing.T) {
	v, ok := lookupIPMap(map[string]string{
		"10.0.0.0/8":  "10.8.0.1",
		"10.0.0.0/24": "10.0.0.99",
	}, "10.0.1.5")
	if !ok {
		t.Fatal("expected true (/8 matches, /24 does not)")
	}
	if v != "10.8.0.1" {
		t.Errorf("got %q, want %q (only /8 matches)", v, "10.8.0.1")
	}
}

// RU106: no match in any CIDR -> false.
func TestLookupIPMap_NoMatch(t *testing.T) {
	_, ok := lookupIPMap(map[string]string{"10.0.0.0/8": "192.168.0.0/16"}, "172.16.0.1")
	if ok {
		t.Error("expected false (172.16.0.1 not in any CIDR key)")
	}
}

// RU107: empty mapping -> false.
func TestLookupIPMap_EmptyMapping(t *testing.T) {
	_, ok := lookupIPMap(map[string]string{}, "10.0.0.1")
	if ok {
		t.Error("expected false (empty mapping)")
	}
}

// ---------------------------------------------------------------------------
// translateCIDR unit tests
// ---------------------------------------------------------------------------

// RU108: target is a single IP (not CIDR) -> returns that IP.
func TestTranslateCIDR_TargetIsIP(t *testing.T) {
	ip := net.ParseIP("10.0.0.5")
	_, srcCIDR, _ := net.ParseCIDR("10.0.0.0/8")
	result := translateCIDR(ip, srcCIDR, "192.168.1.1")
	if result != "192.168.1.1" {
		t.Errorf("got %q, want %q", result, "192.168.1.1")
	}
}

// RU109: target is neither IP nor CIDR -> returned as-is.
func TestTranslateCIDR_TargetNotIPNotCIDR(t *testing.T) {
	ip := net.ParseIP("10.0.0.5")
	_, srcCIDR, _ := net.ParseCIDR("10.0.0.0/8")
	result := translateCIDR(ip, srcCIDR, "hostname")
	if result != "hostname" {
		t.Errorf("got %q, want %q", result, "hostname")
	}
}

// RU110: ip is IPv6 -> target CIDR string returned as-is (v1 is IPv4-only).
func TestTranslateCIDR_IPv6(t *testing.T) {
	ip := net.ParseIP("::1")
	_, srcCIDR, _ := net.ParseCIDR("::/0")
	result := translateCIDR(ip, srcCIDR, "192.168.0.0/16")
	if result != "192.168.0.0/16" {
		t.Errorf("got %q, want %q", result, "192.168.0.0/16")
	}
}

// RU112: host offset preserved from src CIDR to dst CIDR ("网段平移保偏移").
func TestTranslateCIDR_HostOffsetPreserved(t *testing.T) {
	ip := net.ParseIP("10.0.0.5")
	_, srcCIDR, _ := net.ParseCIDR("10.0.0.0/8")
	result := translateCIDR(ip, srcCIDR, "192.168.0.0/16")
	if result != "192.168.0.5" {
		t.Errorf("got %q, want %q (host offset 5 preserved)", result, "192.168.0.5")
	}
}

// RU113: dst CIDR smaller than src -> host offset truncated to dst host bits.
func TestTranslateCIDR_DstSmaller(t *testing.T) {
	ip := net.ParseIP("10.0.0.5")
	_, srcCIDR, _ := net.ParseCIDR("10.0.0.0/8")           // srcHostBits = 24
	result := translateCIDR(ip, srcCIDR, "192.168.0.0/24") // dstHostBits = 8
	// hostOffset = 5 (0x05). dstHostBits=8 < srcHostBits=24, so masked to 8 bits: 5 & 0xFF = 5.
	// dstBase = 192.168.0.0, newIP = 192.168.0.0 | 5 = 192.168.0.5
	if result != "192.168.0.5" {
		t.Errorf("got %q, want %q", result, "192.168.0.5")
	}
}

// RU114: dst CIDR larger than src -> full host offset preserved.
func TestTranslateCIDR_DstLarger(t *testing.T) {
	ip := net.ParseIP("10.0.0.5")
	_, srcCIDR, _ := net.ParseCIDR("10.0.0.0/24")         // srcHostBits = 8
	result := translateCIDR(ip, srcCIDR, "192.168.0.0/8") // dstHostBits = 24
	// hostOffset = 5. dstHostBits=24 >= srcHostBits=8, no truncation.
	// dstBase = 192.0.0.0, newIP = 192.0.0.0 | 5 = 192.0.0.5
	if result != "192.0.0.5" {
		t.Errorf("got %q, want %q", result, "192.0.0.5")
	}
}

// RU115: src /0 -> srcHostBits=32, full host offset masked.
func TestTranslateCIDR_SrcSlash0(t *testing.T) {
	ip := net.ParseIP("10.0.0.5")
	_, srcCIDR, _ := net.ParseCIDR("0.0.0.0/0") // srcHostBits = 32
	result := translateCIDR(ip, srcCIDR, "192.168.0.0/16")
	// dstHostBits = 16 < srcHostBits = 32, so hostOffset = 0x0A000005 & 0xFFFF = 5
	// dstBase = 192.168.0.0, newIP = 192.168.0.0 | 5 = 192.168.0.5
	if result != "192.168.0.5" {
		t.Errorf("got %q, want %q", result, "192.168.0.5")
	}
}

// RU116: src /32 -> hostOffset = 0, newIP = dstBase.
func TestTranslateCIDR_SrcSlash32(t *testing.T) {
	ip := net.ParseIP("10.0.0.5")
	_, srcCIDR, _ := net.ParseCIDR("10.0.0.5/32") // srcHostBits = 0
	result := translateCIDR(ip, srcCIDR, "192.168.0.0/16")
	// hostOffset = 0x0A000005 & 0 = 0
	// dstBase = 192.168.0.0, newIP = 192.168.0.0 | 0 = 192.168.0.0
	if result != "192.168.0.0" {
		t.Errorf("got %q, want %q", result, "192.168.0.0")
	}
}

// ---------------------------------------------------------------------------
// maskLowBits unit tests
// ---------------------------------------------------------------------------

// RU117: n=0 -> 0.
func TestMaskLowBits_Zero(t *testing.T) {
	if maskLowBits(0) != 0 {
		t.Errorf("maskLowBits(0) = %d, want 0", maskLowBits(0))
	}
}

// RU118: n=32 -> 0xFFFFFFFF.
func TestMaskLowBits_32(t *testing.T) {
	if maskLowBits(32) != 0xFFFFFFFF {
		t.Errorf("maskLowBits(32) = %d, want 0xFFFFFFFF", maskLowBits(32))
	}
}

// RU119: n=8 -> 0xFF.
func TestMaskLowBits_8(t *testing.T) {
	if maskLowBits(8) != 0xFF {
		t.Errorf("maskLowBits(8) = %d, want 0xFF", maskLowBits(8))
	}
}

// RU120: n=16 -> 0xFFFF.
func TestMaskLowBits_16(t *testing.T) {
	if maskLowBits(16) != 0xFFFF {
		t.Errorf("maskLowBits(16) = %d, want 0xFFFF", maskLowBits(16))
	}
}

// ---------------------------------------------------------------------------
// genFlowPatches unit tests
// ---------------------------------------------------------------------------

// RU121: ipmap kind -> delegates to applyIPMap, returns IP patch.
func TestGenFlowPatches_IPMap(t *testing.T) {
	layout := testLayout(t)
	flow := testFlow()
	rule := RewriteRule{Kind: "ipmap", Mapping: map[string]string{"10.0.0.1": "192.168.1.1"}}
	patches, err := genFlowPatches(rule, flow, layout)
	if err != nil {
		t.Fatalf("genFlowPatches: %v", err)
	}
	var found bool
	for _, p := range patches {
		if p.Field == "src_ip" {
			found = true
			want := net.ParseIP("192.168.1.1").To4()
			if len(p.Bytes) != 4 || p.Bytes[0] != want[0] || p.Bytes[1] != want[1] || p.Bytes[2] != want[2] || p.Bytes[3] != want[3] {
				t.Errorf("src_ip bytes = %v, want %v", p.Bytes, want)
			}
		}
	}
	if !found {
		t.Error("no src_ip patch")
	}
}

// RU122: portmap kind, src port in mapping -> src_port patch.
func TestGenFlowPatches_PortmapSrc(t *testing.T) {
	layout := testLayout(t)
	flow := testFlow() // SrcPort=1234
	rule := RewriteRule{Kind: "portmap", Mapping: map[string]string{"1234": "5000"}}
	patches, err := genFlowPatches(rule, flow, layout)
	if err != nil {
		t.Fatalf("genFlowPatches: %v", err)
	}
	var found bool
	for _, p := range patches {
		if p.Field == "src_port" {
			found = true
			want := binary.BigEndian.AppendUint16(nil, 5000)
			if len(p.Bytes) != 2 || p.Bytes[0] != want[0] || p.Bytes[1] != want[1] {
				t.Errorf("src_port bytes = %v, want %v", p.Bytes, want)
			}
		}
	}
	if !found {
		t.Error("no src_port patch")
	}
}

// RU125: portmap kind, src port not in mapping -> no patches.
func TestGenFlowPatches_PortmapSrcNotInMap(t *testing.T) {
	layout := testLayout(t)
	flow := testFlow() // SrcPort=1234, DstPort=80
	rule := RewriteRule{Kind: "portmap", Mapping: map[string]string{"9999": "5000"}}
	patches, err := genFlowPatches(rule, flow, layout)
	if err != nil {
		t.Fatalf("genFlowPatches: %v", err)
	}
	if len(patches) != 0 {
		t.Errorf("patches = %d, want 0 (no matching ports)", len(patches))
	}
}

// RU130: macmap kind -> returns nil (per-packet).
func TestGenFlowPatches_Macmap(t *testing.T) {
	layout := testLayout(t)
	flow := testFlow()
	rule := RewriteRule{Kind: "macmap"}
	patches, err := genFlowPatches(rule, flow, layout)
	if err != nil {
		t.Fatalf("genFlowPatches: %v", err)
	}
	if patches != nil {
		t.Errorf("patches = %v, want nil (macmap is per-packet)", patches)
	}
}

// RU131: field kind, apply=set, target=ttl, fixed=128 -> 1 patch.
func TestGenFlowPatches_Field(t *testing.T) {
	layout := testLayout(t)
	flow := testFlow()
	rule := RewriteRule{
		Kind: "field", Target: "ttl", Apply: "set",
		Strategy: core.StrategyConfig{Strategy: "fixed", Value: "128"},
	}
	patches, err := genFlowPatches(rule, flow, layout)
	if err != nil {
		t.Fatalf("genFlowPatches: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("patches = %d, want 1", len(patches))
	}
	if patches[0].Field != "ttl" {
		t.Errorf("field = %q, want ttl", patches[0].Field)
	}
	if len(patches[0].Bytes) != 1 || patches[0].Bytes[0] != 0x80 {
		t.Errorf("bytes = %v, want [0x80]", patches[0].Bytes)
	}
}

// RU132: endpoint kind -> returns nil (per-packet).
func TestGenFlowPatches_Endpoint(t *testing.T) {
	layout := testLayout(t)
	flow := testFlow()
	rule := RewriteRule{Kind: "endpoint"}
	patches, err := genFlowPatches(rule, flow, layout)
	if err != nil {
		t.Fatalf("genFlowPatches: %v", err)
	}
	if patches != nil {
		t.Errorf("patches = %v, want nil (endpoint is per-packet)", patches)
	}
}

// RU133: unknown kind -> error.
func TestGenFlowPatches_UnknownKind(t *testing.T) {
	layout := testLayout(t)
	flow := testFlow()
	rule := RewriteRule{Kind: "unknown"}
	_, err := genFlowPatches(rule, flow, layout)
	if err == nil {
		t.Fatal("expected error for unknown rule kind")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "unknown rule kind") {
		t.Errorf("error = %q, want substring 'unknown rule kind'", errStr)
	}
}

// ---------------------------------------------------------------------------
// genFieldPatches unit tests
// ---------------------------------------------------------------------------

// RU134: apply:offset -> returns nil, nil (skipped for per-packet handling).
func TestGenFieldPatches_ApplyOffsetSkipped(t *testing.T) {
	layout := testLayout(t)
	rule := RewriteRule{
		Kind: "field", Target: "seq", Apply: "offset",
		Strategy: core.StrategyConfig{Strategy: "fixed", Value: "100"},
	}
	patches, err := genFieldPatches(rule, layout)
	if err != nil {
		t.Fatalf("genFieldPatches: %v", err)
	}
	if patches != nil {
		t.Errorf("patches = %v, want nil (apply:offset skipped)", patches)
	}
}

// RU135: unsupported target -> error.
func TestGenFieldPatches_FieldSpecMiss(t *testing.T) {
	layout := testLayout(t)
	rule := RewriteRule{
		Kind: "field", Target: "unknown", Apply: "set",
		Strategy: core.StrategyConfig{Strategy: "fixed", Value: "1"},
	}
	_, err := genFieldPatches(rule, layout)
	if err == nil {
		t.Fatal("expected error for unsupported target")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "unsupported target") {
		t.Errorf("error = %q, want substring 'unsupported target'", errStr)
	}
}

// RU136: target present in fieldSpec but offset is negative (absent in layout).
func TestGenFieldPatches_OffsetNeg(t *testing.T) {
	layout := pcapparser.OffsetLayout{Seq: -1, L4Start: 34, L4Protocol: "tcp"}
	rule := RewriteRule{
		Kind: "field", Target: "seq", Apply: "set",
		Strategy: core.StrategyConfig{Strategy: "fixed", Value: "100"},
	}
	_, err := genFieldPatches(rule, layout)
	if err == nil {
		t.Fatal("expected error for absent field in layout")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "absent in this flow's layout") {
		t.Errorf("error = %q, want substring 'absent in this flow's layout'", errStr)
	}
}

// RU137: empty strategy -> error from resolveStrategyValue.
func TestGenFieldPatches_StrategyFail(t *testing.T) {
	layout := testLayout(t)
	rule := RewriteRule{
		Kind: "field", Target: "ttl", Apply: "set",
		Strategy: core.StrategyConfig{Strategy: ""},
	}
	_, err := genFieldPatches(rule, layout)
	if err == nil {
		t.Fatal("expected error for empty strategy")
	}
}

// RU138: encodeValue fails for target src_ip with invalid value.
func TestGenFieldPatches_EncodeFail(t *testing.T) {
	layout := testLayout(t)
	rule := RewriteRule{
		Kind: "field", Target: "src_ip", Apply: "set",
		Strategy: core.StrategyConfig{Strategy: "fixed", Value: "bad"},
	}
	_, err := genFieldPatches(rule, layout)
	if err == nil {
		t.Fatal("expected error for invalid IP value")
	}
}

// RU139: success case with ttl.
func TestGenFieldPatches_Success(t *testing.T) {
	layout := testLayout(t)
	rule := RewriteRule{
		Kind: "field", Target: "ttl", Apply: "set",
		Strategy: core.StrategyConfig{Strategy: "fixed", Value: "128"},
	}
	patches, err := genFieldPatches(rule, layout)
	if err != nil {
		t.Fatalf("genFieldPatches: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("patches = %d, want 1", len(patches))
	}
	if len(patches[0].Bytes) != 1 || patches[0].Bytes[0] != 0x80 {
		t.Errorf("bytes = %v, want [0x80]", patches[0].Bytes)
	}
	if patches[0].Field != "ttl" {
		t.Errorf("field = %q, want ttl", patches[0].Field)
	}
	if patches[0].Offset != layout.TTL {
		t.Errorf("offset = %d, want %d", patches[0].Offset, layout.TTL)
	}
	if patches[0].Layer != "l3" {
		t.Errorf("layer = %q, want l3", patches[0].Layer)
	}
}

// ---------------------------------------------------------------------------
// resolveOffsetDelta unit tests
// ---------------------------------------------------------------------------

// RU140: empty strategy -> error.
func TestResolveOffsetDelta_StrategyFail(t *testing.T) {
	_, err := resolveOffsetDelta(RewriteRule{Strategy: core.StrategyConfig{Strategy: ""}})
	if err == nil {
		t.Fatal("expected error for empty strategy")
	}
}

// RU141: non-numeric value -> error.
func TestResolveOffsetDelta_ParseFail(t *testing.T) {
	_, err := resolveOffsetDelta(RewriteRule{Strategy: core.StrategyConfig{Strategy: "fixed", Value: "abc"}})
	if err == nil {
		t.Fatal("expected error for non-numeric value")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "offset delta") {
		t.Errorf("error = %q, want substring 'offset delta'", errStr)
	}
}

// RU142: valid value -> uint32.
func TestResolveOffsetDelta_Valid(t *testing.T) {
	v, err := resolveOffsetDelta(RewriteRule{Strategy: core.StrategyConfig{Strategy: "fixed", Value: "1000"}})
	if err != nil {
		t.Fatalf("resolveOffsetDelta: %v", err)
	}
	if v != 1000 {
		t.Errorf("delta = %d, want 1000", v)
	}
}

// RU143: value exceeds uint32 -> truncates to 0.
func TestResolveOffsetDelta_TruncateOverflow(t *testing.T) {
	v, err := resolveOffsetDelta(RewriteRule{Strategy: core.StrategyConfig{Strategy: "fixed", Value: "4294967296"}})
	if err != nil {
		t.Fatalf("resolveOffsetDelta: %v", err)
	}
	if v != 0 {
		t.Errorf("delta = %d, want 0 (overflow truncation)", v)
	}
}

// ---------------------------------------------------------------------------
// endpointPatch unit tests
// ---------------------------------------------------------------------------

// RU145: client_ip s2c -> offset = layout.DstIP, Bytes = newIP.
func TestEndpointPatch_ClientIP_S2C(t *testing.T) {
	layout := testLayout(t)
	newIP := net.ParseIP("11.0.0.1")
	p, err := endpointPatch("s2c", "client_ip", newIP, layout)
	if err != nil {
		t.Fatalf("endpointPatch: %v", err)
	}
	if p.Offset != layout.DstIP {
		t.Errorf("offset = %d, want %d (DstIP)", p.Offset, layout.DstIP)
	}
	want := newIP.To4()
	if len(p.Bytes) != 4 || p.Bytes[0] != want[0] || p.Bytes[1] != want[1] || p.Bytes[2] != want[2] || p.Bytes[3] != want[3] {
		t.Errorf("bytes = %v, want %v", p.Bytes, want)
	}
}

// RU146: server_ip s2c -> offset = layout.SrcIP.
func TestEndpointPatch_ServerIP_S2C(t *testing.T) {
	layout := testLayout(t)
	newIP := net.ParseIP("11.0.0.1")
	p, err := endpointPatch("s2c", "server_ip", newIP, layout)
	if err != nil {
		t.Fatalf("endpointPatch: %v", err)
	}
	if p.Offset != layout.SrcIP {
		t.Errorf("offset = %d, want %d (SrcIP)", p.Offset, layout.SrcIP)
	}
}

// RU152: unknown target -> error.
func TestEndpointPatch_UnknownTarget(t *testing.T) {
	layout := testLayout(t)
	_, err := endpointPatch("c2s", "unknown", net.ParseIP("11.0.0.1"), layout)
	if err == nil {
		t.Fatal("expected error for unsupported endpoint target")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "unsupported endpoint target") {
		t.Errorf("error = %q, want substring 'unsupported endpoint target'", errStr)
	}
}

// RU153: offset negative -> error.
func TestEndpointPatch_OffsetNeg(t *testing.T) {
	layout := pcapparser.OffsetLayout{SrcIP: -1, DstIP: 30, L3Start: 14, L4Start: 34, L4Protocol: "tcp"}
	_, err := endpointPatch("c2s", "client_ip", net.ParseIP("11.0.0.1"), layout)
	if err == nil {
		t.Fatal("expected error for absent offset")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "offset absent") {
		t.Errorf("error = %q, want substring 'offset absent'", errStr)
	}
}

// RU154: IPv6 -> error.
func TestEndpointPatch_IPv6(t *testing.T) {
	layout := testLayout(t)
	_, err := endpointPatch("c2s", "client_ip", net.ParseIP("::1"), layout)
	if err == nil {
		t.Fatal("expected error for IPv6")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "not IPv4") {
		t.Errorf("error = %q, want substring 'not IPv4'", errStr)
	}
}

// RU155: port target via IP path -> error.
func TestEndpointPatch_PortTarget(t *testing.T) {
	layout := testLayout(t)
	_, err := endpointPatch("c2s", "client_port", net.ParseIP("11.0.0.1"), layout)
	if err == nil {
		t.Fatal("expected error for port patching via IP path")
	}
	if errStr := err.Error(); !strings.Contains(errStr, "not supported via IP path") {
		t.Errorf("error = %q, want substring 'not supported via IP path'", errStr)
	}
}
