package pcapparser

// Test points for search.go, derived from tools/test_points/pcapparser.md
// (components S1-S7). REAL tests exercising Search/matchPacket/filterFlows/
// MatchPreview/matchFlowMatcher/ipMatch/decodePayloadFilter directly.

import (
	"strings"
	"testing"
)

// --- S2: matchPacket ---

func TestMatchPacket_DirectionMismatch(t *testing.T) {
	p := PacketModelView{Direction: "s2c", TimestampUs: 10, L4Protocol: "tcp"}
	f := &PacketFilter{Direction: "c2s"}
	if matchPacket(p, f) {
		t.Error("direction mismatch should not match")
	}
}

func TestMatchPacket_L4Mismatch(t *testing.T) {
	p := PacketModelView{Direction: "c2s", L4Protocol: "udp"}
	f := &PacketFilter{L4Protocol: "tcp"}
	if matchPacket(p, f) {
		t.Error("l4 mismatch should not match")
	}
}

func TestMatchPacket_AnomalyMismatch(t *testing.T) {
	p := PacketModelView{Direction: "c2s", AnomalyFlag: ""}
	f := &PacketFilter{AnomalyFlag: "truncated"}
	if matchPacket(p, f) {
		t.Error("anomaly mismatch should not match")
	}
}

func TestMatchPacket_TimeBeforeStart(t *testing.T) {
	p := PacketModelView{Direction: "c2s", TimestampUs: 5}
	f := &PacketFilter{TimeStartUs: 10}
	if matchPacket(p, f) {
		t.Error("ts before start should not match")
	}
}

func TestMatchPacket_TimeAfterEnd(t *testing.T) {
	p := PacketModelView{Direction: "c2s", TimestampUs: 100}
	f := &PacketFilter{TimeEndUs: 50}
	if matchPacket(p, f) {
		t.Error("ts after end should not match")
	}
}

func TestMatchPacket_AllMatch(t *testing.T) {
	p := PacketModelView{Direction: "c2s", L4Protocol: "tcp", AnomalyFlag: "truncated", TimestampUs: 50}
	f := &PacketFilter{Direction: "c2s", L4Protocol: "tcp", AnomalyFlag: "truncated", TimeStartUs: 10, TimeEndUs: 100}
	if !matchPacket(p, f) {
		t.Error("all-fields match should return true")
	}
}

// --- S3: filterFlows ---

func makeFlowsN() []FlowModelView {
	return []FlowModelView{
		{ID: "f1", L4Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1234, DstPort: 80, L7Protocol: "http"},
		{ID: "f2", L4Protocol: "udp", SrcIP: "10.0.0.3", DstIP: "10.0.0.4", SrcPort: 5353, DstPort: 53, L7Protocol: "dns"},
	}
}

func TestFilterFlows_Empty(t *testing.T) {
	out := filterFlows(nil, &FlowFilter{Protocol: "tcp"})
	if len(out) != 0 {
		t.Errorf("filter empty flows = %d, want 0", len(out))
	}
}

func TestFilterFlows_ProtocolMismatch(t *testing.T) {
	out := filterFlows(makeFlowsN(), &FlowFilter{Protocol: "icmp"})
	if len(out) != 0 {
		t.Errorf("protocol mismatch = %d, want 0", len(out))
	}
}

func TestFilterFlows_SrcIPMismatch(t *testing.T) {
	out := filterFlows(makeFlowsN(), &FlowFilter{SrcIP: "9.9.9.9"})
	if len(out) != 0 {
		t.Errorf("srcip mismatch = %d, want 0", len(out))
	}
}

func TestFilterFlows_DstIPMismatch(t *testing.T) {
	out := filterFlows(makeFlowsN(), &FlowFilter{DstIP: "9.9.9.9"})
	if len(out) != 0 {
		t.Errorf("dstip mismatch = %d, want 0", len(out))
	}
}

func TestFilterFlows_SrcPortMismatch(t *testing.T) {
	out := filterFlows(makeFlowsN(), &FlowFilter{SrcPort: 9999})
	if len(out) != 0 {
		t.Errorf("srcport mismatch = %d, want 0", len(out))
	}
}

func TestFilterFlows_DstPortMismatch(t *testing.T) {
	out := filterFlows(makeFlowsN(), &FlowFilter{DstPort: 9999})
	if len(out) != 0 {
		t.Errorf("dstport mismatch = %d, want 0", len(out))
	}
}

func TestFilterFlows_L7TypeMismatch(t *testing.T) {
	out := filterFlows(makeFlowsN(), &FlowFilter{L7Type: "tls"})
	if len(out) != 0 {
		t.Errorf("l7type mismatch = %d, want 0", len(out))
	}
}

func TestFilterFlows_AllMatch(t *testing.T) {
	out := filterFlows(makeFlowsN(), &FlowFilter{Protocol: "tcp", SrcIP: "10.0.0.1", DstPort: 80, L7Type: "http"})
	if len(out) != 1 || out[0].ID != "f1" {
		t.Errorf("all-match = %v, want [f1]", out)
	}
}

// S3-CIDR: filterFlows uses exact string comparison (NOT CIDR). This is the
// ipmap-rewriter-style "no CIDR" path, distinct from matchFlowMatcher/ipMatch
// which IS CIDR-aware. Both functions' CIDR behavior must be tested separately.

func TestFilterFlows_CIDRNotSupported(t *testing.T) {
	// FlowFilter.SrcIP="10.0.0.0/24", flow SrcIP="10.0.0.1": CIDR would match,
	// but filterFlows compares strings -> NOT equal -> flow excluded.
	out := filterFlows(makeFlowsN(), &FlowFilter{SrcIP: "10.0.0.0/24"})
	if len(out) != 0 {
		t.Errorf("CIDR spec in filterFlows = %d matches, want 0 (exact string compare, no CIDR expansion)", len(out))
	}
}

func TestFilterFlows_ExactStringMatch(t *testing.T) {
	// A flow whose SrcIP literally equals "10.0.0.0/24" matches the same string.
	flows := []FlowModelView{{ID: "fx", L4Protocol: "tcp", SrcIP: "10.0.0.0/24"}}
	out := filterFlows(flows, &FlowFilter{SrcIP: "10.0.0.0/24"})
	if len(out) != 1 {
		t.Errorf("literal-string match = %d, want 1 (proves string compare, not CIDR)", len(out))
	}
}

// --- S5: matchFlowMatcher ---

func TestMatchFlowMatcher_ProtocolMismatch(t *testing.T) {
	f := FlowModelView{L4Protocol: "udp", SrcIP: "10.0.0.1", SrcPort: 1234}
	if matchFlowMatcher(f, FlowMatcher{Protocol: "tcp"}) {
		t.Error("protocol mismatch should not match")
	}
}

func TestMatchFlowMatcher_SrcPortMismatch(t *testing.T) {
	f := FlowModelView{L4Protocol: "tcp", SrcPort: 1234}
	if matchFlowMatcher(f, FlowMatcher{SrcPort: 5678}) {
		t.Error("srcport mismatch should not match")
	}
}

func TestMatchFlowMatcher_DstPortMismatch(t *testing.T) {
	f := FlowModelView{L4Protocol: "tcp", DstPort: 80}
	if matchFlowMatcher(f, FlowMatcher{DstPort: 443}) {
		t.Error("dstport mismatch should not match")
	}
}

func TestMatchFlowMatcher_SrcIPMismatch(t *testing.T) {
	f := FlowModelView{SrcIP: "10.0.0.1"}
	if matchFlowMatcher(f, FlowMatcher{SrcIP: "10.0.0.2"}) {
		t.Error("srcip exact mismatch should not match")
	}
}

func TestMatchFlowMatcher_DstIPMismatch(t *testing.T) {
	f := FlowModelView{DstIP: "10.0.0.1"}
	if matchFlowMatcher(f, FlowMatcher{DstIP: "10.0.0.2"}) {
		t.Error("dstip exact mismatch should not match")
	}
}

func TestMatchFlowMatcher_AllMatch(t *testing.T) {
	f := FlowModelView{L4Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1234, DstPort: 80}
	if !matchFlowMatcher(f, FlowMatcher{Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1234, DstPort: 80}) {
		t.Error("all-match should return true")
	}
}

// S5-CIDR: matchFlowMatcher IS CIDR-aware (via ipMatch). Distinct from filterFlows.

func TestMatchFlowMatcher_CIDRMatch(t *testing.T) {
	f := FlowModelView{SrcIP: "10.0.0.1"}
	if !matchFlowMatcher(f, FlowMatcher{SrcIP: "10.0.0.0/8"}) {
		t.Error("CIDR 10.0.0.0/8 should match 10.0.0.1")
	}
}

func TestMatchFlowMatcher_CIDRNoMatch(t *testing.T) {
	f := FlowModelView{SrcIP: "10.0.0.1"}
	if matchFlowMatcher(f, FlowMatcher{SrcIP: "192.168.0.0/16"}) {
		t.Error("CIDR 192.168.0.0/16 should NOT match 10.0.0.1")
	}
}

// --- S6: ipMatch ---

func TestIPMatch_CIDRValidMatch(t *testing.T) {
	if !ipMatch("10.0.0.0/24", "10.0.0.5") {
		t.Error("ipMatch 10.0.0.0/24 vs 10.0.0.5 = false, want true")
	}
}

func TestIPMatch_CIDRValidNoMatch(t *testing.T) {
	if ipMatch("10.0.0.0/24", "10.1.0.5") {
		t.Error("ipMatch 10.0.0.0/24 vs 10.1.0.5 = true, want false")
	}
}

func TestIPMatch_InvalidCIDR(t *testing.T) {
	if ipMatch("10.0.0.0/33", "10.0.0.5") {
		t.Error("ipMatch invalid CIDR /33 = true, want false (ParseCIDR err)")
	}
}

func TestIPMatch_UnparseableCandidate(t *testing.T) {
	if ipMatch("10.0.0.0/24", "not-an-ip") {
		t.Error("ipMatch unparseable candidate = true, want false")
	}
}

func TestIPMatch_Exact(t *testing.T) {
	if !ipMatch("10.0.0.1", "10.0.0.1") {
		t.Error("ipMatch exact equal = false, want true")
	}
	if ipMatch("10.0.0.1", "10.0.0.2") {
		t.Error("ipMatch exact unequal = true, want false")
	}
}

// --- S7: decodePayloadFilter ---

func TestDecodePayloadFilter_Nil(t *testing.T) {
	needle, err := decodePayloadFilter(nil)
	if err != nil {
		t.Errorf("nil: err = %v, want nil", err)
	}
	if needle != nil {
		t.Errorf("nil: needle = %v, want nil", needle)
	}
}

func TestDecodePayloadFilter_PlainText(t *testing.T) {
	needle, err := decodePayloadFilter(&PayloadFilter{Contains: []byte("target"), Encoding: "ascii"})
	if err != nil {
		t.Fatalf("ascii: %v", err)
	}
	if string(needle) != "target" {
		t.Errorf("ascii needle = %q, want target", string(needle))
	}
}

func TestDecodePayloadFilter_HexEmptyNeedle(t *testing.T) {
	needle, err := decodePayloadFilter(&PayloadFilter{Contains: []byte(""), Encoding: "hex"})
	if err != nil {
		t.Errorf("hex empty: err = %v, want nil", err)
	}
	if len(needle) != 0 {
		t.Errorf("hex empty needle len = %d, want 0", len(needle))
	}
}

func TestDecodePayloadFilter_HexOddLength(t *testing.T) {
	_, err := decodePayloadFilter(&PayloadFilter{Contains: []byte("abc"), Encoding: "hex"})
	if err == nil || !strings.Contains(err.Error(), "odd hex") {
		t.Errorf("hex odd 'abc': err = %v, want contains 'odd hex'", err)
	}
}

func TestDecodePayloadFilter_HexInvalidChar(t *testing.T) {
	_, err := decodePayloadFilter(&PayloadFilter{Contains: []byte("0xYZ"), Encoding: "hex"})
	if err == nil || !strings.Contains(err.Error(), "invalid hex") {
		t.Errorf("hex invalid char: err = %v, want contains 'invalid hex'", err)
	}
}

func TestDecodePayloadFilter_HexValid(t *testing.T) {
	// "48656c6c6f" is hex for "Hello".
	needle, err := decodePayloadFilter(&PayloadFilter{Contains: []byte("48656c6c6f"), Encoding: "hex"})
	if err != nil {
		t.Fatalf("hex valid: %v", err)
	}
	if string(needle) != "Hello" {
		t.Errorf("hex valid needle = %q, want Hello", string(needle))
	}
}

// --- S1: Search (additional branches) ---

func TestSearch_FlowFilterAllMatch(t *testing.T) {
	flows := []FlowModelView{
		{ID: "f1", L4Protocol: "tcp"},
		{ID: "f2", L4Protocol: "tcp"},
	}
	res, err := Search(flows, nil, nil, &SearchQuery{FlowFilter: &FlowFilter{Protocol: "tcp"}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("all-match = %d, want 2", len(res))
	}
}

func TestSearch_FlowFilterNoneMatch(t *testing.T) {
	flows := []FlowModelView{{ID: "f1", L4Protocol: "tcp"}}
	res, err := Search(flows, nil, nil, &SearchQuery{FlowFilter: &FlowFilter{Protocol: "icmp"}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("none-match = %d, want 0", len(res))
	}
}

func TestSearch_PayloadNoHits(t *testing.T) {
	flows := []FlowModelView{{ID: "f1", L4Protocol: "tcp"}}
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("hello world"))
	res, err := Search(flows, nil, idx, &SearchQuery{Payload: &PayloadFilter{Contains: []byte("nonexistent")}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("payload no-hits = %d, want 0", len(res))
	}
}

func TestSearch_NoPacketFilter(t *testing.T) {
	flows := []FlowModelView{{ID: "f1", L4Protocol: "tcp"}}
	res, err := Search(flows, nil, nil, &SearchQuery{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 1 {
		t.Errorf("no-filter = %d, want 1 (all candidates)", len(res))
	}
}

func TestSearch_PacketFilterPacketsNil(t *testing.T) {
	// PacketFilter set but packets==nil: packet filter stage skipped, all flows pass.
	flows := []FlowModelView{{ID: "f1", L4Protocol: "tcp"}}
	res, err := Search(flows, nil, nil, &SearchQuery{PacketFilter: &PacketFilter{Direction: "c2s"}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 1 {
		t.Errorf("packets-nil packet filter = %d, want 1 (skipped)", len(res))
	}
}

func TestSearch_LimitZeroReturnAll(t *testing.T) {
	flows := []FlowModelView{
		{ID: "f1"}, {ID: "f2"}, {ID: "f3"}, {ID: "f4"}, {ID: "f5"},
	}
	res, err := Search(flows, nil, nil, &SearchQuery{Limit: 0})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 5 {
		t.Errorf("Limit=0 = %d, want 5 (all)", len(res))
	}
}

func TestSearch_PositiveLimit(t *testing.T) {
	flows := []FlowModelView{
		{ID: "f1"}, {ID: "f2"}, {ID: "f3"}, {ID: "f4"}, {ID: "f5"},
	}
	res, err := Search(flows, nil, nil, &SearchQuery{Limit: 2})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("Limit=2 = %d, want 2", len(res))
	}
}

func TestSearch_NegativeOffsetClamped(t *testing.T) {
	flows := []FlowModelView{{ID: "f1"}, {ID: "f2"}}
	res, err := Search(flows, nil, nil, &SearchQuery{Offset: -5})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 2 {
		t.Errorf("Offset=-5 = %d, want 2 (clamped to 0)", len(res))
	}
}

func TestSearch_OffsetSkips(t *testing.T) {
	flows := []FlowModelView{{ID: "f1"}, {ID: "f2"}, {ID: "f3"}, {ID: "f4"}, {ID: "f5"}}
	res, err := Search(flows, nil, nil, &SearchQuery{Offset: 2})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 3 {
		t.Errorf("Offset=2 = %d, want 3 (skipped first 2)", len(res))
	}
}

func TestSearch_PayloadHitsAttached(t *testing.T) {
	flows := []FlowModelView{{ID: "f1", L4Protocol: "tcp"}}
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("secret password"))
	res, err := Search(flows, nil, idx, &SearchQuery{Payload: &PayloadFilter{Contains: []byte("secret")}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("results = %d, want 1", len(res))
	}
	if len(res[0].Matches) == 0 {
		t.Error("Matches empty, want payload hits attached")
	}
}

func TestSearch_PacketResultsAttached(t *testing.T) {
	flows := []FlowModelView{{ID: "f1", L4Protocol: "tcp"}}
	pkts := []PacketModelView{
		{ID: "p1", FlowID: "f1", Direction: "c2s", TimestampUs: 10, L4Protocol: "tcp"},
		{ID: "p2", FlowID: "f1", Direction: "s2c", TimestampUs: 20, L4Protocol: "tcp"},
	}
	res, err := Search(flows, pkts, nil, &SearchQuery{PacketFilter: &PacketFilter{Direction: "c2s"}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("results = %d, want 1", len(res))
	}
	if len(res[0].Packets) != 1 || res[0].Packets[0].ID != "p1" {
		t.Errorf("Packets = %v, want [p1] (c2s only)", res[0].Packets)
	}
}

func TestSearch_PacketFilterNoMatches(t *testing.T) {
	flows := []FlowModelView{{ID: "f1", L4Protocol: "tcp"}}
	pkts := []PacketModelView{
		{ID: "p1", FlowID: "f1", Direction: "s2c", L4Protocol: "tcp"},
	}
	// Filter for c2s but only s2c packet exists -> flow excluded.
	res, err := Search(flows, pkts, nil, &SearchQuery{PacketFilter: &PacketFilter{Direction: "c2s"}})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("no-packet-match = %d, want 0 (flow excluded)", len(res))
	}
}

// --- S4: MatchPreview ---

func TestMatchPreview_Empty(t *testing.T) {
	hits := MatchPreview(nil, FlowMatcher{Protocol: "tcp"})
	if len(hits) != 0 {
		t.Errorf("MatchPreview empty = %v, want empty", hits)
	}
}

func TestMatchPreview_FlowMatches(t *testing.T) {
	flows := []FlowModelView{{ID: "f1", L4Protocol: "tcp", SrcIP: "10.0.0.1"}}
	hits := MatchPreview(flows, FlowMatcher{Protocol: "tcp"})
	if len(hits) != 1 || hits[0] != "f1" {
		t.Errorf("MatchPreview = %v, want [f1]", hits)
	}
}

func TestMatchPreview_FlowFails(t *testing.T) {
	flows := []FlowModelView{{ID: "f1", L4Protocol: "udp"}}
	hits := MatchPreview(flows, FlowMatcher{Protocol: "tcp"})
	if len(hits) != 0 {
		t.Errorf("MatchPreview = %v, want empty (no match)", hits)
	}
}
