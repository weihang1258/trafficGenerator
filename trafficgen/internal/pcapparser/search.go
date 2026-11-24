package pcapparser

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
)

// SearchQuery is a multi-condition combination query (§17.10). v1 supports AND
// only: all set conditions must match. OR/nested grouping is v2.
type SearchQuery struct {
	FlowFilter    *FlowFilter    // flow-level filter (matched against FlowModel fields)
	PacketFilter  *PacketFilter  // packet-level filter (matched against PacketModel fields)
	Payload       *PayloadFilter // payload content filter (trigram index)
	Scope         string         // reassembled|packet (§17.10); empty = both
	Limit, Offset int
}

// FlowFilter matches flow-level fields. Empty/zero fields are wildcards.
type FlowFilter struct {
	Protocol    string // tcp|udp|icmp|arp
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	L7Type      string // l7_protocol
	L7Method    string
	L7Host      string
	L7QueryName string
}

// PacketFilter matches packet-level fields (§17.10). Empty/zero fields are
// wildcards. Applied to PacketModelView records within candidate flows.
type PacketFilter struct {
	Direction   string // c2s|s2c
	TimeStartUs int64  // inclusive; 0 = no lower bound
	TimeEndUs   int64  // inclusive; 0 = no upper bound
	L4Protocol  string // tcp|udp|icmp|arp
	AnomalyFlag string // truncated|oversize|undersize|""
}

// PayloadFilter matches payload content. Contains is a literal byte substring
// (text or binary); Regex is an optional regex applied after trigram narrowing
// (v1 supports Contains; Regex is v2 but the field is reserved).
type PayloadFilter struct {
	// Contains 是**文本形态**的检索串（第14轮 B8：曾为 []byte，JSON 字符串
	// 会被 encoding/json 强制按 base64 解码——Encoding 参数从未生效）。
	// 解码语义由 Encoding 决定，见 decodePayloadFilter。
	Contains string
	Encoding string // "ascii"(默认)|"hex"|"base64"
	Regex    string // v2
}

// SearchResult is one hit: a flow matching the query, with payload matches if
// a payload filter was applied, and the packet IDs within it that match the
// packet filter (if any).
type SearchResult struct {
	Flow    FlowModelView
	Matches []TrigramMatch    // payload match locations (empty if no payload filter)
	Packets []PacketModelView // packets in this flow matching PacketFilter (empty if none)
}

// FlowModelView is a lightweight projection of storage.FlowModel for search
// results, avoiding a storage import here. The caller (asset layer) maps it.
type FlowModelView struct {
	ID         string
	L4Protocol string
	SrcIP      string
	DstIP      string
	SrcPort    uint16
	DstPort    uint16
	L7Protocol string
	// Typed L7 identity fields. They were declared on FlowFilter but never
	// projected or matched, so passing L7Host/L7Method/L7QueryName acted as a
	// silent wildcard (客户端 2026-11-23 问题 2 的同型：参数存在但不生效).
	L7Method    string
	L7Host      string
	L7QueryName string
}

// PacketModelView is a lightweight projection of storage.PacketModel for
// packet-level search filtering, avoiding a storage import here.
type PacketModelView struct {
	ID          string
	FlowID      string
	Direction   string
	TimestampUs int64
	L4Protocol  string
	AnomalyFlag string
}

// MatchPreview returns the IDs of flows whose headers match the given FlowMatcher
// (§17.11 "matcher 命中预览"). Used by the "configure rewrite rule -> verify
// which flows it hits" endpoint. The matcher semantics mirror replay.FlowMatcher:
// protocol any, port 0 = any, IP supports exact or CIDR.
func MatchPreview(flows []FlowModelView, matcher FlowMatcher) []string {
	var hits []string
	for _, f := range flows {
		if !matchFlowMatcher(f, matcher) {
			continue
		}
		hits = append(hits, f.ID)
	}
	return hits
}

// FlowMatcher is the rewrite-rule flow matcher (§16.4), reused by MatchPreview.
// Empty/zero fields are wildcards. SrcIP/DstIP support exact or CIDR.
type FlowMatcher struct {
	Protocol string
	SrcIP    string
	SrcPort  uint16
	DstIP    string
	DstPort  uint16
}

// matchFlowMatcher reports whether a flow matches the matcher (wildcards on
// empty/zero, CIDR-aware on IPs).
func matchFlowMatcher(f FlowModelView, m FlowMatcher) bool {
	if m.Protocol != "" && f.L4Protocol != m.Protocol {
		return false
	}
	if m.SrcPort != 0 && f.SrcPort != m.SrcPort {
		return false
	}
	if m.DstPort != 0 && f.DstPort != m.DstPort {
		return false
	}
	if m.SrcIP != "" && !ipMatch(m.SrcIP, f.SrcIP) {
		return false
	}
	if m.DstIP != "" && !ipMatch(m.DstIP, f.DstIP) {
		return false
	}
	return true
}

// ipMatch reports whether candidate IP matches spec, where spec is either an
// exact IP or a CIDR network (§16.4 FlowMatcher SrcIP/DstIP support CIDR).
func ipMatch(spec, candidate string) bool {
	if strings.Contains(spec, "/") {
		_, cidr, err := net.ParseCIDR(spec)
		if err != nil {
			return false
		}
		ip := net.ParseIP(candidate)
		return ip != nil && cidr.Contains(ip)
	}
	return spec == candidate
}

// Search runs a multi-condition AND query against in-memory flows + packets +
// the trigram index (§12). It returns matching flows with payload match
// locations and (if a packet filter is set) the matching packets within each
// flow. packets may be nil when no packet-level filter is requested.
func Search(flows []FlowModelView, packets []PacketModelView, index *TrigramIndex, query *SearchQuery) ([]SearchResult, error) {
	// 1. Flow filter: narrow to candidate flows.
	candidates := flows
	if query.FlowFilter != nil {
		candidates = filterFlows(candidates, query.FlowFilter)
	}

	// 2. Payload filter: trigram search -> set of (FlowID, Dir) that contain the
	// pattern. Empty if no payload filter.
	//
	// Scope selects which payload space the search runs over (§17.10):
	//   ""/"reassembled" — the reassembled-stream index (the default, and the
	//     only space we index today: TCP c2s/s2c segments)
	//   "packet"         — per-packet payloads; those are NOT in the trigram
	//     index, so the payload stage is skipped and the caller's packet_filter
	//     does the narrowing. Scope used to be accepted and ignored, which made
	//     `scope=packet` silently behave like `reassembled`.
	switch query.Scope {
	case "", "reassembled", "packet":
	default:
		return nil, fmt.Errorf("invalid scope %q (want reassembled or packet)", query.Scope)
	}
	// scope=packet + payload 是"接受但不生效"，正是这次要清掉的那类静默。
	// 逐包 payload 还没进 trigram 索引，明确报错比假装筛过来得诚实。
	if query.Payload != nil && query.Scope == "packet" {
		return nil, fmt.Errorf("scope=packet does not support payload search yet " +
			"(per-packet payloads are not indexed); omit scope to search the reassembled streams, " +
			"or use packet_filter to narrow per-packet fields")
	}
	var payloadHits map[string][]TrigramMatch // FlowID -> matches
	if query.Payload != nil {
		needle, err := decodePayloadFilter(query.Payload)
		if err != nil {
			return nil, err
		}
		matches := index.Search(needle)
		payloadHits = map[string][]TrigramMatch{}
		for _, m := range matches {
			payloadHits[m.FlowID] = append(payloadHits[m.FlowID], m)
		}
		// Candidates must be in the payload hit set.
		filtered := candidates[:0]
		for _, f := range candidates {
			if _, ok := payloadHits[f.ID]; ok {
				filtered = append(filtered, f)
			}
		}
		candidates = filtered
	}

	// 3. Packet filter: if set, a flow is a hit only if it has >=1 packet
	// matching the packet filter. Collect the matching packets per flow.
	var packetsByFlow map[string][]PacketModelView
	if query.PacketFilter != nil && packets != nil {
		packetsByFlow = map[string][]PacketModelView{}
		for _, p := range packets {
			if !matchPacket(p, query.PacketFilter) {
				continue
			}
			packetsByFlow[p.FlowID] = append(packetsByFlow[p.FlowID], p)
		}
		filtered := candidates[:0]
		for _, f := range candidates {
			if pkts, ok := packetsByFlow[f.ID]; ok && len(pkts) > 0 {
				filtered = append(filtered, f)
			}
		}
		candidates = filtered
	}

	// 4. Build results (paginated).
	limit := query.Limit
	if limit <= 0 {
		limit = len(candidates)
	}
	skip := query.Offset
	if skip < 0 {
		skip = 0
	}
	var results []SearchResult
	for _, f := range candidates {
		if skip > 0 {
			skip--
			continue
		}
		r := SearchResult{Flow: f}
		if payloadHits != nil {
			r.Matches = payloadHits[f.ID]
		}
		if packetsByFlow != nil {
			r.Packets = packetsByFlow[f.ID]
		}
		results = append(results, r)
		if len(results) >= limit {
			break
		}
	}
	return results, nil
}

// matchPacket reports whether a packet matches the PacketFilter (AND of set
// fields). Zero/empty fields are wildcards.
func matchPacket(p PacketModelView, f *PacketFilter) bool {
	if f.Direction != "" && p.Direction != f.Direction {
		return false
	}
	if f.L4Protocol != "" && p.L4Protocol != f.L4Protocol {
		return false
	}
	if f.AnomalyFlag != "" && p.AnomalyFlag != f.AnomalyFlag {
		return false
	}
	if f.TimeStartUs != 0 && p.TimestampUs < f.TimeStartUs {
		return false
	}
	if f.TimeEndUs != 0 && p.TimestampUs > f.TimeEndUs {
		return false
	}
	return true
}

// filterFlows applies the FlowFilter (AND of set fields) to a flow list.
func filterFlows(flows []FlowModelView, f *FlowFilter) []FlowModelView {
	out := flows[:0]
	for _, fl := range flows {
		if f.Protocol != "" && fl.L4Protocol != f.Protocol {
			continue
		}
		if f.SrcIP != "" && fl.SrcIP != f.SrcIP {
			continue
		}
		if f.DstIP != "" && fl.DstIP != f.DstIP {
			continue
		}
		if f.SrcPort != 0 && fl.SrcPort != f.SrcPort {
			continue
		}
		if f.DstPort != 0 && fl.DstPort != f.DstPort {
			continue
		}
		if f.L7Type != "" && fl.L7Protocol != f.L7Type {
			continue
		}
		if f.L7Method != "" && !strings.EqualFold(fl.L7Method, f.L7Method) {
			continue
		}
		if f.L7Host != "" && !strings.EqualFold(fl.L7Host, f.L7Host) {
			continue
		}
		if f.L7QueryName != "" && !strings.EqualFold(fl.L7QueryName, f.L7QueryName) {
			continue
		}
		out = append(out, fl)
	}
	return out
}

// decodePayloadFilter resolves the Contains needle, applying hex decoding if
// Encoding=="hex".
func decodePayloadFilter(p *PayloadFilter) ([]byte, error) {
	if p == nil {
		return nil, nil
	}
	needle := []byte(p.Contains)
	switch p.Encoding {
	case "hex":
		s := strings.TrimSpace(string(needle))
		if len(s)%2 != 0 {
			return nil, fmt.Errorf("odd hex length: %d chars in %q", len(s), s)
		}
		dec := make([]byte, len(s)/2)
		for i := 0; i+1 < len(s); i += 2 {
			b, ok := fromHexPair(s[i], s[i+1])
			if !ok {
				return nil, fmt.Errorf("invalid hex character at position %d in %q", i, s)
			}
			dec[i/2] = b
		}
		needle = dec
	case "base64":
		dec, err := base64.StdEncoding.DecodeString(string(needle))
		if err != nil {
			return nil, fmt.Errorf("invalid base64 in Contains: %w", err)
		}
		needle = dec
	default:
		// ""/"ascii"：原文字节（第14轮 B8：Encoding 此前被忽略、恒按
		// base64 解——ascii 文本必报 illegal base64）。
	}
	return needle, nil
}

// fromHexPair decodes two hex chars to a byte.
func fromHexPair(hi, lo byte) (byte, bool) {
	h, ok1 := hexNibble(hi)
	l, ok2 := hexNibble(lo)
	if !ok1 || !ok2 {
		return 0, false
	}
	return h<<4 | l, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

var errInvalidHex = bytesError("invalid hex encoding in payload filter")

// bytesError is a minimal error type to avoid importing fmt/errors here.
type bytesError string

func (e bytesError) Error() string { return string(e) }

// Ensure bytes import is used (bytesError could use bytes; kept for symmetry).
var _ = bytes.Equal
