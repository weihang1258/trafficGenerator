// Package srv6 implements the SRv6 (Segment Routing over IPv6, 基于 IPv6 的
// 段路由) protocol planner per RFC 8754 / RFC 8200 / RFC 8986.
//
// SRv6 is NOT a standalone transport protocol — it is an IPv6 extension
// header (Next Header = 43, Routing Type = 4) called the SRH (Segment
// Routing Header, 段路由头部). The planner emits one IPv6 packet per flow
// carrying an SRH with the configured Segment List.
//
// Per-flow identity uses the outer IPv6 5-tuple + inner L4 ports + inner
// protocol number (6/17/58); the outer Next Header = 43 is NOT a L4 protocol
// number and does not participate in FlowID hashing.
package srv6

import "github.com/trafficgen/trafficgen/internal/core"

// SRv6Config 与 SRv6TLV 已移至 core.SRv6Config / core.SRv6TLV（FlowSpec.SRv6
// 挂载）。本包通过类型别名继续以裸名 SRv6Config / SRv6TLV 引用，避免大范围
// 改名 emit_*.go / validate.go / planner_test.go 中的形参与类型断言。
type SRv6Config = core.SRv6Config
type SRv6TLV = core.SRv6TLV

// supportedSegTypes are the 29 seg_type names from RFC 8986 + RFC 8754
// (design §3.4). v1 only validates the string — no End* semantic checks
// for unsupported types (V-N-08 passes for unknown valid strings).
var supportedSegTypes = map[string]bool{
	"":                          true, // defaults to "end"
	"end":                       true,
	"end.x":                     true,
	"end.t":                     true,
	"end.dx2":                   true,
	"end.dx4":                   true,
	"end.dx6":                   true,
	"end.dt4":                   true,
	"end.dt6":                   true,
	"end.dt2u":                  true,
	"end.dt2m":                  true,
	"end.b6":                    true,
	"end.b6.encaps":             true,
	"end.b6.encaps.red":         true,
	"end.bm":                    true,
	"end.un":                    true, // End.Un (unicast-destined variant)
	"end.ua":                    true,
	"end.ux":                    true,
	"end.ut":                    true,
	"end.uN":                    true, // uSID variant
	"end.uA":                    true,
	"end.uX":                    true,
	"end.uT":                    true,
	"end.b":                     true,
	"end.d":                     true,
	"end.o":                     true,
	"end.ln":                    true,
	"end.up":                    true,
	"end.UN":                    true, // End.UN (other behavior, RFC 8986)
	"end.u":                     true,
}

// payloadProtocolNextHeader maps the inner protocol name to its IPv6 Next
// Header value. Design §6 / §3.2.
var payloadProtocolNextHeader = map[string]uint8{
	"tcp":    6,
	"udp":    17,
	"icmpv6": 58,
	"ipv6":   41, // IPv6-in-IPv6 (RFC 8986 §4.4/§4.13)
	"ipv4":   4,  // IPv4-in-IPv6 (RFC 8986 §4.5/§4.8)
	"none":   59, // No Next Header (RFC 8200 §4.7)
}

// reservedTLVTypes lists TLV types that MUST NOT be set by users
// (RFC 8754 §8.2: 1/2/3/6 are Reserved; HMAC-Sig TLV Type=6 does NOT exist).
var reservedTLVTypes = map[uint8]bool{
	1: true, // Reserved
	2: true, // Reserved
	3: true, // Reserved
	6: true, // Reserved (HMAC-Sig never existed in RFC 8754)
}

// autoInsertedTLVTypes lists TLV types the serializer inserts automatically.
// Users setting these manually are rejected (V-N-11, V-N-12).
var autoInsertedTLVTypes = map[uint8]bool{
	0: true, // Pad1
	4: true, // PadN
}
