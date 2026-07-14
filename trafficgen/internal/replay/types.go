// Package replay implements PCAP replay: read a pcap asset, rewrite L2/L3/L4
// fields per rules, and replay at a set rate through the existing engine
// pipeline (§16). It reuses the engine's ConfigWorker/PacketWorker/OutputWorker
// and TokenBucket, plugging in via the buildFunc + a replay planner.
package replay

import (
	"github.com/trafficgen/trafficgen/internal/core"
)

// ReplaySpec is the config for a replay strategy (§16.4): which pcap asset to
// replay, how fast, how to rewrite, and optional multi-flow amplification.
type ReplaySpec struct {
	PcapAssetID  string        `json:"pcap_asset_id"`             // references §15 asset
	Loop         int           `json:"loop"`                      // 0 = infinite
	Speed        ReplaySpeed   `json:"speed"`
	Direction    string        `json:"direction"`                 // single | dual
	ChecksumMode string        `json:"checksum_mode"`             // recompute(default) | preserve
	Rewrites     []RewriteRule `json:"rewrites"`
	FlowScaling  *FlowScaling  `json:"flow_scaling,omitempty"`    // optional multi-flow amplification
	Inject       *InjectConfig `json:"inject,omitempty"`          // v2 reserved: anomaly injection
}

// ReplaySpeed selects the rate model (§16.9). Two families: timestamp pacing
// (original/multiplier) and rate pacing (bps/pps/max).
type ReplaySpeed struct {
	Mode       string  `json:"mode"`        // original | multiplier | bps | pps | max
	Multiplier float64 `json:"multiplier"`  // multiplier mode: 1.5 = 1.5x speed
	BPS        string  `json:"bps"`         // bps mode: "200k"
	PPS        float64 `json:"pps"`         // pps mode
}

// RewriteRule defines one rewrite operation (§16.4/§16.5). Kind selects the
// operation: field (single-field override), endpoint (bidirectional client/
// server endpoint), or map (ipmap/portmap/macmap value substitution).
type RewriteRule struct {
	Match    FlowMatcher        `json:"match"`              // which flows/packets; empty = all
	Kind     string             `json:"kind"`               // field | endpoint | ipmap | portmap | macmap
	Target   string             `json:"target"`             // field/endpoint: which field
	Mapping  map[string]string  `json:"mapping,omitempty"`  // map mode: value -> value
	Scope    string             `json:"scope"`              // per-packet | per-flow
	Apply    string             `json:"apply"`              // set | offset
	Strategy core.StrategyConfig `json:"strategy"`          // fixed/inc/random/list/pattern
}

// FlowMatcher matches a flow bidirectionally (§16.4): both directions of a
// connection match the same matcher. Empty/zero fields are wildcards.
type FlowMatcher struct {
	Protocol string `json:"protocol,omitempty"` // tcp|udp|icmp|arp|"" = any
	SrcIP    string `json:"src_ip,omitempty"`   // exact or CIDR, "" = any
	SrcPort  uint16 `json:"src_port,omitempty"` // 0 = any
	DstIP    string `json:"dst_ip,omitempty"`
	DstPort  uint16 `json:"dst_port,omitempty"`
}

// FlowScaling configures multi-flow amplification (§16.8): each original flow
// is cloned N times with per-clone replacement values (IP/port/MAC/seq offset).
type FlowScaling struct {
	Count      int                  `json:"count"`                 // clones per original flow (total N×M)
	SrcIP      core.StrategyConfig `json:"src_ip,omitempty"`
	DstIP      core.StrategyConfig `json:"dst_ip,omitempty"`
	SrcPort    core.StrategyConfig `json:"src_port,omitempty"`
	DstPort    core.StrategyConfig `json:"dst_port,omitempty"`
	SrcMAC     core.StrategyConfig `json:"src_mac,omitempty"`
	DstMAC     core.StrategyConfig `json:"dst_mac,omitempty"`
	SeqOffset  core.StrategyConfig `json:"seq_offset,omitempty"`   // per-flow random seq offset
	Interleave string               `json:"interleave,omitempty"`  // stack(default) | serial
}

// Clone holds the per-clone replacement values for one amplified flow (§9).
type Clone struct {
	Index                                int
	SrcIP, DstIP                         string
	SrcPort, DstPort                     uint16
	SrcMAC, DstMAC                       string
	SeqOffset                            uint32
}

// Patch is a single byte-patch instruction (replay design §2): overwrite
// `Bytes` at `Offset` in the frame. Field is the logical name (for conflict
// detection); Layer determines whether checksum recomputation is triggered.
// Produced by the planner, consumed by the rewriter.
type Patch struct {
	Field  string // logical field name (src_ip/dst_ip/seq/...; conflict detection)
	Offset int    // byte offset within the frame (from OffsetLayout)
	Bytes  []byte // new value
	Layer  string // l2|l3|l4 (drives checksum recompute scope)
}

// InjectConfig is reserved for v2 anomaly injection (§16.10). v1 does not
// implement it; the field is kept here so the config schema is forward-compatible.
type InjectConfig struct {
	Mode string `json:"mode"` // v2: reorder | retransmit | drop | jitter | duplicate | biterror
	Rate float64 `json:"rate"`
}
