package core

import "encoding/json"

// Stratum（比特币矿池 Stratum v1）配置类型。字段名对齐
// test/protocol_pcap/cases/stratum.json 与 docs/protocol-designs/
// 75-stratum-{design,testcase}.md v2.1.1 的配置 typedef：sessions[] 事件编排
// 会话（每事件 = 一条 stratum 行或一对请求/响应行），concurrent=true 时多
// 会话交错回放（tcp 层须同时设 concurrent: true）。行式 JSON（LF 边界、
// 紧凑形态），[tcp→stratum] 终结层（ip 层由依赖补全自动插入）。

// StratumConfig is the flow's stratum terminal-layer configuration.
type StratumConfig struct {
	// Concurrent enables interleaved multi-session replay: session events
	// are emitted round-robin (per event index) instead of session-by-
	// session. The tcp layer must also set {"concurrent": true} to keep
	// independent connections per SrcPort.
	Concurrent bool `json:"concurrent,omitempty"`
	// Profile is informational ("stratum_v1" | "stratum_ipv6_v1" |
	// "stratum_bip310_ext"); the wire form is identical.
	Profile string `json:"profile,omitempty"`
	// Extensions declares BIP310 extensions ("version-rolling") at the
	// config level (non-independent layer chain).
	Extensions []string         `json:"extensions,omitempty"`
	Sessions   []StratumSession `json:"sessions,omitempty"`
	// WireFault injects one negative-path fault (11 kinds, v2.1.0 design
	// §7 — 与 §7 表/用例 §5 表三方同序): json|framing|method|params|hex|
	// state|id|job|carrier|address_family|propagation.
	WireFault string `json:"wire_fault,omitempty"`
}

// StratumSession is one miner connection: ordered event list (one side of
// each stratum transaction). Session identity across connections is the
// SrcPort override (0 = flow default).
type StratumSession struct {
	SrcPort uint16         `json:"src_port,omitempty"`
	DstPort uint16         `json:"dst_port,omitempty"`
	Events  []StratumEvent `json:"events,omitempty"`
}

// StratumEvent is one event: a miner request (subscribe/authorize/submit/
// configure/extranonce_subscribe), a pool notification or reverse request
// (set_difficulty/notify/set_extranonce/set_version_mask/show_message/
// get_version), with the auto-response shape configured in-band (Result /
// Subscriptions / Extranonce fields — design §5 自动派生规则).
type StratumEvent struct {
	Kind string `json:"kind,omitempty"`
	// PackNext merges this line's bytes with the NEXT event's line into one
	// TCP segment (多行粘连单段正例; both lines must be same direction).
	PackNext bool `json:"pack_next,omitempty"`
	// ID is the JSON-RPC id (number for requests, null for notifications),
	// embedded verbatim (json.RawMessage preserves the case JSON's exact
	// literal). Requests echo it in the auto-response; notifications carry
	// the literal null.
	ID json.RawMessage `json:"id,omitempty"`

	// --- subscribe ---
	UserAgent     string          `json:"user_agent,omitempty"`
	Subscriptions json.RawMessage `json:"subscriptions,omitempty"` // [["mining.set_difficulty","7f1a2b3c"],…]
	Extranonce1   string          `json:"extranonce1,omitempty"`
	// Extranonce2Size is the extranonce2 byte size (result[2], JSON number).
	Extranonce2Size int `json:"extranonce2_size,omitempty"`

	// --- authorize / submit / get_version (response shape in Result) ---
	Username    string          `json:"username,omitempty"`
	Password    string          `json:"password,omitempty"`
	JobID       string          `json:"job_id,omitempty"`
	Extranonce2 string          `json:"extranonce2,omitempty"`
	Nonce       string          `json:"nonce,omitempty"`
	VersionBits string          `json:"version_bits,omitempty"` // BIP310 6th submit param
	Result      json.RawMessage `json:"result,omitempty"`       // true | false | "MinerName/1.0.0"

	// --- notify ---
	Prevhash     string   `json:"prevhash,omitempty"` // 64 hex 线序（反转展示序）
	Coinb1       string   `json:"coinb1,omitempty"`
	Coinb2       string   `json:"coinb2,omitempty"`
	MerkleBranch []string `json:"merkle_branch,omitempty"` // 每步 64 hex；可为空数组
	Version      string   `json:"version,omitempty"`       // 8 hex
	Nbits        string   `json:"nbits,omitempty"`         // 8 hex
	Ntime        string   `json:"ntime,omitempty"`         // 8 hex
	CleanJobs    bool     `json:"clean_jobs,omitempty"`

	// --- set_difficulty / set_extranonce / set_version_mask / show_message ---
	Difficulty json.RawMessage `json:"difficulty,omitempty"` // JSON number 十进制定点
	Mask       string          `json:"mask,omitempty"`       // TMask 恒 8 hex
	Message    string          `json:"message,omitempty"`    // show_message 文本

	// --- configure ---
	// Extensions is the BIP310 extension-name array (params[0]); empty →
	// builder default ["version-rolling"] (D-STRATUM-1 G-ST-2).
	Extensions []string        `json:"extensions,omitempty"`
	Params     json.RawMessage `json:"params,omitempty"` // 扩展参数映射
	// VersionRollingMask / MinBitCount are the miner-side BIP310 configure
	// parameters (D-STRATUM-1 G-ST-2). When either is set the configure
	// request params map is built from them; otherwise the pinned
	// FixtureCfgParams literal is used (bit-identical to the old default).
	VersionRollingMask string `json:"version_rolling_mask,omitempty"`
	MinBitCount        int    `json:"min_bit_count,omitempty"`
	// CfgResult is the configure response result mapping (per-extension
	// TExtensionResult; version-rolling carries the intersection mask).
	CfgResult json.RawMessage `json:"cfg_result,omitempty"`
}
