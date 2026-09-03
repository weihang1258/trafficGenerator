package core

import "encoding/json"

// ETHMining（以太坊挖矿 stratum 协议，EthereumStratum/1.0.0 ethash 矿池通信）
// 配置类型。字段名对齐 test/protocol_pcap/cases/ethmining.json 与
// docs/protocol-designs/73-ethmining-{design,testcase}.md v2.0.2：sessions[]
// 事件编排会话（每事件 = 一条 stratum 行或一对请求/响应行），hex_prefix 配置
// 启用 0x 方言变体（"0x" 或 ""），wire_fault 注入负例故障。行式 JSON（LF
// 边界、紧凑形态），[tcp→ethmining] 终结层（ip 层由依赖补全自动插入）。

// ETHMiningConfig is the flow's ethmining terminal-layer configuration.
type ETHMiningConfig struct {
	// Profile is informational ("ethmining_stratum_v1" | "ethmining_ipv6_v1"
	// | "ethmining_hex_prefix_v1"); the wire form is identical for v4/v6
	// (only the IP-layer offset changes), and 0x prefix is selected via
	// HexPrefix below.
	Profile string `json:"profile,omitempty"`
	// HexPrefix declares the session-wide hex data prefix: "" (spec default,
	// no prefix on extranonce/job_id/seedhash/headerhash/minernonce/订阅标识)
	// or "0x" (ethminer / some pool dialect; testcase §3 fixture variant).
	// Mixing forms within one session is a wire_fault.
	HexPrefix string            `json:"hex_prefix,omitempty"`
	Sessions  []ETHMiningSession `json:"sessions,omitempty"`
	// WireFault injects one negative-path fault (10 kinds, design §7 — 与
	// §7 表/用例 §5 表三方同序): json|framing|method|params|hex|state|id|
	// job|carrier|propagation.
	WireFault string `json:"wire_fault,omitempty"`
}

// ETHMiningSession is one miner↔pool connection: ordered event list (one
// side of each stratum transaction). Session identity across connections is
// the SrcPort/DstPort override.
type ETHMiningSession struct {
	SrcPort uint16            `json:"src_port,omitempty"`
	DstPort uint16            `json:"dst_port,omitempty"`
	Events  []ETHMiningEvent  `json:"events,omitempty"`
}

// ETHMiningEvent is one event: a miner request (subscribe/extranonce_subscribe
// /authorize/submit), a pool notification (set_difficulty/notify/set_extranonce),
// or a notify with no auto-response. The auto-response shape is configured
// in-band via Result / SubscriptionID / Extranonce (design §5 自动派生规则).
type ETHMiningEvent struct {
	Kind string `json:"kind,omitempty"`
	// PackNext merges this line's bytes with the NEXT event's line into one
	// TCP segment (多行粘连单段正例; both lines must be same direction).
	PackNext bool `json:"pack_next,omitempty"`
	// ID is the JSON-RPC id (number for requests, null for notifications),
	// embedded verbatim (json.RawMessage preserves the case JSON's exact
	// literal). Requests echo it in the auto-response.
	ID json.RawMessage `json:"id,omitempty"`

	// --- subscribe ---
	UserAgent     string `json:"user_agent,omitempty"`
	Protocol      string `json:"protocol,omitempty"` // "EthereumStratum/1.0.0"
	SubscriptionID string `json:"subscription_id,omitempty"` // 订阅标识（hex 32）
	Extranonce    string `json:"extranonce,omitempty"`        // ≤3 字节 hex

	// --- extranonce_subscribe ---
	// (no extra params)

	// --- authorize / submit ---
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	JobID      string `json:"job_id,omitempty"`
	MinerNonce string `json:"miner_nonce,omitempty"` // 8 − len(extranonce) bytes hex
	// Result is the response payload: true|false|false+error-triple (via
	// nested fields); explicit Error holds the [code,msg,null] tuple when
	// Result is false (ErrorCode/ErrorMsg mirror for plain JSON config).
	Result    json.RawMessage `json:"result,omitempty"`
	ErrorCode int             `json:"error_code,omitempty"`
	ErrorMsg  string          `json:"error_msg,omitempty"`

	// --- set_difficulty ---
	// Difficulty is JSON number (十进制定点 e.g. 0.5, 5000012.0). When unset,
	// a notify event still flows (set_difficulty MUST be sent before the
	// first job per spec §III — but spec allows a default-difficulty 1.0
	// fallback for the miner side; planner validates the configured event
	// sequence, not a derived "default").
	Difficulty json.RawMessage `json:"difficulty,omitempty"`

	// --- notify ---
	SeedHash    string `json:"seed_hash,omitempty"`    // 32 字节 hex
	HeaderHash  string `json:"header_hash,omitempty"`  // 32 字节 hex
	CleanJobs   bool   `json:"clean_jobs,omitempty"`   // true ⇒ 清空作业队列

	// --- set_extranonce ---
	// NewExtranonce is the 1-element set_extranonce param (≤3 字节 hex);
	// bitcoin stratum's 2-element dialect [en1, size] is rejected.
	NewExtranonce string `json:"new_extranonce,omitempty"`
}
