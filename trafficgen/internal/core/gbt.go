package core

import "encoding/json"

// GBT (BIP 22/23 getblocktemplate/submitblock JSON-RPC over HTTP) 配置类型。
// 字段名对齐 test/protocol_pcap/cases/gbt.json 与
// docs/protocol-designs/77-gbt-{design,testcase}.md v2.0.0 的配置 typedef：
// sessions[] 事件编排会话（每事件 = 一笔事务一侧），concurrent=true 时多会话
// 交错回放（tcp 层须同时设 concurrent: true）。

// GBTConfig is the flow's gbt terminal-layer configuration.
type GBTConfig struct {
	// Concurrent enables interleaved multi-session replay: session events are
	// emitted round-robin (per event index) instead of session-by-session.
	// The tcp layer must also set {"concurrent": true} to keep independent
	// connections per SrcPort (no teardown between sessions; all connections
	// are torn down at stream end).
	Concurrent bool          `json:"concurrent,omitempty"`
	Sessions   []GBTSession  `json:"sessions,omitempty"`
	WireFault  *GBTWireFault `json:"wire_fault,omitempty"`
}

// GBTSession is one HTTP session (one TCP connection): auth, HTTP defaults,
// and the ordered event list. Session identity across connections is the
// SrcPort override (0 = the flow's default src port).
type GBTSession struct {
	Role string `json:"role,omitempty"` // miner (default; informational)
	// Auth carries the Basic credentials; nil = no Authorization header
	// (the 401 scenario).
	Auth *GBTAuth `json:"auth,omitempty"`
	// SrcPort overrides the client source port for this session's events
	// (multi-session identity; 0 = flow default).
	SrcPort uint16 `json:"src_port,omitempty"`
	// URI is the session-default request path ("/" unless overridden).
	URI string `json:"uri,omitempty"`
	// URIFrom derives the session request URI ("template.longpolluri" =
	// the longpoll URI from the session's latest template; BIP 22).
	URIFrom string `json:"uri_from,omitempty"`
	// HTTPVersion pins the request-line version ("HTTP/1.1" default;
	// "HTTP/1.0" omits the Host header per the v2.0.0 fixture).
	HTTPVersion string `json:"http_version,omitempty"`
	// JSONRPCVersion selects the wire form: "" / "1.0" = bitcoin-cli form
	// (request carries "jsonrpc":"1.0", response has no jsonrpc member);
	// "2.0" = both carry "jsonrpc":"2.0" (design §3.2 观测形态).
	JSONRPCVersion string     `json:"jsonrpc_version,omitempty"`
	Events         []GBTEvent `json:"events,omitempty"`
}

// GBTAuth is the Basic auth pair (base64(user:pass) → Authorization header).
type GBTAuth struct {
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
}

// GBTEvent is one side of one HTTP transaction (request or response), or —
// with JoinNext — the head of a coalesced run whose bytes concatenate with
// the following event(s) into one TCP segment (多消息粘单段正例).
type GBTEvent struct {
	// Kind is "request" or "response".
	Kind string `json:"kind,omitempty"`
	// JoinNext concatenates this message's bytes with the next event's bytes
	// into a single MessageEvent (same TCP segment).
	JoinNext bool `json:"join_next,omitempty"`
	// ID is the JSON-RPC id: number or string, embedded verbatim
	// (json.RawMessage preserves the case JSON's exact literal — byte layout
	// is pinned by the v2.0.0 fixture). Responses may omit it — the
	// session's latest request id is echoed (auto-derivation ②; the
	// id_mismatch wire fault is the only sanctioned deviation).
	ID json.RawMessage `json:"id,omitempty"`
	// Method is the request method name ("getblocktemplate" | "submitblock").
	Method string `json:"method,omitempty"`
	// Params is the request params JSON, embedded verbatim. String elements
	// "workid_from" / "longpollid_from" are replaced by the corresponding
	// field of the session's latest template (BIP 22 workid 关联/longpoll).
	Params json.RawMessage `json:"params,omitempty"`
	// URI overrides the request path for this event (e.g. "/longpoll").
	URI string `json:"uri,omitempty"`
	// Status is the response status code (200 default; 401 = no body;
	// 500 = error object).
	Status int `json:"status,omitempty"`
	// ResultKind selects the response result payload: template |
	// accepted_null | reject_reason | proposal_true | proposal_reject |
	// error_object.
	ResultKind string `json:"result_kind,omitempty"`
	// Template names the response template variant: full (18-key fixture,
	// height=1000) | refresh (derived from the session's latest template:
	// height+1, curtime+600, longpollid=lp-<h+1>-1) | plain (14 required
	// keys) | tx1 (plain + 1 transaction) | big (plain + 3×740-hex data).
	Template string `json:"template,omitempty"`
	// Reason is the reject_reason string (result_kind=reject_reason /
	// proposal_reject).
	Reason string `json:"reason,omitempty"`
	// ErrorCode / ErrorMessage build the error object (result_kind=
	// error_object).
	ErrorCode    int    `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
	// Close marks this response as the session's last (Connection: close).
	Close bool `json:"close,omitempty"`
}

// GBTWireFault injects one negative-path fault (28 kinds, v2.0.0 design §7).
type GBTWireFault struct {
	Kind  string `json:"kind,omitempty"`  // bad_json|body_truncated|…|error_propagation
	Value string `json:"value,omitempty"` // auxiliary literal (e.g. injected method name)
}
