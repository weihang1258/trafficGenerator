package core

import "encoding/json"

// GetWork (Bitcoin legacy getwork JSON-RPC over HTTP) 配置类型。字段名对齐
// test/protocol_pcap/cases/getwork.json 与 docs/protocol-designs/76-getwork-
// {design,testcase}.md v2.0.0 的配置 typedef：sessions[] 事件编排会话（每
// 事件 = 一笔事务一侧），concurrent=true 时多会话交错回放（tcp 层须同时设
// concurrent: true）。提交方法名就是 getwork（单参 data，无 submit 方法）。

// GetWorkConfig is the flow's getwork terminal-layer configuration.
type GetWorkConfig struct {
	// Concurrent enables interleaved multi-session replay: session events are
	// emitted round-robin (per event index) instead of session-by-session.
	// The tcp layer must also set {"concurrent": true} to keep independent
	// connections per SrcPort (all connections torn down at stream end).
	Concurrent bool              `json:"concurrent,omitempty"`
	Sessions   []GetWorkSession  `json:"sessions,omitempty"`
	WireFault  *GetWorkWireFault `json:"wire_fault,omitempty"`
}

// GetWorkSession is one HTTP session (one TCP connection): auth, HTTP
// defaults, and the ordered event list. Session identity across connections
// is the SrcPort override (0 = the flow's default src port).
type GetWorkSession struct {
	Role string `json:"role,omitempty"` // miner (default; informational)
	// Auth carries the Basic credentials; nil = no Authorization header
	// (the 401 scenario).
	Auth *GetWorkAuth `json:"auth,omitempty"`
	// SrcPort overrides the client source port for this session's events
	// (multi-session identity; 0 = flow default).
	SrcPort uint16 `json:"src_port,omitempty"`
	// URI is the session-default request path ("/" unless overridden).
	URI string `json:"uri,omitempty"`
	// HTTPVersion pins the request-line version ("HTTP/1.1" default;
	// "HTTP/1.0" omits the Host header and forces Connection: close —
	// design §3.1 观测形态).
	HTTPVersion string `json:"http_version,omitempty"`
	// JSONRPCVersion selects the wire form: "" / "1.0" = bitcoind legacy
	// form (request members id,method,params with NO jsonrpc member;
	// response result,error,id); "2.0" = both carry the leading
	// "jsonrpc":"2.0" member (design §3.2 观测形态, one positive case).
	JSONRPCVersion string         `json:"jsonrpc_version,omitempty"`
	Events         []GetWorkEvent `json:"events,omitempty"`
}

// GetWorkAuth is the Basic auth pair (base64(user:pass) → Authorization
// header; fixture dXNlcjpwYXNz).
type GetWorkAuth struct {
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
}

// GetWorkEvent is one side of one HTTP transaction (request or response),
// or — with JoinNext — the head of a coalesced run whose bytes concatenate
// with the following event(s) into one TCP segment (多消息粘单段正例).
type GetWorkEvent struct {
	// Kind is "request" or "response".
	Kind string `json:"kind,omitempty"`
	// JoinNext concatenates this message's bytes with the next event's bytes
	// into a single MessageEvent (same TCP segment).
	JoinNext bool `json:"join_next,omitempty"`
	// ID is the JSON-RPC id: number or string, embedded verbatim
	// (json.RawMessage preserves the case JSON's exact literal). Responses
	// may omit it — the session's latest request id is echoed (design §6
	// 自动派生; the id_mismatch wire fault is the only sanctioned
	// deviation).
	ID json.RawMessage `json:"id,omitempty"`
	// Method is the request method name ("getwork" only — the submit IS a
	// getwork call with a single data param).
	Method string `json:"method,omitempty"`
	// Params is the request params JSON, embedded verbatim: [] (apply) or
	// ["<data 256 hex>"] (submit).
	Params json.RawMessage `json:"params,omitempty"`
	// ParamsFrom derives the submit params from the session's latest work:
	// "work.data_nonce_modified" = ["<latest data with the 4B nonce field
	// (hex chars 153-160) replaced by the fixture submit nonce>"].
	ParamsFrom string `json:"params_from,omitempty"`
	// Status is the response status code (200 default; 401 = no body;
	// 500 = error object).
	Status int `json:"status,omitempty"`
	// ResultKind selects the response result payload: work | true | false |
	// object | error_object.
	ResultKind string `json:"result_kind,omitempty"`
	// Work names the work-object variant for result_kind=work:
	// "fixture_work" (default) | "fixture_work2" (data hex chars 9-12
	// variant — 每请求新 work distinct 正例).
	Work string `json:"work,omitempty"`
	// Status / ShareID build the object result {status,share_id} (third
	// accepted form; fixture accepted / sh-0001).
	ShareID string `json:"share_id,omitempty"`
	// ErrorCode / ErrorMessage build the error object (result_kind=
	// error_object; fixture -32601 / "method not found").
	ErrorCode    int    `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
	// Close marks this response as the session's last (Connection: close).
	Close bool `json:"close,omitempty"`
}

// GetWorkWireFault injects one negative-path fault (17 kinds, v2.0.0 design
// §7 — 一行一注入, 与设计 §7 表/用例 §5 表三方同序).
type GetWorkWireFault struct {
	Kind  string `json:"kind,omitempty"`  // bad_json|body_truncated|…|error_propagation
	Value string `json:"value,omitempty"` // auxiliary literal (e.g. injected method name)
}
