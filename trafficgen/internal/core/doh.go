package core

// DOH (DNS over HTTPS / RFC 8484) 配置类型。字段名对齐
// docs/protocol-designs/66-doh-{design,testcase}.md v2.2.1/v3.0.2 的配置
// typedef（design §6）：sessions[] 事件编排会话（每事件 = 一笔 DNS 查询
// 事务：请求帧 + 自动应答响应帧），concurrent=true 时多会话交错回放
// （tcp 层须同时设 {"concurrent": true}）。链形 [ip→tcp→http→doh]，
// http 层透传转发（doh 事件字节已是完整 HTTP 帧）。
//
// 主 profile doh_http1_plain：HTTP/1.1 明文调试端口 80（RFC 8484 §5 的
// https scheme MUST 属测试用途的规范外偏差，设计 §1 如实声明）；TLS/
// HTTP2/3 为未注册边界。

// DOHConfig is the flow's doh terminal-layer configuration.
type DOHConfig struct {
	// Profile selects the protocol profile: "" / "doh_http1_plain" (default,
	// HTTP/1.1 plaintext port 80). Boundary-only profiles (doh_https_boundary
	// etc.) are rejected — no TLS key log, no inner assertions.
	Profile string `json:"profile,omitempty"`
	// Method is the session-default HTTP mapping: "POST" (default) or "GET".
	Method string `json:"method,omitempty"`
	// URI is the session-default request path ("/dns-query" unless overridden).
	URI string `json:"uri,omitempty"`
	// Concurrent enables interleaved multi-session replay: session events are
	// emitted round-robin (per event index) instead of session-by-session.
	// The tcp layer must also set {"concurrent": true}.
	Concurrent bool         `json:"concurrent,omitempty"`
	Sessions   []DOHSession `json:"sessions,omitempty"`
	// WireFault injects one negative-path fault (26 kinds, design §7 — 与
	// §7 表/用例 §5 表三方同序): query_missing|base64|padding|b64_short|
	// dns_header_short|qdcount|qname|question_truncated|content_type|method|
	// content_length|layer_chain|port_conflict|response_id|response_question|
	// wire_over_max|opcode_nonzero|get_content_type|response_qr|z_nonzero|
	// rdlength_mismatch|ancount_mismatch|qdcount_multi|dns_id_range|ttl_range|
	// qtype_token.
	WireFault string `json:"wire_fault,omitempty"`
}

// DOHSession is one HTTP session (one TCP connection): endpoint overrides and
// the ordered query-transaction list. Session identity across connections is
// the SrcPort override (0 = the flow's default src port).
type DOHSession struct {
	// SrcPort overrides the client source port for this session's events
	// (multi-session identity; 0 = flow default).
	SrcPort uint16 `json:"src_port,omitempty"`
	// DstPort overrides the session's destination port (0 = flow default).
	DstPort uint16 `json:"dst_port,omitempty"`
	// Method overrides the config-level HTTP mapping for this session.
	Method string `json:"method,omitempty"`
	// URI overrides the config-level request path for this session.
	URI string `json:"uri,omitempty"`
	// Events is the session's ordered transaction list; each element is one
	// DNS query transaction (request frame + auto-answered response frame).
	Events []DOHEvent `json:"events,omitempty"`
}

// DOHEvent is one DNS query transaction: the request frame (POST body or GET
// base64url query parameter) plus the auto-answered response frame (ID echo,
// QR=1, answers per Response).
type DOHEvent struct {
	// Kind is "query" (the only legal kind).
	Kind string `json:"kind,omitempty"`
	// DNSID is the 16-bit DNS Transaction ID (RFC 1035 §4.1.1); the response
	// echoes it. 0 is a legal boundary value (RFC 8484 §4.1 SHOULD; the
	// deviation is declared in design §3.2). Out-of-range values (>65535) are
	// rejected (wire fault dns_id_range).
	DNSID int `json:"dns_id,omitempty"`
	// Name is the QNAME (dotted display form; "" = root).
	Name string `json:"name,omitempty"`
	// QType is the query type: token (A/AAAA/HTTPS/MX/TXT/CNAME/SOA/...) or
	// numeric string (any 16-bit value passes through, RFC 1035 §3.2.2);
	// non-numeric unknown tokens are rejected (wire fault qtype_token).
	QType string `json:"qtype,omitempty"`
	// QClass is the query class: token (IN/CHAOS/...) or numeric string;
	// defaults to IN (1).
	QClass string `json:"qclass,omitempty"`
	// Method overrides the HTTP mapping for this event ("POST"/"GET").
	Method string `json:"method,omitempty"`
	// URI overrides the request path for this event. For GET the query
	// parameter is always appended: <uri>?dns=<base64url>.
	URI string `json:"uri,omitempty"`
	// ExtraQuery appends "&<extra_query>" to the GET request URI (error-form
	// fixture doh_http_error_400_extra_param; empty = none).
	ExtraQuery string `json:"extra_query,omitempty"`
	// RD overrides the request's recursion-desired flag (default true; the
	// doh_dns_rd_zero fixture sets false).
	RD *bool `json:"rd,omitempty"`
	// Response declares the auto-answer content; nil = 200 NOERROR with no
	// answers (question echo only).
	Response *DOHResponse `json:"response,omitempty"`
	// HTTP carries per-event header overrides (design §6): same-named
	// defaults are replaced in place (case-insensitive); "" removes the
	// header; unknown names are appended (sorted for determinism).
	HTTP *DOHHTTPOverride `json:"http,omitempty"`
}

// DOHResponse is the auto-answer declaration: HTTP status (0 = 200) + DNS
// response content. Non-2xx statuses produce the error-response shape
// (status line + Content-Length: 0, NO DNS wire — RFC 8484 §4.2.1 /
// design §5 determinism rule).
type DOHResponse struct {
	// Status is the HTTP response status code (0 = 200). 400/404/415 are the
	// sanctioned error forms; non-2xx carries an empty body.
	Status int `json:"status,omitempty"`
	// RCode is the DNS response code: token (NOERROR/FORMERR/SERVFAIL/
	// NXDOMAIN/NOTIMP/REFUSED) or numeric string ("0".."15").
	RCode string `json:"rcode,omitempty"`
	// Answers is the response Answer section (RFC 1035 §4.1.3). Empty with a
	// non-zero RCode = the NXDOMAIN/SERVFAIL shape (ANCOUNT=0).
	Answers []DOHAnswer `json:"answers,omitempty"`
	// Authority carries the Authority section (negative caching, RFC 2308 §5:
	// one SOA whose MINIMUM bounds max-age).
	Authority []DOHAnswer `json:"authority,omitempty"`
	// AA sets the authoritative-answer flag (default false).
	AA bool `json:"aa,omitempty"`
	// TC sets the truncated flag (default false).
	TC bool `json:"tc,omitempty"`
	// RA sets the recursion-available flag (nil = true; doh_dns_ra_zero
	// fixture sets false).
	RA *bool `json:"ra,omitempty"`
}

// DOHAnswer is one resource record. Type selects the RDATA mapping (mirrors
// core.DNSRR conventions):
//
//	A(1)/AAAA(28)        -> RData (IP literal)
//	CNAME(5)/NS(2)/PTR   -> RData (domain name)
//	MX(15)               -> MxPref + RData (exchange name)
//	TXT(16)              -> RData single string, or TXTStrings multi-string
//	SOA(6)               -> MName/RName + Serial/Refresh/Retry/Expire/Minimum
//	HTTPS(65)/SVCB(64)   -> Priority + Target + Params
type DOHAnswer struct {
	Name  string `json:"name,omitempty"`
	Type  string `json:"type,omitempty"`
	Class string `json:"class,omitempty"` // token/numeric; default IN (1)
	TTL   int64  `json:"ttl,omitempty"`   // 32-bit unsigned; 0 legal (max-age=0)
	// RData is the type-dependent payload (see the mapping above).
	RData string `json:"rdata,omitempty"`
	// TXTStrings overrides RData for TXT with multiple character-strings
	// (each segment length-prefixed on the wire, RFC 1035 §3.3.14).
	TXTStrings []string `json:"txt_strings,omitempty"`
	// MxPref is the MX preference (2B big-endian).
	MxPref uint16 `json:"mx_pref,omitempty"`
	// SOA fields (RFC 1035 §3.3.13).
	MName   string `json:"mname,omitempty"`
	RName   string `json:"rname,omitempty"`
	Serial  uint32 `json:"serial,omitempty"`
	Refresh uint32 `json:"refresh,omitempty"`
	Retry   uint32 `json:"retry,omitempty"`
	Expire  uint32 `json:"expire,omitempty"`
	Minimum uint32 `json:"minimum,omitempty"`
	// Priority is the SvcPriority (2B big-endian); 0 = AliasForm.
	Priority uint16 `json:"priority,omitempty"`
	// Target is the TargetName (label-encoded; "." = root 0x00).
	Target string `json:"target,omitempty"`
	// Params are the SvcParams: key + hex-encoded value bytes (fixture-pinned
	// wire form, e.g. alpn "h2" = value_hex "026832").
	Params []DOHSvcParam `json:"params,omitempty"`
}

// DOHSvcParam is one SvcParam (RFC 9460 §2.2): 2B key + 2B length + value.
type DOHSvcParam struct {
	Key      int    `json:"key,omitempty"`
	ValueHex string `json:"value_hex,omitempty"`
}

// DOHHTTPOverride carries per-event HTTP header overrides. A value of ""
// removes the corresponding default header (e.g. Accept: "" for the
// accept-absent fixture).
type DOHHTTPOverride struct {
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
}
