package core

// ONVIF (Open Network Video Interface Forum) 配置类型。字段名对齐
// docs/protocol-designs/67-onvif-{design,testcase}.md v2.1.1 的配置
// typedef（design §6）：sessions[] 事件编排会话（每事件 = 一笔 ONVIF 事务：
// SOAP 1.2 POST 请求帧 + 自动应答响应帧），concurrent=true 时多会话交错
// 回放。链形 [ip→tcp→http→onvif]，http 层透传转发（onvif 事件字节已是
// 完整 HTTP 帧；与 gbt/getwork/cwmp/doh 同款透传家族）。
//
// 主 profile onvif_soap12_http：明文 HTTP/1.1 端口 80，SOAP 1.2 over
// HTTP（application/soap+xml; charset=utf-8）；WS-Discovery（UDP 3702）
// 与 HTTPS/TLS 为未注册边界（设计 §1）。

// ONVIFConfig is the flow's onvif terminal-layer configuration.
type ONVIFConfig struct {
	// Profile selects the protocol profile: "" / "onvif_soap12_http"
	// (default, plaintext HTTP/1.1 port 80). Boundary-only profiles are
	// rejected.
	Profile string `json:"profile,omitempty"`
	// SoapVersion pins the SOAP version: "" / "1.2" (default). SOAP 1.1 is
	// a wire-format error (design §1 钉死 1.2).
	SoapVersion string `json:"soap_version,omitempty"`
	// Charset overrides the Content-Type charset parameter (default utf-8).
	Charset string `json:"charset,omitempty"`
	// ContentType overrides the request Content-Type (default
	// "application/soap+xml; charset=utf-8"). Legal client variants
	// (e.g. text/xml for the 415 fixture) render verbatim.
	ContentType string `json:"content_type,omitempty"`
	// Concurrent enables interleaved multi-session replay: session events
	// are emitted round-robin (per event index) instead of session-by-session.
	Concurrent bool          `json:"concurrent,omitempty"`
	Sessions   []ONVIFSession `json:"sessions,omitempty"`
	// WireFault injects one negative-path fault (38 kinds, design §7 — 与
	// §7 表/用例 §5 表三方同序): soap_envelope_ns|soap_truncated|
	// soap_body_missing|soap_header_order|content_type|charset_missing|
	// charset_wrong|action_mismatch|action_suffix|addressing_action|
	// addressing_message_id|addressing_relates|addressing_ns|
	// operation_unknown|operation_ns|service_unknown|parameter_stream_setup|
	// parameter_profile_token|parameter_timeout|parameter_message_limit|
	// parameter_duration|auth_missing|token_nonce|token_created|
	// carrier_layer|carrier_port|carrier_wsdiscovery|fault_code|fault_reason|
	// fault_value|fault_subcode|length_truncation|length_content_length|
	// subscription_source|subscription_cross_session|token_range|
	// message_limit_range|wsnt_ns.
	WireFault string `json:"wire_fault,omitempty"`
}

// ONVIFSession is one HTTP session (one TCP connection): endpoint overrides
// and the ordered transaction list. Session identity across connections is
// the SrcPort override (0 = the flow's default src port).
type ONVIFSession struct {
	// SrcPort overrides the client source port for this session's events
	// (multi-session identity; 0 = flow default).
	SrcPort uint16 `json:"src_port,omitempty"`
	// DstPort overrides the session's destination port (0 = flow default).
	DstPort uint16 `json:"dst_port,omitempty"`
	// Events is the session's ordered transaction list; each element is one
	// ONVIF transaction (SOAP request frame + auto-answered response frame).
	Events []ONVIFEvent `json:"events,omitempty"`
}

// ONVIFEvent is one ONVIF transaction: the SOAP 1.2 POST request frame plus
// the auto-answered response frame (RelatesTo echo, derived response Action,
// response body per Response).
type ONVIFEvent struct {
	// Kind is "request" (the only legal kind).
	Kind string `json:"kind,omitempty"`
	// Service selects the operation namespace: device|media|ptz|events
	// (design §3.5 四服务).
	Service string `json:"service,omitempty"`
	// Operation is the WSDL operation name (GetSystemDateAndTime, ...).
	Operation string `json:"operation,omitempty"`
	// Method overrides the HTTP method (default POST; the 405 fixture
	// declares PUT — Table 5 legal error event).
	Method string `json:"method,omitempty"`
	// URI is the service endpoint path (default per service:
	// /onvif/{device,media,ptz,event}_service).
	URI string `json:"uri,omitempty"`
	// MessageID is the wsa:MessageID: "auto" (default; engine assigns a
	// deterministic urn:uuid per session/event) or an explicit urn:uuid
	// string (fixture pinning).
	MessageID string `json:"message_id,omitempty"`
	// Action overrides the request wsa:Action (default derived from the
	// WSDL soapAction). Validator rejects mismatch/suffix violations
	// (wire faults action_mismatch/action_suffix).
	Action string `json:"action,omitempty"`
	// To is the request wsa:To (PullMessages carries the subscription
	// endpoint): a literal URL or "same_as_response:<event>.subscription_reference"
	// referencing a same-session CreatePullPointSubscription response.
	To string `json:"to,omitempty"`
	// Auth declares the WS-Security UsernameToken (username/password;
	// digest computed per WSS UsernameToken Profile §4.2, nonce derived
	// deterministically from the MessageID unless pinned).
	Auth *ONVIFAuth `json:"auth,omitempty"`
	// Parameters carries the operation's request parameters (per-operation
	// shape; string values may be "same_as_response:<event>.<path>"
	// transaction-interaction references).
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	// Response declares the auto-answer content; nil = 200 with the
	// operation's empty/minimal response shape.
	Response *ONVIFResponse `json:"response,omitempty"`
	// HTTP carries per-event HTTP header overrides (same semantics as the
	// doh family: same-name replace in place, "" removes, new names append
	// sorted).
	HTTP *ONVIFHTTPOverride `json:"http,omitempty"`
	// WireFault is the per-event wire fault injection (38 kinds, design §7).
	WireFault string `json:"wire_fault,omitempty"`
}

// ONVIFAuth is the UsernameToken declaration (Core Spec §5.9.5: nonce and
// created are both mandatory — the engine always renders both; the
// missing-nonce/missing-created forms are wire_fault injections).
type ONVIFAuth struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// Digest selects PasswordDigest (default true; the Type attribute
	// references the WSS digest profile).
	Digest *bool `json:"digest,omitempty"`
	// Nonce pins the base64 nonce (default: deterministic per MessageID).
	Nonce string `json:"nonce,omitempty"`
	// Created pins the timestamp (default 2026-09-01T00:00:00Z).
	Created string `json:"created,omitempty"`
}

// ONVIFResponse declares the auto-answer: HTTP status (0 = 200) + the
// operation-specific response body fields. Non-2xx statuses render the
// error shape: 401 adds WWW-Authenticate; 400/405/415 render empty bodies
// (Table 5 fixture decision); SOAP Faults render via Fault.
type ONVIFResponse struct {
	HTTPStatus int `json:"http_status,omitempty"`
	// Fault renders a SOAP 1.2 Fault envelope (HTTP 400/500 per
	// Core Spec §5.9.1/§5.8.2.1).
	Fault *ONVIFFault `json:"fault,omitempty"`
	// WWWAuthenticate pins the 401 challenge value (fixture).
	WWWAuthenticate string `json:"www_authenticate,omitempty"`
	// Authorization pins the Authorization header value (digest retry
	// fixture; overriding the default none).
	Authorization string `json:"authorization,omitempty"`

	// ---- operation-specific response payloads (fixture-pinned) ----
	// GetSystemDateAndTime
	SystemDateAndTime *ONVIFSystemDateAndTime `json:"system_date_and_time,omitempty"`
	// GetCapabilities
	Capabilities *ONVIFCapabilities `json:"capabilities,omitempty"`
	// GetDeviceInformation
	Manufacturer   string `json:"manufacturer,omitempty"`
	Model          string `json:"model,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
	SerialNumber   string `json:"serial_number,omitempty"`
	HardwareID     string `json:"hardware_id,omitempty"`
	// GetNetworkInterfaces / GetProfiles (plural instances)
	NetworkInterfaces []ONVIFNetworkInterface `json:"network_interfaces,omitempty"`
	Profiles          []ONVIFProfile          `json:"profiles,omitempty"`
	// GetStreamUri / GetSnapshotUri
	MediaURI string `json:"media_uri,omitempty"`
	// CreatePullPointSubscription
	SubscriptionReference string `json:"subscription_reference,omitempty"`
	CurrentTime           string `json:"current_time,omitempty"`
	TerminationTime       string `json:"termination_time,omitempty"`
	// PullMessages
	NotificationMessages []ONVIFNotification `json:"notification_messages,omitempty"`
}

// ONVIFSystemDateAndTime renders the tt:SystemDateTime payload (RN-2: payload
// elements are tt: while the wrapper is tds:).
type ONVIFSystemDateAndTime struct {
	DateTimeType    string `json:"date_time_type,omitempty"` // NTP | Manual
	DaylightSavings *bool  `json:"daylight_savings,omitempty"`
	TimeZone        string `json:"time_zone,omitempty"`      // e.g. CST-8
	UTCDateTime     string `json:"utc_date_time,omitempty"`  // 2026-09-01T00:00:00Z
	LocalDateTime   string `json:"local_date_time,omitempty"`
}

// ONVIFCapabilities is one service capability entry (XAddr fixture).
type ONVIFCapabilities struct {
	Entries []ONVIFCapabilityEntry `json:"entries,omitempty"`
}

// ONVIFCapabilityEntry is one <tds:{Service}><tt:XAddr>…</tt:XAddr> element.
type ONVIFCapabilityEntry struct {
	Service string `json:"service,omitempty"` // Media|Events|PTZ|Device|Imaging|Analytics
	XAddr   string `json:"x_addr,omitempty"`
}

// ONVIFNetworkInterface is one <tds:NetworkInterfaces token="…"> instance
// (C-2: tds-local element, token attribute, tt:Enabled child).
type ONVIFNetworkInterface struct {
	Token   string `json:"token,omitempty"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// ONVIFProfile is one <trt:Profiles token="…"> instance (C-1: plural
// response element, tt:Profile shape).
type ONVIFProfile struct {
	Token string          `json:"token,omitempty"`
	Name  string          `json:"name,omitempty"`
	Video *ONVIFVideoEncoder `json:"video_encoder,omitempty"`
}

// ONVIFVideoEncoder is the VideoEncoderConfiguration fixture shape.
type ONVIFVideoEncoder struct {
	Encoding  string `json:"encoding,omitempty"` // H264
	Width     int    `json:"width,omitempty"`
	Height    int    `json:"height,omitempty"`
	FrameRate int    `json:"fps,omitempty"`
}

// ONVIFNotification is one wsnt:NotificationMessage (Topic + SimpleItem).
type ONVIFNotification struct {
	Topic      string `json:"topic,omitempty"`
	Dialect    string `json:"dialect,omitempty"` // default ConcreteSet
	SimpleItemName  string `json:"name,omitempty"`
	SimpleItemValue string `json:"value,omitempty"`
}

// ONVIFFault is the SOAP 1.2 Fault declaration (Core Spec §5.8.2.1/Table 4).
type ONVIFFault struct {
	// Value is the s:Code/s:Value (env:Sender / env:Receiver ...).
	Value string `json:"value,omitempty"`
	// Subcode is the s:Subcode/s:Value (ter:NotAuthorized ...).
	Subcode string `json:"subcode,omitempty"`
	// NestedSubcode renders a nested s:Subcode (ter:NoSuchService).
	NestedSubcode string `json:"nested_subcode,omitempty"`
	// Reason is the s:Reason/s:Text content.
	Reason string `json:"reason,omitempty"`
	// Node/Role/Detail render the optional full form.
	Node   string `json:"node,omitempty"`
	Role   string `json:"role,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// ONVIFHTTPOverride carries per-event HTTP header overrides ("" removes).
type ONVIFHTTPOverride struct {
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
}
