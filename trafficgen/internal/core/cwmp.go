package core

// CWMP (TR-069 CPE WAN Management Protocol) 配置类型。字段名对齐
// docs/protocol-designs/64-cwmp-{design,testcase}.md v2.2.2/v3.1.1 的配置
// typedef（design §6）：sessions[] 事件编排会话（每事务 = 一笔事务一侧，
// kind 定方向），flows[] 流关联副连接（download/upload 驱动的文件传输第二
// 连接，driven_by 显式声明主从），concurrent=true 时多会话交错回放（tcp 层
// 须同时设 concurrent: true）。链形 [ip→tcp→http→cwmp]，http 层透传转发
// （cwmp 事件字节已是完整 HTTP 帧）。

// CWMPConfig is the flow's cwmp terminal-layer configuration.
type CWMPConfig struct {
	// Profile selects the protocol profile: "" / "cwmp_http_v1" (default,
	// SOAP 1.1 over plaintext HTTP/1.1) | "cwmp_ipv6_v1" (same content over
	// IPv6) | "cwmp_https_boundary" (TLS boundary only — rejected on the
	// plaintext chain, design §1).
	Profile string `json:"profile,omitempty"`
	// Namespace is the CWMP data-model namespace: default
	// "urn:dslforum-org:cwmp-1-0"; cwmp-1-1 / cwmp-1-2 allowed (§3.7.4
	// negotiation). A SOAP 1.2 envelope namespace here is a wire-format
	// error (negative family "namespace").
	Namespace string `json:"namespace,omitempty"`
	// Concurrent enables interleaved multi-session replay: session
	// transactions are emitted round-robin (per transaction index) instead
	// of session-by-session. The tcp layer must also set {"concurrent":true}
	// (forced automatically when Flows are present).
	Concurrent bool         `json:"concurrent,omitempty"`
	Sessions   []CWMPSession `json:"sessions,omitempty"`
	// Flows are the flow-correlation side connections (download/upload
	// driven file transfers to a separate file server, design §5).
	Flows []CWMPFlow `json:"flows,omitempty"`
	// Auth carries the session-level digest auth material (RFC 7616): when
	// set, the generator computes the Authorization header for retries and
	// the validator recomputes raw Authorization headers for verification.
	Auth *CWMPAuth `json:"auth,omitempty"`
}

// CWMPSession is one HTTP session (one TCP connection): role, endpoints, and
// the ordered transaction list. Session identity across connections is the
// SrcPort override (0 = the flow's default src port); DstIP/DstPort override
// the endpoint (acs_cr reverse connections target the CPE).
type CWMPSession struct {
	// Role is "cpe" (default — the CPE is the HTTP client) | "acs_cr"
	// (ACS-initiated Connection Request: the ACS is the HTTP client).
	Role string `json:"role,omitempty"`
	// SrcPort overrides the client source port for this session's events
	// (multi-session identity; 0 = flow default).
	SrcPort uint16 `json:"src_port,omitempty"`
	// DstIP overrides the session's destination IP (per-session endpoint
	// override — CR sessions target the CPE). Non-empty events carry an
	// absolute L3 destination override.
	DstIP string `json:"dst_ip,omitempty"`
	// DstPort overrides the session's destination port (0 = flow default).
	DstPort uint16 `json:"dst_port,omitempty"`
	// URI is the session-default request path ("/" unless overridden).
	URI string `json:"uri,omitempty"`
	// DeviceID is the session-default DeviceIdStruct (inform transactions
	// without their own device_id fall back to it, then to the fixture
	// defaults).
	DeviceID *CWMPDeviceID `json:"device_id,omitempty"`
	// Transactions is the session's ordered event sequence; each element is
	// ONE side (one HTTP frame) of one transaction and kind fixes direction.
	Transactions []CWMPTransaction `json:"transactions,omitempty"`
}

// CWMPAuth is the HTTP digest auth material (RFC 7616 §3.5). Username follows
// the recommended "<OUI>-<ProductClass>-<SerialNumber>" percent-encoded form
// (TR-069 §3.4.4). Challenge parameters (realm/nonce/opaque/qop) may be given
// here or parsed from the auth challenge's WWW-Authenticate string.
type CWMPAuth struct {
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	Realm     string `json:"realm,omitempty"`
	Nonce     string `json:"nonce,omitempty"`
	CNonce    string `json:"cnonce,omitempty"`
	Opaque    string `json:"opaque,omitempty"`
	QOP       string `json:"qop,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`
}

// CWMPDeviceID is the DeviceIdStruct (A.3.3.1 Table 39): Manufacturer
// string(64), OUI six uppercase hex digits, ProductClass string(64),
// SerialNumber string(64).
type CWMPDeviceID struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	OUI          string `json:"oui,omitempty"`
	ProductClass string `json:"product_class,omitempty"`
	SerialNumber string `json:"serial,omitempty"`
}

// CWMPFault is the SOAP Fault body config (design §3.4): Code is the
// cwmp:Fault/FaultCode numeric value; FaultCode carries an explicit
// soap:faultcode value ("Client"/"Server") — empty derives from the code
// domain; FaultString is the inner cwmp:Fault/FaultString (the OUTER
// faultstring is the fixed "CWMP fault" per §3.4); SPVFaults are the
// SetParameterValuesFault per-parameter entries (SetParameterValues error
// responses only).
type CWMPFault struct {
	FaultCode string        `json:"fault_code,omitempty"`
	Code      int           `json:"code,omitempty"`
	FaultString string      `json:"fault_string,omitempty"`
	SPVFaults []CWMPSPVFault `json:"spv_faults,omitempty"`
}

// CWMPSPVFault is one SetParameterValuesFault entry (ParameterName/FaultCode/
// FaultString).
type CWMPSPVFault struct {
	ParameterName string `json:"parameter_name,omitempty"`
	FaultCode     int    `json:"fault_code,omitempty"`
	FaultString   string `json:"fault_string,omitempty"`
}

// CWMPSOAPEvent is one EventStruct entry of the Inform Event array
// (EventCode + CommandKey).
type CWMPSOAPEvent struct {
	Code       string `json:"code,omitempty"`
	CommandKey string `json:"command_key,omitempty"`
}

// CWMPParameter is one ParameterValueStruct entry (Name + Value; Value carries
// xsi:type="xsd:string" per the anySimpleType rule).
type CWMPParameter struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

// CWMPTransaction is ONE side (one HTTP frame) of one CWMP transaction; kind
// fixes the direction. UP kinds (client POST): inform, acs_request, acs_response
// (a.k.a. cpe_response), empty_post, transfer_complete, autonomous_transfer_complete,
// request_download, kicked_response. DOWN kinds (server side): inform_response,
// the ACS request family (get_parameter_values/get_parameter_names/
// set_parameter_values/get_parameter_attributes/set_parameter_attributes/
// add_object/delete_object/factory_reset/get_rpc_methods/download/upload/
// schedule_download/schedule_upload/reboot/kicked — these ride a 200 response
// body), their *_response counterparts, transfer_complete_response,
// autonomous_transfer_complete_response, request_download_response, fault
// (direction-flexible: UP when responding to a pending ACS request, else DOWN),
// auth_challenge (401), empty_ok (200 empty), empty_response (204),
// connection_request (CR GET), connection_request_authorized.
type CWMPTransaction struct {
	// Kind is the transaction kind (see type doc).
	Kind string `json:"kind,omitempty"`
	// ID is the cwmp:ID header value; empty = auto-increment per session
	// starting "1" (request kinds) or echo of the pending request id
	// (response kinds).
	ID string `json:"id,omitempty"`
	// ForID overrides the response's echoed cwmp:ID (a mismatch vs the
	// pending request id is the correlation negative).
	ForID string `json:"for_id,omitempty"`
	// Method is the acs_request/acs_response method name (snake_case, e.g.
	// "get_parameter_values") or an explicit response method override (the
	// response_suffix_missing negative uses it). For acs_response the
	// derived wire method is Pascal(method)+"Response" unless overridden.
	Method string `json:"method,omitempty"`
	// HTTPStatus is the response HTTP status line override (e.g. 401/503/302).
	// 0 = kind default (200 for SOAP responses, 204 empty_response, ...).
	HTTPStatus int `json:"http_status,omitempty"`
	// Status is the SOAP <Status> element value (set_parameter_values_response
	// etc.: 0=applied, 1=pending reboot). Distinguished from HTTPStatus.
	Status int `json:"status,omitempty"`
	// Location is the redirect Location header (http_status 302/307).
	Location string `json:"location,omitempty"`
	// MaxEnvelopes is the InformResponse MaxEnvelopes value (nil = 1).
	MaxEnvelopes *int `json:"max_envelopes,omitempty"`

	// DeviceID overrides the inform DeviceIdStruct.
	DeviceID *CWMPDeviceID `json:"device_id,omitempty"`
	// Events is the Inform Event array (EventStruct entries).
	Events []CWMPSOAPEvent `json:"events,omitempty"`
	// ParameterList is the ParameterValueStruct array (inform /
	// set_parameter_values / get_parameter_values_response).
	ParameterList []CWMPParameter `json:"parameter_list,omitempty"`
	// ParameterNames is the string array (get_parameter_values /
	// get_parameter_attributes requests).
	ParameterNames []string `json:"parameter_names,omitempty"`
	// ParameterPath is the get_parameter_names path.
	ParameterPath string `json:"parameter_path,omitempty"`
	// NextLevel is the get_parameter_names NextLevel boolean (nil = 0).
	NextLevel *bool `json:"next_level,omitempty"`
	// ParameterKey is the set/add/delete parameter key.
	ParameterKey string `json:"parameter_key,omitempty"`
	// RetryCount is the Inform RetryCount (nil = 0; >0 marks the auth retry).
	RetryCount *uint `json:"retry_count,omitempty"`

	// CommandKey is the transfer/reboot command key (string(32)).
	CommandKey string `json:"command_key,omitempty"`
	// FileType is the download/upload file type enum ("1 Firmware Upgrade
	// Image" ... or vendor "X <vendor> <id>").
	FileType string `json:"file_type,omitempty"`
	// URL is the file transfer URL (userinfo forbidden).
	URL string `json:"url,omitempty"`
	// Username / Password are the file transfer credentials.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// FileSize is the file size (nil = 0 = unknown, legal).
	FileSize *uint64 `json:"file_size,omitempty"`
	// TargetFileName is the download target file name.
	TargetFileName string `json:"target_file_name,omitempty"`
	// DelaySeconds is the download delay (non-zero forbids same-session
	// execution).
	DelaySeconds *uint32 `json:"delay_seconds,omitempty"`
	// StartTime / CompleteTime are the dateTime fields (transfer/schedule
	// family and their responses).
	StartTime    string `json:"start_time,omitempty"`
	CompleteTime string `json:"complete_time,omitempty"`
	// SuccessURL / FailureURL are the ScheduleDownload URLs.
	SuccessURL string `json:"success_url,omitempty"`
	FailureURL string `json:"failure_url,omitempty"`
	// MaxRetries is the ScheduleDownload retry count (nil = 0).
	MaxRetries *int `json:"max_retries,omitempty"`

	// AnnounceURL / TransferURL / IsDownload / FileTypeArg are the
	// AutonomousTransferComplete / RequestDownload fields.
	AnnounceURL  string `json:"announce_url,omitempty"`
	TransferURL  string `json:"transfer_url,omitempty"`
	IsDownload   *bool  `json:"is_download,omitempty"`
	FileTypeArg  string `json:"file_type_arg,omitempty"`
	KickURL      string `json:"kick_url,omitempty"`
	RequestID    *uint  `json:"request_id,omitempty"`

	// Fault is the SOAP Fault body (kind=fault) config.
	Fault *CWMPFault `json:"fault,omitempty"`
	// FaultCode / FaultString build the FaultStruct inside
	// TransferComplete / AutonomousTransferComplete.
	FaultCode   *int   `json:"fault_code,omitempty"`
	FaultString string `json:"fault_string,omitempty"`

	// Writable is the ParameterInfoStruct Writable (nil = 1).
	Writable *bool `json:"writable,omitempty"`
	// Notification is the ParameterAttributeStruct Notification (nil = 0).
	Notification *int `json:"notification,omitempty"`
	// InstanceNumber is the AddObjectResponse instance number (nil = 1).
	InstanceNumber *uint `json:"instance_number,omitempty"`
	// ObjectName is the AddObject/DeleteObject object path.
	ObjectName string `json:"object_name,omitempty"`

	// ---- HTTP-level overrides (negative injection points; validator
	// rejects the wire-fault forms they produce) ----
	// SoapAction: non-nil non-empty = negative (SOAPAction must carry an
	// empty value). Rendered verbatim as the header value.
	SoapAction *string `json:"soap_action,omitempty"`
	// HTTPMethod: "GET" (or anything != POST/empty) = negative.
	HTTPMethod string `json:"http_method,omitempty"`
	// ContentType: non-text/xml value = negative (e.g. "application/json";
	// charset variants of text/xml are legal).
	ContentType string `json:"content_type,omitempty"`
	// ContentLengthOverride replaces the computed Content-Length (mismatch =
	// the length negative).
	ContentLengthOverride *int `json:"content_length_override,omitempty"`
	// TransferEncoding: "chunked" frames the body as chunks (replaces
	// Content-Length).
	TransferEncoding string `json:"transfer_encoding,omitempty"`
	// SetCookie is the response Set-Cookie value (generator echoes it as
	// Cookie on the session's subsequent requests).
	SetCookie string `json:"set_cookie,omitempty"`
	// Cookie is the request Cookie header override (empty = generator echo).
	Cookie string `json:"cookie,omitempty"`
	// Authorization is the raw Authorization header (validator recomputes
	// the digest when cfg.Auth carries the credentials).
	Authorization string `json:"authorization,omitempty"`
	// WWWAuthenticate is the challenge raw header value (auth_challenge /
	// 401 responses; default challenge built when empty).
	WWWAuthenticate string `json:"www_authenticate,omitempty"`
	// NamespaceOverride replaces the envelope xmlns:soap value (non-SOAP-1.1
	// = the envelope negative).
	NamespaceOverride string `json:"namespace_override,omitempty"`
	// RawBody replaces the entire SOAP envelope verbatim (validator
	// XML-checks it — truncated/malformed/bodyless forms are negatives).
	RawBody string `json:"raw_body,omitempty"`
	// CurrentTime overrides the Inform CurrentTime dateTime (default
	// "2026-09-05T12:00:00+00:00"; the negative-offset case uses e.g.
	// "2026-09-05T07:00:00-05:00").
	CurrentTime string `json:"current_time,omitempty"`
	// Close marks this response as the session's last (Connection: close).
	Close bool `json:"close,omitempty"`
}

// CWMPFlow is one flow-correlation side connection (design §5): the CPE opens
// an independent HTTP GET/PUT connection to the file server, anchored to the
// main-session transaction that drives it (driven_by). The generator emits the
// flow block right after the anchored transaction; the flow's last event tears
// the side connection down before main-session traffic resumes.
type CWMPFlow struct {
	// Kind is "http_get" | "http_put".
	Kind string `json:"kind,omitempty"`
	// SrcPort is the side connection's client source port (required —
	// independent four-tuple).
	SrcPort uint16 `json:"src_port,omitempty"`
	// Host is the file server IP (required).
	Host string `json:"host,omitempty"`
	// Port is the file server port (required).
	Port uint16 `json:"port,omitempty"`
	// URI is the request path (default "/").
	URI string `json:"uri,omitempty"`
	// FileB64 is the transfer body: PUT request body / GET 200 body
	// (base64; empty = empty body).
	FileB64 string `json:"file_b64,omitempty"`
	// DrivenBy anchors the flow to the driving main-session transaction.
	DrivenBy *CWMPDrivenBy `json:"driven_by,omitempty"`
}

// CWMPDrivenBy is the flow anchor: the session index and the transaction kind
// after which the flow block is inserted (design §5 insertion position:
// immediately after the anchored transaction — anchor the download_response /
// upload_response kind for the canonical "DownloadResponse 之后、下一事务之前"
// position). Field names the driving field (url/command_key; informational).
type CWMPDrivenBy struct {
	Session     int    `json:"session"`
	Transaction string `json:"transaction"`
	Field       string `json:"field,omitempty"`
}
