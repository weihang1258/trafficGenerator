package core

// MMSE（Multimedia Messaging Service Encapsulation，WAP-209 + OMA-MMS-ENC）
// 配置类型——D-MMSE-1（#38），docs/protocol-designs/71-mmse-{design,testcase}.md
// v2.1.0 §6 typedef 对齐。层链 [ip→tcp→http→mmse]（http 族第 5 协议）：
// mmse 终结层事件是完整 HTTP 帧（透明变换器，cwmp/doh/onvif 同款），http 层
// 逐字转发，tcp 层管分段/握手/挥手。主 profile mmse_http_v1：HTTP/1.1 明文
// （缺省端口 80），Content-Type 恒 application/vnd.wap.mms-message；WSP/WTP
// 与 WAP Push 承载为未注册边界（契约 §1，裁定2）。notification/delivery-ind
// 的 HTTP 承载是回放语义（生成器同扮 MS 与 MMSC 两端，会话级四元组覆盖）。

// MMSEConfig is the flow's mmse terminal-layer configuration.
type MMSEConfig struct {
	// Profile selects the protocol profile: "" / "mmse_http_v1" /
	// "mmse_http_v6"（缺省 http_v1）。边界 profile（mmse_wsp_boundary）与
	// 未定义值拒绝（carrier_profile，裁定2）。
	Profile string `json:"profile,omitempty"`
	// MMSVersion pins X-Mms-MMS-Version：""（缺省 "1.2"）/ "1.0" / "1.1" /
	// "1.2" / "1.3"。线码 = 0x80|(主<<4|次)（N-1 口径：1.0=0x90、1.2=0x92、
	// 1.3=0x93）。
	MMSVersion string `json:"mms_version,omitempty"`
	// Concurrent enables interleaved multi-session replay（C-1）：会话事件按
	// 事件下标 round-robin 交错（非会话逐块）。
	Concurrent bool          `json:"concurrent,omitempty"`
	Sessions   []MMSESession `json:"sessions,omitempty"`
	// WireFault injects one negative-path fault（55 值，契约 §6/§7/用例 §5
	// 三方同序——validator 即拒+主锚词，不落线）：carrier_no_http|
	// carrier_content_type|carrier_port|carrier_profile|head_order_tid_first|
	// head_order_version_missing|head_first_not_8c|pdu_type_unassigned|
	// pdu_type_unsupported|content_type_missing|body_on_bodyless|
	// mandatory_from|mandatory_recipients|mandatory_notif_class|
	// mandatory_notif_size|mandatory_notif_expiry|mandatory_notif_location|
	// mandatory_response_status|mandatory_delivery_msgid|
	// mandatory_delivery_to|mandatory_delivery_date|mandatory_delivery_status|
	// multipart_headers_len|multipart_data_len|multipart_partnum_zero|
	// multipart_partnum_mismatch|multipart_start_dangling|
	// multipart_partnum_over|tid_send_conf|tid_notifyresp|tid_acknowledge|
	// msgid_delivery|msgid_read_rec|sequence_ack_first|
	// sequence_notifyresp_orphan|sequence_conf_orphan|sequence_response_first|
	// length_content_length|length_long_int_over|length_long_int_zero|
	// length_uintvar_over|length_value_length|length_tid_over|value_priority|
	// value_status|value_message_class|value_response_status|value_read_status|
	// value_yesno|value_reply_charging|value_empty_string|value_charset|
	// value_previously_sent|value_notif_expiry_absolute.
	WireFault string `json:"wire_fault,omitempty"`
}

// MMSESession is one HTTP session（一条 TCP 连接）：端点覆盖 + 有序事件列。
// 跨连接会话身份 = 端点覆盖；role 选回放侧（"ua" MS 侧客户端 / "mmsc"
// MMSC 侧回放方向——通知/递送报告 POST 回放，契约 §1）。
type MMSESession struct {
	// Role: "ua"（缺省）/ "mmsc"。
	Role string `json:"role,omitempty"`
	// SrcIP/DstIP override the chain ip layer for this session's connection
	//（mmsc 回放方向需独立四元组，契约 §6）；"" = 链层缺省。
	SrcIP string `json:"src_ip,omitempty"`
	DstIP string `json:"dst_ip,omitempty"`
	// SrcPort/DstPort override the chain tcp layer（0 = 链层缺省）。
	SrcPort uint16 `json:"src_port,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`
	// Concurrent interleaves this session（会话级 flag；config 级强制全部）。
	Concurrent bool `json:"concurrent,omitempty"`
	// Events is the session's ordered event list（每元素一笔 MM1 事务一侧）。
	Events []MMSEEvent `json:"events,omitempty"`
}

// MMSEEvent is one MM1 transaction side（一个 PDU + 其 HTTP 载体形状）。
type MMSEEvent struct {
	// Kind is the PDU/transaction kind: send_req|send_conf|notification_ind|
	// notifyresp_ind|retrieve|retrieve_conf|acknowledge_ind|delivery_ind|
	// read_rec_ind（retrieve 为 GET，URI 自动取引用通知的 content_location，
	// 契约 §5 自动派生③）。
	Kind string `json:"kind,omitempty"`
	// TransactionID is X-Mms-Transaction-ID（"auto" = config 全局计数器
	// MMSE-N-%04d，跨会话唯一；显式串否则；引用形 "same_as_notification:<i>"
	// 回指第 i（0 起）个 notification_ind 的已分配 TID（跨会话，契约 §5）。
	// 策略上界 32B——validator 强制，契约 §3.4/§8）。
	TransactionID string `json:"transaction_id,omitempty"`
	// Date is the Date header（epoch 秒；Long-integer 定宽 4B，契约 §3.3）。
	Date *int64 `json:"date,omitempty"`
	// From carries the two wire forms（§7.2.11）。
	From *MMSEFrom `json:"from,omitempty"`
	// To/Cc/Bcc 收件人地址列表（每项一个头实例；send_req 至少一）。
	To  []string `json:"to,omitempty"`
	Cc  []string `json:"cc,omitempty"`
	Bcc []string `json:"bcc,omitempty"`
	// Subject：裸 Text-string 或 Value-length+charset 形态。
	Subject *MMSESubject `json:"subject,omitempty"`
	// MessageClass: personal|advertisement|informational|auto。
	MessageClass string `json:"message_class,omitempty"`
	// Priority: low|normal|high。
	Priority string `json:"priority,omitempty"`
	// Expiry/DeliveryTime：{"relative": 秒}（Delta-seconds 定宽 3B）或
	// {"absolute": epoch}（Date-value 定宽 4B）；通知 Expiry 仅 interval
	// 形态（表 3——绝对形态拒，value_notif_expiry_absolute）。
	Expiry       *MMSETime `json:"expiry,omitempty"`
	DeliveryTime *MMSETime `json:"delivery_time,omitempty"`
	// SenderVisibility: show|hide。
	SenderVisibility string `json:"sender_visibility,omitempty"`
	// DeliveryReport/ReadReply/ReportAllowed Yes/No 布尔（wire 0x80/0x81；
	// nil = 头缺省）。
	DeliveryReport *bool `json:"delivery_report,omitempty"`
	ReadReply      *bool `json:"read_reply,omitempty"`
	ReportAllowed  *bool `json:"report_allowed,omitempty"`
	// ResponseStatus is X-Mms-Response-Status（send_conf 必选）：1.0 九值
	// ok|error_unspecified|error_service_denied|error_message_format_corrupt|
	// error_sending_address_unresolved|error_message_not_found|
	// error_network_problem|error_content_not_accepted|
	// error_unsupported_message（1.1+ 段本版不产生，收窄拒绝）。
	ResponseStatus string `json:"response_status,omitempty"`
	// ResponseText is X-Mms-Response-Text（send_conf 可选）。
	ResponseText string `json:"response_text,omitempty"`
	// MessageID is the Message-ID 头（RFC 822 msg-id，不含 <>）："auto" =
	// config 全局计数器 mmsc-msg-%d（send_conf 接受时/retrieve-conf 出现）；
	// "same_as_send_conf:<i>" 引用第 i（0 起）个 send_conf 的已分配
	// Message-ID（跨会话回指，契约 §5 取材）。
	MessageID string `json:"message_id,omitempty"`
	// MessageSize is X-Mms-Message-Size 字节（通知必选；Long-integer 定宽 3B）。
	MessageSize *uint32 `json:"message_size,omitempty"`
	// ContentLocation is X-Mms-Content-Location（通知必选）+ retrieve GET
	// URI 来源（自动派生③）。
	ContentLocation string `json:"content_location,omitempty"`
	// Status is X-Mms-Status（notifyresp/delivery 必选）：expired|retrieved|
	// rejected|deferred|unrecognised（本版实测三值 retrieved/expired/
	// deferred 产生，其余为合法协议值但不构成本版覆盖声明，契约 §4）。
	Status string `json:"status,omitempty"`
	// ReadStatus is X-Mms-Read-Status（read-rec 必选）：read|
	// deleted_without_being_read。
	ReadStatus string `json:"read_status,omitempty"`
	// Content is the multipart message body（仅 send_req/retrieve_conf）。
	Content *MMSEContent `json:"content,omitempty"`
	// URI overrides the HTTP request URI（缺省 "/mms"；retrieve GET 用引用
	// 通知的 ContentLocation 路径）。
	URI string `json:"uri,omitempty"`
	// HTTP carries per-event HTTP header overrides（契约 §5 自动派生①；
	// Content-Type/Content-Length 覆盖偏离派生值即拒——carrier_content_type/
	// length_content_length 守卫）。
	HTTP map[string]string `json:"http,omitempty"`
	// WireFault injects a per-event wire fault（覆盖 config 级；故障隔离）。
	WireFault string `json:"wire_fault,omitempty"`
}

// MMSEFrom carries the From header's two wire forms（WAP-209 §7.2.11）：
// Address-present token（0x80 + Encoded-string-value）或
// Insert-address-token（0x81，1B 值体——正例 mmse_from_insert_token）。
type MMSEFrom struct {
	Address     string `json:"address,omitempty"`
	InsertToken bool   `json:"insert_token,omitempty"`
}

// MMSESubject carries the Subject header's two Encoded-string-value forms：
// 裸 Text-string（Charset=0）或 Value-length + charset(106) + Text-string。
type MMSESubject struct {
	Text    string `json:"text,omitempty"`
	Charset int    `json:"charset,omitempty"` // 0 = 裸形态；106 = VL+charset
}

// MMSETime carries the Expiry/Delivery-Time forms：Relative（Delta-seconds
// 定宽 3B）或 Absolute（Date-value 定宽 4B）；wire token 0x81 相对 / 0x80 绝对。
type MMSETime struct {
	Relative *uint32 `json:"relative,omitempty"`
	Absolute *int64  `json:"absolute,omitempty"`
}

// MMSEContent is the WSP 二进制 multipart 消息体（契约 §3.6）：仅
// multipart/related（媒体码 0xB3；mixed 配置拒绝），Start 参数指向 SMIL 根
// 部件 Content-ID。
type MMSEContent struct {
	// Kind: "" / "multipart_related"（唯一产生形态）；"multipart_mixed" 拒。
	Kind string `json:"kind,omitempty"`
	// Start is the multipart/related start 参数（如 "<smil.smil>"）。
	Start string `json:"start,omitempty"`
	// Type is the multipart/related type 参数（如 "application/smil"）。
	Type string `json:"type,omitempty"`
	// Parts is the ordered part list（≤127，契约 §8）。
	Parts []MMSEPart `json:"parts,omitempty"`
}

// MMSEPart is one multipart part：part 头（Content-type 带 name/charset
// 参数——参数编在 Content-type-value 的 Value-length 之内，N-6 实现警告）
// + 数据。
type MMSEPart struct {
	ContentType     string `json:"content_type,omitempty"`
	Charset         int    `json:"charset,omitempty"` // 106 UTF-8（0 = 缺省）
	Name            string `json:"name,omitempty"`    // part ct 参数 0x85
	ContentID       string `json:"content_id,omitempty"`
	ContentLocation string `json:"content_location,omitempty"`
	// Data/DataB64 二选一（都设时 Data 胜）。Data 是纯文本 UTF-8（契约 §6
	// "data": "Hello MMSE world" 形）；二进制载荷走 data_b64——Go []byte 的
	// JSON 默认 base64 语义与契约纯文本 data 形冲突，故用 string。
	Data    string `json:"data,omitempty"`
	DataB64 string `json:"data_b64,omitempty"`
}
