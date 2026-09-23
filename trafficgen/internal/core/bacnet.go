package core

import (
	"bytes"
	"encoding/json"
)

// BACnet/IP（D-BACNET-1 #41，契约 65-bacnet v2.1.0）配置类型。
// 字段名对齐契约 §6 typedef：sessions[] 事件编排会话（每事件 = 一笔
// BACnet 报文一侧，自动应答按 respond 子对象展开——设计 §5 规则①-⑦），
// 多会话按序整块回放（第二会话包号起点 = 前会话总包数 + 1），
// concurrent=true 时按 event index 交错（v2.1 C-1 翻案，正例 47）。
// 链形 [ip→udp→bacnet]：BACnet/IP（Annex J）BVLC Type 0x81 over UDP
// 47808；UDP 无连接——每事件一数据报，无握手/挥手（正例不携带
// has_handshake/terminates，恒 false）。
//
// 全协议大端（§3.4 端序总表）：BVLC Length/DNET/SNET/TTL/Vendor ID/
// Unsigned/Enumerated/Real/Double/ObjectID 均大端。无符号/枚举取最短式
// （≤4B 直存 LVT，不用扩展长度——SDK encode_application_unsigned 行为，
// 正例断言按最短式锚定）。

// BACNETConfig is the flow's bacnet terminal-layer configuration.
type BACNETConfig struct {
	// Profile is informational（bacnet_ip_v1 主档；wire 形态由事件配置决定）.
	Profile string `json:"profile,omitempty"`
	// Concurrent interleaves sessions[] by event index（v2.1 C-1，正例 47）；
	// UDP 无连接，仅生成器级交错，各会话内部事件序/事务配对不放宽.
	Concurrent bool            `json:"concurrent,omitempty"`
	Sessions   []BACNETSession `json:"sessions,omitempty"`
	// WireFault injects one negative-path fault（42 值枚举，设计 §6/§7 与
	// 用例 §5 三方同序）.
	WireFault string `json:"wire_fault,omitempty"`
}

// BACNETSession is one event-orchestration session：端点覆盖 + I-Am 身份
// 缺省 + 有序事件列。会话身份 = SrcIP/SrcPort 覆盖（空/0 = 流缺省）；
// 自动 I-Am（规则①）的四元身份从会话级缺省取（可被事件级覆盖——
// effectiveIAM 单解析权威，生成器/validator 同源）。
type BACNETSession struct {
	// SrcIP overrides the session's source IP（多会话双客户端 .66/.67；
	// 空 = 流缺省。仅 up 方向直落——down 方向留空走链层交换）.
	SrcIP string `json:"src_ip,omitempty"`
	// SrcPort overrides the session's UDP source port (0 = 流缺省).
	SrcPort uint16 `json:"src_port,omitempty"`
	// DstPort overrides the session's destination port (0 = 继承链级缺省
	// 47808 via FieldContract；validator 守会话间一致性).
	DstPort uint16 `json:"dst_port,omitempty"`
	// DeviceInstance/MaxAPDU/Segmentation/VendorID are the auto-I-Am
	// identity defaults (规则①「从会话配置取」；0/nil = fixture 缺省
	// 100/1476/3/15；Segmentation 用指针——0=both 是合法枚举值).
	DeviceInstance int  `json:"device_instance,omitempty"`
	MaxAPDU        int  `json:"max_apdu,omitempty"`
	Segmentation   *int `json:"segmentation,omitempty"`
	VendorID       int  `json:"vendor_id,omitempty"`
	// Events is the session's ordered event list；确认事务 Invoke ID 递增
	// 不重用（TSM），ACK/Error/Reject/Abort/SegmentACK 回显触发请求的
	// Invoke ID；who_is→i_am 状态序与 COV 订阅前置由 validator 守.
	Events []BACNETEvent `json:"events,omitempty"`
}

// BACNETNPDU is the per-event NPDU decoration（§3.2 控制八位组逐位）：
// Dest 存在 → bit5=1（DNET/HopCount 必现，DLEN=IP+Port 存在?6:0）；
// Src 存在 → bit3=1（SNET/SLEN/SADR；SLEN=0 非法）；Priority 0-3 →
// bits1-0；ExpectReply → bit2。bit7（网络层消息）由事件 kind 决定
// （router_discovery/raw_npdu），不由本结构声明。
type BACNETNPDU struct {
	// Dest is the destination specifier (Net>0；IP+Port 都非空 → DLEN=6
	// 携 6B DADR；都空 → DLEN=0 = DNET 内广播；Net=0xFFFF 全局广播).
	Dest *BACNETNPDUAddr `json:"dest,omitempty"`
	// Src is the source specifier (Net>0；IP+Port 必须都非空——SLEN=0 非法).
	Src *BACNETNPDUAddr `json:"src,omitempty"`
	// Priority is the network priority 0-3 (0=Normal 缺省).
	Priority int `json:"priority,omitempty"`
	// ExpectReply sets control bit2 (确认请求/期望回复).
	ExpectReply bool `json:"expect_reply,omitempty"`
}

// BACNETNPDUAddr is one NPDU address specifier.
type BACNETNPDUAddr struct {
	Net  int    `json:"net"` // 1-65535 大端（0xFFFF=全局广播，仅 Dest 合法）
	IP   string `json:"ip,omitempty"`
	Port uint16 `json:"port,omitempty"`
}

// BACNETValue is one application-tagged value（§3.4 十三标签）。
type BACNETValue struct {
	// Type: null|boolean|unsigned|int|real|double|octet_string|
	// char_string|bit_string|enumerated|date|time|object_id.
	Type string `json:"type"`
	// Value is the semantic payload: bool | number | hex string
	// (octet_string/bit_string 内容) | string (char_string) |
	// {year,month,day,weekday} (date) | {hour,minute,second,century}
	// (time)；object_id 用 ObjType/ObjInstance.
	Value interface{} `json:"value,omitempty"`
	// Charset for char_string (0=ANSI/UTF-8 缺省；4=UCS-2).
	Charset int `json:"charset,omitempty"`
	// UnusedBits for bit_string (尾部未用位数).
	UnusedBits int `json:"unused_bits,omitempty"`
	// ObjType/ObjInstance for object_id (类型<<22|实例, 大端).
	ObjType     int `json:"object_type,omitempty"`
	ObjInstance int `json:"object_instance,omitempty"`
}

// BACNETTableEntry is one BDT entry (IP+Port+Mask) or FDT entry
// (IP+Port+TTL+Timeout)——两形态按事件 kind 区分.
type BACNETTableEntry struct {
	IP      string `json:"ip"`
	Port    uint16 `json:"port"`
	Mask    string `json:"mask,omitempty"`    // BDT: hex hex 形如 ffffff00
	TTL     int    `json:"ttl,omitempty"`     // FDT
	Timeout int    `json:"timeout,omitempty"` // FDT
}

// BACNETPropRef is one property reference inside a ReadAccessSpecification
// (RPM 请求) or read result.
type BACNETPropRef struct {
	Property   int  `json:"property"`
	ArrayIndex *int `json:"array_index,omitempty"` // 0=整个数组合法
}

// BACNETReadSpec is one ReadAccessSpecification (RPM 请求可重复多对象).
type BACNETReadSpec struct {
	ObjectType int             `json:"object_type"`
	Instance   int             `json:"instance"`
	Props      []BACNETPropRef `json:"props,omitempty"`
}

// BACNETPropValue is one property value inside a read result.
type BACNETPropValue struct {
	Property   int          `json:"property"`
	ArrayIndex *int         `json:"array_index,omitempty"`
	Value      *BACNETValue `json:"value,omitempty"`
}

// BACNETReadResult is one ReadAccessResult (RPM/RP ComplexACK 可重复多对象).
type BACNETReadResult struct {
	ObjectType int               `json:"object_type"`
	Instance   int               `json:"instance"`
	Props      []BACNETPropValue `json:"props,omitempty"`
}

// BACNETCOVValue is one (property, value) pair of a COV notification's
// open[4] list.
type BACNETCOVValue struct {
	Property int          `json:"property"`
	Value    *BACNETValue `json:"value"`
}

// BACNETRespond drives the auto-derivation rules ②③⑤⑥⑦ (设计 §5)：
// ACK/Error/Reject/Abort 对 confirmed 请求、BVLC-Result 对 BBMD 管理、
// Entries 对 Read-BDT/FDT-Ack、Nets 对 I-Am-Router-To-Network。
type BACNETRespond struct {
	// Ack: "simple" → SimpleACK；"complex" → ComplexACK（值取 Value 或
	// Results）；"" → 不自动补.
	Ack string `json:"ack,omitempty"`
	// Value is the ComplexACK single value (RP；开[3]…闭[3] 包裹).
	Value *BACNETValue `json:"value,omitempty"`
	// Results is the ComplexACK multi-object read results (RPM).
	Results []BACNETReadResult `json:"results,omitempty"`
	// Segmented forces the ComplexACK segmented (正例 30；窗口取 Window).
	Segmented bool `json:"segmented,omitempty"`
	// Window is the proposed window size for segmented ACKs (1-255).
	Window int `json:"window,omitempty"`
	// Entries fills Read-BDT/FDT-Ack 表项 (规则⑥).
	Entries []BACNETTableEntry `json:"entries,omitempty"`
	// Result is the BVLC-Result code (规则⑤；nil → 0x0000 成功).
	Result *int `json:"result,omitempty"`
	// Nets fills I-Am-Router-To-Network DNET 列表 (规则⑦).
	Nets []int `json:"nets,omitempty"`
	// Error replaces the ACK with an Error APDU (规则③).
	Error *BACNETErrorBody `json:"error,omitempty"`
	// Reject replaces the ACK with a Reject APDU (理由 0-7).
	Reject *int `json:"reject,omitempty"`
	// Abort replaces the ACK with an Abort APDU (理由 0-11).
	Abort *int `json:"abort,omitempty"`
}

// BACNETErrorBody is the error-class/error-code pair (Clause 18 组合子集).
type BACNETErrorBody struct {
	Class int `json:"class"`
	Code  int `json:"code"`
}

// BACNETEvent is one event of the BACnet script：24 kinds 覆盖 12 BVLC
// 功能 + 8 APDU 类型 + NPDU 变体。方向由 kind 决定：请求/管理类 up，
// 应答/通知类 down。
type BACNETEvent struct {
	// Kind: who_is|i_am|who_has|i_have|read_property|write_property|rpm|
	// subscribe_cov|cov_notification|dcc|error|reject|abort|
	// segmented_request|segmented_ack|register_foreign_device|write_bdt|
	// read_bdt|read_fdt|delete_fdt|distribute_broadcast|forwarded_npdu|
	// router_discovery|raw_npdu.
	Kind string `json:"kind,omitempty"`
	// WireFault injects a per-event wire fault（覆盖会话级；故障隔离用）.
	WireFault string `json:"wire_fault,omitempty"`
	// InvokeID is the confirmed-transaction correlation 0-255（0 合法边界，
	// 指针区分"声明 0"与"缺省递增"——idWalker 单解析权威，生成器与
	// validator 同源同序）；应答事件回显触发请求值.
	InvokeID *int `json:"invoke_id,omitempty"`
	// SA declares the client accepts segmented responses (Confirmed-REQ
	// 首字节 bit1=1——正例 52；false/缺省 = 0).
	SA bool `json:"sa,omitempty"`

	// NPDU decorates the network layer (dest/src 地址、优先级、期望回复).
	NPDU *BACNETNPDU `json:"npdu,omitempty"`

	// --- who_is / who_has 范围过滤对（[0][1] 成对出现）---
	Low  *int `json:"low,omitempty"`
	High *int `json:"high,omitempty"`

	// --- I-Am / I-Have 身份 + who_has 对象选择 ---
	DeviceInstance int    `json:"device_instance,omitempty"` // I-Am 设备实例（必为 device 类型 8）
	MaxAPDU        int    `json:"max_apdu,omitempty"`        // 50/128/206/480/1024/1476
	Segmentation   *int   `json:"segmentation,omitempty"`    // 0=both/1=transmit/2=receive/3=none（指针：0 合法）
	VendorID       int    `json:"vendor_id,omitempty"`       // ≤65535
	ObjectType     int    `json:"object_type,omitempty"`     // 对象类型 0-1023（who_has ID 分支/RP/WP/COV 对象）
	Instance       int    `json:"instance,omitempty"`        // 对象实例 0-4194303
	ObjectName     string `json:"object_name,omitempty"`     // who_has [3] 名字分支 / I-Have 对象名

	// --- ReadProperty / WriteProperty ---
	Property   int          `json:"property,omitempty"`    // 属性 ID 0-511
	ArrayIndex *int         `json:"array_index,omitempty"` // [2] 可选；0=整个数组
	Value      *BACNETValue `json:"value,omitempty"`       // WP [3] 写入值（开[3]…闭[3]）
	Priority   *int         `json:"priority,omitempty"`    // WP [4] 1-16；nil=缺省(16)

	// --- ReadPropertyMultiple ---
	Reads []BACNETReadSpec `json:"reads,omitempty"`

	// --- COV ---
	ProcessID        int              `json:"process_id,omitempty"`        // [0] 订阅者进程 ID
	IssueConfirmed   *bool            `json:"issue_confirmed,omitempty"`   // [2] 三态：nil=缺省(取消形态)
	Lifetime         *int             `json:"lifetime,omitempty"`          // [3] 秒；nil=缺省
	InitiatingDevice int              `json:"initiating_device,omitempty"` // 通知 [1] 发起设备
	TimeRemaining    int              `json:"time_remaining,omitempty"`    // 通知 [3] 剩余秒
	CovValues        []BACNETCOVValue `json:"cov_values,omitempty"`        // 通知 开[4] 列表

	// --- DeviceCommunicationControl ---
	Duration *int   `json:"duration,omitempty"` // [0] 分钟；nil=缺省
	Disable  *int   `json:"disable,omitempty"`  // [1] 0=enable/1=disable/2=disable-initiation
	Password string `json:"password,omitempty"` // [2]

	// --- BBMD 管理 ---
	TTL     int                `json:"ttl,omitempty"`     // RFD TTL 秒（0=立即到期合法边界——指针不需要：0 即声明值恒渲染）
	Result  *int               `json:"result,omitempty"`  // BVLC-Result 结果码（result 事件/覆盖）
	Entries []BACNETTableEntry `json:"entries,omitempty"` // write_bdt 表项 / read_*_ack 表项
	FwdIP   string             `json:"fwd_ip,omitempty"`  // forwarded_npdu 原始源 IP
	FwdPort uint16             `json:"fwd_port,omitempty"`
	// Inner is the NPDU carried by forwarded_npdu/distribute_broadcast
	// (典型 Who-Is——内层事件仅支持 who_is 形态).
	Inner *BACNETEvent `json:"inner,omitempty"`
	// Nets is the I-Am-Router-To-Network DNET list (NLM 体)；
	// router_discovery 的 Who-Is-Router 体取 Nets[0]（可缺省）.
	Nets []int `json:"nets,omitempty"`
	// NetMsgType for raw_npdu: 0=Who-Is-Router-To-Network(up)/
	// 1=I-Am-Router-To-Network(down).
	NetMsgType int `json:"net_msg_type,omitempty"`

	// --- 分段（segmented_request/segmented_ack/respond.Segmented）---
	Segmented  bool `json:"segmented,omitempty"`   // 强制分段（天然超限外）
	WindowSize int  `json:"window_size,omitempty"` // 提议窗口 1-255（分段事件必填）

	// --- Error / Reject / Abort（standalone kinds）---
	ServiceChoice int   `json:"service_choice,omitempty"` // error 回显的确认服务选择
	ErrClass      int   `json:"error_class,omitempty"`    // 0-7 与 64-65535
	ErrCode       int   `json:"error_code,omitempty"`     // 0-63 与 64-65535
	RejectReason  int   `json:"reject_reason,omitempty"`  // 0-7 / 64-255
	AbortReason   int   `json:"abort_reason,omitempty"`   // 0-11 / 64-255
	SRV           *bool `json:"srv,omitempty"`            // abort/segmentack 服务器侧 bit0

	// Respond drives auto-derivation (respond_i_am ①独立字段；其余 ②③⑤⑥⑦).
	RespondIAM bool           `json:"respond_i_am,omitempty"`
	Respond    *BACNETRespond `json:"respond,omitempty"`
}

// UnmarshalJSON enforces strict key checking at the event level（xmrmining
// 红⑮ 先例：自定义 UnmarshalJSON 绕过外层 decoder 的 DisallowUnknownFields，
// 钩子内必须自带 Decoder+DisallowUnknownFields——三级未知键全拒）.
func (e *BACNETEvent) UnmarshalJSON(b []byte) error {
	type bacnetEventAlias BACNETEvent
	var alias bacnetEventAlias
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&alias); err != nil {
		return err
	}
	*e = BACNETEvent(alias)
	return nil
}

// 42 wire_fault 值（设计 §6 枚举/§7 表/用例 §5 表三方同序）——分发拒与
// 自然守卫的归属见 D-BACNET-1 处置表（P4 据实勘误）。
const (
	BACNETWireFaultBvlcType            = "bvlc_type"
	BACNETWireFaultBvlcFunction        = "bvlc_function"
	BACNETWireFaultBvlcSecure          = "bvlc_secure"
	BACNETWireFaultBvlcLengthMin       = "bvlc_length_min"
	BACNETWireFaultBvlcLengthMismatch  = "bvlc_length_mismatch"
	BACNETWireFaultBvlcLengthForwarded = "bvlc_length_forwarded"
	BACNETWireFaultNpduVersion         = "npdu_version"
	BACNETWireFaultNpduDestMissing     = "npdu_dest_missing"
	BACNETWireFaultNpduSrcLenZero      = "npdu_src_len_zero"
	BACNETWireFaultNpduReservedBits    = "npdu_reserved_bits"
	BACNETWireFaultNpduNoMessageType   = "npdu_no_message_type"
	BACNETWireFaultNpduDlenInvalid     = "npdu_dlen_invalid"
	BACNETWireFaultApduTypeInvalid     = "apdu_type_invalid"
	BACNETWireFaultApduHeaderConfirmed = "apdu_header_confirmed"
	BACNETWireFaultApduHeaderSimpleack = "apdu_header_simpleack"
	BACNETWireFaultServiceConfUnimpl   = "service_confirmed_unimplemented"
	BACNETWireFaultServiceUnconfInv    = "service_unconfirmed_invalid"
	BACNETWireFaultTagLvtMismatch      = "tag_lvt_mismatch"
	BACNETWireFaultTagOpenUnmatched    = "tag_open_unmatched"
	BACNETWireFaultTagBooleanLvt       = "tag_boolean_lvt"
	BACNETWireFaultTagContextNumber    = "tag_context_number"
	BACNETWireFaultObjectTypeOverflow  = "object_type_overflow"
	BACNETWireFaultObjectInstOverflow  = "object_instance_overflow"
	BACNETWireFaultObjectIAMNotDevice  = "object_iam_not_device"
	BACNETWireFaultPropertyIDVendor    = "property_id_vendor"
	BACNETWireFaultPropertyIndexNeg    = "property_index_negative"
	BACNETWireFaultPriorityRange       = "priority_range"
	BACNETWireFaultErrorClassRange     = "error_class_range"
	BACNETWireFaultInvokeMismatch      = "invoke_mismatch"
	BACNETWireFaultInvokeReuse         = "invoke_reuse"
	BACNETWireFaultSegmentExtraFields  = "segment_extra_fields"
	BACNETWireFaultSegmentMissing      = "segment_missing_fields"
	BACNETWireFaultSegmentWindowZero   = "segment_window_zero"
	BACNETWireFaultSegmentSeqSkip      = "segment_sequence_skip"
	BACNETWireFaultCarrierLayerMissing = "carrier_layer_missing"
	BACNETWireFaultCarrierTCP          = "carrier_tcp"
	BACNETWireFaultPortUndeclared      = "port_undeclared"
	BACNETWireFaultAddrFamilyMismatch  = "address_family_mismatch"
	BACNETWireFaultAddrFamilyDerived   = "address_family_derived"
	BACNETWireFaultStateAckNoRequest   = "state_ack_no_request"
	BACNETWireFaultStateIAMNoWhois     = "state_iam_no_whois"
	BACNETWireFaultStateCovNoSubscribe = "state_cov_no_subscribe"
)
