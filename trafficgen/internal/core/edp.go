package core

// EDPConfig is the EDP layer configuration.
// EDP is the OneNET Enhanced Device Protocol - a TCP-based device access protocol
// for IoT devices.
type EDPConfig struct {
	Profile    string       `json:"profile"`    // edp_tcp_plain_v1 / edp_ipv6_v1 (v2.1)
	Sessions   []EDPSession `json:"sessions"`   // 事件编排会话序列
	WireFault  string       `json:"wire_fault"` // 28 值枚举（D-EDP-1 §7 表）
	Concurrent bool         `json:"concurrent"` // 并发会话交错回放
}

// EDPSession is a per-session wire-fault configuration.
type EDPSession struct {
	SrcIP       string `json:"src_ip"`       // 源 IP（IPv4/IPv6 均可）
	DstIP       string `json:"dst_ip"`       // 目的 IP
	SrcPort     uint16 `json:"src_port"`     // 源端口；0=继承链 tcp 端口
	DstPort     uint16 `json:"dst_port"`     // 目标端口；0=默认 4472
	Concurrent  bool   `json:"concurrent"`   // 并发会话交错回放
	Coalesce    bool   `json:"coalesce"`     // 多帧粘连合并
	Events      []EDPEvent `json:"events"`    // 会话事件序列
}

// EDPEvent is a single EDP event in a session.
type EDPEvent struct {
	Kind        string `json:"kind"`        // connect / savedata / pushdata / cmdreq / ping / disconnect
	Auth        string `json:"auth"`        // devid / userid (connect kind)
	Devid       string `json:"devid"`       // 设备编号 (connect, savedata, pushdata)
	APIKey      string `json:"apikey"`      // API key (connect)
	UserID      string `json:"userid"`      // 用户 ID (connect)
	AuthInfo    string `json:"authinfo"`    // 认证信息 (connect)
	KeepTime    *uint16 `json:"keep_time"`  // 心跳间隔 (connect)
	ConnackRtn  *int    `json:"connack_rtn"` // CONNRESP 返回码 (connect)
	Direction   string `json:"direction"`   // up（缺省）/ down（savedata, pushdata——契约 §6）
	DevidFlag   int    `json:"devid_flag"`  // 消息标志设备编号位
	MsgIDFlag   int    `json:"msg_id_flag"` // 消息编号位
	MsgID       *uint16 `json:"msg_id"`     // 消息编号 (savedata, saveack)
	Format      int    `json:"format"`      // 数据格式 0x01-0x05
	JSONStr     string `json:"json"`        // JSON 数据 (type1/3/4)
	Desc        string `json:"desc"`        // desc JSON (type2)
	BinB64      string `json:"bin_b64"`     // 二进制载荷base64 (type2)
	Ack         *bool  `json:"ack"`         // 是否应答 (savedata, cmdreq)
	ErrCode     *int   `json:"err_code"`    // 错误码 (saveack)
	DataB64     string `json:"data_b64"`    // 透传数据base64 (pushdata)
	CmdID       string `json:"cmdid"`       // 命令编号 (cmdreq/cmdresp——契约 §6)
	ReqB64      string `json:"req_b64"`     // 命令请求base64 (cmdreq)
	RespB64     string `json:"resp_b64"`    // 命令响应base64 (cmdresp)
	WireFault   string `json:"wire_fault"`  // 28 值注入
}

// 28 wire_fault values per D-EDP-1 §7 表 (顺序同表)
const (
	EDPWireFaultTypeUnknown           = "type_unknown"
	EDPWireFaultTypeUnimplemented     = "type_unimplemented"
	EDPWireFaultRemainlenMismatch     = "remainlen_mismatch"
	EDPWireFaultRemainlenTruncated    = "remainlen_truncated"
	EDPWireFaultRemainlen5Byte        = "remainlen_5byte"
	EDPWireFaultConnProtocolName      = "protocol_name"
	EDPWireFaultConnVersion           = "version"
	EDPWireFaultConnFlag              = "conn_flag"
	EDPWireFaultSavedataFormat        = "format_flag"
	EDPWireFaultBinDescNoDsID         = "bin_desc_no_dsid"
	EDPWireFaultBinDescInvalid        = "bin_desc_invalid"
	EDPWireFaultBinDescOver           = "bin_desc_over"
	EDPWireFaultBinOver3MB            = "bin_over_3mb"
	EDPWireFaultStateNoConnect        = "state_no_connect"
	EDPWireFaultStateAfterReject      = "state_after_reject"
	EDPWireFaultStateAfterDisconnect  = "state_after_disconnect"
	EDPWireFaultCmdidCorrelation      = "cmdid"
	EDPWireFaultMsgidCorrelation      = "msg_id"
	EDPWireFaultJsonInvalid           = "json_invalid"
	EDPWireFaultJsonOverU16           = "json_over_u16"
	EDPWireFaultLayerChain            = "layer_chain"
	EDPWireFaultCarrierUDP            = "carrier_udp"
	EDPWireFaultPortConflict          = "port_conflict"
	EDPWireFaultAuthDevidEmpty        = "auth_devid_empty"
	EDPWireFaultAuthAPIKeyEmpty       = "auth_apikey_empty"
	EDPWireFaultAuthUserIDEmpty       = "auth_userid_empty"
	EDPWireFaultAuthAuthInfoEmpty     = "auth_authinfo_empty"
	EDPWireFaultConnackRTNRange       = "connack_rtn"
)