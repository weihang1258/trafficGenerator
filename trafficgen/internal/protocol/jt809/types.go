// Package jt809 implements the JT/T 809-2019 platform-to-platform data
// exchange protocol (道路运输车辆卫星定位系统 联营车辆卫星定位系统平台数据交换).
// A JT809 session uses up to TWO independent TCP connections: the main link
// (主链路, lower→upper, port 8812, 0x1xxx messages) and an optional slave
// link (从链路, upper→lower, port 8813, 0x9xxx messages), both routed to one
// PacketWorker via a shared GroupID.
//
// D-JT809-1 裁定1/3：线层重建（5B/转义/CRC16 信封 + 22B/30B 版本条件头）+
// 消息族重排 16 型链路管理面；容器族 0x1200-0x1600/0x9200-0x9600 B′ 登记
// 不编排（在库 probe 需求面=0x9001 已覆盖）。
package jt809

import (
	"github.com/trafficgen/trafficgen/internal/core"
)

// Config/procedure types live in core (vnc/xmpp/jt808 precedent); aliases.
type (
	JT809Config    = core.JT809Config
	JT809Procedure = core.JT809Procedure
)

// Default ports (JT/T 809-2019 §5).
const (
	MainLinkPort  = 8812
	SlaveLinkPort = 8813
)

// Envelope constants（D-JT809-1 P4 勘误：MsgLength=整帧总长 5B+头+体+CRC+5D）.
const (
	FlagBegin         = 0x5B
	FlagEnd           = 0x5D
	CRCLen            = 2
	HeaderLenLegacy   = 22 // 2011/2013：MsgLength4+SN4+MsgID2+GNSS4+Ver3+Enc1+Key4
	HeaderLen2019     = 30 // 2019：22B + Time(8)
	FixedFrameLegacy  = 1 + HeaderLenLegacy + CRCLen + 1
	FixedFrame2019    = 1 + HeaderLen2019 + CRCLen + 1
	PasswordLen       = 8
	DownLinkIPLen     = 32
	DefaultVersionHex = "010000" // 金向量钉死的库缺省版本字面（各版本同形，可配）
)

// MsgId constants — 16 型链路管理族（裁定3）.
const (
	MsgMainLogin          uint16 = 0x1001 // 主链路登录请求 (下级→上级)
	MsgMainLoginResp      uint16 = 0x1002 // 主链路登录应答 (上级→下级)
	MsgMainLogout         uint16 = 0x1003 // 主链路注销请求 (下级→上级)
	MsgMainLogoutResp     uint16 = 0x1004 // 主链路注销应答 (上级→下级)
	MsgMainKeepalive      uint16 = 0x1005 // 主链路连接保持 (下级→上级)
	MsgMainKeepaliveResp  uint16 = 0x1006 // 主链路连接保持应答 (上级→下级)
	MsgMainDisconnect     uint16 = 0x1007 // 主链路断开通知 (下级→上级)
	MsgMainClose          uint16 = 0x1008 // 主链路关闭通知 (下级→上级)
	MsgSlaveConnect       uint16 = 0x9001 // 从链路登录请求 (上级→下级)
	MsgSlaveConnectResp   uint16 = 0x9002 // 从链路登录应答 (下级→上级)
	MsgSlaveLogout        uint16 = 0x9003 // 从链路注销请求 (上级→下级)
	MsgSlaveLogoutResp    uint16 = 0x9004 // 从链路注销应答 (下级→上级)
	MsgSlaveKeepalive     uint16 = 0x9005 // 从链路连接保持 (上级→下级)
	MsgSlaveKeepaliveResp uint16 = 0x9006 // 从链路连接保持应答 (下级→上级)
	MsgSlaveDisconnect    uint16 = 0x9007 // 从链路断开通知 (上级→下级)
	MsgSlaveClose         uint16 = 0x9008 // 从链路关闭通知 (上级→下级)
)

// Procedure type strings (config layer, 裁定4 键面).
const (
	ProcMainLogin          = "main_login"
	ProcMainLoginResp      = "main_login_resp"
	ProcMainLogout         = "main_logout"
	ProcMainLogoutResp     = "main_logout_resp"
	ProcMainKeepalive      = "main_keepalive"
	ProcMainKeepaliveResp  = "main_keepalive_resp"
	ProcMainDisconnect     = "main_disconnect"
	ProcMainClose          = "main_close"
	ProcSlaveConnect       = "slave_connect"
	ProcSlaveConnectResp   = "slave_connect_resp"
	ProcSlaveLogout        = "slave_logout"
	ProcSlaveLogoutResp    = "slave_logout_resp"
	ProcSlaveKeepalive     = "slave_keepalive"
	ProcSlaveKeepaliveResp = "slave_keepalive_resp"
	ProcSlaveDisconnect    = "slave_disconnect"
	ProcSlaveClose         = "slave_close"
)

// msgTypeByName maps config procedure type → (MsgId, wire direction).
// direction 相对本链 TCP 客户端侧：up=客户端→服务端方向发射，down=反向。
var msgTypeByName = map[string]struct {
	id       uint16
	link     string // LinkMain | LinkSlave
	upstream bool   // true=下级→上级语义
}{
	ProcMainLogin:          {MsgMainLogin, LinkMain, true},
	ProcMainLoginResp:      {MsgMainLoginResp, LinkMain, false},
	ProcMainLogout:         {MsgMainLogout, LinkMain, true},
	ProcMainLogoutResp:     {MsgMainLogoutResp, LinkMain, false},
	ProcMainKeepalive:      {MsgMainKeepalive, LinkMain, true},
	ProcMainKeepaliveResp:  {MsgMainKeepaliveResp, LinkMain, false},
	ProcMainDisconnect:     {MsgMainDisconnect, LinkMain, true},
	ProcMainClose:          {MsgMainClose, LinkMain, true},
	ProcSlaveConnect:       {MsgSlaveConnect, LinkSlave, false},
	ProcSlaveConnectResp:   {MsgSlaveConnectResp, LinkSlave, true},
	ProcSlaveLogout:        {MsgSlaveLogout, LinkSlave, false},
	ProcSlaveLogoutResp:    {MsgSlaveLogoutResp, LinkSlave, true},
	ProcSlaveKeepalive:     {MsgSlaveKeepalive, LinkSlave, false},
	ProcSlaveKeepaliveResp: {MsgSlaveKeepaliveResp, LinkSlave, true},
	ProcSlaveDisconnect:    {MsgSlaveDisconnect, LinkSlave, false},
	ProcSlaveClose:         {MsgSlaveClose, LinkSlave, false},
}

// Link selectors (emitMsg SN counter + flow routing).
const (
	LinkMain  = "main"
	LinkSlave = "slave"
)

// DefaultJT809Config returns a config with design reference values
// (GNSSCenterId=291, 2019 形，主链 login+keepalive，从链 connect).
func DefaultJT809Config() *JT809Config {
	return &JT809Config{
		GNSSCenterId: 291,
		VersionFlag:  2,
		Procedures: []JT809Procedure{
			{Type: ProcMainLogin},
			{Type: ProcMainKeepalive},
		},
		SlaveProcedures: []JT809Procedure{
			{Type: ProcSlaveConnect},
		},
	}
}
