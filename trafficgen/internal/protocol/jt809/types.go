// Package jt809 implements the JT/T 809-2019 platform-to-platform data
// exchange protocol (道路运输车辆卫星定位系统平台数据交换). A JT809 session
// uses TWO independent TCP connections: a main link (主链路, lower→upper,
// port 8812) carrying 0x1xxx messages, and an optional slave link (从链路,
// upper→lower, port 8813) carrying 0x9xxx messages.
//
// Per design doc 02-03-04-jt808-jt809-jtt905-design.md v1.1.4-patch.
package jt809

import (
	"github.com/trafficgen/trafficgen/internal/protocol/jt808"
)

// Default ports (design §1).
const (
	MainLinkPort  = 8812
	SlaveLinkPort = 8813
)

// MsgId constants (design §3B.2, §4B).
const (
	MsgMainLogin           uint16 = 0x1001 // 主链路登录请求
	MsgMainLoginResponse   uint16 = 0x1002 // 主链路登录应答
	MsgMainLogout          uint16 = 0x1003 // 主链路注销请求
	MsgMainDisconnectNotice uint16 = 0x1007 // 主链路断开通知
	MsgVehicleDynamic      uint16 = 0x1200 // 车辆动态信息 (container)
	MsgPlatformInteraction uint16 = 0x1300 // 平台交互 (container)
	MsgAlarmWithAttachment uint16 = 0x1400 // 报警信息 (with attachment)
	MsgVehicleStatic       uint16 = 0x1500 // 车辆静态信息 (container)
	MsgVehicleControlResp  uint16 = 0x1600 // 车辆控制应答 (container)
	MsgSlaveConnect        uint16 = 0x9001 // 从链路连接请求
	MsgSlaveConnectResp    uint16 = 0x9002 // 从链路连接应答
	MsgSlaveManagement     uint16 = 0x9100 // 从链路平台管理 (container)
	MsgSlaveVehicleControl uint16 = 0x9600 // 从链路车辆控制 (container)
)

// SubMsgId constants for 0x1200 (design §4B.5).
const (
	SubVehicleRegister    uint8 = 0x01 // 0x1201
	SubRealtimeLocation   uint8 = 0x02 // 0x1202
	SubHistoryLocation    uint8 = 0x03 // 0x1203
	SubAlarmAttachment    uint8 = 0x04 // 0x1204
	SubVehicleDirection   uint8 = 0x05 // 0x1205
	SubAreaVehicle        uint8 = 0x06 // 0x1206
	SubPathRecord         uint8 = 0x07 // 0x1207
	SubAlarm              uint8 = 0x08 // 0x1208
	SubEventReport        uint8 = 0x09 // 0x1209
	SubVehicleLogout      uint8 = 0x0A // 0x120A
)

// SubMsgId constants for 0x1300 (design §4B.6).
const (
	SubQueryVehicle       uint8 = 0x01 // 0x1301
	SubQueryAreaVehicle   uint8 = 0x02 // 0x1302
	SubResponse           uint8 = 0x03 // 0x1303
	SubQuerySpecificPlate uint8 = 0x04 // 0x1304
	SubQueryDriverPhone   uint8 = 0x05 // 0x1305
)

// LoginResult values (design §4B.2, §5B.1). 0-4 only (no 99).
const (
	LoginResultSuccess       uint8 = 0 // 成功
	LoginResultFailure       uint8 = 1 // 失败
	LoginResultPasswordError uint8 = 2 // 密码错误
	LoginResultAccountNotFound uint8 = 3 // 账号不存在
	LoginResultAlreadyLogged uint8 = 4 // 已登录
)

// DisconnectReason values (design §4B.4, §5B.1). 0-2 only (no 99).
const (
	DisconnectReasonNormal uint8 = 0 // 正常
	DisconnectReasonUrgent uint8 = 1 // 紧急
	DisconnectReasonFault  uint8 = 2 // 故障
)

// FileType values (design §4B.7).
const (
	FileTypeNone   uint8 = 0 // 无附件
	FileTypeImage  uint8 = 1 // 图片
	FileTypeAudio  uint8 = 2 // 音频
	FileTypeVideo  uint8 = 3 // 视频
)

// VehicleColor values (design §3B.1, JT/T 415-2006 table A.1).
const (
	VehicleColorNone        uint8 = 0 // 未上车牌/其他
	VehicleColorBlue        uint8 = 1 // 蓝色
	VehicleColorYellowAgri  uint8 = 2 // 黄色 (农用)
	VehicleColorGreen       uint8 = 3 // 绿色
	VehicleColorRed         uint8 = 4 // 红色
	VehicleColorYellow      uint8 = 5 // 黄色
	VehicleColorBlack       uint8 = 6 // 黑色
	VehicleColorWhite       uint8 = 7 // 白色
	VehicleColorGradientGrn uint8 = 8 // 渐变绿
	VehicleColorYellowGreen uint8 = 9 // 黄绿双拼色
)

// Header length (消息头长度) is fixed 32 bytes (design §3B.1).
const (
	HeaderLen           = 32
	MsgLengthLen        = 4  // uint32 BE
	MsgSNLen            = 4  // uint32 BE
	MsgIDLen            = 2  // uint16 BE
	VehicleColorLen     = 1
	VehiclePlateLen     = 21 // GBK, 0x20-padded
	LoginBodyLen        = 25 // UserName(5) + Password(10) + GNSSCenterId(4) + VersionFlag(1) + EncryptFlag(1) + EncryptKey(4)
	LoginRespBodyLen    = 5  // Result(1) + GNSSCenterId(4)
)

// Procedure type strings (design §5B).
const (
	ProcMainLogin              = "main_login"
	ProcMainLoginResponse      = "main_login_response"
	ProcMainLogout             = "main_logout"
	ProcMainDisconnectNotice   = "main_disconnect_notice"
	ProcVehicleRegister        = "vehicle_register"
	ProcRealtimeLocation       = "realtime_location"
	ProcHistoryLocation        = "history_location"
	ProcAlarm                  = "alarm"
	ProcAlarmWithAttachment    = "alarm_with_attachment"
	ProcPlatformInteraction    = "platform_interaction"
	ProcVehicleStatic          = "vehicle_static"
	ProcControlResponse        = "control_response"
	ProcSlaveConnect           = "slave_connect"
	ProcSlaveConnectResponse   = "slave_connect_response"
	ProcSlaveManagement        = "slave_management"
	ProcSlaveVehicleControl    = "slave_vehicle_control"
)

// LinkMain / LinkSlave selects which TCP flow carries the message.
const (
	LinkMain  = "main"
	LinkSlave = "slave"
)

// JT809Config configures a JT/T 809-2019 platform-to-platform exchange
// (design §5B). Local equivalent of the design's FlowSpec.JT809 field.
type JT809Config struct {
	// GNSSCenterId (下级平台编号) 9-digit integer packed into uint32.
	// Required. Range 0..999999999.
	GNSSCenterId uint32 `json:"gnss_center_id"`

	// UserName (用户名) 5 ASCII chars. Default = last 5 digits of
	// GNSSCenterId zero-padded (e.g. GNSSCenterId=291 → "00291").
	// Shorter strings are right-padded with 0x00 to 5 bytes.
	UserName string `json:"user_name,omitempty"`

	// Password (密码) 10 ASCII chars, default "0000000000".
	Password string `json:"password,omitempty"`

	// VersionFlag (协议版本) 0=2011, 1=2013, 2=2019 (default).
	VersionFlag uint8 `json:"version_flag,omitempty"`

	// EncryptFlag (加密标识) 0=plain (default), 1=encrypted (placeholder).
	EncryptFlag uint8 `json:"encrypt_flag,omitempty"`

	// EncryptKey (加密密钥) placeholder, default 0x00000000.
	EncryptKey uint32 `json:"encrypt_key,omitempty"`

	// LoginResult (登录应答结果) for 0x1002/0x9002. 0=success (default).
	LoginResult uint8 `json:"login_result,omitempty"`

	// VehicleColor (车辆颜色) for vehicle-related messages.
	VehicleColor uint8 `json:"vehicle_color,omitempty"`

	// VehiclePlate (车牌号) GBK, only when VehicleColor != 0.
	VehiclePlate string `json:"vehicle_plate,omitempty"`

	// InitialSN (起始流水号) for the per-link MsgSN counter. Each link
	// (main + slave) maintains an independent counter.
	InitialSN uint32 `json:"initial_sn,omitempty"`

	// PlatformInitialSN (平台侧起始流水号) for platformMainMsgSN/Slave.
	PlatformInitialSN uint32 `json:"platform_initial_sn,omitempty"`

	// Procedures (业务流程) ordered list of JT809 messages.
	Procedures []JT809Procedure `json:"procedures"`

	// SlaveLinkEnabled (从链路启用) when true, the planner emits a
	// second TCP flow (upper→lower) carrying 0x9xxx messages.
	SlaveLinkEnabled bool `json:"slave_link_enabled,omitempty"`
}

// JT809Procedure is one step in a JT809 session (design §5B).
type JT809Procedure struct {
	// Type selects the message template (see Proc* constants).
	Type string `json:"type"`

	// Link (链路) "main" (default) | "slave". Selects which TCP flow
	// carries this message. The planner auto-routes 0x9xxx to slave,
	// 0x1xxx to main; this field is an override for edge cases.
	Link string `json:"link,omitempty"`

	// SubMsgId (子消息ID) for 0x1200/0x1300 container messages.
	SubMsgId uint8 `json:"sub_msg_id,omitempty"`

	// SubBody (子消息体) raw bytes for container messages.
	SubBody []byte `json:"sub_body,omitempty"`

	// LocationData for "realtime_location" / "history_location".
	// Reuses jt808.JT808Location since the body layout is identical.
	LocationData *jt808.JT808Location `json:"location_data,omitempty"`

	// HistoryCount (历史条数) for "history_location", default 1.
	HistoryCount int `json:"history_count,omitempty"`

	// AlarmFlag (报警标志) for "alarm".
	AlarmFlag uint32 `json:"alarm_flag,omitempty"`

	// PulseSpeed (脉冲速度) for 0x1208 alarm SubBody. uint16 BE, 0.1 km/h.
	PulseSpeed uint16 `json:"pulse_speed,omitempty"`

	// AlarmTime (报警时间) "YYMMDDhhmmss".
	AlarmTime string `json:"alarm_time,omitempty"`

	// FileType (附件类型) for "alarm_with_attachment". 0/1/2/3.
	FileType uint8 `json:"file_type,omitempty"`

	// FileUrl (附件URL) GBK string, max 256 bytes after GBK encoding.
	FileUrl string `json:"file_url,omitempty"`

	// LoginResult per-procedure override for "main_login_response" /
	// "slave_connect_response".
	LoginResult *uint8 `json:"login_result,omitempty"`

	// DisconnectReason (断开原因) for "main_disconnect_notice".
	DisconnectReason uint8 `json:"disconnect_reason,omitempty"`

	// VehicleColor / VehiclePlate per-procedure override.
	VehicleColor *uint8 `json:"vehicle_color,omitempty"`
	VehiclePlate string  `json:"vehicle_plate,omitempty"`
}

// DefaultJT809Config returns a config populated with design §7B.13
// reference values (GNSSCenterId=291, EncryptFlag=1, EncryptKey=0xDEADBEEF).
func DefaultJT809Config() *JT809Config {
	return &JT809Config{
		GNSSCenterId: 291,
		UserName:     "00291", // last 5 digits of "000000291"
		Password:     "0000000000",
		VersionFlag:  2, // 2019
		EncryptFlag:  1,
		EncryptKey:   0xDEADBEEF,
		VehicleColor: VehicleColorBlue,
		VehiclePlate: "京A12345",
		InitialSN:    0,
	}
}
