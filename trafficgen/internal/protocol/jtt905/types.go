// Package jtt905 implements the JT/T 905-2014 taxi ISU protocol
// (出租车车载信息服务终端通讯协议). A single JTT905 flow models ONE taxi
// ISU (Intelligent Service Unit / 智能服务终端) session over one TCP
// 4-tuple (default port 10700). The core business is shift management:
// 上班签到 (check-in) → 心跳保活 (heartbeats) → 下班签退 (check-out).
//
// The frame format is identical to JT808 (0x7e delimiters, escape,
// XOR checksum, 12/16-byte header) but with a different MsgId space.
//
// Per design doc 02-03-04-jt808-jt809-jtt905-design.md v1.1.4-patch.
package jtt905

import (
	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// Default port (默认端口) for JTT905 (design §1).
const DefaultPort = 10700

// MsgId constants (design §4C).
const (
	MsgISUGeneralResponse uint16 = 0x0001 // ISU 通用应答
	MsgHeartbeat          uint16 = 0x0002 // 终端心跳
	MsgCheckIn            uint16 = 0x1001 // 上班签到
	MsgCheckOut           uint16 = 0x1002 // 下班签退
	MsgCenterGeneralResp  uint16 = 0x8001 // 中心通用应答
	MsgTextDown           uint16 = 0x8300 // 文本下发 (platform command)
)

// Procedure type strings (design §5C).
const (
	ProcCheckIn               = "check_in"
	ProcHeartbeat             = "heartbeat"
	ProcCheckOut              = "check_out"
	ProcCenterGeneralResponse = "center_general_response"
	ProcISUGeneralResponse    = "isu_general_response"
)

// ACKFlag values (design §7C.5): only 0-3, no 99.
const (
	ACKSuccess      uint8 = 0 // 成功/确认
	ACKFailure      uint8 = 1 // 失败
	ACKMessageError uint8 = 2 // 消息有误
	ACKNotSupported uint8 = 3 // 不支持
)

// LicenseColor constants (same encoding as JT808, design §4C.2).
const (
	LicenseColorNone   uint8 = 0
	LicenseColorBlue   uint8 = 1
	LicenseColorYellow uint8 = 2
	LicenseColorBlack  uint8 = 3
	LicenseColorWhite  uint8 = 4
	LicenseColorGreen  uint8 = 5
	LicenseColorOther  uint8 = 9
)

// Field length constants (design §4C).
const (
	DriverIdLen       = 20 // ASCII
	DriverNameLen     = 16 // GBK, 0x20-padded
	LicensePlateLen   = 21 // GBK, 0x20-padded
	LicenseColorLen   = 1
	OnTimeLen         = 6 // BCD
	VehicleModelLen   = 16 // ASCII, 0x20-padded
	LoadCapacityLen   = 2  // uint16 BE
	OffTimeLen        = 6  // BCD
	MileageLen        = 4  // uint32 BE
	IncomeLen         = 4  // uint32 BE
	PassengerCountLen = 2  // uint16 BE
	GeneralResponseLen = 5 // ResponseSN(2)+ResponseMsgId(2)+Result(1), no Phone (design §4C.4)
)

// JTT905Config configures a JT/T 905-2014 taxi ISU session (design §5C).
type JTT905Config struct {
	// Phone (ISU 手机号) 12-digit BCD. Required.
	Phone string `json:"phone"`

	// Version (版本) "2011" | "2013" | "2019" (default). Affects
	// MsgBodyProps bits 10-12 (same encoding as JT808).
	Version string `json:"version,omitempty"`

	// EncryptFlag (加密标志) 0=plain (default), 1=encrypted (placeholder).
	EncryptFlag uint8 `json:"encrypt_flag,omitempty"`

	// InitialSN (起始流水号) for MsgSN counter.
	InitialSN uint16 `json:"initial_sn,omitempty"`

	// PlatformInitialSN (平台侧起始流水号) for platformMsgSN. Default 0.
	// Per-ISU independent counter; NOT tied to InitialSN (design §6C.2).
	PlatformInitialSN uint16 `json:"platform_initial_sn,omitempty"`

	// DriverId (驾驶员从业资格证号) 20 ASCII chars.
	DriverId string `json:"driver_id,omitempty"`

	// DriverName (驾驶员姓名) GBK, up to 16 bytes.
	DriverName string `json:"driver_name,omitempty"`

	// LicensePlate (车牌号) GBK, up to 21 bytes.
	LicensePlate string `json:"license_plate,omitempty"`

	// LicenseColor (车牌颜色) 0-5, 9.
	LicenseColor uint8 `json:"license_color,omitempty"`

	// VehicleModel (车型) ASCII, up to 16 bytes.
	VehicleModel string `json:"vehicle_model,omitempty"`

	// LoadCapacity (核定载客量) for 0x1001.
	LoadCapacity uint16 `json:"load_capacity,omitempty"`

	// OnTime (上班时间) "YYMMDDhhmmss" for 0x1001.
	OnTime string `json:"on_time,omitempty"`

	// OffTime (下班时间) "YYMMDDhhmmss" for 0x1002.
	OffTime string `json:"off_time,omitempty"`

	// Mileage (班次里程, 米) for 0x1002.
	Mileage uint32 `json:"mileage,omitempty"`

	// Income (班次营收, 分) for 0x1002.
	Income uint32 `json:"income,omitempty"`

	// PassengerCount (载客次数) for 0x1002.
	PassengerCount uint16 `json:"passenger_count,omitempty"`

	// HeartbeatCount (心跳次数) for the heartbeat phase between
	// check-in and check-out. Default 3.
	HeartbeatCount int `json:"heartbeat_count,omitempty"`

	// HeartbeatInterval (心跳间隔, 秒) default 60.
	HeartbeatInterval int `json:"heartbeat_interval,omitempty"`

	// Procedures (业务流程) explicit override list. When empty, the
	// planner auto-generates the full session (design §5C H-09):
	//   check-in → (heartbeat + center response)×N → check-out → response
	Procedures []JTT905Procedure `json:"procedures,omitempty"`
}

// JTT905Procedure is one step in a JTT905 session (design §5C).
type JTT905Procedure struct {
	// Type one of: "check_in", "heartbeat", "check_out",
	// "center_general_response", "isu_general_response".
	Type string `json:"type"`

	// ACKFlag (应答标志) for response types. 0/1/2/3 only.
	ACKFlag uint8 `json:"ack_flag,omitempty"`

	// ResponseSN / ResponseMsgId auto-bound when 0.
	ResponseSN     uint16 `json:"response_sn,omitempty"`
	ResponseMsgId  uint16 `json:"response_msg_id,omitempty"`
}

// DefaultJTT905Config returns a config populated with design §7C.8
// reference values.
func DefaultJTT905Config() *JTT905Config {
	return &JTT905Config{
		Phone:          "013800138000",
		Version:        jtcommon.Version2019,
		DriverId:       "11012345678901234567",
		DriverName:     "张三",
		LicensePlate:   "京A12345",
		LicenseColor:   LicenseColorBlue,
		VehicleModel:   "BJ-TAXI",
		LoadCapacity:   4,
		OnTime:         "240803080000",
		OffTime:        "240803160000",
		Mileage:        250000,
		Income:         50000,
		PassengerCount: 12,
		HeartbeatCount: 3,
	}
}
