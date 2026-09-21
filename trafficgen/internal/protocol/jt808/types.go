// Package jt808 implements the JT/T 808-2019 vehicle-terminal protocol
// planner (道路运输车辆卫星定位系统终端通讯协议). A single JT808 flow
// models ONE terminal session over one TCP 4-tuple (default port 7611).
//
// The planner emits a TCP 3-way handshake, a sequence of JT808 messages
// (each wrapped in 0x7e delimiters with escape + XOR checksum), and a
// TCP 3-way teardown. Multi-terminal scenarios use multiple FlowSpecs,
// each with a unique Phone and a distinct 4-tuple.
//
// Per design doc 02-03-04-jt808-jt809-jtt905-design.md v1.1.4-patch.
package jt808

import (
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// Default port (默认端口) for JT808 (design §1).
const DefaultPort = 7611

// MsgId constants (design §4A).
const (
	MsgTerminalRegister         uint16 = 0x0100 // 终端注册 (terminal registration)
	MsgTerminalAuth             uint16 = 0x0102 // 终端鉴权 (terminal authentication)
	MsgTerminalCancel           uint16 = 0x0003 // 终端注销 (terminal cancel)
	MsgTerminalPropertyResponse uint16 = 0x0107 // 查询终端属性应答 (terminal property response)
	MsgLocationReport           uint16 = 0x0200 // 位置上报 (location report)
	MsgLocationQueryResponse    uint16 = 0x0201 // 位置查询应答 (location query response)
	MsgTerminalGeneralResponse  uint16 = 0x0001 // 终端通用应答 (terminal general response)
	MsgPlatformGeneralResponse  uint16 = 0x8001 // 平台通用应答 (platform general response)
	MsgRegistrationResponse     uint16 = 0x8100 // 注册应答 (registration response)
	MsgSetTerminalParams        uint16 = 0x8103 // 设置终端参数 (set terminal parameters)
	MsgQueryTerminalParams      uint16 = 0x8104 // 查询终端参数 (query terminal parameters)
	MsgLocationQuery            uint16 = 0x8201 // 位置查询 (location query)
	MsgTextDown                 uint16 = 0x8300 // 文本下发 (text down)
)

// Procedure type strings (design §5A JT808Procedure.Type).
const (
	ProcRegister                = "register"
	ProcAuth                    = "auth"
	ProcLocationReport          = "location_report"
	ProcLocationQueryResponse   = "location_query_response"
	ProcCancel                  = "cancel"
	ProcPropertyResponse        = "property_response"
	ProcPlatformGeneralResponse = "platform_general_response"
	ProcTerminalGeneralResponse = "terminal_general_response"
	ProcRegistrationResponse    = "registration_response"
	ProcSetParams               = "set_params"
	ProcQueryParams             = "query_params"
	ProcQueryLocation           = "query_location"
	ProcTextDown                = "text_down"
)

// Header length (消息头长度): 12B without fragmentation, 16B with (design §1).
const (
	HeaderLen      = 12
	HeaderLenPkg   = 16
	PhoneLen       = 6 // BCD
	MsgSNLen       = 2 // uint16 BE
	PackageInfoLen = 4 // PackageNum(2) + PackageTotal(2)
	FrameDelimLen  = 1 // 0x7e
	ChecksumLen    = 1
)

// LicenseColor constants (design §4A.1, §5A.1).
const (
	LicenseColorNone   uint8 = 0 // 未上车牌
	LicenseColorBlue   uint8 = 1 // 蓝色
	LicenseColorYellow uint8 = 2 // 黄色 (农用)
	LicenseColorBlack  uint8 = 3 // 黑色
	LicenseColorWhite  uint8 = 4 // 白色
	LicenseColorGreen  uint8 = 5 // 绿色
	LicenseColorOther  uint8 = 9 // 其他
)

// ACKFlag values (design §7A.10): only 0-3, no 99=other.
const (
	ACKSuccess      uint8 = 0 // 成功/确认 (success)
	ACKFailure      uint8 = 1 // 失败 (failure)
	ACKMessageError uint8 = 2 // 消息有误 (message malformed)
	ACKNotSupported uint8 = 3 // 不支持 (not supported)
)

// RegistrationResult values (design §7A.9).
const (
	RegResultSuccess            uint8 = 0 // 成功 (success)
	RegResultVehicleRegistered  uint8 = 1 // 车辆已被注册 (vehicle already registered)
	RegResultVehicleNotInDB     uint8 = 2 // 数据库中无该车辆 (vehicle not in database)
	RegResultTerminalRegistered uint8 = 3 // 终端已被注册 (terminal already registered)
	RegResultTerminalNotFound   uint8 = 4 // 终端不存在 (terminal not found)
)

// Field length constants (design §4A).
const (
	ProvinceIDLen         = 2  // uint16 BE
	CityIDLen             = 2  // uint16 BE
	ManufacturerIDLen     = 5  // ASCII
	TerminalModelLen      = 20 // ASCII right-padded with 0x20
	TerminalIDLen         = 7  // ASCII
	LicenseColorLen       = 1
	IMEILen               = 15 // ASCII
	SoftwareVersionLen    = 20 // bytes
	AuthCodeMaxLen        = 16 // GBK-encoded bytes
	AlarmFlagLen          = 4  // uint32 BE
	StatusFlagLen         = 4  // uint32 BE
	LatitudeLen           = 4  // uint32 BE
	LongitudeLen          = 4  // uint32 BE
	AltitudeLen           = 2  // uint16 BE
	SpeedLen              = 2  // uint16 BE
	DirectionLen          = 2  // uint16 BE
	TimeLen               = 6  // BCD YYMMDDhhmmss
	GeneralResponseLen    = 5  // ResponseSN(2)+ResponseMsgId(2)+Result(1) -- no Phone (design §4A.7)
	RegistrationRespFixed = 3  // ResponseSN(2)+Result(1) (without AuthCode)
)

// D-JT808-1 裁定2（2026-09-21）：JT808Config 六结构迁 core/types.go
// （vnc/xmpp 先例：core 独占类型，FlowSpec/FlowMeta/parse/registry 载荷），
// 本包以类型别名承接——builder/parser/888 行 legacy 测试零改动。
// MsgId/Proc/LicenseColor 常量与 DefaultJT808Config/DefaultPort 仍住本包
// （core 不 import protocol 铁律；core parse 全 string/数值直传不需常量）。

type (
	JT808Config    = core.JT808Config
	JT808Procedure = core.JT808Procedure
	JT808Location  = core.JT808Location
	JT808Extra     = core.JT808Extra
	JT808Param     = core.JT808Param
	JT808Property  = core.JT808Property
)

// DefaultJT808Config returns a config populated with the design's defaults
// (design §7A.14 reference values). Useful for tests.
func DefaultJT808Config() *JT808Config {
	return &JT808Config{
		Phone:           "012345678901",
		Version:         jtcommon.Version2019,
		LicenseColor:    LicenseColorBlue,
		LicensePlate:    "京A12345",
		ProvinceId:      11, // 北京 (GB/T 2260)
		CityId:          0,
		ManufacturerId:  "TEST",
		TerminalModel:   "TG-DEMO",
		TerminalId:      "0000001",
		InitialSN:       0,
		AuthCode:        "ABCDEF1234567890",
		IMEI:            "012345678901234",
		SoftwareVersion: "TG-V1.0.0",
	}
}
