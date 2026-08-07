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
	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// Default port (默认端口) for JT808 (design §1).
const DefaultPort = 7611

// MsgId constants (design §4A).
const (
	MsgTerminalRegister           uint16 = 0x0100 // 终端注册 (terminal registration)
	MsgTerminalAuth               uint16 = 0x0102 // 终端鉴权 (terminal authentication)
	MsgTerminalCancel             uint16 = 0x0003 // 终端注销 (terminal cancel)
	MsgTerminalPropertyResponse   uint16 = 0x0107 // 查询终端属性应答 (terminal property response)
	MsgLocationReport             uint16 = 0x0200 // 位置上报 (location report)
	MsgLocationQueryResponse      uint16 = 0x0201 // 位置查询应答 (location query response)
	MsgTerminalGeneralResponse    uint16 = 0x0001 // 终端通用应答 (terminal general response)
	MsgPlatformGeneralResponse    uint16 = 0x8001 // 平台通用应答 (platform general response)
	MsgRegistrationResponse       uint16 = 0x8100 // 注册应答 (registration response)
	MsgSetTerminalParams          uint16 = 0x8103 // 设置终端参数 (set terminal parameters)
	MsgQueryTerminalParams        uint16 = 0x8104 // 查询终端参数 (query terminal parameters)
	MsgLocationQuery              uint16 = 0x8201 // 位置查询 (location query)
	MsgTextDown                   uint16 = 0x8300 // 文本下发 (text down)
)

// Procedure type strings (design §5A JT808Procedure.Type).
const (
	ProcRegister                 = "register"
	ProcAuth                     = "auth"
	ProcLocationReport           = "location_report"
	ProcLocationQueryResponse     = "location_query_response"
	ProcCancel                   = "cancel"
	ProcPropertyResponse         = "property_response"
	ProcPlatformGeneralResponse  = "platform_general_response"
	ProcTerminalGeneralResponse  = "terminal_general_response"
	ProcRegistrationResponse     = "registration_response"
	ProcSetParams                = "set_params"
	ProcQueryParams              = "query_params"
	ProcQueryLocation            = "query_location"
	ProcTextDown                 = "text_down"
)

// Header length (消息头长度): 12B without fragmentation, 16B with (design §1).
const (
	HeaderLen        = 12
	HeaderLenPkg     = 16
	PhoneLen         = 6  // BCD
	MsgSNLen         = 2  // uint16 BE
	PackageInfoLen   = 4  // PackageNum(2) + PackageTotal(2)
	FrameDelimLen    = 1  // 0x7e
	ChecksumLen      = 1
)

// LicenseColor constants (design §4A.1, §5A.1).
const (
	LicenseColorNone    uint8 = 0 // 未上车牌
	LicenseColorBlue    uint8 = 1 // 蓝色
	LicenseColorYellow  uint8 = 2 // 黄色 (农用)
	LicenseColorBlack   uint8 = 3 // 黑色
	LicenseColorWhite   uint8 = 4 // 白色
	LicenseColorGreen   uint8 = 5 // 绿色
	LicenseColorOther   uint8 = 9 // 其他
)

// ACKFlag values (design §7A.10): only 0-3, no 99=other.
const (
	ACKSuccess       uint8 = 0 // 成功/确认 (success)
	ACKFailure       uint8 = 1 // 失败 (failure)
	ACKMessageError  uint8 = 2 // 消息有误 (message malformed)
	ACKNotSupported  uint8 = 3 // 不支持 (not supported)
)

// RegistrationResult values (design §7A.9).
const (
	RegResultSuccess              uint8 = 0 // 成功 (success)
	RegResultVehicleRegistered    uint8 = 1 // 车辆已被注册 (vehicle already registered)
	RegResultVehicleNotInDB       uint8 = 2 // 数据库中无该车辆 (vehicle not in database)
	RegResultTerminalRegistered  uint8 = 3 // 终端已被注册 (terminal already registered)
	RegResultTerminalNotFound     uint8 = 4 // 终端不存在 (terminal not found)
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

// JT808Config configures a JT/T 808-2019 vehicle-terminal session. It is
// the local equivalent of the design's FlowSpec.JT808 field; trafficgen's
// core/types.go integration is deferred to the main agent (rule: do NOT
// modify core/* files).
//
// All fields mirror design §5A exactly. Validate enforces §5A.1.
type JT808Config struct {
	// Phone (终端手机号) — 12-digit BCD. Must match ^\d{12}$. Required.
	Phone string `json:"phone"`

	// Version (版本标志) — "2011" | "2013" | "2019" (default). Affects
	// MsgBodyProps bits 10-12.
	Version string `json:"version,omitempty"`

	// EncryptFlag (加密标志) — 0=plain (default), 1=encrypted (placeholder;
	// trafficgen does NOT implement real encryption per design §14).
	EncryptFlag uint8 `json:"encrypt_flag,omitempty"`

	// LicenseColor (车牌颜色) 0-5, 9. 0 means no plate; LicensePlate MUST
	// then be empty.
	LicenseColor uint8 `json:"license_color,omitempty"`

	// LicensePlate (车牌号) GBK-encoded, only when LicenseColor != 0.
	LicensePlate string `json:"license_plate,omitempty"`

	// ProvinceId / CityId (省域/市域 ID) for 0x0100 registration.
	ProvinceId uint16 `json:"province_id,omitempty"`
	CityId     uint16 `json:"city_id,omitempty"`

	// ManufacturerId (制造商ID) 5 ASCII chars, default "TEST".
	ManufacturerId string `json:"manufacturer_id,omitempty"`

	// TerminalModel (终端型号) up to 20 bytes, default "TG-DEMO".
	TerminalModel string `json:"terminal_model,omitempty"`

	// TerminalId (终端ID) 7 bytes, default "0000001".
	TerminalId string `json:"terminal_id,omitempty"`

	// TerminalType (终端类型) for 0x0107 property response, 0-2.
	TerminalType uint8 `json:"terminal_type,omitempty"`

	// InitialSN (起始流水号) for the per-flow MsgSN counter. Each subsequent
	// message increments by 1, wrapping at 65535.
	InitialSN uint16 `json:"initial_sn,omitempty"`

	// PlatformInitialSN (平台侧起始流水号) for platformMsgSN. Default 0.
	// Per-Terminal independent counter; NOT tied to InitialSN (design §6A.2).
	PlatformInitialSN uint16 `json:"platform_initial_sn,omitempty"`

	// AuthCode (鉴权码) for 0x0102. Must be 1-16 bytes GBK after encoding.
	AuthCode string `json:"auth_code,omitempty"`

	// IMEI (终端IMEI) for 0x0102 auth body. 15 ASCII chars.
	IMEI string `json:"imei,omitempty"`

	// SoftwareVersion (软件版本号) for 0x0102. 20 bytes ASCII/GBK.
	SoftwareVersion string `json:"software_version,omitempty"`

	// RegistrationResult (注册应答结果) for 0x8100. 0=success (default),
	// 1-4=fail. When non-zero, AuthCode is omitted.
	RegistrationResult uint8 `json:"registration_result,omitempty"`

	// Procedures (业务流程) ordered list of JT808 messages to emit.
	Procedures []JT808Procedure `json:"procedures"`
}

// JT808Procedure is one step in a JT808 session (design §5A).
type JT808Procedure struct {
	// Type selects the message template (see Proc* constants).
	Type string `json:"type"`

	// ACKFlag (通用应答标志) for general_response / registration_response.
	// 0/1/2/3 only.
	ACKFlag uint8 `json:"ack_flag,omitempty"`

	// LocationData for "location_report" / "location_query_response".
	LocationData *JT808Location `json:"location_data,omitempty"`

	// ResponseSN for general_response / registration_response /
	// location_query_response. When 0, auto-bound to the matching upstream
	// SN (design §5A M-05).
	ResponseSN uint16 `json:"response_sn,omitempty"`

	// ResponseMsgId for "general_response". When 0, auto-bound.
	ResponseMsgId uint16 `json:"response_msg_id,omitempty"`

	// RegistrationResult per-procedure override for "registration_response".
	RegistrationResult *uint8 `json:"registration_result,omitempty"`

	// AuthCode per-procedure override for "registration_response" when
	// result=0.
	AuthCode string `json:"auth_code,omitempty"`

	// IMEI per-procedure override for "auth".
	IMEI *string `json:"imei,omitempty"`

	// SoftwareVersion per-procedure override for "auth".
	SoftwareVersion *string `json:"software_version,omitempty"`

	// Text (文本内容) for "text_down", GBK.
	Text string `json:"text,omitempty"`

	// TextFlag (文本标志) for "text_down", 0-3 (bit flags).
	TextFlag uint8 `json:"text_flag,omitempty"`

	// Params (参数列表) for "set_params": TLV items.
	Params []JT808Param `json:"params,omitempty"`

	// PropertyData (终端属性) for "property_response".
	PropertyData *JT808Property `json:"property_data,omitempty"`
}

// JT808Location models the 0x0200 location body (design §4A.3).
type JT808Location struct {
	AlarmFlag  uint32 `json:"alarm_flag"`
	StatusFlag uint32 `json:"status_flag"`
	Latitude   uint32 `json:"latitude"`  // 1e-6 deg
	Longitude  uint32 `json:"longitude"`  // 1e-6 deg
	Altitude   uint16 `json:"altitude"`   // m
	Speed      uint16 `json:"speed"`      // 0.1 km/h
	Direction  uint16 `json:"direction"` // 0-359
	Time       string `json:"time"`      // "YYMMDDhhmmss" (BCD-encoded by planner)
	ExtraItems []JT808Extra `json:"extra_items,omitempty"`

	// Bit-level convenience fields (扩展表 2). When non-nil, the planner
	// OR-merges them into StatusFlag before encoding (design §5A H-05).
	// StatusFlag (when set directly) takes precedence; these are OR-merged
	// on top. nil = not applied.
	ACC         *bool `json:"acc,omitempty"`         // bit0
	DoorStatus  *bool `json:"door_status,omitempty"` // bit1
	OilCircuit  *bool `json:"oil_circuit,omitempty"` // bit2
	RunStatus   *bool `json:"run_status,omitempty"` // alias of ACC
}

// JT808Extra is one TLV extra item (design §4A.3).
type JT808Extra struct {
	Type   uint8  `json:"type"`
	Length uint8  `json:"length,omitempty"` // auto-computed by planner
	Value  []byte `json:"value"`
}

// JT808Param is one TLV param item for 0x8103 (design §4A.9).
type JT808Param struct {
	Id    uint8  `json:"id"`
	Value []byte `json:"value"`
}

// JT808Property models the 0x0107 terminal property response (design §4A.6).
type JT808Property struct {
	DeviceType      uint8  `json:"device_type"`
	ManufacturerId  string `json:"manufacturer_id"`
	TerminalModel   string `json:"terminal_model"`
	TerminalId      string `json:"terminal_id"`
	IccId           string `json:"icc_id"`
	Imei            string `json:"imei"`
	SoftwareVersion string `json:"software_version"`
	GnssModule      uint8  `json:"gnss_module"`
	CommModule      uint8  `json:"comm_module"`
	ProvinceId      uint16 `json:"province_id"`
	CityId          uint16 `json:"city_id"`
	CountyId        uint16 `json:"county_id"`
	TownId          uint16 `json:"town_id"`
	Operator        uint8  `json:"operator"`
	APN             string `json:"apn"`
	HardwareVersion string `json:"hardware_version"`
	MaxSpeed        uint16 `json:"max_speed"`
}

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
