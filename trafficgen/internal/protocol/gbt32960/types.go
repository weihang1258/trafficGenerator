// Package gbt32960 implements the GB/T 32960.3-2016 protocol planner
// (电动汽车远程服务与管理系统技术规范 第3部分：通讯协议, Electric
// Vehicle Remote Service and Management System — Part 3: Communication
// Protocol).
//
// A single GBT32960 flow models ONE vehicle (or one platform-as-client
// session) over one TCP 4-tuple. Multi-vehicle scenarios use multiple
// FlowSpecs, each with a unique VIN and a distinct 4-tuple (see design
// §7.11).
//
// Wire format (design §2.1): every message is
//
//	start_flag(2B 0x23 0x23) | cmd(1B) | resp(1B) | VIN(17B) |
//	encrypt(1B) | data_len(2B big-endian) | data(N) | BCC(1B)
//
// Total length = 25 + N bytes. The planner emits a TCP handshake, the
// GBT32960 message sequence (each message as one PSH-ACK payload), and a
// TCP teardown — all within one flow.
package gbt32960

import (
	"github.com/trafficgen/trafficgen/internal/core"
)

// Type aliases — the GBT32960 config types live in core/types.go (so
// FlowSpec.GBT32960 can reference them without an import cycle). These
// aliases let the rest of this package refer to the types by their
// unqualified names (e.g. GBT32960Config instead of core.GBT32960Config).
type (
	GBT32960Config        = core.GBT32960Config
	GBT32960Report        = core.GBT32960Report
	GBT32960AlarmData     = core.GBT32960AlarmData
	GBT32960RemoteControl = core.GBT32960RemoteControl
	GBT32960PlatformLogin = core.GBT32960PlatformLogin
	GBT32960StatusChange  = core.GBT32960StatusChange
)

// Constants for the GBT32960 protocol (design appendix A).
const (
	// DefaultPort (默认端口) — platform-side listener.
	DefaultPort = 10020

	// DefaultTTL (默认TTL) used when spec.TTL is zero.
	DefaultTTL = 64

	// DefaultMSS (默认MSS) mirrors internal/protocol/tcp.DefaultMSS (1460).
	DefaultMSS = 1460

	// MinMSS (最小MSS) per RFC 879 (design V27).
	MinMSS = 536

	// StartFlag (起始符) is the fixed 2-byte ASCII `##` (0x23 0x23).
	StartFlag0 = 0x23
	StartFlag1 = 0x23

	// VINLen (VIN 长度) — 17 bytes per §2.3.
	VINLen = 17

	// SIMLen (SIM/ICCID 长度) — 20 bytes per §3.1.
	SIMLen = 20

	// HeaderLen (报文头长度) = 2 + 1 + 1 + 17 + 1 + 2 = 24 bytes.
	HeaderLen = 24

	// BCCLen (校验码长度) — 1 byte.
	BCCLen = 1

	// DataUnitMaxLen (数据单元长度上限) — 65531 (65532-65535 reserved).
	DataUnitMaxLen = 65531

	// LoginDataBase (0x01 数据单元基础长度) = 6+2+20+1+1 = 30 (excl n×m codes).
	LoginDataBase = 30

	// LogoutDataLen (0x04 数据单元长度) = 6+2 = 8 bytes per §3.4.
	LogoutDataLen = 8

	// RealtimeDataBase (0x02 数据单元基础长度) = 6 bytes collect time.
	RealtimeDataBase = 6

	// PlatformLoginDataLen (0x05 数据单元长度) = 12+20+16 = 48 per §3.5.
	PlatformLoginDataLen = 48

	// Command units (命令单元, design §1.3).
	CmdVehicleLogin   = 0x01 // 车辆登入
	CmdRealtimeReport = 0x02 // 实时信息上报
	CmdReissueReport  = 0x03 // 补报信息上报
	CmdVehicleLogout  = 0x04 // 车辆登出
	CmdPlatformLogin  = 0x05 // 平台登入
	CmdPlatformLogout = 0x06 // 平台登出
	CmdReissueReq     = 0x07 // 补发请求
	CmdControl        = 0x08 // 控制命令
	CmdParamQuery     = 0x09 // 参数查询
	CmdParamSet       = 0x0A // 参数设置
	CmdHeartbeat      = 0x0B // 平台心跳
	CmdAck            = 0x0C // 平台确认

	// Response flags (应答标志, design §1.4).
	// 0xFE = uplink messages (and 0x0C header) always.
	// 0x01-0x04 are written into the NEXT uplink message's resp field
	// (NOT into the 0x0C header/data unit — see §3.12).
	RespSuccess = 0x01 // 成功
	RespError   = 0x02 // 错误
	RespVINDup  = 0x03 // VIN 重复 (VIN duplicated)
	RespNotSupp = 0x04 // 命令不支持
	RespNone    = 0xFE // 上行报文 / 0x0C 报文头恒 0xFE

	// Encrypt rules (数据加密方式, design §2.2).
	EncNone   = 0x01 // 不加密
	EncRSA    = 0x02 // RSA
	EncAES128 = 0x03 // AES128
	EncSM2    = 0x04 // SM2
	EncSM4    = 0x05 // SM4

	// InfoTypeVehicleData (信息类型 0x01 整车数据) — 18-byte info body.
	InfoTypeVehicleData = 0x01
	// InfoTypeVehiclePos (信息类型 0x05 车辆位置) — 9-byte info body
	// (1 status + 4 lon + 4 lat, NO speed per design §3.2).
	InfoTypeVehiclePos = 0x05
	// InfoTypeAlarm (信息类型 0x07 报警数据) — 5-byte info body
	// (1 level + 4 flags big-endian).
	InfoTypeAlarm = 0x07

	// VehicleDataBodyLen (整车数据信息体长度) — 18 bytes per §3.2.
	VehicleDataBodyLen = 18
	// VehiclePosBodyLen (车辆位置信息体长度) — 9 bytes per §3.2.
	VehiclePosBodyLen = 9
	// AlarmBodyLen (报警信息体长度) — 5 bytes per §3.2.1.
	AlarmBodyLen = 5

	// SerialMaxPerDay (登入流水号上限) per §3.1 (65531, wraps to 1).
	SerialMaxPerDay = 65531
)
