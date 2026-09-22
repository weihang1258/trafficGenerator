// Package jtt905 implements the JT/T 905.2-2014 taxi ISU protocol
// (出租汽车服务管理信息系统 运营专用设备——ISU 与中心通信协议). A single
// JTT905 flow models ONE taxi ISU session over one TCP 4-tuple (default
// port 10700): 上班签到(0x0B03) → 心跳保活(0x0002)+中心应答(0x8001) →
// 下班签退(0x0B04).
//
// 线面=808 族（D-JTT905-1 裁定1）：`7E`+转义(头 12B+体+XOR(1))+`7E`，
// jtcommon XORChecksum/Escape 复用；DataLength=纯消息体长度（金向量
// 0x0023=35 实证，无版本/加密/分包位）。MsgId 空间按 SmallChi/JT905
// 对照表重排（legacy 虚构 0x1001/0x1002 废弃，真=0x0B03/0x0B04）。
package jtt905

import (
	"github.com/trafficgen/trafficgen/internal/core"
)

// Config/procedure/position types live in core（jt808/809 先例）.
type (
	JTT905Config    = core.JTT905Config
	JTT905Procedure = core.JTT905Procedure
	JTT905Position  = core.JTT905Position
)

// Default port (legacy 自选缺省；标准未定端口，如实注记).
const DefaultPort = 10700

// Envelope constants（808 族，jtcommon 复用）.
const (
	HeaderLen      = 12 // MsgId2+DataLength2+ISU6+MsgNum2
	ChecksumLen    = 1
	ISUIdLen       = 6  // BCD，12 位数字
	LicenseLen     = 16 // ASCII \0 补
	QualCodeLen    = 19 // ASCII \0 补
	PlateLen       = 6  // ASCII \0 补
	TimeLen        = 6  // BCD yyyyMMddHHmm（12 位）
	PositionLen    = 25 // 0x0200 基础位
	GeneralRespLen = 5  // ReplySN2+ReplyMsgId2+Result1
)

// MsgId constants（D-JTT905-1 裁定2，SmallChi/JT905 对照表实名）.
const (
	MsgISUGeneralResponse uint16 = 0x0001 // ISU 通用应答 (ISU→中心)
	MsgHeartbeat          uint16 = 0x0002 // ISU 心跳 (ISU→中心)
	MsgCheckIn            uint16 = 0x0B03 // 上班签到信息上传 (ISU→中心)
	MsgCheckOut           uint16 = 0x0B04 // 下班签退信息上传 (ISU→中心)
	MsgCenterGeneralResp  uint16 = 0x8001 // 中心通用应答 (中心→ISU)
)

// Procedure type strings（裁定2 5 型；legacy 虚构 0x1001/0x1002 废弃）.
const (
	ProcCheckIn               = "check_in"
	ProcHeartbeat             = "heartbeat"
	ProcCheckOut              = "check_out"
	ProcCenterGeneralResponse = "center_general_response"
	ProcISUGeneralResponse    = "isu_general_response"
)

// msgTypeByName maps procedure type → (MsgId, direction, ISU-side counter).
var msgTypeByName = map[string]struct {
	id        uint16
	down      bool // true=中心→ISU（下行，走 PlatformInitialSN 计数器）
	isuCenter bool // true=ISU 侧（InitialSN 计数器）
}{
	ProcCheckIn:               {MsgCheckIn, false, true},
	ProcHeartbeat:             {MsgHeartbeat, false, true},
	ProcCheckOut:              {MsgCheckOut, false, true},
	ProcISUGeneralResponse:    {MsgISUGeneralResponse, false, true},
	ProcCenterGeneralResponse: {MsgCenterGeneralResp, true, false},
}

// DefaultJTT905Config returns a config with reference values
// (isu_id=103456789012——金向量同号，自动会话签到→心跳→签退).
func DefaultJTT905Config() *JTT905Config {
	return &JTT905Config{
		ISUId:             "103456789012",
		BusinessLicense:   "BUSLIC0000000000",
		QualificationCode: "QUAL000000000000000",
		PlateNo:           "A12345", // 0x0B03/0B04 车牌位=ASCII 6B（WriteASCII 实录，汉字不入）
		HeartbeatCount:    1,
	}
}
