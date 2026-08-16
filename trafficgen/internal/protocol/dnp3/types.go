// Package dnp3 implements IEEE 1815-2012 DNP3 framing and planning.
package dnp3

const (
	DefaultPort = 20000
	DefaultTTL  = 64
	DefaultMSS  = 1460

	Start1        = 0x05
	Start2        = 0x64
	LinkHeaderLen = 10
	MaxLinkLength = 255
	MaxAppData    = 225
)

// Link-layer function codes.
const (
	LinkReset          uint8 = 0
	LinkNACK           uint8 = 1
	LinkStatus         uint8 = 2
	LinkUserConfirm    uint8 = 3
	LinkUserNoConfirm  uint8 = 4
	LinkRequestStatus  uint8 = 9
	LinkNotSupported   uint8 = 11
)

// Application-layer function codes.
const (
	AppRead                  uint8 = 1
	AppWrite                 uint8 = 2
	AppSelect                uint8 = 3
	AppOperate               uint8 = 4
	AppDirectOperate         uint8 = 5
	AppDirectOperateNoAck    uint8 = 6
	AppFreeze                uint8 = 7
	AppFreezeNoAck           uint8 = 8
	AppFreezeClear           uint8 = 9
	AppFreezeClearNoAck      uint8 = 10
	AppRespond               uint8 = 0x81 // 129: IEEE 1815-2012
	AppUnsolicitedRespond    uint8 = 0x82 // 130: IEEE 1815-2012
	AppConfirm               uint8 = 0x00 // IEEE 1815-2012
	AppEnableUnsolicited     uint8 = 20
	AppDisableUnsolicited    uint8 = 21
	AppAssignClass           uint8 = 22
	AppDelayMeasurement      uint8 = 23
	AppRecordCurrentTime     uint8 = 24
	AppColdRestart           uint8 = 0x0D // 13: IEEE 1815-2012
	AppWarmRestart           uint8 = 0x0E // 14: IEEE 1815-2012
	AppInitializeData        uint8 = 131
	AppInitializeApplication uint8 = 132
)

var appFunctions = map[string]uint8{
	"read": AppRead, "write": AppWrite, "select": AppSelect,
	"operate": AppOperate, "direct_operate": AppDirectOperate,
	"direct_operate_no_ack": AppDirectOperateNoAck, "freeze": AppFreeze,
	"freeze_no_ack": AppFreezeNoAck, "freeze_clear": AppFreezeClear,
	"freeze_clear_no_ack": AppFreezeClearNoAck, "respond": AppRespond,
	"unsolicited_respond": AppUnsolicitedRespond, "confirm": AppConfirm,
	"enable_unsolicited": AppEnableUnsolicited,
	"disable_unsolicited": AppDisableUnsolicited, "assign_class": AppAssignClass,
	"delay_measurement": AppDelayMeasurement,
	"record_current_time": AppRecordCurrentTime, "cold_restart": AppColdRestart,
	"warm_restart": AppWarmRestart, "initialize_data": AppInitializeData,
	"initialize_application": AppInitializeApplication,
}

// CROB is the wire value of Object 12 Variation 1.
type CROB struct {
	Code    uint8
	Count   uint8
	OnTime  uint16
	OffTime uint16
	Status  *uint8
}

// LinkFrame is a parsed DNP3 data-link frame.
type LinkFrame struct {
	Length  uint8
	Control uint8
	DstAddr uint16
	SrcAddr uint16
	Data    []byte
}

// AppFrame is a parsed DNP3 application frame.
type AppFrame struct {
	Control      uint8
	FunctionCode uint8
	IIN          uint16
	HasIIN       bool
	Objects      []ParsedObject
}

// ParsedObject contains one parsed object header and its remaining wire data.
type ParsedObject struct {
	ObjectType uint8
	Variation  uint8
	Qualifier  uint8
	Start      uint16
	Stop       uint16
	Count      uint16
	Data       []byte
}
