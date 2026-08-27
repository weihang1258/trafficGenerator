package iec104

import "github.com/trafficgen/trafficgen/internal/core"

type IEC104Config = core.IEC104Config
type IEC104Event = core.IEC104Event
type IEC104Command = core.IEC104Command

const (
	transportTCP        = "tcp"
	TypeMSpNa     uint8 = 1
	TypeMDpNa     uint8 = 3
	TypeMMeNa     uint8 = 9
	TypeMSpTb     uint8 = 30
	TypeMMeTd     uint8 = 34
	TypeCScNa     uint8 = 45
	TypeCDcTa     uint8 = 59
	TypeCICNa     uint8 = 100
	maxAPDULength       = 253
	UStartDTAct   uint8 = 0x07
	UStartDTCon   uint8 = 0x0b
	UStopDTAct    uint8 = 0x13
	UStopDTCon    uint8 = 0x23
	UTestFRAct    uint8 = 0x43
	UTestFRCon    uint8 = 0x83
)
