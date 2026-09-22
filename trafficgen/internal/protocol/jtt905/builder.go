package jtt905

import (
	"encoding/binary"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// buildFrame assembles one complete JTT905 wire frame（裁定1，jtcommon
// 808 族原语复用）：XOR 对未转义头+体计算 → 转义（含校验码与头内特殊
// 字节——金向量 MsgNum=007E 上线 7D02 实证）→ 7E 定界。
func buildFrame(headerAndBody []byte) []byte {
	cs := jtcommon.XORChecksum(headerAndBody)
	withCS := append(append([]byte{}, headerAndBody...), cs)
	escaped := jtcommon.Escape(withCS)
	out := make([]byte, 0, len(escaped)+2)
	out = append(out, jtcommon.FrameDelimiter)
	out = append(out, escaped...)
	out = append(out, jtcommon.FrameDelimiter)
	return out
}

// buildSimpleFrame constructs one non-fragmented JTT905 frame.
// 消息头 12B：MsgId(2)+DataLength(2)=**纯消息体长度**（裁定1：金向量
// 0x0023=35 实证，无 808 式版本/加密/分包位）+ISU(BCD6)+MsgNum(2)。
func buildSimpleFrame(msgID uint16, body []byte, isuBCD []byte, msgNum uint16) ([]byte, error) {
	if len(isuBCD) != ISUIdLen {
		return nil, fmt.Errorf("jtt905: ISU BCD %d bytes, want %d", len(isuBCD), ISUIdLen)
	}
	hdr := make([]byte, 0, HeaderLen)
	hdr = binary.BigEndian.AppendUint16(hdr, msgID)
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(len(body)))
	hdr = append(hdr, isuBCD...)
	hdr = binary.BigEndian.AppendUint16(hdr, msgNum)
	return buildFrame(append(hdr, body...)), nil
}

// buildPosition encodes the 0x0200 位置基本体 25B（裁定3：报警4+状态4+
// 纬4+经4+速2+向1+时间 BCD6；方向 1B 金向量算术钉死；附加列表 B′）。
func buildPosition(pos *JTT905Position) ([]byte, error) {
	if pos == nil {
		return nil, fmt.Errorf("jtt905: nil position")
	}
	b := make([]byte, 0, PositionLen)
	b = binary.BigEndian.AppendUint32(b, pos.AlarmFlag)
	b = binary.BigEndian.AppendUint32(b, pos.StatusFlag)
	b = binary.BigEndian.AppendUint32(b, pos.Lat)
	b = binary.BigEndian.AppendUint32(b, pos.Lng)
	b = binary.BigEndian.AppendUint16(b, pos.Speed)
	b = append(b, pos.Direction)
	t := pos.Time
	if t == "" {
		t = "000000000000"
	}
	tb, err := jtcommon.BCDEncode(t)
	if err != nil {
		return nil, fmt.Errorf("jtt905: position time: %w", err)
	}
	if len(tb) != 6 {
		return nil, fmt.Errorf("jtt905: position time %q must be 12 digits", t)
	}
	return append(b, tb...), nil
}

// bcdField encodes a fixed-width BCD digit string（0x0B04 位数族）.
// 空=全 0；位数错报错（T-13 锚面）。
func bcdField(v string, digits int, name string) ([]byte, error) {
	if v == "" {
		v = padZeros(digits)
	}
	if len(v) != digits {
		return nil, fmt.Errorf("jtt905: %s %q must be %d digits", name, v, digits)
	}
	b, err := jtcommon.BCDEncode(v)
	if err != nil {
		return nil, fmt.Errorf("jtt905: %s: %w", name, err)
	}
	return b, nil
}

// timeField encodes a yyyyMMddHHmm 12-digit BCD6 time（0x0B03/0x0B04）.
func timeField(v, name string) ([]byte, error) {
	if v == "" {
		v = "000000000000"
	}
	if len(v) != 12 {
		return nil, fmt.Errorf("jtt905: %s %q must be 12 digits (yyyyMMddHHmm)", name, v)
	}
	b, err := jtcommon.BCDEncode(v)
	if err != nil {
		return nil, fmt.Errorf("jtt905: %s: %w", name, err)
	}
	return b, nil
}

func padZeros(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = '0'
	}
	return string(out)
}

// buildCheckInBody 0x0B03 上班签到体（裁定3）：Position?(25B)+license16
// \0补+qual19 \0补+plate6 \0补+uptime BCD6(yyyyMMddHHmm)。
func buildCheckInBody(cfg *JTT905Config) ([]byte, error) {
	b := make([]byte, 0, PositionLen+LicenseLen+QualCodeLen+PlateLen+TimeLen)
	if cfg.Position != nil {
		pos, err := buildPosition(cfg.Position)
		if err != nil {
			return nil, err
		}
		b = append(b, pos...)
	}
	b = append(b, jtcommon.PadRightZeroASCII(cfg.BusinessLicense, LicenseLen)...)
	b = append(b, jtcommon.PadRightZeroASCII(cfg.QualificationCode, QualCodeLen)...)
	b = append(b, jtcommon.PadRightZeroASCII(cfg.PlateNo, PlateLen)...)
	t, err := timeField(cfg.OnDutyPowerOnTime, "Uptime")
	if err != nil {
		return nil, err
	}
	return append(b, t...), nil
}

// buildCheckOutBody 0x0B04 下班签退体（裁定3）：Position?+license16+
// qual19+plate6+K值2+开机6+关机6+里程3+运营里程3+车次2+计时3+总金额3+
// 卡金额3+卡次2+班间里程2+总里程4+总运营里程4+单价2+总次数4+签退方式1。
func buildCheckOutBody(cfg *JTT905Config) ([]byte, error) {
	b := make([]byte, 0, 128)
	if cfg.Position != nil {
		pos, err := buildPosition(cfg.Position)
		if err != nil {
			return nil, err
		}
		b = append(b, pos...)
	}
	b = append(b, jtcommon.PadRightZeroASCII(cfg.BusinessLicense, LicenseLen)...)
	b = append(b, jtcommon.PadRightZeroASCII(cfg.QualificationCode, QualCodeLen)...)
	b = append(b, jtcommon.PadRightZeroASCII(cfg.PlateNo, PlateLen)...)
	for _, f := range []struct {
		v   string
		n   int
		key string
	}{
		{cfg.TaximeterKValue, 4, "TaximeterKValue"},
	} {
		fb, err := bcdField(f.v, f.n, f.key)
		if err != nil {
			return nil, err
		}
		b = append(b, fb...)
	}
	on, err := timeField(cfg.OnDutyPowerOnTime, "OnDutyPowerOnTime")
	if err != nil {
		return nil, err
	}
	off, err := timeField(cfg.OnDutyPowerOffTime, "OnDutyPowerOffTime")
	if err != nil {
		return nil, err
	}
	b = append(b, on...)
	b = append(b, off...)
	for _, f := range []struct {
		v   string
		n   int
		key string
	}{
		{cfg.OnDutyMileage, 6, "OnDutyMileage"},
		{cfg.OnDutyOperationMileage, 6, "OnDutyOperationMileage"},
		{cfg.TrainNumber, 4, "TrainNumber"},
		{cfg.TimingTime, 6, "TimingTime"},
		{cfg.TotalAmount, 6, "TotalAmount"},
		{cfg.CardAmount, 6, "CardAmount"},
		{cfg.CardCount, 4, "CardCount"},
		{cfg.OnDutyMileageBetween, 4, "OnDutyMileageBetween"},
		{cfg.TotalMileage, 8, "TotalMileage"},
		{cfg.TotalOperationMileage, 8, "TotalOperationMileage"},
		{cfg.UnitPrice, 4, "UnitPrice"},
	} {
		fb, err := bcdField(f.v, f.n, f.key)
		if err != nil {
			return nil, err
		}
		b = append(b, fb...)
	}
	b = binary.BigEndian.AppendUint32(b, cfg.TotalOperations)
	b = append(b, cfg.SignType)
	return b, nil
}

// buildGeneralResponseBody 0x0001/0x8001 通用应答体：ReplySN(2)+ReplyMsgId(2)+Result(1)。
func buildGeneralResponseBody(replySN, replyMsgID uint16, result uint8) []byte {
	b := make([]byte, 0, GeneralRespLen)
	b = binary.BigEndian.AppendUint16(b, replySN)
	b = binary.BigEndian.AppendUint16(b, replyMsgID)
	return append(b, result)
}
