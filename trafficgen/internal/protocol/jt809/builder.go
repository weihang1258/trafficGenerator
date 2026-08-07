package jt809

import (
	"encoding/binary"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/protocol/jt808"
	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// buildHeader constructs the JT809 32-byte fixed header (design §3B.1):
//
//	MsgLength(4 BE) + MsgSN(4 BE) + MsgId(2 BE) +
//	VehicleColor(1) + VehiclePlate(21 GBK, 0x20-padded)
//
// MsgLength is the TOTAL length (header + body, including the MsgLength
// field itself). The caller passes the body so we can compute the length.
func buildHeader(msgSN uint32, msgID uint16, vehicleColor uint8, vehiclePlate string, body []byte) ([]byte, error) {
	totalLen := HeaderLen + len(body)
	h := make([]byte, 0, HeaderLen)
	h = binary.BigEndian.AppendUint32(h, uint32(totalLen))
	h = binary.BigEndian.AppendUint32(h, msgSN)
	h = binary.BigEndian.AppendUint16(h, msgID)
	h = append(h, vehicleColor)
	plate, err := jtcommon.PadRightSpaceGBK(vehiclePlate, VehiclePlateLen)
	if err != nil {
		return nil, fmt.Errorf("jt809: VehiclePlate: %w", err)
	}
	h = append(h, plate...)
	return h, nil
}

// buildFrame assembles a complete JT809 message: header (32B) + body.
// JT809 has NO start/end delimiter and NO escape and NO checksum
// (design §1, §3B).
func buildFrame(msgSN uint32, msgID uint16, vehicleColor uint8, vehiclePlate string, body []byte) ([]byte, error) {
	hdr, err := buildHeader(msgSN, msgID, vehicleColor, vehiclePlate, body)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(hdr)+len(body))
	out = append(out, hdr...)
	out = append(out, body...)
	return out, nil
}

// buildLoginBody constructs the 0x1001 / 0x9001 login body (design §4B.1,
// §4B.8): UserName(5) + Password(10) + GNSSCenterId(4) + VersionFlag(1) +
// EncryptFlag(1) + EncryptKey(4) = 25 bytes. No LinkFlag field (H-01).
func buildLoginBody(cfg *JT809Config) []byte {
	body := make([]byte, 0, LoginBodyLen)
	body = append(body, jtcommon.PadRightZeroASCII(cfg.UserName, 5)...)
	body = append(body, jtcommon.PadRightZeroASCII(cfg.Password, 10)...)
	body = binary.BigEndian.AppendUint32(body, cfg.GNSSCenterId)
	body = append(body, cfg.VersionFlag)
	body = append(body, cfg.EncryptFlag)
	body = binary.BigEndian.AppendUint32(body, cfg.EncryptKey)
	return body
}

// buildLoginRespBody constructs the 0x1002 / 0x9002 login response body
// (design §4B.2, §4B.9): Result(1) + GNSSCenterId(4) = 5 bytes.
// No ResponseSN field (C-04).
func buildLoginRespBody(result uint8, gnssCenterId uint32) []byte {
	body := make([]byte, 0, LoginRespBodyLen)
	body = append(body, result)
	body = binary.BigEndian.AppendUint32(body, gnssCenterId)
	return body
}

// buildDisconnectNoticeBody constructs the 0x1007 body (design §4B.4):
// ReasonCode(1) + GNSSCenterId(4).
func buildDisconnectNoticeBody(reason uint8, gnssCenterId uint32) []byte {
	body := make([]byte, 0, 5)
	body = append(body, reason)
	body = binary.BigEndian.AppendUint32(body, gnssCenterId)
	return body
}

// buildContainerBody constructs a 0x1200/0x1300/0x1500/0x1600/0x9100/0x9600
// container body (design §4B.5, §4B.6, §4B.12, §4B.13, §4B.10, §4B.11):
//
//	SubMsgId(1) + SubLength(2 BE) + SubBody
//
// SubLength is the length of SubBody only (NOT including SubMsgId +
// SubLength itself).
func buildContainerBody(subMsgId uint8, subBody []byte) []byte {
	body := make([]byte, 0, 3+len(subBody))
	body = append(body, subMsgId)
	body = binary.BigEndian.AppendUint16(body, uint16(len(subBody)))
	body = append(body, subBody...)
	return body
}

// buildVehicleRegisterSubBody constructs the 0x1201 SubBody (design §4B.5):
// TerminalPhone(6 BCD) + ManufacturerId(5 ASCII) + TerminalModel(20) +
// TerminalId(7). 38 bytes total. Does NOT repeat VehicleColor/VehiclePlate
// (those are in the 0x1200 header — design C-02).
func buildVehicleRegisterSubBody(phoneBCD, manufacturerId, terminalModel, terminalId []byte) []byte {
	body := make([]byte, 0, 38)
	body = append(body, phoneBCD...)
	body = append(body, manufacturerId...)
	body = append(body, terminalModel...)
	body = append(body, terminalId...)
	return body
}

// buildRealtimeLocationSubBody reuses the JT808 0x0200 location body
// layout (design §4B.5 0x1202). Calls jt808's builder via the exported
// BuildLocationBody helper.
func buildRealtimeLocationSubBody(loc *jt808.JT808Location) ([]byte, error) {
	return jt808.BuildLocationBody(loc)
}

// buildAlarmSubBody constructs the 0x1208 alarm SubBody (design §4B.5):
// AlarmFlag(4 BE) + PulseSpeed(2 BE) + remaining 0x0200 location fields
// (StatusFlag onwards — AlarmFlag is NOT repeated since 0x1208 already
// carries its own AlarmFlag at the head). The result is:
//
//	AlarmFlag(4) + PulseSpeed(2) + StatusFlag(4) + Lat(4) + Lon(4) +
//	Alt(2) + Speed(2) + Direction(2) + Time(6) + ExtraItems(variable)
func buildAlarmSubBody(alarmFlag uint32, pulseSpeed uint16, loc *jt808.JT808Location) ([]byte, error) {
	body := make([]byte, 0, 6+24)
	body = binary.BigEndian.AppendUint32(body, alarmFlag)
	body = binary.BigEndian.AppendUint16(body, pulseSpeed)
	if loc != nil {
		locBody, err := jt808.BuildLocationBody(loc)
		if err != nil {
			return nil, err
		}
		// Skip the first 4 bytes (locBody starts with AlarmFlag which we
		// already wrote above); append StatusFlag onwards.
		const alarmFlagSize = 4
		if len(locBody) > alarmFlagSize {
			body = append(body, locBody[alarmFlagSize:]...)
		}
	}
	return body, nil
}

// buildAlarmWithAttachmentBody constructs the 0x1400 body (design §4B.7):
// AlarmFlag(4) + AlarmTime(6 BCD) + AlarmInfo(variable) + FileType(1) +
// FileUrl(variable GBK, max 256B).
//
// AlarmInfo is variable-length with no length prefix — the design's
// example treats it as a GBK string terminated by FileType. We encode
// AlarmInfo as GBK with no length prefix and rely on the receiver
// parsing FileType as the last byte. For test purposes, AlarmInfo is
// passed as raw bytes via the SubBody field on the procedure.
func buildAlarmWithAttachmentBody(alarmFlag uint32, alarmTime string, alarmInfo []byte, fileType uint8, fileUrl string) ([]byte, error) {
	timeBCD, err := jtcommon.EncodeTimeBCD(alarmTime)
	if err != nil {
		return nil, fmt.Errorf("jt809: AlarmTime BCD: %w", err)
	}
	body := make([]byte, 0, 4+6+len(alarmInfo)+1+256)
	body = binary.BigEndian.AppendUint32(body, alarmFlag)
	body = append(body, timeBCD...)
	body = append(body, alarmInfo...)
	body = append(body, fileType)
	if fileType != FileTypeNone {
		url, err := jtcommon.GBKEncode(fileUrl)
		if err != nil {
			return nil, fmt.Errorf("jt809: FileUrl GBK: %w", err)
		}
		if len(url) > 256 {
			return nil, fmt.Errorf("jt809: FileUrl GBK length %d > 256", len(url))
		}
		body = append(body, url...)
	}
	return body, nil
}

// buildVehicleDirectionSubBody constructs 0x1205 SubBody (design §4B.5):
// TerminalPhone(6 BCD) + Direction(2 BE).
func buildVehicleDirectionSubBody(phoneBCD []byte, direction uint16) []byte {
	body := make([]byte, 0, 8)
	body = append(body, phoneBCD...)
	body = binary.BigEndian.AppendUint16(body, direction)
	return body
}

// buildAreaVehicleSubBody constructs 0x1206 SubBody (design §4B.5):
// TerminalPhone(6 BCD) + AreaType(1) + AreaData(variable).
func buildAreaVehicleSubBody(phoneBCD []byte, areaType uint8, areaData []byte) []byte {
	body := make([]byte, 0, 7+len(areaData))
	body = append(body, phoneBCD...)
	body = append(body, areaType)
	body = append(body, areaData...)
	return body
}

// buildPathRecordSubBody constructs 0x1207 SubBody (design §4B.5):
// TerminalPhone(6 BCD) + PathCount(2 BE) + PathPoints(variable).
func buildPathRecordSubBody(phoneBCD []byte, pathCount uint16, pathPoints []byte) []byte {
	body := make([]byte, 0, 8+len(pathPoints))
	body = append(body, phoneBCD...)
	body = binary.BigEndian.AppendUint16(body, pathCount)
	body = append(body, pathPoints...)
	return body
}

// buildEventReportSubBody constructs 0x1209 SubBody (design §4B.5):
// TerminalPhone(6 BCD) + EventId(2 BE) + EventTime(6 BCD).
func buildEventReportSubBody(phoneBCD []byte, eventId uint16, eventTime string) ([]byte, error) {
	timeBCD, err := jtcommon.EncodeTimeBCD(eventTime)
	if err != nil {
		return nil, fmt.Errorf("jt809: EventTime BCD: %w", err)
	}
	body := make([]byte, 0, 14)
	body = append(body, phoneBCD...)
	body = binary.BigEndian.AppendUint16(body, eventId)
	body = append(body, timeBCD...)
	return body, nil
}

// buildVehicleLogoutSubBody constructs 0x120A SubBody (design §4B.5):
// TerminalPhone(6 BCD).
func buildVehicleLogoutSubBody(phoneBCD []byte) []byte {
	body := make([]byte, 0, 6)
	body = append(body, phoneBCD...)
	return body
}

// buildAlarmAttachmentSubBody constructs 0x1204 SubBody (design §4B.5):
// AlarmFlag(4) + AlarmTime(6 BCD) + AlarmInfo(variable) + FileType(1) +
// FileSize(4 BE) + FileUrl(variable GBK, max 256B).
func buildAlarmAttachmentSubBody(alarmFlag uint32, alarmTime string, alarmInfo []byte, fileType uint8, fileSize uint32, fileUrl string) ([]byte, error) {
	timeBCD, err := jtcommon.EncodeTimeBCD(alarmTime)
	if err != nil {
		return nil, fmt.Errorf("jt809: AlarmTime BCD: %w", err)
	}
	body := make([]byte, 0, 4+6+len(alarmInfo)+1+4+256)
	body = binary.BigEndian.AppendUint32(body, alarmFlag)
	body = append(body, timeBCD...)
	body = append(body, alarmInfo...)
	body = append(body, fileType)
	body = binary.BigEndian.AppendUint32(body, fileSize)
	if fileType != FileTypeNone {
		url, err := jtcommon.GBKEncode(fileUrl)
		if err != nil {
			return nil, fmt.Errorf("jt809: FileUrl GBK: %w", err)
		}
		if len(url) > 256 {
			return nil, fmt.Errorf("jt809: FileUrl GBK length %d > 256", len(url))
		}
		body = append(body, url...)
	}
	return body, nil
}
