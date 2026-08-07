package jtt905

import (
	"encoding/binary"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// buildFrame assembles a complete JTT905 frame from header+body bytes.
// The frame format is identical to JT808: XOR checksum → escape → wrap
// with 0x7e (design §3C.1, §3A.3, §3A.4).
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
func buildSimpleFrame(msgID uint16, props uint16, phoneBCD []byte, msgSN uint16, body []byte) []byte {
	hdr := make([]byte, 0, 12)
	hdr = binary.BigEndian.AppendUint16(hdr, msgID)
	hdr = binary.BigEndian.AppendUint16(hdr, props)
	hdr = append(hdr, phoneBCD...)
	hdr = binary.BigEndian.AppendUint16(hdr, msgSN)
	hdrAndBody := append(hdr, body...)
	return buildFrame(hdrAndBody)
}

// buildCheckInBody constructs the 0x1001 check-in body (design §4C.2):
//
//	DriverId(20 ASCII, 0x20-padded) + DriverName(16 GBK, 0x20-padded)
//	+ LicensePlate(21 GBK, 0x20-padded) + LicenseColor(1) + OnTime(6 BCD)
//	+ VehicleModel(16 ASCII, 0x20-padded) + LoadCapacity(2 BE)
func buildCheckInBody(cfg *JTT905Config) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("jtt905: nil config")
	}
	driverName, err := jtcommon.PadRightSpaceGBK(cfg.DriverName, DriverNameLen)
	if err != nil {
		return nil, fmt.Errorf("jtt905: DriverName: %w", err)
	}
	plate, err := jtcommon.PadRightSpaceGBK(cfg.LicensePlate, LicensePlateLen)
	if err != nil {
		return nil, fmt.Errorf("jtt905: LicensePlate: %w", err)
	}
	onTime, err := jtcommon.EncodeTimeBCD(cfg.OnTime)
	if err != nil {
		return nil, fmt.Errorf("jtt905: OnTime BCD: %w", err)
	}
	body := make([]byte, 0, DriverIdLen+DriverNameLen+LicensePlateLen+LicenseColorLen+OnTimeLen+VehicleModelLen+LoadCapacityLen)
	body = append(body, jtcommon.PadRightSpace(cfg.DriverId, DriverIdLen)...)
	body = append(body, driverName...)
	body = append(body, plate...)
	body = append(body, cfg.LicenseColor)
	body = append(body, onTime...)
	body = append(body, jtcommon.PadRightSpace(cfg.VehicleModel, VehicleModelLen)...)
	body = binary.BigEndian.AppendUint16(body, cfg.LoadCapacity)
	return body, nil
}

// buildCheckOutBody constructs the 0x1002 check-out body (design §4C.3):
//
//	DriverId(20) + DriverName(16) + LicensePlate(21) + LicenseColor(1)
//	+ OffTime(6 BCD) + Mileage(4 BE) + Income(4 BE) + PassengerCount(2 BE)
func buildCheckOutBody(cfg *JTT905Config) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("jtt905: nil config")
	}
	driverName, err := jtcommon.PadRightSpaceGBK(cfg.DriverName, DriverNameLen)
	if err != nil {
		return nil, fmt.Errorf("jtt905: DriverName: %w", err)
	}
	plate, err := jtcommon.PadRightSpaceGBK(cfg.LicensePlate, LicensePlateLen)
	if err != nil {
		return nil, fmt.Errorf("jtt905: LicensePlate: %w", err)
	}
	offTime, err := jtcommon.EncodeTimeBCD(cfg.OffTime)
	if err != nil {
		return nil, fmt.Errorf("jtt905: OffTime BCD: %w", err)
	}
	body := make([]byte, 0, DriverIdLen+DriverNameLen+LicensePlateLen+LicenseColorLen+OffTimeLen+MileageLen+IncomeLen+PassengerCountLen)
	body = append(body, jtcommon.PadRightSpace(cfg.DriverId, DriverIdLen)...)
	body = append(body, driverName...)
	body = append(body, plate...)
	body = append(body, cfg.LicenseColor)
	body = append(body, offTime...)
	body = binary.BigEndian.AppendUint32(body, cfg.Mileage)
	body = binary.BigEndian.AppendUint32(body, cfg.Income)
	body = binary.BigEndian.AppendUint16(body, cfg.PassengerCount)
	return body, nil
}

// buildGeneralResponseBody constructs the 0x8001 / 0x0001 general response
// body (design §4C.4, §4C.5): ResponseSN(2) + ResponseMsgId(2) + Result(1)
// = 5 bytes. Phone is NOT included (it's in the header).
func buildGeneralResponseBody(responseSN, responseMsgID uint16, result uint8) []byte {
	body := make([]byte, 0, GeneralResponseLen)
	body = binary.BigEndian.AppendUint16(body, responseSN)
	body = binary.BigEndian.AppendUint16(body, responseMsgID)
	body = append(body, result)
	return body
}
