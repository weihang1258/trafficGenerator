package iec104

import (
	"encoding/binary"
	"fmt"
	"time"
)

func BuildUFrame(control uint8) ([]byte, error) {
	switch control {
	case UStartDTAct, UStartDTCon, UStopDTAct, UStopDTCon, UTestFRAct, UTestFRCon:
	default:
		return nil, fmt.Errorf("iec104: invalid U-frame control 0x%02x", control)
	}
	return []byte{0x68, 0x04, control, 0, 0, 0}, nil
}

func BuildSFrame(rx uint16) ([]byte, error) {
	if rx > 32767 {
		return nil, fmt.Errorf("iec104: receive sequence %d exceeds 15-bit range", rx)
	}
	b := []byte{0x68, 0x04, 0x01, 0, 0, 0}
	binary.LittleEndian.PutUint16(b[4:6], rx<<1)
	return b, nil
}

func BuildInformation(cfg *IEC104Config, tx, rx uint16) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("iec104: config is nil")
	}
	if tx > 32767 || rx > 32767 {
		return nil, fmt.Errorf("iec104: sequence exceeds 15-bit range")
	}
	asdu, err := buildASDU(cfg)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 6, 6+len(asdu))
	b[0], b[1] = 0x68, byte(4+len(asdu))
	binary.LittleEndian.PutUint16(b[2:4], tx<<1)
	binary.LittleEndian.PutUint16(b[4:6], rx<<1)
	return append(b, asdu...), nil
}

func buildASDU(cfg *IEC104Config) ([]byte, error) {
	if !validType(cfg.TypeID) {
		return nil, fmt.Errorf("iec104: invalid type %d", cfg.TypeID)
	}
	if cfg.Cause == 0 || cfg.Cause > 63 {
		return nil, fmt.Errorf("iec104: invalid cause %d", cfg.Cause)
	}
	if cfg.InformationObjectAddress > 0xffffff {
		return nil, fmt.Errorf("iec104: IOA %d exceeds 24-bit range", cfg.InformationObjectAddress)
	}
	out := []byte{cfg.TypeID, 1, cfg.Cause, 0}
	out = binary.LittleEndian.AppendUint16(out, cfg.CommonAddress)
	out = append(out, byte(cfg.InformationObjectAddress), byte(cfg.InformationObjectAddress>>8), byte(cfg.InformationObjectAddress>>16))
	switch cfg.TypeID {
	case TypeMSpNa:
		out = append(out, cfg.SIQ)
	case TypeMDpNa:
		out = append(out, cfg.DIQ)
	case TypeMMeNa:
		out = binary.LittleEndian.AppendUint16(out, uint16(cfg.Value))
		out = append(out, cfg.QDS)
	case TypeMSpTb:
		out = append(out, cfg.SIQ)
		stamp, err := encodeCP56Time2a(cfg.Time)
		if err != nil {
			return nil, err
		}
		out = append(out, stamp...)
	case TypeMMeTd:
		out = binary.LittleEndian.AppendUint16(out, uint16(cfg.Value))
		out = append(out, cfg.QDS)
		stamp, err := encodeCP56Time2a(cfg.Time)
		if err != nil {
			return nil, err
		}
		out = append(out, stamp...)
	case TypeCScNa:
		sco := cfg.SCO
		if sco == 0 {
			sco = byte(cfg.Value)
		}
		if cfg.Select {
			sco |= 0x80
		}
		out = append(out, sco)
	case TypeCDcTa:
		dco := cfg.DCO
		if dco == 0 {
			dco = byte(cfg.Value)
		}
		out = append(out, dco)
		stamp, err := encodeCP56Time2a(cfg.Time)
		if err != nil {
			return nil, err
		}
		out = append(out, stamp...)
	case TypeCICNa:
		out = append(out, cfg.QOI)
	}
	return out, nil
}

func encodeCP56Time2a(value string) ([]byte, error) {
	if value == "" {
		return make([]byte, 7), nil
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return nil, fmt.Errorf("iec104: invalid CP56Time2a time %q: %w", value, err)
	}
	ms := t.Nanosecond()/1e6 + t.Second()*1000
	out := make([]byte, 7)
	binary.LittleEndian.PutUint16(out[0:2], uint16(ms))
	out[2] = byte(t.Minute())
	out[3] = byte(t.Hour())
	out[4] = byte(t.Day())
	out[5] = byte(int(t.Month()) | (int(t.Weekday()) << 5))
	out[6] = byte(t.Year() - 2000)
	return out, nil
}

func validType(t uint8) bool {
	switch t {
	case TypeMSpNa, TypeMDpNa, TypeMMeNa, TypeMSpTb, TypeMMeTd, TypeCScNa, TypeCDcTa, TypeCICNa:
		return true
	}
	return false
}
