package s7

import (
	"encoding/binary"
	"fmt"
)

func BuildConnectionRequest(cfg *S7Config) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("s7: config is nil")
	}
	return []byte{0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02}, nil
}

func BuildSetup(cfg *S7Config, response bool) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("s7: config is nil")
	}
	ref := cfg.PDURef
	if ref == 0 {
		ref = 1
	}
	pdu := []byte{0x03, 0x00, 0x00, 0x19, 0x02, 0xf0, 0x80, 0x32, rosctrJob, 0x00, byte(ref >> 8), byte(ref), 0x00, 0x00, 0x08, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xe0}
	if response {
		pdu[8] = rosctrAckData
	}
	return pdu, nil
}

func BuildRead(cfg *S7Config, cmd S7Command) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("s7: config is nil")
	}
	if err := validateCommand(cmd); err != nil {
		return nil, err
	}
	ref := cmd.PDURef
	if ref == 0 {
		ref = cfg.PDURef + 1
	}
	if ref == 0 {
		ref = 1
	}
	items := cmd.Items
	body := []byte{0x03, 0x00, 0x00, 0x20, 0x02, 0xf0, 0x80, 0x32, rosctrJob, 0x00, 0x00, 0x03, 0x00, 0x00, 0x0e, 0x00, 0x01, 0x04, byte(len(items))}
	for _, item := range items {
		addr := item.Address*8 + uint32(item.Bit)
		body = append(body, 0x12, 0x0a, 0x10, item.TransportSize, byte(item.Length>>8), byte(item.Length), byte(item.DBNumber>>8), byte(item.DBNumber), item.Area, byte(addr>>16), byte(addr>>8), byte(addr), 0)
	}
	binary.BigEndian.PutUint16(body[2:4], uint16(len(body)))
	return body, nil
}

func BuildWrite(cfg *S7Config, cmd S7Command) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("s7: config is nil")
	}
	if err := validateCommand(cmd); err != nil {
		return nil, err
	}
	ref := cmd.PDURef
	if ref == 0 {
		ref = cfg.PDURef
	}
	if ref == 0 {
		ref = 1
	}
	body := []byte{0x03, 0x00, 0, 0, 0x02, 0xf0, 0x80, 0x32, rosctrJob, 0, byte(ref >> 8), byte(ref), 0, 0, 0, 14, 0, 1, 0x05, byte(len(cmd.Items))}
	for _, item := range cmd.Items {
		addr := item.Address*8 + uint32(item.Bit)
		body = append(body, 0x12, 0x0a, 0x10, item.TransportSize, byte(item.Length>>8), byte(item.Length), byte(item.DBNumber>>8), byte(item.DBNumber), item.Area, byte(addr>>16), byte(addr>>8), byte(addr), 0)
	}
	binary.BigEndian.PutUint16(body[2:4], uint16(len(body)))
	return body, nil
}

func validateCommand(cmd S7Command) error {
	if cmd.ROSCTR != 0 && cmd.ROSCTR != rosctrJob && cmd.ROSCTR != rosctrAckData {
		return fmt.Errorf("s7: rosctr %d is invalid", cmd.ROSCTR)
	}
	for _, item := range cmd.Items {
		if !validArea(item.Area) {
			return fmt.Errorf("s7: area 0x%02x is invalid", item.Area)
		}
		if item.Address > 0xFFFF {
			return fmt.Errorf("s7: address %d exceeds range", item.Address)
		}
		if item.Bit > 7 {
			return fmt.Errorf("s7: bit %d exceeds range", item.Bit)
		}
		if item.Length == 0 {
			return fmt.Errorf("s7: length must be > 0")
		}
	}
	return nil
}

func validArea(area uint8) bool {
	switch area {
	case 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x1c, 0x1d:
		return true
	}
	return false
}
