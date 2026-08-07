// Package doip implements the DOIP (Diagnostic over IP, ISO 13400-2) protocol.
package doip

import (
	"fmt"
)

// Parser parses DOIP protocol packets.
type Parser struct{}

// NewParser creates a new DOIP packet parser.
func NewParser() *Parser { return &Parser{} }

// ParseResult holds the parsed DOIP packet information.
type ParseResult struct {
	ProtocolVersion        uint8
	InverseProtocolVersion uint8
	PayloadType            uint16
	PayloadLength          uint32
	Payload                []byte
}

// ParsePacket parses a raw DOIP packet.
func (p *Parser) ParsePacket(data []byte) (*ParseResult, error) {
	if len(data) < DoIPHeaderLen {
		return nil, fmt.Errorf("doip: packet too short, minimum %d bytes for header, got %d", DoIPHeaderLen, len(data))
	}

	pv := data[0]
	invPV := data[1]
	if invPV != inverseProtocolVersion(pv) {
		return nil, fmt.Errorf("doip: inverse protocol version mismatch: expected 0x%02X, got 0x%02X", inverseProtocolVersion(pv), invPV)
	}

	pt := uint16(data[2])<<8 | uint16(data[3])
	pl := uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])

	if uint32(len(data)) < DoIPHeaderLen+pl {
		return nil, fmt.Errorf("doip: packet truncated: header says payload length %d, but packet only has %d bytes total", pl, len(data))
	}

	payload := data[DoIPHeaderLen : DoIPHeaderLen+pl]

	return &ParseResult{
		ProtocolVersion:        pv,
		InverseProtocolVersion: invPV,
		PayloadType:            pt,
		PayloadLength:          pl,
		Payload:                payload,
	}, nil
}

// ParseGenericNack parses a 0x0000 Generic DoIP Header NACK payload.
func ParseGenericNack(payload []byte) (uint8, error) {
	if len(payload) != 1 {
		return 0, fmt.Errorf("doip: 0x0000 payload must be 1 byte, got %d", len(payload))
	}
	return payload[0], nil
}

// ParseVehicleAnnouncement parses a 0x0004 Vehicle Announcement payload.
func ParseVehicleAnnouncement(payload []byte, pv uint8) (vin string, logicalAddr uint16, eid, gid string, far, syncStatus uint8, err error) {
	expectedLen := 33
	if pv == ProtocolVersionV1 {
		expectedLen = 32
	}
	if len(payload) != expectedLen {
		err = fmt.Errorf("doip: 0x0004 payload must be %d bytes (V%d), got %d", expectedLen, pv, len(payload))
		return
	}

	vin = string(payload[0:17])
	logicalAddr = uint16(payload[17])<<8 | uint16(payload[18])
	eid = formatMAC(payload[19:25])
	gid = formatMAC(payload[25:31])
	far = payload[31]
	if pv != ProtocolVersionV1 {
		syncStatus = payload[32]
	}
	return
}

// ParseRoutingActivationRequest parses a 0x0005 payload.
func ParseRoutingActivationRequest(payload []byte) (sourceAddr uint16, actType uint8, oem []byte, err error) {
	if len(payload) < 7 {
		err = fmt.Errorf("doip: 0x0005 payload must be >= 7 bytes, got %d", len(payload))
		return
	}
	sourceAddr = uint16(payload[0])<<8 | uint16(payload[1])
	actType = payload[2]
	// Reserved ISO bytes at 3-6 must be 0.
	if payload[3] != 0 || payload[4] != 0 || payload[5] != 0 || payload[6] != 0 {
		err = fmt.Errorf("doip: 0x0005 reserved ISO bytes must be 0")
		return
	}
	if len(payload) > 7 {
		oem = payload[7:]
	}
	return
}

// ParseRoutingActivationResponse parses a 0x0006 payload.
func ParseRoutingActivationResponse(payload []byte) (clientLA, serverLA uint16, respCode uint8, oem []byte, err error) {
	if len(payload) < 9 {
		err = fmt.Errorf("doip: 0x0006 payload must be >= 9 bytes, got %d", len(payload))
		return
	}
	clientLA = uint16(payload[0])<<8 | uint16(payload[1])
	serverLA = uint16(payload[2])<<8 | uint16(payload[3])
	respCode = payload[4]
	// Reserved ISO bytes at 5-8 must be 0.
	if payload[5] != 0 || payload[6] != 0 || payload[7] != 0 || payload[8] != 0 {
		err = fmt.Errorf("doip: 0x0006 reserved ISO bytes must be 0")
		return
	}
	if len(payload) > 9 {
		oem = payload[9:]
	}
	return
}

// ParseAliveCheckResponse parses a 0x0008 payload.
func ParseAliveCheckResponse(payload []byte) (uint16, error) {
	if len(payload) != 2 {
		return 0, fmt.Errorf("doip: 0x0008 payload must be 2 bytes, got %d", len(payload))
	}
	return uint16(payload[0])<<8 | uint16(payload[1]), nil
}

// ParseEntityStatusResponse parses a 0x4002 payload.
func ParseEntityStatusResponse(payload []byte) (nodeType, maxOpen, curOpen uint8, maxDataSize uint32, err error) {
	if len(payload) != 7 {
		err = fmt.Errorf("doip: 0x4002 payload must be 7 bytes, got %d", len(payload))
		return
	}
	nodeType = payload[0]
	maxOpen = payload[1]
	curOpen = payload[2]
	maxDataSize = uint32(payload[3])<<24 | uint32(payload[4])<<16 | uint32(payload[5])<<8 | uint32(payload[6])
	return
}

// ParsePowerModeResponse parses a 0x4004 payload.
func ParsePowerModeResponse(payload []byte) (uint8, error) {
	if len(payload) != 1 {
		return 0, fmt.Errorf("doip: 0x4004 payload must be 1 byte, got %d", len(payload))
	}
	return payload[0], nil
}

// ParseDiagnosticMessage parses a 0x8001 payload.
func ParseDiagnosticMessage(payload []byte) (sa, ta uint16, userData []byte, err error) {
	if len(payload) < 4 {
		err = fmt.Errorf("doip: 0x8001 payload must be >= 4 bytes, got %d", len(payload))
		return
	}
	sa = uint16(payload[0])<<8 | uint16(payload[1])
	ta = uint16(payload[2])<<8 | uint16(payload[3])
	if len(payload) > 4 {
		userData = payload[4:]
	}
	return
}

// ParseDiagnosticMessageAck parses a 0x8002 payload.
func ParseDiagnosticMessageAck(payload []byte) (sa, ta uint16, ackCode uint8, prevDiag []byte, err error) {
	if len(payload) < 5 {
		err = fmt.Errorf("doip: 0x8002 payload must be >= 5 bytes, got %d", len(payload))
		return
	}
	sa = uint16(payload[0])<<8 | uint16(payload[1])
	ta = uint16(payload[2])<<8 | uint16(payload[3])
	ackCode = payload[4]
	if len(payload) > 5 {
		prevDiag = payload[5:]
	}
	return
}

// ParseDiagnosticMessageNack parses a 0x8003 payload.
func ParseDiagnosticMessageNack(payload []byte) (sa, ta uint16, nackCode uint8, prevDiag []byte, err error) {
	if len(payload) < 5 {
		err = fmt.Errorf("doip: 0x8003 payload must be >= 5 bytes, got %d", len(payload))
		return
	}
	sa = uint16(payload[0])<<8 | uint16(payload[1])
	ta = uint16(payload[2])<<8 | uint16(payload[3])
	nackCode = payload[4]
	if len(payload) > 5 {
		prevDiag = payload[5:]
	}
	return
}
