// Package doip implements the DOIP (Diagnostic over IP, ISO 13400-2) protocol.
package doip

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Builder builds DOIP protocol packets.
type Builder struct{}

// NewBuilder creates a new DOIP packet builder.
func NewBuilder() *Builder { return &Builder{} }

// BuildPacket builds a DOIP packet from a PacketConfig.
// The payload already contains the DoIP header + payload from the planner.
// This builder ensures the packet is properly framed.
func (b *Builder) BuildPacket(cfg core.PacketConfig) ([]byte, error) {
	// The planner already builds the full DoIP frame in the Payload field.
	// This builder just validates and returns it.
	if len(cfg.Payload) < DoIPHeaderLen {
		return nil, fmt.Errorf("doip: payload too short, minimum %d bytes for header", DoIPHeaderLen)
	}

	// Validate header consistency.
	pv := cfg.Payload[0]
	invPV := cfg.Payload[1]
	if invPV != inverseProtocolVersion(pv) {
		return nil, fmt.Errorf("doip: inverse protocol version mismatch: expected 0x%02X, got 0x%02X", inverseProtocolVersion(pv), invPV)
	}

	pt := uint16(cfg.Payload[2])<<8 | uint16(cfg.Payload[3])
	pl := uint32(cfg.Payload[4])<<24 | uint32(cfg.Payload[5])<<16 | uint32(cfg.Payload[6])<<8 | uint32(cfg.Payload[7])

	actualPL := uint32(len(cfg.Payload) - DoIPHeaderLen)
	if pl != actualPL {
		return nil, fmt.Errorf("doip: payload length mismatch: header says %d, actual %d", pl, actualPL)
	}

	// Validate payload type-specific constraints.
	switch pt {
	case PTGenericNack:
		if pl != 1 {
			return nil, fmt.Errorf("doip: 0x0000 payload length must be 1, got %d", pl)
		}
	case PTVehicleIDRequest:
		if pl != 0 {
			return nil, fmt.Errorf("doip: 0x0001 payload length must be 0, got %d", pl)
		}
	case PTVehicleIDRequestEID:
		if pl != 6 {
			return nil, fmt.Errorf("doip: 0x0002 payload length must be 6, got %d", pl)
		}
	case PTVehicleIDRequestVIN:
		if pl != 17 {
			return nil, fmt.Errorf("doip: 0x0003 payload length must be 17, got %d", pl)
		}
	case PTVehicleAnnouncement:
		if pv == ProtocolVersionV1 {
			if pl != 32 {
				return nil, fmt.Errorf("doip: 0x0004 V1 payload length must be 32, got %d", pl)
			}
		} else {
			if pl != 33 {
				return nil, fmt.Errorf("doip: 0x0004 V2 payload length must be 33, got %d", pl)
			}
		}
	case PTRoutingActivationReq:
		if pv == ProtocolVersionV1 {
			if pl != 7 {
				return nil, fmt.Errorf("doip: 0x0005 V1 payload length must be 7, got %d", pl)
			}
		} else {
			if pl < 7 {
				return nil, fmt.Errorf("doip: 0x0005 V2 payload length must be >= 7, got %d", pl)
			}
		}
	case PTRoutingActivationResp:
		if pv == ProtocolVersionV1 {
			if pl != 9 {
				return nil, fmt.Errorf("doip: 0x0006 V1 payload length must be 9, got %d", pl)
			}
		} else {
			if pl < 9 {
				return nil, fmt.Errorf("doip: 0x0006 V2 payload length must be >= 9, got %d", pl)
			}
		}
	case PTAliveCheckRequest:
		if pl != 0 {
			return nil, fmt.Errorf("doip: 0x0007 payload length must be 0, got %d", pl)
		}
	case PTAliveCheckResponse:
		if pl != 2 {
			return nil, fmt.Errorf("doip: 0x0008 payload length must be 2, got %d", pl)
		}
	case PTEntityStatusRequest:
		if pl != 0 {
			return nil, fmt.Errorf("doip: 0x4001 payload length must be 0, got %d", pl)
		}
	case PTEntityStatusResponse:
		if pl != 7 {
			return nil, fmt.Errorf("doip: 0x4002 payload length must be 7, got %d", pl)
		}
	case PTPowerModeRequest:
		if pl != 0 {
			return nil, fmt.Errorf("doip: 0x4003 payload length must be 0, got %d", pl)
		}
	case PTPowerModeResponse:
		if pl != 1 {
			return nil, fmt.Errorf("doip: 0x4004 payload length must be 1, got %d", pl)
		}
	case PTDiagnosticMessage:
		if pl < 4 {
			return nil, fmt.Errorf("doip: 0x8001 payload length must be >= 4, got %d", pl)
		}
	case PTDiagnosticMessageAck:
		if pl < 5 {
			return nil, fmt.Errorf("doip: 0x8002 payload length must be >= 5, got %d", pl)
		}
		if cfg.Payload[DoIPHeaderLen+4] != 0x00 {
			return nil, fmt.Errorf("doip: 0x8002 AckCode must be 0x00")
		}
	case PTDiagnosticMessageNack:
		if pl < 5 {
			return nil, fmt.Errorf("doip: 0x8003 payload length must be >= 5, got %d", pl)
		}
		nc := cfg.Payload[DoIPHeaderLen+4]
		if nc < 0x02 || nc > 0x08 {
			return nil, fmt.Errorf("doip: 0x8003 NackCode must be 0x02-0x08, got 0x%02X", nc)
		}
	}

	return cfg.Payload, nil
}
