// Package enip implements the EtherNet/IP (ENIP) protocol planner.
// Reference: ODVA EtherNet/IP Volume 1 & 2, CIP Common Specification,
// OpENer source/src/cip/ciptypes.h, source/src/enet_encap/cpf.h.
//
// ENIP encapsulates CIP (Common Industrial Protocol) over TCP/UDP port 44818.
// All multi-byte fields are little-endian (LE). The ENIP encapsulation header
// is fixed 24 bytes: Command(2) + Length(2) + SessionHandle(4) + Status(4) +
// SenderContext(8) + Options(4).
//
// Type definitions (ENIPConfig, ENIPCommand, CPFItem, ENIPSubRequest,
// ENIPIOData) live in internal/core/types.go so they can be referenced by
// core.FlowSpec. This file provides package-level aliases for convenience.
package enip

import (
	"github.com/trafficgen/trafficgen/internal/core"
)

// Type aliases for convenience — the canonical definitions live in
// internal/core/types.go so they can be embedded in core.FlowSpec.
type (
	// Config is an alias for core.ENIPConfig.
	Config = core.ENIPConfig
	// Command is an alias for core.ENIPCommand.
	Command = core.ENIPCommand
	// Item is an alias for core.CPFItem (CPF item).
	Item = core.CPFItem
	// SubRequest is an alias for core.ENIPSubRequest.
	SubRequest = core.ENIPSubRequest
	// IOData is an alias for core.ENIPIOData.
	IOData = core.ENIPIOData
)
