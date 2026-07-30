// Package ike implements the IKE/IKEv2 protocol planner (RFC 7296).
//
// IKEv2（互联网密钥交换协议第 2 版，Internet Key Exchange Protocol
// Version 2）is a stateful key-exchange protocol used to negotiate IPsec
//（互联网协议安全，Internet Protocol Security）Security Associations（安全关联，
// SA). It runs over UDP port 500 (RFC 8229 TCP/4500 and IKE-NAT-T/4500 are
// rejected by this planner — the design_ike.md §1.1 mandate).
//
// The planner synthesizes wire-format-compliant IKE messages: 28-byte IKE
// Header（IKE 头，SPIi/SPIr/Next Payload/Version/Exchange Type/Flags/Message
// ID/Length), 4-byte Generic Payload Header（通用载荷头）, and one of the 18
// known payload types (RFC 7296 §3.2). It performs NO real cryptography —
// SK（加密且认证载荷，Encrypted and Authenticated）/SKF（加密且认证分片）bodies
// are filled with deterministic pseudo-bytes derived from OpaqueKeySeed.
//
// Transport follows the existing UDP-planner pattern (syslog/ntp/snmp):
// every IKEMessage becomes one UDP PacketConfig（包配置）on the configured
// 4-tuple with L2/L3 carried by core.L3Base + core.EtherTypeFor.
//
// Design reference: /tmp/l7_planner_design/design_ike.md
// Test reference: /tmp/l7_planner_design/testcases_ike.md
package ike

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Constants per RFC 7296 §3.1 (IKE Header field values).
const (
	// IKEHeaderLen is the fixed IKE Header size (28 bytes).
	IKEHeaderLen = 28

	// GenericHeaderLen is the fixed Generic Payload Header size (4 bytes).
	GenericHeaderLen = 4

	// FlagInitiator (I) marks a message from the original initiator.
	FlagInitiator uint8 = 0x08
	// FlagVersion (V) marks support for a higher major version.
	FlagVersion uint8 = 0x10
	// FlagResponse (R) marks a response (vs. request).
	FlagResponse uint8 = 0x20

	// Payload type wire values (RFC 7296 §3.2). NOTE: the user's original
	// task list mislabeled 34 as Proposal and 35 as Transform; those are
	// substructures of SA, not top-level payloads. We emit the IANA-true
	// values: 34=KE, 35=IDi. Any "33=Proposal"/"34=Transform" input is
	// rejected by Validate (see testcase 4.3.x).
	PayloadSA     uint8 = 33
	PayloadKE     uint8 = 34
	PayloadIDi    uint8 = 35
	PayloadIDr    uint8 = 36
	PayloadCERT   uint8 = 37
	PayloadCERTREQ uint8 = 38
	PayloadAUTH   uint8 = 39
	PayloadNONCE  uint8 = 40
	PayloadNOTIFY uint8 = 41
	PayloadDELETE uint8 = 42
	PayloadVENDOR uint8 = 43
	PayloadTSi    uint8 = 44
	PayloadTSr    uint8 = 45
	PayloadSK     uint8 = 46
	PayloadCP     uint8 = 47
	PayloadEAP    uint8 = 48
	PayloadSKF    uint8 = 53

	// Exchange Type wire values (RFC 7296 §3.1 + RFC 8784 + session resume).
	ExchangeIKE_SA_INIT        uint8 = 34
	ExchangeIKE_SA_AUTH        uint8 = 35
	ExchangeCREATE_CHILD_SA    uint8 = 36
	ExchangeINFORMATIONAL      uint8 = 37
	ExchangeIKE_SESSION_RESUME uint8 = 38
	ExchangeIKE_INTERMEDIATE   uint8 = 43

	// Transform Type wire values (RFC 7296 §3.3.2).
	TransformENCR uint8 = 1
	TransformPRF  uint8 = 2
	TransformINTEG uint8 = 3
	TransformDH   uint8 = 4
	TransformESN  uint8 = 5

	// Protocol ID values inside SA / NOTIFY / DELETE payloads.
	ProtocolNone uint8 = 0
	ProtocolIKE  uint8 = 1
	ProtocolAH   uint8 = 2
	ProtocolESP  uint8 = 3

	// Default ports per design_ike.md §6.1.
	DefaultPort     uint16 = 500
	ForbiddenSrcPort uint16 = 500

	// Default sizes per design_ike.md §6.2 / §8.
	DefaultDHGroup         uint16 = 14 // 2048-bit MODP
	DefaultNonceSize       uint16 = 32 // bytes, range 16..256
	DefaultIVLength        uint16 = 16
	DefaultICVLength       uint16 = 16
	DefaultFragmentThreshold uint16 = 1200

	// Hard upper bound for OpaqueData length to keep a single IKE message
	// under typical MTU when fragmentation is enabled. We still emit
	// multiple SKF payloads beyond this.
	MaxSingleOpaqueBytes = 60000

	// --- ESP data-plane constants (RFC 4303) ---

	// ProtocolESPData is the IP protocol number for ESP (50, RFC 4303).
	// Named ProtocolESPData to avoid collision with the SA-payload
	// ProtocolESP (3) constant used inside IKE Proposal substructures.
	ProtocolESPData uint8 = 50

	// DefaultESPIVLength is the default ESP IV length (AES-CBC, 16 bytes).
	DefaultESPIVLength = 16

	// DefaultESPICVLength is the default ESP ICV length (HMAC-SHA-256-128,
	// 16 bytes).
	DefaultESPICVLength = 16

	// DefaultESPInnerPayloadSize is the default inner payload data size.
	DefaultESPInnerPayloadSize = 100

	// DefaultESPSPI is the auto-assigned ESP SPI when SPI=0 is configured.
	// (SPI=0 is rejected at validation; this is the fallback for unset.)
	DefaultESPSPI uint32 = 0xDEADBEEF

	// IPProtoIPv4Encap is the Next Header value for IPv4-in-IPv4 tunnel
	// mode (RFC 2003 §3.1). In ESP tunnel mode, NextHeader=4 tells the
	// receiver that the decrypted payload starts with an IPv4 header.
	IPProtoIPv4Encap uint8 = 4
)

// Default NONCE / AUTH data sizes when the user doesn't override.
const (
	defaultAuthDataBytes  = 32
	defaultCertDataBytes  = 32
	defaultVendorIDBytes  = 16
	defaultKEKeyDataBytes = 256 // DH Group 14 (2048-bit MODP) expects 256-byte public value
)

// Planner is the IKEv2 protocol planner.
type Planner struct{}

// NewPlanner returns a new IKEv2 planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "ike" }

// Validate validates an IKE FlowSpec. Defaults are NOT applied here (per
// validate_conventions.md §1.3); they are applied in Plan. Validation is
// read-only.
//
// Hard rejections (always):
//   - missing IKEConfig, bad SrcIP/DstIP, DstPort != 500, SrcPort == 500
//   - EncryptionMode other than "" or "opaque" (real crypto not implemented)
//   - Scenario and Messages both set
//
// Strict-only rejections (only when Strict=true and !FaultInjection):
//   - Invalid Exchange Type (not in 34-38 or 43)
//   - Invalid IKE Version (not 2.0 in IKEv2 mode)
//   - Malformed payload field values (Nonce length, payload counts, etc.)
//   - Mixing IKEv2 messages with IKEv1 (Version 1.0)
//
// FaultInjection bypasses strict checks for Raw*Override and known-invalid
// fields, but still validates wire-shape basics (length >= 4 for Generic
// Header, payload type validity, etc.).
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("ike: SrcIP %q not a valid IP", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("ike: DstIP %q not a valid IP", spec.DstIP)
		}
	}
	// RFC 8229: IKE over TCP/4500 is rejected. design_ike.md §1.1.
	if spec.DstPort != 0 && spec.DstPort != DefaultPort {
		return fmt.Errorf("ike: DstPort %d invalid (must be 0 or %d per RFC 7296 §1.2; RFC 8229 TCP/4500 is not implemented)", spec.DstPort, DefaultPort)
	}
	if spec.SrcPort == ForbiddenSrcPort {
		return fmt.Errorf("ike: SrcPort %d is reserved (IKE server port; client must use ephemeral >1024)", spec.SrcPort)
	}
	if spec.IKE == nil {
		return fmt.Errorf("ike: IKE config is required")
	}
	cfg := spec.IKE

	// Version + role defaults (only the structural ones — strict checks are
	// per-message).
	if cfg.Role != "" && cfg.Role != "initiator" && cfg.Role != "responder" {
		return fmt.Errorf("ike: Role %q invalid (must be 'initiator' or 'responder')", cfg.Role)
	}
	// EncryptMode: only "opaque" (default) is accepted.
	if cfg.EncryptMode != "" && cfg.EncryptMode != "opaque" {
		return fmt.Errorf("ike: EncryptMode %q invalid (only 'opaque' is implemented; real crypto is out of scope)", cfg.EncryptMode)
	}

	// Scenario + Messages both set → reject (would conflict).
	if cfg.Scenario != "" && len(cfg.Messages) > 0 {
		return fmt.Errorf("ike: Scenario %q and Messages (%d) cannot both be set", cfg.Scenario, len(cfg.Messages))
	}

	// Validate each user-supplied IKEMessage.
	role := cfg.Role
	if role == "" {
		role = "initiator"
	}
	msgStrict := cfg.Strict
	for i := range cfg.Messages {
		if err := validateIKEMessage(&cfg.Messages[i], role, msgStrict, cfg.FaultInjection); err != nil {
			return fmt.Errorf("ike: Messages[%d]: %w", i, err)
		}
	}

	// Validate scenario name (if set).
	if cfg.Scenario != "" {
		switch cfg.Scenario {
		case "standard_v2", "eap_md5", "eap_tls", "eap_only", "multiple_child_sa",
			"child_rekey", "ike_rekey", "dpd", "delete_sa", "informational",
			"nat_detection", "fragmented_auth", "rekey", "invalid_ke_retry",
			"cookie_retry", "cert_chain", "ppk", "null_auth", "session_resume",
			"ikev1":
			// Known scenario.
		default:
			return fmt.Errorf("ike: Scenario %q unknown", cfg.Scenario)
		}
	}

	// Validate DefaultProposal (if set).
	if cfg.DefaultProposal != nil {
		if err := validateProposal(cfg.DefaultProposal, cfg.Strict, cfg.FaultInjection); err != nil {
			return fmt.Errorf("ike: DefaultProposal: %w", err)
		}
	}

	// Validate each child SA definition.
	for i := range cfg.ChildSAs {
		cs := &cfg.ChildSAs[i]
		if cs.Proposal != nil {
			if err := validateProposal(cs.Proposal, cfg.Strict, cfg.FaultInjection); err != nil {
				return fmt.Errorf("ike: ChildSAs[%d].Proposal: %w", i, err)
			}
		}
		for j := range cs.TSi {
			if err := validateTS(&cs.TSi[j], cfg.Strict, cfg.FaultInjection); err != nil {
				return fmt.Errorf("ike: ChildSAs[%d].TSi[%d]: %w", i, j, err)
			}
		}
		for j := range cs.TSr {
			if err := validateTS(&cs.TSr[j], cfg.Strict, cfg.FaultInjection); err != nil {
				return fmt.Errorf("ike: ChildSAs[%d].TSr[%d]: %w", i, j, err)
			}
		}
	}

	// Validate ESP data-plane configuration (if set).
	if cfg.ESPDataPlane != nil {
		if err := validateESPDataPlane(cfg.ESPDataPlane); err != nil {
			return fmt.Errorf("ike: ESPDataPlane: %w", err)
		}
	}

	return nil
}

// validateESPDataPlane validates the ESP data-plane configuration per
// RFC 4303. SPI must be non-zero (§2.1), mode must be tunnel/transport (§2.4/
// §2.6), inner IPs must be valid for tunnel mode, and direction must be
// up/down/empty.
func validateESPDataPlane(esp *core.ESPDataPlaneConfig) error {
	if esp == nil {
		return nil
	}
	if esp.SPI == 0 {
		return fmt.Errorf("SPI=0 is reserved (RFC 4303 §2.1); set a non-zero value or omit for auto")
	}
	if esp.Count < 0 {
		return fmt.Errorf("Count %d must be >= 0", esp.Count)
	}
	mode := esp.Mode
	if mode == "" {
		mode = "tunnel"
	}
	if mode != "tunnel" && mode != "transport" {
		return fmt.Errorf("Mode %q invalid (must be 'tunnel' or 'transport')", esp.Mode)
	}
	if esp.Direction != "" && esp.Direction != "up" && esp.Direction != "down" {
		return fmt.Errorf("Direction %q invalid (must be 'up' or 'down')", esp.Direction)
	}
	if mode == "tunnel" {
		if esp.InnerSrcIP != "" && net.ParseIP(esp.InnerSrcIP) == nil {
			return fmt.Errorf("InnerSrcIP %q not a valid IP", esp.InnerSrcIP)
		}
		if esp.InnerDstIP != "" && net.ParseIP(esp.InnerDstIP) == nil {
			return fmt.Errorf("InnerDstIP %q not a valid IP", esp.InnerDstIP)
		}
	}
	return nil
}
func validateIKEMessage(m *core.IKEMessage, role string, strict, fault bool) error {
	// Direction: "up" or "down".
	if m.Direction != "up" && m.Direction != "down" {
		return fmt.Errorf("Direction %q invalid (must be 'up' or 'down')", m.Direction)
	}

	// Exchange Type. 34/35/36/37/38 standard; 43 extension.
	if strict {
		switch m.ExchangeType {
		case ExchangeIKE_SA_INIT, ExchangeIKE_SA_AUTH, ExchangeCREATE_CHILD_SA,
			ExchangeINFORMATIONAL, ExchangeIKE_SESSION_RESUME, ExchangeIKE_INTERMEDIATE:
			// ok
		default:
			return fmt.Errorf("ExchangeType %d not a known value (strict mode allows 34-38 or 43 only)", m.ExchangeType)
		}
	}

	// MessageID: nil = derive. If set, must be in 0..0xFFFFFFFF.
	if m.MessageID != nil {
		id := *m.MessageID
		if id > 0xFFFFFFFF {
			return fmt.Errorf("MessageID %d out of uint32 range", id)
		}
	}

	// Fault-only fields: if not fault mode, Raw overrides must be nil.
	if !fault {
		if m.RawLengthOverride != nil {
			return fmt.Errorf("RawLengthOverride set without FaultInjection=true")
		}
		if m.RawNextPayloadOverride != nil {
			return fmt.Errorf("RawNextPayloadOverride set without FaultInjection=true")
		}
		if m.RawFlagsOverride != nil {
			return fmt.Errorf("RawFlagsOverride set without FaultInjection=true")
		}
	}

	// Validate each payload.
	for i := range m.Payloads {
		if err := validateIKEPayload(&m.Payloads[i], strict, fault); err != nil {
			return fmt.Errorf("Payloads[%d]: %w", i, err)
		}
	}
	if m.Encrypted != nil {
		for i := range m.Encrypted.InnerPayloads {
			if err := validateIKEPayload(&m.Encrypted.InnerPayloads[i], strict, fault); err != nil {
				return fmt.Errorf("Encrypted.InnerPayloads[%d]: %w", i, err)
			}
		}
	}

	return nil
}

// validateIKEPayload validates a single IKEPayload.
func validateIKEPayload(p *core.IKEPayload, strict, fault bool) error {
	// Fault mode: Raw+Raw*Override allow unknown type. Otherwise type must
	// be one of the 18 known values (or any uint8 in fault mode).
	knownType := false
	switch p.Type {
	case PayloadSA, PayloadKE, PayloadIDi, PayloadIDr, PayloadCERT, PayloadCERTREQ,
		PayloadAUTH, PayloadNONCE, PayloadNOTIFY, PayloadDELETE, PayloadVENDOR,
		PayloadTSi, PayloadTSr, PayloadSK, PayloadCP, PayloadEAP, PayloadSKF:
		knownType = true
	}
	if !knownType && !fault {
		return fmt.Errorf("Type %d unknown (set FaultInjection=true to permit)", p.Type)
	}

	// Raw*Override requires fault.
	if !fault {
		if p.RawLengthOverride != nil || p.RawNextPayloadOverride != nil {
			return fmt.Errorf("RawLengthOverride/RawNextPayloadOverride require FaultInjection=true")
		}
	}

	if strict {
		// Each typed substruct must be set iff its Type is the matching one.
		// We don't enforce strict 1-of-1 here; instead, fields that contradict
		// the Type are rejected.
		switch p.Type {
		case PayloadSA:
			if p.SA == nil {
				return fmt.Errorf("SA payload (Type 33) requires SA field")
			}
			for i := range p.SA.Proposals {
				if err := validateProposal(&p.SA.Proposals[i], strict, fault); err != nil {
					return fmt.Errorf("SA.Proposals[%d]: %w", i, err)
				}
			}
		case PayloadKE:
			if p.KE == nil {
				return fmt.Errorf("KE payload (Type 34) requires KE field")
			}
		case PayloadIDi, PayloadIDr:
			if p.ID == nil {
				return fmt.Errorf("ID payload (Type %d) requires ID field", p.Type)
			}
		case PayloadCERT:
			if p.Certificate == nil {
				return fmt.Errorf("CERT payload (Type 37) requires Certificate field")
			}
		case PayloadCERTREQ:
			if p.CertificateRequest == nil {
				return fmt.Errorf("CERTREQ payload (Type 38) requires CertificateRequest field")
			}
		case PayloadAUTH:
			if p.Auth == nil {
				return fmt.Errorf("AUTH payload (Type 39) requires Auth field")
			}
		case PayloadNONCE:
			if len(p.Nonce) < 16 || len(p.Nonce) > 256 {
				return fmt.Errorf("NONCE payload length %d out of range [16..256] (RFC 7296 §3.9)", len(p.Nonce))
			}
		case PayloadNOTIFY:
			if p.Notify == nil {
				return fmt.Errorf("NOTIFY payload (Type 41) requires Notify field")
			}
			if err := validateNotify(p.Notify, strict); err != nil {
				return err
			}
		case PayloadDELETE:
			if p.Delete == nil {
				return fmt.Errorf("DELETE payload (Type 42) requires Delete field")
			}
			if err := validateDelete(p.Delete, strict); err != nil {
				return err
			}
		case PayloadVENDOR:
			if len(p.VendorID) == 0 {
				return fmt.Errorf("VENDOR payload (Type 43) requires non-empty VendorID")
			}
		case PayloadTSi, PayloadTSr:
			if len(p.TrafficSelectors) == 0 {
				return fmt.Errorf("TS payload (Type %d) requires at least one TrafficSelector", p.Type)
			}
			for i := range p.TrafficSelectors {
				if err := validateTS(&p.TrafficSelectors[i], strict, fault); err != nil {
					return fmt.Errorf("TrafficSelectors[%d]: %w", i, err)
				}
			}
		case PayloadSK:
			// SK in a cleartext payload chain only appears in fault-injection
			// scenarios. The message-level Encrypted field produces the SK
			// wrapper for legitimate IKE_SA_AUTH/INFORMATIONAL/CREATE_CHILD_SA
			// messages. There is no per-payload SK substruct in core types.
			if strict {
				return fmt.Errorf("SK payload (Type 46) in cleartext Payloads chain is invalid - set message-level Encrypted instead")
			}
		case PayloadCP:
			if p.Config == nil {
				return fmt.Errorf("CP payload (Type 47) requires Config field")
			}
		case PayloadEAP:
			if p.EAP == nil {
				return fmt.Errorf("EAP payload (Type 48) requires EAP field")
			}
			if err := validateEAP(p.EAP, strict); err != nil {
				return err
			}
		case PayloadSKF:
			if p.Fragment == nil {
				return fmt.Errorf("SKF payload (Type 53) requires Fragment field")
			}
			if p.Fragment.FragmentNumber == 0 {
				return fmt.Errorf("SKF FragmentNumber must be >= 1")
			}
			if p.Fragment.TotalFragments == 0 {
				return fmt.Errorf("SKF TotalFragments must be >= 1")
			}
			if p.Fragment.FragmentNumber > p.Fragment.TotalFragments {
				return fmt.Errorf("SKF FragmentNumber %d > TotalFragments %d", p.Fragment.FragmentNumber, p.Fragment.TotalFragments)
			}
		}
	}

	// Non-strict checks that always apply (structural correctness).
	if p.ID != nil {
		if p.ID.IDType != 1 && p.ID.IDType != 2 && p.ID.IDType != 3 && p.ID.IDType != 5 && p.ID.IDType != 11 {
			if strict {
				return fmt.Errorf("ID Type %d invalid (RFC 7296 §3.5)", p.ID.IDType)
			}
		}
		if len(p.ID.Data) == 0 {
			return fmt.Errorf("ID Data must be non-empty")
		}
	}
	if p.Auth != nil && strict {
		switch p.Auth.Method {
		case 1, 2, 9, 13:
			// ok
		default:
			return fmt.Errorf("AUTH Method %d invalid (RFC 7296 §3.10 / RFC 7619 §2.2)", p.Auth.Method)
		}
	}
	if p.EAP != nil {
		if p.EAP.Code < 1 || p.EAP.Code > 4 {
			if strict {
				return fmt.Errorf("EAP Code %d invalid (RFC 3748: 1-4)", p.EAP.Code)
			}
		}
	}
	return nil
}

// validateNotify checks NOTIFY payload invariants.
func validateNotify(n *core.IKENotify, strict bool) error {
	if strict {
		// SPI Size must match SPI length (if non-zero SPI).
		if len(n.SPI) > 255 {
			return fmt.Errorf("NOTIFY SPI length %d exceeds 255", len(n.SPI))
		}
		// INVALID_KE_PAYLOAD Data must be exactly 2 bytes (RFC 7296 §3.10.1).
		if n.MessageType == 17 && len(n.Data) != 2 {
			return fmt.Errorf("INVALID_KE_PAYLOAD Data must be 2 bytes (got %d)", len(n.Data))
		}
		// COOKIE Data must be 1..64 bytes (RFC 8019 §4).
		if n.MessageType == 16390 {
			if len(n.Data) < 1 || len(n.Data) > 64 {
				return fmt.Errorf("COOKIE Data must be 1..64 bytes (got %d)", len(n.Data))
			}
		}
		// NAT Detection Data must be 20 bytes.
		if (n.MessageType == 16388 || n.MessageType == 16389) && len(n.Data) != 20 {
			return fmt.Errorf("NAT Detection Data must be 20 bytes (got %d)", len(n.Data))
		}
	}
	return nil
}

// validateDelete checks DELETE payload invariants.
func validateDelete(d *core.IKEDelete, strict bool) error {
	if strict {
		// IKE Protocol ID must have SPI Size 0 and 0 SPIs.
		if d.ProtocolID == ProtocolIKE {
			if d.SPISize != 0 {
				return fmt.Errorf("DELETE Protocol IKE: SPI Size must be 0")
			}
			if len(d.SPIs) != 0 {
				return fmt.Errorf("DELETE Protocol IKE: SPI list must be empty")
			}
		} else {
			// AH/ESP must have SPI Size=4 and SPI list length matching count.
			if d.SPISize != 4 {
				return fmt.Errorf("DELETE Protocol %d: SPI Size must be 4 (got %d)", d.ProtocolID, d.SPISize)
			}
			if len(d.SPIs) > 65535 {
				return fmt.Errorf("DELETE: too many SPIs (%d > 65535)", len(d.SPIs))
			}
		}
	}
	return nil
}

// validateTS checks Traffic Selector invariants.
func validateTS(ts *core.IKETrafficSelector, strict, fault bool) error {
	if strict {
		switch ts.TSType {
		case 7, 8:
			// ok
		default:
			return fmt.Errorf("TS Type %d invalid (RFC 7296 §3.13.1: 7=IPv4, 8=IPv6)", ts.TSType)
		}
		if len(ts.StartAddress) != len(ts.EndAddress) {
			return fmt.Errorf("TS Start/End Address length mismatch (%d vs %d)", len(ts.StartAddress), len(ts.EndAddress))
		}
		if ts.StartPort > ts.EndPort {
			return fmt.Errorf("TS Start Port %d > End Port %d", ts.StartPort, ts.EndPort)
		}
		if ts.TSType == 7 && len(ts.StartAddress) != 4 {
			return fmt.Errorf("TS Type 7 (IPv4) requires 4-byte addresses (got %d)", len(ts.StartAddress))
		}
		if ts.TSType == 8 && len(ts.StartAddress) != 16 {
			return fmt.Errorf("TS Type 8 (IPv6) requires 16-byte addresses (got %d)", len(ts.StartAddress))
		}
	}
	return nil
}

// validateEAP checks EAP payload invariants.
func validateEAP(e *core.IKEEAP, strict bool) error {
	if strict {
		if e.Code < 1 || e.Code > 4 {
			return fmt.Errorf("EAP Code %d invalid (must be 1..4)", e.Code)
		}
		// Success/Failure (Code 3/4) MUST NOT have a Type field.
		if (e.Code == 3 || e.Code == 4) && e.Type != nil {
			return fmt.Errorf("EAP Success/Failure MUST NOT have a Type field")
		}
		// Request/Response (Code 1/2) MUST have a Type field.
		if (e.Code == 1 || e.Code == 2) && e.Type == nil {
			return fmt.Errorf("EAP Request/Response MUST have a Type field")
		}
	}
	return nil
}

// validateProposal checks a single Proposal substructure.
func validateProposal(p *core.IKEProposal, strict, fault bool) error {
	if strict {
		if p.Number == 0 {
			return fmt.Errorf("Proposal Number must be >= 1 (got 0)")
		}
		switch p.ProtocolID {
		case ProtocolIKE, ProtocolAH, ProtocolESP:
			// ok
		default:
			return fmt.Errorf("Proposal ProtocolID %d invalid (must be 1=IKE, 2=AH, 3=ESP)", p.ProtocolID)
		}
		if len(p.Transforms) == 0 {
			return fmt.Errorf("Proposal must have at least one Transform")
		}
		for i := range p.Transforms {
			if err := validateTransform(&p.Transforms[i], strict, fault); err != nil {
				return fmt.Errorf("Transforms[%d]: %w", i, err)
			}
		}
		// SPI length must match the protocol's expectation.
		switch p.ProtocolID {
		case ProtocolIKE:
			if len(p.SPI) != 0 && strict {
				return fmt.Errorf("IKE Proposal SPI must be empty (got %d bytes)", len(p.SPI))
			}
		case ProtocolAH, ProtocolESP:
			if len(p.SPI) != 4 && strict {
				return fmt.Errorf("AH/ESP Proposal SPI must be 4 bytes (got %d)", len(p.SPI))
			}
		}
	}
	return nil
}

// validateTransform checks a Transform substructure.
func validateTransform(t *core.IKETransform, strict, fault bool) error {
	if strict {
		if t.Type < 1 || t.Type > 5 {
			return fmt.Errorf("Transform Type %d invalid (must be 1-5 per RFC 7296 §3.3.2)", t.Type)
		}
	}
	return nil
}

// Plan generates PacketConfigs for an IKE FlowSpec. The flow is read in the
// returned channel; close semantics follow the existing planners (syslog,
// ntp, snmp) — the goroutine writes and closes. Validate is called first.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)
		p.runPlan(ctx, configChan, spec)
	}()

	return configChan, nil
}

// runPlan executes the plan in a goroutine. It picks the message source
// (Messages explicit vs. Scenario template vs. default) and emits packets
// one at a time, observing ctx.Done for early termination.
func (p *Planner) runPlan(ctx context.Context, ch chan<- core.PacketConfig, spec core.FlowSpec) {
	cfg := spec.IKE
	if cfg == nil {
		return
	}

	// Apply defaults that require spec-side values (e.g. SPI from seed).
	applied := applyDefaults(spec)

	// Resolve message sequence.
	var msgs []core.IKEMessage
	if len(applied.Messages) > 0 {
		msgs = applied.Messages
	} else {
		scenario := applied.Scenario
		if scenario == "" {
			scenario = "standard_v2"
		}
		msgs = buildScenario(scenario, applied)
	}

	// Assign sequential Message IDs per direction. The INIT_REQ/INIT_RESP
	// pair shares MsgID=0; the AUTH_REQ/AUTH_RESP pair shares MsgID=1; etc.
	// For each new "request" (the first message of a request/response pair
	// in a given direction), increment the counter. Responses echo the
	// request's MsgID. We approximate this by tracking the last-seen MsgID
	// per direction; when a message has no explicit MessageID and is not a
	// response, we increment the per-direction counter and assign.
	// For simplicity in this synthetic planner: pair-wise assignment by
	// exchange index. Each pair (req+resp) shares a single MsgID; the next
	// pair gets MsgID+1. This matches the standard INIT(0)/AUTH(1) pattern
	// and scales to multi-round EAP.
	msgID := uint32(applied.StartMessageID)
	pairIndex := 0
	lastDir := ""
	for i := range msgs {
		m := &msgs[i]
		if m.MessageID == nil {
			// If this is the first message or the direction changed from
			// the previous, we increment msgID for a new request. Responses
			// (IsResponse=true) reuse the previous request's MsgID.
			if i == 0 {
				m.MessageID = uint32Ptr(msgID)
				lastDir = m.Direction
			} else if m.IsResponse {
				m.MessageID = uint32Ptr(msgID)
			} else {
				// New request - increment MsgID.
				msgID++
				m.MessageID = uint32Ptr(msgID)
				lastDir = m.Direction
			}
		}
		_ = pairIndex
		_ = lastDir
	}

	flowID := fmt.Sprintf("ike-%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
	now := time.Now()
	pktIdx := uint64(0)
	rng := newOpaqueRNG(applied.OpaqueKeySeed, applied.InitiatorSPI)

	for mi := range msgs {
		msg := &msgs[mi]
		// Generate PacketConfigs for this IKE message (may emit multiple
		// for retransmits or fragmentation).
		emitMessage(ctx, ch, spec, flowID, msg, now, &pktIdx, rng, applied)
	}

	// Emit ESP data-plane packets AFTER the IKE control-plane handshake
	// (RFC 4303 data plane follows SA establishment). When ESPDataPlane is
	// configured, emit ESP packets as raw IP-protocol-50 frames.
	if applied.ESPDataPlane != nil {
		emitESPDataPlane(ctx, ch, spec, flowID, now, &pktIdx, rng, applied)
	}
}

// uint32Ptr returns a pointer to v (helper for assigning *uint32 fields).
func uint32Ptr(v uint32) *uint32 { return &v }

// applyDefaults fills in default values that Validate cannot (because they
// require derived state). Returns the effective IKEConfig.
func applyDefaults(spec core.FlowSpec) core.IKEConfig {
	cfg := *spec.IKE // shallow copy

	// Role default.
	if cfg.Role == "" {
		cfg.Role = "initiator"
	}
	// Version defaults.
	if cfg.VersionMajor == 0 && cfg.VersionMinor == 0 {
		cfg.VersionMajor = 2
		cfg.VersionMinor = 0
	}
	// Nonce size default + range clamp.
	if cfg.DefaultNonceSize == 0 {
		cfg.DefaultNonceSize = DefaultNonceSize
	}
	if cfg.DefaultNonceSize < 16 {
		cfg.DefaultNonceSize = 16
	}
	if cfg.DefaultNonceSize > 256 {
		cfg.DefaultNonceSize = 256
	}
	// DH group default.
	if cfg.DefaultDHGroup == 0 {
		cfg.DefaultDHGroup = DefaultDHGroup
	}
	// Auth method default.
	if cfg.DefaultAuthMethod == 0 {
		cfg.DefaultAuthMethod = 1 // RSA Digital Signature
	}
	// EncryptMode default.
	if cfg.EncryptMode == "" {
		cfg.EncryptMode = "opaque"
	}
	// Fragment threshold default (0 = no fragmentation).
	if cfg.FragmentationSupported && cfg.FragmentThreshold == 0 {
		cfg.FragmentThreshold = DefaultFragmentThreshold
	}

	// InitiatorSPI: if 0 and Role=initiator, derive from seed.
	if cfg.InitiatorSPI == 0 && cfg.Role == "initiator" {
		seed := cfg.OpaqueKeySeed
		if seed == 0 {
			// Use a deterministic non-zero seed to avoid SPIi=0 errors.
			seed = uint64(time.Now().UnixNano())
		}
		cfg.InitiatorSPI = deriveSPI(seed)
	}
	// ResponderSPI: if 0 and Role=responder, derive.
	if cfg.ResponderSPI == 0 && cfg.Role == "responder" {
		seed := cfg.OpaqueKeySeed
		if seed == 0 {
			seed = uint64(time.Now().UnixNano())
		}
		cfg.ResponderSPI = deriveSPI(seed ^ 0x1234567890ABCDEF)
	}

	return cfg
}

// deriveSPI returns a deterministic non-zero 64-bit value derived from seed.
// Used when the user doesn't supply a specific SPI.
func deriveSPI(seed uint64) uint64 {
	r := rand.New(rand.NewSource(int64(seed)))
	v := uint64(r.Uint64())
	if v == 0 {
		v = 0xDEADBEEFCAFEBABE
	}
	return v
}

// opaqueRNG produces deterministic pseudo-bytes for opaque crypto slots
// (NONCE / KE / AUTH data / SK ciphertext / SKF payloads). It's seeded by
// the InitiatorSPI (or the user's OpaqueKeySeed) so re-running produces
// identical byte streams.
type opaqueRNG struct {
	rng *rand.Rand
}

// newOpaqueRNG returns an opaqueRNG seeded from seed ^ spi.
func newOpaqueRNG(seed, spi uint64) *opaqueRNG {
	effectiveSeed := seed
	if effectiveSeed == 0 {
		effectiveSeed = spi
	}
	if effectiveSeed == 0 {
		effectiveSeed = 1 // avoid zero seed (rand panics)
	}
	return &opaqueRNG{
		rng: rand.New(rand.NewSource(int64(effectiveSeed))),
	}
}

// bytes returns n deterministic pseudo-bytes.
func (o *opaqueRNG) bytes(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(o.rng.Uint32())
	}
	return b
}

// emitMessage emits all PacketConfigs for one IKEMessage (handles
// retransmits and SKF fragmentation).
//
// When cfg.FragmentationSupported is enabled and the serialized SK payload
// exceeds cfg.FragmentThreshold, the message is split into multiple IKE
// datagrams, each carrying one SKF (type 53) payload per RFC 7383. All
// fragments share the same SPIi/SPIr/Exchange Type/Message ID/Flags; only
// the IKE Header Length and the SKF Fragment Number differ.
func emitMessage(
	ctx context.Context,
	ch chan<- core.PacketConfig,
	spec core.FlowSpec,
	flowID string,
	msg *core.IKEMessage,
	now time.Time,
	pktIdx *uint64,
	rng *opaqueRNG,
	cfg core.IKEConfig,
) {
	// Build the message payload bytes (header + payloads).
	bytes, fragCount, fragNum := buildIKEMessageBytes(msg, cfg, rng)

	// If fragmentation is enabled and this message's payload chain exceeds
	// the threshold, emit one IKE datagram per SKF fragment instead of the
	// single unfragmented message. Retransmits apply to the whole fragment
	// set (each fragment is retransmitted together).
	if cfg.FragmentationSupported && cfg.FragmentThreshold > 0 && msg.Encrypted != nil &&
		shouldFragment(bytes, cfg.FragmentThreshold) {
		emitFragmented(ctx, ch, spec, flowID, msg, now, pktIdx, rng, cfg)
		return
	}

	// Emit the canonical message + any retransmits (each is byte-identical).
	copies := msg.Retransmit
	if copies == 0 && cfg.RetransmitCount > 0 {
		copies = cfg.RetransmitCount
	}
	for i := 0; i <= copies; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}
		pc := buildPacketConfig(spec, flowID, msg, *pktIdx, bytes, fragCount, fragNum, now, rng, cfg)
		ch <- pc
		*pktIdx++
	}
}

// shouldFragment reports whether the serialized IKE message (header +
// payload chain) exceeds the fragmentation threshold. The threshold is
// compared against the total IKE message length (IKE Header Length field),
// matching design_ike.md §4 场景 12 ("SK 超过配置阈值时...切成多个 SKF").
func shouldFragment(ikeBytes []byte, threshold uint16) bool {
	return uint16(len(ikeBytes)) > threshold
}

// emitFragmented splits the SK payload of an encrypted IKE message into
// SKF fragments and emits one IKE datagram per fragment. Each datagram
// shares SPIi/SPIr/Exchange Type/Message ID/Flags; the IKE Header Next
// Payload is PayloadSKF (53), and the IKE Header Length reflects only
// that fragment's bytes.
func emitFragmented(
	ctx context.Context,
	ch chan<- core.PacketConfig,
	spec core.FlowSpec,
	flowID string,
	msg *core.IKEMessage,
	now time.Time,
	pktIdx *uint64,
	rng *opaqueRNG,
	cfg core.IKEConfig,
) {
	// Re-serialize the SK body so we can split the ciphertext into chunks.
	skBody := encodeSK(msg.Encrypted, cfg, rng)
	// Each SKF body = 4 (Fragment Number + Total) + chunk. The SKF Generic
	// Payload Header adds 4 bytes. The IKE Header adds 28 bytes. So the
	// per-fragment payload-chunk budget = threshold - 28 (IKE hdr) - 4
	// (generic hdr) - 4 (SKF fragment header).
	threshold := int(cfg.FragmentThreshold)
	perFragment := threshold - IKEHeaderLen - GenericHeaderLen - 4 // 4 = FragmentNumber + TotalFragments
	if perFragment < 1 {
		perFragment = 1 // guard against a pathologically small threshold
	}

	totalFrags := uint16((len(skBody) + perFragment - 1) / perFragment)
	if totalFrags == 0 {
		totalFrags = 1
	}

	// Resolve SPI / header fields shared by all fragments.
	spii := cfg.InitiatorSPI
	if msg.InitiatorSPI != nil {
		spii = *msg.InitiatorSPI
	}
	spir := cfg.ResponderSPI
	if msg.ResponderSPI != nil {
		spir = *msg.ResponderSPI
	}
	msgID := uint32(0)
	if msg.MessageID != nil {
		msgID = *msg.MessageID
	}
	flags := computeFlags(msg)
	version := (cfg.VersionMajor << 4) | (cfg.VersionMinor & 0x0F)

	// Emit the canonical set of fragments, then any retransmits (each
	// retransmit resends the whole fragment set byte-identically).
	copies := msg.Retransmit
	if copies == 0 && cfg.RetransmitCount > 0 {
		copies = cfg.RetransmitCount
	}
	for r := 0; r <= copies; r++ {
		for f := uint16(0); f < totalFrags; f++ {
			select {
			case <-ctx.Done():
				return
			default:
			}
			start := int(f) * perFragment
			end := start + perFragment
			if end > len(skBody) {
				end = len(skBody)
			}
			chunk := skBody[start:end]

			// SKF payload body: FragmentNumber(2) + TotalFragments(2) + Data.
			skfBody := make([]byte, 4+len(chunk))
			binary.BigEndian.PutUint16(skfBody[0:2], f+1)
			binary.BigEndian.PutUint16(skfBody[2:4], totalFrags)
			copy(skfBody[4:], chunk)

			// Generic Payload Header: Next Payload = 0 (SKF is the only
			// payload in a fragmented datagram), Critical=0, Length.
			genHdr := make([]byte, GenericHeaderLen)
			genHdr[0] = 0 // no next payload
			binary.BigEndian.PutUint16(genHdr[2:4], uint16(GenericHeaderLen+len(skfBody)))

			// IKE Header.
			hdr := make([]byte, IKEHeaderLen)
			binary.BigEndian.PutUint64(hdr[0:8], spii)
			binary.BigEndian.PutUint64(hdr[8:16], spir)
			hdr[16] = PayloadSKF // Next Payload = SKF (53)
			hdr[17] = version
			hdr[18] = msg.ExchangeType
			hdr[19] = flags
			binary.BigEndian.PutUint32(hdr[20:24], msgID)
			totalLen := uint32(IKEHeaderLen + GenericHeaderLen + len(skfBody))
			binary.BigEndian.PutUint32(hdr[24:28], totalLen)

			full := make([]byte, 0, len(hdr)+len(genHdr)+len(skfBody))
			full = append(full, hdr...)
			full = append(full, genHdr...)
			full = append(full, skfBody...)

			pc := buildPacketConfig(spec, flowID, msg, *pktIdx, full, totalFrags, f+1, now, rng, cfg)
			ch <- pc
			*pktIdx++
		}
	}
}

// buildIKEMessageBytes serializes the IKE Header + payload chain for one
// message. Returns (full bytes, totalFragments, fragmentNumber). When the
// message is fragmented via SKF, this returns the header bytes of the
// first fragment (other fragments are emitted separately by the caller).
func buildIKEMessageBytes(msg *core.IKEMessage, cfg core.IKEConfig, rng *opaqueRNG) ([]byte, uint16, uint16) {
	// Resolve Message ID (sequential counter or explicit override).
	msgID := uint32(0)
	if msg.MessageID != nil {
		msgID = *msg.MessageID
	}

	// Resolve SPI values.
	spii := cfg.InitiatorSPI
	if msg.InitiatorSPI != nil {
		spii = *msg.InitiatorSPI
	}
	spir := cfg.ResponderSPI
	if msg.ResponderSPI != nil {
		spir = *msg.ResponderSPI
	}

	// Serialize payloads (without the IKE Header yet).
	payloadsBytes, nextPayload := encodePayloads(msg, cfg, rng)

	// Build the IKE Header.
	hdr := make([]byte, IKEHeaderLen)
	binary.BigEndian.PutUint64(hdr[0:8], spii)
	binary.BigEndian.PutUint64(hdr[8:16], spir)
	hdr[16] = nextPayload
	hdr[17] = (cfg.VersionMajor << 4) | (cfg.VersionMinor & 0x0F)
	hdr[18] = msg.ExchangeType
	hdr[19] = computeFlags(msg)
	binary.BigEndian.PutUint32(hdr[20:24], msgID)

	// Total length = 28 + payload bytes.
	totalLen := uint32(IKEHeaderLen + len(payloadsBytes))
	binary.BigEndian.PutUint32(hdr[24:28], totalLen)

	// Fault overrides (if set and FaultInjection mode).
	if msg.RawLengthOverride != nil {
		binary.BigEndian.PutUint32(hdr[24:28], *msg.RawLengthOverride)
	}
	if msg.RawNextPayloadOverride != nil {
		hdr[16] = *msg.RawNextPayloadOverride
	}
	if msg.RawFlagsOverride != nil {
		hdr[19] = *msg.RawFlagsOverride
	}

	full := append(hdr, payloadsBytes...)
	return full, 1, 1
}

// computeFlags returns the IKE Header flags byte (I/V/R).
func computeFlags(msg *core.IKEMessage) uint8 {
	var f uint8
	if msg.FromOriginalInitiator {
		f |= FlagInitiator
	}
	if msg.HigherVersionSupported {
		f |= FlagVersion
	}
	if msg.IsResponse {
		f |= FlagResponse
	}
	return f
}

// encodePayloads serializes the payload chain. When the message has
// Encrypted set, all cleartext payloads go into an SK (type 46) wrapper.
// Returns (serialized bytes, next_payload for the IKE Header).
func encodePayloads(msg *core.IKEMessage, cfg core.IKEConfig, rng *opaqueRNG) ([]byte, uint8) {
	// Case 1: Encrypted is set → wrap cleartext payloads in SK.
	if msg.Encrypted != nil {
		skBytes := encodeSK(msg.Encrypted, cfg, rng)
		// Build the SK's Generic Payload Header. Its Next Payload byte
		// points to the FIRST inner payload's Type (or 0 when there are no
		// inner payloads). The IKE Header's Next Payload will be set to
		// PayloadSK by the caller (buildIKEMessageBytes).
		innerNext := uint8(0)
		if len(msg.Encrypted.InnerPayloads) > 0 {
			innerNext = msg.Encrypted.InnerPayloads[0].Type
		}
		hdr := make([]byte, GenericHeaderLen)
		hdr[0] = innerNext
		// Critical bit always 0 for SK (RFC 7296 §3.2).
		binary.BigEndian.PutUint16(hdr[2:4], uint16(GenericHeaderLen+len(skBytes)))
		full := make([]byte, 0, GenericHeaderLen+len(skBytes))
		full = append(full, hdr...)
		full = append(full, skBytes...)
		// IKE Header's Next Payload = PayloadSK (the wrapper itself).
		return full, PayloadSK
	}
	// Case 2: cleartext payload chain.
	if len(msg.Payloads) == 0 {
		return nil, 0
	}
	return encodePayloadChain(msg.Payloads, cfg, rng)
}

// encodePayloadChain serializes a chain of payloads, threading Next-Payload
// pointers. The last payload's Next Payload = 0.
func encodePayloadChain(payloads []core.IKEPayload, cfg core.IKEConfig, rng *opaqueRNG) ([]byte, uint8) {
	if len(payloads) == 0 {
		return nil, 0
	}
	var out []byte
	for i := range payloads {
		p := &payloads[i]
		isLast := i == len(payloads)-1
		nextType := uint8(0)
		if !isLast {
			nextType = payloads[i+1].Type
		}
		body := encodePayloadBody(p, cfg, rng)
		// Generic Header: Next Payload(1) + Critical(1) + Length(2).
		hdr := make([]byte, GenericHeaderLen)
		hdr[0] = nextType
		if p.Critical {
			hdr[1] = 0x80
		}
		payloadLen := uint16(GenericHeaderLen + len(body))
		binary.BigEndian.PutUint16(hdr[2:4], payloadLen)
		// Fault overrides for header.
		if p.RawLengthOverride != nil {
			binary.BigEndian.PutUint16(hdr[2:4], *p.RawLengthOverride)
		}
		if p.RawNextPayloadOverride != nil {
			hdr[0] = *p.RawNextPayloadOverride
		}
		out = append(out, hdr...)
		out = append(out, body...)
	}
	// First Next Payload is payloads[0].Type.
	return out, payloads[0].Type
}

// encodePayloadBody encodes a single payload's body (without the Generic
// Header). Switches on Type to dispatch to typed encoders.
func encodePayloadBody(p *core.IKEPayload, cfg core.IKEConfig, rng *opaqueRNG) []byte {
	// Raw override wins.
	if len(p.Raw) > 0 {
		return p.Raw
	}
	switch p.Type {
	case PayloadSA:
		if p.SA != nil {
			return encodeSA(p.SA)
		}
	case PayloadKE:
		if p.KE != nil {
			return encodeKE(p.KE, rng)
		}
	case PayloadIDi, PayloadIDr:
		if p.ID != nil {
			return encodeID(p.ID)
		}
	case PayloadCERT:
		if p.Certificate != nil {
			return encodeCert(p.Certificate)
		}
	case PayloadCERTREQ:
		if p.CertificateRequest != nil {
			return encodeCertReq(p.CertificateRequest)
		}
	case PayloadAUTH:
		if p.Auth != nil {
			return encodeAuth(p.Auth, rng)
		}
	case PayloadNONCE:
		return p.Nonce
	case PayloadNOTIFY:
		if p.Notify != nil {
			return encodeNotify(p.Notify)
		}
	case PayloadDELETE:
		if p.Delete != nil {
			return encodeDelete(p.Delete)
		}
	case PayloadVENDOR:
		return p.VendorID
	case PayloadTSi, PayloadTSr:
		return encodeTSChain(p.TrafficSelectors)
	case PayloadSK:
		// SK in cleartext chain (fault-injection only). Use Raw bytes if
		// supplied, otherwise emit an empty body. Validation already
		// rejected this in strict mode.
		if len(p.Raw) > 0 {
			return p.Raw
		}
		return nil
	case PayloadCP:
		if p.Config != nil {
			return encodeCP(p.Config)
		}
	case PayloadEAP:
		if p.EAP != nil {
			return encodeEAP(p.EAP)
		}
	case PayloadSKF:
		if p.Fragment != nil {
			return encodeSKF(p.Fragment)
		}
	}
	// Empty body (caller has already validated or fault mode allows).
	return nil
}

// --- SA / Proposal / Transform encoders ---

// encodeSA encodes the body of an SA payload (Proposal Substructures).
func encodeSA(sa *core.IKESA) []byte {
	if sa == nil || len(sa.Proposals) == 0 {
		return nil
	}
	var out []byte
	for i, prop := range sa.Proposals {
		isLast := i == len(sa.Proposals)-1
		lastByte := uint8(0)
		if !isLast {
			lastByte = 2 // More Proposals
		}
		propBytes := encodeProposal(&prop, lastByte)
		out = append(out, propBytes...)
	}
	return out
}

// encodeProposal encodes a single Proposal Substructure.
// lastByte is 0 (last) or 2 (more proposals following).
func encodeProposal(p *core.IKEProposal, lastByte uint8) []byte {
	transformsBytes := encodeTransforms(p.Transforms)
	spiLen := len(p.SPI)
	// Layout: Last(1) + Reserved(1) + Proposal Length(2) + Proposal#(1) +
	//          Protocol ID(1) + SPI Size(1) + #Transforms(1) + SPI + Transforms
	propLen := 8 + spiLen + len(transformsBytes)
	body := make([]byte, propLen)
	body[0] = lastByte
	body[1] = 0 // reserved
	binary.BigEndian.PutUint16(body[2:4], uint16(propLen))
	body[4] = p.Number
	body[5] = p.ProtocolID
	body[6] = uint8(spiLen)
	body[7] = uint8(len(p.Transforms))
	copy(body[8:8+spiLen], p.SPI)
	copy(body[8+spiLen:], transformsBytes)
	return body
}

// encodeTransforms encodes a list of Transform Substructures.
func encodeTransforms(transforms []core.IKETransform) []byte {
	if len(transforms) == 0 {
		return nil
	}
	var out []byte
	for i, t := range transforms {
		isLast := i == len(transforms)-1
		lastByte := uint8(0)
		if !isLast {
			lastByte = 3 // More Transforms
		}
		// Layout: Last(1) + Reserved1(1) + Transform Length(2) +
		//          Type(1) + Reserved2(1) + ID(2) + Attributes
		attrs := t.RawAttributes
		if len(attrs) == 0 && t.KeyLengthBits > 0 {
			// Encode Key Length as a TV (short-form) Transform Attribute
			// (RFC 7296 §3.3.5). The Key Length attribute (type 14) is fixed
			// length and MUST use the Type/Value form with AF=1. Wire layout:
			//   AF(1 bit)=1 | Attribute Type(15 bits)=14 | Attribute Value(2 bytes)
			// For AES-128 this is 0x80 0x0E 0x00 0x80. Setting AF=0 (TLV form)
			// would make the following 2 bytes (0x00 0x80) be parsed as a
			// 128-byte Attribute Length, causing Wireshark to swallow the next
			// transforms as attribute value — exactly the malformed-packet
			// symptom reported on IKE_SA_INIT.
			attrs = []byte{0x80 | byte((14>>8)&0x7F), byte(14 & 0xFF), byte(t.KeyLengthBits >> 8), byte(t.KeyLengthBits & 0xFF)}
		}
		tLen := 8 + len(attrs)
		body := make([]byte, tLen)
		body[0] = lastByte
		body[1] = 0
		binary.BigEndian.PutUint16(body[2:4], uint16(tLen))
		body[4] = t.Type
		body[5] = 0
		binary.BigEndian.PutUint16(body[6:8], t.ID)
		copy(body[8:], attrs)
		out = append(out, body...)
	}
	return out
}

// --- KE / ID / CERT / CERTREQ / AUTH / NONCE encoders ---

// encodeKE encodes a KE payload body: DH Group(2) + Reserved(2) + Key Data(N).
func encodeKE(ke *core.IKEKE, rng *opaqueRNG) []byte {
	keyData := ke.KeyData
	if len(keyData) == 0 {
		// Derive a deterministic opaque blob. Group 14 (2048-bit MODP) expects
		// 256 bytes; Group 19 (256-bit ECP) expects 32; Group 31 (Curve25519)
		// expects 32. We use a fixed 256-byte default that exceeds all groups.
		keyData = rng.bytes(defaultKEKeyDataBytes)
	}
	body := make([]byte, 4+len(keyData))
	binary.BigEndian.PutUint16(body[0:2], ke.DHGroup)
	binary.BigEndian.PutUint16(body[2:4], 0) // reserved
	copy(body[4:], keyData)
	return body
}

// encodeID encodes an ID payload body: ID Type(1) + Reserved(3) + Data(N).
func encodeID(id *core.IKEIdentity) []byte {
	body := make([]byte, 4+len(id.Data))
	body[0] = id.IDType
	// bytes[1:4] reserved = 0
	copy(body[4:], id.Data)
	return body
}

// encodeCert encodes a CERT payload body: Cert Encoding(1) + Certificate Data(N).
func encodeCert(c *core.IKECertificate) []byte {
	body := make([]byte, 1+len(c.Data))
	body[0] = c.Encoding
	copy(body[1:], c.Data)
	return body
}

// encodeCertReq encodes a CERTREQ payload body: Cert Encoding(1) + CA list(N).
func encodeCertReq(cr *core.IKECertificateRequest) []byte {
	var caBytes []byte
	for _, ca := range cr.CAs {
		caBytes = append(caBytes, ca...)
	}
	body := make([]byte, 1+len(caBytes))
	body[0] = cr.Encoding
	copy(body[1:], caBytes)
	return body
}

// encodeAuth encodes an AUTH payload body: Auth Method(1) + Reserved(3) + Data(N).
func encodeAuth(a *core.IKEAuth, rng *opaqueRNG) []byte {
	data := a.Data
	if len(data) == 0 {
		data = rng.bytes(defaultAuthDataBytes)
	}
	body := make([]byte, 4+len(data))
	body[0] = a.Method
	copy(body[4:], data)
	return body
}

// --- NOTIFY / DELETE encoders ---

// encodeNotify encodes a NOTIFY payload body:
// Protocol ID(1) + SPI Size(1) + Notify Message Type(2) + SPI(N) + Notification Data(M).
func encodeNotify(n *core.IKENotify) []byte {
	spiLen := len(n.SPI)
	body := make([]byte, 4+spiLen+len(n.Data))
	body[0] = n.ProtocolID
	body[1] = uint8(spiLen)
	binary.BigEndian.PutUint16(body[2:4], n.MessageType)
	copy(body[4:4+spiLen], n.SPI)
	copy(body[4+spiLen:], n.Data)
	return body
}

// encodeDelete encodes a DELETE payload body:
// Protocol ID(1) + SPI Size(1) + #SPIs(2) + SPI list(N).
func encodeDelete(d *core.IKEDelete) []byte {
	var spiBytes []byte
	for _, spi := range d.SPIs {
		spiBytes = append(spiBytes, spi...)
	}
	body := make([]byte, 4+len(spiBytes))
	body[0] = d.ProtocolID
	body[1] = d.SPISize
	binary.BigEndian.PutUint16(body[2:4], uint16(len(d.SPIs)))
	copy(body[4:], spiBytes)
	return body
}

// --- TS / CP / EAP / SK / SKF encoders ---

// encodeTSChain encodes a TS payload body: #TS(1) + Reserved(3) + TS Substructures.
func encodeTSChain(tss []core.IKETrafficSelector) []byte {
	var subBytes []byte
	for _, ts := range tss {
		subBytes = append(subBytes, encodeTS(&ts)...)
	}
	body := make([]byte, 4+len(subBytes))
	body[0] = uint8(len(tss))
	copy(body[4:], subBytes)
	return body
}

// encodeTS encodes one TS Substructure (RFC 7296 §3.13.1).
// Layout: TS Type(1) + IP Protocol ID(1) + Selector Length(2) +
//          Start Port(2) + End Port(2) + Start Addr(4/16) + End Addr(4/16).
func encodeTS(ts *core.IKETrafficSelector) []byte {
	addrLen := len(ts.StartAddress)
	if addrLen == 0 {
		addrLen = 4
	}
	total := 8 + addrLen*2
	body := make([]byte, total)
	body[0] = ts.TSType
	body[1] = ts.IPProtocolID
	binary.BigEndian.PutUint16(body[2:4], uint16(total))
	binary.BigEndian.PutUint16(body[4:6], ts.StartPort)
	binary.BigEndian.PutUint16(body[6:8], ts.EndPort)
	copy(body[8:8+addrLen], ts.StartAddress)
	copy(body[8+addrLen:8+addrLen*2], ts.EndAddress)
	return body
}

// encodeCP encodes a CP payload body: CFG Type(1) + Reserved(3) + Attributes.
func encodeCP(c *core.IKEConfiguration) []byte {
	var attrBytes []byte
	for _, a := range c.Attributes {
		// Each attribute: Type(2) + Length(2) + Value(N) — TLV form for
		// multi-byte values; TV (Type + Value, no length) for <=2-byte values
		// is a separate encoding form, but the standard TLV form works for
		// all attribute types. RFC 4306 §3.15.1.
		attrBytes = append(attrBytes, byte(a.Type>>8), byte(a.Type&0xFF))
		if len(a.Value) > 0 {
			attrBytes = append(attrBytes, byte(len(a.Value)>>8), byte(len(a.Value)&0xFF))
			attrBytes = append(attrBytes, a.Value...)
		} else {
			attrBytes = append(attrBytes, 0, 0)
		}
	}
	body := make([]byte, 4+len(attrBytes))
	body[0] = c.CFGType
	copy(body[4:], attrBytes)
	return body
}

// encodeEAP encodes an EAP payload body (RFC 3748).
// Layout: Code(1) + Identifier(1) + Length(2) + [Type(1)] + [Type-Data(N)].
func encodeEAP(e *core.IKEEAP) []byte {
	var typeByte byte
	hasType := e.Type != nil
	if hasType {
		typeByte = *e.Type
	}
	eapLen := 4
	if hasType {
		eapLen = 5 + len(e.Data)
	}
	body := make([]byte, eapLen)
	body[0] = e.Code
	body[1] = e.Identifier
	binary.BigEndian.PutUint16(body[2:4], uint16(eapLen))
	if hasType {
		body[4] = typeByte
		copy(body[5:], e.Data)
	}
	return body
}

// encodeSK encodes an SK payload body (IV + Ciphertext + PadLength + ICV).
// The cleartext "ciphertext" is opaque pseudo-bytes. InnerPayloads are
// threaded via SK's own Generic Payload Header Next Payload pointer (the
// caller must derive the first inner-payload type and set it in the outer
// Generic Header).
func encodeSK(e *core.IKEEncryptedBody, cfg core.IKEConfig, rng *opaqueRNG) []byte {
	ivLen := e.IVLength
	if ivLen == 0 {
		ivLen = DefaultIVLength
	}
	icvLen := e.ICVLength
	if icvLen == 0 {
		icvLen = DefaultICVLength
	}

	// Determine the inner-payload chain bytes (used for sizing the opaque
	// ciphertext). The SK's Outer-Generic-Header Next-Payload points to the
	// first inner payload's Type; the caller (encodePayloads) sets that.
	var innerChain []byte
	if len(e.InnerPayloads) > 0 {
		innerChain, _ = encodePayloadChain(e.InnerPayloads, cfg, rng)
	}

	// Ciphertext bytes: opaque data, padded to PadTo (or 16 default) and
	// followed by 1-byte pad-length + ICV.
	ciphertext := e.OpaqueData
	if len(ciphertext) == 0 {
		// Pad the inner chain's length (as a stand-in for the actual
		// encrypted content) to PadTo. Then add a pad-length byte. This is
		// a wire-shape approximation — RFC 7296 §3.14 requires the pad to
		// fill to a multiple of the encryption block size, with the last
		// byte being the pad length.
		pad := e.PadTo
		if pad == 0 {
			pad = 16
		}
		size := len(innerChain)
		if size == 0 {
			size = int(ivLen) // empty SK content has at least ICV+IV
		}
		rem := size % int(pad)
		padBytes := 0
		if rem != 0 {
			padBytes = int(pad) - rem
		}
		ciphertext = make([]byte, 0, size+padBytes+1+int(icvLen))
		ciphertext = append(ciphertext, innerChain...)
		ciphertext = append(ciphertext, make([]byte, padBytes)...)
		ciphertext = append(ciphertext, byte(padBytes))
	}

	iv := rng.bytes(int(ivLen))
	icv := rng.bytes(int(icvLen))

	body := make([]byte, 0, len(iv)+len(ciphertext)+len(icv))
	body = append(body, iv...)
	body = append(body, ciphertext...)
	body = append(body, icv...)
	return body
}

// encodeSKF encodes an SKF payload body (RFC 7383 §2):
// Fragment Number(2) + Total Fragments(2) + Encrypted Fragment Data(N).
// FragmentNumber and TotalFragments are validated upstream.
func encodeSKF(f *core.IKEFragment) []byte {
	if f == nil {
		return nil
	}
	body := make([]byte, 4+len(f.Data))
	binary.BigEndian.PutUint16(body[0:2], f.FragmentNumber)
	binary.BigEndian.PutUint16(body[2:4], f.TotalFragments)
	copy(body[4:], f.Data)
	return body
}

// buildPacketConfig builds the core.PacketConfig for a fully-serialized
// IKE message. Direction determines L2/L3/L4 port swap.
func buildPacketConfig(
	spec core.FlowSpec,
	flowID string,
	msg *core.IKEMessage,
	pktIdx uint64,
	bytes []byte,
	fragCount, fragNum uint16,
	now time.Time,
	rng *opaqueRNG,
	cfg core.IKEConfig,
) core.PacketConfig {
	// Direction-based src/dst swap.
	srcIP := spec.SrcIP
	dstIP := spec.DstIP
	srcMAC := spec.SrcMAC
	dstMAC := spec.DstMAC
	srcPort := spec.SrcPort
	dstPort := DefaultPort

	if msg.Direction == "down" {
		// Responder → Initiator: swap L2/L3/L4.
		srcIP, dstIP = dstIP, srcIP
		srcMAC, dstMAC = dstMAC, srcMAC
		srcPort, dstPort = dstPort, srcPort
	}

	// IP ID: deterministic, incrementing.
	ipID := uint16(pktIdx & 0xFFFF)

	ttl := spec.TTL
	if ttl == 0 {
		ttl = 64
	}

	md := map[string]interface{}{
		"ike_exchange_type": int(msg.ExchangeType),
		"ike_message_id":    int(readMsgID(bytes)),
		"ike_spi_i":         readSPIi(bytes),
		"ike_spi_r":         readSPIr(bytes),
	}
	if fragCount > 1 {
		md["ike_fragment_number"] = int(fragNum)
		md["ike_fragment_total"] = int(fragCount)
	}

	return core.PacketConfig{
		FlowID:      flowID,
		PacketIndex: pktIdx,
		Direction:   msg.Direction,
		Timestamp:   now,
		L2: core.L2Config{
			SrcMAC:    srcMAC,
			DstMAC:    dstMAC,
			EtherType: core.EtherTypeFor(srcIP),
		},
		L3: core.L3Base(srcIP, dstIP, core.ProtocolUDP, ttl, ipID, spec),
		L4: core.L4Config{
			Protocol: "udp",
			SrcPort:  srcPort,
			DstPort:  dstPort,
		},
		Payload:  bytes,
		Metadata: md,
	}
}

// readMsgID extracts the Message ID from a fully-serialized IKE message.
func readMsgID(bytes []byte) uint32 {
	if len(bytes) < 24 {
		return 0
	}
	return binary.BigEndian.Uint32(bytes[20:24])
}

// readSPIi extracts the Initiator SPI from a fully-serialized IKE message.
func readSPIi(bytes []byte) uint64 {
	if len(bytes) < 8 {
		return 0
	}
	return binary.BigEndian.Uint64(bytes[0:8])
}

// readSPIr extracts the Responder SPI from a fully-serialized IKE message.
func readSPIr(bytes []byte) uint64 {
	if len(bytes) < 16 {
		return 0
	}
	return binary.BigEndian.Uint64(bytes[8:16])
}

// --- ESP data-plane emission (RFC 4303) ---

// emitESPDataPlane emits ESP data-plane packets after the IKE control-plane
// handshake. Each ESP packet is a raw IP-protocol-50 frame (no L4 header):
//
//	[Outer IP hdr][SPI(4)][Seq(4)][IV][PayloadData][Padding][PadLen][NextHdr][ICV]
//
// In tunnel mode (RFC 4303 §2.6), PayloadData = inner IPv4 header + inner L4
// + data; NextHeader = 4 (IPv4-in-IPv4, RFC 2003). In transport mode (§2.4),
// PayloadData = inner L4 header + data; NextHeader = InnerProto.
//
// The planner performs NO real encryption — the PayloadData is either a
// synthesized inner IP packet (tunnel) or inner L4+data (transport), and
// the IV/ICV are deterministic pseudo-bytes. The structure is wire-format
// compliant so Wireshark can parse the ESP frame.
func emitESPDataPlane(
	ctx context.Context,
	ch chan<- core.PacketConfig,
	spec core.FlowSpec,
	flowID string,
	now time.Time,
	pktIdx *uint64,
	rng *opaqueRNG,
	cfg core.IKEConfig,
) {
	esp := cfg.ESPDataPlane
	if esp == nil {
		return
	}

	spi := esp.SPI
	if spi == 0 {
		spi = DefaultESPSPI
	}
	count := esp.Count
	if count <= 0 {
		count = 1
	}
	mode := esp.Mode
	if mode == "" {
		mode = "tunnel"
	}
	direction := esp.Direction
	if direction == "" {
		direction = "up"
	}
	ivLen := esp.IVLength
	if ivLen <= 0 {
		ivLen = DefaultESPIVLength
	}
	icvLen := esp.ICVLength
	if icvLen <= 0 {
		icvLen = DefaultESPICVLength
	}
	innerPayloadSize := esp.InnerPayloadSize
	if innerPayloadSize <= 0 {
		innerPayloadSize = DefaultESPInnerPayloadSize
	}

	// Resolve outer IP / MAC based on direction.
	srcIP := spec.SrcIP
	dstIP := spec.DstIP
	srcMAC := spec.SrcMAC
	dstMAC := spec.DstMAC
	if direction == "down" {
		srcIP, dstIP = dstIP, srcIP
		srcMAC, dstMAC = dstMAC, srcMAC
	}

	ttl := spec.TTL
	if ttl == 0 {
		ttl = 64
	}

	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		seqNum := uint32(i + 1)
		espBytes := buildESPPacket(esp, spi, seqNum, ivLen, icvLen, innerPayloadSize, mode, rng)

		ipID := uint16(*pktIdx & 0xFFFF)

		pc := core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: *pktIdx,
			Direction:   direction,
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    srcMAC,
				DstMAC:    dstMAC,
				EtherType: core.EtherTypeFor(srcIP),
			},
			L3: core.L3Base(srcIP, dstIP, ProtocolESPData, ttl, ipID, spec),
			// ESP is an IP-layer protocol (protocol 50); there is no L4
			// header. Leave L4 zeroed so the builder writes no L4 bytes and
			// the ESP payload follows the IP header directly.
			L4:      core.L4Config{},
			Payload: espBytes,
			Metadata: map[string]interface{}{
				"esp_spi":     int(spi),
				"esp_seq":     int(seqNum),
				"esp_mode":    mode,
				"esp_iv_len":  ivLen,
				"esp_icv_len": icvLen,
			},
		}

		select {
		case ch <- pc:
			*pktIdx++
		case <-ctx.Done():
			return
		}
	}
}

// buildESPPacket constructs one ESP packet's payload bytes (everything after
// the outer IP header): SPI + Seq + IV + PayloadData + Padding + PadLength +
// NextHeader + ICV (RFC 4303 §2).
func buildESPPacket(
	esp *core.ESPDataPlaneConfig,
	spi uint32,
	seqNum uint32,
	ivLen, icvLen, innerPayloadSize int,
	mode string,
	rng *opaqueRNG,
) []byte {
	// Build the payload data (the cleartext before "encryption").
	var payloadData []byte
	var nextHeader uint8

	if mode == "tunnel" {
		payloadData = buildInnerIPv4Packet(esp, innerPayloadSize, rng)
		nextHeader = IPProtoIPv4Encap // 4 = IPv4-in-IPv4
	} else {
		// Transport mode: payload = inner L4 header + data.
		payloadData = buildInnerL4(esp, innerPayloadSize, rng)
		nextHeader = esp.InnerProto // e.g. 17=UDP, 6=TCP
	}

	// IV: deterministic pseudo-bytes.
	iv := rng.bytes(ivLen)

	// Compute padding for 4-byte alignment (RFC 4303 §2.4: the
	// PayloadData + Padding + PadLength + NextHeader must be a multiple
	// of the block size; we use 4-byte alignment as the minimum).
	// payloadLen = len(payloadData) + padding + 2 (PadLen + NextHdr).
	payloadLen := len(payloadData) + 2
	remainder := payloadLen % 4
	padLen := 0
	if remainder != 0 {
		padLen = 4 - remainder
	}

	// Assemble: SPI(4) + Seq(4) + IV + PayloadData + Padding + PadLen(1) + NextHdr(1) + ICV.
	total := 8 + ivLen + len(payloadData) + padLen + 2 + icvLen
	out := make([]byte, total)
	binary.BigEndian.PutUint32(out[0:4], spi)
	binary.BigEndian.PutUint32(out[4:8], seqNum)
	copy(out[8:8+ivLen], iv)
	copy(out[8+ivLen:8+ivLen+len(payloadData)], payloadData)
	// Padding bytes: 1, 2, 3, ... (RFC 4303 §2.4 recommended scheme).
	for i := 0; i < padLen; i++ {
		out[8+ivLen+len(payloadData)+i] = byte(i + 1)
	}
	// PadLength byte.
	out[8+ivLen+len(payloadData)+padLen] = byte(padLen)
	// NextHeader byte.
	out[8+ivLen+len(payloadData)+padLen+1] = nextHeader
	// ICV: deterministic pseudo-bytes.
	icv := rng.bytes(icvLen)
	copy(out[8+ivLen+len(payloadData)+padLen+2:], icv)

	return out
}

// buildInnerIPv4Packet constructs a minimal inner IPv4 header + inner L4 +
// payload for ESP tunnel mode (RFC 4303 §2.6). The inner IPv4 header is
// 20 bytes with valid version/IHL/TTL/Protocol/checksum.
func buildInnerIPv4Packet(esp *core.ESPDataPlaneConfig, innerPayloadSize int, rng *opaqueRNG) []byte {
	srcIP := net.ParseIP(esp.InnerSrcIP).To4()
	dstIP := net.ParseIP(esp.InnerDstIP).To4()

	// Inner L4 payload (the data inside the inner IP packet).
	innerL4 := buildInnerL4(esp, innerPayloadSize, rng)

	// Inner IPv4 header (20 bytes).
	totalLen := 20 + len(innerL4)
	hdr := make([]byte, 20)
	hdr[0] = 0x45 // Version 4, IHL 5
	// TOS = 0 (best effort).
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(hdr[4:6], 0) // IPID (inner, deterministic 0)
	binary.BigEndian.PutUint16(hdr[6:8], 0) // Flags + FragOffset (no flags)
	hdr[8] = 64                              // TTL
	hdr[9] = esp.InnerProto                  // Protocol
	binary.BigEndian.PutUint16(hdr[10:12], 0) // Checksum placeholder
	if srcIP != nil {
		copy(hdr[12:16], srcIP)
	}
	if dstIP != nil {
		copy(hdr[16:20], dstIP)
	}
	// Compute and set the IPv4 header checksum.
	cs := ipChecksum(hdr)
	binary.BigEndian.PutUint16(hdr[10:12], cs)

	return append(hdr, innerL4...)
}

// buildInnerL4 constructs the inner L4 header + data. Currently supports
// UDP (8-byte header) and TCP (20-byte header). For unknown protocols,
// returns just the payload data.
func buildInnerL4(esp *core.ESPDataPlaneConfig, innerPayloadSize int, rng *opaqueRNG) []byte {
	data := rng.bytes(innerPayloadSize)
	switch esp.InnerProto {
	case 17: // UDP
		hdr := make([]byte, 8)
		binary.BigEndian.PutUint16(hdr[0:2], esp.InnerSrcPort)
		binary.BigEndian.PutUint16(hdr[2:4], esp.InnerDstPort)
		binary.BigEndian.PutUint16(hdr[4:6], uint16(8+len(data)))
		binary.BigEndian.PutUint16(hdr[6:8], 0) // checksum (0 = optional for UDP)
		return append(hdr, data...)
	case 6: // TCP
		hdr := make([]byte, 20)
		binary.BigEndian.PutUint16(hdr[0:2], esp.InnerSrcPort)
		binary.BigEndian.PutUint16(hdr[2:4], esp.InnerDstPort)
		binary.BigEndian.PutUint32(hdr[4:8], 0) // Seq
		binary.BigEndian.PutUint32(hdr[8:12], 0) // Ack
		hdr[12] = 0x50                            // Data Offset 5 (20 bytes)
		hdr[13] = 0x02                            // SYN
		binary.BigEndian.PutUint16(hdr[14:16], 65535) // Window
		return append(hdr, data...)
	default:
		return data
	}
}

// ipChecksum computes the standard IP header checksum (RFC 791) over a
// header with the checksum field set to 0.
func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// --- Scenario templates ---

// buildScenario expands a named scenario into a sequence of IKEMessages.
// See design_ike.md §4 for the 20 business scenarios.
func buildScenario(name string, cfg core.IKEConfig) []core.IKEMessage {
	role := cfg.Role
	isInitiator := role == "initiator"

	// Default Proposal: ENCR=AES-CBC-128(12), PRF=HMAC-SHA2-256(5),
	// INTEG=HMAC-SHA2-256-128(12), DH=2048_MODP(14), ESN=no(0).
	defaultProposal := cfg.DefaultProposal
	if defaultProposal == nil {
		defaultProposal = &core.IKEProposal{
			Number:     1,
			ProtocolID: ProtocolIKE,
			Transforms: []core.IKETransform{
				{Type: TransformENCR, ID: 12, KeyLengthBits: 128},
				{Type: TransformPRF, ID: 5},
				{Type: TransformINTEG, ID: 12},
				{Type: TransformDH, ID: cfg.DefaultDHGroup},
			},
		}
	}

	// Identity data: IPv4 address string for the initiator ID.
	idData := []byte("10.0.0.1")
	if cfg.Role == "responder" {
		idData = []byte("10.0.0.2")
	}

	switch name {
	case "standard_v2":
		return buildStandardV2(defaultProposal, idData, cfg, isInitiator)
	case "eap_md5":
		return buildEAPMD5(defaultProposal, idData, cfg, isInitiator)
	case "eap_tls":
		return buildEAPTLS(defaultProposal, idData, cfg, isInitiator)
	case "eap_only":
		return buildEAPOnly(defaultProposal, idData, cfg, isInitiator)
	case "dpd":
		return buildDPD(defaultProposal, idData, cfg, isInitiator)
	case "delete_sa":
		return buildDeleteSA(defaultProposal, idData, cfg, isInitiator)
	case "informational":
		return buildInformational(defaultProposal, idData, cfg, isInitiator)
	case "nat_detection":
		return buildNATDetection(defaultProposal, idData, cfg, isInitiator)
	case "ikev1":
		return buildIKEv1(defaultProposal, idData, cfg, isInitiator)
	case "multiple_child_sa":
		return buildMultipleChildSA(defaultProposal, idData, cfg, isInitiator)
	case "child_rekey":
		return buildChildRekey(defaultProposal, idData, cfg, isInitiator)
	case "ike_rekey":
		return buildIKERekey(defaultProposal, idData, cfg, isInitiator)
	case "invalid_ke_retry":
		return buildInvalidKERetry(defaultProposal, idData, cfg, isInitiator)
	case "cookie_retry":
		return buildCookieRetry(defaultProposal, idData, cfg, isInitiator)
	case "cert_chain":
		return buildCertChain(defaultProposal, idData, cfg, isInitiator)
	case "ppk":
		return buildPPK(defaultProposal, idData, cfg, isInitiator)
	case "null_auth":
		return buildNullAuth(defaultProposal, idData, cfg, isInitiator)
	case "session_resume":
		return buildSessionResume(defaultProposal, idData, cfg, isInitiator)
	case "fragmented_auth":
		return buildFragmentedAuth(defaultProposal, idData, cfg, isInitiator)
	case "rekey":
		return buildRekey(defaultProposal, idData, cfg, isInitiator)
	}
	// Should be unreachable (validated above).
	return nil
}

// buildStandardV2 returns the canonical 4-message INIT/AUTH handshake.
func buildStandardV2(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	authReqInner := []core.IKEPayload{
		{Type: PayloadIDi, ID: &core.IKEIdentity{IDType: 1, Data: idData}},
		{Type: PayloadAUTH, Auth: &core.IKEAuth{Method: cfg.DefaultAuthMethod}},
		{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
		{Type: PayloadTSi, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
		{Type: PayloadTSr, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
	}
	authRespInner := []core.IKEPayload{
		{Type: PayloadIDr, ID: &core.IKEIdentity{IDType: 1, Data: idData}},
		{Type: PayloadAUTH, Auth: &core.IKEAuth{Method: cfg.DefaultAuthMethod}},
		{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
		{Type: PayloadTSi, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
		{Type: PayloadTSr, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
	}
	initReq := []core.IKEPayload{
		{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
		{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
		{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
	}
	initResp := []core.IKEPayload{
		{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
		{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
		{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
	}

	if isInit {
		spirZero := uint64(0)
		return []core.IKEMessage{
			{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true,
				ResponderSPI: &spirZero, Payloads: initReq},
			{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true,
				Payloads: initResp},
			{Direction: "up", ExchangeType: ExchangeIKE_SA_AUTH, FromOriginalInitiator: true,
				Encrypted: &core.IKEEncryptedBody{InnerPayloads: authReqInner}},
			{Direction: "down", ExchangeType: ExchangeIKE_SA_AUTH, IsResponse: true,
				Encrypted: &core.IKEEncryptedBody{InnerPayloads: authRespInner}},
		}
	}
	// Responder: same messages, directions inverted.
	spirZero := uint64(0)
	return []core.IKEMessage{
		{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true,
			ResponderSPI: &spirZero, Payloads: initReq},
		{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true,
			Payloads: initResp},
		{Direction: "down", ExchangeType: ExchangeIKE_SA_AUTH, FromOriginalInitiator: true,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: authReqInner}},
		{Direction: "up", ExchangeType: ExchangeIKE_SA_AUTH, IsResponse: true,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: authRespInner}},
	}
}

// buildEAPMD5 returns the EAP-MD5 authentication scenario (testcase 3.2).
func buildEAPMD5(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	initReq := []core.IKEPayload{
		{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
		{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
		{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
	}
	initResp := []core.IKEPayload{
		{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
		{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
		{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
	}

	// EAP-MD5: 4 rounds (Identity, MD5-Challenge, MD5-Response, Success).
	md5Challenge := make([]byte, 16)
	eapID := uint8(0)
	eapRound := func(code uint8, eapType uint8, data []byte) core.IKEPayload {
		t := eapType
		return core.IKEPayload{
			Type: PayloadEAP,
			EAP:  &core.IKEEAP{Code: code, Identifier: eapID, Type: &t, Data: data},
		}
	}
	eapSuccess := core.IKEPayload{
		Type: PayloadEAP,
		EAP:  &core.IKEEAP{Code: 3, Identifier: eapID + 1},
	}
	eapID++ // Identity
	identityReq := eapRound(1, 1, nil) // Request/Identity
	identityResp := eapRound(2, 1, idData)
	eapID++ // MD5
	md5Req := eapRound(1, 4, md5Challenge)        // Request/MD5-Challenge
	md5Resp := eapRound(2, 4, make([]byte, 16))    // Response/MD5

	authReqInner := []core.IKEPayload{
		{Type: PayloadIDi, ID: &core.IKEIdentity{IDType: 1, Data: idData}},
	}
	authRespInner := []core.IKEPayload{
		{Type: PayloadIDr, ID: &core.IKEIdentity{IDType: 1, Data: idData}},
		identityReq,
	}
	authReq2Inner := []core.IKEPayload{identityResp}
	authResp2Inner := []core.IKEPayload{md5Req}
	authReq3Inner := []core.IKEPayload{md5Resp}
	authResp3Inner := []core.IKEPayload{eapSuccess}
	authReq4Inner := []core.IKEPayload{
		{Type: PayloadAUTH, Auth: &core.IKEAuth{Method: cfg.DefaultAuthMethod}},
	}
	authResp4Inner := []core.IKEPayload{
		{Type: PayloadAUTH, Auth: &core.IKEAuth{Method: cfg.DefaultAuthMethod}},
		{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
		{Type: PayloadTSi, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
		{Type: PayloadTSr, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
	}

	upDown := func(direction string, isResp bool, isOrigInit bool, inner []core.IKEPayload) core.IKEMessage {
		return core.IKEMessage{
			Direction: direction, ExchangeType: ExchangeIKE_SA_AUTH,
			IsResponse: isResp, FromOriginalInitiator: isOrigInit,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: inner},
		}
	}

	if isInit {
		return []core.IKEMessage{
			{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: initReq},
			{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: initResp},
			upDown("up", false, true, authReqInner),
			upDown("down", true, false, authRespInner),
			upDown("up", false, true, authReq2Inner),
			upDown("down", true, false, authResp2Inner),
			upDown("up", false, true, authReq3Inner),
			upDown("down", true, false, authResp3Inner),
			upDown("up", false, true, authReq4Inner),
			upDown("down", true, false, authResp4Inner),
		}
	}
	return []core.IKEMessage{
		{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: initReq},
		{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: initResp},
		upDown("down", false, true, authReqInner),
		upDown("up", true, false, authRespInner),
		upDown("down", false, true, authReq2Inner),
		upDown("up", true, false, authResp2Inner),
		upDown("down", false, true, authReq3Inner),
		upDown("up", true, false, authResp3Inner),
		upDown("down", false, true, authReq4Inner),
		upDown("up", true, false, authResp4Inner),
	}
}

// buildEAPTLS returns the EAP-TLS scenario (testcase 3.3).
func buildEAPTLS(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	// EAP-TLS: 5+ rounds. Each EAP-TLS payload uses Type=13 with opaque
	// Type-Data bytes. The opaque bytes are arbitrary — the planner does
	// not parse TLS.
	tlsChunk1 := []byte{0x80, 0x00, 0x00, 0x00, 0x10} // TLS ClientHello-like header
	tlsChunk2 := []byte{0x80, 0x00, 0x00, 0x00, 0x20} // ServerHello-like

	eapType13 := uint8(13)

	initReq := []core.IKEPayload{
		{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
		{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
		{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
	}
	initResp := []core.IKEPayload{
		{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
		{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
		{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
	}

	mkEAP := func(code uint8, id uint8, data []byte) core.IKEPayload {
		t := eapType13
		return core.IKEPayload{Type: PayloadEAP, EAP: &core.IKEEAP{Code: code, Identifier: id, Type: &t, Data: data}}
	}
	mkEAPIdentity := func(code uint8, id uint8, data []byte) core.IKEPayload {
		t := uint8(1)
		return core.IKEPayload{Type: PayloadEAP, EAP: &core.IKEEAP{Code: code, Identifier: id, Type: &t, Data: data}}
	}
	mkEAPSuccess := func(id uint8) core.IKEPayload {
		return core.IKEPayload{Type: PayloadEAP, EAP: &core.IKEEAP{Code: 3, Identifier: id}}
	}

	round := func(direction string, isResp bool, inner []core.IKEPayload) core.IKEMessage {
		return core.IKEMessage{
			Direction: direction, ExchangeType: ExchangeIKE_SA_AUTH,
			IsResponse: isResp, FromOriginalInitiator: !isResp,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: inner},
		}
	}

	id := uint8(0)
	authReqInner := []core.IKEPayload{
		{Type: PayloadIDi, ID: &core.IKEIdentity{IDType: 1, Data: idData}},
	}
	authRespInner := []core.IKEPayload{
		{Type: PayloadIDr, ID: &core.IKEIdentity{IDType: 1, Data: idData}},
		mkEAPIdentity(1, id, nil),
	}
	id++
	authReq2Inner := []core.IKEPayload{mkEAPIdentity(2, id, idData)}
	id++
	authResp2Inner := []core.IKEPayload{mkEAP(1, id, tlsChunk1)}
	id++
	authReq3Inner := []core.IKEPayload{mkEAP(2, id, tlsChunk1)}
	id++
	authResp3Inner := []core.IKEPayload{mkEAP(1, id, tlsChunk2)}
	id++
	authReq4Inner := []core.IKEPayload{mkEAP(2, id, tlsChunk2)}
	id++
	authResp4Inner := []core.IKEPayload{mkEAPSuccess(id)}
	authReq5Inner := []core.IKEPayload{
		{Type: PayloadAUTH, Auth: &core.IKEAuth{Method: cfg.DefaultAuthMethod}},
	}
	authResp5Inner := []core.IKEPayload{
		{Type: PayloadAUTH, Auth: &core.IKEAuth{Method: cfg.DefaultAuthMethod}},
		{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
		{Type: PayloadTSi, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
		{Type: PayloadTSr, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
	}

	if isInit {
		return []core.IKEMessage{
			{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: initReq},
			{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: initResp},
			round("up", false, authReqInner),
			round("down", true, authRespInner),
			round("up", false, authReq2Inner),
			round("down", true, authResp2Inner),
			round("up", false, authReq3Inner),
			round("down", true, authResp3Inner),
			round("up", false, authReq4Inner),
			round("down", true, authResp4Inner),
			round("up", false, authReq5Inner),
			round("down", true, authResp5Inner),
		}
	}
	return []core.IKEMessage{
		{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: initReq},
		{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: initResp},
		round("down", false, authReqInner),
		round("up", true, authRespInner),
		round("down", false, authReq2Inner),
		round("up", true, authResp2Inner),
		round("down", false, authReq3Inner),
		round("up", true, authResp3Inner),
		round("down", false, authReq4Inner),
		round("up", true, authResp4Inner),
		round("down", false, authReq5Inner),
		round("up", true, authResp5Inner),
	}
}

// buildEAPOnly returns the EAP-only authentication scenario (RFC 5998).
func buildEAPOnly(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	return buildEAPMD5(prop, idData, cfg, isInit) // Simplified: EAP-MD5 layout, with eap_only=true at config level.
}

// buildDPD returns the DPD scenario: INIT + AUTH + N empty INFORMATIONALs.
func buildDPD(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	base := buildStandardV2(prop, idData, cfg, isInit)
	dpdCount := cfg.DPDCount
	if dpdCount == 0 {
		dpdCount = 3
	}
	dir := "up"
	respDir := "down"
	isOrig := true
	isResp := false
	if !isInit {
		dir = "down"
		respDir = "up"
		isOrig = true
		isResp = false
	}
	for i := 0; i < dpdCount; i++ {
		base = append(base,
			core.IKEMessage{Direction: dir, ExchangeType: ExchangeINFORMATIONAL, FromOriginalInitiator: isOrig, Encrypted: &core.IKEEncryptedBody{}},
			core.IKEMessage{Direction: respDir, ExchangeType: ExchangeINFORMATIONAL, IsResponse: true, Encrypted: &core.IKEEncryptedBody{}},
		)
	}
	_ = isResp
	return base
}

// buildDeleteSA returns the delete SA scenario.
func buildDeleteSA(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	base := buildStandardV2(prop, idData, cfg, isInit)
	dir := "up"
	respDir := "down"
	isOrig := true
	if !isInit {
		dir = "down"
		respDir = "up"
		isOrig = true
	}

	// Delete CHILD SA (ESP SPI 4-byte example).
	espSPI := []byte{0x01, 0x02, 0x03, 0x04}
	base = append(base,
		core.IKEMessage{Direction: dir, ExchangeType: ExchangeINFORMATIONAL, FromOriginalInitiator: isOrig,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadDELETE, Delete: &core.IKEDelete{ProtocolID: ProtocolESP, SPISize: 4, SPIs: [][]byte{espSPI}}},
			}}},
		core.IKEMessage{Direction: respDir, ExchangeType: ExchangeINFORMATIONAL, IsResponse: true,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadDELETE, Delete: &core.IKEDelete{ProtocolID: ProtocolESP, SPISize: 4, SPIs: [][]byte{espSPI}}},
			}}},
		// Delete IKE SA.
		core.IKEMessage{Direction: dir, ExchangeType: ExchangeINFORMATIONAL, FromOriginalInitiator: isOrig,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadDELETE, Delete: &core.IKEDelete{ProtocolID: ProtocolIKE, SPISize: 0}},
			}}},
		core.IKEMessage{Direction: respDir, ExchangeType: ExchangeINFORMATIONAL, IsResponse: true,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadDELETE, Delete: &core.IKEDelete{ProtocolID: ProtocolIKE, SPISize: 0}},
			}}},
	)
	return base
}

// buildInformational returns the informational scenario: INIT + AUTH + NOTIFY.
func buildInformational(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	base := buildStandardV2(prop, idData, cfg, isInit)
	dir := "up"
	respDir := "down"
	isOrig := true
	if !isInit {
		dir = "down"
		respDir = "up"
		isOrig = true
	}
	base = append(base,
		core.IKEMessage{Direction: dir, ExchangeType: ExchangeINFORMATIONAL, FromOriginalInitiator: isOrig,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 14}}, // NO_PROPOSAL_CHOSEN test
			}}},
		core.IKEMessage{Direction: respDir, ExchangeType: ExchangeINFORMATIONAL, IsResponse: true,
			Encrypted: &core.IKEEncryptedBody{}},
	)
	return base
}

// buildNATDetection returns the NAT detection scenario: INIT with NAT NOTIFYs.
func buildNATDetection(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	// NAT detection source/destination payloads — 20 bytes SHA-1.
	natData := make([]byte, 20)

	natNotifSrc := &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16388, Data: natData}
	natNotifDst := &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16389, Data: natData}

	initReq := []core.IKEPayload{
		{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
		{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
		{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
		{Type: PayloadNOTIFY, Notify: natNotifSrc},
		{Type: PayloadNOTIFY, Notify: natNotifDst},
	}
	initResp := []core.IKEPayload{
		{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
		{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
		{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
		{Type: PayloadNOTIFY, Notify: natNotifSrc},
		{Type: PayloadNOTIFY, Notify: natNotifDst},
	}

	if isInit {
		return []core.IKEMessage{
			{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: initReq},
			{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: initResp},
			{Direction: "up", ExchangeType: ExchangeIKE_SA_AUTH, FromOriginalInitiator: true, Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadIDi, ID: &core.IKEIdentity{IDType: 1, Data: idData}},
				{Type: PayloadAUTH, Auth: &core.IKEAuth{Method: cfg.DefaultAuthMethod}},
			}}},
			{Direction: "down", ExchangeType: ExchangeIKE_SA_AUTH, IsResponse: true, Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadIDr, ID: &core.IKEIdentity{IDType: 1, Data: idData}},
				{Type: PayloadAUTH, Auth: &core.IKEAuth{Method: cfg.DefaultAuthMethod}},
			}}},
		}
	}
	return []core.IKEMessage{
		{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: initReq},
		{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: initResp},
		{Direction: "down", ExchangeType: ExchangeIKE_SA_AUTH, FromOriginalInitiator: true, Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
			{Type: PayloadIDi, ID: &core.IKEIdentity{IDType: 1, Data: idData}},
			{Type: PayloadAUTH, Auth: &core.IKEAuth{Method: cfg.DefaultAuthMethod}},
		}}},
		{Direction: "up", ExchangeType: ExchangeIKE_SA_AUTH, IsResponse: true, Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
			{Type: PayloadIDr, ID: &core.IKEIdentity{IDType: 1, Data: idData}},
			{Type: PayloadAUTH, Auth: &core.IKEAuth{Method: cfg.DefaultAuthMethod}},
		}}},
	}
}

// buildIKEv1 returns a minimal IKEv1 compatibility scenario.
func buildIKEv1(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	_ = idData
	if isInit {
		return []core.IKEMessage{
			{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
				{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
			}},
		}
	}
	return []core.IKEMessage{
		{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{
			{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
			{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
		}},
	}
}

// buildMultipleChildSA returns a scenario with multiple CREATE_CHILD_SA exchanges.
func buildMultipleChildSA(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	base := buildStandardV2(prop, idData, cfg, isInit)
	dir := "up"
	respDir := "down"
	isOrig := true
	if !isInit {
		dir = "down"
		respDir = "up"
		isOrig = true
	}

	// Three CREATE_CHILD_SA exchanges.
	for i := 0; i < 3; i++ {
		base = append(base,
			core.IKEMessage{Direction: dir, ExchangeType: ExchangeCREATE_CHILD_SA, FromOriginalInitiator: isOrig,
				Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
					{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
					{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
					{Type: PayloadTSi, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
					{Type: PayloadTSr, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
				}}},
			core.IKEMessage{Direction: respDir, ExchangeType: ExchangeCREATE_CHILD_SA, IsResponse: true,
				Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
					{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
					{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
					{Type: PayloadTSi, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
					{Type: PayloadTSr, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
				}}},
		)
	}
	return base
}

// buildChildRekey returns the CHILD SA rekey scenario.
func buildChildRekey(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	base := buildStandardV2(prop, idData, cfg, isInit)
	dir := "up"
	respDir := "down"
	isOrig := true
	if !isInit {
		dir = "down"
		respDir = "up"
		isOrig = true
	}

	// CHILD SA Rekey: CREATE_CHILD_SA with REKEY_SA notify + old SPI.
	oldSPI := []byte{0x01, 0x02, 0x03, 0x04}
	rekeyNotify := &core.IKENotify{ProtocolID: ProtocolESP, SPI: oldSPI, MessageType: 32} // REKEY_SA = 32
	base = append(base,
		core.IKEMessage{Direction: dir, ExchangeType: ExchangeCREATE_CHILD_SA, FromOriginalInitiator: isOrig,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
				{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
				{Type: PayloadNOTIFY, Notify: rekeyNotify},
				{Type: PayloadTSi, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
				{Type: PayloadTSr, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
			}}},
		core.IKEMessage{Direction: respDir, ExchangeType: ExchangeCREATE_CHILD_SA, IsResponse: true,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
				{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
				{Type: PayloadTSi, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
				{Type: PayloadTSr, TrafficSelectors: []core.IKETrafficSelector{makeTSv4All()}},
			}}},
		// INFORMATIONAL DELETE old SPI.
		core.IKEMessage{Direction: dir, ExchangeType: ExchangeINFORMATIONAL, FromOriginalInitiator: isOrig,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadDELETE, Delete: &core.IKEDelete{ProtocolID: ProtocolESP, SPISize: 4, SPIs: [][]byte{oldSPI}}},
			}}},
		core.IKEMessage{Direction: respDir, ExchangeType: ExchangeINFORMATIONAL, IsResponse: true,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadDELETE, Delete: &core.IKEDelete{ProtocolID: ProtocolESP, SPISize: 4, SPIs: [][]byte{oldSPI}}},
			}}},
	)
	return base
}

// buildIKERekey returns the IKE SA rekey scenario.
func buildIKERekey(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	base := buildStandardV2(prop, idData, cfg, isInit)
	dir := "up"
	respDir := "down"
	isOrig := true
	if !isInit {
		dir = "down"
		respDir = "up"
		isOrig = true
	}

	// IKE SA Rekey: CREATE_CHILD_SA with Protocol IKE proposal + KE.
	ikeProposal := *prop
	ikeProposal.ProtocolID = ProtocolIKE
	base = append(base,
		core.IKEMessage{Direction: dir, ExchangeType: ExchangeCREATE_CHILD_SA, FromOriginalInitiator: isOrig,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{ikeProposal}}},
				{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
				{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
			}}},
		core.IKEMessage{Direction: respDir, ExchangeType: ExchangeCREATE_CHILD_SA, IsResponse: true,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{ikeProposal}}},
				{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
				{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
			}}},
		// INFORMATIONAL DELETE IKE SA.
		core.IKEMessage{Direction: dir, ExchangeType: ExchangeINFORMATIONAL, FromOriginalInitiator: isOrig,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadDELETE, Delete: &core.IKEDelete{ProtocolID: ProtocolIKE, SPISize: 0}},
			}}},
		core.IKEMessage{Direction: respDir, ExchangeType: ExchangeINFORMATIONAL, IsResponse: true,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadDELETE, Delete: &core.IKEDelete{ProtocolID: ProtocolIKE, SPISize: 0}},
			}}},
	)
	return base
}

// buildInvalidKERetry returns the INVALID_KE_PAYLOAD retry scenario.
func buildInvalidKERetry(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	if isInit {
		return []core.IKEMessage{
			// First INIT with DH=19.
			{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
				{Type: PayloadKE, KE: &core.IKEKE{DHGroup: 19}},
				{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
			}},
			// Response: INVALID_KE_PAYLOAD suggesting DH=14.
			{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: []core.IKEPayload{
				{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 17, Data: []byte{0x00, 0x0E}}},
			}},
			// Retry INIT with DH=14, same Message ID=0.
			{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
				{Type: PayloadKE, KE: &core.IKEKE{DHGroup: 14}},
				{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
			}},
			// Normal response.
			{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
				{Type: PayloadKE, KE: &core.IKEKE{DHGroup: 14}},
				{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
			}},
		}
	}
	return []core.IKEMessage{
		{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{
			{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
			{Type: PayloadKE, KE: &core.IKEKE{DHGroup: 19}},
			{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
		}},
		{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: []core.IKEPayload{
			{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 17, Data: []byte{0x00, 0x0E}}},
		}},
	}
}

// buildCookieRetry returns the COOKIE retry scenario.
func buildCookieRetry(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	cookie := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if isInit {
		return []core.IKEMessage{
			// First INIT.
			{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
				{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
				{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
			}},
			// Response with COOKIE notify.
			{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: []core.IKEPayload{
				{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16390, Data: cookie}},
			}},
			// Retry INIT with COOKIE.
			{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
				{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
				{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
				{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16390, Data: cookie}},
			}},
			// Normal response.
			{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
				{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
				{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
			}},
		}
	}
	return []core.IKEMessage{
		{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{
			{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
			{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
			{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
		}},
		{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: []core.IKEPayload{
			{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16390, Data: cookie}},
		}},
	}
}

// buildCertChain returns the cert chain scenario: AUTH with 3 CERTs.
func buildCertChain(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	base := buildStandardV2(prop, idData, cfg, isInit)
	// Replace AUTH inner with: CERTREQ + 3×CERT + AUTH.
	inner := []core.IKEPayload{
		{Type: PayloadIDi, ID: &core.IKEIdentity{IDType: 1, Data: idData}},
		{Type: PayloadCERTREQ, CertificateRequest: &core.IKECertificateRequest{
			Encoding: 4,
			CAs:      [][]byte{make([]byte, 20)}, // one CA SHA-1 hash
		}},
		{Type: PayloadCERT, Certificate: &core.IKECertificate{Encoding: 4, Data: make([]byte, 32)}},
		{Type: PayloadCERT, Certificate: &core.IKECertificate{Encoding: 4, Data: make([]byte, 32)}},
		{Type: PayloadCERT, Certificate: &core.IKECertificate{Encoding: 4, Data: make([]byte, 32)}},
		{Type: PayloadAUTH, Auth: &core.IKEAuth{Method: 9}}, // ECDSA
	}
	if isInit {
		base[2] = core.IKEMessage{Direction: "up", ExchangeType: ExchangeIKE_SA_AUTH, FromOriginalInitiator: true,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: inner}}
	} else {
		base[2] = core.IKEMessage{Direction: "down", ExchangeType: ExchangeIKE_SA_AUTH, FromOriginalInitiator: true,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: inner}}
	}
	return base
}

// buildPPK returns the RFC 8784 PPK scenario.
func buildPPK(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	ppkID := []byte("ppk-id-1")
	if isInit {
		return []core.IKEMessage{
			// INIT with INTERMEDIATE_EXCHANGE_SUPPORTED notify.
			{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
				{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
				{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
				{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16438}},
			}},
			{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
				{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
				{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
				{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16438}},
			}},
			// IKE_INTERMEDIATE (Exchange=43) — opaque SK data.
			{Direction: "up", ExchangeType: ExchangeIKE_INTERMEDIATE, FromOriginalInitiator: true,
				Encrypted: &core.IKEEncryptedBody{OpaqueData: make([]byte, 64)}},
			{Direction: "down", ExchangeType: ExchangeIKE_INTERMEDIATE, IsResponse: true,
				Encrypted: &core.IKEEncryptedBody{OpaqueData: make([]byte, 64)}},
			// AUTH with USE_PPK + PPK_IDENTITY notify.
			{Direction: "up", ExchangeType: ExchangeIKE_SA_AUTH, FromOriginalInitiator: true,
				Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
					{Type: PayloadIDi, ID: &core.IKEIdentity{IDType: 11, Data: ppkID}},
					{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16435}}, // USE_PPK
					{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16436, Data: ppkID}},
					{Type: PayloadAUTH, Auth: &core.IKEAuth{Method: cfg.DefaultAuthMethod}},
				}}},
			{Direction: "down", ExchangeType: ExchangeIKE_SA_AUTH, IsResponse: true,
				Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
					{Type: PayloadIDr, ID: &core.IKEIdentity{IDType: 11, Data: ppkID}},
					{Type: PayloadAUTH, Auth: &core.IKEAuth{Method: cfg.DefaultAuthMethod}},
				}}},
		}
	}
	return []core.IKEMessage{
		{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{
			{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
			{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
			{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
			{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16438}},
		}},
		{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: []core.IKEPayload{
			{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
			{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
			{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
			{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16438}},
		}},
		{Direction: "down", ExchangeType: ExchangeIKE_INTERMEDIATE, FromOriginalInitiator: true,
			Encrypted: &core.IKEEncryptedBody{OpaqueData: make([]byte, 64)}},
		{Direction: "up", ExchangeType: ExchangeIKE_INTERMEDIATE, IsResponse: true,
			Encrypted: &core.IKEEncryptedBody{OpaqueData: make([]byte, 64)}},
		{Direction: "down", ExchangeType: ExchangeIKE_SA_AUTH, FromOriginalInitiator: true,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadIDi, ID: &core.IKEIdentity{IDType: 11, Data: ppkID}},
				{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16435}},
				{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16436, Data: ppkID}},
				{Type: PayloadAUTH, Auth: &core.IKEAuth{Method: cfg.DefaultAuthMethod}},
			}}},
		{Direction: "up", ExchangeType: ExchangeIKE_SA_AUTH, IsResponse: true,
			Encrypted: &core.IKEEncryptedBody{InnerPayloads: []core.IKEPayload{
				{Type: PayloadIDr, ID: &core.IKEIdentity{IDType: 11, Data: ppkID}},
				{Type: PayloadAUTH, Auth: &core.IKEAuth{Method: cfg.DefaultAuthMethod}},
			}}},
	}
}

// buildNullAuth returns the NULL authentication scenario (RFC 7619).
func buildNullAuth(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	nullcfg := cfg
	nullcfg.DefaultAuthMethod = 13 // NULL
	return buildStandardV2(prop, idData, nullcfg, isInit)
}

// buildSessionResume returns the IKE_SESSION_RESUME scenario (Exchange 38).
func buildSessionResume(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	_ = prop
	_ = idData
	_ = cfg
	if isInit {
		return []core.IKEMessage{
			{Direction: "up", ExchangeType: ExchangeIKE_SESSION_RESUME, FromOriginalInitiator: true,
				Encrypted: &core.IKEEncryptedBody{OpaqueData: make([]byte, 64)}},
			{Direction: "down", ExchangeType: ExchangeIKE_SESSION_RESUME, IsResponse: true,
				Encrypted: &core.IKEEncryptedBody{OpaqueData: make([]byte, 64)}},
		}
	}
	return []core.IKEMessage{
		{Direction: "down", ExchangeType: ExchangeIKE_SESSION_RESUME, FromOriginalInitiator: true,
			Encrypted: &core.IKEEncryptedBody{OpaqueData: make([]byte, 64)}},
		{Direction: "up", ExchangeType: ExchangeIKE_SESSION_RESUME, IsResponse: true,
			Encrypted: &core.IKEEncryptedBody{OpaqueData: make([]byte, 64)}},
	}
}

// buildFragmentedAuth returns the fragmented AUTH scenario.
// For simplicity we emit a single AUTH with a large OpaqueData that the
// builder will split into SKF (type 53) fragments.
func buildFragmentedAuth(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	big := make([]byte, 5000)
	if isInit {
		return []core.IKEMessage{
			{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
				{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
				{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
				{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16430}},
			}},
			{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: []core.IKEPayload{
				{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
				{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
				{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
				{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16430}},
			}},
			{Direction: "up", ExchangeType: ExchangeIKE_SA_AUTH, FromOriginalInitiator: true,
				Encrypted: &core.IKEEncryptedBody{OpaqueData: big}},
			{Direction: "down", ExchangeType: ExchangeIKE_SA_AUTH, IsResponse: true,
				Encrypted: &core.IKEEncryptedBody{OpaqueData: big}},
		}
	}
	return []core.IKEMessage{
		{Direction: "down", ExchangeType: ExchangeIKE_SA_INIT, FromOriginalInitiator: true, Payloads: []core.IKEPayload{
			{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
			{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
			{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
			{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16430}},
		}},
		{Direction: "up", ExchangeType: ExchangeIKE_SA_INIT, IsResponse: true, Payloads: []core.IKEPayload{
			{Type: PayloadSA, SA: &core.IKESA{Proposals: []core.IKEProposal{*prop}}},
			{Type: PayloadKE, KE: &core.IKEKE{DHGroup: cfg.DefaultDHGroup}},
			{Type: PayloadNONCE, Nonce: make([]byte, cfg.DefaultNonceSize)},
			{Type: PayloadNOTIFY, Notify: &core.IKENotify{ProtocolID: ProtocolIKE, MessageType: 16430}},
		}},
		{Direction: "down", ExchangeType: ExchangeIKE_SA_AUTH, FromOriginalInitiator: true,
			Encrypted: &core.IKEEncryptedBody{OpaqueData: big}},
		{Direction: "up", ExchangeType: ExchangeIKE_SA_AUTH, IsResponse: true,
			Encrypted: &core.IKEEncryptedBody{OpaqueData: big}},
	}
}

// buildRekey returns a combined rekey scenario.
func buildRekey(prop *core.IKEProposal, idData []byte, cfg core.IKEConfig, isInit bool) []core.IKEMessage {
	base := buildChildRekey(prop, idData, cfg, isInit)
	return append(base, buildIKERekey(prop, idData, cfg, isInit)...)
}

// --- Helpers ---

// makeTSv4All returns a "match everything IPv4" Traffic Selector.
func makeTSv4All() core.IKETrafficSelector {
	return core.IKETrafficSelector{
		TSType:       7, // IPv4_RANGE
		IPProtocolID: 0, // any
		StartPort:    0,
		EndPort:      65535,
		StartAddress: []byte{0, 0, 0, 0},
		EndAddress:   []byte{255, 255, 255, 255},
	}
}

// exchangeTypeName returns the ASCII name of an Exchange Type (for logging / debug).
func exchangeTypeName(e uint8) string {
	switch e {
	case ExchangeIKE_SA_INIT:
		return "IKE_SA_INIT"
	case ExchangeIKE_SA_AUTH:
		return "IKE_SA_AUTH"
	case ExchangeCREATE_CHILD_SA:
		return "CREATE_CHILD_SA"
	case ExchangeINFORMATIONAL:
		return "INFORMATIONAL"
	case ExchangeIKE_SESSION_RESUME:
		return "IKE_SESSION_RESUME"
	case ExchangeIKE_INTERMEDIATE:
		return "IKE_INTERMEDIATE"
	}
	return "UNKNOWN"
}