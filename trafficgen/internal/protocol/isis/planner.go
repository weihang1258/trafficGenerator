package isis

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner validates an IS-IS flow spec. IS-IS is an L2-only [eth, isis] chain;
// the terminal generator emits full packets via req.Emit.
type Planner struct{}

func NewPlanner() *Planner    { return &Planner{} }
func (*Planner) Name() string { return "isis" }

// Validate rejects invalid IS-IS specs (negative-path cases). Each error
// message contains a stable substring that the case's error_contains anchors on.
func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.ISIS
	if cfg == nil {
		return nil
	}
	// 1. Unknown wire profile (error_contains "profile").
	switch cfg.WireProfile {
	case "", "iso10589_llc", "iso10589_ethertype":
		// ok
	default:
		return fmt.Errorf("isis: unknown wire profile %q (want iso10589_llc or iso10589_ethertype)", cfg.WireProfile)
	}
	// 2. Single top-level config with events: validate each event.
	if err := validateLevelAndType(cfg.Level, cfg.PDUType, cfg.WireFault); err != nil {
		return err
	}
	// 3. System ID must be 6 bytes (error_contains "system").
	for _, sid := range []string{cfg.SystemID} {
		if cfg.SystemID == "" {
			continue
		}
		if _, err := parseSystemID(sid); err != nil {
			return fmt.Errorf("isis: %v", err)
		}
	}
	// 4. LSP IDs (error_contains "system" / "length").
	for _, lid := range []string{cfg.LSPID, cfg.StartLSPID, cfg.EndLSPID} {
		if lid == "" {
			continue
		}
		if _, err := parseLSPID(lid); err != nil {
			return fmt.Errorf("isis: %v", err)
		}
	}
	// 5. Address profile (error_contains "address").
	if err := validateAddressProfile(cfg.AddressProfile, cfg.TLVs); err != nil {
		return err
	}
	// 6. Duplicate area address source (error_contains "area").
	if len(cfg.AreaAddresses) > 0 && hasAreaTLV(cfg.TLVs) {
		return fmt.Errorf("isis: duplicate area address source (area_addresses and TLV type 1 both set)")
	}
	// 7. IP carrier must be absent (IS-IS is L2-only, error_contains "carrier").
	// spec.SrcIP/DstIP/ports are always defaulted for isis (10.0.0.1/20.0.0.1/
	// 12345/80), so they cannot distinguish a real IP carrier — an [ip, isis]
	// chain is rejected earlier by the chain validator. Here we reject the
	// mixed LLC + EtherType carrier (neg_mixed_carrier).
	if cfg.WireFault != nil && cfg.WireFault.Kind == "mixed_carrier" {
		return fmt.Errorf("isis: mixed carrier (LLC and EtherType both set)")
	}
	if cfg.LLC != nil && cfg.WireProfile == "iso10589_ethertype" {
		return fmt.Errorf("isis: mixed carrier (LLC header set with ethertype profile)")
	}
	// 8. Header fault (error_contains "header").
	if cfg.WireFault != nil && cfg.WireFault.Kind == "header" {
		if cfg.WireFault.HeaderLength != 8 {
			return fmt.Errorf("isis: bad header (header length %d must be 8)", cfg.WireFault.HeaderLength)
		}
	}
	// 10. Level/type fault (error_contains "level").
	if cfg.WireFault != nil && cfg.WireFault.Kind == "level_type" {
		return fmt.Errorf("isis: level/type mismatch (level %q with pdu_type %d / circuit_type %d)", cfg.Level, cfg.WireFault.PDUType, cfg.WireFault.CircuitType)
	}
	// 11. PDU/TLV length fault (error_contains "length").
	if cfg.WireFault != nil && cfg.WireFault.Kind == "length" {
		return fmt.Errorf("isis: length mismatch (declared pdu_length %d)", cfg.WireFault.PDULength)
	}
	if cfg.WireFault != nil && cfg.WireFault.Kind == "declared_length" {
		return fmt.Errorf("isis: length mismatch (declared pdu_length %d)", cfg.WireFault.PDULength)
	}
	// 12. Vendor TLV (error_contains "tlv").
	for _, t := range cfg.TLVs {
		if !isKnownTLV(t.Type) {
			return fmt.Errorf("isis: unsupported tlv type %d (vendor/unknown tlv, only 1/9/132/232/236 allowed)", t.Type)
		}
		if t.Type == 9 && cfg.PDUType != "csnp" && cfg.PDUType != "psnp" {
			return fmt.Errorf("isis: tlv type 9 (LSP Entries) only valid for CSNP/PSNP (got %q)", cfg.PDUType)
		}
		if _, err := parseHexSpace(t.ValueHex); err != nil {
			return fmt.Errorf("isis: tlv %d has invalid value_hex: %v", t.Type, err)
		}
	}
	// 13. Checksum fault (error_contains "checksum").
	if cfg.WireFault != nil && cfg.WireFault.Kind == "checksum" {
		return fmt.Errorf("isis: bad LSP checksum (manual checksum injected via wire_fault)")
	}
	if cfg.ChecksumMode != "" && cfg.ChecksumMode != "auto" && cfg.ChecksumMode != "manual" {
		return fmt.Errorf("isis: invalid checksum_mode %q", cfg.ChecksumMode)
	}
	// 14. Event sequence validation (error_contains "state" / "address" / "system").
	for i, ev := range cfg.Events {
		if err := validateEvent(ev); err != nil {
			return fmt.Errorf("isis: events[%d] %v", i, err)
		}
		if err := validateAddressProfile(ev.AddressProfile, ev.TLVs); err != nil {
			return fmt.Errorf("isis: events[%d] %v", i, err)
		}
		for _, t := range ev.TLVs {
			if !isKnownTLV(t.Type) {
				return fmt.Errorf("isis: events[%d] unsupported TLV type %d", i, t.Type)
			}
		}
		if ev.Kind == "lsp" || ev.Kind == "csnp" || ev.Kind == "psnp" {
			if ev.SystemID != "" {
				if _, err := parseSystemID(ev.SystemID); err != nil {
					return fmt.Errorf("isis: events[%d] %v", i, err)
				}
			}
			if ev.LSPID != "" {
				if _, err := parseLSPID(ev.LSPID); err != nil {
					return fmt.Errorf("isis: events[%d] %v", i, err)
				}
			}
		}
	}
	return nil
}

// validateEvent validates one event in a sequence. The neighbor state must be
// a legal adjacency state (error_contains "state").
func validateEvent(ev core.ISISEvent) error {
	switch ev.Kind {
	case "iih", "lsp", "psnp", "csnp":
		// ok
	case "":
		return fmt.Errorf("missing kind")
	default:
		return fmt.Errorf("invalid kind %q", ev.Kind)
	}
	switch ev.NeighborState {
	case "", "Init", "Initializing", "Up", "Down":
		// ok
	default:
		return fmt.Errorf("invalid neighbor state %q", ev.NeighborState)
	}
	if ev.NeighborState == "Down" && ev.Kind != "iih" {
		return fmt.Errorf("invalid neighbor state %q for %q (Down is only valid for IIH)", ev.NeighborState, ev.Kind)
	}
	return nil
}

// validateLevelAndType validates the level/pdu_type combination.
func validateLevelAndType(level, pduType string, wf *core.ISISWireFault) error {
	if level != "" && level != "l1" && level != "l2" {
		return fmt.Errorf("isis: invalid level %q", level)
	}
	if wf != nil && wf.Kind == "level_type" {
		return fmt.Errorf("isis: level/type mismatch (level %q)", level)
	}
	if pduType == "" {
		return nil
	}
	switch pduType {
	case "lan_hello", "p2p_hello", "lsp", "psnp", "csnp", "events":
		// ok
	default:
		return fmt.Errorf("isis: invalid pdu_type %q", pduType)
	}
	return nil
}

// validateAddressProfile validates the TLV address-family profile
// (error_contains "address"). ipv4_basic uses TLV 132, ipv6_basic uses TLV 232;
// mixing them is rejected.
func validateAddressProfile(profile string, tlvs []core.ISISTLV) error {
	if profile == "" {
		return nil
	}
	if profile != "ipv4_basic" && profile != "ipv6_basic" {
		return fmt.Errorf("isis: invalid address profile %q", profile)
	}
	hasV4 := hasTLV(tlvs, 132)
	hasV6 := hasTLV(tlvs, 232)
	if profile == "ipv4_basic" && hasV6 {
		return fmt.Errorf("isis: address family mismatch (ipv4_basic profile but IPv6 TLV 232 present)")
	}
	if profile == "ipv6_basic" && hasV4 {
		return fmt.Errorf("isis: address family mismatch (ipv6_basic profile but IPv4 TLV 132 present)")
	}
	if profile == "ipv4_basic" && !hasV4 {
		return fmt.Errorf("isis: ipv4_basic profile requires IPv4 TLV 132")
	}
	if profile == "ipv6_basic" && !hasV6 {
		return fmt.Errorf("isis: ipv6_basic profile requires IPv6 TLV 232")
	}
	return nil
}

func hasAreaTLV(tlvs []core.ISISTLV) bool {
	return hasTLV(tlvs, 1)
}

func hasTLV(tlvs []core.ISISTLV, t int) bool {
	for _, x := range tlvs {
		if x.Type == t {
			return true
		}
	}
	return false
}

// isKnownTLV reports whether the TLV type is a registered standard type.
func isKnownTLV(t int) bool {
	switch t {
	case 1, 9, 132, 232, 236:
		return true
	}
	return false
}
