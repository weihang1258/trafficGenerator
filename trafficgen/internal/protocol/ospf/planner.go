package ospf

import (
	"fmt"
	"net"

	"github.com/trafficgen/trafficgen/internal/core"
)

type Planner struct{}

func NewPlanner() *Planner    { return &Planner{} }
func (*Planner) Name() string { return "ospf" }

// Validate rejects invalid OSPF specs (negative-path cases). OSPFv2 only
// (RFC 2328). A nil config is allowed (P0b-2 default).
func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.OSPF
	if cfg == nil {
		return nil
	}
	// OSPFv3 (RFC 5340) rejection. The ipv6_rfc5340_boundary case sends
	// version=3 + profile=rfc5340_ipv6; error_contains "rfc5340".
	if cfg.Profile == "rfc5340_ipv6" || cfg.Version == 3 {
		return fmt.Errorf("ospf: version/profile uses rfc5340 (OSPFv3, IPv6) which is rejected here; use OSPFv2 rfc2328_ipv4")
	}
	// IPv6 addressing is N/A for OSPFv2 (RFC 2328, IPv4 only). A flow whose
	// src/dst is an IPv6 address cannot be carried on IPv4 protocol 89; the
	// neg_ipv6_v2 case (IPv6 + version=2 + rfc2328_ipv4) asserts this with the
	// "rfc5340" anchor (OSPFv3 is the IPv6 variant).
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP).To4() == nil {
		return fmt.Errorf("ospf: IPv6 source address (rfc5340/OSPFv3 is IPv6; OSPFv2 rfc2328_ipv4 requires IPv4)")
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP).To4() == nil {
		return fmt.Errorf("ospf: IPv6 destination address (rfc5340/OSPFv3 is IPv6; OSPFv2 rfc2328_ipv4 requires IPv4)")
	}
	// Carrier rejection (design §6 载体): OSPFv2 rides directly on IPv4
	// protocol 89 with no TCP/UDP ports. A wire_fault kind "carrier" is the
	// planner-boundary injection for the neg_udp case (T-OSPF-N1): the UDP
	// carrier config is rejected here, error anchored "ip".
	if cfg.WireFault != nil && cfg.WireFault.Kind == "carrier" {
		return fmt.Errorf("ospf: UDP/TCP carrier is invalid for OSPFv2 (carrier must be ip protocol 89, no transport ports)")
	}
	if cfg.Version != 0 && cfg.Version != 2 {
		return fmt.Errorf("ospf: version %d must be 2 (OSPFv2 IPv4)", cfg.Version)
	}
	// packet_type invalid → error contains "type". An empty packet_type is
	// legal when the config carries an event sequence (ospf.events): the
	// generator's event branch ignores PacketType entirely (layer_gen.go
	// "Event sequence" branch, before buildFromConfig). When both events and
	// a non-empty packet_type are present the packet_type is ignored — same
	// event-authoritative semantics. A single-message config (no events)
	// still requires a valid packet_type.
	if cfg.PacketType != "" {
		if _, err := packetTypeFromString(cfg.PacketType); err != nil {
			return fmt.Errorf("ospf: %v", err)
		}
	} else if len(cfg.Events) == 0 {
		return fmt.Errorf("ospf: invalid packet_type %q (set packet_type for a single message or events for a sequence)", cfg.PacketType)
	}
	// router_id malformed → error contains "router".
	if cfg.RouterID != "" && net.ParseIP(cfg.RouterID).To4() == nil {
		return fmt.Errorf("ospf: invalid router_id %q", cfg.RouterID)
	}
	// area_id wire_fault → error contains "area".
	if cfg.WireFault != nil && cfg.WireFault.Kind == "area_id" {
		return fmt.Errorf("ospf: invalid area_id (wire_fault area_id)")
	}
	if cfg.AreaID != "" && net.ParseIP(cfg.AreaID).To4() == nil {
		return fmt.Errorf("ospf: invalid area_id %q", cfg.AreaID)
	}
	// declared_length wire_fault → error contains "length".
	if cfg.WireFault != nil && cfg.WireFault.Kind == "declared_length" {
		return fmt.Errorf("ospf: packet_length (wire_fault declared_length)")
	}
	switch cfg.ChecksumMode {
	case "", "auto", "invalid", "zero", "bad":
	default:
		return fmt.Errorf("ospf: invalid checksum_mode %q", cfg.ChecksumMode)
	}
	// LSA header validation (DD/ACK/requests/LSU).
	for _, lh := range cfg.LSAHeaders {
		if net.ParseIP(lh.LinkStateID).To4() == nil {
			return fmt.Errorf("ospf: invalid lsa link_state_id %q", lh.LinkStateID)
		}
	}
	for _, lsa := range cfg.LSAs {
		if lsa.LSAType < 1 || lsa.LSAType > 7 {
			return fmt.Errorf("ospf: invalid lsa_type %d", lsa.LSAType)
		}
		if net.ParseIP(lsa.LinkStateID).To4() == nil {
			return fmt.Errorf("ospf: invalid lsa link_state_id %q", lsa.LinkStateID)
		}
		if lsa.LSAType == 1 && len(lsa.Links) > 0 {
			for _, l := range lsa.Links {
				if net.ParseIP(l.LinkID).To4() == nil {
					return fmt.Errorf("ospf: invalid link_id %q", l.LinkID)
				}
			}
		}
	}
	// Event sequence validation.
	for i, ev := range cfg.Events {
		if _, err := packetTypeFromString(ev.Kind); err != nil {
			return fmt.Errorf("ospf: events[%d] invalid kind %v", i, err)
		}
	}
	return nil
}
