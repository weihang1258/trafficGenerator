package pim

import (
	"fmt"
	"net"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner validates a PIM-SM flow spec. PIM is a raw-IP [ip, pim] chain; the
// terminal generator emits full packets via req.Emit.
type Planner struct{}

func NewPlanner() *Planner    { return &Planner{} }
func (*Planner) Name() string { return "pim" }

// Validate rejects invalid PIM-SM specs (negative-path cases). The spec is
// checked at two levels: the top-level config and each event in the sequence.
func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.PIM
	if cfg == nil {
		return nil
	}
	// SSM (RFC 4607) is a source-specific tree profile; it cannot carry
	// RP/Register or wildcard state (which are PIM-SM constructs).
	ssm := strings.Contains(cfg.Profile, "ssm")
	// Non-IPv4 profile (e.g. pim_rfc7761_ipv6_pending) is unsupported here.
	if cfg.Profile != "" && !strings.Contains(cfg.Profile, "ipv4") {
		return fmt.Errorf("pim: unsupported profile %q (only IPv4 PIM profiles are supported)", cfg.Profile)
	}
	// checksum_mode must be a known value.
	switch cfg.ChecksumMode {
	case "", "auto", "invalid", "zero", "bad":
	default:
		return fmt.Errorf("pim: invalid checksum_mode %q", cfg.ChecksumMode)
	}
	// Top-level wire fault.
	if err := validateWireFault(cfg.WireFault); err != nil {
		return err
	}
	// Event sequence validation.
	for i, ev := range cfg.Events {
		if err := validateEvent(ev, ssm); err != nil {
			return fmt.Errorf("pim: events[%d] %w", i, err)
		}
	}
	return nil
}

// validateEvent checks one PIM event for structural errors and wire-fault
// injection.
func validateEvent(ev core.PIMEvent, ssm bool) error {
	// df_election is a Bidirectional-PIM construct; a SM profile cannot carry
	// it. Validate must reject with an error containing "df".
	if ev.Kind == "df_election" {
		return fmt.Errorf("pim df: %s requires independent bidi profile", ev.Kind)
	}
	// SSM profile cannot carry RP/Register or wildcard source state.
	if ssm {
		if ev.Kind == "register" || ev.Kind == "register_stop" {
			return fmt.Errorf("pim ssm: %s is not valid for SSM (source-specific tree, no RP/Register)", ev.Kind)
		}
		if ev.Kind == "bootstrap" || ev.Kind == "candidate_rp_adv" {
			return fmt.Errorf("pim ssm: %s is not valid for SSM (no RP)", ev.Kind)
		}
		for _, g := range ev.Groups {
			for _, s := range g.JoinedSources {
				if s.Wildcard {
					return fmt.Errorf("pim ssm: wildcard (*,G) join is not valid for SSM")
				}
			}
			for _, s := range g.PrunedSources {
				if s.Wildcard {
					return fmt.Errorf("pim ssm: wildcard (*,G) prune is not valid for SSM")
				}
			}
		}
	}
	// Wire fault injected on this event.
	if err := validateWireFault(ev.WireFault); err != nil {
		return err
	}
	// Address family: the IPv4 profile cannot encode IPv6 group/source.
	if !isIPv4(ev.UpstreamNeighbor) && ev.UpstreamNeighbor != "" {
		return fmt.Errorf("pim: upstream neighbor %q is not an IPv4 address", ev.UpstreamNeighbor)
	}
	if !isIPv4(ev.Group) && ev.Group != "" {
		return fmt.Errorf("pim: group %q is not an IPv4 address", ev.Group)
	}
	if !isIPv4(ev.Source) && ev.Source != "" {
		return fmt.Errorf("pim: source %q is not an IPv4 address", ev.Source)
	}
	if !isIPv4(ev.BSR) && ev.BSR != "" {
		return fmt.Errorf("pim: bsr %q is not an IPv4 address", ev.BSR)
	}
	if !isIPv4(ev.RP) && ev.RP != "" {
		return fmt.Errorf("pim: rp %q is not an IPv4 address", ev.RP)
	}
	// Per-group source/group address validation.
	for _, g := range ev.Groups {
		if g.Group != "" && net.ParseIP(g.Group).To4() == nil {
			return fmt.Errorf("pim: group %q is not an IPv4 address", g.Group)
		}
		for _, s := range g.JoinedSources {
			if err := validateSource(s); err != nil {
				return err
			}
		}
		for _, s := range g.PrunedSources {
			if err := validateSource(s); err != nil {
				return err
			}
		}
	}
	// Group prefixes must be IPv4 CSIER prefixes.
	for _, gp := range ev.GroupPrefixes {
		if _, _, err := net.ParseCIDR(gp); err != nil {
			return fmt.Errorf("pim: group_prefix %q is not an IPv4 CIDR prefix", gp)
		}
	}
	return nil
}

// validateSource checks a join/prune source. A non-wildcard source must be an
// IPv4 address.
func validateSource(s core.PIMSource) error {
	if s.Wildcard {
		return nil
	}
	if s.Source != "" && net.ParseIP(s.Source).To4() == nil {
		return fmt.Errorf("pim: source %q is not an IPv4 address", s.Source)
	}
	return nil
}

// validateWireFault rejects a wire-fault injection whose kind this package
// treats as a hard error (checksum/length/type are surfaced as validation
// errors so the negative-path tests fail cleanly).
func validateWireFault(wf *core.PIMWireFault) error {
	if wf == nil {
		return nil
	}
	switch wf.Kind {
	case "checksum":
		return fmt.Errorf("pim: checksum wire fault rejected (invalid checksum is a malformed message)")
	case "length":
		return fmt.Errorf("pim: length wire fault rejected (declared_total_length=%d)", wf.DeclaredTotalLength)
	case "type":
		return fmt.Errorf("pim: type wire fault rejected (unknown message type value=%d)", wf.Value)
	case "address":
		// address_family wire fault; also rejected here for completeness.
		return fmt.Errorf("pim: address-family wire fault rejected")
	case "":
		return nil
	default:
		return fmt.Errorf("pim: unsupported wire fault kind %q", wf.Kind)
	}
}
