package igmp

import (
	"fmt"
	"net"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner validates an IGMP flow spec. IGMP is a raw-IP [ip, igmp] chain; the
// terminal generator emits full packets via req.Emit.
type Planner struct{}

func NewPlanner() *Planner    { return &Planner{} }
func (*Planner) Name() string { return "igmp" }

// Validate rejects invalid IGMP specs (negative-path cases). A nil config is
// allowed (P0b-2: empty config defaults to a v1 general query).
func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.IGMP
	if cfg == nil {
		return nil
	}
	// IPv6 is N/A for IGMP (IPv4 multicast only).
	if cfg.AddressFamily == "ipv6" {
		return fmt.Errorf("igmp: IPv6 is N/A")
	}
	// Destination must be multicast (224.0.0.0/4) for reports/leaves; general
	// queries use 224.0.0.1. Event sequences (cfg.Events) derive their
	// per-message destination from each event's kind/profile/group (validated
	// below in the events loop), so the top-level DstIP check is skipped —
	// otherwise the flat spec default (20.0.0.1) would wrongly reject
	// event-driven cases that omit dst_ip.
	if len(cfg.Events) == 0 && spec.DstIP != "" {
		dip := net.ParseIP(spec.DstIP).To4()
		if dip == nil {
			return fmt.Errorf("igmp: non-multicast destination (must be IPv4 multicast)")
		}
		if !isMulticast4(dip) {
			return fmt.Errorf("igmp: non-multicast destination")
		}
	}
	// IGMP TTL must be 1.
	if spec.TTL != 0 && spec.TTL != 1 {
		return fmt.Errorf("igmp: TTL must be 1")
	}
	// profile/kind mismatch.
	if _, _, err := profileKind(cfg); err != nil {
		return err
	}
	// wire_fault negative-path injection: the spec requests an on-wire fault
	// (wrong IP protocol / bad checksum), which the generator must NOT emit —
	// reject at validation (IGMPWireFault kinds protocol|checksum; the other
	// kinds record|source_count|group are already rejected by the v3 record /
	// source-count checks below).
	if cfg.WireFault != nil {
		switch cfg.WireFault.Kind {
		case "protocol":
			return fmt.Errorf("igmp: IP Protocol 2 required (wire_fault protocol)")
		case "checksum":
			return fmt.Errorf("igmp: invalid checksum requested (wire_fault checksum)")
		}
	}
	// checksum_mode must be a known value.
	switch cfg.ChecksumMode {
	case "", "auto", "invalid", "zero", "bad":
	default:
		return fmt.Errorf("igmp: invalid checksum_mode %q", cfg.ChecksumMode)
	}
	// v3 records validation.
	for i, rec := range cfg.Records {
		if _, err := recordTypeFromString(rec.RecordType); err != nil {
			return fmt.Errorf("igmp: invalid v3 record %d (%v)", i, err)
		}
		if net.ParseIP(rec.Group).To4() == nil {
			return fmt.Errorf("igmp: invalid v3 record group %q", rec.Group)
		}
		for _, s := range rec.Sources {
			if net.ParseIP(s).To4() == nil {
				return fmt.Errorf("igmp: invalid v3 record source %q", s)
			}
		}
	}
	// Event sequence validation.
	for i, ev := range cfg.Events {
		if _, err := igmpTypeFor(ev.Profile, ev.Kind); err != nil {
			return fmt.Errorf("igmp: events[%d] %v", i, err)
		}
		if !isMulticastGroup(ev.Group) {
			return fmt.Errorf("igmp: events[%d] non-multicast group", i)
		}
		for _, rec := range ev.Records {
			if _, err := recordTypeFromString(rec.RecordType); err != nil {
				return fmt.Errorf("igmp: events[%d] invalid record_type %v", i, err)
			}
		}
	}
	return nil
}

// profileKind validates that (profile, kind) is a known combination and returns
// them. Returns an error message containing "profile" for mismatches.
func profileKind(cfg *core.IGMPConfig) (string, string, error) {
	profile := cfg.Profile
	if profile == "" {
		profile = "v1"
	}
	kind := cfg.Kind
	if kind == "" {
		kind = "query"
	}
	if _, err := igmpTypeFor(profile, kind); err != nil {
		return "", "", fmt.Errorf("igmp: invalid profile %q / kind %q", profile, kind)
	}
	// v1 kind restrictions: v1 has report(0x12) and query only; no leave.
	if profile == "v1" && kind == "leave" {
		return "", "", fmt.Errorf("igmp: invalid profile %q / kind %q", profile, kind)
	}
	if profile == "v3" && kind == "leave" {
		return "", "", fmt.Errorf("igmp: invalid profile %q / kind %q", profile, kind)
	}
	// v3 query requires sources to be well-formed (source_count matches length).
	if profile == "v3" && kind == "query" {
		if len(cfg.Sources) > 0 && cfg.SourceCount > 0 && cfg.SourceCount != len(cfg.Sources) {
			return "", "", fmt.Errorf("igmp: v3 query source count %d != sources %d", cfg.SourceCount, len(cfg.Sources))
		}
	}
	return profile, kind, nil
}

func isMulticast4(ip net.IP) bool {
	return ip[0] >= 0xe0 && ip[0] <= 0xef
}

func isMulticastGroup(group string) bool {
	if group == "" || group == "0.0.0.0" {
		return true // general query uses 0.0.0.0
	}
	ip := net.ParseIP(group).To4()
	return ip != nil && isMulticast4(ip)
}
