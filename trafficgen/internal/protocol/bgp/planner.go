package bgp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

type Planner struct{}

func (Planner) Name() string { return "bgp" }

func (Planner) Validate(spec core.FlowSpec) error {
	if spec.BGP == nil {
		// P0b-2：空配置不再报错——Plan 会默认化并产默认流（layers 数组路径
		// 下 layer config 为空/缺省时）。
		return nil
	}
	if spec.BGP.Transport != "" && spec.BGP.Transport != "tcp" {
		return fmt.Errorf("bgp: transport %q invalid; BGP requires tcp", spec.BGP.Transport)
	}
	if spec.Metadata != nil {
		if transport, ok := spec.Metadata["transport"].(string); ok && transport != "" && transport != "tcp" {
			return fmt.Errorf("bgp: transport %q invalid; BGP requires tcp", transport)
		}
	}
	// Legacy fields are still validated for direct (non-events) usage.
	if err := ValidateConfig(spec.BGP); err != nil {
		return err
	}
	return validateSessionConfig(spec.BGP)
}

// validateSessionConfig validates config-level invariants that apply whether
// the events are on the top level or inside a session: profile, sessions>1),
// then each event's internal consistency and sequence state machine. When a
// single session is present, that session's events are the effective sequence.
func validateSessionConfig(cfg *BGPConfig) error {
	if cfg == nil {
		return nil
	}
	if len(cfg.Sessions) > 1 {
		return fmt.Errorf("bgp: sessions (%d) multi-stream expansion is not supported on a layer chain (one flow per chain)", len(cfg.Sessions))
	}
	events := cfg.Events
	if len(cfg.Sessions) == 1 {
		events = cfg.Sessions[0].Events
	}
	return validateEventSequence(events)
}

// validateEventSequence enforces the RFC 4271 adjacency state machine (design
// §4) over the ordered event sequence: opens come first (a pair), keepalive/
// update only after the open exchange, notification is terminal, and each
// event's own config is internally valid.
func validateEventSequence(events []core.BGPEvent) error {
	if events == nil {
		return nil
	}
	openSeen := false
	openCount := 0
	opened := false // an open preceded a processed event; used to reject opens after
	for i := range events {
		ev := &events[i]
		if err := validateEventConfig(ev); err != nil {
			return err
		}
		switch ev.Kind {
		case "open":
			// Opens are the only events allowed before the exchange is done;
			// keepalive/update/notification all require the open exchange.
			if opened {
				return fmt.Errorf("bgp: open after application events started (state violation)")
			}
			openSeen = true
			openCount++
		case "keepalive", "update":
			opened = true
			if !openSeen {
				return fmt.Errorf("bgp: %s before OPEN exchange completed (state violation)", ev.Kind)
			}
		case "notification":
			if !openSeen {
				return fmt.Errorf("bgp: notification before OPEN exchange completed (state violation)")
			}
			// Notification must be the last BGP application event (§4).
			if i != len(events)-1 {
				return fmt.Errorf("bgp: notification must be the last application event")
			}
		}
	}
	// §4: opens must appear as a pair (one per direction) before the exchange is
	// considered complete. A connect-only session (zero events) is permitted,
	// but if opens exist they must be a pair.
	if openCount > 0 && openCount != 2 {
		return fmt.Errorf("bgp: OPEN exchange requires exactly two OPEN messages (one per direction), got %d", openCount)
	}
	return nil
}

func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	bgpCfg := spec.BGP
	if bgpCfg == nil {
		bgpCfg = &BGPConfig{}
	}
	events := bgpCfg.Events
	if len(bgpCfg.Sessions) == 1 {
		events = bgpCfg.Sessions[0].Events
	}
	if events == nil {
		events = defaultDualEvents(bgpCfg)
	}
	out := make(chan core.PacketConfig, 16)
	go func() {
		defer close(out)
		idx := uint64(0)
		emit := func(up bool, payload []byte, flags uint8) bool {
			sip, dip, sp, dp := spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort
			if !up {
				sip, dip, sp, dp = dip, sip, dp, sp
			}
			select {
			case out <- core.PacketConfig{FlowID: "bgp", PacketIndex: idx, Direction: map[bool]string{true: "up", false: "down"}[up], L2: core.L2Config{EtherType: core.EtherTypeFor(sip)}, L3: core.L3Base(sip, dip, 6, 64, uint16(idx), spec), L4: core.L4Config{Protocol: "tcp", SrcPort: sp, DstPort: dp, Flags: flags, WindowSize: 65535}, Payload: payload}:
				idx++
				return true
			case <-ctx.Done():
				return false
			}
		}
		if !emit(true, nil, 2) || !emit(false, nil, 0x12) || !emit(true, nil, 0x10) {
			return
		}
		for i := range events {
			ev := &events[i]
			msg, err := BuildEvent(*ev)
			if err != nil {
				return
			}
			up := ev.Direction != "s2c"
			if !emit(up, msg, 0x18) {
				return
			}
		}
		emit(true, nil, 0x11)
		emit(false, nil, 0x11)
	}()
	return out, nil
}
