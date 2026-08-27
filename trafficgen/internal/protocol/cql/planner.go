package cql

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner implements the CQL/Cassandra native protocol planner.
type Planner struct{}

// Name returns the protocol name.
func (Planner) Name() string { return "cql" }

// Validate validates a CQL flow spec.
func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.CQL
	if cfg == nil {
		return fmt.Errorf("cql: config is required")
	}
	if len(cfg.Events) == 0 && len(cfg.Sessions) == 0 {
		return fmt.Errorf("cql: at least one event or session required")
	}
	if len(cfg.Events) > 0 && len(cfg.Sessions) > 0 {
		return fmt.Errorf("cql: events and sessions are mutually exclusive")
	}
	if cfg.WireProfile == "" {
		return fmt.Errorf("cql: wire_profile is required")
	}
	if _, _, err := versionForProfile(cfg.WireProfile); err != nil {
		return err
	}
	if err := checkWireFault(cfg.WireFault); err != nil {
		return err
	}
	if len(cfg.Sessions) > 0 {
		for i, s := range cfg.Sessions {
			if len(s.Events) == 0 {
				return fmt.Errorf("cql: session %d: empty events", i)
			}
			if err := validateEvents(s.Events); err != nil {
				return fmt.Errorf("cql: session %d: %w", i, err)
			}
		}
	} else if err := validateEvents(cfg.Events); err != nil {
		return err
	}
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("cql: invalid source IP")
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("cql: invalid destination IP")
	}
	return nil
}

// validateEvents validates event kind, direction, and state machine.
func validateEvents(events []core.CQLEvent) error {
	ready := false
	for i, ev := range events {
		if _, ok := opcodeForKind(ev.Kind); !ok {
			return fmt.Errorf("cql: event %d: unknown kind %q", i, ev.Kind)
		}
		dir := ev.Direction
		if dir == "" {
			dir = "c2s"
		}
		if dir != "c2s" && dir != "s2c" {
			return fmt.Errorf("cql: event %d: invalid direction %q (want c2s|s2c)", i, dir)
		}
		// Kind-specific direction rules (CQL native protocol §3.1).
		switch ev.Kind {
		case "startup", "options", "query", "prepare", "execute":
			if dir != "c2s" {
				return fmt.Errorf("cql: event %d: %s must be c2s (client→server)", i, ev.Kind)
			}
		case "ready", "supported", "result", "authenticate", "auth_success", "error":
			if dir != "s2c" {
				return fmt.Errorf("cql: event %d: %s must be s2c (server→client)", i, ev.Kind)
			}
		case "auth_response":
			if dir != "c2s" {
				return fmt.Errorf("cql: event %d: auth_response must be c2s (client→server)", i)
			}
		}
		// State machine: query needs startup→ready or auth_success first.
		if ev.Kind == "ready" || ev.Kind == "auth_success" {
			ready = true
		}
		if ev.Kind == "query" && !ready {
			return fmt.Errorf("cql: event %d: state: query before startup/ready", i)
		}
	}
	return nil
}

// Plan generates packet configs for a CQL flow.
func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = 9042
	}
	cfg := spec.CQL
	reqVer, respVer, err := versionForProfile(cfg.WireProfile)
	if err != nil {
		return nil, err
	}

	out := make(chan core.PacketConfig, 32)
	go func() {
		defer close(out)
		idx := uint64(0)
		emit := func(up bool, payload []byte, flags uint8, srcPort uint16) bool {
			sip, dip, sp, dp := spec.SrcIP, spec.DstIP, srcPort, spec.DstPort
			dir := "up"
			if !up {
				sip, dip, sp, dp = dip, sip, dp, sp
				dir = "down"
			}
			select {
			case out <- core.PacketConfig{
				FlowID:      "cql",
				PacketIndex: idx,
				Direction:   dir,
				L2:          core.L2Config{EtherType: core.EtherTypeFor(sip)},
				L3:          core.L3Base(sip, dip, 6, 64, uint16(idx), spec),
				L4:          core.L4Config{Protocol: "tcp", SrcPort: sp, DstPort: dp, Flags: flags, WindowSize: 65535},
				Payload:     payload,
				Timestamp:   time.Now(),
			}:
				idx++
				return true
			case <-ctx.Done():
				return false
			}
		}
		if len(cfg.Sessions) > 0 {
			for _, s := range cfg.Sessions {
				sp := s.SrcPort
				if sp == 0 {
					sp = spec.SrcPort
				}
				if err := runSession(ctx, emit, s.Events, sp, reqVer, respVer); err != nil {
					return
				}
			}
			return
		}
		runSession(ctx, emit, cfg.Events, spec.SrcPort, reqVer, respVer)
	}()
	return out, nil
}

// runSession emits the full per-session packet sequence: TCP handshake,
// CQL events as framed messages, TCP teardown.
func runSession(ctx context.Context, emit func(up bool, payload []byte, flags uint8, srcPort uint16) bool, events []core.CQLEvent, srcPort uint16, reqVer, respVer byte) error {
	// TCP handshake: SYN, SYN-ACK, ACK
	if !emit(true, nil, 0x02, srcPort) || !emit(false, nil, 0x12, srcPort) || !emit(true, nil, 0x10, srcPort) {
		return ctx.Err()
	}
	// CQL events: each builds a native protocol frame.
	for _, ev := range events {
		payload, err := buildFrame(reqVer, respVer, ev)
		if err != nil {
			return err
		}
		up := ev.Direction != "s2c"
		if !emit(up, payload, 0x18, srcPort) {
			return ctx.Err()
		}
	}
	// TCP teardown: FIN/ACK (c2s), ACK (s2c), FIN/ACK (s2c), ACK (c2s).
	emit(true, nil, 0x11, srcPort)
	emit(false, nil, 0x10, srcPort)
	emit(false, nil, 0x11, srcPort)
	emit(true, nil, 0x10, srcPort)
	return nil
}