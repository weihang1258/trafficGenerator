package dameng

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultPort is the Dameng DM8 default database port.
	DefaultPort = 5236
)

// Planner plans Dameng (DM8, TCP 5236) traffic.
type Planner struct{}

func (Planner) Name() string { return "dameng" }

// eventKindValid reports whether kind is one of the six known event kinds.
func eventKindValid(kind string) bool {
	switch kind {
	case "connect", "auth_request", "auth_response", "sql_request", "sql_response", "close":
		return true
	}
	return false
}

// kindUp reports whether a kind's natural direction is client->server.
// auth_response/sql_response are always s2c; close is client-initiated.
func kindUp(kind string) (bool, error) {
	switch kind {
	case "connect", "auth_request", "sql_request", "close":
		return true, nil
	case "auth_response", "sql_response":
		return false, nil
	}
	return false, fmt.Errorf("dameng: unknown event kind %q", kind)
}

func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.Dameng
	if cfg == nil {
		// P0b-2: 空配置不再报错——Plan 会默认化并产默认流 (layers 数组路径
		// 下 layer config 为空/缺省时)。
		return nil
	}
	if cfg.WireProfile == "" {
		return fmt.Errorf("dameng: wire_profile is required")
	}
	if !knownProfiles[cfg.WireProfile] {
		return fmt.Errorf("dameng: unknown wire profile %q", cfg.WireProfile)
	}
	if len(cfg.Events) == 0 && len(cfg.Sessions) == 0 {
		return fmt.Errorf("dameng: at least one event or session required")
	}
	if len(cfg.Events) > 0 && len(cfg.Sessions) > 0 {
		return fmt.Errorf("dameng: events and sessions are mutually exclusive")
	}
	if cfg.PayloadSize != "" && cfg.PayloadSize != "profile_minimum_nonempty" {
		return fmt.Errorf("dameng: unsupported payload_size %q", cfg.PayloadSize)
	}
	if err := checkWireFault(cfg.WireFault); err != nil {
		return err
	}
	if len(cfg.Sessions) > 0 {
		for i, s := range cfg.Sessions {
			if len(s.Events) == 0 {
				return fmt.Errorf("dameng: session %d with empty events", i)
			}
			if err := validateEventSequence(s.Events); err != nil {
				return fmt.Errorf("dameng: session %d: %w", i, err)
			}
		}
	} else if err := validateEventSequence(cfg.Events); err != nil {
		return err
	}
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("dameng: invalid source IP")
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("dameng: invalid destination IP")
	}
	return nil
}

// validateEventSequence enforces the DM8 state machine: connect first,
// auth_response only after auth_request, SQL only after a successful
// auth_response, matching request/response directions,
// and close only as the last event.
func validateEventSequence(evs []core.DamengEvent) error {
	authOK := false
	for i, ev := range evs {
		if !eventKindValid(ev.Kind) {
			return fmt.Errorf("dameng: event %d: unknown kind %q (want connect|auth_request|auth_response|sql_request|sql_response|close)", i, ev.Kind)
		}
		if i == 0 && ev.Kind != "connect" {
			return fmt.Errorf("dameng: event %d: state: first event must be connect", i)
		}
		if ev.Kind == "close" && i != len(evs)-1 {
			return fmt.Errorf("dameng: event %d: state: close must be the last event", i)
		}
		if ev.Kind == "auth_response" && !authRequested(evs, i) {
			return fmt.Errorf("dameng: event %d: state: auth_response without auth_request", i)
		}
		switch ev.Kind {
		case "connect":
			if i != 0 {
				return fmt.Errorf("dameng: event %d: state: connect only allowed as first event", i)
			}
		case "auth_request":
			if i == 0 {
				return fmt.Errorf("dameng: event %d: state: first event must be connect", i)
			}
		case "auth_response":
			if ev.Result != "" && ev.Result != "success" && ev.Result != "error" {
				return fmt.Errorf("dameng: event %d: auth: invalid result %q (want success|error)", i, ev.Result)
			}
			if ev.Result == "error" {
				authOK = false
			} else {
				authOK = true
			}
		case "sql_request":
			if !authOK {
				return fmt.Errorf("dameng: event %d: auth: SQL request before successful authentication", i)
			}
			if ev.SQL == "" {
				return fmt.Errorf("dameng: event %d: sql: empty SQL text", i)
			}
		case "sql_response":
			if !authOK {
				return fmt.Errorf("dameng: event %d: auth: SQL response before successful authentication", i)
			}
			if ev.Result != "" && ev.Result != "success" && ev.Result != "error" {
				return fmt.Errorf("dameng: event %d: sql: invalid result %q (want success|error)", i, ev.Result)
			}
		}
	}
	return nil
}

// authRequested checks whether an auth_request precedes index i (a config
// default: without a challenge round, exactly one auth_request).
func authRequested(evs []core.DamengEvent, idx int) bool {
	for j := 0; j < idx; j++ {
		if evs[j].Kind == "auth_request" {
			return true
		}
	}
	return false
}

func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = DefaultPort
	}
	cfg := spec.Dameng
	if cfg == nil {
		cfg = &core.DamengConfig{Events: []core.DamengEvent{{Kind: "connect"}}}
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
				FlowID:      "dameng",
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
		// Multi-session: each session gets its own handshake, events,
		// and teardown on an independent src port.
		if len(cfg.Sessions) > 0 {
			for _, s := range cfg.Sessions {
				srcPort := s.SrcPort
				if srcPort == 0 {
					srcPort = spec.SrcPort
				}
				if err := runSession(ctx, emit, s.Events, srcPort); err != nil {
					return
				}
			}
			return
		}
		runSession(ctx, emit, cfg.Events, spec.SrcPort)
	}()
	return out, nil
}

// runSession emits the full per-session packet sequence: TCP handshake,
// application events, TCP teardown.
func runSession(ctx context.Context, emit func(up bool, payload []byte, flags uint8, srcPort uint16) bool, evs []core.DamengEvent, srcPort uint16) error {
	if !emit(true, nil, 0x02, srcPort) || !emit(false, nil, 0x12, srcPort) || !emit(true, nil, 0x10, srcPort) {
		return ctx.Err()
	}
	for _, ev := range evs {
		payload, err := buildPacket(ev)
		if err != nil {
			return err
		}
		up, err := eventUp(ev)
		if err != nil {
			return err
		}
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

// eventUp determines the direction of an event: explicit Direction wins,
// otherwise the kind's natural role. The order of checks matches the
// s2c kind check first, so an explicit direction for a fixed-role event
// must be consistent with its kind (validated by Validate).
func eventUp(ev core.DamengEvent) (bool, error) {
	if ev.Direction != "" {
		return ev.Direction == "c2s", nil
	}
	return kindUp(ev.Kind)
}