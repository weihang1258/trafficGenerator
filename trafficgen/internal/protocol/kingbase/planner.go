package kingbase

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Event kinds.
const (
	kindStartup         = "startup"
	kindAuthRequest     = "auth_request"
	kindAuthResponse    = "auth_response"
	kindReady           = "ready"
	kindQuery           = "query"
	kindRowDescription  = "row_description"
	kindDataRow         = "data_row"
	kindCommandComplete = "command_complete"
	kindQueryError      = "query_error"
	kindTerminate       = "terminate"
	kindPassword        = "password"
)

// registered wire profiles.
const (
	profileV8PGCompatible = "kingbase_es_v8_pg_compatible"
	profilePGReference    = "postgresql_v3_compatible_reference"
	profileNativePending  = "kingbase_native_pending"
)

var knownProfiles = map[string]bool{
	profileV8PGCompatible: true,
	profilePGReference:    true,
	profileNativePending:  true,
}

// wireFault is the negative-test fault injection (design §4).
type wireFault struct {
	Kind  string      `json:"kind"`
	Value interface{} `json:"value"`
}

// checkWireFault parses the config wire_fault and returns a config error
// if the injected fault is in scope.
func checkWireFault(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var f wireFault
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("kingbase: invalid wire_fault: %v", err)
	}
	switch f.Kind {
	case "truncate_startup":
		return fmt.Errorf("kingbase: wire fault: startup length truncated by %v, below minimum outer length", f.Value)
	case "message_limit":
		return fmt.Errorf("kingbase: wire fault: message %v exceeds implementation limit", f.Value)
	default:
		return fmt.Errorf("kingbase: wire fault: unknown kind %q", f.Kind)
	}
}

// Planner implements the KingBase protocol planner.
type Planner struct{}

// Name returns the protocol name.
func (Planner) Name() string { return "kingbase" }

// Validate validates a KingBase flow spec. Read-only.
func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.KingBase
	if cfg == nil {
		return fmt.Errorf("kingbase: config is required")
	}
	if err := checkWireFault(cfg.WireFault); err != nil {
		return err
	}
	if cfg.WireProfile == "" {
		return fmt.Errorf("kingbase: wire_profile is required")
	}
	if !knownProfiles[cfg.WireProfile] {
		return fmt.Errorf("kingbase: unknown wire profile %q", cfg.WireProfile)
	}
	if cfg.WireProfile == profileNativePending {
		return fmt.Errorf("kingbase: wire profile %q has no fixed payload (native pending)", cfg.WireProfile)
	}
	if spec.DstPort != 0 && spec.DstPort != DefaultPort {
		return fmt.Errorf("kingbase: destination port %d is not the default %d", spec.DstPort, DefaultPort)
	}
	if spec.SrcIP != "" && net.ParseIP(spec.SrcIP) == nil {
		return fmt.Errorf("kingbase: invalid source IP")
	}
	if spec.DstIP != "" && net.ParseIP(spec.DstIP) == nil {
		return fmt.Errorf("kingbase: invalid destination IP")
	}
	// Validate events across sessions (each with its own state machine).
	validateEvents := func(events []core.KingBaseEvent) error {
		st := &sessionState{}
		for i, ev := range events {
			if err := validateEvent(ev, st, i); err != nil {
				return err
			}
		}
		return nil
	}
	if len(cfg.Sessions) > 0 {
		for i := range cfg.Sessions {
			if err := validateEvents(cfg.Sessions[i].Events); err != nil {
				return fmt.Errorf("kingbase: session %d: %v", i, err)
			}
		}
	} else if err := validateEvents(cfg.Events); err != nil {
		return err
	}
	return nil
}

// sessionState tracks the wire state machine for one session.
type sessionState struct {
	ready bool
}

// validateEvent validates a single event against the session state machine.
func validateEvent(ev core.KingBaseEvent, st *sessionState, idx int) error {
	if !validKind(ev.Kind) {
		return fmt.Errorf("kingbase: event %d: invalid kind %q", idx, ev.Kind)
	}
	if ev.Direction != "" && !validDirection(ev.Direction) {
		return fmt.Errorf("kingbase: event %d: invalid direction %q (want c2s|s2c)", idx, ev.Direction)
	}
	if ev.Kind == kindQuery && strings.TrimSpace(ev.SQL) == "" {
		return fmt.Errorf("kingbase: event %d: query requires non-empty sql", idx)
	}
	// State machine (design §3.3 / §4 rule 5): c2s state events may only
	// appear after the server signaled ready.
	if ev.Direction == "c2s" && c2sNeedsReady(ev.Kind) && !st.ready {
		return fmt.Errorf("kingbase: event %d: %s before ready (state error)", idx, ev.Kind)
	}
	// Advance state: server events that set ready.
	if ev.Direction == "s2c" && s2cMakesReady(ev.Kind) {
		st.ready = true
	}
	return nil
}

// c2sNeedsReady reports whether a c2s event may only appear after ready.
func c2sNeedsReady(kind string) bool {
	switch kind {
	case kindQuery, kindPassword:
		return true
	}
	return false
}

// s2cMakesReady reports whether an s2c event sets the ready state.
func s2cMakesReady(kind string) bool {
	switch kind {
	case kindReady, kindAuthRequest, kindRowDescription, kindDataRow, kindCommandComplete, kindQueryError:
		return true
	}
	return false
}

// validKind reports whether the event kind is registered.
func validKind(kind string) bool {
	switch kind {
	case kindStartup, kindAuthRequest, kindAuthResponse, kindReady,
		kindQuery, kindRowDescription, kindDataRow, kindCommandComplete,
		kindQueryError, kindTerminate, kindPassword:
		return true
	}
	return false
}

// validDirection reports whether the direction is c2s or s2c.
func validDirection(d string) bool {
	return d == "c2s" || d == "s2c"
}

// Plan generates packet configs for a KingBase flow.
func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = DefaultPort
	}
	cfg := spec.KingBase

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
				FlowID:      "kingbase",
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
				if err := runSession(ctx, emit, s.Events, sp); err != nil {
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
func runSession(ctx context.Context, emit func(up bool, payload []byte, flags uint8, srcPort uint16) bool, evs []core.KingBaseEvent, srcPort uint16) error {
	// TCP handshake
	if !emit(true, nil, 0x02, srcPort) || !emit(false, nil, 0x12, srcPort) || !emit(true, nil, 0x10, srcPort) {
		return ctx.Err()
	}
	for _, ev := range evs {
		payload, err := buildEventPayload(ev)
		if err != nil {
			return err
		}
		up := ev.Direction != "s2c"
		if !emit(up, payload, 0x18, srcPort) {
			return ctx.Err()
		}
	}
	// TCP teardown: FIN/ACK (c2s), ACK (s2c), FIN/ACK (s2c), ACK (c2s)
	emit(true, nil, 0x11, srcPort)
	emit(false, nil, 0x10, srcPort)
	emit(false, nil, 0x11, srcPort)
	emit(true, nil, 0x10, srcPort)
	return nil
}

// buildEventPayload encodes one event into a wire payload.
func buildEventPayload(ev core.KingBaseEvent) ([]byte, error) {
	switch ev.Kind {
	case kindStartup:
		params := map[string]string{}
		if ev.User != "" {
			params["user"] = ev.User
		}
		if ev.Database != "" {
			params["database"] = ev.Database
		}
		if ev.User == "" && ev.Database == "" {
			params["user"] = "test"
		}
		return buildStartupMessage(ProtocolV3, params), nil
	case kindAuthRequest:
		return buildAuthRequest(authCleartext), nil
	case kindAuthResponse:
		return buildPasswordMessage("testpass"), nil
	case kindReady:
		return buildReadyForQuery(rfqIdle), nil
	case kindQuery:
		sql := ev.SQL
		if sql == "" {
			sql = "SELECT 1"
		}
		return buildQueryMessage(sql), nil
	case kindRowDescription:
		return buildRowDescription(), nil
	case kindDataRow:
		return buildDataRow(), nil
	case kindCommandComplete:
		tag := ev.Tag
		if tag == "" {
			tag = "SELECT 1"
		}
		return buildCommandComplete(tag), nil
	case kindQueryError:
		return buildErrorResponse("ERROR", "28P01", "invalid password"), nil
	case kindPassword:
		return buildPasswordMessage("testpass"), nil
	case kindTerminate:
		return buildTerminateMessage(), nil
	}
	return nil, fmt.Errorf("kingbase: event %q has no builder", ev.Kind)
}