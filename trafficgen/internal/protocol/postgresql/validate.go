package postgresql

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// knownWireProfiles is the set of registered wire profiles (postgresql 层字段)。
// dialect=postgresql uses "postgresql_v3"; dialect=kingbase uses a KingBase
// compatible profile. An unregistered profile is rejected (negative case
// kingbase_neg_profile expects an error containing "profile").
var knownWireProfiles = map[string]bool{
	"postgresql_v3":                         true,
	"kingbase_es_v8_pg_compatible":          true,
	"postgresql_v3_compatible_reference":    true,
	"kingbase_native_pending":               true,
}

// pgSessionState tracks the wire state machine for one session (design §3.3 /
// §4 rule 5): a c2s state event (query/password) may only appear after the
// server signaled ready.
type pgSessionState struct {
	ready bool
}

// validatePostgresqlConfig is the registered protocol validator for the
// postgresql terminal layer (P0a 共享 wire 层 + kingbase dialect 变体)。It is
// invoked by ChainPlanner.ValidateSpec after translateTerminalConfig has
// defaulted spec.PostgreSQL, so it validates the completed config (read-only).
func validatePostgresqlConfig(spec *core.FlowSpec) error {
	cfg := spec.PostgreSQL
	if cfg == nil {
		return fmt.Errorf("postgresql: config is required")
	}
	if cfg.Dialect != "" && cfg.Dialect != "postgresql" && cfg.Dialect != "kingbase" {
		return fmt.Errorf("postgresql: unknown dialect %q (want postgresql|kingbase)", cfg.Dialect)
	}
	if cfg.WireProfile == "" {
		return fmt.Errorf("postgresql: wire_profile is required")
	}
	if !knownWireProfiles[cfg.WireProfile] {
		return fmt.Errorf("postgresql: unknown wire profile %q", cfg.WireProfile)
	}
	if cfg.WireProfile == "kingbase_native_pending" {
		return fmt.Errorf("postgresql: wire profile %q has no fixed payload (native pending)", cfg.WireProfile)
	}
	if err := checkPostgreSqlWireFault(cfg.WireFault); err != nil {
		return err
	}
	validateEvents := func(evs []core.PostgreSQLEvent) error {
		st := &pgSessionState{}
		for i := range evs {
			if err := validatePostgreSqlEvent(&evs[i], st, i); err != nil {
				return err
			}
		}
		return nil
	}
	if len(cfg.Sessions) > 0 {
		for i := range cfg.Sessions {
			if err := validateEvents(cfg.Sessions[i].Events); err != nil {
				return fmt.Errorf("postgresql: session %d: %v", i, err)
			}
		}
	} else if err := validateEvents(cfg.Events); err != nil {
		return err
	}
	return nil
}

// pgwireFault is the negative-test fault injection (design §4, wire_fault)。
type pgwireFault struct {
	Kind  string      `json:"kind"`
	Value interface{} `json:"value"`
}

// checkPostgreSqlWireFault parses the config wire_fault and returns a config
// error if the injected fault is in scope. An absent or blank WireFault (nil,
// "", whitespace, null, or empty object) is a no-op — the postgresql schema
// default used to inject "" into the JSON round-trip, which must not be
// mis-read as a fault (design §4: wire_fault is present only for negative
// cases).
func checkPostgreSqlWireFault(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var probe interface{}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return fmt.Errorf("postgresql: invalid wire_fault: %v", err)
	}
	// Blank string / null / empty object => no fault injected.
	switch v := probe.(type) {
	case nil:
		return nil
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return fmt.Errorf("postgresql: invalid wire_fault: expected object, got string %q", v)
	case map[string]interface{}:
		if len(v) == 0 {
			return nil
		}
	default:
		return fmt.Errorf("postgresql: invalid wire_fault: expected object, got %T", probe)
	}
	var f pgwireFault
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("postgresql: invalid wire_fault: %v", err)
	}
	switch f.Kind {
	case "truncate_startup":
		return fmt.Errorf("postgresql: wire fault: startup length truncated by %v, below minimum outer length", f.Value)
	case "message_limit":
		return fmt.Errorf("postgresql: wire fault: message %v exceeds implementation limit", f.Value)
	default:
		return fmt.Errorf("postgresql: wire fault: unknown kind %q", f.Kind)
	}
}

// validatePostgreSqlEvent validates a single event against the session state
// machine.
func validatePostgreSqlEvent(ev *core.PostgreSQLEvent, st *pgSessionState, idx int) error {
	if !validPgKind(ev.Kind) {
		return fmt.Errorf("postgresql: event %d: invalid kind %q", idx, ev.Kind)
	}
	if ev.Direction != "" && ev.Direction != "c2s" && ev.Direction != "s2c" {
		return fmt.Errorf("postgresql: event %d: invalid direction %q (want c2s|s2c)", idx, ev.Direction)
	}
	if (ev.Kind == "query" || ev.Kind == "simple_query") && strings.TrimSpace(ev.SQL) == "" {
		return fmt.Errorf("postgresql: event %d: query requires non-empty sql", idx)
	}
	// State machine (design §3.3 / §4 rule 5): c2s state events may only
	// appear after the server signaled ready.
	if ev.Direction == "c2s" && c2sNeedsPgReady(ev.Kind) && !st.ready {
		return fmt.Errorf("postgresql: event %d: %s before ready (state error)", idx, ev.Kind)
	}
	// Advance state: server events that set ready.
	if ev.Direction == "s2c" && s2cMakesPgReady(ev.Kind) {
		st.ready = true
	}
	return nil
}

// c2sNeedsPgReady reports whether a c2s event may only appear after ready.
func c2sNeedsPgReady(kind string) bool {
	switch kind {
	case "query", "simple_query", "password":
		return true
	}
	return false
}

// s2cMakesPgReady reports whether an s2c event sets the ready state.
func s2cMakesPgReady(kind string) bool {
	switch kind {
	case "ready", "auth_request", "row_description", "data_row", "command_complete", "query_error":
		return true
	}
	return false
}

// validPgKind reports whether the event kind is registered.
func validPgKind(kind string) bool {
	switch kind {
	case "startup", "auth_request", "auth_response", "ready", "query", "simple_query",
		"parameter_status", "backend_key_data", "row_description", "data_row",
		"command_complete", "query_error", "password", "terminate":
		return true
	}
	return false
}
