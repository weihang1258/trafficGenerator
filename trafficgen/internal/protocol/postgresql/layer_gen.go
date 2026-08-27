package postgresql

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/pgwire"
)

// PostgreSQLGenerator implements the layers.LayerGenerator interface for the
// shared postgresql wire layer (P0a). It is event-driven: reads
// req.Meta.PostgreSQL.Events (or Sessions) and turns each event into PG v3
// bytes via the shared pgwire package. kingbase is a dialect variant of this
// same layer — the generator is dialect-agnostic for byte construction (both
// ride PG v3 outer wire); the dialect only selects the port (handled by the
// chain's FieldContract) and the wire_profile (validated by the validator).
type PostgreSQLGenerator struct {
	// paramIdx is the per-session counter for the default ParameterStatus
	// list (parameter_status events carrying no explicit name/value). It is a
	// per-instance field (the factory returns a fresh generator per flow), so
	// concurrent flows never share the counter (data-race-free) and each flow
	// cycles the default list deterministically from position 0.
	paramIdx int
}

// Name returns the protocol name.
func (g *PostgreSQLGenerator) Name() string { return "postgresql" }

// GenEvents returns the event generator.
func (g *PostgreSQLGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is not wired (events flow through the chain planner).
func (g *PostgreSQLGenerator) EmitEvent(layers.MessageEvent) error {
	return fmt.Errorf("postgresql generator: EmitEvent is not wired")
}

// Generate generates PostgreSQL v3 wire events from the config.
func (g *PostgreSQLGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("postgresql generator: EmitMsg is nil")
	}
	cfg := req.Meta.PostgreSQL
	if cfg == nil {
		return fmt.Errorf("postgresql: config is required")
	}
	if len(cfg.Sessions) > 0 {
		for _, s := range cfg.Sessions {
			for i := range s.Events {
				// 每条 session 是一条独立 TCP 连接：把 session 的源端口带上事件，
				// tcp 层据 SrcPort 覆盖判定会话边界（P0a 多会话，kingbase S8）。
				if err := g.genEvent(ctx, req.EmitMsg, &s.Events[i], s.SrcPort); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for i := range cfg.Events {
		if err := g.genEvent(ctx, req.EmitMsg, &cfg.Events[i], 0); err != nil {
			return err
		}
	}
	return nil
}

// genEvent encodes one event into a wire payload and emits it. srcPort is the
// session's source port override (0 = no override, tcp layer uses the flow
// src_port); it is forwarded as MessageEvent.SrcPort so the tcp transport can
// detect a session boundary for multi-session flows.
func (g *PostgreSQLGenerator) genEvent(ctx context.Context, emit func(layers.MessageEvent) error, ev *core.PostgreSQLEvent, srcPort uint16) error {
	payload, err := g.buildEventPayload(ev)
	if err != nil {
		return err
	}
	up := ev.Direction != "s2c"
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return emit(layers.MessageEvent{Up: up, Bytes: payload, SrcPort: srcPort})
	}
}

// defaultParamOrder is the default ParameterStatus list cycled by
// parameter_status events that carry no explicit name/value. Mirrors the
// legacy postgresql planner's deterministic parameter order so Wireshark sees
// a parseable "Parameter status" sequence.
var defaultParamOrder = []struct{ name, val string }{
	{"server_encoding", "UTF8"},
	{"client_encoding", "UTF8"},
	{"DateStyle", "ISO, MDY"},
	{"TimeZone", "UTC"},
	{"integer_datetimes", "on"},
	{"standard_conforming_strings", "on"},
	{"application_name", "trafficgen"},
}

// buildEventPayload encodes one event into PostgreSQL v3 bytes.
//   - startup: StartupMessage (no type byte) with event user/database params
//     (empty params → just version + terminator, matching the postgresql case
//     frame [00 00 00 09 00 03 00 00 00]).
//   - auth_request: AuthenticationRequest with event authtype (default 3 =
//     cleartext, matching kingbase's existing behavior).
//   - auth_response / password: PasswordMessage.
//   - parameter_status: ParameterStatus with event name/value, or a cycled
//     default from defaultParamOrder when absent.
//   - backend_key_data: BackendKeyData with event pid/secret (default 12345/67890).
//   - ready: ReadyForQuery 'I'.
//   - query / simple_query: SimpleQuery with event SQL (default "SELECT 1").
//   - row_description: RowDescription (single int4 "col1").
//   - data_row: DataRow (single column 42).
//   - command_complete: CommandComplete with event tag (default "SELECT 1").
//   - query_error: ErrorResponse.
//   - terminate: TerminateMessage.
func (g *PostgreSQLGenerator) buildEventPayload(ev *core.PostgreSQLEvent) ([]byte, error) {
	switch ev.Kind {
	case "startup":
		params := map[string]string{}
		if ev.User != "" {
			params["user"] = ev.User
		}
		if ev.Database != "" {
			params["database"] = ev.Database
		}
		return pgwire.StartupMessage(pgwire.ProtocolV3, params), nil
	case "auth_request":
		code := int32(pgwire.AuthCleartextCode)
		if ev.Authtype != nil {
			code = *ev.Authtype
		}
		return pgwire.AuthRequest(code), nil
	case "auth_response", "password":
		return pgwire.PasswordMessage("testpass"), nil
	case "parameter_status":
		if ev.Name != "" || ev.Value != "" {
			return pgwire.ParameterStatus(ev.Name, ev.Value), nil
		}
		// cycle default parameter list (per-instance counter)
		p := defaultParamOrder[g.paramIdx%len(defaultParamOrder)]
		g.paramIdx++
		return pgwire.ParameterStatus(p.name, p.val), nil
	case "backend_key_data":
		pid, secret := ev.PID, ev.Secret
		if pid == 0 {
			pid = 12345
		}
		if secret == 0 {
			secret = 67890
		}
		return pgwire.BackendKeyData(pid, secret), nil
	case "ready":
		return pgwire.ReadyForQuery(pgwire.RFQIdle), nil
	case "query", "simple_query":
		sql := ev.SQL
		if sql == "" {
			sql = "SELECT 1"
		}
		return pgwire.QueryMessage(sql), nil
	case "row_description":
		return pgwire.RowDescription(), nil
	case "data_row":
		return pgwire.DataRow(), nil
	case "command_complete":
		tag := ev.Tag
		if tag == "" {
			tag = "SELECT 1"
		}
		return pgwire.CommandComplete(tag), nil
	case "query_error":
		return pgwire.ErrorResponse("ERROR", "42P01", "relation does not exist"), nil
	case "terminate":
		return pgwire.TerminateMessage(), nil
	}
	return nil, fmt.Errorf("postgresql: event %q has no builder", ev.Kind)
}

func init() {
	layers.RegisterLayerGenerator("postgresql", func() (layers.LayerGenerator, error) { return &PostgreSQLGenerator{}, nil })
	layers.RegisterLayerValidator("postgresql", func(s *core.FlowSpec) error { return validatePostgresqlConfig(s) })
}
