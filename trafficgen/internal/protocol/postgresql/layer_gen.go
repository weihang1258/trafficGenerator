package postgresql

import (
	"context"
	"encoding/hex"
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
//   - ssl_request / gssenc_request: the untyped 8-byte request magic.
//   - cancel_request: the untyped 16-byte request (magic + event pid/secret).
//   - auth_request: AuthenticationRequest with event authtype (default 3 =
//     cleartext, matching kingbase's existing behavior).
//   - auth_response / password: PasswordMessage.
//   - parameter_status: ParameterStatus with event name/value, or a cycled
//     default from defaultParamOrder when absent.
//   - backend_key_data: BackendKeyData with event pid/secret (default 12345/67890).
//   - ready: ReadyForQuery with event status (default 'I').
//   - query / simple_query: SimpleQuery with event SQL (default "SELECT 1").
//   - row_description: RowDescription (event cols, or single int4 "col1").
//   - data_row: DataRow (event row_values, or single column 42).
//   - command_complete: CommandComplete with event tag (default "SELECT 1").
//   - query_error: ErrorResponse (event fields, or the default trio).
//   - notice: NoticeResponse (same field layout, does not end the transaction).
//   - notification: NotificationResponse (event pid/channel/payload).
//   - empty_query: EmptyQueryResponse.
//   - extended query: parse / bind / describe / execute / sync / flush / close
//     and the completion messages parse_complete / bind_complete /
//     close_complete / no_data / portal_suspended / parameter_description.
//   - function_call / function_call_response.
//   - negotiate_protocol_version.
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
		ver := ev.ProtocolVersion
		if ver == 0 {
			ver = pgwire.ProtocolV3
		}
		return pgwire.StartupMessage(ver, params), nil
	case "ssl_request":
		return pgwire.SSLRequest(), nil
	case "gssenc_request":
		return pgwire.GSSENCRequest(), nil
	case "cancel_request":
		return pgwire.CancelRequest(ev.PID, ev.Secret), nil
	case "auth_request":
		code := int32(pgwire.AuthCleartextCode)
		if ev.Authtype != nil {
			code = *ev.Authtype
		}
		return pgwire.AuthRequestData(code, authRequestData(code, ev.AuthData)), nil
	case "auth_response", "password":
		if ev.AuthToken != "" {
			return pgwire.PasswordMessageRaw(pgAuthToken(ev.AuthToken)), nil
		}
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
		return pgwire.ReadyForQuery(pgwireStatus(ev.Status)), nil
	case "query", "simple_query":
		sql := ev.SQL
		if sql == "" {
			sql = "SELECT 1"
		}
		return pgwire.QueryMessage(sql), nil
	case "row_description":
		if len(ev.Cols) == 0 {
			return pgwire.RowDescription(), nil
		}
		fields := make([]pgwire.FieldDesc, len(ev.Cols))
		for i, c := range ev.Cols {
			fields[i] = pgwire.FieldDesc{
				Name:     c.Name,
				TableOID: c.TableOID,
				Column:   c.Column,
				TypeOID:  c.TypeOID,
				TypeLen:  c.TypeLen,
				TypeMod:  c.TypeMod,
				Format:   c.FormatCode,
			}
		}
		return pgwire.RowDescriptionFields(fields), nil
	case "data_row":
		if len(ev.RowValues) == 0 {
			return pgwire.DataRow(), nil
		}
		cols := make([][]byte, len(ev.RowValues))
		for i, v := range ev.RowValues {
			if v == nil {
				continue // nil = SQL NULL (length -1)
			}
			cols[i] = []byte(*v)
		}
		return pgwire.DataRowColumns(cols), nil
	case "command_complete":
		tag := ev.Tag
		if tag == "" {
			tag = "SELECT 1"
		}
		return pgwire.CommandComplete(tag), nil
	case "query_error":
		if len(ev.Fields) == 0 {
			return pgwire.ErrorResponse("ERROR", "42P01", "relation does not exist"), nil
		}
		return pgwire.ErrorResponseFields(pgErrorFields(ev.Fields)), nil
	case "notice":
		if len(ev.Fields) == 0 {
			return pgwire.NoticeResponse(pgErrorFields([]core.PGErrorField{
				{Type: 'S', Value: "ERROR"},
				{Type: 'C', Value: "42P01"},
				{Type: 'M', Value: "relation does not exist"},
			})), nil
		}
		return pgwire.NoticeResponse(pgErrorFields(ev.Fields)), nil
	case "notification":
		return pgwire.NotificationResponse(ev.PID, ev.Channel, ev.Payload), nil
	case "empty_query":
		// The empty-query exchange is one kind in two directions (direction is
		// this protocol's standard disambiguator): c2s = SimpleQuery with an
		// empty SQL string (Q + single NUL), s2c = EmptyQueryResponse (I).
		// A dedicated kind is required because "query"/"simple_query" reject
		// blank sql (negative case neg_empty_sql) — see validate.go.
		if ev.Direction == "c2s" {
			return pgwire.QueryMessage(""), nil
		}
		return pgwire.EmptyQueryResponse(), nil
	case "parse":
		sql := ev.SQL
		if sql == "" {
			sql = "SELECT 1"
		}
		return pgwire.Parse(ev.Statement, sql, ev.OIDs), nil
	case "parse_complete":
		return pgwire.ParseComplete(), nil
	case "bind":
		return pgwire.Bind(ev.Portal, ev.Statement, ev.ParamFormats, optionalStrings(ev.ParamValues), ev.ResultFormats), nil
	case "bind_complete":
		return pgwire.BindComplete(), nil
	case "describe":
		return pgwire.Describe(pgMode(ev.Mode), pgDescribeName(ev)), nil
	case "execute":
		return pgwire.Execute(ev.Portal, ev.MaxRows), nil
	case "sync":
		return pgwire.Sync(), nil
	case "flush":
		return pgwire.Flush(), nil
	case "close":
		return pgwire.Close(pgMode(ev.Mode), pgDescribeName(ev)), nil
	case "close_complete":
		return pgwire.CloseComplete(), nil
	case "no_data":
		return pgwire.NoData(), nil
	case "portal_suspended":
		return pgwire.PortalSuspended(), nil
	case "parameter_description":
		return pgwire.ParameterDescription(ev.OIDs), nil
	case "function_call":
		oid := ev.FunctionOID
		if oid == 0 {
			oid = 1244 // nextval, matching the legacy planner default
		}
		return pgwire.FunctionCall(oid, ev.ArgumentFormats, optionalStrings(ev.Arguments), ev.FunctionResultFmt), nil
	case "function_call_response":
		if ev.FunctionResultNull {
			return pgwire.FunctionCallResponse(nil), nil
		}
		return pgwire.FunctionCallResponse([]byte(ev.FunctionResult)), nil
	case "negotiate_protocol_version":
		return pgwire.NegotiateProtocolVersion(ev.NewestMinor, ev.UnrecognizedOptions), nil
	case "terminate":
		return pgwire.TerminateMessage(), nil
	}
	return nil, fmt.Errorf("postgresql: event %q has no builder", ev.Kind)
}

// authRequestData returns the AuthenticationRequest sub-type payload for
// authCode (design §3.4). ev.AuthData (hex) wins when present; otherwise the
// generator supplies the per-sub-type default that makes the message
// structurally valid:
//   - 5 (MD5Password): the legacy planner's salt 12 34 56 78 (planner.go
//     md5SaltOrDefault), giving the measured length=12 shape.
//   - 10 (SASL): the SCRAM-SHA-256 mechanism list plus its zero terminator.
//
// Sub-types 0/2/3/6/7/9 carry no payload, so the result is empty and the
// message stays 8 bytes. Malformed hex cannot reach here — the validator
// rejects it first (a nil decode would silently drop the sub-type payload).
func authRequestData(authCode int32, hexData string) []byte {
	if hexData != "" {
		if b, err := hex.DecodeString(hexData); err == nil {
			return b
		}
	}
	switch authCode {
	case 5:
		return []byte{0x12, 0x34, 0x56, 0x78}
	case 10:
		return append([]byte("SCRAM-SHA-256"), 0, 0)
	}
	return nil
}

// pgAuthToken decodes the c2s opaque token hex for GSSResponse /
// SASLInitialResponse / SASLResponse. The validator rejects malformed hex
// before the generator runs, so the error branch is unreachable from a config
// path; it yields nil (an obviously empty token) rather than the literal
// string bytes, which would look like a plausible message on the wire.
func pgAuthToken(hexData string) []byte {
	b, err := hex.DecodeString(hexData)
	if err != nil {
		return nil
	}
	return b
}

// pgwireStatus maps the event status string to a ReadyForQuery status byte.
// Absent/unrecognised values fall back to 'I' (idle).
func pgwireStatus(s string) byte {
	switch s {
	case "T":
		return pgwire.RFQInTrans
	case "E":
		return pgwire.RFQFailed
	default:
		return pgwire.RFQIdle
	}
}

// pgMode maps the event mode string to a Describe/Close target byte.
// Absent/unrecognised values fall back to 'S' (statement).
func pgMode(s string) byte {
	if s == "portal" {
		return pgwire.ModePortal
	}
	return pgwire.ModeStatement
}

// pgDescribeName picks the object name a Describe/Close event targets: the
// portal name in portal mode, the statement name otherwise.
func pgDescribeName(ev *core.PostgreSQLEvent) string {
	if pgMode(ev.Mode) == pgwire.ModePortal {
		return ev.Portal
	}
	return ev.Statement
}

// pgErrorFields converts core error fields to the pgwire field type.
func pgErrorFields(in []core.PGErrorField) []pgwire.ErrorField {
	out := make([]pgwire.ErrorField, len(in))
	for i, f := range in {
		out[i] = pgwire.ErrorField{Type: f.Type, Value: f.Value}
	}
	return out
}

// optionalStrings dereferences an optional-string slice into raw byte values,
// mapping a nil element to nil (SQL NULL / NULL parameter).
func optionalStrings(in []*string) [][]byte {
	out := make([][]byte, len(in))
	for i, s := range in {
		if s == nil {
			continue
		}
		out[i] = []byte(*s)
	}
	return out
}

func init() {
	layers.RegisterLayerGenerator("postgresql", func() (layers.LayerGenerator, error) { return &PostgreSQLGenerator{}, nil })
	layers.RegisterLayerValidator("postgresql", func(s *core.FlowSpec) error { return validatePostgresqlConfig(s) })
}
