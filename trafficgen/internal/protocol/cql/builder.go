package cql

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/trafficgen/trafficgen/internal/core"
)

// CQL/Cassandra native protocol v4/v5 opcodes (§3.1).
const (
	OpError        = 0x00
	OpStartup      = 0x01
	OpReady        = 0x02
	OpAuthenticate = 0x03
	OpOptions      = 0x05
	OpSupported    = 0x06
	OpQuery        = 0x07
	OpResult       = 0x08
	OpPrepare      = 0x09
	OpExecute      = 0x0A
	OpAuthResponse = 0x0F
	OpAuthSuccess  = 0x10
)

// Version bytes: request has direction bit clear; response sets 0x80.
const (
	ReqV4  = 0x04
	RespV4 = 0x84
	ReqV5  = 0x05
	RespV5 = 0x85
)

// Header flag bits (§1).
const (
	FlagCompression   = 0x01
	FlagTracing       = 0x02
	FlagCustomPayload = 0x04
	FlagWarning       = 0x08
	FlagBeta          = 0x10
)

// Result kinds (§3.1). VOID is the only kind stably encoded in v1.
const (
	ResultVoid = 0x00000001
)

// maxFrameBytes is the implementation's frame size cap (§5 上限).
const maxFrameBytes = 256 * 1024

// opcodeForKind maps a config event kind to its opcode byte.
func opcodeForKind(kind string) (byte, bool) {
	switch kind {
	case "error":
		return OpError, true
	case "startup":
		return OpStartup, true
	case "ready":
		return OpReady, true
	case "authenticate":
		return OpAuthenticate, true
	case "options":
		return OpOptions, true
	case "supported":
		return OpSupported, true
	case "query":
		return OpQuery, true
	case "result":
		return OpResult, true
	case "prepare":
		return OpPrepare, true
	case "execute":
		return OpExecute, true
	case "auth_response":
		return OpAuthResponse, true
	case "auth_success":
		return OpAuthSuccess, true
	}
	return 0, false
}

// versionForProfile returns (request, response) version bytes for a wire profile.
func versionForProfile(profile string) (byte, byte, error) {
	switch profile {
	case "cql_v4", "cql_v4_auth":
		return ReqV4, RespV4, nil
	case "cql_v5":
		return ReqV5, RespV5, nil
	}
	return 0, 0, fmt.Errorf("cql: unsupported wire profile version %q (want cql_v4|cql_v4_auth|cql_v5)", profile)
}

// dirVersion picks the version byte for an event's direction: c2s request uses
// reqVer; s2c response uses respVer.
func dirVersion(reqVer, respVer byte, direction string) byte {
	if direction == "s2c" {
		return respVer
	}
	return reqVer
}

// buildHeader assembles the 9-byte native frame header: version(1) + flags(1) +
// stream(i16) + opcode(1) + length(i32). Body is appended after the header; the
// length field is the body byte count (§不变式 2).
func buildHeader(version, flags byte, stream int16, opcode byte, body []byte) ([]byte, error) {
	if len(body) > maxFrameBytes {
		return nil, fmt.Errorf("cql: body %d exceeds max frame %d", len(body), maxFrameBytes)
	}
	b := make([]byte, 9+len(body))
	b[0] = version
	b[1] = flags
	binary.BigEndian.PutUint16(b[2:4], uint16(stream))
	b[4] = opcode
	binary.BigEndian.PutUint32(b[5:9], uint32(len(body)))
	copy(b[9:], body)
	return b, nil
}

// buildFrame is the convenience wrapper: header + opcode body.
func buildFrame(reqVer, respVer byte, ev core.CQLEvent) ([]byte, error) {
	op, ok := opcodeForKind(ev.Kind)
	if !ok {
		return nil, fmt.Errorf("cql: unknown event kind %q", ev.Kind)
	}
	body, err := buildBody(op, reqVer, ev)
	if err != nil {
		return nil, err
	}
	version := dirVersion(reqVer, respVer, ev.Direction)
	return buildHeader(version, ev.Flags, ev.Stream, op, body)
}

// buildBody builds the frame body for an opcode from the event config.
// reqVer 决定 QUERY/EXECUTE 的 flags 宽度（W1/G-CQL-2：v4 [byte]、
// v5 [int]，native_protocol_v4.spec §4.1.4 / v5 §9 Changes#4）。
func buildBody(op byte, reqVer byte, ev core.CQLEvent) ([]byte, error) {
	switch op {
	case OpStartup:
		return buildStringMapBody(ev.Options), nil
	case OpReady:
		return nil, nil // empty body
	case OpAuthenticate:
		return appendString(nil, ev.Mechanism), nil
	case OpOptions:
		return nil, nil // empty body
	case OpSupported:
		return buildStringMultimapBody(ev.Options), nil
	case OpQuery:
		return buildQueryBody(reqVer, ev), nil
	case OpResult:
		return appendI32(nil, ResultVoid), nil
	case OpPrepare:
		return appendLongString(nil, ev.Query), nil
	case OpExecute:
		b := appendShortBytes(nil, []byte(ev.PreparedID))
		b = appendU16(b, ev.Consistency)
		b = appendQueryFlags(b, reqVer, ev.QueryFlags)
		return b, nil
	case OpAuthResponse:
		return appendBytes(nil, ev.Bytes), nil
	case OpAuthSuccess:
		return appendBytes(nil, ev.Bytes), nil
	case OpError:
		b := appendI32(nil, ev.Code)
		return appendString(b, ev.Message), nil
	}
	return nil, fmt.Errorf("cql: unsupported opcode %#x", op)
}

// buildQueryBody encodes [long string query] + consistency(short) + flags.
// W1（G-CQL-2）：v4 的 <query_parameters> flags 是 [byte]（1 字节，
// native_protocol_v4.spec §4.1.4），v5 扩为 [int]（4 字节，v5 §9
// Changes#4 "Enlarged ... from [byte] to [int]"）。宽度按 profile 选，
// 不再恒写 4 字节（tshark cql.query.flags 亦为 FT_UINT8 佐证 v4 面）。
func buildQueryBody(reqVer byte, ev core.CQLEvent) []byte {
	b := appendLongString(nil, ev.Query)
	b = appendU16(b, ev.Consistency)
	return appendQueryFlags(b, reqVer, ev.QueryFlags)
}

// appendQueryFlags appends the QUERY/EXECUTE flags field at the width the
// request version defines: 1 byte for v4, 4 bytes for v5.
func appendQueryFlags(b []byte, reqVer byte, flags uint32) []byte {
	if reqVer == ReqV5 {
		return appendU32(b, flags)
	}
	return append(b, byte(flags))
}

// buildStringMapBody encodes a STARTUP [string map]: short count + string
// key/value pairs.
func buildStringMapBody(options map[string]interface{}) []byte {
	if len(options) == 0 {
		return appendU16(nil, 0)
	}
	b := appendU16(nil, uint16(len(options)))
	for _, k := range sortedKeys(options) {
		b = appendString(b, k)
		b = appendString(b, fmt.Sprint(options[k]))
	}
	return b
}

// buildStringMultimapBody encodes a SUPPORTED [string multimap]: short count +
// string key + short value count + string values.
func buildStringMultimapBody(options map[string]interface{}) []byte {
	if len(options) == 0 {
		return appendU16(nil, 0)
	}
	b := appendU16(nil, uint16(len(options)))
	for _, k := range sortedKeys(options) {
		b = appendString(b, k)
		vals := multiValues(options[k])
		b = appendU16(b, uint16(len(vals)))
		for _, val := range vals {
			b = appendString(b, val)
		}
	}
	return b
}

// sortedKeys returns the map's string keys in a deterministic order so the
// emitted string map / string multimap is reproducible: CQL_VERSION always
// leads (it is conventionally first in STARTUP/SUPPORTED), then the remaining
// keys lexicographically. The pcap cases pin the bytes with CQL_VERSION first;
// a plain sort.Strings would put COMPRESSION ahead of CQL_VERSION ('C'<'Q').
func sortedKeys(options map[string]interface{}) []string {
	keys := make([]string, 0, len(options))
	for k := range options {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		if k == "CQL_VERSION" {
			copy(keys[1:i+1], keys[0:i])
			keys[0] = k
			break
		}
	}
	return keys
}

// multiValues normalizes a SUPPORTED multimap value (string or []interface{})
// into a string slice.
func multiValues(v interface{}) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case string:
		return []string{t}
	default:
		return nil
	}
}

// appendU16 appends a big-endian uint16.
func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// appendI32 appends a big-endian int32.
func appendI32(b []byte, v int32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// appendU32 appends a big-endian uint32.
func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// appendString appends a 2-byte length prefix + UTF-8 bytes ([string]).
func appendString(b []byte, s string) []byte {
	b = appendU16(b, uint16(len(s)))
	return append(b, []byte(s)...)
}

// appendLongString appends a 4-byte length prefix + UTF-8 bytes ([long string]).
func appendLongString(b []byte, s string) []byte {
	b = appendU32(b, uint32(len(s)))
	return append(b, []byte(s)...)
}

// appendBytes appends a 4-byte length prefix + raw bytes ([bytes]).
func appendBytes(b []byte, p []byte) []byte {
	b = appendU32(b, uint32(len(p)))
	return append(b, p...)
}

// appendShortBytes appends a 2-byte length prefix + raw bytes ([short bytes]).
func appendShortBytes(b []byte, p []byte) []byte {
	b = appendU16(b, uint16(len(p)))
	return append(b, p...)
}

// wireFault is the negative-test fault injection: the planner checks it before
// constructing any frame, returning a config error similar to TNS.
type wireFault struct {
	Kind  string      `json:"kind"`
	Value interface{} `json:"value"`
}

// checkWireFault parses the config wire_fault and returns a config error if the
// injected fault is in scope (§5 负例).
func checkWireFault(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var f wireFault
	if err := json.Unmarshal(raw, &f); err != nil {
		return fmt.Errorf("cql: invalid wire_fault: %v", err)
	}
	switch f.Kind {
	case "opcode":
		return fmt.Errorf("cql: wire fault: invalid opcode %v", f.Value)
	case "length":
		return fmt.Errorf("cql: wire fault: invalid length %v", f.Value)
	case "message_limit":
		return fmt.Errorf("cql: wire fault: frame over message limit %v", f.Value)
	default:
		return fmt.Errorf("cql: wire fault: unknown kind %q", f.Kind)
	}
}
