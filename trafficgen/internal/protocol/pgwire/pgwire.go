// Package pgwire is the shared PostgreSQL v3 wire builder (共用零件).
//
// It factors the PG v3 message-construction logic out of the per-protocol
// packages (postgresql / kingbase) so both can reuse the same byte-level
// builders instead of duplicating them. This is the "postgresql → shared wire
// layer" convergence from docs/protocol-designs/18-layer-config-design.md
// §4.3 / §2.2: kingbase is a dialect variant of the postgresql layer, and both
// ride on the same PG v3 wire.
//
// Scope: pure byte construction, no `core`/`layers` imports (this package is
// imported by protocol packages, which already import core/layers). Anything
// that needs to map a config/event to bytes lives in the caller.
//
// Wire layout facts (PostgreSQL v3):
//   - StartupMessage is the ONLY message WITHOUT a 1-byte type tag: it is
//     [int32 length (includes itself)][int32 protocol_version][key\0val\0...\0].
//   - Every other message is [1-byte type][int32 length (includes itself,
//     NOT the type byte)][payload].
package pgwire

import (
	"encoding/binary"
	"fmt"
)

// ProtocolV3 is the default PostgreSQL protocol version (v3.0).
const ProtocolV3 = 0x00030000

// Message type tags (ASCII). The compiler enforces uint8 size.
const (
	TypeAuth           byte = 'R' // 0x52, Authentication (sub-typed by int32)
	TypePassword       byte = 'p' // 0x70, PasswordMessage
	TypeParameter      byte = 'S' // 0x53, ParameterStatus
	TypeBackendKeyData byte = 'K' // 0x4B, BackendKeyData
	TypeReadyForQuery  byte = 'Z' // 0x5A, ReadyForQuery
	TypeQuery          byte = 'Q' // 0x51, SimpleQuery
	TypeRowDesc        byte = 'T' // 0x54, RowDescription
	TypeDataRow        byte = 'D' // 0x44, DataRow
	TypeCmdComplete    byte = 'C' // 0x43, CommandComplete
	TypeError          byte = 'E' // 0x45, ErrorResponse
	TypeTerminate      byte = 'X' // 0x58, Terminate
)

// Authentication sub-type codes (int32 discriminator after type 'R').
const (
	AuthOkCode        int32 = 0
	AuthCleartextCode int32 = 3
	AuthMD5Code       int32 = 5
	AuthSASLCode      int32 = 10
)

// ReadyForQuery status bytes.
const (
	RFQIdle    byte = 'I' // not in transaction
	RFQInTrans byte = 'T' // in transaction
	RFQFailed  byte = 'E' // in failed transaction
)

// appendUint16 appends v as big-endian uint16.
func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// appendUint32 appends v as big-endian uint32.
func appendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// StartupMessage builds a PostgreSQL v3 StartupMessage (no type byte).
// Format: [int32 length (includes itself)][int32 protocol_version]
// [key\0value\0...]\0. params may be nil/empty → just version + terminator.
func StartupMessage(protocolVersion int32, params map[string]string) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload[0:4], uint32(protocolVersion))
	keys := sortedKeys(params)
	for _, k := range keys {
		payload = append(payload, []byte(k)...)
		payload = append(payload, 0)
		payload = append(payload, []byte(params[k])...)
		payload = append(payload, 0)
	}
	payload = append(payload, 0) // final null terminator

	length := uint32(4 + len(payload)) // includes itself
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out[0:4], length)
	copy(out[4:], payload)
	return out
}

// TypedMessage builds a PostgreSQL v3 typed message:
// [1 byte type][int32 length (includes self, excludes type)][payload].
func TypedMessage(typeByte byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = typeByte
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(payload)))
	copy(out[5:], payload)
	return out
}

// AuthRequest builds an AuthenticationRequest ('R') message with the given
// auth sub-type code.
func AuthRequest(authCode int32) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(authCode))
	return TypedMessage(TypeAuth, payload)
}

// AuthOk builds an AuthenticationOk ('R' code=0) message.
func AuthOk() []byte {
	return AuthRequest(AuthOkCode)
}

// PasswordMessage builds a PasswordMessage ('p').
func PasswordMessage(password string) []byte {
	return TypedMessage(TypePassword, append([]byte(password), 0))
}

// ParameterStatus builds a ParameterStatus ('S') message.
func ParameterStatus(name, value string) []byte {
	payload := append([]byte(name), 0)
	payload = append(payload, []byte(value)...)
	payload = append(payload, 0)
	return TypedMessage(TypeParameter, payload)
}

// BackendKeyData builds a BackendKeyData ('K') message.
func BackendKeyData(pid, secret int32) []byte {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint32(payload[0:4], uint32(pid))
	binary.BigEndian.PutUint32(payload[4:8], uint32(secret))
	return TypedMessage(TypeBackendKeyData, payload)
}

// ReadyForQuery builds a ReadyForQuery ('Z') message.
func ReadyForQuery(status byte) []byte {
	return TypedMessage(TypeReadyForQuery, []byte{status})
}

// QueryMessage builds a SimpleQuery ('Q') message.
func QueryMessage(sql string) []byte {
	return TypedMessage(TypeQuery, append([]byte(sql), 0))
}

// RowDescription builds a RowDescription ('T') with a single int4 column named
// "col1". Shared by the postgresql/kingbase terminal generators, whose pcap
// cases assert only the outer type ('T'), not the private column metadata.
func RowDescription() []byte {
	fieldName := "col1"
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload[0:2], 1) // 1 field
	payload = append(payload, []byte(fieldName)...)
	payload = append(payload, 0)
	payload = appendUint32(payload, 0)          // table_oid
	payload = appendUint16(payload, 1)          // attnum
	payload = appendUint32(payload, 23)         // type_oid (int4)
	payload = appendUint16(payload, 4)          // typlen
	payload = appendUint32(payload, 0xFFFFFFFF) // typmod (-1 as uint32)
	payload = appendUint16(payload, 0)          // format (text)
	return TypedMessage(TypeRowDesc, payload)
}

// DataRow builds a DataRow ('D') with one column containing int32(42).
// Matches the postgresql case frame assertion
// [44 00 00 00 0e 00 01 00 00 00 04 00 00 00 2a].
func DataRow() []byte {
	colData := make([]byte, 4)
	binary.BigEndian.PutUint32(colData, 42)
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload[0:2], 1) // 1 column
	payload = appendUint32(payload, uint32(len(colData)))
	payload = append(payload, colData...)
	return TypedMessage(TypeDataRow, payload)
}

// CommandComplete builds a CommandComplete ('C') message.
func CommandComplete(tag string) []byte {
	return TypedMessage(TypeCmdComplete, append([]byte(tag), 0))
}

// ErrorResponse builds an ErrorResponse ('E') message. Fields are (type byte +
// C-string) pairs, terminated by a zero byte.
func ErrorResponse(severity, code, message string) []byte {
	var payload []byte
	if severity != "" {
		payload = append(payload, 'S')
		payload = append(payload, []byte(severity)...)
		payload = append(payload, 0)
	}
	if code != "" {
		payload = append(payload, 'C')
		payload = append(payload, []byte(code)...)
		payload = append(payload, 0)
	}
	if message != "" {
		payload = append(payload, 'M')
		payload = append(payload, []byte(message)...)
		payload = append(payload, 0)
	}
	payload = append(payload, 0) // terminator
	return TypedMessage(TypeError, payload)
}

// TerminateMessage builds a Terminate ('X') message.
func TerminateMessage() []byte {
	return TypedMessage(TypeTerminate, nil)
}

// TruncateStartup truncates the startup message payload by n bytes.
// Returns an error if n >= len(payload) (would leave no valid message).
// Used by the wire_fault negative-path test (truncated Startup length).
func TruncateStartup(startup []byte, n int) ([]byte, error) {
	if n <= 0 {
		return startup, nil
	}
	if n >= len(startup) {
		return nil, fmt.Errorf("pgwire: truncate_startup: value %d exceeds message length %d", n, len(startup))
	}
	return startup[:len(startup)-n], nil
}

// sortedKeys returns the keys of m in sorted order (deterministic startup
// encoding). nil map → empty slice.
func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// insertion sort (param maps are tiny)
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}
