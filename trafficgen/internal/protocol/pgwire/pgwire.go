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

// ProtocolV3_1 / ProtocolV3_2 are the v3.1 (pipeline mode) and v3.2
// (PostgreSQL 18) protocol versions. Note the dissector only recognises 3.0 —
// v3.1/v3.2 payloads must be asserted via frames hex (design §3.2/§3.9).
const (
	ProtocolV3_1 = 0x00030001
	ProtocolV3_2 = 0x00030002
)

// Untyped request magic codes (design §3.2). These ride the StartupMessage
// outer shape (int32 length + int32 code + payload) but carry a magic instead
// of a protocol version.
const (
	CancelRequestCode int32 = 80877102 // 04 D2 16 2E
	SSLRequestCode    int32 = 80877103 // 04 D2 16 2F
	GSSENCRequestCode int32 = 80877104 // 04 D2 16 30
)

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
	TypeNotice         byte = 'N' // 0x4E, NoticeResponse
	TypeNotification   byte = 'A' // 0x41, NotificationResponse
	TypeEmptyQuery     byte = 'I' // 0x49, EmptyQueryResponse
	TypeTerminate      byte = 'X' // 0x58, Terminate

	// Extended-query (frontend) tags. Several letters collide with
	// backend tags (D/E/C/S/H) — direction + session state disambiguate
	// (design §3.3).
	TypeParse    byte = 'P'
	TypeBind     byte = 'B'
	TypeDescribe byte = 'D'
	TypeExecute  byte = 'E'
	TypeSync     byte = 'S'
	TypeFlush    byte = 'H'
	TypeClose    byte = 'C'
	TypeFunction byte = 'F'

	// Extended-query completion / auxiliary (backend) tags.
	TypeParseComplete   byte = '1'
	TypeBindComplete    byte = '2'
	TypeCloseComplete   byte = '3'
	TypeParamDesc       byte = 't'
	TypeNoData          byte = 'n'
	TypePortalSuspended byte = 's'
	TypeFuncCallResp    byte = 'V'
	TypeNegotiate       byte = 'v'
)

// Authentication sub-type codes (int32 discriminator after type 'R').
const (
	AuthOkCode        int32 = 0
	AuthKerberosV5    int32 = 2
	AuthCleartextCode int32 = 3
	AuthMD5Code       int32 = 5
	AuthSCMCredCode   int32 = 6
	AuthGSSCode       int32 = 7
	AuthGSSContCode   int32 = 8
	AuthSSPICode      int32 = 9
	AuthSASLCode      int32 = 10
	AuthSASLContCode  int32 = 11
	AuthSASLFinalCode int32 = 12
)

// Describe/Close mode bytes (Byte1 S|P).
const (
	ModeStatement byte = 'S'
	ModePortal    byte = 'P'
)

// FieldDesc is one RowDescription column descriptor (design §3.3).
type FieldDesc struct {
	Name     string
	TableOID int32
	Column   int16
	TypeOID  int32
	TypeLen  int16
	TypeMod  int32
	Format   int16
}

// ErrorField is one ErrorResponse/NoticeResponse field: a 1-byte code plus a
// NUL-terminated value (design §3.6).
type ErrorField struct {
	Type  byte
	Value string
}

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

// AuthRequestData builds an AuthenticationRequest ('R') carrying the sub-type
// code plus a sub-type-specific payload (design §3.4):
//   - code 5 (MD5Password): exactly 4 salt bytes.
//   - code 8 (GSSContinue): Byte^n GSSAPI/SSPI token.
//   - code 10 (SASL): one String per mechanism name plus a zero terminator.
//   - codes 11/12 (SASLContinue/SASLFinal): Byte^n SASL data.
//
// Sub-types with no payload (0/2/3/6/7/9) use AuthRequest. Payloads are
// opaque — the builder never interprets or validates the cryptography
// (design §10 铁律: MD5 digest / SCRAM / GSSAPI are never implemented).
func AuthRequestData(authCode int32, data []byte) []byte {
	payload := make([]byte, 4, 4+len(data))
	binary.BigEndian.PutUint32(payload, uint32(authCode))
	payload = append(payload, data...)
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

// PasswordMessageRaw builds a PasswordMessage ('p') from opaque bytes with no
// NUL terminator. The GSSResponse / SASLInitialResponse / SASLResponse
// messages all ride the 'p' type but carry a byte token rather than a
// C-string (design §3.4), so they must not get the trailing zero that
// PasswordMessage appends.
func PasswordMessageRaw(data []byte) []byte {
	return TypedMessage(TypePassword, data)
}

// ParameterStatus builds a ParameterStatus ('S') message.
func ParameterStatus(name, value string) []byte {
	payload := append([]byte(name), 0)
	payload = append(payload, []byte(value)...)
	payload = append(payload, 0)
	return TypedMessage(TypeParameter, payload)
}

// BackendKeyData builds a BackendKeyData ('K') message with a fixed 4-byte
// secret. PostgreSQL 18 (protocol 3.2) allows a variable-length secret
// (4..256 bytes); that face is a declared structural gap (design §3.8 /
// G-PG-2) and is not implemented here.
func BackendKeyData(pid, secret int32) []byte {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint32(payload[0:4], uint32(pid))
	binary.BigEndian.PutUint32(payload[4:8], uint32(secret))
	return TypedMessage(TypeBackendKeyData, payload)
}

// ReadyForQuery builds a ReadyForQuery ('Z') message. status is one of
// RFQIdle ('I'), RFQInTrans ('T'), RFQFailed ('E').
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
	return RowDescriptionFields([]FieldDesc{{Name: "col1", Column: 1, TypeOID: 23, TypeLen: 4, TypeMod: -1}})
}

// RowDescriptionFields builds a RowDescription ('T') from explicit column
// descriptors (design §3.3): int16 column count followed by, per column,
// name\0 + tableOID int32 + column int16 + typeOID int32 + typeLen int16 +
// typeMod int32 + format int16.
func RowDescriptionFields(fields []FieldDesc) []byte {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(fields)))
	for _, f := range fields {
		payload = append(payload, []byte(f.Name)...)
		payload = append(payload, 0)
		payload = appendUint32(payload, uint32(f.TableOID))
		payload = appendUint16(payload, uint16(f.Column))
		payload = appendUint32(payload, uint32(f.TypeOID))
		payload = appendUint16(payload, uint16(f.TypeLen))
		payload = appendUint32(payload, uint32(f.TypeMod))
		payload = appendUint16(payload, uint16(f.Format))
	}
	return TypedMessage(TypeRowDesc, payload)
}

// DataRow builds a DataRow ('D') with one column containing int32(42).
// Matches the postgresql case frame assertion
// [44 00 00 00 0e 00 01 00 00 00 04 00 00 00 2a].
func DataRow() []byte {
	colData := make([]byte, 4)
	binary.BigEndian.PutUint32(colData, 42)
	return DataRowColumns([][]byte{colData})
}

// DataRowColumns builds a DataRow ('D') from explicit column values: int16
// column count followed by, per column, an int32 length and the value. A nil
// column encodes length -1 (SQL NULL), per design §3.3.
func DataRowColumns(cols [][]byte) []byte {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(cols)))
	for _, c := range cols {
		if c == nil {
			payload = appendUint32(payload, 0xFFFFFFFF) // -1 = NULL
			continue
		}
		payload = appendUint32(payload, uint32(len(c)))
		payload = append(payload, c...)
	}
	return TypedMessage(TypeDataRow, payload)
}

// CommandComplete builds a CommandComplete ('C') message.
func CommandComplete(tag string) []byte {
	return TypedMessage(TypeCmdComplete, append([]byte(tag), 0))
}

// ErrorResponse builds an ErrorResponse ('E') message. Fields are (type byte +
// C-string) pairs, terminated by a zero byte.
func ErrorResponse(severity, code, message string) []byte {
	var fields []ErrorField
	if severity != "" {
		fields = append(fields, ErrorField{'S', severity})
	}
	if code != "" {
		fields = append(fields, ErrorField{'C', code})
	}
	if message != "" {
		fields = append(fields, ErrorField{'M', message})
	}
	return ErrorResponseFields(fields)
}

// ErrorResponseFields builds an ErrorResponse ('E') from an explicit field
// sequence (design §3.6): each field is a 1-byte code plus a NUL-terminated
// value; the whole sequence ends with a single 0x00 byte.
func ErrorResponseFields(fields []ErrorField) []byte {
	return TypedMessage(TypeError, errorFieldsPayload(fields))
}

// NoticeResponse builds a NoticeResponse ('N'). Same field layout as
// ErrorResponse but does not end the transaction (design §3.6).
func NoticeResponse(fields []ErrorField) []byte {
	return TypedMessage(TypeNotice, errorFieldsPayload(fields))
}

// errorFieldsPayload encodes a (code + C-string) sequence with the single
// trailing 0x00 terminator shared by ErrorResponse/NoticeResponse.
func errorFieldsPayload(fields []ErrorField) []byte {
	var payload []byte
	for _, f := range fields {
		payload = append(payload, f.Type)
		payload = append(payload, []byte(f.Value)...)
		payload = append(payload, 0)
	}
	return append(payload, 0)
}

// NotificationResponse builds a NotificationResponse ('A'): int32 pid +
// channel\0 + payload\0.
func NotificationResponse(pid int32, channel, payload string) []byte {
	out := appendUint32(nil, uint32(pid))
	out = append(out, []byte(channel)...)
	out = append(out, 0)
	out = append(out, []byte(payload)...)
	out = append(out, 0)
	return TypedMessage(TypeNotification, out)
}

// EmptyQueryResponse builds an EmptyQueryResponse ('I') — the reply to an
// empty SimpleQuery string, replacing CommandComplete.
func EmptyQueryResponse() []byte { return TypedMessage(TypeEmptyQuery, nil) }

// NoData builds a NoData ('n') reply to Describe on a statement that returns
// no rows.
func NoData() []byte { return TypedMessage(TypeNoData, nil) }

// PortalSuspended builds a PortalSuspended ('s') reply when Execute's row
// limit was reached.
func PortalSuspended() []byte { return TypedMessage(TypePortalSuspended, nil) }

// ParameterDescription builds a ParameterDescription ('t'): int16 parameter
// count followed by one int32 type OID per parameter.
func ParameterDescription(oids []int32) []byte {
	out := appendUint16(nil, uint16(len(oids)))
	for _, oid := range oids {
		out = appendUint32(out, uint32(oid))
	}
	return TypedMessage(TypeParamDesc, out)
}

// ParseComplete / BindComplete / CloseComplete are the empty extended-query
// completion messages ('1' / '2' / '3').
func ParseComplete() []byte { return TypedMessage(TypeParseComplete, nil) }
func BindComplete() []byte  { return TypedMessage(TypeBindComplete, nil) }
func CloseComplete() []byte { return TypedMessage(TypeCloseComplete, nil) }

// Parse builds a Parse ('P'): stmt\0 + query\0 + int16 param count + int32
// OIDs.
func Parse(stmt, sql string, paramOIDs []int32) []byte {
	out := append([]byte(stmt), 0)
	out = append(out, []byte(sql)...)
	out = append(out, 0)
	out = appendUint16(out, uint16(len(paramOIDs)))
	for _, oid := range paramOIDs {
		out = appendUint32(out, uint32(oid))
	}
	return TypedMessage(TypeParse, out)
}

// Bind builds a Bind ('B'): portal\0 + stmt\0 + int16 format count + formats +
// int16 value count + (int32 len + bytes)* + int16 result-format count +
// result formats. A nil value encodes length -1 (NULL).
func Bind(portal, stmt string, formats []int16, values [][]byte, resultFormats []int16) []byte {
	out := append([]byte(portal), 0)
	out = append(out, []byte(stmt)...)
	out = append(out, 0)
	out = appendUint16(out, uint16(len(formats)))
	for _, f := range formats {
		out = appendUint16(out, uint16(f))
	}
	out = appendUint16(out, uint16(len(values)))
	for _, v := range values {
		if v == nil {
			out = appendUint32(out, 0xFFFFFFFF) // -1 = NULL
			continue
		}
		out = appendUint32(out, uint32(len(v)))
		out = append(out, v...)
	}
	out = appendUint16(out, uint16(len(resultFormats)))
	for _, f := range resultFormats {
		out = appendUint16(out, uint16(f))
	}
	return TypedMessage(TypeBind, out)
}

// Describe builds a Describe ('D'): Byte1 mode ('S' statement | 'P' portal) +
// name\0.
func Describe(mode byte, name string) []byte {
	out := append([]byte{mode}, []byte(name)...)
	return TypedMessage(TypeDescribe, append(out, 0))
}

// Execute builds an Execute ('E'): portal\0 + int32 max rows (0 = no limit).
func Execute(portal string, maxRows int32) []byte {
	out := append([]byte(portal), 0)
	out = appendUint32(out, uint32(maxRows))
	return TypedMessage(TypeExecute, out)
}

// Sync / Flush are the empty extended-query control messages ('S' / 'H').
func Sync() []byte  { return TypedMessage(TypeSync, nil) }
func Flush() []byte { return TypedMessage(TypeFlush, nil) }

// Close builds a Close ('C'): Byte1 mode ('S' statement | 'P' portal) +
// name\0.
func Close(mode byte, name string) []byte {
	out := append([]byte{mode}, []byte(name)...)
	return TypedMessage(TypeClose, append(out, 0))
}

// FunctionCall builds a FunctionCall ('F'): int32 function OID + int16 format
// count + formats + int16 arg count + (int32 len + bytes)* + int16 result
// format.
func FunctionCall(oid int32, formats []int16, args [][]byte, resultFormat int16) []byte {
	out := appendUint32(nil, uint32(oid))
	out = appendUint16(out, uint16(len(formats)))
	for _, f := range formats {
		out = appendUint16(out, uint16(f))
	}
	out = appendUint16(out, uint16(len(args)))
	for _, a := range args {
		out = appendUint32(out, uint32(len(a)))
		out = append(out, a...)
	}
	out = appendUint16(out, uint16(resultFormat))
	return TypedMessage(TypeFunction, out)
}

// FunctionCallResponse builds a FunctionCallResponse ('V'): int32 length
// (-1 = NULL) plus the value.
func FunctionCallResponse(value []byte) []byte {
	if value == nil {
		return TypedMessage(TypeFuncCallResp, []byte{0xFF, 0xFF, 0xFF, 0xFF})
	}
	out := appendUint32(nil, uint32(len(value)))
	return TypedMessage(TypeFuncCallResp, append(out, value...))
}

// NegotiateProtocolVersion builds a NegotiateProtocolVersion ('v'): int32
// newest supported minor + int32 unrecognized-option count + String[].
// The 3.6.14 dissector reads this as Unknown — assert via frames hex.
func NegotiateProtocolVersion(newestMinor int32, unrecognized []string) []byte {
	out := appendUint32(nil, uint32(newestMinor))
	out = appendUint32(out, uint32(len(unrecognized)))
	for _, u := range unrecognized {
		out = append(out, []byte(u)...)
		out = append(out, 0)
	}
	return TypedMessage(TypeNegotiate, out)
}

// SSLRequest builds the untyped 8-byte SSLRequest (length 8 + magic).
func SSLRequest() []byte { return untypedRequest(SSLRequestCode) }

// GSSENCRequest builds the untyped 8-byte GSSENCRequest (length 8 + magic).
func GSSENCRequest() []byte { return untypedRequest(GSSENCRequestCode) }

// CancelRequest builds the untyped 16-byte CancelRequest: length 16 + magic +
// the target backend's pid and secret. It rides a second, independent
// connection and gets no response bytes (design §10.4).
func CancelRequest(pid, secret int32) []byte {
	out := appendUint32(nil, 16)
	out = appendUint32(out, uint32(CancelRequestCode))
	out = appendUint32(out, uint32(pid))
	out = appendUint32(out, uint32(secret))
	return out
}

// untypedRequest builds the StartupMessage outer shape with a request magic
// instead of a protocol version (design §3.1/§3.2).
func untypedRequest(code int32) []byte {
	out := appendUint32(nil, 8)
	return appendUint32(out, uint32(code))
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
