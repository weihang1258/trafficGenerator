package kingbase

import (
	"github.com/trafficgen/trafficgen/internal/protocol/pgwire"
)

// PostgreSQL v3 wire protocol constants (delegated to the shared pgwire
// package — kingbase is a dialect variant of the shared postgresql wire layer).
const (
	// ProtocolV3 is the PostgreSQL v3 protocol version.
	ProtocolV3 = pgwire.ProtocolV3
)

// Message type constants (ASCII), delegated to pgwire.
const (
	typeAuth           = pgwire.TypeAuth
	typePassword       = pgwire.TypePassword
	typeParameter      = pgwire.TypeParameter
	typeReadyForQuery  = pgwire.TypeReadyForQuery
	typeQuery          = pgwire.TypeQuery
	typeRowDesc        = pgwire.TypeRowDesc
	typeDataRow        = pgwire.TypeDataRow
	typeCmdComplete    = pgwire.TypeCmdComplete
	typeError          = pgwire.TypeError
	typeTerminate      = pgwire.TypeTerminate
)

// Authentication sub-type codes (delegated to pgwire).
const (
	authOk        = pgwire.AuthOkCode
	authCleartext = pgwire.AuthCleartextCode
	authMD5       = pgwire.AuthMD5Code
	authSASL      = pgwire.AuthSASLCode
)

// ReadyForQuery status bytes (delegated to pgwire).
const (
	rfqIdle    = pgwire.RFQIdle
	rfqInTrans = pgwire.RFQInTrans
	rfqFailed  = pgwire.RFQFailed
)

// DefaultPort is the KingBase default port.
const DefaultPort = 54321

// buildStartupMessage builds a PostgreSQL v3 StartupMessage.
// Format: int32 length (includes itself) + int32 protocol_version +
// key\0value\0... + \0 terminator. This is the ONLY PG v3 message with no
// type byte.
func buildStartupMessage(protocolVersion int32, params map[string]string) []byte {
	return pgwire.StartupMessage(protocolVersion, params)
}

// buildTypedMessage builds a PostgreSQL v3 typed message:
// [1 byte type][int32 length (includes self, excludes type)][payload].
func buildTypedMessage(typeByte byte, payload []byte) []byte {
	return pgwire.TypedMessage(typeByte, payload)
}

// buildAuthRequest builds an AuthenticationRequest ('R') message.
func buildAuthRequest(authCode int32) []byte {
	return pgwire.AuthRequest(authCode)
}

// buildAuthOk builds an AuthenticationOk ('R' code=0) message.
func buildAuthOk() []byte {
	return pgwire.AuthOk()
}

// buildPasswordMessage builds a PasswordMessage ('p').
func buildPasswordMessage(password string) []byte {
	return pgwire.PasswordMessage(password)
}

// buildParameterStatus builds a ParameterStatus ('S') message.
func buildParameterStatus(name, value string) []byte {
	return pgwire.ParameterStatus(name, value)
}

// buildReadyForQuery builds a ReadyForQuery ('Z') message.
func buildReadyForQuery(status byte) []byte {
	return pgwire.ReadyForQuery(status)
}

// buildQueryMessage builds a SimpleQuery ('Q') message.
func buildQueryMessage(sql string) []byte {
	return pgwire.QueryMessage(sql)
}

// buildRowDescription builds a RowDescription ('T') with one column.
func buildRowDescription() []byte {
	return pgwire.RowDescription()
}

// buildDataRow builds a DataRow ('D') with one column containing int32(42).
func buildDataRow() []byte {
	return pgwire.DataRow()
}

// buildCommandComplete builds a CommandComplete ('C') message.
func buildCommandComplete(tag string) []byte {
	return pgwire.CommandComplete(tag)
}

// buildErrorResponse builds an ErrorResponse ('E') message.
// Fields are type byte + C-string, terminated by a zero byte.
func buildErrorResponse(severity, code, message string) []byte {
	return pgwire.ErrorResponse(severity, code, message)
}

// buildTerminateMessage builds a Terminate ('X') message.
func buildTerminateMessage() []byte {
	return pgwire.TerminateMessage()
}

// applyTruncateStartup truncates the startup message payload by n bytes.
// Returns an error if n >= len(payload) (would leave no valid message).
func applyTruncateStartup(startup []byte, n int) ([]byte, error) {
	return pgwire.TruncateStartup(startup, n)
}

// --- helpers (kingbase test compatibility; thin wrappers over pgwire) ---

func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func sortStrings(s []string) {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}
