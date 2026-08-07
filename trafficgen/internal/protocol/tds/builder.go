// Package tds: builder.go holds the TDS wire-format constants (spec §2) and
// the encoder helpers used by the planner. The planner composes packet
// payloads from these primitives; tests assert against the byte sequences
// produced here.
//
// Wire-format notes (spec §1.7):
//   - All multi-byte integers are little-endian unless explicitly noted as
//     big-endian. Big-endian fields are: packet header Length/SPID, and
//     PRELOGIN PL_OFFSET/PL_OPTION_LENGTH.
//   - B_VARCHAR = 1B BYTELEN (Unicode char count) + UCS-2 LE bytes.
//   - US_VARCHAR = 2B LE USHORTLEN (Unicode char count) + UCS-2 LE bytes.
//   - UCS-2 LE encodes each character as 2 bytes; byte length = 2 * char count.
package tds

import (
	"encoding/binary"
	"unicode/utf16"
)

// TDS packet Type values (spec §2.1.1).
const (
	TypeSQLBatch      = 0x01
	TypePreTDS7Login  = 0x02
	TypeRPC           = 0x03
	TypeTabularResult = 0x04
	TypeUnused        = 0x05 // spec §2.1.1: no meaning assigned
	TypeAttention     = 0x06
	TypeBulkLoad      = 0x07
	TypeFedAuthToken  = 0x08
	TypeTransMgrReq   = 0x0E
	TypeLogin7        = 0x10
	TypeSSPI          = 0x11
	TypePreLogin      = 0x12
)

// TDS packet Status bits (spec §2.1.2).
const (
	StatusNormal            = 0x00
	StatusEOM               = 0x01
	StatusIgnore            = 0x02
	StatusResetConnection   = 0x08 // TDS 7.1+
	StatusResetConnSkipTran = 0x10 // TDS 7.3+
)

// PRELOGIN option tokens (spec §3.1).
const (
	PLVersion    = 0x00
	PLEncryption = 0x01
	PLInstOpt    = 0x02
	PLThreadID   = 0x03
	PLMARS       = 0x04
	PLTraceID    = 0x05
	PLFedAuthReq = 0x06
	PLNonceOpt   = 0x07
	PLTerminator = 0xFF
)

// ENCRYPTION option values (spec §3.1).
const (
	EncryptOff      = 0x00
	EncryptOn       = 0x01
	EncryptNotSup   = 0x02
	EncryptRequired = 0x03
)

// ALL_HEADERS HeaderType values (spec §2.5).
const (
	HeaderQueryNotif            = 0x0000
	HeaderTransactionDescriptor = 0x0002
	HeaderTraceActivity         = 0x0003
)

// TransMgrReq RequestType values (spec §3.5).
const (
	TMGetDTCAddr    = 0
	TMPropagateXact = 1
	TMBeginXact     = 5
	TMPromoteXact   = 6
	TMCommitXact    = 7
	TMRollbackXact  = 8
	TMSaveXact      = 9
)

// Isolation levels for TM_BEGIN_XACT (spec §3.5).
const (
	IsoUseCurrent      = 0x00
	IsoReadUncommitted = 0x01
	IsoReadCommitted   = 0x02
	IsoRepeatableRead  = 0x03
	IsoSerializable    = 0x04
	IsoSnapshot        = 0x05
)

// Token stream tokens (spec §3.6).
const (
	TokenColMetadata   = 0x81
	TokenRow           = 0xD1
	TokenNbcRow        = 0xD2
	TokenDone          = 0xFD
	TokenDoneProc      = 0xFE
	TokenDoneInProc    = 0xFF
	TokenEnvChange     = 0xE3
	TokenError         = 0xAA
	TokenInfo          = 0xAB
	TokenFeatureExtAck = 0xAE
	TokenFedAuthInfo   = 0xEE
	TokenLoginAck      = 0xAD
	TokenReturnStatus  = 0x79
	TokenReturnValue   = 0xAC
	TokenSessionState  = 0xE4
	TokenOrder         = 0xA9
	TokenTabName       = 0xA4
	TokenColInfo       = 0xA5
	TokenOffset        = 0x78
)

// DONE Status bits (spec §3.9). Note DONE_RPCINBATCH (0x80) applies ONLY to
// DONEPROC (spec §2.2.7.8), not DONE — a v3.0.0 bug fixed in v3.0.1.
const (
	DONEFinal      = 0x00
	DONEMore       = 0x01
	DONEError      = 0x02
	DONEInXact     = 0x04
	DONECount      = 0x10
	DONEAttn       = 0x20
	DONERPCInBatch = 0x80 // DONEPROC only
	DONESrvError   = 0x0100
)

// COLMETADATA Flags bits (spec §3.7, LSB order). v3.0.1 corrected the bit
// assignments to match spec §2.2.7.4 (v3.0.0 had several bits wrong).
const (
	FlagNullable        = 0x0001
	FlagCaseSen         = 0x0002
	FlagUpdateableMask  = 0x000C
	FlagIdentity        = 0x0010
	FlagComputed        = 0x0020
	FlagFixedLenCLRType = 0x0100
	FlagSparseColumnSet = 0x0400
	FlagEncrypted       = 0x0800
	FlagHidden          = 0x2000
	FlagKey             = 0x4000
	FlagNullableUnknown = 0x8000
)

// Data type tokens (spec §2.4).
const (
	TypeNull        = 0x1F
	TypeInt1        = 0x30
	TypeBit         = 0x32
	TypeInt2        = 0x34
	TypeInt4        = 0x38
	TypeDateTime4   = 0x3A
	TypeFloat4      = 0x3B
	TypeMoney       = 0x3C
	TypeDateTime    = 0x3D
	TypeFloat8      = 0x3E
	TypeMoney4      = 0x7A
	TypeInt8        = 0x7F
	TypeDecimal     = 0x37 // legacy
	TypeNumeric     = 0x3F // legacy
	TypeGUID        = 0x24
	TypeIntN        = 0x26
	TypeBitN        = 0x68
	TypeDecimalN    = 0x6A
	TypeNumericN    = 0x6C
	TypeFloatN      = 0x6D
	TypeMoneyN      = 0x6E
	TypeDateTimeN   = 0x6F
	TypeDate        = 0x28
	TypeTime        = 0x29
	TypeDateTime2   = 0x2A
	TypeDateTimeOff = 0x2B
	TypeChar        = 0x2F
	TypeVarChar     = 0x27
	TypeBinary      = 0x2D
	TypeVarBinary   = 0x25
	TypeBigVarBin   = 0xA5
	TypeBigVarChar  = 0xA7
	TypeBigBinary   = 0xAD
	TypeBigChar     = 0xAF
	TypeNVarChar    = 0xE7
	TypeNChar       = 0xEF
	TypeVector      = 0xF5
	TypeImage       = 0x22
	TypeNText       = 0x63
	TypeSSVariant   = 0x62
	TypeText        = 0x23
	TypeXML         = 0xF1
	TypeJSON        = 0xF4
	TypeUDT         = 0xF0
)

// PLP sentinels (spec §2.4.4).
const (
	PLPNull       uint64 = 0xFFFFFFFFFFFFFFFF
	PLPUnknownLen uint64 = 0xFFFFFFFFFFFFFFFE
	PLPTerminator uint32 = 0x00000000
)

// CHARBIN_NULL (2B) for USHORTLEN char/binary types (spec §2.4.3).
const CharBinNull2 = 0xFFFF

// CHARBIN_NULL (4B) for LONGLEN text/ntext/image types.
const CharBinNull4 = 0xFFFFFFFF

// DefaultCollation is the raw-collation sentinel (spec §2.4.5).
var DefaultCollation = [5]byte{0x09, 0x04, 0xD0, 0x00, 0x34}

// encodeUTF16 converts a Go string to UCS-2 LE bytes (spec §1.7).
func encodeUTF16(s string) []byte {
	codes := utf16.Encode([]rune(s))
	out := make([]byte, len(codes)*2)
	for i, r := range codes {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}

// putBE16/putBE32 write big-endian integers (used for packet-header Length/
// SPID and PRELOGIN offsets).
func putBE16(b []byte, v uint16) { b[0] = byte(v >> 8); b[1] = byte(v) }
func putBE32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

// putLE16/putLE32/putLE64 write little-endian integers.
func putLE16(b []byte, v uint16) { binary.LittleEndian.PutUint16(b, v) }
func putLE32(b []byte, v uint32) { binary.LittleEndian.PutUint32(b, v) }
func putLE64(b []byte, v uint64) { binary.LittleEndian.PutUint64(b, v) }

// bVarChar encodes a B_VARCHAR (spec §2.3): 1B BYTELEN (Unicode char count)
// + UCS-2 LE bytes. Char count is capped at 255.
func bVarChar(s string) []byte {
	codes := utf16.Encode([]rune(s))
	n := byte(len(codes))
	if len(codes) > 0xFF {
		n = 0xFF
		codes = codes[:0xFF]
	}
	out := make([]byte, 1+int(n)*2)
	out[0] = n
	for i, r := range codes {
		binary.LittleEndian.PutUint16(out[1+i*2:], r)
	}
	return out
}

// usVarChar encodes a US_VARCHAR (spec §2.3): 2B LE USHORTLEN (Unicode char
// count) + UCS-2 LE bytes.
func usVarChar(s string) []byte {
	codes := utf16.Encode([]rune(s))
	out := make([]byte, 2+len(codes)*2)
	binary.LittleEndian.PutUint16(out, uint16(len(codes)))
	for i, r := range codes {
		binary.LittleEndian.PutUint16(out[2+i*2:], r)
	}
	return out
}

// bVarByte encodes a B_VARBYTE: 1B length + raw bytes.
func bVarByte(b []byte) []byte {
	out := make([]byte, 1+len(b))
	if len(b) > 0xFF {
		copy(out[1:], b[:0xFF])
		out[0] = 0xFF
	} else {
		out[0] = byte(len(b))
		copy(out[1:], b)
	}
	return out
}

// usVarByte encodes a US_VARBYTE: 2B LE length + raw bytes.
func usVarByte(b []byte) []byte {
	out := make([]byte, 2+len(b))
	binary.LittleEndian.PutUint16(out, uint16(len(b)))
	copy(out[2:], b)
	return out
}

// obfuscatePassword applies the LOGIN7 password obfuscation (spec §3.2):
// each byte has its high/low nibbles swapped, then XORed with 0xA5.
func obfuscatePassword(pw string) []byte {
	raw := encodeUTF16(pw)
	out := make([]byte, len(raw))
	for i, b := range raw {
		// 显式括号：先交换高低 nibble，再异或 0xA5。
		// Go 中 | 与 ^ 同优先级（左结合），不加括号虽结果正确但易误读。
		out[i] = ((b << 4) | (b >> 4)) ^ 0xA5
	}
	return out
}
