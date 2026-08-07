package smb

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// SMBOperation 已上移至 core.SMBOperation（smb/types.go 通过类型别名引用）。

// SMB2/SMB3 Protocol Constants (MS-SMB2)

// SMB2 ProtocolId (协议标识符) = 0xFE534D42 ("\xFESMB" in ASCII).
const SMB2ProtocolID uint32 = 0xFE534D42

// TransformProtocolID (加密 Transform 协议标识符) = 0xFD534D42 ("FDSMB",
// MS-SMB2 §3.1.4.3). 加密 PDU 的 TRANSFORM_HEADER 头部使用该值替代 SMB2
// ProtocolId ("FDSMB": FD 53 4D 42).
const TransformProtocolID uint32 = 0xFD534D42

// SMB2 SYNC Header size (SMB2头大小) = 64 bytes (MS-SMB2 §2.2.1.2).
const HeaderSize = 64

// TRANSFORM_HEADER size (SMB3 加密头大小) = 52 bytes (MS-SMB2 §3.1.4.3).
const TransformHeaderSize = 52

// NBSS Session Service header size = 4 bytes.
const NBSSHeaderSize = 4

// NBSS Session Message type.
const NBSSSessionMessage = 0x00

// SMB2 Command codes (命令码, MS-SMB2 §2.2.1.2).
const (
	CmdNegotiate      uint16 = 0x0000
	CmdSessionSetup   uint16 = 0x0001
	CmdLogoff         uint16 = 0x0002
	CmdTreeConnect    uint16 = 0x0003
	CmdTreeDisconnect uint16 = 0x0004
	CmdCreate         uint16 = 0x0005
	CmdClose          uint16 = 0x0006
	CmdFlush          uint16 = 0x0007
	CmdRead           uint16 = 0x0008
	CmdWrite          uint16 = 0x0009
	CmdLock           uint16 = 0x000A
	CmdIOCTL          uint16 = 0x000B
	CmdCancel         uint16 = 0x000C
	CmdEcho           uint16 = 0x000D
	CmdQueryDirectory uint16 = 0x000E
	CmdChangeNotify   uint16 = 0x000F
	CmdQueryInfo      uint16 = 0x0010
	CmdSetInfo        uint16 = 0x0011
	CmdOplockBreak    uint16 = 0x0012
)

// SMB2 Flags (标志位, MS-SMB2 §2.2.1.2).
const (
	FlagServerToRedir uint32 = 0x00000001 // 响应方向
	FlagAsyncCommand  uint32 = 0x00000002 // 异步命令（本设计不使用）
	FlagRelatedOps    uint32 = 0x00000004 // 链式相关（本设计不使用）
	FlagSigned        uint32 = 0x00000008 // 已签名
)

// SMB2 Dialects (方言, MS-SMB2 §2.2.1).
const (
	DialectSMB2_002 uint16 = 0x0202
	DialectSMB2_1   uint16 = 0x0210
	DialectSMB3_0   uint16 = 0x0300
	DialectSMB3_02  uint16 = 0x0302
	DialectSMB3_11  uint16 = 0x0311
)

// SMB2 Global Capabilities (全局能力).
const (
	GlobalCapEncryption     uint32 = 0x00000001
	GlobalCapDirectoryLease uint32 = 0x00000002
	GlobalCapMultichannel   uint32 = 0x00000004
)

// SMB2 Negotiate Context Types (协商上下文类型).
const (
	NegotiateContextPreauth  uint16 = 0x0001
	NegotiateContextEncrypt  uint16 = 0x0002
	NegotiateContextCompress uint16 = 0x0003
)

// SMB2 Encryption Algorithms (加密算法, SMB3.1.1).
const (
	EncryptAESCCM uint16 = 0x0001
	EncryptAESGCM uint16 = 0x0002
)

// SMB2 Hash Algorithms (哈希算法, Preauth Integrity).
const (
	HashSHA512 uint16 = 0x0001
)

// NTSTATUS codes (NT状态码, MS-SMB2 §2.2.1.2 + §3.26).
const (
	StatusSuccess                uint32 = 0x00000000
	StatusMoreProcessingRequired uint32 = 0xC0000016
	StatusAccessDenied           uint32 = 0xC0000022
	StatusObjectNameNotFound     uint32 = 0xC0000034
	StatusObjectNameCollision    uint32 = 0xC0000035
	StatusInvalidParameter       uint32 = 0xC000000D
	StatusCancelled              uint32 = 0xC0000120
	StatusInvalidImageFormat     uint32 = 0xC000007B
	StatusBadNetworkName         uint32 = 0xC00000CC
	StatusLogonFailure           uint32 = 0xC000006D
	StatusEndOfFile              uint32 = 0xC0000020
	StatusFileLockConflict       uint32 = 0xC0000021
	StatusUserSessionDeleted     uint32 = 0xC00003E3
	StatusInvalidHandle          uint32 = 0xC0000080
)

// validDialects is the set of allowed SMB dialect hex strings.
var validDialects = map[string]bool{
	"0x0202": true,
	"0x0210": true,
	"0x0300": true,
	"0x0302": true,
	"0x0311": true,
}

// validAuthMechanisms lists the supported authentication mechanisms.
var validAuthMechanisms = map[string]bool{
	"ntlm":      true,
	"kerberos":  true,
	"anonymous": true,
	"guest":     true,
}

// validOpTypes lists the supported SMB operation types.
var validOpTypes = map[string]bool{
	"read":            true,
	"write":           true,
	"close":           true,
	"query_directory": true,
	"query_info":      true,
	"set_info":        true,
	"flush":           true,
	"echo":            true,
	"lock":            true,
	"ioctl":           true,
}

// validErrorOnCommands lists valid ErrorOnCommand values.
var validErrorOnCommands = map[string]bool{
	"negotiate":       true,
	"session_setup":   true,
	"tree_connect":    true,
	"create":          true,
	"read":            true,
	"write":           true,
	"close":           true,
	"tree_disconnect": true,
	"logoff":          true,
}

// knownStatusCodes is the set of 14 NT status codes from design §3.26.
var knownStatusCodes = map[uint32]bool{
	StatusSuccess:                true,
	StatusMoreProcessingRequired: true,
	StatusAccessDenied:           true,
	StatusObjectNameNotFound:     true,
	StatusObjectNameCollision:    true,
	StatusInvalidParameter:       true,
	StatusCancelled:              true,
	StatusInvalidImageFormat:     true,
	StatusBadNetworkName:         true,
	StatusLogonFailure:           true,
	StatusEndOfFile:              true,
	StatusFileLockConflict:       true,
	StatusUserSessionDeleted:     true,
	StatusInvalidHandle:          true,
}

// defaultDialects is the default dialect set (Windows 10 client typical).
var defaultDialects = []string{"0x0202", "0x0210", "0x0300", "0x0302", "0x0311"}

// commandNames maps command opcodes to readable names.
var commandNames = map[uint16]string{
	CmdNegotiate:      "negotiate",
	CmdSessionSetup:   "session_setup",
	CmdLogoff:         "logoff",
	CmdTreeConnect:    "tree_connect",
	CmdTreeDisconnect: "tree_disconnect",
	CmdCreate:         "create",
	CmdClose:          "close",
	CmdFlush:          "flush",
	CmdRead:           "read",
	CmdWrite:          "write",
	CmdLock:           "lock",
	CmdIOCTL:          "ioctl",
	CmdCancel:         "cancel",
	CmdEcho:           "echo",
	CmdQueryDirectory: "query_directory",
	CmdChangeNotify:   "change_notify",
	CmdQueryInfo:      "query_info",
	CmdSetInfo:        "set_info",
	CmdOplockBreak:    "oplock_break",
}

// parseDialect converts a dialect hex string to uint16.
func parseDialect(s string) (uint16, error) {
	switch strings.ToLower(s) {
	case "0x0202":
		return DialectSMB2_002, nil
	case "0x0210":
		return DialectSMB2_1, nil
	case "0x0300":
		return DialectSMB3_0, nil
	case "0x0302":
		return DialectSMB3_02, nil
	case "0x0311":
		return DialectSMB3_11, nil
	}
	return 0, fmt.Errorf("invalid dialect: %s", s)
}

// creditChargeFor returns CreditCharge per dialect (MS-SMB2 §2.2.1.2).
// SMB 2.0.2 MUST be reserved (0); SMB 2.1+ = 1.
func creditChargeFor(dialect uint16) uint16 {
	if dialect == DialectSMB2_002 {
		return 0
	}
	return 1
}

// smbFlags computes the SMB2 Flags field for a packet direction.
func smbFlags(isResponse, signed bool) uint32 {
	var f uint32
	if isResponse {
		f |= FlagServerToRedir
	}
	if signed {
		f |= FlagSigned
	}
	return f
}

// writeUint16LE writes a uint16 little-endian at the given offset in buf.
func writeUint16LE(buf []byte, off int, v uint16) {
	binary.LittleEndian.PutUint16(buf[off:off+2], v)
}

// writeUint32LE writes a uint32 little-endian at the given offset in buf.
func writeUint32LE(buf []byte, off int, v uint32) {
	binary.LittleEndian.PutUint32(buf[off:off+4], v)
}

// writeUint64LE writes a uint64 little-endian at the given offset in buf.
func writeUint64LE(buf []byte, off int, v uint64) {
	binary.LittleEndian.PutUint64(buf[off:off+8], v)
}

// writeBytes writes raw bytes at the given offset in buf (no length prefix).
func writeBytes(buf []byte, off int, b []byte) int {
	copy(buf[off:], b)
	return off + len(b)
}

// utf16LE encodes a UTF-8 string to UTF-16LE bytes.
func utf16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r > 0xFFFF {
			// Surrogate pair (should not happen for SMB path/file names).
			r1 := 0xD800 + ((r - 0x10000) >> 10)
			r2 := 0xDC00 + ((r - 0x10000) & 0x3FF)
			out = append(out, byte(r1), byte(r1>>8))
			out = append(out, byte(r2), byte(r2>>8))
		} else {
			out = append(out, byte(r), byte(r>>8))
		}
	}
	return out
}

// defaultAuthRounds returns the default AuthRounds for a mechanism.
// ntlm→3, kerberos→2, anonymous/guest→1.
func defaultAuthRounds(mechanism string) int {
	switch mechanism {
	case "ntlm":
		return 3
	case "kerberos":
		return 2
	case "anonymous", "guest":
		return 1
	}
	return 1
}
