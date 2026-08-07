// Package tftp implements the TFTP (Trivial File Transfer Protocol, RFC 1350)
// planner. TFTP runs over UDP: the client sends RRQ/WRQ to server port 69,
// and the server picks its own ephemeral TID port for the rest of the
// transfer. Both directions of the data plane share the same 4-tuple.
package tftp

// Opcode values per RFC 1350 §4 and RFC 2347 §2.
const (
	OpRRQ   uint16 = 1 // Read Request (读请求)
	OpWRQ   uint16 = 2 // Write Request (写请求)
	OpDATA  uint16 = 3 // Data block (数据块)
	OpACK   uint16 = 4 // Acknowledgment (确认)
	OpERROR uint16 = 5 // Error (错误)
	OpOACK  uint16 = 6 // Option Acknowledgment (选项确认, RFC 2347)
)

// Error codes per RFC 1350 §4 and RFC 2347 §2.
const (
	ErrNotDefined         uint8 = 0 // Not defined (未定义, 见 ErrMsg)
	ErrFileNotFound       uint8 = 1 // File not found (文件不存在)
	ErrAccessViolation    uint8 = 2 // Access violation (访问违规)
	ErrDiskFull           uint8 = 3 // Disk full or allocation exceeded (磁盘满)
	ErrIllegalOp          uint8 = 4 // Illegal TFTP operation (非法操作)
	ErrUnknownTID         uint8 = 5 // Unknown transfer ID (未知传输标识)
	ErrFileExists         uint8 = 6 // File already exists (文件已存在)
	ErrNoSuchUser         uint8 = 7 // No such user (无此用户)
	ErrOptNegotiation     uint8 = 8 // Failed to negotiate options (选项协商失败, RFC 2347)
)

// Default values per RFC 1350 / RFC 2348 / RFC 7440.
const (
	DefaultBlkSize    uint16 = 512   // RFC 1350 §4 default block size
	DefaultTimeout    uint8  = 5     // trafficgen default (RFC 1350 未规定)
	MinBlkSize        uint16 = 8     // RFC 2348 §2 minimum
	MaxBlkSize        uint16 = 65464 // RFC 2348 §2 maximum
	MinTimeout        uint8  = 1     // RFC 2349 §2 minimum
	MaxTimeout        uint8  = 255   // RFC 2349 §2 maximum
	MinWindowSize     uint16 = 1     // RFC 7440 §3 minimum
	MaxWindowSize     uint16 = 65535 // RFC 7440 §3 maximum
	MinEphemeralPort  uint16 = 1024  // exclude well-known ports
	MaxEphemeralPort  uint16 = 65535 // uint16 max
	MinDynamicPort    uint16 = 49152 // RFC 6335 dynamic port range lower
	MaxDynamicPort    uint16 = 65535 // RFC 6335 dynamic port range upper
	MaxFilenameBytes         = 255   // trafficgen limit (RFC 1350 未规定上限)
	MaxErrMsgBytes           = 255   // trafficgen limit (truncate)
	DefaultServerPort uint16 = 69    // RFC 1350 well-known TID
)

// defaultErrMsg maps ErrCode to the default ErrMsg per RFC 1350 / RFC 2347.
// Returns the ASCII string WITHOUT the trailing NUL byte; the builder appends it.
var defaultErrMsg = map[uint8]string{
	ErrNotDefined:     "Not defined",
	ErrFileNotFound:   "File not found",
	ErrAccessViolation: "Access violation",
	ErrDiskFull:       "Disk full or allocation exceeded",
	ErrIllegalOp:      "Illegal TFTP operation",
	ErrUnknownTID:     "Unknown transfer ID",
	ErrFileExists:     "File already exists",
	ErrNoSuchUser:     "No such user",
	ErrOptNegotiation: "Failed to negotiate options",
}

// DefaultErrMsg returns the default ErrMsg for the given ErrCode (RFC 1350 /
// RFC 2347). Returns "Not defined" for unknown codes (code 0 semantics).
func DefaultErrMsg(code uint8) string {
	if msg, ok := defaultErrMsg[code]; ok {
		return msg
	}
	return defaultErrMsg[ErrNotDefined]
}

// optionName maps the internal option index to the wire-format ASCII name
// (lowercase, RFC 2347/2348/2349/7440). The order matches the fixed output
// order: blksize → timeout → tsize → windowsize (§5.2).
var optionNames = []string{
	"blksize",
	"timeout",
	"tsize",
	"windowsize",
}

// optionIndex identifies an option's position in the fixed output order.
const (
	optBlkSize   = 0
	optTimeout   = 1
	optTSize     = 2
	optWindow    = 3
	numOptions   = 4
)
