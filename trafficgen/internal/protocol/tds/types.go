// Package tds implements the TDS (Tabular Data Stream, MS-TDS v20260617)
// protocol planner: the Microsoft SQL Server client-server wire format over
// TCP 1433.
//
// File types.go (this file) holds the configuration types per design doc
// 09-tds-design.md §5. The TDSConfig is serialized as JSON and carried in
// FlowSpec.Payload (mirrors the a2a pattern); the planner unmarshals it on
// Validate/Plan.
package tds

// DefaultPort is the TDS well-known TCP port (MS-TDS §1).
const DefaultPort = 1433

// TDSVersion 是 LOGIN7.TDSVersion (客户端→服务器) 与 LOGINACK.TDSVersion
// (服务器→客户端) 共用的 32 位版本常量。两个方向均以大端 (BE) 网络序写入
// 线路 (spec footnote 72: 表中两列均为 "network transfer format")。
// 客户端→服务器 7.4 wire = 04 00 00 74 (常量 0x04000074 的 BE 编码)；
// 服务器→客户端 7.4 wire = 74 00 00 04 (常量 0x74000004 的 BE 编码)。
// 两方向常量值不同但字节序一致 (均为 BE)。
type TDSVersion uint32

const (
	// TDSVersion71 is SQL Server 2000 (spec §1.2).
	TDSVersion71 TDSVersion = 0x00000071
	// TDSVersion72 is SQL Server 2005 (spec §1.2).
	TDSVersion72 TDSVersion = 0x02000972
	// TDSVersion73A is SQL Server 2008 (no NbcRow, no fSparseColumnSet).
	TDSVersion73A TDSVersion = 0x03000A73
	// TDSVersion73B is SQL Server 2008 R2 (NbcRow + sparse column set).
	TDSVersion73B TDSVersion = 0x03000B73
	// TDSVersion74 is SQL Server 2012+ and the design default.
	TDSVersion74 TDSVersion = 0x04000074
)

// RequestType is the kind of request a session can issue (spec §5).
type RequestType string

const (
	RequestSQLBatch  RequestType = "sql_batch"
	RequestRPC       RequestType = "rpc"
	RequestTransMgr  RequestType = "trans_mgr"
	RequestAttention RequestType = "attention"
)

// TDSConfig is the top-level TDS session configuration (design §5). One
// TDSConfig corresponds to one TDS flow (one TCP connection + PRELOGIN +
// LOGIN7 + sessions). Carried as JSON in FlowSpec.Payload.
type TDSConfig struct {
	Version      TDSVersion    `json:"version,omitempty"`      // default 7.4
	PacketSize   int           `json:"packet_size,omitempty"`  // default 4096; 512..32767
	EncryptMode  int           `json:"encrypt_mode,omitempty"` // 0=off 1=on 2=not_sup 3=req
	MarsEnabled  bool          `json:"mars,omitempty"`
	AppName      string        `json:"app_name,omitempty"`    // default "trafficgen"
	ServerName   string        `json:"server_name,omitempty"` // default "MSSQLServer"
	ClientName   string        `json:"client_name,omitempty"` // default "trafficgen-host"
	UserName     string        `json:"user_name,omitempty"`   // default "sa"
	Password     string        `json:"password,omitempty"`    // default "password"
	Database     string        `json:"database,omitempty"`
	Language     string        `json:"language,omitempty"`
	InterfaceLib string        `json:"interface_lib,omitempty"` // default "ODBC"
	ClientLCID   uint32        `json:"client_lcid,omitempty"`   // default 0x0409
	FeatureExts  []FeatureExt  `json:"feature_exts,omitempty"`
	Login        *LoginSpec    `json:"login,omitempty"`
	Sessions     []SessionSpec `json:"sessions,omitempty"`
}

// SessionSpec is one MARS session (a sequence of requests). When MARS is
// disabled, exactly one session is allowed.
type SessionSpec struct {
	ID            string        `json:"id"`
	TransactionID uint64        `json:"transaction_id,omitempty"`
	Requests      []RequestSpec `json:"requests"`
}

// RequestSpec is a single client→server request. Exactly one of
// Sql/Rpc/TransMgr must match Type; Type=attention ignores the rest.
type RequestSpec struct {
	Type     RequestType   `json:"type"`
	Sql      *SqlBatchSpec `json:"sql,omitempty"`
	Rpc      *RpcSpec      `json:"rpc,omitempty"`
	TransMgr *TransMgrSpec `json:"trans_mgr,omitempty"`
	Outcome  *OutcomeSpec  `json:"outcome,omitempty"`
}

// SqlBatchSpec holds one or more SQL statements (spec §3.3). Multiple
// statements produce multiple result sets separated by DONE_MORE.
type SqlBatchSpec struct {
	Statements []StatementSpec `json:"statements"`
}

// StatementSpec is one SQL statement within a batch.
type StatementSpec struct {
	Text           string `json:"text"`
	ExpectRows     int    `json:"expect_rows,omitempty"`
	ExpectDoneMore bool   `json:"expect_done_more,omitempty"`
}

// RpcSpec is an RPC request (spec §3.4). ProcName (long form, US_VARCHAR)
// and ProcID (short form, 0xFFFF + ProcID) are mutually exclusive.
type RpcSpec struct {
	ProcName   string      `json:"proc_name,omitempty"`
	ProcID     *uint16     `json:"proc_id,omitempty"`
	WithRecomp bool        `json:"with_recomp,omitempty"`
	NoMetaData bool        `json:"no_metadata,omitempty"`
	Params     []ParamSpec `json:"params,omitempty"`
}

// ParamSpec is one RPC parameter. StatusFlags encode ByRef (bit0) and
// DefaultValue (bit1); fEncrypted (bit3) is set implicitly when the param is
// marked encrypted (not yet supported by this planner — reserved).
type ParamSpec struct {
	Name         string  `json:"name,omitempty"`
	ByRef        bool    `json:"by_ref,omitempty"`
	DefaultValue bool    `json:"default_value,omitempty"`
	Type         string  `json:"type"`
	MaxLen       *int    `json:"max_len,omitempty"`
	Precision    *byte   `json:"precision,omitempty"`
	Scale        *byte   `json:"scale,omitempty"`
	Collation    string  `json:"collation,omitempty"`
	Value        *string `json:"value,omitempty"`
	IsNull       bool    `json:"null,omitempty"`
	Max          bool    `json:"max,omitempty"`
}

// TransMgrSpec is a Transaction Manager request (spec §3.5).
type TransMgrSpec struct {
	RequestType uint16 `json:"request_type"`
	Payload     string `json:"payload,omitempty"` // hex
}

// FeatureExt is one FeatureExt option (spec §3.2). Only stateless options
// are supported; Data is hex.
type FeatureExt struct {
	ID   uint8  `json:"id"`
	Data string `json:"data,omitempty"`
	// AckData 是服务器 FEATUREEXTACK 中对应 FeatureId 的回执数据 (hex)，
	// 如 SESSIONRECOVERY 的 SessionStateDataSet、FEDAUTH 的 Nonce+Signature、
	// COLUMNENCRYPTION 的版本等 (spec §3.14)。为空时回执数据长度为 0。
	AckData string `json:"ack_data,omitempty"`
}

// LoginSpec overrides LOGIN7 fixed fields for testing (design §5).
type LoginSpec struct {
	OptionFlags1    *byte             `json:"option_flags1,omitempty"`
	OptionFlags2    *byte             `json:"option_flags2,omitempty"`
	TypeFlags       *byte             `json:"type_flags,omitempty"`
	OptionFlags3    *byte             `json:"option_flags3,omitempty"`
	ClientTimeZone  int32             `json:"client_time_zone,omitempty"`
	OffsetOverrides map[string]string `json:"offset_overrides,omitempty"`
}

// OutcomeSpec asserts expected response behavior (design §9.3). The planner
// populates a Result from observed tokens and the test compares.
type OutcomeSpec struct {
	ExpectError     bool            `json:"expect_error,omitempty"`
	ErrorNumber     *int32          `json:"error_number,omitempty"`
	ErrorClass      *byte           `json:"error_class,omitempty"`
	ExpectInfoCount int             `json:"expect_info_count,omitempty"`
	ExpectEnvChange map[byte]string `json:"expect_env_change,omitempty"`
	ExpectTranID    bool            `json:"expect_tran_id,omitempty"`
	ExpectRows      int64           `json:"expect_rows,omitempty"`
}

// Result captures the parsed outcome of a single request, used by tests to
// assert the planner's response to server-simulated tokens. The planner
// fills this from the server response stream; OutcomeSpec fields are
// checked against it by the test harness.
type Result struct {
	ErrorTokens  []ErrorToken
	InfoCount    int
	EnvChanges   []EnvChangeToken
	LastRowCount int64
	GotTranID    bool
}

// ErrorToken is a parsed ERROR/INFO token payload (spec §3.11).
type ErrorToken struct {
	Number     int32
	State      byte
	Class      byte
	MsgText    string
	ServerName string
	ProcName   string
	LineNumber int64
	bytes      int // internal: total payload size on the wire (excl. token+len)
}

// EnvChangeToken is a parsed ENVCHANGE token (spec §3.10).
type EnvChangeToken struct {
	Type     byte
	NewValue []byte
	OldValue []byte
}

// MaxLoginLen is the LOGIN7 length cap (spec §3.2 / §10.2: ≤ 128K-1).
const MaxLoginLen = 128*1024 - 1

// MaxProcNameBytes is the RPC ProcName byte cap (spec §3.4 / §10.2).
const MaxProcNameBytes = 1046

// MaxLoginFieldChars is the per-field character cap for LOGIN7 string fields
// (HostName/UserName/Password/AppName/ServerName/CltIntName/Language/Database/
// ChangePassword). AtchDBFile has a separate 260-char cap (spec §3.2).
const MaxLoginFieldChars = 128

// MaxAtchDBFileChars is the AtchDBFile character cap (spec §3.2).
const MaxAtchDBFileChars = 260

// DefaultPacketSize is the LOGIN7 default PacketSize (spec §3.2).
const DefaultPacketSize = 4096
