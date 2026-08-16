// Package nfs implements the NFS (Network File System) protocol planner
// per RFC 7530 (NFSv4.0) / RFC 7531 (NFSv4.0 XDR) / RFC 1813 (NFSv3) /
// RFC 5531 (ONC RPC). The package provides XDR encoding for NFS/RPC
// messages, a Planner that generates per-RPC-call PacketConfig streams,
// and a parser for XDR decoding (used by the parser tests).
//
// All NFS messages are wrapped in ONC RPC (RFC 5531). On TCP, each RPC
// message is preceded by a 4-byte Record Mark (RM) with the high bit set
// (LAST_FRAGMENT) and the low 31 bits carrying the message length
// excluding the RM itself. On UDP, no RM is present.
//
// The Planner reads its configuration from core.FlowSpec.Metadata["nfs"]
// carrying an *NFSConfig. The Caller is responsible for setting this key
// before invoking the planner. The package also provides helpers for
// constructing FlowSpec values that target the NFS protocol.
package nfs

// --- Constants ---

// Default NFS TCP port (RFC 7530 §3 / RFC 1813 §11).
const DefaultPort = 2049

// Filehandle size limits (RFC 7531 §3, RFC 1813 §2.6).
const (
	NFS3FHSIZE = 64
	NFS4FHSIZE = 128
)

// NFSv3 filename length limit (RFC 1813 §2.6 NFS3_MAXNAMLEN).
const NFS3MaxNamelen = 255

// COMPOUND tag length limit (RFC 7530 §15).
const MaxCompoundTagLen = 1024

// Stateid.Other is always 12 bytes (RFC 7531 §3 stateid4).
const StateidOtherSize = 12

// writeverf3 is a fixed-length opaque[8] (RFC 1813 §2.6).
const WriteVerfSize = 8

// cookieverf3 / verifier4 are fixed-length opaque[8].
const CookieVerfSize = 8

// UDP datagram payload cap (65535 - 20 IP - 8 UDP).
const UDPMaxPayload = 65507

// DefaultMSS for TCP segmentation.
const DefaultMSS = 1460

// RPC program numbers (RFC 5531 / RFC 1813).
const (
	ProgramNFS   = 100003
	ProgramMount = 100005
	ProgramNLM   = 100021
)

// RPC procedure numbers.
const (
	RPCProcCall  = 0
	RPCProcReply = 1
)

// RPC message types (RFC 5531 §8).
const (
	RPCCall    = 0
	RPCReply   = 1
	RPCVersion = 2
)

// RPC reply states.
const (
	RPCMsgAccepted = 0
	RPCMsgDenied   = 1
)

// RPC accept states (RFC 5531 §8 — reply_state=MSG_ACCEPTED).
const (
	RPCSuccess      = 0
	RPCProgUnavail  = 1
	RPCProgMismatch = 2
	RPCProcUnavail  = 3
	RPCGarbageArgs  = 4
	RPCSystemErr    = 5
)

// RPC reject states (RFC 5531 §8 — reply_state=MSG_DENIED).
const (
	RPCMismatch  = 0
	RPCAuthError = 1
)

// auth_stat values (RFC 5531 §9.3).
const (
	AuthOK             = 0
	AuthBadCred        = 1
	AuthRejectedCred   = 2
	AuthBadVerf        = 3
	AuthRejectedVerf   = 4
	AuthTooWeak        = 5
	AuthInvalidResp    = 6
	AuthFailed         = 7
)

// Auth flavors (RFC 5531 §9).
const (
	AuthFlavorNone = 0
	AuthFlavorSys  = 1
	AuthFlavorShort = 2
	AuthFlavorGSS  = 6
)

// NFSv3 procedure numbers (RFC 1813 §3.2).
const (
	NFS3ProcNULL      = 0
	NFS3ProcGETATTR   = 1
	NFS3ProcSETATTR   = 2
	NFS3ProcLOOKUP    = 3
	NFS3ProcACCESS    = 4
	NFS3ProcREADLINK  = 5
	NFS3ProcREAD      = 6
	NFS3ProcWRITE     = 7
	NFS3ProcCREATE    = 8
	NFS3ProcMKDIR     = 9
	NFS3ProcSYMLINK   = 10
	NFS3ProcMKNOD     = 11
	NFS3ProcREMOVE    = 12
	NFS3ProcRMDIR     = 13
	NFS3ProcRENAME    = 14
	NFS3ProcLINK      = 15
	NFS3ProcREADDIR   = 16
	NFS3ProcREADDIRPLUS = 17
	NFS3ProcFSSTAT    = 18
	NFS3ProcFSINFO    = 19
	NFS3ProcPATHCONF  = 20
	NFS3ProcCOMMIT    = 21
)

// NFSv3 ftype3 values (RFC 1813 §2.5).
const (
	NF3REG  = 1
	NF3DIR  = 2
	NF3BLK  = 3
	NF3CHR  = 4
	NF3LNK  = 5
	NF3SOCK = 6
	NF3FIFO = 7
)

// NFSv3 time_how values (RFC 1813 §2.6 set_atime/set_mtime).
const (
	TimeHowDONT_CHANGE       = 0
	TimeHowSET_TO_SERVER_TIME = 1
	TimeHowSET_TO_CLIENT_TIME = 2
)

// NFSv3 stable_how values (RFC 1813 §3.3.7 WRITE3args).
const (
	StableUnstable = 0
	StableDataSync = 1
	StableFileSync = 2
)

// NFSv4 procedure numbers (RFC 7530 §18).
const (
	NFS4ProcNULL      = 0
	NFS4ProcCOMPOUND  = 1
	NFS4ProcCBCompound = 2
)

// NFSv4 opcodes (RFC 7531 §6.1 enum nfs_opnum4).
const (
	OP_ACCESS             = 3
	OP_CLOSE              = 4
	OP_COMMIT             = 5
	OP_CREATE             = 6
	OP_DELEGPURGE         = 7
	OP_DELEGRETURN        = 8
	OP_GETATTR            = 9
	OP_GETFH              = 10
	OP_LINK               = 11
	OP_LOCK               = 12
	OP_LOCKT              = 13
	OP_LOCKU              = 14
	OP_LOOKUP             = 15
	OP_LOOKUPP            = 16
	OP_NVERIFY            = 17
	OP_OPEN               = 18
	OP_OPENATTR           = 19
	OP_OPEN_CONFIRM       = 20
	OP_OPEN_DOWNGRADE     = 21
	OP_PUTFH              = 22
	OP_PUTPUBFH           = 23
	OP_PUTROOTFH          = 24
	OP_READ               = 25
	OP_READDIR            = 26
	OP_READLINK           = 27
	OP_REMOVE             = 28
	OP_RENAME             = 29
	OP_RENEW              = 30
	OP_RESTOREFH          = 31
	OP_SAVEFH             = 32
	OP_SECINFO            = 33
	OP_SETATTR            = 34
	OP_SETCLIENTID        = 35
	OP_SETCLIENTID_CONFIRM = 36
	OP_VERIFY             = 37
	OP_WRITE              = 38
	OP_RELEASE_LOCKOWNER  = 39
	// NFSv4.1+ opcodes (40-62) accepted at Validate but not used by auto-
	// completion logic.
	OP_WANT_DELEGATION     = 40 // NFSv4.1 (RFC 5661)
	OP_BIND_CONN_TO_SESSION = 41 // NFSv4.1
	OP_EXCHANGE_ID          = 42 // NFSv4.1
	OP_CREATE_SESSION       = 43 // NFSv4.1
	OP_DESTROY_SESSION      = 44 // NFSv4.1
	OP_FREE_STATEID         = 45 // NFSv4.1
	OP_GET_DIR_DELEGATION   = 46 // NFSv4.1
	OP_GETDEVICEINFO        = 47 // NFSv4.1 (pNFS)
	OP_GETDEVICELIST        = 48 // NFSv4.1 (pNFS)
	OP_LAYOUTCOMMIT         = 49 // NFSv4.1 (pNFS)
	OP_LAYOUTGET            = 50 // NFSv4.1 (pNFS)
	OP_LAYOUTRETURN         = 51 // NFSv4.1 (pNFS)
	OP_SECINFO_NO_NAME      = 52 // NFSv4.1
	OP_SEQUENCE             = 53 // NFSv4.1
	OP_SET_SSV              = 54 // NFSv4.1
	OP_TEST_STATEID         = 55 // NFSv4.1
	OP_WANT_DELEGATION_V4_2 = 56 // NFSv4.2
)

// NFSv4 opentype / createmode values (RFC 7531 §5.2 openflag4).
const (
	OpenTypeNOCREATE = 0
	OpenTypeCREATE   = 1

	CreatemodeUNCHECKED4 = 0
	CreatemodeGUARDED4   = 1
	CreatemodeEXCLUSIVE4 = 2
)

// NFSv4 claim type values (RFC 7531 §5.2 open_claim4).
const (
	ClaimNULL            = 0
	ClaimPREVIOUS        = 1
	ClaimDELEGATE_CUR    = 2
	ClaimDELEGATE_PREV   = 3
)

// NFSv4 share_access / share_deny values (RFC 7530 §16.17.2).
const (
	ShareAccessREAD  = 1
	ShareAccessWRITE = 2
	ShareAccessBOTH  = 3
)
const (
	ShareDenyNONE  = 0
	ShareDenyREAD  = 1
	ShareDenyWRITE = 2
	ShareDenyBOTH  = 3
)

// NFSv4 lock type values (RFC 7530 §16.10).
const (
	LockTypeREAD_LT  = 1
	LockTypeWRITE_LT = 2
	LockTypeREADW_LT = 3
)

// NFSv4 objtype (createtype4) values (RFC 7531 §5.4).
const (
	NF4REG         = 1
	NF4DIR         = 2
	NF4BLK         = 3
	NF4CHR         = 4
	NF4LNK         = 5
	NF4SOCK        = 6
	NF4FIFO        = 7
	NF4ATTRDIR     = 8
	NF4NAMEDATTR   = 9
)

// NFSv4 op status codes (subset; RFC 7530 §15.3 / RFC 7531 §3 enum nfsstat4).
const (
	NFS4OK                = 0
	NFS4ERR_PERM          = 1
	NFS4ERR_NOENT         = 2
	NFS4ERR_IO            = 5
	NFS4ERR_ACCESS        = 13
	NFS4ERR_EXIST         = 17
	NFS4ERR_XDEV          = 18
	NFS4ERR_NOTDIR        = 20
	NFS4ERR_ISDIR         = 21
	NFS4ERR_INVAL         = 22
	NFS4ERR_FBIG          = 27
	NFS4ERR_NOSPC         = 28
	NFS4ERR_ROFS          = 30
	NFS4ERR_MLINK         = 31
	NFS4ERR_NAMETOOLONG   = 63
	NFS4ERR_NOTEMPTY      = 66
	NFS4ERR_DQUOT         = 69
	NFS4ERR_STALE         = 70
	NFS4ERR_DELAY         = 10008
	NFS4ERR_RESOURCE      = 10018
	NFS4ERR_MOVED         = 10019
	NFS4ERR_NOFILEHANDLE  = 10020
	NFS4ERR_MINOR_VERS_MISMATCH = 10021
	NFS4ERR_STALE_CLIENTID = 10022
	NFS4ERR_STALE_STATEID = 10023
	NFS4ERR_OLD_STATEID   = 10024
	NFS4ERR_BAD_STATEID   = 10025
	NFS4ERR_BAD_SEQID     = 10026
	NFS4ERR_NOT_SAME      = 10027
	NFS4ERR_RESTOREFH     = 10030
	NFS4ERR_BAD_XDR       = 10036
	NFS4ERR_OP_ILLEGAL    = 10044
	NFS4ERR_BADHANDLE     = 10001
	NFS4ERR_BAD_COOKIE    = 10003
	NFS4ERR_EXPIRED       = 10011
)

// NFSv3 op status codes (RFC 1813 §2.7).
const (
	NFS3OK         = 0
	NFS3ERR_PERM   = 1
	NFS3ERR_NOENT  = 2
	NFS3ERR_IO     = 5
	NFS3ERR_NXIO   = 6
	NFS3ERR_ACCES  = 13
	NFS3ERR_EXIST  = 17
	NFS3ERR_XDEV   = 18
	NFS3ERR_NODEV  = 19
	NFS3ERR_NOTDIR = 20
	NFS3ERR_ISDIR  = 21
	NFS3ERR_INVAL  = 22
	NFS3ERR_FBIG   = 27
	NFS3ERR_NOSPC  = 28
	NFS3ERR_ROFS   = 30
	NFS3ERR_MLINK  = 31
	NFS3ERR_NAMETOOLONG = 63
	NFS3ERR_NOTEMPTY = 66
	NFS3ERR_DQUOT  = 69
	NFS3ERR_STALE  = 70
	NFS3ERR_BADHANDLE = 10001
	NFS3ERR_NOT_SYNC = 10002
	NFS3ERR_BAD_COOKIE = 10003
)

// --- Core types ---

// NFSConfig is the top-level NFS protocol configuration. It is passed to
// the Planner via core.FlowSpec.Metadata["nfs"].
type NFSConfig struct {
	Version     int    `json:"version"`               // 3 or 4 (required)
	Transport   string `json:"transport,omitempty"`   // "tcp" (default) or "udp" (v3 only)
	AuthFlavor  uint32 `json:"auth_flavor,omitempty"` // 0=auth_none, 1=auth_sys
	AuthSys     *AuthSysInfo `json:"auth_sys,omitempty"`
	XIDBase     uint32 `json:"xid_base,omitempty"`
	XIDIncr     int    `json:"xid_incr,omitempty"`
	Ops         []NFSOp `json:"ops"`
	Sessions    int    `json:"sessions,omitempty"`
	SessionsSrcPortBase uint16 `json:"sessions_src_port_base,omitempty"`
	SessionsSrcPortStep int    `json:"sessions_src_port_step,omitempty"`
	ResultStatus uint32 `json:"result_status,omitempty"`
	Direction   string `json:"direction,omitempty"`
	MountFilehandle []byte `json:"mount_filehandle,omitempty"`
	MinorVersion *uint32 `json:"minorversion,omitempty"`
}

// NFSOp describes one RPC round-trip (one CALL + one REPLY). For NFSv3
// each Op = one procedure call. For NFSv4 each Op = one COMPOUND carrying
// CompoundOps.
type NFSOp struct {
	// NFSv3 fields
	Program        uint32 `json:"program,omitempty"`
	ProgVersion    uint32 `json:"prog_version,omitempty"`
	Procedure      uint32 `json:"procedure,omitempty"`
	Filehandle     []byte `json:"filehandle,omitempty"`
	Filename       string `json:"filename,omitempty"`
	Oldname        string `json:"oldname,omitempty"`        // RENAME from.name
	Newname        string `json:"newname,omitempty"`        // RENAME to.name / LINK link.name
	Filehandle2    []byte `json:"filehandle2,omitempty"`    // RENAME to.dir fh
	LinkDirFh      []byte `json:"link_dirfh,omitempty"`     // LINK link.dir fh
	SymlinkTarget  string `json:"symlink_target,omitempty"` // SYMLINK symlink_data
	Ftype          uint32 `json:"ftype,omitempty"`          // MKNOD ftype3 discriminant
	Devdata        [8]byte `json:"devdata,omitempty"`       // MKNOD specdata3 (specdata1+specdata2)
	Attributes     *NFSAttributes `json:"attributes,omitempty"`
	Offset         uint64 `json:"offset,omitempty"`
	Count          uint32 `json:"count,omitempty"`
	Data           []byte `json:"data,omitempty"`
	StableHow      uint32 `json:"stable_how,omitempty"`
	Access         uint32 `json:"access,omitempty"`
	Cookie         uint64 `json:"cookie,omitempty"`
	CookieVerf     [8]byte `json:"cookie_verf,omitempty"`
	DirCount       uint32 `json:"dir_count,omitempty"`
	MaxCount       uint32 `json:"max_count,omitempty"`

	// NFSv4 COMPOUND fields
	CompoundOps []NFSv4CompoundOp `json:"compound_ops,omitempty"`
	Tag         string            `json:"tag,omitempty"`

	// NFSv3 MOUNT fields (Program=100005)
	DirPath string `json:"dirpath,omitempty"`

	// Per-op reply control
	ReplyStatus uint32 `json:"reply_status,omitempty"`

	// RPC layer error injection (pointer semantics: nil = success path)
	RPCAcceptState  *uint32 `json:"rpc_accept_state,omitempty"`
	RPCRejectState  *uint32 `json:"rpc_reject_state,omitempty"`
	RPCMismatchLow  *uint32 `json:"rpc_mismatch_low,omitempty"`
	RPCMismatchHigh *uint32 `json:"rpc_mismatch_high,omitempty"`
	AuthStat        *uint32 `json:"auth_stat,omitempty"`

	// OPEN reply stateid reference for subsequent op stateid substitution
	OpenReplyStateid *NFSStateid `json:"open_reply_stateid,omitempty"`
}

// NFSv4CompoundOp describes one operation inside a COMPOUND request.
type NFSv4CompoundOp struct {
	Opcode uint32 `json:"opcode"`

	Filehandle []byte      `json:"filehandle,omitempty"`
	Name       string      `json:"name,omitempty"`
	OpenStateid *NFSStateid `json:"open_stateid,omitempty"`
	Stateid    *NFSStateid `json:"stateid,omitempty"`
	Seqid      uint32      `json:"seqid,omitempty"`
	Clientid   uint64      `json:"clientid,omitempty"`
	Owner      *NFSLockOwner `json:"owner,omitempty"`
	Offset     uint64      `json:"offset,omitempty"`
	Count      uint32      `json:"count,omitempty"`
	Data       []byte      `json:"data,omitempty"`
	StableHow  uint32      `json:"stable_how,omitempty"`
	Access     uint32      `json:"access,omitempty"`
	AttrMask   []uint32    `json:"attr_mask,omitempty"`
	Attrs      *NFSAttributes `json:"attrs,omitempty"`
	Cookie     uint64      `json:"cookie,omitempty"`
	CookieVerf [8]byte     `json:"cookie_verf,omitempty"`
	Oldname    string      `json:"oldname,omitempty"`
	Newname    string      `json:"newname,omitempty"`
	ShareAccess uint32     `json:"share_access,omitempty"`
	ShareDeny   uint32     `json:"share_deny,omitempty"`
	LockType    uint32     `json:"lock_type,omitempty"`
	Reclaim     bool       `json:"reclaim,omitempty"`
	Length      uint64     `json:"length,omitempty"`

	// OPEN claim / openhow unions
	Claim   *NFSClaim   `json:"claim,omitempty"`
	OpenHow *NFSOpenHow `json:"openhow,omitempty"`

	// CREATE objtype
	ObjType uint32 `json:"objtype,omitempty"`

	// SETCLIENTID args
	Client         *NFSClientId `json:"client,omitempty"`
	Callback       *CBCallback  `json:"callback,omitempty"`
	CallbackIdent  uint32       `json:"callback_ident,omitempty"`

	// SETCLIENTID_CONFIRM verifier
	ClientidVerifier [8]byte `json:"clientid_verifier,omitempty"`

	// LOCK args
	NewLockOwner    bool             `json:"new_lock_owner,omitempty"`
	OpenToLockOwner *OpenToLockOwner `json:"open_to_lock_owner,omitempty"`
	LockOwner       *LockOwner       `json:"lock_owner,omitempty"`

	// per-op failure injection
	OpStatus *uint32 `json:"op_status,omitempty"`
}

// NFSClientId represents SETCLIENTID4args nfs_client_id4 (RFC 7531 §5.2).
type NFSClientId struct {
	Verifier [8]byte `json:"verifier"`
	Id       string  `json:"id"`
}

// CBCallback represents SETCLIENTID4args cb_client4 (RFC 7531 §5.2).
type CBCallback struct {
	Program uint32 `json:"program"`
	NetID   string `json:"netid"`
	Addr    string `json:"addr"`
}

// NFSClaim represents OPEN4args open_claim4 union (RFC 7531 §5.2).
type NFSClaim struct {
	Type           string      `json:"type"` // "null" / "previous" / "delegate_cur" / "delegate_prev"
	File           string      `json:"file,omitempty"`
	DelegateType   uint32      `json:"delegate_type,omitempty"`
	DelegateStateid *NFSStateid `json:"delegate_stateid,omitempty"`
}

// NFSOpenHow represents OPEN4args openflag4 union (RFC 7531 §5.2).
type NFSOpenHow struct {
	Type     string  `json:"type"` // "nocreate"/"unchecked"/"guarded"/"exclusive"
	Verifier [8]byte `json:"verifier,omitempty"`
}

// OpenToLockOwner represents LOCK4args open_to_lock_owner4 (RFC 7531 §5.5).
type OpenToLockOwner struct {
	OpenSeqid   uint32        `json:"open_seqid"`
	OpenStateid *NFSStateid   `json:"open_stateid"`
	LockSeqid   uint32        `json:"lock_seqid"`
	LockOwner   *NFSLockOwner `json:"lock_owner"`
}

// LockOwner represents LOCK4args lock_owner4 (RFC 7531 §5.5).
// lock_owner4 = clientid4 + state_owner4{seqid4, owner4} (RFC 7530
// §16.10.2). Pre-fix the seqid was missing, so tshark 3.6 read the
// lock_owner4 as a 16B stateid4 and consumed the owner bytes (t111
// frame 8 evidence).
type LockOwner struct {
	Clientid uint64 `json:"clientid"`
	Seqid    uint32 `json:"seqid"`
	Owner    []byte `json:"owner"`
}

// NFSStateid represents RFC 7531 §3 stateid4.
type NFSStateid struct {
	Seqid uint32   `json:"seqid"`
	Other [12]byte `json:"other"`
}

// NFSLockOwner represents open_owner4 / lock_owner4 owner field.
type NFSLockOwner struct {
	Clientid uint64 `json:"clientid"`
	Owner    []byte `json:"owner"`
}

// NFSAttributes represents NFSv3 sattr3 / NFSv4 fattr4 (subset) shared fields.
//
// AtimeSecs/AtimeNsecs/MtimeSecs/MtimeNsecs are *uint32 (pointer semantics)
// to distinguish three states:
//   nil            → not explicitly provided by user (used for "SET_TO_SERVER_TIME" time_how=1)
//   non-nil, value → explicitly provided (used for SET_TO_CLIENT_TIME time_how=2)
//
// Sentinel value 0xFFFFFFFF is also treated as SET_TO_SERVER_TIME (time_how=1).
type NFSAttributes struct {
	SetMode  bool   `json:"set_mode,omitempty"`
	Mode     uint32 `json:"mode,omitempty"`
	SetUid   bool   `json:"set_uid,omitempty"`
	Uid      uint32 `json:"uid,omitempty"`
	SetGid   bool   `json:"set_gid,omitempty"`
	Gid      uint32 `json:"gid,omitempty"`
	SetSize  bool   `json:"set_size,omitempty"`
	Size     uint64 `json:"size,omitempty"`
	SetAtime bool   `json:"set_atime,omitempty"`
	AtimeSecs  *uint32 `json:"atime_secs,omitempty"`
	AtimeNsecs *uint32 `json:"atime_nsecs,omitempty"`
	SetMtime bool   `json:"set_mtime,omitempty"`
	MtimeSecs  *uint32 `json:"mtime_secs,omitempty"`
	MtimeNsecs *uint32 `json:"mtime_nsecs,omitempty"`

	// SETATTR3 sattrguard3 (RFC 1813 §3.3.2)
	SattrGuardCheck       bool   `json:"sattr_guard_check,omitempty"`
	SattrGuardCtimeSecs   uint32 `json:"sattr_guard_ctime_secs,omitempty"`
	SattrGuardCtimeNsecs  uint32 `json:"sattr_guard_ctime_nsecs,omitempty"`
}

// AuthSysInfo represents RFC 5531 §9.2 auth_sys credentials.
type AuthSysInfo struct {
	Stamp       uint32   `json:"stamp,omitempty"`
	MachineName string   `json:"machine_name,omitempty"`
	UID         uint32   `json:"uid,omitempty"`
	GID         uint32   `json:"gid,omitempty"`
	Groups      []uint32 `json:"groups,omitempty"`
}

// EncodedRPCMessage represents a fully-encoded RPC message (call or reply)
// with its Record Mark prefix when TCP is used. For UDP the RecordMark
// field is left zero and the payload starts at XID.
type EncodedRPCMessage struct {
	RecordMark uint32 // 0 for UDP; for TCP: 0x80000000 | len(Payload)
	Payload    []byte // XID onward (XDR-encoded)
}

// IsTCP returns true when this message uses TCP transport.
func (e EncodedRPCMessage) IsTCP() bool { return e.RecordMark != 0 }
