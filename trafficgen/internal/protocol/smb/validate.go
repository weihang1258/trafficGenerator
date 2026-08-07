// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// validate.go: Validate function for SMBConfig (§8) and ApplyDefaults.
package smb

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ValidateConfig validates an SMBConfig against design §8 rules V1-V37.
func ValidateConfig(s *SMBConfig) error {
	if s == nil {
		return fmt.Errorf("smb: SMBConfig is required")
	}

	// V35: Transport must be "direct" or "netbios"
	if s.Transport != "" && s.Transport != "direct" && s.Transport != "netbios" {
		return fmt.Errorf("smb: Transport must be direct or netbios")
	}

	// V1: Dialects in allowed list (and V2: no SMB1 strings)
	for _, d := range s.Dialects {
		if !validDialects[d] {
			// V2: check SMB1 string
			if strings.Contains(strings.ToLower(d), "nt lm 0.12") {
				return fmt.Errorf("smb: SMB1 dialect string not supported, must use 0x0202+ numeric")
			}
			return fmt.Errorf("smb: dialect %s not in allowed list (MS-SMB2 §3.2.1)", d)
		}
	}

	// V3: SelectedDialect must be in Dialects (when both set)
	if s.SelectedDialect != "" {
		checkList := s.Dialects
		if len(checkList) == 0 {
			checkList = defaultDialects
		}
		found := false
		for _, d := range checkList {
			if d == s.SelectedDialect {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("smb: SelectedDialect must be in Dialects list")
		}
	}

	// V11: AuthMechanism
	if s.AuthMechanism != "" && !validAuthMechanisms[s.AuthMechanism] {
		return fmt.Errorf("smb: auth_mechanism must be ntlm/kerberos/anonymous/guest")
	}

	// V12-V16: AuthRounds (0 = default)
	if s.AuthRounds != 0 {
		if s.AuthRounds < 1 || s.AuthRounds > 3 {
			return fmt.Errorf("smb: AuthRounds must be 1-3 (0 for default)")
		}
		mechanism := s.AuthMechanism
		if mechanism == "" {
			mechanism = "ntlm"
		}
		switch mechanism {
		case "ntlm":
			if s.AuthRounds != 2 && s.AuthRounds != 3 {
				return fmt.Errorf("smb: ntlm auth can only be 2 or 3 rounds")
			}
		case "kerberos":
			if s.AuthRounds != 2 {
				return fmt.Errorf("smb: kerberos auth can only be 2 rounds")
			}
		case "anonymous", "guest":
			if s.AuthRounds != 1 {
				return fmt.Errorf("smb: %s auth can only be 1 round", mechanism)
			}
		}
	}

	// V18: TreeConnectShare UNC path
	if s.TreeConnectShare != "" {
		if !strings.HasPrefix(s.TreeConnectShare, "\\\\") ||
			!strings.Contains(s.TreeConnectShare[2:], "\\") {
			return fmt.Errorf("smb: TreeConnectShare must be UNC path \\\\server\\share")
		}
	}

	// V19: ShareType
	if s.ShareType > 2 {
		return fmt.Errorf("smb: ShareType must be 0(DISK)/1(PIPE)/2(PRINT)")
	}

	// V21: CreateDisposition
	if s.CreateDisposition > 5 {
		return fmt.Errorf("smb: CreateDisposition must be 0-5")
	}

	// V23: Operations OpType
	for _, op := range s.Operations {
		if !validOpTypes[op.OpType] {
			return fmt.Errorf("smb: OpType must be read/write/close/query_directory/query_info/set_info/flush/echo/lock/ioctl")
		}
		// V26: WRITE Data+DataB64 mutually exclusive
		if op.OpType == "write" {
			if len(op.Data) > 0 && op.DataB64 != "" {
				return fmt.Errorf("smb: Data and DataB64 cannot both be set")
			}
			if op.DataB64 != "" {
				if _, err := base64.StdEncoding.DecodeString(op.DataB64); err != nil {
					return fmt.Errorf("smb: DataB64 must be valid base64")
				}
			}
		}
	}

	// V28: ErrorOnCommand
	if s.ErrorOnCommand != "" && !validErrorOnCommands[s.ErrorOnCommand] {
		return fmt.Errorf("smb: ErrorOnCommand must be negotiate/session_setup/tree_connect/create/read/write/close/tree_disconnect/logoff")
	}

	// V29-V31: ErrorResponseStatus/ErrorOnCommand consistency
	if s.ErrorResponseStatus != 0 {
		if s.ErrorOnCommand == "" {
			return fmt.Errorf("smb: ErrorOnCommand must be set when ErrorResponseStatus is non-zero")
		}
		if !knownStatusCodes[s.ErrorResponseStatus] {
			return fmt.Errorf("smb: ErrorResponseStatus must be a known NT status code")
		}
	}
	if s.ErrorOnCommand != "" && s.ErrorResponseStatus == 0 {
		return fmt.Errorf("smb: ErrorResponseStatus must be non-zero when ErrorOnCommand is set")
	}

	// V32-V34: Size limits
	if s.MaxTransactSize > 16777215 {
		return fmt.Errorf("smb: MaxTransactSize exceeds NBSS limit (16777215)")
	}
	if s.MaxReadSize > 16777215 {
		return fmt.Errorf("smb: MaxReadSize exceeds NBSS limit (16777215)")
	}
	if s.MaxWriteSize > 16777215 {
		return fmt.Errorf("smb: MaxWriteSize exceeds NBSS limit (16777215)")
	}

	// V36: EncryptionAlgorithm
	if s.EncryptionAlgorithm != 0 {
		if s.EncryptionAlgorithm != EncryptAESCCM && s.EncryptionAlgorithm != EncryptAESGCM {
			return fmt.Errorf("smb: EncryptionAlgorithm must be 0x0001(AES-CCM) or 0x0002(AES-GCM)")
		}
	}

	// V37: EncryptionRequired needs SMB3.0+
	if s.EncryptionRequired {
		found := false
		for _, d := range s.Dialects {
			dv, err := parseDialect(d)
			if err == nil && dv >= DialectSMB3_0 {
				found = true
				break
			}
		}
		if !found && len(s.Dialects) > 0 {
			return fmt.Errorf("smb: EncryptionRequired requires SMB3.0+ dialect")
		}
	}

	// V10: PreauthIntegrityHashAlgorithms only SHA-512
	for _, a := range s.PreauthIntegrityHashAlgorithms {
		if a != HashSHA512 {
			return fmt.Errorf("smb: PreauthIntegrityHashAlgorithms only supports 0x0001 (SHA-512)")
		}
	}

	return nil
}

// applyDefaults returns a copy of s with design §5.2 defaults applied.
func applyDefaults(s *SMBConfig) *SMBConfig {
	if s == nil {
		s = &SMBConfig{}
	}
	cfg := *s // value copy

	// Dialects (V4)
	if len(cfg.Dialects) == 0 {
		cfg.Dialects = append([]string{}, defaultDialects...)
	}
	// SelectedDialect
	if cfg.SelectedDialect == "" {
		cfg.SelectedDialect = cfg.Dialects[len(cfg.Dialects)-1]
	}

	// GUIDs
	var zeroGUID [16]byte
	if cfg.ClientGuid == zeroGUID {
		_, _ = rand.Read(cfg.ClientGuid[:])
	}
	if cfg.ServerGuid == zeroGUID {
		_, _ = rand.Read(cfg.ServerGuid[:])
	}

	// SecurityMode
	if cfg.SecurityMode == 0 {
		cfg.SecurityMode = 0x01
	}
	if cfg.SigningRequired {
		cfg.SecurityMode |= 0x02
	}

	// ClientCapabilities with dialect adjustment (M-7)
	if cfg.ClientCapabilities == 0 {
		cfg.ClientCapabilities = GlobalCapEncryption | GlobalCapDirectoryLease
	}
	dialectRev, _ := parseDialect(cfg.SelectedDialect)
	if dialectRev < DialectSMB3_0 {
		cfg.ClientCapabilities &^= GlobalCapEncryption // clear bit0
	}

	// AuthMechanism + AuthRounds (V12-V16)
	if cfg.AuthMechanism == "" {
		cfg.AuthMechanism = "ntlm"
	}
	if cfg.AuthRounds == 0 {
		cfg.AuthRounds = defaultAuthRounds(cfg.AuthMechanism)
	}

	// TreeConnectShare
	if cfg.TreeConnectShare == "" {
		cfg.TreeConnectShare = "\\\\server\\share"
	}
	// V20: IPC$ auto sets ShareType
	if strings.Contains(cfg.TreeConnectShare, "IPC$") {
		cfg.ShareType = 1
	}

	// M-1 修复: CreateDisposition=0 (supersede) 是合法值, AccessMask=0 /
	// ShareAccess=0 也是合法值。JSON 解码丢失 presence 信息后无法区分
	// "未设置" 与 "显式 0", 此处采用启发式: 当用户在 create 阶段显式提供过
	// 任何字段 (AccessMask/FileAttributes/ShareAccess/CreateDisposition/
	// CreateOptions/FilePath 任一非零或非空) 时, 认为这是显式配置, 保留
	// 显式 0 透传; 仅当整个 create 段全为零 (纯空配置) 时才套用 §5.2 默认值。
	// 注意: createStageSet 必须在 FilePath 默认值应用之前计算, 否则空配置
	// 的 FilePath 被默认填 "file.txt" 后误判为显式配置。
	createStageSet := cfg.CreateOptions != 0 ||
		cfg.AccessMask != 0 ||
		cfg.FileAttributes != 0 ||
		cfg.ShareAccess != 0 ||
		cfg.CreateDisposition != 0 ||
		cfg.FilePath != ""
	if cfg.CreateDisposition == 0 && !createStageSet {
		cfg.CreateDisposition = 1
	}
	if cfg.AccessMask == 0 && !createStageSet {
		cfg.AccessMask = 0x00120089
	}
	if cfg.FileAttributes == 0 && !createStageSet {
		cfg.FileAttributes = 0x80
	}
	if cfg.ShareAccess == 0 && !createStageSet {
		cfg.ShareAccess = 0x07
	}

	// FilePath
	if cfg.FilePath == "" {
		cfg.FilePath = "file.txt"
	}
	if cfg.MaxTransactSize == 0 {
		cfg.MaxTransactSize = 65536
	}
	if cfg.MaxReadSize == 0 {
		cfg.MaxReadSize = 1048576
	}
	if cfg.MaxWriteSize == 0 {
		cfg.MaxWriteSize = 1048576
	}
	if cfg.EncryptionAlgorithm == 0 {
		cfg.EncryptionAlgorithm = EncryptAESCCM
	}
	if len(cfg.PreauthIntegrityHashAlgorithms) == 0 {
		cfg.PreauthIntegrityHashAlgorithms = []uint16{HashSHA512}
	}

	// Include flags
	if cfg.IncludeNegotiate == nil {
		b := true
		cfg.IncludeNegotiate = &b
	}
	if cfg.IncludeAuth == nil {
		b := true
		cfg.IncludeAuth = &b
	}
	if cfg.IncludeTreeConnect == nil {
		b := true
		cfg.IncludeTreeConnect = &b
	}
	if cfg.IncludeTeardown == nil {
		b := true
		cfg.IncludeTeardown = &b
	}

	// Operations (V24)
	if len(cfg.Operations) == 0 {
		cfg.Operations = []SMBOperation{{OpType: "read", Offset: 0, Length: 4096}}
	}

	// FileId
	if cfg.FileId == zeroGUID {
		_, _ = rand.Read(cfg.FileId[:])
	}

	return &cfg
}

// boolPtr dereferences a *bool with a default.
func boolPtr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// randUint32 generates a random uint32.
func randUint32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// makeSynOptions builds a minimal TCP SYN options block (MSS + NOP + WScale
// + NOP + NOP + SACK-Permitted).
func makeSynOptions(mss uint16) []core.TCPOption {
	// MSS (Kind=2, Len=4, 2-byte value)
	mssOpt := core.TCPOption{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss & 0xFF)}}
	// Window Scale (Kind=3, Len=3, 1-byte value 7)
	wscaleOpt := core.TCPOption{Kind: core.TCPOptWinScale, Data: []byte{0x07}}
	// SACK-Permitted (Kind=4, Len=2, no data)
	sackOpt := core.TCPOption{Kind: core.TCPOptSACKPermit}
	// NOP (Kind=1) 作为分隔/填充
	nopOpt := core.TCPOption{Kind: core.TCPOptNOP}
	return []core.TCPOption{mssOpt, nopOpt, wscaleOpt, nopOpt, nopOpt, sackOpt}
}
