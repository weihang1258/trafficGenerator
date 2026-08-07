// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// SMB (Server Message Block) is a session-level protocol where a single
// TCP connection (port 445 direct, or 139 over NetBIOS) carries the full
// session lifecycle: negotiate, authenticate, tree connect, file
// operations, and teardown. The planner emits:
//
//  1. TCP 3-way handshake (SYN, SYN-ACK, ACK).
//  2. SMB2 PDU sequence as PSH-ACK payloads:
//     a. NEGOTIATE (client→server request, server→client response).
//     b. SESSION_SETUP × AuthRounds (NTLM/Kerberos/anonymous/guest).
//     c. TREE_CONNECT (request, response with TreeId).
//     d. CREATE (request, response with FileId).
//     e. Operations[]: READ/WRITE/QUERY_DIRECTORY/QUERY_INFO/LOCK/IOCTL.
//     f. CLOSE (request, response).
//     g. TREE_DISCONNECT (request, response).
//     h. LOGOFF (request, response).
//  3. TCP 4-way teardown (FIN/FIN-ACK/ACK).
//
// Each SMB2 PDU is prefixed with a 4-byte NBSS (NetBIOS Session Service)
// header when Transport is "direct" (the default). Every PDU carries a
// 64-byte SMB2 SYNC header (ProtocolId, Command, Flags, MessageId,
// SessionId, TreeId, etc.) followed by a command-specific body.
package smb

import "github.com/trafficgen/trafficgen/internal/core"

// SMBConfig 已移至 core.SMBConfig（FlowSpec.SMB 挂载）。
// 本包通过 core.FlowSpec.SMB 读取配置；emit_*.go 中的 *SMBConfig 形参
// 统一改为 core.SMBConfig（同包别名 SMBConfig = core.SMBConfig 在下方声明）。

// SMBConfig 是 core.SMBConfig 的别名，供本包 emit_*.go / validate.go /
// smb_test.go 继续以裸名 SMBConfig 引用，避免大范围改名。
type SMBConfig = core.SMBConfig

// SMBOperation 是 core.SMBOperation 的别名（与 core/types.go 中的字段完全一致）。
type SMBOperation = core.SMBOperation
