// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// smb.go: Planner implementation. Reads SMBConfig from
// core.FlowSpec.SMB (core.FlowSpec.SMB *core.SMBConfig), runs
// the §4 state machine, and emits PacketConfig packets to the channel.
package smb

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// DefaultPort is the canonical SMB port (TCP 445).
const DefaultPort = 445

// DefaultNBSSPort is the NetBIOS Session Service port (TCP 139).
const DefaultNBSSPort = 139

// DefaultMSS is the default TCP MSS.
const DefaultMSS = 1460

// MinMSS per RFC 879.
const MinMSS = 536

// DefaultTTL is the default IP TTL.
const DefaultTTL = 64

// globalSessionID is the atomic counter for unique SessionId assignment
// across concurrent sessions (design §4.1).
var globalSessionID uint64 = 0

// Planner implements the SMB2/SMB3 protocol planner.
type Planner struct{}

// NewPlanner creates a new SMB planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "smb" }

// LookupSMBConfig extracts the SMBConfig from FlowSpec.SMB.
// 新代码通过 FlowSpec.SMB 直接挂载（core.FlowSpec.SMB *core.SMBConfig）。
func LookupSMBConfig(spec core.FlowSpec) (*SMBConfig, error) {
	if spec.SMB != nil {
		return spec.SMB, nil
	}
	return nil, fmt.Errorf("smb: spec.SMB is required")
}

// Validate validates an SMB flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	cfg, err := LookupSMBConfig(spec)
	if err != nil {
		return err
	}
	return ValidateConfig(cfg)
}

// nextSessionID returns the next unique SessionId (atomic).
func nextSessionID() uint64 {
	return atomic.AddUint64(&globalSessionID, 1)
}

// Plan generates packet configs for an SMB flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	cfg, err := LookupSMBConfig(spec)
	if err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("smb-%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		// Apply defaults to a working copy
		wcfg := applyDefaults(cfg)

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		synOpts := makeSynOptions(mss)

		now := time.Now()
		packetIndex := uint64(0)
		ipIDCounter := uint16(0)
		nextIPID := func() uint16 {
			id := ipIDCounter
			ipIDCounter++
			return id
		}

		clientSeq := randUint32()
		serverSeq := randUint32()

		// Session state (§4.1)
		session := &smbSessionState{
			messageID:     0,
			sessionID:     0,
			treeID:        0,
			fileID:        wcfg.FileId,
			creditBalance: 64,
		}

		// Resolve selected dialect into numeric
		dialectRev, _ := parseDialect(wcfg.SelectedDialect)
		session.dialectRev = dialectRev

		stopAfter := wcfg.ErrorOnCommand

		// TCP 3-way handshake
		emitTCPPacket(ctx, spec, "up", clientSeq, 0, 0x02, nil, synOpts, effectiveTTL,
			nextIPID(), &packetIndex, flowID, now, configChan)
		clientSeq++
		emitTCPPacket(ctx, spec, "down", serverSeq, clientSeq, 0x12, nil, synOpts, effectiveTTL,
			nextIPID(), &packetIndex, flowID, now, configChan)
		serverSeq++
		emitTCPPacket(ctx, spec, "up", clientSeq, serverSeq, 0x10, nil, nil, effectiveTTL,
			nextIPID(), &packetIndex, flowID, now, configChan)

		// NEGOTIATE
		negotiateErrored := false
		if boolPtr(wcfg.IncludeNegotiate, true) {
			if stopAfter == "negotiate" {
				negotiateErrored = true
				emitNegotiatePDU(ctx, spec, session, wcfg, &clientSeq, &serverSeq,
					mss, effectiveTTL, &now, &packetIndex, nextIPID,
					flowID, configChan, true)
			} else {
				emitNegotiatePDU(ctx, spec, session, wcfg, &clientSeq, &serverSeq,
					mss, effectiveTTL, &now, &packetIndex, nextIPID,
					flowID, configChan, false)
			}
		}

		// SESSION_SETUP
		authErrored := false
		if !negotiateErrored && boolPtr(wcfg.IncludeAuth, true) {
			if stopAfter == "session_setup" {
				authErrored = true
				emitSessionSetupPDUs(ctx, spec, session, wcfg, &clientSeq, &serverSeq,
					mss, effectiveTTL, &now, &packetIndex, nextIPID,
					flowID, configChan, true)
			} else {
				emitSessionSetupPDUs(ctx, spec, session, wcfg, &clientSeq, &serverSeq,
					mss, effectiveTTL, &now, &packetIndex, nextIPID,
					flowID, configChan, false)
			}
		}

		// TREE_CONNECT
		treeErrored := false
		tearDownFromError := false
		if !negotiateErrored && !authErrored && boolPtr(wcfg.IncludeTreeConnect, true) {
			if stopAfter == "tree_connect" {
				treeErrored = true
				emitTreeConnectPDU(ctx, spec, session, wcfg, &clientSeq, &serverSeq,
					mss, effectiveTTL, &now, &packetIndex, nextIPID,
					flowID, configChan, true)
			} else {
				emitTreeConnectPDU(ctx, spec, session, wcfg, &clientSeq, &serverSeq,
					mss, effectiveTTL, &now, &packetIndex, nextIPID,
					flowID, configChan, false)
			}
		}

		// CREATE + Operations
		createErrored := false
		if !negotiateErrored && !authErrored && !treeErrored {
			if stopAfter == "create" {
				createErrored = true
				tearDownFromError = true
				emitCreatePDU(ctx, spec, session, wcfg, &clientSeq, &serverSeq,
					mss, effectiveTTL, &now, &packetIndex, nextIPID,
					flowID, configChan, true)
			} else {
				emitCreatePDU(ctx, spec, session, wcfg, &clientSeq, &serverSeq,
					mss, effectiveTTL, &now, &packetIndex, nextIPID,
					flowID, configChan, false)

				// Operations loop
				opsErrored := false
				for _, op := range wcfg.Operations {
					opErrored := false
					switch op.OpType {
					case "read":
						if stopAfter == "read" {
							opErrored = true
							opsErrored = true
							tearDownFromError = true
							emitReadPDU(ctx, spec, session, wcfg, op, &clientSeq, &serverSeq,
								mss, effectiveTTL, &now, &packetIndex, nextIPID,
								flowID, configChan, true)
						} else {
							emitReadPDU(ctx, spec, session, wcfg, op, &clientSeq, &serverSeq,
								mss, effectiveTTL, &now, &packetIndex, nextIPID,
								flowID, configChan, false)
						}
					case "write":
						if stopAfter == "write" {
							opErrored = true
							opsErrored = true
							tearDownFromError = true
							emitWritePDU(ctx, spec, session, wcfg, op, &clientSeq, &serverSeq,
								mss, effectiveTTL, &now, &packetIndex, nextIPID,
								flowID, configChan, true)
						} else {
							emitWritePDU(ctx, spec, session, wcfg, op, &clientSeq, &serverSeq,
								mss, effectiveTTL, &now, &packetIndex, nextIPID,
								flowID, configChan, false)
						}
					case "close":
						if stopAfter == "close" {
							opErrored = true
							opsErrored = true
							tearDownFromError = true
							emitClosePDU(ctx, spec, session, wcfg, &clientSeq, &serverSeq,
								mss, effectiveTTL, &now, &packetIndex, nextIPID,
								flowID, configChan, true)
						} else {
							emitClosePDU(ctx, spec, session, wcfg, &clientSeq, &serverSeq,
								mss, effectiveTTL, &now, &packetIndex, nextIPID,
								flowID, configChan, false)
						}
					case "query_directory":
						emitQueryDirectoryPDU(ctx, spec, session, wcfg, op, &clientSeq, &serverSeq,
							mss, effectiveTTL, &now, &packetIndex, nextIPID,
							flowID, configChan, false)
					case "query_info":
						emitQueryInfoPDU(ctx, spec, session, wcfg, op, &clientSeq, &serverSeq,
							mss, effectiveTTL, &now, &packetIndex, nextIPID,
							flowID, configChan, false)
					case "lock":
						emitLockPDU(ctx, spec, session, wcfg, op, &clientSeq, &serverSeq,
							mss, effectiveTTL, &now, &packetIndex, nextIPID,
							flowID, configChan, false)
					case "ioctl":
						emitIOCTLPDU(ctx, spec, session, wcfg, op, &clientSeq, &serverSeq,
							mss, effectiveTTL, &now, &packetIndex, nextIPID,
							flowID, configChan, false)
					case "echo":
						emitLightweightPDU(ctx, spec, session, CmdEcho, &clientSeq, &serverSeq,
							mss, effectiveTTL, &now, &packetIndex, nextIPID,
							flowID, configChan, wcfg.SigningRequired)
					case "flush":
						emitFlushPDU(ctx, spec, session, &clientSeq, &serverSeq,
							mss, effectiveTTL, &now, &packetIndex, nextIPID,
							flowID, configChan, wcfg.SigningRequired)
					}
					// §4.2: 错误注入后跳过后续依赖该命令的操作（如 READ 错误后跳过
					// 后续 READ/WRITE），仅保留拆解命令（CLOSE/TREE_DISCONNECT/LOGOFF）。
					if opErrored {
						break
					}
				}

				// §4 state machine: CLOSE is mandatory teardown after Operations,
				// unless CLOSE was already emitted as the errored command.
				closeAlreadyEmitted := opsErrored && stopAfter == "close"
				if !closeAlreadyEmitted {
					emitClosePDU(ctx, spec, session, wcfg, &clientSeq, &serverSeq,
						mss, effectiveTTL, &now, &packetIndex, nextIPID,
						flowID, configChan, false)
				}
			}
		}

		// Teardown
		if boolPtr(wcfg.IncludeTeardown, true) && !negotiateErrored {
			// Skip TREE_DISCONNECT for tree_connect / session_setup errors
			// (no TreeId assigned; see design §4.2 skip rule table).
			if !treeErrored && !authErrored {
				// H-1 修复: ErrorOnCommand=tree_disconnect 时 TREE_DISCONNECT 的
				// 请求正常生成、响应返回错误 (ErrorResponseStatus)，之后仍执行 LOGOFF
				// （§4.2 跳过规则表: tree_disconnect 保留 LOGOFF）。
				treeDiscErr := stopAfter == "tree_disconnect"
				emitTreeDisconnectPDU(ctx, spec, session, wcfg, &clientSeq, &serverSeq,
					mss, effectiveTTL, &now, &packetIndex, nextIPID,
					flowID, configChan, treeDiscErr)
			}
			// H-1 修复: ErrorOnCommand=logoff 时 LOGOFF 请求正常生成、响应返回
			// 错误 (ErrorResponseStatus)，之后直接 TCP teardown（§4.2 跳过规则表）。
			logoffErr := stopAfter == "logoff"
			emitLogoffPDU(ctx, spec, session, wcfg, &clientSeq, &serverSeq,
				mss, effectiveTTL, &now, &packetIndex, nextIPID,
				flowID, configChan, logoffErr)
		}
		_ = createErrored
		_ = tearDownFromError

		// TCP teardown
		emitTCPPacket(ctx, spec, "up", clientSeq, serverSeq, 0x11, nil, nil, effectiveTTL,
			nextIPID(), &packetIndex, flowID, now, configChan)
		clientSeq++
		emitTCPPacket(ctx, spec, "down", serverSeq, clientSeq, 0x11, nil, nil, effectiveTTL,
			nextIPID(), &packetIndex, flowID, now, configChan)
		serverSeq++
		emitTCPPacket(ctx, spec, "up", clientSeq, serverSeq, 0x10, nil, nil, effectiveTTL,
			nextIPID(), &packetIndex, flowID, now, configChan)
	}()

	return configChan, nil
}

// smbSessionState tracks per-session mutable state used by the planner.
type smbSessionState struct {
	messageID     uint64
	sessionID     uint64
	treeID        uint32
	treeIDCounter uint32 // 会话内 TreeId 递增计数器，从 1 开始
	fileID        [16]byte
	creditBalance uint16
	dialectRev    uint16
	// encryptRequired 置为 true 后，后续信令 PDU 用 TRANSFORM_HEADER(52B) 包裹
	// （设计 §3.27/S14）。SESSION_SETUP 认证完成后按 EncryptionRequired 设置。
	encryptRequired bool
}
