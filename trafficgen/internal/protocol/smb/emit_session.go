// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// emit_session.go: NEGOTIATE / SESSION_SETUP / TREE_CONNECT emitters.
package smb

import (
	"context"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// emitNegotiatePDU emits NEGOTIATE request + response.
func emitNegotiatePDU(
	ctx context.Context,
	spec core.FlowSpec,
	session *smbSessionState,
	cfg *SMBConfig,
	clientSeq, serverSeq *uint32,
	mss uint16,
	ttl uint8,
	now *time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
	flowID string,
	configChan chan<- core.PacketConfig,
	errorResponse bool,
) {
	dialects := make([]uint16, 0, len(cfg.Dialects))
	for _, d := range cfg.Dialects {
		if dv, err := parseDialect(d); err == nil {
			dialects = append(dialects, dv)
		}
	}

	preauth := cfg.PreauthIntegrityHashAlgorithms
	encAlgs := []uint16{cfg.EncryptionAlgorithm}

	reqBody := buildNegotiateRequestBody(dialects, cfg.SecurityMode,
		cfg.ClientCapabilities, cfg.ClientGuid, preauth, encAlgs)
	reqFlags := smbFlags(false, cfg.SigningRequired)

	var respStatus uint32 = StatusSuccess
	if errorResponse {
		respStatus = cfg.ErrorResponseStatus
	}

	emitSMB2PDU(ctx, spec, session, "up", CmdNegotiate, 0,
		reqFlags, reqBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, false)
	// BUG #5 修复 (CRITICAL, 二次修正): messageID 必须在 request 与 response 都
	// 发射完毕后递增。原修复仅在 request 后递增，导致 response 复用了已递增的
	// MessageId——违反 SMB2 规范（request/response 共用同一 MessageId，下一个
	// request 才递增到新值）。现已调整为 response 发射后递增。

	var respBody []byte
	if errorResponse {
		respBody = buildNegotiateErrorResponseBody()
	} else {
		respBody = buildNegotiateResponseBody(session.dialectRev, cfg.SecurityMode,
			cfg.ServerGuid, cfg.ServerCapabilities, cfg.MaxTransactSize,
			cfg.MaxReadSize, cfg.MaxWriteSize, buildGSSAPIBlob(cfg.AuthMechanism))
	}
	respFlags := smbFlags(true, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "down", CmdNegotiate, respStatus,
		respFlags, respBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, true)
	// response 发射后再递增 messageID，下一个 request 才使用新值。
	session.messageID++
}

// emitSessionSetupPDUs emits SESSION_SETUP request/response pairs.
func emitSessionSetupPDUs(
	ctx context.Context,
	spec core.FlowSpec,
	session *smbSessionState,
	cfg *SMBConfig,
	clientSeq, serverSeq *uint32,
	mss uint16,
	ttl uint8,
	now *time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
	flowID string,
	configChan chan<- core.PacketConfig,
	errorResponse bool,
) {
	for round := 0; round < cfg.AuthRounds; round++ {
		isLastRound := round == cfg.AuthRounds-1

		var secBlob []byte
		if len(cfg.SecurityBlob) > 0 {
			secBlob = cfg.SecurityBlob
		} else {
			switch cfg.AuthMechanism {
			case "ntlm":
				switch round {
				case 0:
					secBlob = buildNTLMSSPNegotiateBlob()
				case 1:
					secBlob = buildNTLMSSPAuthBlob()
				default:
					secBlob = []byte{}
				}
			case "kerberos":
				secBlob = buildGSSAPIBlob("kerberos")
			case "anonymous", "guest":
				secBlob = buildGSSAPIBlob(cfg.AuthMechanism)
			default:
				secBlob = buildGSSAPIBlob("ntlm")
			}
		}

		reqBody := buildSessionSetupRequestBody(0, uint8(cfg.SecurityMode), 0x01,
			0, secBlob, cfg.PreviousSessionId)
		reqFlags := smbFlags(false, cfg.SigningRequired)

		emitSMB2PDU(ctx, spec, session, "up", CmdSessionSetup, 0,
			reqFlags, reqBody, true, clientSeq, serverSeq, mss, ttl,
			now, packetIndex, nextIPID, flowID, configChan, false)
		// BUG #5 修复: messageID 在 response 发射后递增（request/response 共用）。

		if round == 0 {
			session.sessionID = nextSessionID()
		}

		var respStatus uint32 = StatusSuccess
		if errorResponse && isLastRound {
			respStatus = cfg.ErrorResponseStatus
		} else if !isLastRound && cfg.AuthMechanism == "ntlm" {
			respStatus = StatusMoreProcessingRequired
		}

		var respBody []byte
		if errorResponse && isLastRound {
			respBody = buildSessionSetupErrorResponseBody()
		} else {
			var respBlob []byte
			var sessionFlags uint16
			if cfg.EncryptionRequired {
				sessionFlags = 0x04 // EncryptData bit
			}
			if cfg.AuthMechanism == "ntlm" && !isLastRound {
				respBlob = buildNTLMSSPChallengeBlob()
			}
			respBody = buildSessionSetupResponseBody(sessionFlags, respBlob)
		}
		respFlags := smbFlags(true, cfg.SigningRequired)

		emitSMB2PDU(ctx, spec, session, "down", CmdSessionSetup, respStatus,
			respFlags, respBody, true, clientSeq, serverSeq, mss, ttl,
			now, packetIndex, nextIPID, flowID, configChan, true)
		// response 发射后递增 messageID，下一轮 request 才使用新值。
		session.messageID++
	}

	// H-3 修复: 认证完成后（SessionFlags.EncryptData 已协商），若
	// EncryptionRequired 且 dialect > SMB3.0，则后续信令 PDU 全部以
	// TRANSFORM_HEADER 包裹（设计 §3.27/S14）。NEGOTIATE 与 SESSION_SETUP
	// 自身不加密（S14 包序列中 SESSION_SETUP #1 为明文 SIGNED）。
	if cfg.EncryptionRequired && session.dialectRev > DialectSMB3_0 {
		session.encryptRequired = true
	}
}

// emitTreeConnectPDU emits TREE_CONNECT request + response.
func emitTreeConnectPDU(
	ctx context.Context,
	spec core.FlowSpec,
	session *smbSessionState,
	cfg *SMBConfig,
	clientSeq, serverSeq *uint32,
	mss uint16,
	ttl uint8,
	now *time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
	flowID string,
	configChan chan<- core.PacketConfig,
	errorResponse bool,
) {
	reqBody := buildTreeConnectRequestBody(cfg.TreeConnectShare)
	reqFlags := smbFlags(false, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "up", CmdTreeConnect, 0,
		reqFlags, reqBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, false)
	// BUG #5 修复: messageID 在 response 发射后递增。

	if !errorResponse {
		session.treeIDCounter++
		session.treeID = session.treeIDCounter
	}

	var respStatus uint32 = StatusSuccess
	if errorResponse {
		respStatus = cfg.ErrorResponseStatus
	}
	var respBody []byte
	if errorResponse {
		// Full 16B fixed part: dissect_smb2_error_response keeps parsing when
		// StructureSize != 9; the old 4-byte body was flagged malformed.
		respBody = buildTreeConnectErrorResponseBody()
	} else {
		respBody = buildTreeConnectResponseBody(cfg.ShareType, 0, 0, 0x001F1FFF)
	}
	respFlags := smbFlags(true, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "down", CmdTreeConnect, respStatus,
		respFlags, respBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, true)
	// response 发射后递增 messageID。
	session.messageID++
}
