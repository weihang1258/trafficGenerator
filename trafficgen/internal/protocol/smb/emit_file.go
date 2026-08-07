// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// emit_file.go: CREATE / READ / WRITE / CLOSE emitters.
package smb

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// emitCreatePDU emits CREATE request + response.
func emitCreatePDU(
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
	reqBody := buildCreateRequestBody(2, cfg.AccessMask, cfg.FileAttributes,
		uint32(cfg.ShareAccess), uint32(cfg.CreateDisposition), cfg.CreateOptions,
		cfg.FilePath)
	reqFlags := smbFlags(false, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "up", CmdCreate, 0,
		reqFlags, reqBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, false)
	// BUG #5 修复: messageID 在 response 发射后递增（request/response 共用）。

	var respStatus uint32 = StatusSuccess
	if errorResponse {
		respStatus = cfg.ErrorResponseStatus
	}
	var respBody []byte
	if errorResponse {
		// T140a: error response keeps StructureSize=89 (LE 0x59 0x00) + zeros
		respBody = make([]byte, 8)
		respBody[0] = 0x59
		respBody[1] = 0x00
	} else {
		respBody = buildCreateResponseBody(0, 1, session.fileID)
	}
	respFlags := smbFlags(true, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "down", CmdCreate, respStatus,
		respFlags, respBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, true)
	// response 发射后递增 messageID。
	session.messageID++
}

// emitReadPDU emits READ request + response.
func emitReadPDU(
	ctx context.Context,
	spec core.FlowSpec,
	session *smbSessionState,
	cfg *SMBConfig,
	op SMBOperation,
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
	fileID := session.fileID
	if op.FileId != ([16]byte{}) {
		fileID = op.FileId
	}

	reqBody := buildReadRequestBody(op.Length, op.Offset, fileID, op.MinimumCount)
	reqFlags := smbFlags(false, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "up", CmdRead, 0,
		reqFlags, reqBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, false)
	// BUG #5 修复: messageID 在 response 发射后递增。

	var respStatus uint32 = StatusSuccess
	if errorResponse {
		respStatus = cfg.ErrorResponseStatus
	}
	var respBody []byte
	if errorResponse {
		respBody = buildReadErrorResponseBody()
	} else {
		// BUG #16 修复 (CRITICAL): READ 响应必须携带实际读取的数据负载。
		// 原 buildReadResponseBody 仅返回 16 字节头部，DataLength 字段声明了长度
		// 但缺少对应的数据体，导致 Wireshark 解析时 EndOfSmb 报"missing data"。
		// 修复: 生成 op.Length 字节占位数据追加到响应体。
		respBody = buildReadResponseBody(op.Length, makeReadData(op.Length))
	}
	respFlags := smbFlags(true, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "down", CmdRead, respStatus,
		respFlags, respBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, true)
	// response 发射后递增 messageID。
	session.messageID++
}

// emitWritePDU emits WRITE request + response.
func emitWritePDU(
	ctx context.Context,
	spec core.FlowSpec,
	session *smbSessionState,
	cfg *SMBConfig,
	op SMBOperation,
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
	fileID := session.fileID
	if op.FileId != ([16]byte{}) {
		fileID = op.FileId
	}

	data := op.Data
	if len(data) == 0 && op.DataB64 != "" {
		if decoded, err := base64.StdEncoding.DecodeString(op.DataB64); err == nil {
			data = decoded
		}
	}

	reqBody := buildWriteRequestBody(uint32(len(data)), op.Offset, fileID, data, op.Flags)
	reqFlags := smbFlags(false, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "up", CmdWrite, 0,
		reqFlags, reqBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, false)
	// BUG #5 修复: messageID 在 response 发射后递增。

	var respStatus uint32 = StatusSuccess
	if errorResponse {
		respStatus = cfg.ErrorResponseStatus
	}
	var respBody []byte
	if errorResponse {
		respBody = buildWriteErrorResponseBody()
	} else {
		respBody = buildWriteResponseBody(uint32(len(data)))
	}
	respFlags := smbFlags(true, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "down", CmdWrite, respStatus,
		respFlags, respBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, true)
	// response 发射后递增 messageID。
	session.messageID++
}

// emitClosePDU emits CLOSE request + response.
func emitClosePDU(
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
	reqBody := buildCloseRequestBody(session.fileID)
	reqFlags := smbFlags(false, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "up", CmdClose, 0,
		reqFlags, reqBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, false)
	// BUG #5 修复: messageID 在 response 发射后递增。

	respStatus := StatusSuccess
	if errorResponse {
		respStatus = cfg.ErrorResponseStatus
	}
	respBody := buildCloseResponseBody()
	respFlags := smbFlags(true, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "down", CmdClose, respStatus,
		respFlags, respBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, true)
	// response 发射后递增 messageID。
	session.messageID++
}
