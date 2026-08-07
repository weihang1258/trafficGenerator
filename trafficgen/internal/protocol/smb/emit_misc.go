// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// emit_misc.go: QUERY_DIRECTORY / QUERY_INFO / LOCK / IOCTL / FLUSH /
// ECHO / TREE_DISCONNECT / LOGOFF emitters.
package smb

import (
	"context"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// emitQueryDirectoryPDU emits QUERY_DIRECTORY request + response.
func emitQueryDirectoryPDU(
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
	fileName := op.FileName
	if fileName == "" {
		fileName = "*"
	}
	infoClass := op.InfoClass
	if infoClass == 0 {
		infoClass = 37
	}

	reqBody := buildQueryDirectoryRequestBody(session.fileID, infoClass, fileName, 4096)
	reqFlags := smbFlags(false, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "up", CmdQueryDirectory, 0,
		reqFlags, reqBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, false)
	// BUG #5 修复: messageID 在 response 发射后递增。

	var respStatus uint32 = StatusSuccess
	if errorResponse {
		respStatus = cfg.ErrorResponseStatus
	}
	respBody := buildQueryDirectoryResponseBody([]byte{})
	respFlags := smbFlags(true, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "down", CmdQueryDirectory, respStatus,
		respFlags, respBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, true)
	// response 发射后递增 messageID。
	session.messageID++
}

// emitQueryInfoPDU emits QUERY_INFO request + response.
func emitQueryInfoPDU(
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
	infoType := op.InfoType
	fileInfoClass := op.FileInfoClass
	if fileInfoClass == 0 {
		fileInfoClass = 4
	}
	reqBody := buildQueryInfoRequestBody(infoType, fileInfoClass, 40, 0, session.fileID, nil)
	reqFlags := smbFlags(false, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "up", CmdQueryInfo, 0,
		reqFlags, reqBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, false)
	// BUG #5 修复: messageID 在 response 发射后递增。

	var respStatus uint32 = StatusSuccess
	if errorResponse {
		respStatus = cfg.ErrorResponseStatus
	}
	respBody := buildQueryInfoResponseBody([]byte{})
	respFlags := smbFlags(true, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "down", CmdQueryInfo, respStatus,
		respFlags, respBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, true)
	// response 发射后递增 messageID。
	session.messageID++
}

// emitLockPDU emits LOCK request + response with a single EXCLUSIVE lock.
func emitLockPDU(
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
	flags := op.Flags
	if flags == 0 {
		flags = 0x02
	}
	length := op.Length
	if length == 0 {
		length = 4096
	}
	lockEl := buildLockElement(op.Offset, uint64(length), flags)
	reqBody := buildLockRequestBody(session.fileID, lockEl)
	reqFlags := smbFlags(false, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "up", CmdLock, 0,
		reqFlags, reqBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, false)
	// BUG #5 修复: messageID 在 response 发射后递增。

	var respStatus uint32 = StatusSuccess
	if errorResponse {
		respStatus = cfg.ErrorResponseStatus
	}
	respBody := buildLightweightBody()
	respFlags := smbFlags(true, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "down", CmdLock, respStatus,
		respFlags, respBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, true)
	// response 发射后递增 messageID。
	session.messageID++
}

// emitIOCTLPDU emits IOCTL request + response.
func emitIOCTLPDU(
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
	_ = op
	reqBody := buildIOCTLRequestBody(0x00060194, session.fileID, make([]byte, 8))
	reqFlags := smbFlags(false, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "up", CmdIOCTL, 0,
		reqFlags, reqBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, false)
	// BUG #5 修复: messageID 在 response 发射后递增。

	var respStatus uint32 = StatusSuccess
	if errorResponse {
		respStatus = cfg.ErrorResponseStatus
	}
	respBody := buildLightweightBody()
	respFlags := smbFlags(true, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "down", CmdIOCTL, respStatus,
		respFlags, respBody, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, true)
	// response 发射后递增 messageID。
	session.messageID++
}

// emitLightweightPDU emits ECHO request + response.
func emitLightweightPDU(
	ctx context.Context,
	spec core.FlowSpec,
	session *smbSessionState,
	cmd uint16,
	clientSeq, serverSeq *uint32,
	mss uint16,
	ttl uint8,
	now *time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
	flowID string,
	configChan chan<- core.PacketConfig,
	signingRequired bool,
) {
	body := buildLightweightBody()
	reqFlags := smbFlags(false, signingRequired)
	respFlags := smbFlags(true, signingRequired)
	emitSMB2PDU(ctx, spec, session, "up", cmd, 0,
		reqFlags, body, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, false)
	// BUG #5 修复: messageID 在 response 发射后递增。
	emitSMB2PDU(ctx, spec, session, "down", cmd, StatusSuccess,
		respFlags, body, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, true)
	// response 发射后递增 messageID。
	session.messageID++
}

// emitFlushPDU emits FLUSH request + response.
func emitFlushPDU(
	ctx context.Context,
	spec core.FlowSpec,
	session *smbSessionState,
	clientSeq, serverSeq *uint32,
	mss uint16,
	ttl uint8,
	now *time.Time,
	packetIndex *uint64,
	nextIPID func() uint16,
	flowID string,
	configChan chan<- core.PacketConfig,
	signingRequired bool,
) {
	body := buildFlushRequestBody(session.fileID)
	reqFlags := smbFlags(false, signingRequired)
	emitSMB2PDU(ctx, spec, session, "up", CmdFlush, 0,
		reqFlags, body, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, false)
	// BUG #5 修复: messageID 在 response 发射后递增。
	respFlags := smbFlags(true, signingRequired)
	emitSMB2PDU(ctx, spec, session, "down", CmdFlush, StatusSuccess,
		respFlags, buildLightweightBody(), true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, true)
	// response 发射后递增 messageID。
	session.messageID++
}

// emitTreeDisconnectPDU emits TREE_DISCONNECT request + response.
// errorResponse 非零时响应返回 cfg.ErrorResponseStatus（H-1 修复：
// ErrorOnCommand=tree_disconnect 时请求正常生成、响应返回错误）。
func emitTreeDisconnectPDU(
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
	body := buildLightweightBody()
	reqFlags := smbFlags(false, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "up", CmdTreeDisconnect, 0,
		reqFlags, body, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, false)
	// BUG #5 修复: messageID 在 response 发射后递增。
	var respStatus uint32 = StatusSuccess
	if errorResponse {
		respStatus = cfg.ErrorResponseStatus
	}
	respFlags := smbFlags(true, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "down", CmdTreeDisconnect, respStatus,
		respFlags, body, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, true)
	// response 发射后递增 messageID。
	session.messageID++
}

// emitLogoffPDU emits LOGOFF request + response.
// errorResponse 非零时，响应 Status 字段返回 cfg.ErrorResponseStatus（H-1 修复：
// ErrorOnCommand=logoff 时请求正常生成、响应返回错误后再 TCP teardown）。
func emitLogoffPDU(
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
	body := buildLightweightBody()
	reqFlags := smbFlags(false, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "up", CmdLogoff, 0,
		reqFlags, body, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, false)
	// BUG #5 修复: messageID 在 response 发射后递增。
	var respStatus uint32 = StatusSuccess
	if errorResponse {
		respStatus = cfg.ErrorResponseStatus
	}
	respFlags := smbFlags(true, cfg.SigningRequired)
	emitSMB2PDU(ctx, spec, session, "down", CmdLogoff, respStatus,
		respFlags, body, true, clientSeq, serverSeq, mss, ttl,
		now, packetIndex, nextIPID, flowID, configChan, true)
	// response 发射后递增 messageID。
	session.messageID++
}
