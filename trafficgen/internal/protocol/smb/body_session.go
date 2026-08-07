// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// body_session.go: SESSION_SETUP request/response body builders (§3.7-3.8).
package smb

import (
	"encoding/binary"
)

// buildSessionSetupRequestBody builds a SESSION_SETUP request body.
// flags = SMB2_SESSION_FLAG_BINDING (0x01) for SMB3 multichannel.
// securityMode = uint8 (bit0=SigningEnabled, bit1=SigningRequired).
// capabilities = uint32 (bit0=DFS).
// channel = uint32 (0=None, 1=RDMA).
// previousSessionId = uint64 (for reconnection).
func buildSessionSetupRequestBody(
	flags uint8,
	securityMode uint8,
	capabilities uint32,
	channel uint32,
	securityBlob []byte,
	previousSessionId uint64,
) []byte {
	body := make([]byte, 24)
	body[0] = 0x19 // StructureSize = 25 (0x0019 LE)
	body[1] = 0x00
	body[2] = flags
	body[3] = securityMode
	binary.LittleEndian.PutUint32(body[4:8], capabilities)
	binary.LittleEndian.PutUint32(body[8:12], channel)
	// SecurityBufferOffset from SMB2 header start = 64 + 24 = 88
	binary.LittleEndian.PutUint16(body[12:14], 88)
	binary.LittleEndian.PutUint16(body[14:16], uint16(len(securityBlob)))
	binary.LittleEndian.PutUint64(body[16:24], previousSessionId)
	body = append(body, securityBlob...)
	return body
}

// buildSessionSetupResponseBody builds a SESSION_SETUP response body.
func buildSessionSetupResponseBody(sessionFlags uint16, securityBlob []byte) []byte {
	body := make([]byte, 8)
	body[0] = 0x09 // StructureSize = 9 (0x0009 LE)
	body[1] = 0x00
	binary.LittleEndian.PutUint16(body[2:4], sessionFlags)
	// SecurityBufferOffset from SMB2 header start = 64 + 8 = 72
	binary.LittleEndian.PutUint16(body[4:6], 72)
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(securityBlob)))
	body = append(body, securityBlob...)
	return body
}

// buildSessionSetupErrorResponseBody builds an 8-byte SESSION_SETUP error
// response body (StructureSize=9 + SessionFlags=0 + Offset=0 + Length=0,
// see design §9.3).
func buildSessionSetupErrorResponseBody() []byte {
	body := make([]byte, 8)
	body[0] = 0x09 // StructureSize = 9 (0x0009 LE)
	body[1] = 0x00
	// SessionFlags=0, SecurityBufferOffset=0, SecurityBufferLength=0
	return body
}

// buildTreeConnectRequestBody builds a TREE_CONNECT request body.
// path = UNC path string (UTF-8); planner converts to UTF-16LE.
func buildTreeConnectRequestBody(path string) []byte {
	utf16Path := utf16LE(path)
	body := make([]byte, 8)
	body[0] = 0x09 // StructureSize = 9 (LE)
	body[1] = 0x00
	body[2] = 0x00 // Reserved
	body[3] = 0x00
	// PathOffset from SMB2 header start = 64 + 8 = 72
	binary.LittleEndian.PutUint16(body[4:6], 72)
	binary.LittleEndian.PutUint16(body[6:8], uint16(len(utf16Path)))
	body = append(body, utf16Path...)
	return body
}

// buildTreeConnectResponseBody builds a TREE_CONNECT response body.
func buildTreeConnectResponseBody(
	shareType uint8,
	shareFlags uint32,
	capabilities uint32,
	maximalAccess uint32,
) []byte {
	body := make([]byte, 16)
	body[0] = 0x10 // StructureSize = 16 (LE)
	body[1] = 0x00
	body[2] = shareType
	body[3] = 0x00 // Reserved
	binary.LittleEndian.PutUint32(body[4:8], shareFlags)
	binary.LittleEndian.PutUint32(body[8:12], capabilities)
	binary.LittleEndian.PutUint32(body[12:16], maximalAccess)
	return body
}
