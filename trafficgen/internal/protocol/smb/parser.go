// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// parser.go: SMB2 SYNC Header parser and command body parsers.
// The parser functions verify byte-level correctness of PDU payloads
// produced by the planner / builder. They are intended for round-trip
// tests and field-by-field assertions (T196-T225 in the design).
package smb

import (
	"encoding/binary"
	"fmt"
)

// ParsedPDU is the result of parsing a single SMB2 PDU.
type ParsedPDU struct {
	// NBSS length (4-byte prefix), 0 if no NBSS.
	NBSSLength uint32

	// Raw header fields (from 64-byte SMB2 header)
	ProtocolID    uint32
	StructureSize uint16
	CreditCharge  uint16
	Status        uint32
	Command       uint16
	Credit        uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32
	TreeID        uint32
	SessionID     uint64
	Signature     []byte

	// Raw command body (everything after the 64-byte header).
	Body []byte
}

// ParsePDU parses a single SMB2 PDU (with optional 4-byte NBSS prefix).
// If withNBSS is true, the first 4 bytes are treated as the NBSS header.
func ParsePDU(data []byte, withNBSS bool) (*ParsedPDU, error) {
	p := &ParsedPDU{}
	off := 0

	if withNBSS {
		if len(data) < NBSSHeaderSize {
			return nil, fmt.Errorf("smb: NBSS header too short (%d bytes)", len(data))
		}
		// Length is 3-byte BE in bits 1-3.
		p.NBSSLength = uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
		off += NBSSHeaderSize
	}

	if len(data)-off < HeaderSize {
		return nil, fmt.Errorf("smb: SMB2 header too short (%d bytes)", len(data)-off)
	}

	h := data[off : off+HeaderSize]
	// ProtocolId is byte-order preserved (FE 53 4D 42), so rebuild the
	// uint32 from the wire bytes rather than LittleEndian (which would
	// interpret 42 4D 53 FE for LE-written headers and mismatch real
	// servers' FE 53 4D 42).
	p.ProtocolID = uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
	p.StructureSize = binary.LittleEndian.Uint16(h[4:6])
	p.CreditCharge = binary.LittleEndian.Uint16(h[6:8])
	p.Status = binary.LittleEndian.Uint32(h[8:12])
	p.Command = binary.LittleEndian.Uint16(h[12:14])
	p.Credit = binary.LittleEndian.Uint16(h[14:16])
	p.Flags = binary.LittleEndian.Uint32(h[16:20])
	p.NextCommand = binary.LittleEndian.Uint32(h[20:24])
	p.MessageID = binary.LittleEndian.Uint64(h[24:32])
	p.Reserved = binary.LittleEndian.Uint32(h[32:36])
	p.TreeID = binary.LittleEndian.Uint32(h[36:40])
	p.SessionID = binary.LittleEndian.Uint64(h[40:48])
	p.Signature = make([]byte, 16)
	copy(p.Signature, h[48:64])

	off += HeaderSize
	if off < len(data) {
		p.Body = make([]byte, len(data)-off)
		copy(p.Body, data[off:])
	}

	return p, nil
}

// ParseNegotiateRequest parses a NEGOTIATE request body.
// Returns dialect count, security mode, capabilities, client GUID, and
// dialect list.
func ParseNegotiateRequest(body []byte) (
	dialectCount uint16,
	securityMode uint16,
	capabilities uint32,
	clientGUID [16]byte,
	dialects []uint16,
	err error,
) {
	if len(body) < 36 {
		err = fmt.Errorf("smb: NEGOTIATE request body too short (%d)", len(body))
		return
	}
	structureSize := binary.LittleEndian.Uint16(body[0:2])
	if structureSize != 36 {
		err = fmt.Errorf("smb: NEGOTIATE request StructureSize=%d, want 36", structureSize)
		return
	}
	dialectCount = binary.LittleEndian.Uint16(body[2:4])
	securityMode = binary.LittleEndian.Uint16(body[4:6])
	capabilities = binary.LittleEndian.Uint32(body[8:12])
	copy(clientGUID[:], body[12:28])
	for i := 0; i < int(dialectCount); i++ {
		d := binary.LittleEndian.Uint16(body[36+i*2 : 36+i*2+2])
		dialects = append(dialects, d)
	}
	return
}

// ParseNegotiateResponse parses a NEGOTIATE response body.
func ParseNegotiateResponse(body []byte) (
	securityMode uint16,
	dialectRev uint16,
	serverGUID [16]byte,
	capabilities uint32,
	maxTransactSize uint32,
	maxReadSize uint32,
	maxWriteSize uint32,
	securityBufOffset uint16,
	securityBufLength uint16,
	err error,
) {
	if len(body) < 64 {
		err = fmt.Errorf("smb: NEGOTIATE response body too short (%d)", len(body))
		return
	}
	structureSize := binary.LittleEndian.Uint16(body[0:2])
	if structureSize != 65 {
		err = fmt.Errorf("smb: NEGOTIATE response StructureSize=%d, want 65", structureSize)
		return
	}
	securityMode = binary.LittleEndian.Uint16(body[2:4])
	dialectRev = binary.LittleEndian.Uint16(body[4:6])
	copy(serverGUID[:], body[8:24])
	capabilities = binary.LittleEndian.Uint32(body[24:28])
	maxTransactSize = binary.LittleEndian.Uint32(body[28:32])
	maxReadSize = binary.LittleEndian.Uint32(body[32:36])
	maxWriteSize = binary.LittleEndian.Uint32(body[36:40])
	securityBufOffset = binary.LittleEndian.Uint16(body[56:58])
	securityBufLength = binary.LittleEndian.Uint16(body[58:60])
	return
}

// ParseSessionSetupRequest parses a SESSION_SETUP request body.
func ParseSessionSetupRequest(body []byte) (
	securityMode uint8,
	capabilities uint32,
	channel uint32,
	secBufOffset uint16,
	secBufLength uint16,
	previousSessionID uint64,
	err error,
) {
	if len(body) < 24 {
		err = fmt.Errorf("smb: SESSION_SETUP request body too short (%d)", len(body))
		return
	}
	structureSize := binary.LittleEndian.Uint16(body[0:2])
	if structureSize != 25 {
		err = fmt.Errorf("smb: SESSION_SETUP request StructureSize=%d, want 25", structureSize)
		return
	}
	// body[2] = Flags (uint8, BINDING)
	securityMode = body[3]
	capabilities = binary.LittleEndian.Uint32(body[4:8])
	channel = binary.LittleEndian.Uint32(body[8:12])
	secBufOffset = binary.LittleEndian.Uint16(body[12:14])
	secBufLength = binary.LittleEndian.Uint16(body[14:16])
	previousSessionID = binary.LittleEndian.Uint64(body[16:24])
	return
}

// ParseSessionSetupResponse parses a SESSION_SETUP response body.
func ParseSessionSetupResponse(body []byte) (
	sessionFlags uint16,
	secBufOffset uint16,
	secBufLength uint16,
	err error,
) {
	if len(body) < 8 {
		err = fmt.Errorf("smb: SESSION_SETUP response body too short (%d)", len(body))
		return
	}
	structureSize := binary.LittleEndian.Uint16(body[0:2])
	if structureSize != 9 {
		err = fmt.Errorf("smb: SESSION_SETUP response StructureSize=%d, want 9", structureSize)
		return
	}
	sessionFlags = binary.LittleEndian.Uint16(body[2:4])
	secBufOffset = binary.LittleEndian.Uint16(body[4:6])
	secBufLength = binary.LittleEndian.Uint16(body[6:8])
	return
}

// ParseTreeConnectRequest parses a TREE_CONNECT request body.
func ParseTreeConnectRequest(body []byte) (
	pathOffset uint16,
	pathLength uint16,
	path string,
	err error,
) {
	if len(body) < 8 {
		err = fmt.Errorf("smb: TREE_CONNECT request body too short (%d)", len(body))
		return
	}
	structureSize := binary.LittleEndian.Uint16(body[0:2])
	if structureSize != 9 {
		err = fmt.Errorf("smb: TREE_CONNECT request StructureSize=%d, want 9", structureSize)
		return
	}
	pathOffset = binary.LittleEndian.Uint16(body[4:6])
	pathLength = binary.LittleEndian.Uint16(body[6:8])
	// Path is UTF-16LE. PathOffset 字段从 SMB2 头(64B)起算（设计 §3.9），
	// 而本函数收到的是命令体（不含 64B 头），需换算为命令体内偏移。
	relative := int(pathOffset) - HeaderSize
	if relative >= 0 && relative+int(pathLength) <= len(body) {
		pathBytes := body[relative : relative+int(pathLength)]
		path = utf16LEToString(pathBytes)
	}
	return
}

// ParseTreeConnectResponse parses a TREE_CONNECT response body.
func ParseTreeConnectResponse(body []byte) (
	shareType uint8,
	shareFlags uint32,
	capabilities uint32,
	maximalAccess uint32,
	err error,
) {
	if len(body) < 16 {
		err = fmt.Errorf("smb: TREE_CONNECT response body too short (%d)", len(body))
		return
	}
	structureSize := binary.LittleEndian.Uint16(body[0:2])
	if structureSize != 16 {
		err = fmt.Errorf("smb: TREE_CONNECT response StructureSize=%d, want 16", structureSize)
		return
	}
	shareType = body[2]
	shareFlags = binary.LittleEndian.Uint32(body[4:8])
	capabilities = binary.LittleEndian.Uint32(body[8:12])
	maximalAccess = binary.LittleEndian.Uint32(body[12:16])
	return
}

// ParseCreateRequest parses a CREATE request body.
func ParseCreateRequest(body []byte) (
	impersonationLevel uint32,
	desiredAccess uint32,
	fileAttributes uint32,
	shareAccess uint32,
	createDisposition uint32,
	createOptions uint32,
	nameOffset uint16,
	nameLength uint16,
	name string,
	err error,
) {
	if len(body) < 56 {
		err = fmt.Errorf("smb: CREATE request body too short (%d)", len(body))
		return
	}
	structureSize := binary.LittleEndian.Uint16(body[0:2])
	if structureSize != 57 {
		err = fmt.Errorf("smb: CREATE request StructureSize=%d, want 57", structureSize)
		return
	}
	impersonationLevel = binary.LittleEndian.Uint32(body[4:8])
	desiredAccess = binary.LittleEndian.Uint32(body[24:28])
	fileAttributes = binary.LittleEndian.Uint32(body[28:32])
	shareAccess = binary.LittleEndian.Uint32(body[32:36])
	createDisposition = binary.LittleEndian.Uint32(body[36:40])
	createOptions = binary.LittleEndian.Uint32(body[40:44])
	nameOffset = binary.LittleEndian.Uint16(body[44:46])
	nameLength = binary.LittleEndian.Uint16(body[46:48])
	// NameOffset 字段从 SMB2 头(64B)起算（设计 §3.11），而本函数收到的是
	// 命令体（不含 64B 头），需换算为命令体内偏移（120-64=56）。
	relative := int(nameOffset) - HeaderSize
	if relative >= 0 && relative+int(nameLength) <= len(body) {
		nameBytes := body[relative : relative+int(nameLength)]
		name = utf16LEToString(nameBytes)
	}
	return
}

// ParseCreateResponse parses a CREATE response body.
func ParseCreateResponse(body []byte) (
	oplockLevel uint8,
	createAction uint32,
	fileID [16]byte,
	err error,
) {
	if len(body) < 88 {
		err = fmt.Errorf("smb: CREATE response body too short (%d)", len(body))
		return
	}
	structureSize := binary.LittleEndian.Uint16(body[0:2])
	if structureSize != 89 {
		err = fmt.Errorf("smb: CREATE response StructureSize=%d, want 89", structureSize)
		return
	}
	oplockLevel = body[2]
	createAction = binary.LittleEndian.Uint32(body[4:8])
	copy(fileID[:], body[64:80])
	return
}

// ParseReadRequest parses a READ request body.
func ParseReadRequest(body []byte) (
	length uint32,
	offset uint64,
	fileID [16]byte,
	err error,
) {
	if len(body) < 48 {
		err = fmt.Errorf("smb: READ request body too short (%d)", len(body))
		return
	}
	structureSize := binary.LittleEndian.Uint16(body[0:2])
	if structureSize != 49 {
		err = fmt.Errorf("smb: READ request StructureSize=%d, want 49", structureSize)
		return
	}
	length = binary.LittleEndian.Uint32(body[4:8])
	offset = binary.LittleEndian.Uint64(body[8:16])
	copy(fileID[:], body[16:32])
	return
}

// ParseReadResponse parses a READ response body.
func ParseReadResponse(body []byte) (
	dataOffset uint8,
	dataLength uint32,
	err error,
) {
	if len(body) < 16 {
		err = fmt.Errorf("smb: READ response body too short (%d)", len(body))
		return
	}
	structureSize := binary.LittleEndian.Uint16(body[0:2])
	if structureSize != 17 {
		err = fmt.Errorf("smb: READ response StructureSize=%d, want 17", structureSize)
		return
	}
	dataOffset = body[2]
	dataLength = binary.LittleEndian.Uint32(body[4:8])
	return
}

// ParseWriteRequest parses a WRITE request body.
func ParseWriteRequest(body []byte) (
	dataOffset uint16,
	length uint32,
	offset uint64,
	fileID [16]byte,
	err error,
) {
	if len(body) < 48 {
		err = fmt.Errorf("smb: WRITE request body too short (%d)", len(body))
		return
	}
	structureSize := binary.LittleEndian.Uint16(body[0:2])
	if structureSize != 49 {
		err = fmt.Errorf("smb: WRITE request StructureSize=%d, want 49", structureSize)
		return
	}
	dataOffset = binary.LittleEndian.Uint16(body[2:4])
	length = binary.LittleEndian.Uint32(body[4:8])
	offset = binary.LittleEndian.Uint64(body[8:16])
	copy(fileID[:], body[16:32])
	return
}

// ParseWriteResponse parses a WRITE response body.
func ParseWriteResponse(body []byte) (
	count uint32,
	err error,
) {
	if len(body) < 16 {
		err = fmt.Errorf("smb: WRITE response body too short (%d)", len(body))
		return
	}
	structureSize := binary.LittleEndian.Uint16(body[0:2])
	if structureSize != 17 {
		err = fmt.Errorf("smb: WRITE response StructureSize=%d, want 17", structureSize)
		return
	}
	count = binary.LittleEndian.Uint32(body[4:8])
	return
}

// ParseCloseRequest parses a CLOSE request body.
func ParseCloseRequest(body []byte) (
	fileID [16]byte,
	err error,
) {
	if len(body) < 24 {
		err = fmt.Errorf("smb: CLOSE request body too short (%d)", len(body))
		return
	}
	structureSize := binary.LittleEndian.Uint16(body[0:2])
	if structureSize != 24 {
		err = fmt.Errorf("smb: CLOSE request StructureSize=%d, want 24", structureSize)
		return
	}
	copy(fileID[:], body[8:24])
	return
}

// utf16LEToString decodes UTF-16LE bytes to a Go string.
func utf16LEToString(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		r := rune(b[i]) | rune(b[i+1])<<8
		runes = append(runes, r)
	}
	return string(runes)
}

// IsKnownStatusCode returns true if the given NT status is in the known
// 14-code set from design §3.26.
func IsKnownStatusCode(status uint32) bool {
	return knownStatusCodes[status]
}
