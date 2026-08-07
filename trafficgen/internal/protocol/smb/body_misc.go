// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// body_misc.go: QUERY_DIRECTORY/QUERY_INFO/LOCK/IOCTL/FLUSH/ECHO/
// TREE_DISCONNECT/LOGOFF body builders (§3.19-3.25).
package smb

import (
	"encoding/binary"
)

// buildLightweightBody builds a 4-byte minimal body for lightweight commands
// (TREE_DISCONNECT, LOGOFF, ECHO, and lightweight responses).
func buildLightweightBody() []byte {
	body := make([]byte, 4)
	body[0] = 0x04 // StructureSize = 4 (0x0004 LE)
	body[1] = 0x00
	body[2] = 0x00 // Reserved
	body[3] = 0x00
	return body
}

// buildFlushRequestBody builds a FLUSH request body.
func buildFlushRequestBody(fileID [16]byte) []byte {
	body := make([]byte, 24)
	body[0] = 0x18 // StructureSize = 24 (0x0018 LE)
	body[1] = 0x00
	// Reserved (2-3) = 0
	// Reserved (4-7) = 0
	copy(body[8:24], fileID[:])
	return body
}

// buildQueryDirectoryRequestBody builds a QUERY_DIRECTORY request body.
// fileID: directory file handle.
// infoClass: FileInformationClass (37=IdBothDirectoryInformation).
// fileName: wildcard pattern (UTF-8).
// outputBufferLength: max output length.
func buildQueryDirectoryRequestBody(
	fileID [16]byte,
	infoClass uint8,
	fileName string,
	outputBufferLength uint32,
) []byte {
	utf16Name := utf16LE(fileName)
	body := make([]byte, 32)
	body[0] = 0x21 // StructureSize = 33 (0x0021 LE)
	body[1] = 0x00
	body[2] = infoClass
	body[3] = 0x00 // Flags
	// FileIndex (4-7) = 0
	copy(body[8:24], fileID[:])
	// FileNameOffset from SMB2 header start = 64 + 32 = 96
	binary.LittleEndian.PutUint16(body[24:26], 96)
	binary.LittleEndian.PutUint16(body[26:28], uint16(len(utf16Name)))
	binary.LittleEndian.PutUint32(body[28:32], outputBufferLength)
	body = append(body, utf16Name...)
	return body
}

// buildQueryDirectoryResponseBody builds a QUERY_DIRECTORY response body.
func buildQueryDirectoryResponseBody(outputBuffer []byte) []byte {
	body := make([]byte, 8)
	body[0] = 0x09 // StructureSize = 9 (LE)
	body[1] = 0x00
	// OutputBufferOffset from SMB2 header start = 64 (fixed)
	binary.LittleEndian.PutUint16(body[2:4], 64)
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(outputBuffer)))
	body = append(body, outputBuffer...)
	return body
}

// buildQueryInfoRequestBody builds a QUERY_INFO request body.
// infoType: 0=File, 1=FileSystem, 2=Security, 3=Quota.
// fileInfoClass: e.g. 4=FileBasicInfo.
// outputBufferLength: max output length.
// inputBufferOffset: from SMB2 header start.
// additionalInformation: bitmask.
// fileID: 16-byte FileId.
// inputBuffer: variable input data.
func buildQueryInfoRequestBody(
	infoType uint8,
	fileInfoClass uint8,
	outputBufferLength uint32,
	inputBufferOffset uint16,
	fileID [16]byte,
	inputBuffer []byte,
) []byte {
	body := make([]byte, 40)
	body[0] = 0x29 // StructureSize = 41 (0x0029 LE)
	body[1] = 0x00
	body[2] = infoType
	body[3] = fileInfoClass
	binary.LittleEndian.PutUint32(body[4:8], outputBufferLength)
	binary.LittleEndian.PutUint16(body[8:10], inputBufferOffset)
	// Reserved (10-11) = 0
	// InputBufferLength (12-15) = 0
	// AdditionalInformation (16-19) = 0
	// Flags (20-23) = 0
	copy(body[24:40], fileID[:])
	body = append(body, inputBuffer...)
	return body
}

// buildQueryInfoResponseBody builds a QUERY_INFO response body.
func buildQueryInfoResponseBody(outputBuffer []byte) []byte {
	body := make([]byte, 8)
	body[0] = 0x09 // StructureSize = 9 (LE)
	body[1] = 0x00
	// OutputBufferOffset from SMB2 header start = 64
	binary.LittleEndian.PutUint16(body[2:4], 64)
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(outputBuffer)))
	body = append(body, outputBuffer...)
	return body
}

// buildLockElement builds a 24-byte LOCK_ELEMENT (§3.24).
// flags: bit0=SHARED_LOCK, bit1=EXCLUSIVE_LOCK, bit2=UNLOCK, bit3=FAIL_IMMEDIATELY.
func buildLockElement(offset uint64, length uint64, flags uint32) []byte {
	el := make([]byte, 24)
	binary.LittleEndian.PutUint64(el[0:8], offset)
	binary.LittleEndian.PutUint64(el[8:16], length)
	binary.LittleEndian.PutUint32(el[16:20], flags)
	// Reserved (20-23) = 0
	return el
}

// buildLockRequestBody builds a LOCK request body with a single lock element.
func buildLockRequestBody(fileID [16]byte, lockElement []byte) []byte {
	body := make([]byte, 24)
	body[0] = 0x30 // StructureSize = 48 (0x0030 LE)
	body[1] = 0x00
	binary.LittleEndian.PutUint16(body[2:4], 1) // LockCount = 1
	// LockSequence (4-7) = 0
	copy(body[8:24], fileID[:])
	body = append(body, lockElement...)
	return body
}

// buildIOCTLRequestBody builds an IOCTL request body.
// ctlCode: IOCTL control code (e.g. 0x00060194 = FSCTL_DFS_GET_REFERRALS).
// fileID: 16-byte FileId.
// inputBuffer: variable input buffer.
//
// 字段布局见设计 S9 HexDump：
//
//	InputOffset = 120 (64 头 + 56 固定体)、InputCount = len(inputBuffer)、
//	MaxInputResponse = 0、OutputOffset = 0、OutputCount = 0、
//	MaxOutputResponse = 4096、Flags = 0x01 (IS_IOCTL)、Reserved2 = 0。
//
// (H-2 修复：原实现把 MaxOutputResponse 写入 OutputCount、OutputOffset 区域
// 写无意义值、Flags=0。)
func buildIOCTLRequestBody(
	ctlCode uint32,
	fileID [16]byte,
	inputBuffer []byte,
) []byte {
	body := make([]byte, 56)
	body[0] = 0x39 // StructureSize = 57 (0x0039 LE)
	body[1] = 0x00
	// Reserved (2-3) = 0
	binary.LittleEndian.PutUint32(body[4:8], ctlCode)
	copy(body[8:24], fileID[:])
	// InputOffset from SMB2 header start = 64 + 56 = 120
	binary.LittleEndian.PutUint32(body[24:28], 120)
	binary.LittleEndian.PutUint32(body[28:32], uint32(len(inputBuffer))) // InputCount
	binary.LittleEndian.PutUint32(body[32:36], 0)                        // MaxInputResponse = 0
	binary.LittleEndian.PutUint32(body[36:40], 0)                        // OutputOffset = 0
	binary.LittleEndian.PutUint32(body[40:44], 0)                        // OutputCount = 0
	binary.LittleEndian.PutUint32(body[44:48], 0x1000)                   // MaxOutputResponse = 4096
	binary.LittleEndian.PutUint32(body[48:52], 0x00000001)               // Flags = 0x01 (IS_IOCTL)
	// Reserved2 (52-55) = 0
	body = append(body, inputBuffer...)
	return body
}
