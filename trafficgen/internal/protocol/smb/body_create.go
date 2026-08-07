// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// body_create.go: CREATE request/response body builders (§3.11-3.12).
package smb

import (
	"encoding/binary"
)

// buildCreateRequestBody builds a CREATE request body.
// impersonationLevel: 0=Anonymous, 1=Identification, 2=Impersonation, 3=Delegate.
// desiredAccess: FILE_READ_DATA etc.
// fileAttributes: 0x80=NORMAL etc.
// shareAccess: bit0=READ, bit1=WRITE, bit2=DELETE.
// createDisposition: 0=supersede, 1=open, 2=create, 3=open_if, 4=overwrite, 5=overwrite_if.
// createOptions: bit0=directory, etc.
// name: UTF-8 file path; planner converts to UTF-16LE.
func buildCreateRequestBody(
	impersonationLevel uint32,
	desiredAccess uint32,
	fileAttributes uint32,
	shareAccess uint32,
	createDisposition uint32,
	createOptions uint32,
	name string,
) []byte {
	utf16Name := utf16LE(name)
	body := make([]byte, 56)
	body[0] = 0x39 // StructureSize = 57 (0x0039 LE)
	body[1] = 0x00
	body[2] = 0x00 // SecurityFlags
	body[3] = 0x00 // RequestedOplockLevel = 0
	binary.LittleEndian.PutUint32(body[4:8], impersonationLevel)
	// SmbCreateFlags (8-15) = 0
	// RootDirectoryFid (16-23) = 0
	binary.LittleEndian.PutUint32(body[24:28], desiredAccess)
	binary.LittleEndian.PutUint32(body[28:32], fileAttributes)
	binary.LittleEndian.PutUint32(body[32:36], shareAccess)
	binary.LittleEndian.PutUint32(body[36:40], createDisposition)
	binary.LittleEndian.PutUint32(body[40:44], createOptions)
	// NameOffset from SMB2 header start = 64 + 56 = 120
	binary.LittleEndian.PutUint16(body[44:46], 120)
	binary.LittleEndian.PutUint16(body[46:48], uint16(len(utf16Name)))
	// CreateContextsOffset (48-51) = 0
	// CreateContextsLength (52-55) = 0
	body = append(body, utf16Name...)
	return body
}

// buildCreateResponseBody builds a CREATE response body.
// oplockLevel: 0=none, 1=II, 2=exclusive, 3=Batch, 4=Lease.
// createAction: 0=superseded, 1=opened, 2=created, 3=overwritten.
// fileID: 16-byte FileId (8B persistent + 8B volatile).
func buildCreateResponseBody(
	oplockLevel uint8,
	createAction uint32,
	fileID [16]byte,
) []byte {
	body := make([]byte, 88)
	body[0] = 0x59 // StructureSize = 89 (0x0059 LE)
	body[1] = 0x00
	body[2] = oplockLevel
	body[3] = 0x00 // Flags
	binary.LittleEndian.PutUint32(body[4:8], createAction)
	// CreationTime (8-15) = 0
	// LastAccessTime (16-23) = 0
	// LastWriteTime (24-31) = 0
	// ChangeTime (32-39) = 0
	// AllocationSize (40-47) = 0
	// EndOfFile (48-55) = 0
	// FileAttributes (56-59) = 0
	// Reserved (60-63) = 0
	copy(body[64:80], fileID[:])
	// CreateContextsOffset (80-83) = 0
	// CreateContextsLength (84-87) = 0
	return body
}
