// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// smb_test_build.go: Unit tests for body builders (session/tree/file).
package smb

import (
	"encoding/binary"
	"testing"
)

// TestBuildSessionSetupRequestBody verifies SESSION_SETUP fields.
func TestBuildSessionSetupRequestBody(t *testing.T) {
	blob := []byte{0x4E, 0x54, 0x4C, 0x4D}
	body := buildSessionSetupRequestBody(0, 0x01, 0x01, 0, blob, 0)
	if len(body) < 24+4 {
		t.Fatal("body too short")
	}
	if body[0] != 0x19 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 19 00", body[0], body[1])
	}
	if body[3] != 0x01 {
		t.Errorf("SecurityMode = %X", body[3])
	}
	off := binary.LittleEndian.Uint16(body[12:14])
	if off != 88 {
		t.Errorf("SecurityBufferOffset = %d, want 88", off)
	}
	length := binary.LittleEndian.Uint16(body[14:16])
	if length != 4 {
		t.Errorf("SecurityBufferLength = %d, want 4", length)
	}
}

// TestBuildSessionSetupResponseBody verifies SESSION_SETUP response fields.
func TestBuildSessionSetupResponseBody(t *testing.T) {
	blob := []byte{0x01, 0x02}
	body := buildSessionSetupResponseBody(0x02, blob)
	if len(body) < 8+2 {
		t.Fatal("body too short")
	}
	if body[0] != 0x09 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 09 00", body[0], body[1])
	}
	flags := binary.LittleEndian.Uint16(body[2:4])
	if flags != 0x02 {
		t.Errorf("SessionFlags = %X, want 02", flags)
	}
	off := binary.LittleEndian.Uint16(body[4:6])
	if off != 72 {
		t.Errorf("SecurityBufferOffset = %d, want 72", off)
	}
}

// TestBuildTreeConnectRequestBody verifies TREE_CONNECT fields.
func TestBuildTreeConnectRequestBody(t *testing.T) {
	body := buildTreeConnectRequestBody("\\\\server\\share")
	if len(body) < 8 {
		t.Fatal("body too short")
	}
	if body[0] != 0x09 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 09 00", body[0], body[1])
	}
	off := binary.LittleEndian.Uint16(body[4:6])
	if off != 72 {
		t.Errorf("PathOffset = %d, want 72", off)
	}
	plen := binary.LittleEndian.Uint16(body[6:8])
	if plen != 28 {
		t.Errorf("PathLength = %d, want 28 (14 chars × 2)", plen)
	}
}

// TestBuildTreeConnectResponseBody verifies TREE_CONNECT response fields.
func TestBuildTreeConnectResponseBody(t *testing.T) {
	body := buildTreeConnectResponseBody(0, 0, 0, 0x001F1FFF)
	if len(body) < 16 {
		t.Fatal("body too short")
	}
	if body[0] != 0x10 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 10 00", body[0], body[1])
	}
	if body[2] != 0 {
		t.Errorf("ShareType = %d, want 0", body[2])
	}
	maxAcc := binary.LittleEndian.Uint32(body[12:16])
	if maxAcc != 0x001F1FFF {
		t.Errorf("MaximalAccess = %X, want 001F1FFF", maxAcc)
	}
}

// TestBuildCreateRequestBodyDefaults verifies default fields.
func TestBuildCreateRequestBodyDefaults(t *testing.T) {
	body := buildCreateRequestBody(2, 0x00120089, 0x80, 0x07, 1, 0, "test.txt")
	if len(body) < 56 {
		t.Fatal("body too short")
	}
	if body[0] != 0x39 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 39 00", body[0], body[1])
	}
	level := binary.LittleEndian.Uint32(body[4:8])
	if level != 2 {
		t.Errorf("ImpersonationLevel = %d, want 2", level)
	}
	off := binary.LittleEndian.Uint16(body[44:46])
	if off != 120 {
		t.Errorf("NameOffset = %d, want 120", off)
	}
}

// TestBuildCreateResponseBody verifies CREATE response fields.
func TestBuildCreateResponseBody(t *testing.T) {
	var fid [16]byte
	for i := range fid {
		fid[i] = byte(i + 1)
	}
	body := buildCreateResponseBody(0, 1, fid)
	if len(body) < 88 {
		t.Fatal("body too short")
	}
	if body[0] != 0x59 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 59 00", body[0], body[1])
	}
	if body[2] != 0 {
		t.Errorf("OplockLevel = %d, want 0", body[2])
	}
	action := binary.LittleEndian.Uint32(body[4:8])
	if action != 1 {
		t.Errorf("CreateAction = %d, want 1", action)
	}
	for i := 0; i < 16; i++ {
		if body[64+i] != byte(i+1) {
			t.Errorf("FileId[%d] = %X, want %X", i, body[64+i], i+1)
		}
	}
}

// TestBuildReadRequestBody verifies READ request fields.
func TestBuildReadRequestBody(t *testing.T) {
	var fid [16]byte
	for i := range fid {
		fid[i] = byte(i + 1)
	}
	body := buildReadRequestBody(8192, 1024, fid, 0)
	if len(body) < 48 {
		t.Fatal("body too short")
	}
	length := binary.LittleEndian.Uint32(body[4:8])
	if length != 8192 {
		t.Errorf("Length = %d, want 8192", length)
	}
	offset := binary.LittleEndian.Uint64(body[8:16])
	if offset != 1024 {
		t.Errorf("Offset = %d, want 1024", offset)
	}
	for i := 0; i < 16; i++ {
		if body[16+i] != byte(i+1) {
			t.Errorf("FileId[%d] = %X, want %X", i, body[16+i], i+1)
		}
	}
}

// TestBuildReadResponseBody verifies READ response fields.
// BUG #16 修复后响应体尾部追加实际读取数据。
func TestBuildReadResponseBody(t *testing.T) {
	const dataLen = uint32(4096)
	body := buildReadResponseBody(dataLen, makeReadData(dataLen))
	if len(body) < 16 {
		t.Fatal("body too short")
	}
	if body[0] != 0x11 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 11 00", body[0], body[1])
	}
	if body[2] != 0x50 {
		t.Errorf("DataOffset = %X, want 50", body[2])
	}
	length := binary.LittleEndian.Uint32(body[4:8])
	if length != 4096 {
		t.Errorf("DataLength = %d, want 4096", length)
	}
	// BUG #16: 验证实际数据被追加 (len(body) 应为 16 + dataLen = 4112)。
	if uint32(len(body)-16) != dataLen {
		t.Errorf("response data trailing bytes = %d, want %d", len(body)-16, dataLen)
	}
}

// TestBuildWriteRequestBody verifies WRITE request fields.
func TestBuildWriteRequestBody(t *testing.T) {
	var fid [16]byte
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	body := buildWriteRequestBody(4, 0, fid, data, 0)
	if len(body) < 48+4 {
		t.Fatal("body too short")
	}
	if body[0] != 0x31 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 31 00", body[0], body[1])
	}
	off := binary.LittleEndian.Uint16(body[2:4])
	if off != 112 {
		t.Errorf("DataOffset = %d, want 112", off)
	}
	length := binary.LittleEndian.Uint32(body[4:8])
	if length != 4 {
		t.Errorf("Length = %d, want 4", length)
	}
	for i := 0; i < 4; i++ {
		if body[48+i] != data[i] {
			t.Errorf("Data[%d] = %X, want %X", i, body[48+i], data[i])
		}
	}
}

// TestBuildWriteResponseBody verifies WRITE response fields.
func TestBuildWriteResponseBody(t *testing.T) {
	body := buildWriteResponseBody(128)
	if len(body) < 16 {
		t.Fatal("body too short")
	}
	if body[0] != 0x11 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 11 00", body[0], body[1])
	}
	count := binary.LittleEndian.Uint32(body[4:8])
	if count != 128 {
		t.Errorf("Count = %d, want 128", count)
	}
}

// TestBuildCloseRequestBody verifies CLOSE request fields.
func TestBuildCloseRequestBody(t *testing.T) {
	var fid [16]byte
	for i := range fid {
		fid[i] = byte(i + 1)
	}
	body := buildCloseRequestBody(fid)
	if len(body) < 24 {
		t.Fatal("body too short")
	}
	if body[0] != 0x18 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 18 00", body[0], body[1])
	}
	for i := 0; i < 16; i++ {
		if body[8+i] != byte(i+1) {
			t.Errorf("FileId[%d] = %X, want %X", i, body[8+i], i+1)
		}
	}
}

// TestBuildCloseResponseBody verifies CLOSE response fields.
func TestBuildCloseResponseBody(t *testing.T) {
	body := buildCloseResponseBody()
	if len(body) < 60 {
		t.Fatal("body too short")
	}
	if body[0] != 0x3C || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 3C 00", body[0], body[1])
	}
}

// TestBuildLockElement verifies LOCK_ELEMENT fields.
func TestBuildLockElement(t *testing.T) {
	el := buildLockElement(100, 200, 0x02)
	if len(el) < 24 {
		t.Fatal("element too short")
	}
	offset := binary.LittleEndian.Uint64(el[0:8])
	if offset != 100 {
		t.Errorf("Offset = %d, want 100", offset)
	}
	length := binary.LittleEndian.Uint64(el[8:16])
	if length != 200 {
		t.Errorf("Length = %d, want 200", length)
	}
	flags := binary.LittleEndian.Uint32(el[16:20])
	if flags != 0x02 {
		t.Errorf("Flags = %X, want 02", flags)
	}
}

// TestBuildLockRequestBody verifies LOCK request fields.
func TestBuildLockRequestBody(t *testing.T) {
	var fid [16]byte
	lockEl := buildLockElement(0, 4096, 0x02)
	body := buildLockRequestBody(fid, lockEl)
	if len(body) < 24 {
		t.Fatal("body too short")
	}
	if body[0] != 0x30 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 30 00", body[0], body[1])
	}
	count := binary.LittleEndian.Uint16(body[2:4])
	if count != 1 {
		t.Errorf("LockCount = %d, want 1", count)
	}
}
