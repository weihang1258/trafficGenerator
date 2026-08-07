// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// body_file.go: READ/WRITE/CLOSE body builders (§3.13-3.18).
package smb

import (
	"encoding/binary"
)

// buildReadRequestBody builds a READ request body.
// length: bytes to read.
// offset: file offset.
// fileID: 16-byte FileId.
// minimumCount: minimum bytes to return (0 = length).
func buildReadRequestBody(
	length uint32,
	offset uint64,
	fileID [16]byte,
	minimumCount uint32,
) []byte {
	body := make([]byte, 49)
	body[0] = 0x31 // StructureSize = 49 (0x0031 LE)
	body[1] = 0x00
	body[2] = 0x00 // Padding
	body[3] = 0x00 // Flags
	binary.LittleEndian.PutUint32(body[4:8], length)
	binary.LittleEndian.PutUint64(body[8:16], offset)
	copy(body[16:32], fileID[:])
	binary.LittleEndian.PutUint32(body[32:36], minimumCount)
	// Channel (36-39) = 0
	// RemainingBytes (40-43) = 0
	// ReadChannelInfoOffset (44-45) = 0
	// ReadChannelInfoLength (46-47) = 0
	// Buffer (48) = 0 (M-3 修复: 设计 S5 中 READ req 固定体后附 1B Buffer,
	// 使 Body 总长 = 49B, NBSS = 64+48+1 = 113, 与 S5 一致)
	return body
}

// buildReadResponseBody builds a READ response body (header + data).
// dataLength: 实际返回的读取字节数 (用于设置 DataLength 字段).
// data: 实际读取的文件数据 (DataOffset 之后追加到响应体).
//
// BUG #16 修复 (CRITICAL): 原实现仅返回 16 字节头部而遗漏 data 部分.
// SMB2 规范 (MS-SMB2 §3.13) 要求响应体由 16 字节响应头 + 实际数据组成.
// Wireshark 验证时若缺少 data 字段会报 "EndOfSmb, missing data".
func buildReadResponseBody(dataLength uint32, data []byte) []byte {
	body := make([]byte, 16)
	body[0] = 0x11 // StructureSize = 17 (0x0011 LE)
	body[1] = 0x00
	body[2] = 0x50 // DataOffset = 80 (从 SMB2 header 起始: 64 头 + 16 响应头)
	body[3] = 0x00 // Reserved
	binary.LittleEndian.PutUint32(body[4:8], dataLength)
	// DataRemaining (8-11) = 0
	// Flags (12-15) = 0
	// BUG #16 修复: 将读取的实际数据追加到响应头之后。
	body = append(body, data...)
	return body
}

// makeReadData 生成 READ 响应携带的数据占位字节 (全 0x00).
// 真实流量生成场景不需要语义内容，仅需保证 DataLength 字段有对应长度的数据。
func makeReadData(length uint32) []byte {
	if length == 0 {
		return []byte{}
	}
	return make([]byte, length)
}

// buildReadErrorResponseBody builds a 16-byte READ error response body
// (StructureSize=17 + DataOffset=0 + DataLength=0 + DataRemaining=0 + Flags=0,
// see design §9.3).
func buildReadErrorResponseBody() []byte {
	body := make([]byte, 16)
	body[0] = 0x11
	body[1] = 0x00
	body[2] = 0x00
	body[3] = 0x00
	// body[4:8] = 0 (DataLength=0)
	// body[8:12] = 0 (DataRemaining=0)
	// body[12:16] = 0 (Flags=0)
	return body
}

// buildWriteRequestBody builds a WRITE request body.
// length: bytes to write.
// offset: file offset.
// fileID: 16-byte FileId.
// data: payload bytes.
// flags: WRITE_THROUGH (bit0) etc.
func buildWriteRequestBody(
	length uint32,
	offset uint64,
	fileID [16]byte,
	data []byte,
	flags uint32,
) []byte {
	body := make([]byte, 48)
	body[0] = 0x31 // StructureSize = 49 (0x0031 LE)
	body[1] = 0x00
	// DataOffset from SMB2 header start = 64 + 48 = 112
	binary.LittleEndian.PutUint16(body[2:4], 112)
	binary.LittleEndian.PutUint32(body[4:8], length)
	binary.LittleEndian.PutUint64(body[8:16], offset)
	copy(body[16:32], fileID[:])
	// Channel (32-35) = 0
	// RemainingBytes (36-39) = 0
	// WriteChannelInfoOffset (40-41) = 0
	// WriteChannelInfoLength (42-43) = 0
	binary.LittleEndian.PutUint32(body[44:48], flags)
	body = append(body, data...)
	return body
}

// buildWriteResponseBody builds a WRITE response body.
// count: bytes written.
func buildWriteResponseBody(count uint32) []byte {
	body := make([]byte, 16)
	body[0] = 0x11 // StructureSize = 17 (0x0011 LE)
	body[1] = 0x00
	// Reserved (2-3) = 0
	binary.LittleEndian.PutUint32(body[4:8], count)
	// Remaining (8-11) = 0
	// WriteChannelInfoOffset (12-13) = 0
	// WriteChannelInfoLength (14-15) = 0
	return body
}

// buildWriteErrorResponseBody builds a 16-byte WRITE error response body
// (StructureSize=17 + Count=0 + Remaining=0, see design §9.3).
func buildWriteErrorResponseBody() []byte {
	body := make([]byte, 16)
	body[0] = 0x11
	body[1] = 0x00
	// body[4:8] = 0 (Count=0)
	// body[8:12] = 0 (Remaining=0)
	// body[12:14] = 0 (WriteChannelInfoOffset=0)
	// body[14:16] = 0 (WriteChannelInfoLength=0)
	return body
}

// buildCloseRequestBody builds a CLOSE request body.
// fileID: 16-byte FileId.
func buildCloseRequestBody(fileID [16]byte) []byte {
	body := make([]byte, 24)
	body[0] = 0x18 // StructureSize = 24 (0x0018 LE)
	body[1] = 0x00
	// Flags (2-3) = 0
	// Reserved (4-7) = 0
	copy(body[8:24], fileID[:])
	return body
}

// buildCloseResponseBody builds a CLOSE response body (60 bytes).
func buildCloseResponseBody() []byte {
	body := make([]byte, 60)
	body[0] = 0x3C // StructureSize = 60 (0x003C LE)
	body[1] = 0x00
	// All time/size fields = 0
	return body
}
