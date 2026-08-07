// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// builder.go: SMB2 SYNC Header + NBSS prefix + NEGOTIATE body builders.
package smb

import (
	"encoding/binary"
	"time"
)

// buildNBSSHeader builds a 4-byte NBSS session message header.
// Type = 0x00 (Session Message), Length = 3-byte BE payload length.
func buildNBSSHeader(payloadLen int) []byte {
	h := make([]byte, NBSSHeaderSize)
	h[0] = NBSSSessionMessage
	h[1] = byte((payloadLen >> 16) & 0xFF)
	h[2] = byte((payloadLen >> 8) & 0xFF)
	h[3] = byte(payloadLen & 0xFF)
	return h
}

// buildSMB2Header constructs the 64-byte SMB2 SYNC Header (MS-SMB2 §2.2.1.2).
func buildSMB2Header(
	cmd uint16,
	creditCharge uint16,
	status uint32,
	flags uint32,
	messageID uint64,
	treeID uint32,
	sessionID uint64,
) []byte {
	h := make([]byte, HeaderSize)
	// SMB2 ProtocolId is the 4 bytes FE 53 4D 42 on the wire (MS-SMB2
	// §2.2.1.2) — byte-order preserved, NOT little-endian. writeUint32LE
	// would emit 42 4D 53 FE, which real servers reject.
	h[0], h[1], h[2], h[3] = 0xFE, 0x53, 0x4D, 0x42
	writeUint16LE(h, 4, HeaderSize)
	writeUint16LE(h, 6, creditCharge)
	writeUint32LE(h, 8, status)
	writeUint16LE(h, 12, cmd)
	writeUint16LE(h, 14, 31)
	writeUint32LE(h, 16, flags)
	writeUint32LE(h, 20, 0)
	writeUint64LE(h, 24, messageID)
	writeUint32LE(h, 32, 0)
	writeUint32LE(h, 36, treeID)
	writeUint64LE(h, 40, sessionID)
	// M-2 修复: SigningRequired=true 时 Signature 区 (偏移 48-63) 必须为
	// 非零占位 (设计 §3.1/S14/T184)。调用方通过 Flags=FlagSigned 表示已签名，
	// 在此填入确定性的非全零占位字节。
	if flags&FlagSigned != 0 {
		writeSignaturePlaceholder(h, 48, messageID, sessionID)
	}
	return h
}

// writeSignaturePlaceholder 填充签名区的确定性非全零占位字节。基础分量
// (i*0x5A+0x7E) 保证即使 messageID/sessionID 全 0 也非全零, 避免不同 PDU
// 之间签名区完全雷同。
func writeSignaturePlaceholder(h []byte, off int, messageID uint64, sessionID uint64) {
	for i := 0; i < 16; i++ {
		c := byte(i*0x5A + 0x7E)
		if i < 8 {
			c ^= byte(messageID >> (i * 8))
		}
		if i >= 4 && i < 12 {
			c ^= byte(sessionID >> ((i - 4) * 8))
		}
		h[off+i] = c
	}
}

// buildTransformHeader builds the 52-byte SMB3 TRANSFORM_HEADER (MS-SMB2
// §3.1.4.3 / 设计 §3.27). 原 SMB2 头+体作为密文 (EncryptedMessage) 跟在
// 该头之后; ProtocolId = 0xFD534D42, Flags bit0 = Encrypted.
func buildTransformHeader(origMessageSize uint32, sessionID uint64) []byte {
	th := make([]byte, TransformHeaderSize)
	// Transform ProtocolId = FD 53 4D 42 on the wire (MS-SMB2 §3.1.4.3),
	// byte-order preserved (same as SMB2 ProtocolId).
	th[0], th[1], th[2], th[3] = 0xFD, 0x53, 0x4D, 0x42
	// Signature (4-19) = 占位全 0 (trafficgen 不实现真实加密)
	// Nonce (20-35) = 占位全 0
	writeUint32LE(th, 36, origMessageSize)
	writeUint16LE(th, 42, 0x0001) // Flags = bit0 Encrypted
	writeUint64LE(th, 44, sessionID)
	return th
}

// align8 pads b to an 8-byte boundary by appending zero bytes.
func align8(b []byte) []byte {
	rem := len(b) % 8
	if rem == 0 {
		return b
	}
	out := make([]byte, len(b)+(8-rem))
	copy(out, b)
	return out
}

// fakeSalt returns a deterministic 32-byte salt.
func fakeSalt(n int) []byte {
	out := make([]byte, n)
	t := time.Now().UnixNano()
	for i := 0; i < n && i < 8; i++ {
		out[i] = byte(t >> (i * 8))
	}
	for i := 8; i < n; i++ {
		out[i] = byte(i*7 + 0x5A)
	}
	return out
}

// buildPreauthContext builds a Preauth Integrity negotiate context.
func buildPreauthContext(algs []uint16) []byte {
	saltLen := 32
	data := make([]byte, 4)
	writeUint16LE(data, 0, uint16(len(algs)))
	writeUint16LE(data, 2, uint16(saltLen))
	for _, a := range algs {
		data = append(data, byte(a), byte(a>>8))
	}
	data = append(data, fakeSalt(saltLen)...)
	// Pad data to 8-byte boundary (MS-SMB2 §2.2.3.1: each context 8B aligned).
	rem := len(data) % 8
	if rem != 0 {
		data = append(data, make([]byte, 8-rem)...)
	}

	ctx := make([]byte, 8)
	writeUint16LE(ctx, 0, NegotiateContextPreauth)
	writeUint16LE(ctx, 2, uint16(len(data)))
	writeUint32LE(ctx, 4, 0)
	ctx = append(ctx, data...)
	return ctx
}

// buildEncryptionContext builds an Encryption negotiate context.
func buildEncryptionContext(ciphers []uint16) []byte {
	data := make([]byte, 2)
	writeUint16LE(data, 0, uint16(len(ciphers)))
	for _, c := range ciphers {
		data = append(data, byte(c), byte(c>>8))
	}
	// Pad data to 8-byte boundary (MS-SMB2 §2.2.3.1: each context 8B aligned).
	rem := len(data) % 8
	if rem != 0 {
		data = append(data, make([]byte, 8-rem)...)
	}
	ctx := make([]byte, 8)
	writeUint16LE(ctx, 0, NegotiateContextEncrypt)
	writeUint16LE(ctx, 2, uint16(len(data)))
	writeUint32LE(ctx, 4, 0)
	ctx = append(ctx, data...)
	return ctx
}

// buildNegotiateRequestBody builds a NEGOTIATE request body (§3.5).
func buildNegotiateRequestBody(
	dialects []uint16,
	securityMode uint16,
	clientCapabilities uint32,
	clientGUID [16]byte,
	preauthAlgs []uint16,
	encAlgs []uint16,
) []byte {
	fixed := make([]byte, 36)
	writeUint16LE(fixed, 0, 36)
	writeUint16LE(fixed, 2, uint16(len(dialects)))
	writeUint16LE(fixed, 4, securityMode)
	writeUint32LE(fixed, 8, clientCapabilities)
	copy(fixed[12:28], clientGUID[:])

	dialectBytes := make([]byte, len(dialects)*2)
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(dialectBytes[i*2:], d)
	}
	body := append(fixed, dialectBytes...)

	ctxCount := 0
	var ctxList []byte
	if len(preauthAlgs) > 0 {
		ctxList = append(ctxList, buildPreauthContext(preauthAlgs)...)
		ctxCount++
	}
	if len(encAlgs) > 0 {
		ctxList = align8(ctxList)
		ctxList = append(ctxList, buildEncryptionContext(encAlgs)...)
		ctxCount++
	}

	if ctxCount == 0 {
		writeUint32LE(body, 28, 0)
		writeUint16LE(body, 32, 0)
		return body
	}

	preCtxLen := len(body)
	padLen := (8 - (preCtxLen % 8)) % 8
	ctxOffset := uint32(HeaderSize + preCtxLen + padLen)
	writeUint32LE(body, 28, ctxOffset)
	writeUint16LE(body, 32, uint16(ctxCount))
	body = append(body, make([]byte, padLen)...)
	body = append(body, ctxList...)
	return body
}

// buildNegotiateResponseBody builds a NEGOTIATE response body (§3.6).
func buildNegotiateResponseBody(
	dialectRev uint16,
	securityMode uint16,
	serverGUID [16]byte,
	serverCapabilities uint32,
	maxTransactSize uint32,
	maxReadSize uint32,
	maxWriteSize uint32,
	securityBlob []byte,
) []byte {
	fixed := make([]byte, 64)
	writeUint16LE(fixed, 0, 65)
	writeUint16LE(fixed, 2, securityMode)
	writeUint16LE(fixed, 4, dialectRev)
	writeUint16LE(fixed, 6, 0)
	copy(fixed[8:24], serverGUID[:])
	writeUint32LE(fixed, 24, serverCapabilities)
	writeUint32LE(fixed, 28, maxTransactSize)
	writeUint32LE(fixed, 32, maxReadSize)
	writeUint32LE(fixed, 36, maxWriteSize)
	writeUint16LE(fixed, 56, 128) // SecurityBufferOffset from SMB2 header
	writeUint16LE(fixed, 58, uint16(len(securityBlob)))
	writeUint32LE(fixed, 60, 0)
	body := append(fixed, securityBlob...)
	return body
}
