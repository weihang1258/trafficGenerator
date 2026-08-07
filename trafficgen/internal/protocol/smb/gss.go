// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// gss.go: GSS-API/SPNEGO and NTLMSSP blob builders (placeholder content).
// All blobs are placeholder bytes — trafficgen does not implement real
// encryption or authentication state machines.
package smb

import (
	"encoding/binary"
)

// buildGSSAPIBlob builds a generic GSS-API/SPNEGO placeholder blob.
// mechanism: "ntlm", "kerberos", "anonymous", or "guest".
// The blob is a simple SPNEGO wrapper with a fake mechanism OID and
// an initialized token bytes placeholder.
func buildGSSAPIBlob(mechanism string) []byte {
	// SPNEGO wrapper: simple 16-byte placeholder
	blob := make([]byte, 0, 128)

	// SPNEGO OID prefix (6 bytes) + MS-Kerb/LAN Manager identifier (10 bytes)
	blob = append(blob, 0x60, 0x76) // SPNEGO NegTokenInit
	// Length placeholder (will be overwritten)
	lengthIdx := len(blob)
	blob = append(blob, 0x82, 0x01, 0x70) // 2-byte length

	// MechType
	blob = append(blob, 0x30, 0x37)
	blob = append(blob, 0xA0, 0x03, 0x0A, 0x01, 0x01) // MechType: 1.0.1 placeholder
	blob = append(blob, 0xA1, 0x05, 0x1B, 0x01, 0x01, 0x01, 0x01)

	// Inner token placeholder
	blob = append(blob, 0xA2, 0x60)
	// Mechanism-specific dummy payload follows
	var mechBytes []byte
	switch mechanism {
	case "ntlm":
		mechBytes = buildNTLMSSPNegotiateBlob()
	case "kerberos":
		mechBytes = []byte("KRB_TGT_PLACEHOLDER_32_BYTES_HERE_PAD")
		mechBytes = append(mechBytes, make([]byte, 32)...)
	case "anonymous":
		mechBytes = []byte("ANONYMOUS_PLACEHOLDER_BLOB")
	case "guest":
		mechBytes = []byte("GUEST_PLACEHOLDER_BLOB")
	default:
		mechBytes = []byte("UNKNOWN_MECHANISM")
	}
	// Truncate/pad to uniform size
	for len(mechBytes) < 96 {
		mechBytes = append(mechBytes, 0x00)
	}
	if len(mechBytes) > 96 {
		mechBytes = mechBytes[:96]
	}
	blob = append(blob, mechBytes...)

	// Overwrite length
	binary.BigEndian.PutUint16(blob[lengthIdx+1:lengthIdx+3], uint16(len(blob)-4))
	return blob
}

// buildNTLMSSPNegotiateBlob builds a NTLMSSP NEGOTIATE (type 1) token placeholder.
// Standard layout: signature(8B) + type(4B) + flags(4B) + domain fields(8B) +
// workstation fields(8B) + version(8B) = 40 bytes.
func buildNTLMSSPNegotiateBlob() []byte {
	blob := make([]byte, 40)
	// "NTLMSSP\0" signature
	copy(blob[0:8], []byte("NTLMSSP\x00"))
	// MessageType = 1 (NEGOTIATE)
	binary.LittleEndian.PutUint32(blob[8:12], 1)
	// Flags: 0xE2088297 (NEGOTIATE_NTLM | NEGOTIATE_EXTENDED_SESSIONSECURITY | etc.)
	binary.LittleEndian.PutUint32(blob[12:16], 0xE2088297)
	// DomainNameFields: Len(2)=0, MaxLen(2)=0, Offset(4)=40
	binary.LittleEndian.PutUint16(blob[16:18], 0)
	binary.LittleEndian.PutUint16(blob[18:20], 0)
	binary.LittleEndian.PutUint32(blob[20:24], 40)
	// WorkstationFields: Len=0, MaxLen=0, Offset=40
	binary.LittleEndian.PutUint16(blob[24:26], 0)
	binary.LittleEndian.PutUint16(blob[26:28], 0)
	binary.LittleEndian.PutUint32(blob[28:32], 40)
	// Version (8 bytes) = 0
	return blob
}

// buildNTLMSSPChallengeBlob builds a NTLMSSP CHALLENGE (type 2) token placeholder.
// Standard layout: signature(8B) + type(4B) + target name fields(8B) +
// flags(4B) + challenge(8B) + reserved(8B) + target info fields(8B) + version(8B)
// = 56 bytes minimum.
func buildNTLMSSPChallengeBlob() []byte {
	blob := make([]byte, 112)
	// "NTLMSSP\0" signature
	copy(blob[0:8], []byte("NTLMSSP\x00"))
	// MessageType = 2 (CHALLENGE)
	binary.LittleEndian.PutUint32(blob[8:12], 2)
	// TargetNameFields: Len=0, MaxLen=0, Offset=56
	binary.LittleEndian.PutUint16(blob[12:14], 0)
	binary.LittleEndian.PutUint16(blob[14:16], 0)
	binary.LittleEndian.PutUint32(blob[16:20], 56)
	// Flags
	binary.LittleEndian.PutUint32(blob[20:24], 0xE2888297)
	// Challenge (8B) - server challenge placeholder
	binary.LittleEndian.PutUint64(blob[24:32], 0x0123456789ABCDEF)
	// Reserved (8B)
	// TargetInfoFields: Len=48, MaxLen=48, Offset=56
	binary.LittleEndian.PutUint16(blob[40:42], 48)
	binary.LittleEndian.PutUint16(blob[42:44], 48)
	binary.LittleEndian.PutUint32(blob[44:48], 56)
	// Version (8B) = 0
	// 48 bytes of target info placeholder
	for i := 56; i < 104; i++ {
		blob[i] = byte(i)
	}
	return blob
}

// buildNTLMSSPAuthBlob builds a NTLMSSP AUTH (type 3) token placeholder.
// Standard layout: signature(8B) + type(4B) + LM response fields(8B) +
// NTLM response fields(8B) + domain fields(8B) + user fields(8B) +
// workstation fields(8B) + session key fields(8B) + flags(4B) + version(8B) +
// MIC(16B) = 80 bytes minimum.
func buildNTLMSSPAuthBlob() []byte {
	blob := make([]byte, 80)
	// "NTLMSSP\0" signature
	copy(blob[0:8], []byte("NTLMSSP\x00"))
	// MessageType = 3 (AUTH)
	binary.LittleEndian.PutUint32(blob[8:12], 3)
	// LMResponseFields: Len=0, MaxLen=0, Offset=80
	binary.LittleEndian.PutUint16(blob[12:14], 0)
	binary.LittleEndian.PutUint16(blob[14:16], 0)
	binary.LittleEndian.PutUint32(blob[16:20], 80)
	// NTLMResponseFields: Len=0, MaxLen=0, Offset=80
	binary.LittleEndian.PutUint16(blob[20:22], 0)
	binary.LittleEndian.PutUint16(blob[22:24], 0)
	binary.LittleEndian.PutUint32(blob[24:28], 80)
	// DomainFields: Len=0, MaxLen=0, Offset=80
	binary.LittleEndian.PutUint16(blob[28:30], 0)
	binary.LittleEndian.PutUint16(blob[30:32], 0)
	binary.LittleEndian.PutUint32(blob[32:36], 80)
	// UserFields: Len=0, MaxLen=0, Offset=80
	binary.LittleEndian.PutUint16(blob[36:38], 0)
	binary.LittleEndian.PutUint16(blob[38:40], 0)
	binary.LittleEndian.PutUint32(blob[40:44], 80)
	// WorkstationFields: Len=0, MaxLen=0, Offset=80
	binary.LittleEndian.PutUint16(blob[44:46], 0)
	binary.LittleEndian.PutUint16(blob[46:48], 0)
	binary.LittleEndian.PutUint32(blob[48:52], 80)
	// SessionKeyFields: Len=0, MaxLen=0, Offset=80
	binary.LittleEndian.PutUint16(blob[52:54], 0)
	binary.LittleEndian.PutUint16(blob[54:56], 0)
	binary.LittleEndian.PutUint32(blob[56:60], 80)
	// Flags
	binary.LittleEndian.PutUint32(blob[60:64], 0xE2888297)
	// Version (8B) = 0
	// MIC (16B) = 0
	return blob
}
