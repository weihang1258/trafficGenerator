// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// gss.go: GSS-API/SPNEGO and NTLMSSP blob builders.
// The blobs carry placeholder authentication data (trafficgen does not
// implement real encryption or authentication state machines), but they are
// DER/BER well-formed so parsers (Wireshark, SPNEGO implementations) can
// decode them without malformed-packet errors.
//
// G-SMB-2 boundary (D-SMB-1, ruling c: coexist): the Type1/Challenge/Auth
// placeholders below (32/48/88B) serve full-session smb flows only;
// standalone NTLM exchanges live in the ntlm layer (G-NTLM-3). If the ntlm
// builder drifts from these sizes, reunification is framework backlog.
package smb

import (
	"encoding/binary"
)

// SPNEGO OID 1.3.6.1.5.5.2 (RFC 4178).
var spnegoOID = []byte{0x2B, 0x06, 0x01, 0x05, 0x05, 0x02}

// kerberosOID is the Kerberos V5 mechanism OID 1.2.840.113554.1.2.2 (RFC 4121).
var kerberosOID = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02}

// gssTLSCapabilitiesOID is the GSS_C_IN_FLOW OID 1.3.6.1.5.5.14 used by
// Wireshark to pick the in-flow mechanism for anonymous/guest sessions.
var gssTLSCapabilitiesOID = []byte{0x2B, 0x06, 0x01, 0x05, 0x05, 0x0E}

// buildGSSAPIBlob builds a GSS-API/SPNEGO NegotiationToken (RFC 4178):
//
//	NegotiationToken ::= SEQUENCE {
//	    OBJECT IDENTIFIER (SPNEGO mechanism 1.3.6.1.5.5.2),
//	    [0] NegTokenInit
//	}
//	NegTokenInit ::= SEQUENCE {
//	    mechTypes   [0] SEQUENCE OF OBJECT IDENTIFIER,
//	    reqFlags    [1] BIT STRING OPTIONAL,
//	    mechToken   [2] OCTET STRING,       -- optional
//	    mechListMIC [3] OCTET STRING OPTIONAL
//	}
//
// The outer SPNEGO OID is required: Wireshark's GSS-API dissector
// (packet-gssapi.c) reads the OID directly after the SEQUENCE tag, and
// without it every SMB negotiate response was flagged malformed.
//
// mechanism: "ntlm", "kerberos", "anonymous", or "guest".
func buildGSSAPIBlob(mechanism string) []byte {
	var mechTypes [][]byte
	var token []byte
	switch mechanism {
	case "ntlm":
		mechTypes = [][]byte{spnegoOID}
		token = buildNTLMSSPNegotiateBlob()
	case "kerberos":
		mechTypes = [][]byte{kerberosOID}
		token = []byte("KRB_TGT_PLACEHOLDER_32_BYTES_HERE_PAD")
	case "anonymous":
		mechTypes = [][]byte{gssTLSCapabilitiesOID}
		token = []byte("ANONYMOUS_PLACEHOLDER_BLOB")
	case "guest":
		mechTypes = [][]byte{gssTLSCapabilitiesOID}
		token = []byte("GUEST_PLACEHOLDER_BLOB")
	default:
		mechTypes = [][]byte{spnegoOID}
		token = []byte("UNKNOWN_MECHANISM")
	}

	mtSeq := []byte{0x30}
	mtSeq = append(mtSeq, berLength(mechTypesLen(mechTypes))...)
	for _, oid := range mechTypes {
		mtSeq = append(mtSeq, 0x06, byte(len(oid)))
		mtSeq = append(mtSeq, oid...)
	}

	// NegTokenInit ::= SEQUENCE { mechTypes [0] SEQUENCE OF OID,
	//                             mechToken [2] OCTET STRING OPTIONAL }
	var negTokenInit []byte
	negTokenInit = append(negTokenInit, 0xA0)
	negTokenInit = append(negTokenInit, berLength(len(mtSeq))...)
	negTokenInit = append(negTokenInit, mtSeq...)
	if len(token) > 0 {
		negTokenInit = append(negTokenInit, 0xA2)
		negTokenInit = append(negTokenInit, berLength(len(token))...)
		negTokenInit = append(negTokenInit, token...)
	}

	// SPNEGO wrapper (wireshark packet-gssapi.c expects the mechanism OID
	// directly after the outer SEQUENCE; the previous blob skipped it and
	// tshark flagged every negotiate response as malformed). The NegTokenInit
	// itself is a plain SEQUENCE on the wire (packet-spnego.c):
	//   SEQUENCE { OBJECT IDENTIFIER (SPNEGO), SEQUENCE { [0] mechTypes, [2] mechToken } }
	content := make([]byte, 0, 2+len(spnegoOID)+2+len(negTokenInit))
	content = append(content, 0x06, byte(len(spnegoOID)))
	content = append(content, spnegoOID...)
	content = append(content, 0x30)
	content = append(content, berLength(len(negTokenInit))...)
	content = append(content, negTokenInit...)

	blob := make([]byte, 0, 1+len(content))
	blob = append(blob, 0x60)
	blob = append(blob, berLength(len(content))...)
	blob = append(blob, content...)
	return blob
}

func mechTypesLen(mechTypes [][]byte) int {
	n := 0
	for _, oid := range mechTypes {
		n += 2 + len(oid) // tag 06 + 1-byte length + OID
	}
	return n
}

// berLength encodes a BER definite length with the minimal header:
// single byte for < 128, otherwise 0x81/0x82 + big-endian bytes.
func berLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n & 0xFF)}
	}
}

// buildNTLMSSPNegotiateBlob builds an NTLMSSP NEGOTIATE (type 1) message
// (MS-NLMP §2.2.1.1). Minimal form: signature(8B) + type(4B) + flags(4B) +
// domain fields(8B) + workstation fields(8B) = 32 bytes fixed body.
func buildNTLMSSPNegotiateBlob() []byte {
	blob := make([]byte, 32)
	copy(blob[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(blob[8:12], 1) // MessageType NEGOTIATE
	// NegotiateExtendedSessionSecurity | NegotiateAlwaysSign |
	// NegotiateUnicode | NegotiateNTLM.
	binary.LittleEndian.PutUint32(blob[12:16], 0x00088201)
	// DomainNameFields: Len(2)=0 @16, MaxLen(2)=0 @18, Offset(4)=32 @20.
	binary.LittleEndian.PutUint32(blob[20:24], 32)
	// WorkstationFields: Len(2)=0 @24, MaxLen(2)=0 @26, Offset(4)=32 @28.
	binary.LittleEndian.PutUint32(blob[28:32], 32)
	return blob
}

// buildNTLMSSPChallengeBlob builds an NTLMSSP CHALLENGE (type 2) message
// (MS-NLMP §2.2.1.2). Minimal form: signature(8B) + type(4B) +
// target name fields(8B) + flags(4B) + challenge(8B) + reserved(8B) +
// target info fields(8B) = 48 bytes fixed body.
func buildNTLMSSPChallengeBlob() []byte {
	blob := make([]byte, 48)
	copy(blob[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(blob[8:12], 2) // MessageType CHALLENGE
	// TargetNameFields: Len(2)=0 @12, MaxLen(2)=0 @14, Offset(4)=48 @16.
	binary.LittleEndian.PutUint32(blob[16:20], 48)
	// NegotiateExtendedSessionSecurity | NegotiateAlwaysSign |
	// NegotiateUnicode | NegotiateNTLM.
	binary.LittleEndian.PutUint32(blob[20:24], 0x00088201)
	// Challenge (8B) - server challenge placeholder.
	binary.LittleEndian.PutUint64(blob[24:32], 0x0123456789ABCDEF)
	// Reserved (8B) = 0.
	// TargetInfoFields: Len(2)=0, MaxLen(2)=0, Offset(4)=48.
	binary.LittleEndian.PutUint32(blob[44:48], 48)
	return blob
}

// buildNTLMSSPAuthBlob builds an NTLMSSP AUTH (type 3) message (MS-NLMP
// §2.2.1.3). Fixed body: signature(8B) + type(4B) + LM response fields(8B) +
// NTLM response fields(8B) + domain fields(8B) + user fields(8B) +
// workstation fields(8B) + session key fields(8B) + flags(4B) + version(8B) +
// MIC(16B) = 88 bytes.
//
// The Version field (64-71) and MIC (72-87) are mandatory: Wireshark 3.6.14
// (packet-ntlmssp.c dissect_ntlmssp_auth) reads the 8-byte Version field
// whenever NEGOTIATE_VERSION (0x08) is set in flags, then reads the 16-byte
// MIC. The previous 68-byte blob with all offsets = 68 collided with the
// Version read past the tvb and produced [Malformed Packet: NTLMSSP] on the
// AUTH session-setup frame of every NTLM SMB session.
func buildNTLMSSPAuthBlob() []byte {
	blob := make([]byte, 88)
	copy(blob[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(blob[8:12], 3) // MessageType AUTH
	// Each payload field: Len(2)=0, MaxLen(2)=0, Offset(4)=88.
	for _, base := range []int{12, 20, 28, 36, 44, 52} {
		binary.LittleEndian.PutUint32(blob[base+4:base+8], 88)
	}
	// Flags (60-63) = 0x00088209: NEGOTIATE_UNICODE (0x1) | NEGOTIATE_SIGN
	// (0x8) | NEGOTIATE_NTLM (0x200) | NEGOTIATE_ALWAYS_SIGN (0x80000)
	// (MS-NLMP §2.2.1.1). NEGOTIATE_VERSION (0x02000000) is NOT set — the
	// dissector still parses the 8-byte Version field unconditionally in
	// AUTH (type 3) messages (packet-ntlmssp.c dissect_ntlmssp_auth).
	binary.LittleEndian.PutUint32(blob[60:64], 0x00088209)
	// Version (MS-NLMP §2.2.2.10): Major=10, Minor=0, Build=0, Reserved=15.
	blob[64] = 10 // MajorVersion
	blob[65] = 0  // MinorVersion
	blob[66] = 0  // BuildNumber (low)
	blob[67] = 0  // BuildNumber (high)
	blob[68] = 0x0F // Reserved
	// MIC (72-87): 16-byte message integrity code placeholder (all zeros).
	return blob
}
