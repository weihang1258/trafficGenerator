// Package smb implements the SMB2/SMB3 protocol planner (MS-SMB2).
//
// smb_test_build_more.go: Unit tests for query/ioctl/flush/GSS/NTLMSSP.
package smb

import (
	"encoding/binary"
	"testing"
)

// TestBuildQueryDirectoryRequestBody verifies QUERY_DIRECTORY fields.
func TestBuildQueryDirectoryRequestBody(t *testing.T) {
	var fid [16]byte
	body := buildQueryDirectoryRequestBody(fid, 37, "*", 4096)
	if len(body) < 32 {
		t.Fatal("body too short")
	}
	if body[0] != 0x21 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 21 00", body[0], body[1])
	}
	if body[2] != 37 {
		t.Errorf("InfoClass = %d, want 37", body[2])
	}
	off := binary.LittleEndian.Uint16(body[24:26])
	if off != 96 {
		t.Errorf("FileNameOffset = %d, want 96", off)
	}
}

// TestBuildQueryInfoRequestBody verifies QUERY_INFO fields.
func TestBuildQueryInfoRequestBody(t *testing.T) {
	var fid [16]byte
	body := buildQueryInfoRequestBody(0, 4, 4096, 0, fid, nil)
	if len(body) < 40 {
		t.Fatal("body too short")
	}
	if body[0] != 0x29 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 29 00", body[0], body[1])
	}
	if body[2] != 0 {
		t.Errorf("InfoType = %d, want 0", body[2])
	}
	if body[3] != 4 {
		t.Errorf("FileInfoClass = %d, want 4", body[3])
	}
}

// TestBuildIOCTLRequestBody verifies IOCTL fields (H-2: 布局对照设计 S9).
func TestBuildIOCTLRequestBody(t *testing.T) {
	var fid [16]byte
	input := []byte{0x12, 0x34}
	body := buildIOCTLRequestBody(0x00060194, fid, input)
	if len(body) < 56+2 {
		t.Fatal("body too short")
	}
	if body[0] != 0x39 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 39 00", body[0], body[1])
	}
	ctl := binary.LittleEndian.Uint32(body[4:8])
	if ctl != 0x00060194 {
		t.Errorf("CtlCode = %X, want 00060194", ctl)
	}
	// H-2 逐字段断言 (设计 S9 HexDump):
	// InputOffset=120, InputCount=len(input), MaxInputResponse=0,
	// OutputOffset=0, OutputCount=0, MaxOutputResponse=4096, Flags=0x01.
	if got := binary.LittleEndian.Uint32(body[24:28]); got != 120 {
		t.Errorf("InputOffset = %d, want 120", got)
	}
	if got := binary.LittleEndian.Uint32(body[28:32]); got != uint32(len(input)) {
		t.Errorf("InputCount = %d, want %d", got, len(input))
	}
	if got := binary.LittleEndian.Uint32(body[32:36]); got != 0 {
		t.Errorf("MaxInputResponse = %d, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(body[36:40]); got != 0 {
		t.Errorf("OutputOffset = %d, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(body[40:44]); got != 0 {
		t.Errorf("OutputCount = %d, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(body[44:48]); got != 4096 {
		t.Errorf("MaxOutputResponse = %d, want 4096", got)
	}
	if got := binary.LittleEndian.Uint32(body[48:52]); got != 0x00000001 {
		t.Errorf("Flags = %X, want 0x00000001 (IS_IOCTL)", got)
	}
	// 输入缓冲区紧随 56B 固定体。
	if body[56] != 0x12 || body[57] != 0x34 {
		t.Errorf("InputBuffer = % X, want 12 34", body[56:58])
	}
}

// TestBuildLightweightBody verifies lightweight body structure.
func TestBuildLightweightBody(t *testing.T) {
	body := buildLightweightBody()
	if len(body) < 4 {
		t.Fatal("body too short")
	}
	if body[0] != 0x04 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 04 00", body[0], body[1])
	}
}

// TestBuildFlushRequestBody verifies FLUSH request fields.
func TestBuildFlushRequestBody(t *testing.T) {
	var fid [16]byte
	for i := range fid {
		fid[i] = byte(i + 1)
	}
	body := buildFlushRequestBody(fid)
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

// TestGSSAPIBlob_NTLM verifies NTLM blob structure.
func TestGSSAPIBlob_NTLM(t *testing.T) {
	blob := buildGSSAPIBlob("ntlm")
	if len(blob) < 8 {
		t.Fatal("blob too short")
	}
	if blob[0] != 0x60 {
		t.Errorf("SPNEGO tag = %X, want 60", blob[0])
	}
}

// TestGSSAPIBlob_Kerberos verifies Kerberos blob structure.
func TestGSSAPIBlob_Kerberos(t *testing.T) {
	blob := buildGSSAPIBlob("kerberos")
	if len(blob) < 8 {
		t.Fatal("blob too short")
	}
	if blob[0] != 0x60 {
		t.Errorf("SPNEGO tag = %X, want 60", blob[0])
	}
}

// TestGSSAPIBlob_Anonymous verifies Anonymous blob structure.
func TestGSSAPIBlob_Anonymous(t *testing.T) {
	blob := buildGSSAPIBlob("anonymous")
	if len(blob) < 8 {
		t.Fatal("blob too short")
	}
	if blob[0] != 0x60 {
		t.Errorf("SPNEGO tag = %X, want 60", blob[0])
	}
}

// parseBERLen reads a BER definite-length header from b at off; returns the
// value and the header size (bytes consumed).
func parseBERLen(b []byte, off int) (int, int, bool) {
	if off >= len(b) {
		return 0, 0, false
	}
	first := b[off]
	if first < 0x80 {
		return int(first), 1, true
	}
	n := int(first & 0x7F)
	if n == 0 || n > 4 || off+1+n > len(b) {
		return 0, 0, false
	}
	v := 0
	for i := 0; i < n; i++ {
		v = v<<8 | int(b[off+1+i])
	}
	return v, 1 + n, true
}

// TestGSSAPIBlob_StandardSPNEGOStructure verifies the SPNEGO negTokenInit
// wrapper is DER/BER well-formed and carries a real mechanism OID (regression
// for the placeholder blob that tshark flagged "BER Error: Object Identifier
// expected" on every SMB negotiate packet).
//
// The blob must be the RFC 4178 GSS-API message:
//
//	NegotiationToken ::= CHOICE { negTokenInit [0] NegTokenInit, ... }
//	with the SPNEGO mechanism OID 1.3.6.1.5.5.2 (wireshark packet-gssapi.c
//	reads the OID directly after the outer SEQUENCE).
func TestGSSAPIBlob_StandardSPNEGOStructure(t *testing.T) {
	for _, mech := range []string{"ntlm", "kerberos", "anonymous", "guest"} {
		blob := buildGSSAPIBlob(mech)
		if len(blob) < 24 {
			t.Fatalf("%s: blob too short (%d)", mech, len(blob))
		}
		// 1. SEQUENCE (60) + BER definite length covering the content.
		if blob[0] != 0x60 {
			t.Fatalf("%s: outer tag = %02X, want 60", mech, blob[0])
		}
		contentLen, hdrLen, ok := parseBERLen(blob, 1)
		if !ok {
			t.Fatalf("%s: bad outer BER length header", mech)
		}
		if 1+hdrLen+contentLen != len(blob) {
			t.Errorf("%s: outer length %d + header %d = %d, want blob len %d",
				mech, contentLen, hdrLen, 1+hdrLen+contentLen, len(blob))
		}
		off := 1 + hdrLen
		// 2. The SPNEGO mechanism OID must come directly after the outer
		// SEQUENCE (packet-gssapi.c reads the OID right after the SEQUENCE).
		if blob[off] != 0x06 {
			t.Fatalf("%s: OID tag = %02X (off %d), want 06", mech, blob[off], off)
		}
		if blob[off+1] != 6 {
			t.Fatalf("%s: OID length = %d, want 6", mech, blob[off+1])
		}
		oid := blob[off+2 : off+2+6]
		if string(oid) != "+\x06\x01\x05\x05\x02" {
			t.Errorf("%s: OID = % X, want 2B 06 01 05 05 02 (SPNEGO 1.3.6.1.5.5.2)",
				mech, oid)
		}
		negOff := off + 2 + 6
		// 3. NegTokenInit: [0] a0 + BER len + SEQUENCE (30) of mechTypes.
		if blob[negOff] != 0x30 {
			t.Fatalf("%s: NegTokenInit tag = %02X (off %d), want 30 SEQUENCE",
				mech, blob[negOff], negOff)
		}
		negLen, negHdr, ok := parseBERLen(blob, negOff+1)
		if !ok {
			t.Fatalf("%s: bad NegTokenInit BER length", mech)
		}
		_ = negLen
		mtOff := negOff + 1 + negHdr
		if blob[mtOff] != 0xA0 {
			t.Fatalf("%s: first field tag = %02X, want A0 (mechTypes)", mech, blob[mtOff])
		}
		mtLen, mtHdr, ok := parseBERLen(blob, mtOff+1)
		if !ok {
			t.Fatalf("%s: bad mechTypes BER length", mech)
		}
		_ = mtLen
		seqOff := mtOff + 1 + mtHdr
		if blob[seqOff] != 0x30 {
			t.Fatalf("%s: mechTypes inner tag = %02X, want 30 SEQUENCE", mech, blob[seqOff])
		}
		seqLen, seqHdr, ok := parseBERLen(blob, seqOff+1)
		if !ok {
			t.Fatalf("%s: bad mechTypes SEQUENCE length", mech)
		}
		oidOff := seqOff + 1 + seqHdr
		if blob[oidOff] != 0x06 {
			t.Fatalf("%s: mechType tag = %02X, want 06 OID", mech, blob[oidOff])
		}
		oidLen := int(blob[oidOff+1])
		if oidOff+2+oidLen > seqOff+1+seqHdr+seqLen {
			t.Fatalf("%s: OID overruns mechTypes SEQUENCE", mech)
		}
		// 4. [2] mechToken: a2 + BER len + token bytes.
		tokOff := mtOff + 1 + mtHdr + 1 + seqHdr + 2 + oidLen
		if tokOff >= len(blob) || blob[tokOff] != 0xA2 {
			t.Fatalf("%s: mechToken tag = %02X (off %d), want A2", mech, blob[tokOff], tokOff)
		}
		tokLen, tokHdr, ok := parseBERLen(blob, tokOff+1)
		if !ok {
			t.Fatalf("%s: bad mechToken BER length", mech)
		}
		if tokOff+1+tokHdr+tokLen != len(blob) {
			t.Errorf("%s: mechToken ends at %d, want blob len %d",
				mech, tokOff+1+tokHdr+tokLen, len(blob))
		}
		if mech == "ntlm" {
			tok := blob[tokOff+1+tokHdr:]
			if string(tok[0:8]) != "NTLMSSP\x00" {
				t.Errorf("%s: mechToken sig = %q, want NTLMSSP", mech, tok[0:8])
			}
		}
	}
}

// TestNTLMSSPNegotiateBlob_Minimal verifies the NTLMSSP NEGOTIATE type 1 blob
// is 40 bytes, self-consistent (domain/workstation offsets) and parses cleanly
// as a minimal message.
func TestNTLMSSPNegotiateBlob_Minimal(t *testing.T) {
	blob := buildNTLMSSPNegotiateBlob()
	if len(blob) != 32 {
		t.Fatalf("len = %d, want 32", len(blob))
	}
	if msgType := binary.LittleEndian.Uint32(blob[8:12]); msgType != 1 {
		t.Errorf("MessageType = %d, want 1", msgType)
	}
	// DomainNameFields offset (20-23) must point past the fixed 40-byte body
	// (empty payloads allowed, offsets must still be in range).
	if off := binary.LittleEndian.Uint32(blob[20:24]); off < 32 {
		t.Errorf("DomainNameOffset = %d, want >= 32", off)
	}
	if off := binary.LittleEndian.Uint32(blob[28:32]); off < 32 {
		t.Errorf("WorkstationOffset = %d, want >= 32", off)
	}
	// NTLMv2 (0x80000000) must NOT be advertised on a type 1 with no
	// NTLMv2 response data.
	if flags := binary.LittleEndian.Uint32(blob[12:16]); flags&0x80000000 != 0 {
		t.Errorf("flags %08X advertises NTLMv2, want not set", flags)
	}
}

// TestNTLMSSPChallengeBlob_Minimal verifies the NTLMSSP CHALLENGE type 2 blob
// is self-consistent: no target info data is claimed past the fixed body.
func TestNTLMSSPChallengeBlob_Minimal(t *testing.T) {
	blob := buildNTLMSSPChallengeBlob()
	if len(blob) != 48 {
		t.Fatalf("len = %d, want 48", len(blob))
	}
	if msgType := binary.LittleEndian.Uint32(blob[8:12]); msgType != 2 {
		t.Errorf("MessageType = %d, want 2", msgType)
	}
	if tl := binary.LittleEndian.Uint16(blob[12:14]); tl != 0 {
		t.Errorf("TargetNameLen = %d, want 0", tl)
	}
	if toff := binary.LittleEndian.Uint32(blob[16:20]); toff < 48 {
		t.Errorf("TargetNameOffset = %d, want >= 48", toff)
	}
	if tiLen := binary.LittleEndian.Uint16(blob[40:42]); tiLen != 0 {
		t.Errorf("TargetInfoLen = %d, want 0 (no data present)", tiLen)
	}
	if tiOff := binary.LittleEndian.Uint32(blob[44:48]); tiOff < 48 {
		t.Errorf("TargetInfoOffset = %d, want >= 48", tiOff)
	}
}

// TestNTLMSSPAuthBlob_Minimal verifies the NTLMSSP AUTH type 3 blob is
// self-consistent: all payload fields point past the fixed 88-byte body with
// zero lengths, and the optional Version/MIC fields are present so Wireshark
// 3.6.14 (packet-ntlmssp.c dissect_ntlmssp_auth) never reads past the tvb.
// Regression for 507 pcap malformed findings (frame 8 [Malformed Packet:
// NTLMSSP]): the old 68-byte blob with all offsets = 68 collided with the
// Version field read at offset 64+.
func TestNTLMSSPAuthBlob_Minimal(t *testing.T) {
	blob := buildNTLMSSPAuthBlob()
	if len(blob) != 88 {
		t.Fatalf("len = %d, want 88", len(blob))
	}
	if msgType := binary.LittleEndian.Uint32(blob[8:12]); msgType != 3 {
		t.Errorf("MessageType = %d, want 3", msgType)
	}
	// LM(12-19)/NTLM(20-27)/Domain(28-35)/User(36-43)/Workstation(44-51)/
	// SessionKey(52-59): each has Len(2B)+MaxLen(2B) then Offset(4B).
	for name, base := range map[string]int{
		"LM": 12, "NTLM": 20, "Domain": 28, "User": 36,
		"Workstation": 44, "SessionKey": 52,
	} {
		if l := binary.LittleEndian.Uint16(blob[base : base+2]); l != 0 {
			t.Errorf("%s Len = %d, want 0", name, l)
		}
		if off := binary.LittleEndian.Uint32(blob[base+4 : base+8]); off != 88 {
			t.Errorf("%s Offset = %d, want 88", name, off)
		}
	}
	// Flags (60-63): NEGOTIATE_VERSION (0x08) must be set so the dissector
	// parses the Version field (64-71) instead of re-reading the blob end.
	if flags := binary.LittleEndian.Uint32(blob[60:64]); flags&0x00000008 == 0 {
		t.Errorf("flags = %08X, want NEGOTIATE_VERSION (0x08) set", flags)
	}
	// Version field (64-71): Major=10, Minor=0, Build=0, Reserved=15.
	if blob[64] != 10 || blob[65] != 0 {
		t.Errorf("Version = %d.%d, want 10.0", blob[64], blob[65])
	}
	if blob[66] != 0 || blob[67] != 0 {
		t.Errorf("Version Build = %d %d, want 0 0", blob[66], blob[67])
	}
	if blob[68] != 0x0F {
		t.Errorf("Version Reserved = %02X, want 0F", blob[68])
	}
	// MIC (72-87) must exist (16 bytes) even if all zeros.
	if len(blob) < 88 {
		t.Fatalf("blob too short for MIC: %d", len(blob))
	}
}

// TestNTLMSSPNegotiateBlob verifies NTLMSSP NEGOTIATE structure.
func TestNTLMSSPNegotiateBlob(t *testing.T) {
	blob := buildNTLMSSPNegotiateBlob()
	if len(blob) < 32 {
		t.Fatal("blob too short")
	}
	if string(blob[0:8]) != "NTLMSSP\x00" {
		t.Errorf("signature = %q, want NTLMSSP", blob[0:8])
	}
	msgType := binary.LittleEndian.Uint32(blob[8:12])
	if msgType != 1 {
		t.Errorf("MessageType = %d, want 1", msgType)
	}
}

// TestNTLMSSPChallengeBlob verifies NTLMSSP CHALLENGE structure.
func TestNTLMSSPChallengeBlob(t *testing.T) {
	blob := buildNTLMSSPChallengeBlob()
	if len(blob) < 48 {
		t.Fatal("blob too short")
	}
	if string(blob[0:8]) != "NTLMSSP\x00" {
		t.Errorf("signature = %q, want NTLMSSP", blob[0:8])
	}
	msgType := binary.LittleEndian.Uint32(blob[8:12])
	if msgType != 2 {
		t.Errorf("MessageType = %d, want 2", msgType)
	}
}

// TestNTLMSSPAuthBlob verifies NTLMSSP AUTH structure.
func TestNTLMSSPAuthBlob(t *testing.T) {
	blob := buildNTLMSSPAuthBlob()
	if len(blob) != 88 {
		t.Fatal("blob too short")
	}
	if string(blob[0:8]) != "NTLMSSP\x00" {
		t.Errorf("signature = %q, want NTLMSSP", blob[0:8])
	}
	msgType := binary.LittleEndian.Uint32(blob[8:12])
	if msgType != 3 {
		t.Errorf("MessageType = %d, want 3", msgType)
	}
}

// TestBuildQueryDirectoryResponseBody verifies QUERY_DIRECTORY response.
func TestBuildQueryDirectoryResponseBody(t *testing.T) {
	out := []byte{0x01, 0x02}
	body := buildQueryDirectoryResponseBody(out)
	if len(body) < 8+2 {
		t.Fatal("body too short")
	}
	if body[0] != 0x09 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 09 00", body[0], body[1])
	}
	off := binary.LittleEndian.Uint16(body[2:4])
	if off != 64 {
		t.Errorf("OutputBufferOffset = %d, want 64", off)
	}
	length := binary.LittleEndian.Uint32(body[4:8])
	if length != 2 {
		t.Errorf("OutputBufferLength = %d, want 2", length)
	}
}

// TestBuildQueryInfoResponseBody verifies QUERY_INFO response.
func TestBuildQueryInfoResponseBody(t *testing.T) {
	out := []byte{0xAA, 0xBB}
	body := buildQueryInfoResponseBody(out)
	if len(body) < 8+2 {
		t.Fatal("body too short")
	}
	if body[0] != 0x09 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 09 00", body[0], body[1])
	}
	off := binary.LittleEndian.Uint16(body[2:4])
	if off != 64 {
		t.Errorf("OutputBufferOffset = %d, want 64", off)
	}
	length := binary.LittleEndian.Uint32(body[4:8])
	if length != 2 {
		t.Errorf("OutputBufferLength = %d, want 2", length)
	}
}

// TestBuildNegotiateRequestBody_FieldValues verifies field values per byte level.
func TestBuildNegotiateRequestBody_FieldValues(t *testing.T) {
	var guid [16]byte
	for i := range guid {
		guid[i] = byte(i + 1)
	}
	body := buildNegotiateRequestBody([]uint16{0x0202, 0x0311}, 0x01, 0x03, guid, nil, nil)
	if len(body) < 40 {
		t.Fatal("body too short")
	}
	if body[0] != 0x24 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 24 00", body[0], body[1])
	}
	if body[2] != 0x02 || body[3] != 0x00 {
		t.Errorf("DialectCount = %X %X, want 02 00", body[2], body[3])
	}
	if body[4] != 0x01 {
		t.Errorf("SecurityMode = %X", body[4])
	}
	// Capabilities = 0x03
	caps := binary.LittleEndian.Uint32(body[8:12])
	if caps != 0x03 {
		t.Errorf("Capabilities = %X, want 03", caps)
	}
	// Dialects at offset 36
	if body[36] != 0x02 || body[37] != 0x02 {
		t.Errorf("Dialect[0] = %X %X", body[36], body[37])
	}
	if body[38] != 0x11 || body[39] != 0x03 {
		t.Errorf("Dialect[1] = %X %X", body[38], body[39])
	}
}

// TestBuildSMB2Header verifies SMB2 header fields.
func TestBuildSMB2Header(t *testing.T) {
	hdr := buildSMB2Header(CmdRead, 1, 0, 0, 42, 7, 0xABCDEF)
	if len(hdr) != 64 {
		t.Errorf("header len = %d, want 64", len(hdr))
	}
	pid := uint32(hdr[0])<<24 | uint32(hdr[1])<<16 | uint32(hdr[2])<<8 | uint32(hdr[3])
	if pid != SMB2ProtocolID {
		t.Errorf("ProtocolId = %X, want FE534D42", pid)
	}
	ss := binary.LittleEndian.Uint16(hdr[4:6])
	if ss != 64 {
		t.Errorf("StructureSize = %d, want 64", ss)
	}
	cc := binary.LittleEndian.Uint16(hdr[6:8])
	if cc != 1 {
		t.Errorf("CreditCharge = %d, want 1", cc)
	}
	cmd := binary.LittleEndian.Uint16(hdr[12:14])
	if cmd != CmdRead {
		t.Errorf("Command = %X, want %X", cmd, CmdRead)
	}
	msgID := binary.LittleEndian.Uint64(hdr[24:32])
	if msgID != 42 {
		t.Errorf("MessageId = %d, want 42", msgID)
	}
	treeID := binary.LittleEndian.Uint32(hdr[36:40])
	if treeID != 7 {
		t.Errorf("TreeId = %d, want 7", treeID)
	}
	sid := binary.LittleEndian.Uint64(hdr[40:48])
	if sid != 0xABCDEF {
		t.Errorf("SessionId = %X, want ABCDEF", sid)
	}
}

// TestBuildNBSSHeader_LargeLength verifies NBSS length > 255.
func TestBuildNBSSHeader_LargeLength(t *testing.T) {
	h := buildNBSSHeader(0x010203)
	if h[0] != 0x00 {
		t.Errorf("NBSS type = %X", h[0])
	}
	if h[1] != 0x01 || h[2] != 0x02 || h[3] != 0x03 {
		t.Errorf("NBSS length = %X %X %X, want 01 02 03", h[1], h[2], h[3])
	}
}

// TestAlign8_AlreadyAligned verifies 8-byte alignment of aligned input.
func TestAlign8_AlreadyAligned(t *testing.T) {
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(i)
	}
	out := align8(b)
	if len(out) != 16 {
		t.Errorf("aligned len = %d, want 16", len(out))
	}
}

// TestCreditChargeFor_SMB3_0_2 verifies SMB3.0.2 credit.
func TestCreditChargeFor_SMB3_0_2(t *testing.T) {
	if creditChargeFor(DialectSMB3_02) != 1 {
		t.Errorf("SMB3.0.2 CreditCharge should be 1")
	}
}

// TestParsePDU_NoNBSS verifies parsing without NBSS header.
func TestParsePDU_NoNBSS(t *testing.T) {
	hdr := buildSMB2Header(CmdCreate, 1, 0, 0, 1, 0, 0)
	body := buildCreateRequestBody(2, 0x00120089, 0x80, 0x07, 1, 0, "test.txt")
	pdu := append(hdr, body...)
	parsed, err := ParsePDU(pdu, false)
	if err != nil {
		t.Fatalf("ParsePDU: %v", err)
	}
	if parsed.Command != CmdCreate {
		t.Errorf("Command = %X, want %X", parsed.Command, CmdCreate)
	}
	if parsed.NBSSLength != 0 {
		t.Errorf("NBSSLength = %d, want 0", parsed.NBSSLength)
	}
}

// TestBuildNegotiateResponseBody verifies NEGOTIATE response fields.
func TestBuildNegotiateResponseBody(t *testing.T) {
	var guid [16]byte
	for i := range guid {
		guid[i] = byte(i + 1)
	}
	body := buildNegotiateResponseBody(0x0311, 0x01, guid, 0x03, 65536, 1048576, 1048576, []byte{0x01, 0x02})
	if len(body) < 64 {
		t.Fatal("body too short")
	}
	if body[0] != 0x41 || body[1] != 0x00 {
		t.Errorf("StructureSize = %X %X, want 41 00", body[0], body[1])
	}
	if body[2] != 0x01 {
		t.Errorf("SecurityMode = %X", body[2])
	}
	dialect := binary.LittleEndian.Uint16(body[4:6])
	if dialect != 0x0311 {
		t.Errorf("DialectRevision = %X, want 0311", dialect)
	}
	maxTransact := binary.LittleEndian.Uint32(body[28:32])
	if maxTransact != 65536 {
		t.Errorf("MaxTransactSize = %d, want 65536", maxTransact)
	}
	secOffset := binary.LittleEndian.Uint16(body[56:58])
	if secOffset != 128 {
		t.Errorf("SecurityBufferOffset = %d, want 128", secOffset)
	}
}

// TestBuildSessionSetupRequestBody_PreviousSessionId verifies reconnection.
func TestBuildSessionSetupRequestBody_PreviousSessionId(t *testing.T) {
	body := buildSessionSetupRequestBody(0, 0x01, 0x01, 0, []byte{0x01}, 0x1234567890ABCDEF)
	if len(body) < 24 {
		t.Fatal("body too short")
	}
	prev := binary.LittleEndian.Uint64(body[16:24])
	if prev != 0x1234567890ABCDEF {
		t.Errorf("PreviousSessionId = %X, want 1234567890ABCDEF", prev)
	}
}

// TestBuildTreeConnectRequestBody_SharePath verifies IPC path.
func TestBuildTreeConnectRequestBody_SharePath(t *testing.T) {
	body := buildTreeConnectRequestBody("\\\\server\\IPC$")
	if len(body) < 8 {
		t.Fatal("body too short")
	}
	plen := binary.LittleEndian.Uint16(body[6:8])
	// "\\\\server\\IPC$" = 13 chars = 26 bytes UTF-16LE
	if plen != 26 {
		t.Errorf("PathLength = %d, want 26", plen)
	}
}

// TestBuildCreateRequestBody_AccessMask verifies access mask.
func TestBuildCreateRequestBody_AccessMask(t *testing.T) {
	body := buildCreateRequestBody(2, 0x12345678, 0x80, 0x07, 1, 0, "x")
	if len(body) < 56 {
		t.Fatal("body too short")
	}
	mask := binary.LittleEndian.Uint32(body[24:28])
	if mask != 0x12345678 {
		t.Errorf("DesiredAccess = %X, want 12345678", mask)
	}
}

// TestBuildIOCTLRequestBody_InputBuffer verifies input buffer append.
func TestBuildIOCTLRequestBody_InputBuffer(t *testing.T) {
	var fid [16]byte
	input := []byte{0xCA, 0xFE}
	body := buildIOCTLRequestBody(0x00060194, fid, input)
	if len(body) < 56+2 {
		t.Fatal("body too short")
	}
	if body[56] != 0xCA || body[57] != 0xFE {
		t.Errorf("InputBuffer = %X %X, want CA FE", body[56], body[57])
	}
}
