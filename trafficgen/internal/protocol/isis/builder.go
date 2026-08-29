package isis

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// IS-IS (ISO 10589) wire constants.
const (
	// Common header.
	nlpid       = 0x83 // Intradomain Routing Protocol Discriminator
	headerLen   = 0x08 // Length Indicator (8)
	version     = 0x01 // Version/Protocol ID Extension
	idLength    = 0x06 // System ID length
	version2    = 0x01 // Version
	reserved    = 0x00
	maxAreaAddr = 0x00 // Maximum Area Addresses (0 means 3)

	// PDU types (ISO 10589).
	pduTypeLANIIHL1 = 0x0f // L1 LAN IIH (15)
	pduTypeLANIIHL2 = 0x10 // L2 LAN IIH (16)
	pduTypeLSPL1    = 0x12 // L1 LSP (18)
	pduTypeLSPL2    = 0x14 // L2 LSP (20)
	pduTypeCSNPL1   = 0x18 // L1 CSNP (24)
	pduTypeCSNPL2   = 0x19 // L2 CSNP (25)
	pduTypePSNPL1   = 0x1a // L1 PSNP (26)
	pduTypePSNPL2   = 0x1b // L2 PSNP (27)

	circuitTypeL1 = 0x01
	circuitTypeL2 = 0x02

	llcDSAP    = 0xfe
	llcSSAP    = 0xfe
	llcControl = 0x03

	// minLLCPayload is the IEEE 802.3 minimum data field (bytes after the
	// 14-byte MAC header) — LLC(3) + PDU padded to at least 46 bytes so real
	// NICs accept the frame. The 802.3 Length field is this value.
	minLLCPayload = 46
)

// parseSystemID parses a System ID given as "xxxx.xxxx.xxxx" or 12 hex digits
// (6 bytes). Returns the 6-byte ID.
func parseSystemID(s string) ([]byte, error) {
	clean := strings.ReplaceAll(s, ".", "")
	if len(clean) != 12 {
		return nil, fmt.Errorf("system id %q must be 6 bytes (12 hex digits)", s)
	}
	b := make([]byte, 6)
	for i := 0; i < 6; i++ {
		v, err := hexByte(clean[2*i : 2*i+2])
		if err != nil {
			return nil, fmt.Errorf("system id %q: %v", s, err)
		}
		b[i] = v
	}
	return b, nil
}

// hexByte converts a 2-hex-char string to a byte.
func hexByte(s string) (byte, error) {
	if len(s) != 2 {
		return 0, fmt.Errorf("invalid hex byte %q", s)
	}
	hi, ok := hexVal(s[0])
	if !ok {
		return 0, fmt.Errorf("invalid hex byte %q", s)
	}
	lo, ok := hexVal(s[1])
	if !ok {
		return 0, fmt.Errorf("invalid hex byte %q", s)
	}
	return hi<<4 | lo, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// parseHexSpace parses a space-separated hex byte string like "03 49 00 01".
func parseHexSpace(s string) ([]byte, error) {
	parts := strings.Fields(s)
	b := make([]byte, 0, len(parts))
	for _, p := range parts {
		v, err := hexByte(p)
		if err != nil {
			return nil, err
		}
		b = append(b, v)
	}
	return b, nil
}

// encodeTLVs appends type(1)+length(1)+value for each TLV.
func encodeTLVs(tlvs []core.ISISTLV) []byte {
	var out []byte
	for _, t := range tlvs {
		v, err := parseHexSpace(t.ValueHex)
		if err != nil {
			continue // invalid TLV value: skip (validator rejects earlier)
		}
		out = append(out, byte(t.Type), byte(len(v)))
		out = append(out, v...)
	}
	return out
}

// commonHeader builds the 8-byte IS-IS common header with the given PDU type.
// hdrLen is the Length Indicator value (ISO 10589 §9.1): the total byte count of
// the fixed header fields including the common 8-byte header. Each PDU type has
// a different fixed header size, so hdrLen must be passed explicitly.
func commonHeader(pduType byte, hdrLen byte) []byte {
	return []byte{nlpid, hdrLen, version, idLength, pduType, version2, reserved, maxAreaAddr}
}

// parseLANID parses a LAN ID as "xxxx.xxxx.xxxx.xx" or 14 hex digits
// (7 bytes: system id 6 + circuit id 1).
func parseLANID(s string) ([]byte, error) {
	clean := strings.ReplaceAll(s, ".", "")
	if len(clean) != 14 {
		return nil, fmt.Errorf("lan_id %q must be 7 bytes (14 hex digits)", s)
	}
	b := make([]byte, 7)
	for i := 0; i < 7; i++ {
		v, err := hexByte(clean[2*i : 2*i+2])
		if err != nil {
			return nil, fmt.Errorf("lan_id %q: %v", s, err)
		}
		b[i] = v
	}
	return b, nil
}

// iiHFixedHeaderLen is the total IS-IS LAN IIH fixed header length for the
// Length Indicator byte.  The fixed header spans the 8-byte common header
// plus 19 IIH-specific bytes (circuit_type + source_id(6) + holding_timer(2)
// + pdu_length(2) + priority(1) + lan_id(7)), totaling 27 bytes.
const iiHFixedHeaderLen byte = 27 // 8 + 1 + 6 + 2 + 2 + 1 + 7

// lspFixedHeaderLen is the total IS-IS LSP fixed header length for the
// Length Indicator byte. The fixed header spans the 8-byte common header plus
// 19 LSP-specific bytes (pdu_length(2) + remaining_life(2) + lsp_id(8) +
// sequence_number(4) + checksum(2) + type_block(1)), totaling 27 bytes
// (Wireshark 3.6.14 packet-isis-lsp.c dissect_isis_lsp).
const lspFixedHeaderLen byte = 27 // 8 + 2 + 2 + 8 + 4 + 2 + 1

// csnpFixedHeaderLen is the total IS-IS CSNP fixed header length for the
// Length Indicator byte. The fixed header spans the 8-byte common header plus
// 25 CSNP-specific bytes (pdu_length(2) + source_id(6) + source_circuit(1) +
// start_lsp_id(8) + end_lsp_id(8)), totaling 33 bytes (Wireshark 3.6.14
// packet-isis-snp.c dissect_isis_csnp).
const csnpFixedHeaderLen byte = 33 // 8 + 2 + 6 + 1 + 8 + 8

// psnpFixedHeaderLen is the total IS-IS PSNP fixed header length for the
// Length Indicator byte. The fixed header spans the 8-byte common header plus
// 9 PSNP-specific bytes (pdu_length(2) + source_id(6) + source_circuit(1)),
// totaling 17 bytes (Wireshark 3.6.14 packet-isis-snp.c dissect_isis_psnp).
const psnpFixedHeaderLen byte = 17 // 8 + 2 + 6 + 1

// buildIIH builds a LAN IIH PDU (Type 15/16). The Length Indicator is set
// to iiHFixedHeaderLen (27) so tshark's hello subdissector fully decodes the
// PDU without expert errors.
func buildIIH(level string, systemID string, holdingTimer, priority int, lanID string, tlvs []core.ISISTLV) ([]byte, error) {
	pduType, circuitType := pduTypeForIIH(level)
	sid, err := parseSystemID(systemID)
	if err != nil {
		return nil, err
	}
	lan, err := parseLANID(lanID)
	if err != nil {
		return nil, err
	}
	tlv := encodeTLVs(tlvs)
	// Fixed fields: Circuit Type(1) + Source ID(6) + Holding Timer(2) +
	// PDU Length(2) + Priority(1) + LAN ID(7) = 19 bytes after common header,
	// already included in iiHFixedHeaderLen (27). pduLen = fixed header + TLVs.
	pduLen := int(iiHFixedHeaderLen) + len(tlv)
	pdu := commonHeader(pduType, iiHFixedHeaderLen)
	pdu = append(pdu, byte(circuitType))
	pdu = append(pdu, sid...)
	pdu = binary.BigEndian.AppendUint16(pdu, uint16(holdingTimer))
	pdu = binary.BigEndian.AppendUint16(pdu, uint16(pduLen))
	pdu = append(pdu, byte(priority))
	pdu = append(pdu, lan...)
	pdu = append(pdu, tlv...)
	if len(pdu) != pduLen {
		return nil, fmt.Errorf("IIH length mismatch: got %d want %d", len(pdu), pduLen)
	}
	return pdu, nil
}

// pduTypeForIIH returns the PDU type byte and circuit type for the level.
func pduTypeForIIH(level string) (byte, byte) {
	if level == "l2" {
		return pduTypeLANIIHL2, circuitTypeL2
	}
	return pduTypeLANIIHL1, circuitTypeL1
}

// buildLSP builds an LSP PDU (Type 18/20). checksum is computed over the
// PDU per ISO 10589 §8.2.3 (Fletcher-16, starting at the LSP ID, excluding
// the checksum field; remaining lifetime is NOT excluded from the sum).
func buildLSP(level string, lspID string, remainingLifetime, sequence, partition, circuitType int, tlvs []core.ISISTLV, checksumMode string) ([]byte, error) {
	pduType := pduTypeForLSP(level)
	lspid, err := parseLSPID(lspID)
	if err != nil {
		return nil, err
	}
	ct := circuitType
	if ct == 0 {
		ct = circuitTypeForLevel(level)
	}
	// The IS-IS type block is ONE byte after the checksum: bit 7 = Partition
	// Repair (P), bits 1-0 = IS type (1=L1, 2=L2, 3=L1/L2). The other bits
	// (Attachment, Overload) default to 0. partition maps to bit 7; the IS
	// type maps to the low 2 bits — the builder's `circuitType` argument is
	// the IS type value (l1→1, l2→2), NOT the circuit-type bit (1/2).
	typeBlock := byte(partition&0x01)<<7 | byte(ct&0x03)
	tlv := encodeTLVs(tlvs)
	// Fixed fields after common header: PDU Length(2) + Remaining Lifetime(2)
	// + LSP ID(8) + Sequence Number(4) + Checksum(2) + Type Block(1) =
	// 19 bytes, already included in lspFixedHeaderLen (27).
	pduLen := int(lspFixedHeaderLen) + len(tlv)
	pdu := commonHeader(pduType, lspFixedHeaderLen)
	pdu = binary.BigEndian.AppendUint16(pdu, uint16(pduLen))
	pdu = binary.BigEndian.AppendUint16(pdu, uint16(remainingLifetime))
	pdu = append(pdu, lspid...)
	pdu = binary.BigEndian.AppendUint32(pdu, uint32(sequence))
	pdu = binary.BigEndian.AppendUint16(pdu, 0) // checksum placeholder
	pdu = append(pdu, typeBlock)
	pdu = append(pdu, tlv...)
	if len(pdu) != pduLen {
		return nil, fmt.Errorf("LSP length mismatch: got %d want %d", len(pdu), pduLen)
	}
	// Compute Fletcher-16 checksum.
	ck := osiFletcherChecksum(pdu, 12, pduLen-12, 24)
	binary.BigEndian.PutUint16(pdu[24:26], ck)
	return pdu, nil
}

// pduTypeForLSP returns the PDU type byte for the level.
func pduTypeForLSP(level string) byte {
	if level == "l2" {
		return pduTypeLSPL2
	}
	return pduTypeLSPL1
}

func circuitTypeForLevel(level string) int {
	if level == "l2" {
		return circuitTypeL2
	}
	return circuitTypeL1
}

// parseLSPID parses an LSP ID given as 16 hex digits (8 bytes:
// system id 6 + pseudonode 1 + fragment 1).
func parseLSPID(s string) ([]byte, error) {
	clean := strings.ReplaceAll(s, ".", "")
	if len(clean) != 16 {
		return nil, fmt.Errorf("lsp_id %q must be 8 bytes (16 hex digits)", s)
	}
	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		v, err := hexByte(clean[2*i : 2*i+2])
		if err != nil {
			return nil, fmt.Errorf("lsp_id %q: %v", s, err)
		}
		b[i] = v
	}
	return b, nil
}

// buildCSNP builds a CSNP PDU (Type 24/25).
func buildCSNP(level string, systemID string, startLSPID, endLSPID string, tlvs []core.ISISTLV) ([]byte, error) {
	pduType := pduTypeForCSNP(level)
	sid, err := parseSystemID(systemID)
	if err != nil {
		return nil, err
	}
	start, err := parseLSPID(startLSPID)
	if err != nil {
		return nil, err
	}
	end, err := parseLSPID(endLSPID)
	if err != nil {
		return nil, err
	}
	tlv := encodeTLVs(tlvs)
	// Fixed: PDU Length(2) + Source ID(6) + Source Circuit(1) +
	// Start LSP ID(8) + End LSP ID(8) = 25, already included in
	// csnpFixedHeaderLen (33).
	pduLen := int(csnpFixedHeaderLen) + len(tlv)
	pdu := commonHeader(pduType, csnpFixedHeaderLen)
	pdu = binary.BigEndian.AppendUint16(pdu, uint16(pduLen))
	pdu = append(pdu, sid...)
	pdu = append(pdu, 0x00) // Source Circuit ID (zero per ISO 10589:2002 9.10)
	pdu = append(pdu, start...)
	pdu = append(pdu, end...)
	pdu = append(pdu, tlv...)
	if len(pdu) != pduLen {
		return nil, fmt.Errorf("CSNP length mismatch: got %d want %d", len(pdu), pduLen)
	}
	return pdu, nil
}

func pduTypeForCSNP(level string) byte {
	if level == "l2" {
		return pduTypeCSNPL2
	}
	return pduTypeCSNPL1
}

// buildPSNP builds a PSNP PDU (Type 26/27).
func buildPSNP(level string, systemID string, tlvs []core.ISISTLV) ([]byte, error) {
	pduType := pduTypeForPSNP(level)
	sid, err := parseSystemID(systemID)
	if err != nil {
		return nil, err
	}
	tlv := encodeTLVs(tlvs)
	// Fixed: PDU Length(2) + Source ID(6) + Source Circuit(1) = 9, already
	// included in psnpFixedHeaderLen (17).
	pduLen := int(psnpFixedHeaderLen) + len(tlv)
	pdu := commonHeader(pduType, psnpFixedHeaderLen)
	pdu = binary.BigEndian.AppendUint16(pdu, uint16(pduLen))
	pdu = append(pdu, sid...)
	pdu = append(pdu, 0x00) // Source Circuit ID (zero per ISO 10589:2002 9.10)
	pdu = append(pdu, tlv...)
	if len(pdu) != pduLen {
		return nil, fmt.Errorf("PSNP length mismatch: got %d want %d", len(pdu), pduLen)
	}
	return pdu, nil
}

func pduTypeForPSNP(level string) byte {
	if level == "l2" {
		return pduTypePSNPL2
	}
	return pduTypePSNPL1
}

// pduTypeForString maps the config pdu_type string to a wire PDU type byte
// given the level.
func pduTypeForString(pduType, level string) (byte, error) {
	switch pduType {
	case "lan_hello", "lan_hello_iih":
		t, _ := pduTypeForIIH(level)
		return t, nil
	case "lsp":
		return pduTypeForLSP(level), nil
	case "csnp":
		return pduTypeForCSNP(level), nil
	case "psnp":
		return pduTypeForPSNP(level), nil
	}
	return 0, fmt.Errorf("unsupported pdu_type %q", pduType)
}

// osiFletcherChecksum implements Wireshark's osi_check_and_get_checksum
// (the ISO 10589 Fletcher-16 LSP checksum). data is the full PDU; offset is
// the byte where the checksummed range starts (the LSP ID); length is the
// checksummed length (pdu_length - 12); offsetCheck is the absolute position
// of the 2-byte checksum field. Returns the 16-bit checksum.
func osiFletcherChecksum(data []byte, offset, length, offsetCheck int) uint16 {
	p := data[offset : offset+length]
	oc := offsetCheck - offset
	var c0, c1 uint32
	block := oc / 5803
	idx := 0
	initlen := length
	discard := false
	for length != 0 {
		seglen := length
		if block == 0 {
			seglen = oc % 5803
			discard = true
		} else if seglen > 5803 {
			seglen = 5803
		} else {
			discard = false
		}
		for i := 0; i < seglen; i++ {
			c0 += uint32(p[idx])
			idx++
			c1 += c0
		}
		if discard {
			idx += 2 // skip the checksum field
			c1 += 2 * c0
			length -= 2
			discard = false
		}
		c0 %= 255
		c1 %= 255
		length -= seglen
		block--
	}
	factor := uint32(initlen-oc) * c0
	x := int64(factor) - int64(c0) - int64(c1)
	y := int64(c1) - int64(factor) - 1
	if x < 0 {
		x--
	}
	if y > 0 {
		y++
	}
	x = cMod(x, 255)
	y = cMod(y, 255)
	if x == 0 {
		x = 0xFF
	}
	if y == 0 {
		y = 0x01
	}
	return uint16(x)<<8 | uint16(y)&0xFF
}

// cMod implements C-style truncating modulo (the C `%` operator). Go's native
// `%` is already truncating toward zero, matching C, so no adjustment is needed
// for a negative dividend (unlike the floor-modulo the Python prototype used).
func cMod(a, b int64) int64 {
	return a % b
}

// llcPayloadLen returns the payload size to emit for the LLC carrier: the PDU
// padded to max(46, LLC(3) + PDU) so the 802.3 Length field carries the norm
// (IEEE 802.3 minimum data field). The core builder writes len(payload) into
// the Length field, so the payload must already include LLC(3) + padding.
func llcPayloadLen(pdu []byte) int {
	n := 3 + len(pdu)
	if n < minLLCPayload {
		n = minLLCPayload
	}
	return n
}
