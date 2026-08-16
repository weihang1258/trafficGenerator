// Package tds: builder_response.go — server-response token builders
// (spec §3.7-3.14) used by tests to synthesize TDS responses. The planner
// emits both client requests and simulated server responses so the test
// harness can assert against a complete byte stream.
package tds

import (
	"encoding/binary"
	"fmt"
)

// ColMetadataColumn describes one ColumnData entry (spec §3.7).
type ColMetadataColumn struct {
	UserType uint32
	Flags    uint16
	TypeInfo []byte
	ColName  string
}

// BuildColMetadata builds the COLMETADATA token (spec §3.7).
func BuildColMetadata(cols []ColMetadataColumn, noMetaData bool) []byte {
	if noMetaData {
		return []byte{TokenColMetadata, 0xFF, 0xFF}
	}
	var body []byte
	body = append(body, TokenColMetadata)
	cnt := make([]byte, 2)
	binary.LittleEndian.PutUint16(cnt, uint16(len(cols)))
	body = append(body, cnt...)
	for _, c := range cols {
		ut := make([]byte, 4)
		binary.LittleEndian.PutUint32(ut, c.UserType)
		body = append(body, ut...)
		fl := make([]byte, 2)
		binary.LittleEndian.PutUint16(fl, c.Flags)
		body = append(body, fl...)
		body = append(body, c.TypeInfo...)
		body = append(body, bVarChar(c.ColName)...)
	}
	return body
}

// BuildRow builds the ROW token (spec §3.8). cellData is the concatenation
// of each column's TYPE_VARBYTE-encoded value in declaration order.
func BuildRow(cellData []byte) []byte {
	return append([]byte{TokenRow}, cellData...)
}

// BuildNbcRow builds the NBCROW token (spec §3.8). nullBitmap is the
// null-bitmap (1 bit per column, LSB order, ceiling to bytes). cellData
// contains only the non-NULL columns in declaration order.
func BuildNbcRow(nullBitmap, cellData []byte) []byte {
	out := make([]byte, 1+len(nullBitmap)+len(cellData))
	out[0] = TokenNbcRow
	copy(out[1:], nullBitmap)
	copy(out[1+len(nullBitmap):], cellData)
	return out
}

// BuildDone builds a DONE/DONEPROC/DONEINPROC token (spec §3.9). token must
// be one of TokenDone(0xFD)/TokenDoneProc(0xFE)/TokenDoneInProc(0xFF).
// rowCount8B=true emits the 8B (TDS 7.2+) form; false emits 4B (TDS 7.1).
func BuildDone(token byte, status uint16, curCmd uint16, rowCount int64, rowCount8B bool) ([]byte, error) {
	if token != TokenDone && token != TokenDoneProc && token != TokenDoneInProc {
		return nil, fmt.Errorf("invalid done token 0x%02x", token)
	}
	var out []byte
	out = append(out, token)
	st := make([]byte, 2)
	binary.LittleEndian.PutUint16(st, status)
	out = append(out, st...)
	cc := make([]byte, 2)
	binary.LittleEndian.PutUint16(cc, curCmd)
	out = append(out, cc...)
	if rowCount8B {
		rc := make([]byte, 8)
		binary.LittleEndian.PutUint64(rc, uint64(rowCount))
		out = append(out, rc...)
	} else {
		rc := make([]byte, 4)
		binary.LittleEndian.PutUint32(rc, uint32(rowCount))
		out = append(out, rc...)
	}
	return out, nil
}

// BuildEnvChange builds an ENVCHANGE token (spec §3.10). Type is the 1-byte
// env-change type; newValue/oldValue are the raw EnvValueData payloads
// (caller encodes the B_VARCHAR/B_VARBYTE wrapper).
func BuildEnvChange(typ byte, newValue, oldValue []byte) []byte {
	payload := append([]byte{typ}, newValue...)
	payload = append(payload, oldValue...)
	var out []byte
	out = append(out, TokenEnvChange)
	l := make([]byte, 2)
	binary.LittleEndian.PutUint16(l, uint16(len(payload)))
	out = append(out, l...)
	out = append(out, payload...)
	return out
}

// EnvChangeTranValue encodes the B_VARBYTE form for ENVCHANGE Type 8/9/10
// (spec §3.10): 1B length(0x08) + 8B TransactionID LE.
func EnvChangeTranValue(txnID uint64) []byte {
	out := make([]byte, 9)
	out[0] = 8
	binary.LittleEndian.PutUint64(out[1:], txnID)
	return out
}

// EnvChangeEmptyValue is the %x00 form (empty OldValue or NewValue for
// types 8/9/10).
func EnvChangeEmptyValue() []byte { return []byte{0} }

// EnvChangeBVarChar encodes a B_VARCHAR ENVCHANGE value (Type 1/2/4/etc).
func EnvChangeBVarChar(s string) []byte { return bVarChar(s) }

// BuildErrorInfo builds an ERROR or INFO token (spec §3.11). token must be
// TokenError(0xAA) or TokenInfo(0xAB). lineNumber8B=true emits the 4B form
// (TDS 7.2+); false emits 2B (TDS 7.1).
func BuildErrorInfo(token byte, number int32, state, class byte, msgText, serverName, procName string,
	lineNumber int64, lineNumber8B bool) ([]byte, error) {
	if token != TokenError && token != TokenInfo {
		return nil, fmt.Errorf("invalid error/info token 0x%02x", token)
	}
	msgUCS := encodeUTF16(msgText)
	var inner []byte
	inner = append(inner, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(inner[0:4], uint32(number))
	inner = append(inner, state, class)
	ml := make([]byte, 2)
	binary.LittleEndian.PutUint16(ml, uint16(len(msgUCS)/2))
	inner = append(inner, ml...)
	inner = append(inner, msgUCS...)
	inner = append(inner, bVarChar(serverName)...)
	inner = append(inner, bVarChar(procName)...)
	if lineNumber8B {
		ln := make([]byte, 4)
		binary.LittleEndian.PutUint32(ln, uint32(lineNumber))
		inner = append(inner, ln...)
	} else {
		ln := make([]byte, 2)
		binary.LittleEndian.PutUint16(ln, uint16(lineNumber))
		inner = append(inner, ln...)
	}
	out := []byte{token}
	l := make([]byte, 2)
	binary.LittleEndian.PutUint16(l, uint16(len(inner)))
	out = append(out, l...)
	out = append(out, inner...)
	return out, nil
}

// BuildLoginAck builds the LOGINACK token (spec §3.12). tdsVersion is the
// server→client form: for TDS 7.4 the wire bytes are `74 00 00 04` (BE form
// of 0x74000004 per spec footnote 72 — opposite direction from LOGIN7).
func BuildLoginAck(interfaceByte byte, tdsVersion uint32, progName string, progVersion uint32) []byte {
	pn := bVarChar(progName)
	inner := []byte{interfaceByte}
	ver := make([]byte, 4)
	// Server→client TDSVersion: the 32-bit logical value is written in BE
	// on the wire (spec footnote 72 "Server to client" column). So we emit
	// the 4 bytes in big-endian order of the logical version constant.
	ver[0] = byte(tdsVersion >> 24)
	ver[1] = byte(tdsVersion >> 16)
	ver[2] = byte(tdsVersion >> 8)
	ver[3] = byte(tdsVersion)
	inner = append(inner, ver...)
	inner = append(inner, pn...)
	pv := make([]byte, 4)
	binary.LittleEndian.PutUint32(pv, progVersion)
	inner = append(inner, pv...)
	out := []byte{TokenLoginAck}
	l := make([]byte, 2)
	binary.LittleEndian.PutUint16(l, uint16(len(inner)))
	out = append(out, l...)
	out = append(out, inner...)
	return out
}

// BuildReturnStatus builds the RETURNSTATUS token (spec §3.13).
func BuildReturnStatus(value int32) []byte {
	out := make([]byte, 5)
	out[0] = TokenReturnStatus
	binary.LittleEndian.PutUint32(out[1:], uint32(value))
	return out
}

// --- TableResponse wrapper ---

// BuildTableResponsePacket wraps a token stream in a Type=0x04 packet
// (spec §3.16). tokens is the concatenated token bytes.
func BuildTableResponsePacket(tokens []byte, spid uint16, packetID byte) []byte {
	totalLen := 8 + len(tokens)
	h := PacketHeader(TypeTabularResult, StatusEOM, totalLen, spid, packetID, 0)
	out := make([]byte, totalLen)
	copy(out[:8], h[:])
	copy(out[8:], tokens)
	return out
}

// BuildTableResponsePackets wraps a full Type=0x04 response packet, splitting
// the message into packetSize-bounded packets when it exceeds the negotiated
// packet size (MS-TDS §2.2.3.2 multi-packet messages; T-148). Intermediate
// packets carry Status=0x00 and only the final packet has StatusEOM; packet
// IDs increment mod 256. A packet that fits is returned unchanged.
func BuildTableResponsePackets(packet []byte, packetSize int) [][]byte {
	if packetSize <= 0 || len(packet) <= packetSize {
		return [][]byte{packet}
	}
	spid := binary.LittleEndian.Uint16(packet[4:6])
	pid := packet[6]
	tokens := packet[8:]
	maxPayload := packetSize - 8
	if maxPayload < 1 {
		return [][]byte{packet}
	}
	var out [][]byte
	remaining := tokens
	for len(remaining) > 0 {
		n := len(remaining)
		if n > maxPayload {
			n = maxPayload
		}
		chunk := remaining[:n]
		remaining = remaining[n:]
		status := byte(StatusEOM)
		if len(remaining) > 0 {
			status = 0x00
		}
		totalLen := 8 + len(chunk)
		h := PacketHeader(TypeTabularResult, status, totalLen, spid, pid, 0)
		pkt := make([]byte, totalLen)
		copy(pkt[:8], h[:])
		copy(pkt[8:], chunk)
		out = append(out, pkt)
		pid = (pid + 1) & 0xFF
	}
	return out
}

// DefaultCollationBytes returns the 5-byte default collation (spec §2.4.5).
func DefaultCollationBytes() [5]byte { return DefaultCollation }
