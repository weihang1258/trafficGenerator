// Package tds: parser.go — TDS packet and token-stream parser (spec §4.5).
// Parses the client request side (PRELOGIN/LOGIN7/SQLBatch/RPC) for
// round-trip tests and the server response token stream (Type=0x04) for
// the response-side assertions.
package tds

import (
	"encoding/binary"
	"fmt"
)

// Packet is a parsed TDS packet header + body.
type Packet struct {
	Type     byte
	Status   byte
	Length   int
	SPID     uint16
	PacketID byte
	Window   byte
	Body     []byte
}

// ParsePacket parses an 8-byte TDS packet header + body (spec §2.1).
// Returns an error when Length < 8 or > 32767 (spec §8 V-41/V-42).
func ParsePacket(data []byte) (*Packet, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("tds: packet shorter than 8-byte header (%d bytes)", len(data))
	}
	p := &Packet{
		Type:     data[0],
		Status:   data[1],
		Length:   int(binary.BigEndian.Uint16(data[2:4])),
		SPID:     binary.BigEndian.Uint16(data[4:6]),
		PacketID: data[6],
		Window:   data[7],
	}
	if p.Length < 8 {
		return nil, fmt.Errorf("tds: invalid length %d < 8 (V-TDS-050)", p.Length)
	}
	if p.Length > 32767 {
		return nil, fmt.Errorf("tds: invalid length %d > 32767 (V-TDS-051)", p.Length)
	}
	if len(data) < p.Length {
		return nil, fmt.Errorf("tds: packet truncated: have %d bytes, header says %d", len(data), p.Length)
	}
	p.Body = data[8:p.Length]
	return p, nil
}

// --- PRELOGIN parser (spec §3.1) ---

// PreLoginResult is the parsed PRELOGIN options.
type PreLoginResult struct {
	Options map[byte][]byte
}

// ParsePreLogin parses the PRELOGIN body (spec §3.1). Option entries are
// token(1B) + offset(2B BE) + len(2B BE); the terminator is 0xFF.
func ParsePreLogin(body []byte) (*PreLoginResult, error) {
	res := &PreLoginResult{Options: make(map[byte][]byte)}
	pos := 0
	first := true
	for pos < len(body) {
		tok := body[pos]
		if tok == PLTerminator {
			// 遇 TERMINATOR 即结束选项表遍历。选项的实际数据由
			// offset/len 引用,可能位于 TERMINATOR 之后(spec §3.1:
			// "data section follows the option table"),此前强制
			// TERMINATOR 必须为最后一字节会误拒合法的 PRELOGIN
			// (CRITICAL 1)。
			break
		}
		if first && tok != PLVersion {
			return nil, fmt.Errorf("tds: PRELOGIN first option must be VERSION (A5)")
		}
		first = false
		if pos+5 > len(body) {
			return nil, fmt.Errorf("tds: PRELOGIN option table truncated")
		}
		off := int(binary.BigEndian.Uint16(body[pos+1 : pos+3]))
		l := int(binary.BigEndian.Uint16(body[pos+3 : pos+5]))
		if off+l > len(body) {
			return nil, fmt.Errorf("tds: PRELOGIN option data out of range")
		}
		res.Options[tok] = body[off : off+l]
		pos += 5
	}
	if _, ok := res.Options[PLVersion]; !ok {
		return nil, fmt.Errorf("tds: PRELOGIN response missing VERSION (A17)")
	}
	return res, nil
}

// --- LOGIN7 parser (spec §3.2) ---

// Login7Result is the parsed LOGIN7 body.
type Login7Result struct {
	TDSVersion   uint32
	PacketSize   uint32
	OptionFlags1 byte
	OptionFlags2 byte
	TypeFlags    byte
	OptionFlags3 byte
	ClientLCID   uint32
	HostName     string
	UserName     string
	Password     []byte // obfuscated
	AppName      string
	ServerName   string
	CltIntName   string
	Language     string
	Database     string
	Fields       []string
}

// ParseLogin7 parses the LOGIN7 body (spec §3.2). Requires TDS 7.2+
// (58-byte offset table). Returns the string fields (UCS-2 LE decoded).
func ParseLogin7(body []byte) (*Login7Result, error) {
	if len(body) < 36+58 {
		return nil, fmt.Errorf("tds: LOGIN7 body too short (%d bytes)", len(body))
	}
	r := &Login7Result{}
	// TDSVersion 为大端网络序 (与 BuildLogin7 保持一致；spec footnote 72)。
	r.TDSVersion = binary.BigEndian.Uint32(body[4:8])
	r.PacketSize = binary.LittleEndian.Uint32(body[8:12])
	r.OptionFlags1 = body[24]
	r.OptionFlags2 = body[25]
	r.TypeFlags = body[26]
	r.OptionFlags3 = body[27]
	r.ClientLCID = binary.LittleEndian.Uint32(body[32:36])

	// Offset table: 13 pairs (ib 2B LE + cch 2B LE) + ClientID 6B +
	// cbSSPILong 4B = 58B. We only read the pairs.
	read := func(i int) (ib, cch uint16) {
		base := 36 + i*4
		return binary.LittleEndian.Uint16(body[base : base+2]),
			binary.LittleEndian.Uint16(body[base+2 : base+4])
	}
	ibHost, cchHost := read(0)
	ibUser, cchUser := read(1)
	ibPW, cchPW := read(2)
	ibApp, cchApp := read(3)
	ibSrv, cchSrv := read(4)
	ibCltInt, cchCltInt := read(6)
	ibLang, cchLang := read(7)
	ibDB, cchDB := read(8)

	if ibHost+cchHost*2 > uint16(len(body)) || ibUser+cchUser*2 > uint16(len(body)) ||
		ibPW+cchPW*2 > uint16(len(body)) || ibApp+cchApp*2 > uint16(len(body)) ||
		ibSrv+cchSrv*2 > uint16(len(body)) || ibCltInt+cchCltInt*2 > uint16(len(body)) ||
		ibLang+cchLang*2 > uint16(len(body)) || ibDB+cchDB*2 > uint16(len(body)) {
		return nil, fmt.Errorf("tds: LOGIN7 field out of range")
	}
	dec := func(ib, cch uint16) string {
		if cch == 0 {
			return ""
		}
		raw := body[ib : ib+cch*2]
		codes := make([]uint16, cch)
		for i := range codes {
			codes[i] = binary.LittleEndian.Uint16(raw[i*2:])
		}
		return string(codesToRunes(codes))
	}
	r.HostName = dec(ibHost, cchHost)
	r.UserName = dec(ibUser, cchUser)
	r.Password = body[ibPW : ibPW+cchPW*2]
	r.AppName = dec(ibApp, cchApp)
	r.ServerName = dec(ibSrv, cchSrv)
	r.CltIntName = dec(ibCltInt, cchCltInt)
	r.Language = dec(ibLang, cchLang)
	r.Database = dec(ibDB, cchDB)
	return r, nil
}

// codesToRunes converts UTF-16 code units to a Go string.
func codesToRunes(codes []uint16) []rune {
	out := make([]rune, 0, len(codes))
	for i := 0; i < len(codes); i++ {
		c := codes[i]
		if c >= 0xD800 && c <= 0xDBFF && i+1 < len(codes) {
			lo := codes[i+1]
			if lo >= 0xDC00 && lo <= 0xDFFF {
				out = append(out, rune(0x10000+(uint32(c)-0xD800)<<10+uint32(lo)-0xDC00))
				i++
				continue
			}
		}
		out = append(out, rune(c))
	}
	return out
}

// --- SQL Batch parser (spec §3.3) ---

// ParseSQLBatch parses the SQL Batch body. Returns the SQL text. The
// ALL_HEADERS prefix (22 bytes for a single TransactionDescriptor header)
// is skipped when tds7Plus=true.
func ParseSQLBatch(body []byte, tds7Plus bool) (string, error) {
	off := 0
	if tds7Plus {
		if len(body) < 22 {
			return "", fmt.Errorf("tds: SQL Batch body too short for ALL_HEADERS")
		}
		total := int(binary.LittleEndian.Uint32(body[0:4]))
		if total < 4 || total > len(body) {
			return "", fmt.Errorf("tds: SQL Batch ALL_HEADERS total %d out of range", total)
		}
		off = total
	}
	sqlUCS := body[off:]
	if len(sqlUCS)%2 != 0 {
		return "", fmt.Errorf("tds: SQLText odd length %d (V-TDS-021)", len(sqlUCS))
	}
	codes := make([]uint16, len(sqlUCS)/2)
	for i := range codes {
		codes[i] = binary.LittleEndian.Uint16(sqlUCS[i*2:])
	}
	return string(codesToRunes(codes)), nil
}

// --- ALL_HEADERS parser (spec §2.5) ---

// AllHeadersResult is the parsed ALL_HEADERS.
type AllHeadersResult struct {
	TransactionDescriptor uint64
	OutstandingCount      uint32
	HeaderTypes           []uint16
}

// ParseAllHeaders parses the ALL_HEADERS prefix (spec §2.5).
func ParseAllHeaders(body []byte) (*AllHeadersResult, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("tds: ALL_HEADERS truncated")
	}
	total := int(binary.LittleEndian.Uint32(body[0:4]))
	if total < 4 || total > len(body) {
		return nil, fmt.Errorf("tds: ALL_HEADERS total length %d out of range", total)
	}
	res := &AllHeadersResult{}
	pos := 4
	for pos+4 <= total {
		hdrLen := int(binary.LittleEndian.Uint32(body[pos : pos+4]))
		if hdrLen < 6 || pos+hdrLen > total {
			return nil, fmt.Errorf("tds: ALL_HEADERS header length %d out of range", hdrLen)
		}
		hType := binary.LittleEndian.Uint16(body[pos+4 : pos+6])
		res.HeaderTypes = append(res.HeaderTypes, hType)
		switch hType {
		case HeaderTransactionDescriptor:
			if hdrLen < 18 {
				return nil, fmt.Errorf("tds: TransactionDescriptor header too short")
			}
			res.TransactionDescriptor = binary.LittleEndian.Uint64(body[pos+6 : pos+14])
			res.OutstandingCount = binary.LittleEndian.Uint32(body[pos+14 : pos+18])
		}
		pos += hdrLen
	}
	return res, nil
}

// --- Response token stream parser (spec §4.5) ---

// Token is one parsed token from the server response stream.
type Token struct {
	Type   byte
	Length int // valid for variable-length tokens; -1 otherwise
	Data   []byte
}

// ParseTokenStream parses a stream of response tokens. It stops at the
// first DONE-series token (DONE/DONEPROC/DONEINPROC) — the caller decides
// whether more packets follow (DONE_MORE).
func ParseTokenStream(body []byte) ([]Token, error) {
	var tokens []Token
	pos := 0
	for pos < len(body) {
		if len(body)-pos < 1 {
			return nil, fmt.Errorf("tds: token stream truncated at %d", pos)
		}
		tok := body[pos]
		pos++
		switch tok {
		case TokenDone, TokenDoneProc, TokenDoneInProc:
			// DONE: Status(2) + CurCmd(2) + RowCount(4 or 8)
			if len(body)-pos < 4 {
				return nil, fmt.Errorf("tds: DONE truncated")
			}
			// We cannot know the row-count width without a version flag;
			// default to 8B (TDS 7.2+) — the 4B (7.1) form is handled by
			// the caller-level parser when a version is known. For the
			// generic stream parser, consume 8B when available, else 4B.
			rcBytes := 8
			if len(body)-pos < 8 {
				rcBytes = 4
			}
			tokens = append(tokens, Token{Type: tok, Length: 4 + rcBytes, Data: body[pos-1 : pos+4+rcBytes]})
			pos += 4 + rcBytes
		case TokenColMetadata:
			if len(body)-pos < 2 {
				return nil, fmt.Errorf("tds: COLMETADATA truncated")
			}
			cnt := int(binary.LittleEndian.Uint16(body[pos : pos+2]))
			pos += 2
			if cnt == 0xFFFF {
				tokens = append(tokens, Token{Type: tok, Length: 2, Data: nil})
				continue
			}
			// Column data: UserType(4) + Flags(2) + TYPE_INFO + ColName(B_VARCHAR)
			for i := 0; i < cnt; i++ {
				if len(body)-pos < 6 {
					return nil, fmt.Errorf("tds: COLMETADATA column truncated")
				}
				pos += 6 // UserType + Flags
				tiLen, err := typeInfoLen(body[pos:])
				if err != nil {
					return nil, fmt.Errorf("tds: COLMETADATA TYPE_INFO: %w", err)
				}
				pos += tiLen
				if len(body)-pos < 1 {
					return nil, fmt.Errorf("tds: COLMETADATA ColName truncated")
				}
				n := int(body[pos])
				pos++
				if len(body)-pos < n*2 {
					return nil, fmt.Errorf("tds: COLMETADATA ColName out of range")
				}
				pos += n * 2
			}
			tokens = append(tokens, Token{Type: tok, Length: -1})
		case TokenRow, TokenNbcRow:
			// Row/NbcRow: variable-count; the generic parser cannot know
			// the boundary without column metadata — the caller-level
			// parser (ParseResponse) resolves it. Mark as opaque.
			tokens = append(tokens, Token{Type: tok, Length: -1})
		case TokenError, TokenInfo, TokenEnvChange, TokenLoginAck, TokenReturnValue,
			TokenSessionState, TokenOrder, TokenTabName, TokenColInfo:
			if len(body)-pos < 2 {
				return nil, fmt.Errorf("tds: token 0x%02x truncated at length field", tok)
			}
			l := int(binary.LittleEndian.Uint16(body[pos : pos+2]))
			pos += 2
			if len(body)-pos < l {
				return nil, fmt.Errorf("tds: token 0x%02x data truncated (want %d, have %d)", tok, l, len(body)-pos)
			}
			tokens = append(tokens, Token{Type: tok, Length: l, Data: body[pos : pos+l]})
			pos += l
		case TokenReturnStatus:
			if len(body)-pos < 4 {
				return nil, fmt.Errorf("tds: RETURNSTATUS truncated")
			}
			tokens = append(tokens, Token{Type: tok, Length: 4, Data: body[pos : pos+4]})
			pos += 4
		default:
			// Unknown token: classify (spec §1.6) and skip tolerantly.
			switch {
			case tok&0x40 != 0 && tok&0x20 == 0: // xx01xxxx zero-length
				tokens = append(tokens, Token{Type: tok, Length: 0})
			case tok&0x60 == 0x60: // xx11xxxx fixed-length (1/2/4/8)
				fixed := []int{1, 2, 4, 8}
				// Determine the fixed length from the token bits
				// (spec §1.6: Fixed Length Token = xx11xxxx).
				var flen int
				// The fixed data width is encoded in the low bits;
				// MS-TDS assigns 1/2/4/8 by token. Default to 4.
				flen = fixed[(tok>>2)&3]
				if len(body)-pos < flen {
					return nil, fmt.Errorf("tds: fixed token 0x%02x truncated", tok)
				}
				tokens = append(tokens, Token{Type: tok, Length: flen, Data: body[pos : pos+flen]})
				pos += flen
			case tok&0x20 != 0: // xx10xxxx variable-length: 2B length
				if len(body)-pos < 2 {
					return nil, fmt.Errorf("tds: variable token 0x%02x truncated", tok)
				}
				l := int(binary.LittleEndian.Uint16(body[pos : pos+2]))
				pos += 2
				if len(body)-pos < l {
					return nil, fmt.Errorf("tds: variable token 0x%02x data truncated", tok)
				}
				tokens = append(tokens, Token{Type: tok, Length: l, Data: body[pos : pos+l]})
				pos += l
			default: // xx00xxxx variable-count: 2B count
				if len(body)-pos < 2 {
					return nil, fmt.Errorf("tds: count token 0x%02x truncated", tok)
				}
				cnt := int(binary.LittleEndian.Uint16(body[pos : pos+2]))
				pos += 2
				// Cannot know per-entry size; skip 2-byte entries
				// heuristically, then stop scanning if the remaining
				// bytes look like another token. For robustness we skip
				// 2*cnt bytes (best effort).
				skip := 2 * cnt
				if len(body)-pos < skip {
					skip = len(body) - pos
				}
				tokens = append(tokens, Token{Type: tok, Length: skip, Data: body[pos : pos+skip]})
				pos += skip
			}
		}
	}
	return tokens, nil
}

// typeInfoLen returns the byte length of a TYPE_INFO field (spec §2.4.5).
func typeInfoLen(b []byte) (int, error) {
	if len(b) < 1 {
		return 0, fmt.Errorf("empty TYPE_INFO")
	}
	t := b[0]
	switch t {
	// Fixed-length types: no TYPE_VARLEN.
	case TypeInt1, TypeBit, TypeInt2, TypeInt4, TypeDateTime4, TypeFloat4,
		TypeMoney, TypeDateTime, TypeFloat8, TypeMoney4, TypeInt8,
		TypeDecimal, TypeNumeric, TypeNull:
		return 1, nil
	// BYTELEN types with length prefix (1B).
	case TypeGUID, TypeIntN, TypeBitN,
		TypeFloatN, TypeMoneyN, TypeDateTimeN, TypeChar, TypeVarChar,
		TypeBinary, TypeVarBinary:
		if len(b) < 2 {
			return 0, fmt.Errorf("truncated BYTELEN type")
		}
		return 2, nil
	// HIGH 1: DECIMALN/NUMERICN 的 TYPE_INFO 为 type(1B) + maxlen(1B) +
	// precision(1B) + scale(1B) = 4 字节 (spec §2.4.5 表 "DECIMALN" 行:
	// "TYPE_VARLEN: 1B maxlen, 1B precision, 1B scale")。此前被错误归入
	// 普通 BYTELEN 分支返回 2,丢失 precision/scale,导致 COLMETADATA 列
	// TYPE_INFO 长度算少 2 字节,后续 ColName 偏移错位。
	case TypeDecimalN, TypeNumericN:
		if len(b) < 4 {
			return 0, fmt.Errorf("truncated DECIMALN/NUMERICN type")
		}
		return 4, nil
	// Date: 3B value, no TYPE_VARLEN.
	case TypeDate:
		return 1, nil
	// Time/DateTime2/DateTimeOffset: SCALE 1B.
	case TypeTime, TypeDateTime2, TypeDateTimeOff:
		return 2, nil
	// USHORTLEN types: 2B maxlen (+5B collation for char types).
	case TypeBigVarBin, TypeBigVarChar, TypeBigBinary, TypeBigChar,
		TypeNVarChar, TypeNChar:
		if len(b) < 3 {
			return 0, fmt.Errorf("truncated USHORTLEN type")
		}
		// char family has collation
		switch t {
		case TypeBigVarChar, TypeBigChar, TypeNVarChar, TypeNChar:
			return 8, nil // 1 + 2 + 5 collation
		default:
			return 3, nil
		}
	// LONGLEN types: 4B len prefix.
	case TypeImage, TypeNText, TypeSSVariant, TypeText:
		return 5, nil
	// PLP types (XML/JSON/UDT/MAX): 1B token only (no USHORTMAXLEN for
	// XML/UDT/JSON; varchar(max) has 0xFFFF which is inside the 2B maxlen).
	case TypeXML, TypeJSON, TypeUDT:
		return 1, nil
	case TypeVector:
		// Vector: SCALE (1B) follows.
		return 2, nil
	default:
		return 0, fmt.Errorf("unknown type token 0x%02x", t)
	}
}

// ParseResponse parses the server response token stream with column
// metadata context (spec §4.5). It walks tokens in order, consuming ROW and
// NBCROW cells according to the current COLMETADATA column definitions.
// Rows after DONE reset the column context. Returns the parsed result.
func ParseResponse(body []byte, rowCount8B bool, version TDSVersion) (*ResponseResult, error) {
	res := &ResponseResult{}
	var cols []ColMetadataColumn
	pos := 0
	for pos < len(body) {
		if pos+1 > len(body) {
			return nil, fmt.Errorf("tds: response truncated mid-token")
		}
		tok := body[pos]
		switch tok {
		case TokenColMetadata:
			if pos+3 > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-COLMETADATA")
			}
			cnt := int(binary.LittleEndian.Uint16(body[pos+1 : pos+3]))
			pos += 3
			cols = nil
			if cnt == 0xFFFF {
				res.NoMetaData = true
				continue
			}
			for i := 0; i < cnt; i++ {
				if pos+6 > len(body) {
					return nil, fmt.Errorf("tds: response truncated mid-COLMETADATA column %d", i)
				}
				ut := binary.LittleEndian.Uint32(body[pos : pos+4])
				flags := binary.LittleEndian.Uint16(body[pos+4 : pos+6])
				pos += 6
				tiLen, err := typeInfoLen(body[pos:])
				if err != nil {
					return nil, fmt.Errorf("tds: COLMETADATA TYPE_INFO: %w", err)
				}
				// CRITICAL 2: 此前忘记把 TYPE_INFO 切片存进
				// ColMetadataColumn.TypeInfo,导致后续 ROW/NBCROW 调用
				// cellDataLen(body[pos:], c.TypeInfo) 时 typeInfo 为 nil,
				// cellDataLen 在第 0 行就报 "empty type info"。这里把
				// TYPE_INFO 原始字节 (含 type token 与可能的 maxlen/collation
				// /precision/scale) 复制到列定义,供后续 cell 解码使用。
				typeInfo := make([]byte, tiLen)
				copy(typeInfo, body[pos:pos+tiLen])
				pos += tiLen
				if pos >= len(body) {
					return nil, fmt.Errorf("tds: response truncated mid-COLMETADATA ColName")
				}
				n := int(body[pos])
				pos++
				if pos+n*2 > len(body) {
					return nil, fmt.Errorf("tds: response truncated mid-COLMETADATA ColName data")
				}
				name := decodeUCS2(body[pos : pos+n*2])
				pos += n * 2
				cols = append(cols, ColMetadataColumn{UserType: ut, Flags: flags, TypeInfo: typeInfo, ColName: name})
			}
			res.ColCount = len(cols)
		case TokenRow:
			pos++
			// Cell data depends on column types.
			for _, c := range cols {
				if pos >= len(body) {
					return nil, fmt.Errorf("tds: response truncated mid-ROW")
				}
				skip, err := cellDataLen(body[pos:], c.TypeInfo)
				if err != nil {
					return nil, fmt.Errorf("tds: ROW cell: %w", err)
				}
				if skip < 0 {
					// NULL sentinel of known width.
					skip = -skip
				}
				pos += skip
			}
			res.RowCount++
		case TokenNbcRow:
			pos++
			nBytes := (len(cols) + 7) / 8
			if pos+nBytes > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-NBCROW bitmap")
			}
			bitmap := body[pos : pos+nBytes]
			pos += nBytes
			for i, c := range cols {
				nullBit := (bitmap[i/8] >> (i % 8)) & 1
				if nullBit == 1 {
					continue
				}
				if pos >= len(body) {
					return nil, fmt.Errorf("tds: response truncated mid-NBCROW data")
				}
				skip, err := cellDataLen(body[pos:], c.TypeInfo)
				if err != nil {
					return nil, fmt.Errorf("tds: NBCROW cell: %w", err)
				}
				if skip < 0 {
					skip = -skip
				}
				pos += skip
			}
			res.RowCount++
		case TokenDone, TokenDoneProc, TokenDoneInProc:
			if pos+5 > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-DONE")
			}
			status := binary.LittleEndian.Uint16(body[pos+1 : pos+3])
			curCmd := binary.LittleEndian.Uint16(body[pos+3 : pos+5])
			pos += 5
			var rowCount int64
			if rowCount8B {
				if pos+8 > len(body) {
					return nil, fmt.Errorf("tds: response truncated mid-DONE rowcount")
				}
				rowCount = int64(binary.LittleEndian.Uint64(body[pos : pos+8]))
				pos += 8
			} else {
				if pos+4 > len(body) {
					return nil, fmt.Errorf("tds: response truncated mid-DONE rowcount")
				}
				rowCount = int64(binary.LittleEndian.Uint32(body[pos : pos+4]))
				pos += 4
			}
			d := DoneToken{
				Type:     tok,
				Status:   status,
				CurCmd:   curCmd,
				RowCount: rowCount,
			}
			res.Dones = append(res.Dones, d)
			res.LastDone = d
			// DONE resets the column context (spec §7.5 T-091).
			cols = nil
		case TokenError, TokenInfo:
			et, err := parseErrorInfo(body[pos:], rowCount8B)
			if err != nil {
				return nil, err
			}
			if tok == TokenError {
				res.Errors = append(res.Errors, et)
			} else {
				res.InfoTokens = append(res.InfoTokens, et)
			}
			pos += 3 + et.bytes // token + len + data
		case TokenEnvChange:
			if pos+3 > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-ENVCHANGE")
			}
			l := int(binary.LittleEndian.Uint16(body[pos+1 : pos+3]))
			if pos+3+l > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-ENVCHANGE data")
			}
			env := parseEnvChange(body[pos+3 : pos+3+l])
			// R3-NEW-02 (HIGH) 修复: Type 15 (Promote Transaction) 的 Length
			// 字段只覆盖 Type 字节 (Length=0x01)，NewValue 的 L_VARBYTE (4B LE
			// 长度 + DTC token 数据) 与 OldValue (%x00) 都位于 Length 之外
			// (spec §3.10 + §2.2.7.9 注释: "Client drivers are responsible for
			// reading the additional payload if type is 15")。此前调用点用
			// `pos += 3 + l` 推进，对 Type 15 会少读 L_VARBYTE+OldValue，导致
			// 残留字节被下一个 token 误解析。这里把额外负载也读出。
			consumed := 3 + l
			if env.Type == 15 {
				extra, err := readEnvChangeType15Extra(body[pos+3+l:])
				if err != nil {
					return nil, fmt.Errorf("tds: ENVCHANGE Type 15 extra: %w", err)
				}
				env.NewValue = extra
				// OldValue = %x00 (1B)，紧跟在 L_VARBYTE 之后。
				// extra 已含 4B 长度前缀，所以总偏移 = pos + 3 + l + len(extra) + 1。
				if pos+3+l+len(extra)+1 > len(body) {
					return nil, fmt.Errorf("tds: ENVCHANGE Type 15 OldValue truncated")
				}
				env.OldValue = nil
				consumed = 3 + l + len(extra) + 1
			}
			res.EnvChanges = append(res.EnvChanges, env)
			pos += consumed
		case TokenLoginAck:
			if pos+3 > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-LOGINACK")
			}
			l := int(binary.LittleEndian.Uint16(body[pos+1 : pos+3]))
			if pos+3+l > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-LOGINACK data")
			}
			res.LoginAck = parseLoginAck(body[pos+3 : pos+3+l])
			pos += 3 + l
		case TokenReturnStatus:
			if pos+5 > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-RETURNSTATUS")
			}
			res.ReturnStatus = int32(binary.LittleEndian.Uint32(body[pos+1 : pos+5]))
			pos += 5
		case TokenFeatureExtAck:
			// FeatureAckOpt list: skip to the 0xFF terminator (spec §3.14).
			p := pos + 1
			terminated := false
			for p < len(body) {
				if body[p] == 0xFF {
					terminated = true
					break
				}
				if p+5 > len(body) {
					return nil, fmt.Errorf("tds: FEATUREEXTACK truncated")
				}
				l := int(binary.LittleEndian.Uint32(body[p+1 : p+5]))
				if p+5+l > len(body) {
					return nil, fmt.Errorf("tds: FEATUREEXTACK data truncated")
				}
				p += 5 + l
			}
			if !terminated {
				return nil, fmt.Errorf("tds: FEATUREEXTACK missing terminator")
			}
			res.FeatureExtAck = true
			pos = p + 1
		case TokenSessionState:
			if pos+5 > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-SESSIONSTATE")
			}
			l := int(binary.LittleEndian.Uint32(body[pos+1 : pos+5]))
			if pos+5+l > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-SESSIONSTATE data")
			}
			pos += 5 + l
			res.SessionStates++
		case TokenReturnValue:
			// RETURNVALUE (spec §3.13 / §7.1.16):
			// TokenType(0xAC,1B) + ParamOrdinal(2B LE) + ParamName(B_VARCHAR)
			// + Status(1B) + UserType(4B LE) + Flags(2B LE) + TypeInfo + Value.
			//
			// R3-NEW-01 (CRITICAL) 修复: 此前 `pos += 2` 只跳过 ParamOrdinal
			// 却漏掉 TokenType 字节，导致后续 ParamName.BYTELEN 读到错误偏移，
			// 整个 RETURNVALUE token 解析链全部错位。
			//
			// 边界校验: 至少需要 TokenType(1) + ParamOrdinal(2) + ParamName
			// BYTELEN(1) = 4 字节才能继续；pos+=3 后读 body[pos] 须先保证
			// pos < len(body)。
			if pos+4 > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-RETURNVALUE")
			}
			// 跳过 TokenType(1B) + ParamOrdinal(2B)。
			pos += 3
			// ParamName = B_VARCHAR: 1B BYTELEN + n*2 字节 UCS-2 LE。
			n := int(body[pos])
			pos++
			if pos+n*2 > len(body) {
				return nil, fmt.Errorf("tds: RETURNVALUE ParamName out of range")
			}
			pos += n * 2
			// Status(1B) + UserType(4B) + Flags(2B) = 7 字节。
			if pos+7 > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-RETURNVALUE")
			}
			pos += 7 // Status + UserType + Flags
			tiLen, err := typeInfoLen(body[pos:])
			if err != nil {
				return nil, fmt.Errorf("tds: RETURNVALUE TYPE_INFO: %w", err)
			}
			pos += tiLen
			skip, err := cellDataLen(body[pos:], body[pos-tiLen:pos])
			if err != nil {
				return nil, fmt.Errorf("tds: RETURNVALUE value: %w", err)
			}
			if skip < 0 {
				skip = -skip
			}
			pos += skip
			res.ReturnValues++
		case TokenOrder:
			if pos+3 > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-ORDER")
			}
			l := int(binary.LittleEndian.Uint16(body[pos+1 : pos+3]))
			if pos+3+l > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-ORDER data")
			}
			pos += 3 + l
		case TokenTabName:
			if pos+3 > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-TABNAME")
			}
			l := int(binary.LittleEndian.Uint16(body[pos+1 : pos+3]))
			if pos+3+l > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-TABNAME data")
			}
			pos += 3 + l
		case TokenColInfo:
			if pos+3 > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-COLINFO")
			}
			l := int(binary.LittleEndian.Uint16(body[pos+1 : pos+3]))
			if pos+3+l > len(body) {
				return nil, fmt.Errorf("tds: response truncated mid-COLINFO data")
			}
			pos += 3 + l
		default:
			// Unknown token: tolerate-skip by class (spec §4.5).
			skipped, err := skipUnknownToken(body[pos:], tok)
			if err != nil {
				return nil, err
			}
			pos += skipped
		}
	}
	return res, nil
}

// ResponseResult is the parsed server response.
type ResponseResult struct {
	ColCount      int
	NoMetaData    bool
	RowCount      int64
	Errors        []ErrorToken
	InfoTokens    []ErrorToken
	EnvChanges    []EnvChangeToken
	Dones         []DoneToken
	LastDone      DoneToken
	LoginAck      *LoginAckToken
	ReturnStatus  int32
	FeatureExtAck bool
	SessionStates int
	ReturnValues  int
}

// DoneToken is a parsed DONE-series token.
type DoneToken struct {
	Type     byte
	Status   uint16
	CurCmd   uint16
	RowCount int64
}

// LoginAckToken is a parsed LOGINACK token (spec §3.12).
type LoginAckToken struct {
	Interface   byte
	TDSVersion  uint32
	ProgName    string
	ProgVersion uint32
}

// cellDataLen returns the byte length of one cell's TYPE_VARBYTE payload.
// A negative result means a NULL sentinel of width -result. The generic
// parser returns a negative width when the type is a NULL.
func cellDataLen(b []byte, typeInfo []byte) (int, error) {
	if len(b) < 1 {
		return 0, fmt.Errorf("empty cell")
	}
	if len(typeInfo) < 1 {
		return 0, fmt.Errorf("empty type info")
	}
	t := typeInfo[0]
	switch t {
	// HIGH 3: TypeBitN(0x68) 从此处移除。BITNTYPE 属 BYTELEN_TYPE,
	// TYPE_VARBYTE 为 1B 长度前缀 (0=NULL, 1=1B 数据),此前按定长返回
	// 1 会把 NULL 标记或长度前缀当作数据,导致后续 cell 偏移错位。
	case TypeInt1, TypeBit:
		return 1, nil
	case TypeInt2:
		return 2, nil
	// HIGH 2: TypeDate(0x28) 从此处移除。DATETYPE 属 BYTELEN_TYPE,
	// TYPE_VARBYTE 为 1B 长度前缀 (0=NULL, 3=3B 日期值),此前按定长
	// 返回 4 会少算长度前缀,导致后续 cell 偏移错位。
	case TypeInt4, TypeFloat4, TypeMoney4:
		return 4, nil
	case TypeInt8, TypeFloat8, TypeMoney, TypeDateTime:
		return 8, nil
	case TypeGUID, TypeIntN, TypeDecimalN, TypeNumericN, TypeFloatN,
		TypeMoneyN, TypeDateTimeN, TypeDateTime2, TypeDateTimeOff, TypeTime,
		// BYTELEN char/binary 类型 (spec §2.4.3 BYTELEN_TYPE 最后一组):
		// CHARTYPE(0x2F)/VARCHARTYPE(0x27)/BINARYTYPE(0x2D)/VARBINARYTYPE(0x25)。
		// 修复 Bug 7 (HIGH): 此前 cellDataLen 未覆盖这四种 BYTELEN char/binary
		// 类型，COLMETADATA 列含这些类型时 ParseResponse 会落入 default 分支
		// 报 "unknown cell type"。
		// NULL = GEN_NULL (1B 0x00); 非 NULL = 1B 长度 + 数据 (spec §2.4.3
		// BYTELEN_TYPE 表 "0~255" 合法长度 + spec §2.4.4 GEN_NULL 规则)。
		TypeChar, TypeVarChar, TypeBinary, TypeVarBinary,
		// HIGH 2 + HIGH 3: TypeDate(0x28) 与 TypeBitN(0x68) 都属 BYTELEN_TYPE,
		// TYPE_VARBYTE 为 1B 长度前缀 (spec §2.4.3): TypeDate 数据 3B
		// (长度前缀 0x00=NULL 或 0x03), TypeBitN 数据 1B (0x00=NULL 或 0x01)。
		TypeDate, TypeBitN:
		// BYTELEN-prefixed: width from the first byte.
		if len(b) < 1 {
			return 0, fmt.Errorf("truncated BYTELEN cell")
		}
		w := int(b[0])
		if w == 0 {
			return -1, nil // GEN_NULL
		}
		return 1 + w, nil
	case TypeBigVarChar, TypeBigChar, TypeNVarChar, TypeNChar,
		TypeBigVarBin, TypeBigBinary:
		// MAX types use PLP encoding (spec §2.4.4) — detect via the
		// USHORTMAXLEN=0xFFFF marker in TYPE_INFO.
		if len(typeInfo) >= 3 && typeInfo[1] == 0xFF && typeInfo[2] == 0xFF {
			// PLP: 8B total length + chunks + 4B terminator, or 8B NULL.
			if len(b) < 8 {
				return 0, fmt.Errorf("truncated MAX PLP cell")
			}
			total := binary.LittleEndian.Uint64(b[0:8])
			if total == PLPNull {
				return -8, nil
			}
			return plpLength(b)
		}
		if len(b) < 2 {
			return 0, fmt.Errorf("truncated USHORTLEN cell")
		}
		w := int(binary.LittleEndian.Uint16(b[0:2]))
		if w == 0xFFFF {
			return -2, nil // CHARBIN_NULL 2B
		}
		return 2 + w, nil
	case TypeVector:
		// VECTORTYPE(0xF5) 属 USHORTLEN_TYPE (spec §2.4.3 USHORTLEN_TYPE 列表
		// 最后一项)。修复 Bug 7 (HIGH): 此前 cellDataLen 未覆盖 TypeVector，
		// COLMETADATA 列含 VECTOR 类型时 ParseResponse 落入 default 报错。
		// 数据段 = 2B LE 长度前缀 + (8B VECTOR 头 + NN*sizeof(T)) (spec
		// §2.4.3 + §2.5.5.7)。VECTORTYPE 不是 char/binary 类型 (spec §2.4.4
		// 第 1485-1489 行: 2B CHARBIN_NULL 仅适用于 BIG* char/binary)，
		// 故 NULL 走 GEN_NULL 语义，但 USHORTLEN 长度前缀为 2B，因此 NULL
		// 表示为 2B 长度=0x0000 (return -2 表示 2B NULL 宽度)。
		if len(b) < 2 {
			return 0, fmt.Errorf("truncated USHORTLEN VECTOR cell")
		}
		w := int(binary.LittleEndian.Uint16(b[0:2]))
		if w == 0x0000 {
			return -2, nil // GEN_NULL (2B 长度=0，符合 USHORTLEN 前缀宽度)
		}
		return 2 + w, nil
	case TypeText, TypeNText, TypeImage:
		if len(b) < 4 {
			return 0, fmt.Errorf("truncated LONGLEN cell")
		}
		w := int(binary.LittleEndian.Uint32(b[0:4]))
		if w == 0xFFFFFFFF {
			return -4, nil // CHARBIN_NULL 4B
		}
		return 4 + w, nil
	case TypeXML, TypeJSON, TypeUDT:
		// PLP: 8B total length + chunks + 4B terminator, or 8B NULL.
		if len(b) < 8 {
			return 0, fmt.Errorf("truncated PLP cell")
		}
		total := binary.LittleEndian.Uint64(b[0:8])
		if total == PLPNull {
			return -8, nil
		}
		return plpLength(b)
	case TypeNull:
		return 0, nil
	case TypeDecimal, TypeNumeric:
		// Legacy: precision/scale in data.
		return 5, nil
	default:
		return 0, fmt.Errorf("unknown cell type 0x%02x", t)
	}
}

// plpLength computes the total byte length of a PLP_BODY starting at b
// (which begins with the 8B ULONGLONGLEN).
func plpLength(b []byte) (int, error) {
	if len(b) < 8 {
		return 0, fmt.Errorf("truncated PLP")
	}
	total := binary.LittleEndian.Uint64(b[0:8])
	pos := 8
	if total == PLPUnknownLen {
		// Unknown length: read chunks until terminator.
		for {
			if pos+4 > len(b) {
				return 0, fmt.Errorf("truncated PLP chunk")
			}
			chunk := binary.LittleEndian.Uint32(b[pos : pos+4])
			if chunk == 0 {
				return pos + 4, nil
			}
			pos += 4 + int(chunk)
		}
	}
	// Known length: sum chunks until terminator or end.
	for {
		if pos+4 > len(b) {
			return 0, fmt.Errorf("truncated PLP chunk")
		}
		chunk := binary.LittleEndian.Uint32(b[pos : pos+4])
		if chunk == 0 {
			return pos + 4, nil
		}
		pos += 4 + int(chunk)
	}
}

// parseErrorInfo parses an ERROR/INFO token body (spec §3.11). Returns the
// ErrorToken and the total token size (including TokenType+Length).
func parseErrorInfo(b []byte, line4B bool) (ErrorToken, error) {
	// b starts at the TokenType byte.
	if len(b) < 3 {
		return ErrorToken{}, fmt.Errorf("tds: ERROR/INFO truncated")
	}
	l := int(binary.LittleEndian.Uint16(b[1:3]))
	if 3+l > len(b) {
		return ErrorToken{}, fmt.Errorf("tds: ERROR/INFO data truncated")
	}
	d := b[3 : 3+l]
	et := ErrorToken{bytes: l}
	if len(d) < 7 {
		return et, fmt.Errorf("tds: ERROR/INFO payload too short")
	}
	et.Number = int32(binary.LittleEndian.Uint32(d[0:4]))
	et.State = d[4]
	et.Class = d[5]
	msgLen := int(binary.LittleEndian.Uint16(d[6:8]))
	pos := 8
	if pos+msgLen*2 > len(d) {
		return et, fmt.Errorf("tds: ERROR/INFO MsgText out of range")
	}
	et.MsgText = decodeUCS2(d[pos : pos+msgLen*2])
	pos += msgLen * 2
	// ServerName B_VARCHAR
	if pos >= len(d) {
		return et, fmt.Errorf("tds: ERROR/INFO ServerName truncated")
	}
	n := int(d[pos])
	pos++
	if pos+n*2 > len(d) {
		return et, fmt.Errorf("tds: ERROR/INFO ServerName out of range")
	}
	et.ServerName = decodeUCS2(d[pos : pos+n*2])
	pos += n * 2
	// ProcName B_VARCHAR
	if pos >= len(d) {
		return et, fmt.Errorf("tds: ERROR/INFO ProcName truncated")
	}
	n = int(d[pos])
	pos++
	if pos+n*2 > len(d) {
		return et, fmt.Errorf("tds: ERROR/INFO ProcName out of range")
	}
	et.ProcName = decodeUCS2(d[pos : pos+n*2])
	pos += n * 2
	// LineNumber
	if line4B {
		if pos+4 > len(d) {
			return et, fmt.Errorf("tds: ERROR/INFO LineNumber truncated")
		}
		et.LineNumber = int64(binary.LittleEndian.Uint32(d[pos : pos+4]))
	} else {
		if pos+2 > len(d) {
			return et, fmt.Errorf("tds: ERROR/INFO LineNumber truncated")
		}
		et.LineNumber = int64(binary.LittleEndian.Uint16(d[pos : pos+2]))
	}
	return et, nil
}

// parseEnvChange parses an ENVCHANGE EnvValueData (Type+NewValue+OldValue).
func parseEnvChange(d []byte) EnvChangeToken {
	env := EnvChangeToken{Type: d[0]}
	if len(d) < 2 {
		return env
	}
	// Type determines the value shapes (spec §3.10):
	//  - B_VARCHAR/B_VARBYTE-prefixed types have 1B length in NewValue/OldValue.
	//  - For types 8/9/10, NewValue=%x00 or 1B len + 8B; OldValue similarly.
	switch env.Type {
	case 1, 3, 4, 13, 19:
		// B_VARCHAR-style: 1B BYTELEN + UCS-2 data.
		pos := 1
		if pos >= len(d) {
			return env
		}
		n := int(d[pos])
		pos++
		if n == 0 {
			env.NewValue = nil
		} else {
			if pos+n*2 > len(d) {
				return env
			}
			env.NewValue = d[pos : pos+n*2]
			pos += n * 2
		}
		if pos >= len(d) {
			return env
		}
		n = int(d[pos])
		pos++
		if n == 0 {
			env.OldValue = nil
		} else {
			if pos+n*2 > len(d) {
				return env
			}
			env.OldValue = d[pos : pos+n*2]
		}
	case 2:
		// Language: both NewValue and OldValue are B_VARCHAR (spec §3.10 Type 2).
		pos := 1
		if pos >= len(d) {
			return env
		}
		n := int(d[pos])
		pos++
		if n == 0 {
			env.NewValue = nil
		} else {
			if pos+n*2 > len(d) {
				return env
			}
			env.NewValue = d[pos : pos+n*2]
			pos += n * 2
		}
		if pos >= len(d) {
			return env
		}
		n = int(d[pos])
		pos++
		if n == 0 {
			env.OldValue = nil
		} else {
			if pos+n*2 > len(d) {
				return env
			}
			env.OldValue = d[pos : pos+n*2]
		}
	case 7:
		// SQL Collation: B_VARBYTE(5B collation). 1B BYTELEN + raw bytes.
		pos := 1
		if pos >= len(d) {
			return env
		}
		n := int(d[pos])
		pos++
		if n == 0 {
			env.NewValue = nil
		} else {
			if pos+n > len(d) {
				return env
			}
			env.NewValue = d[pos : pos+n]
			pos += n
		}
		if pos >= len(d) {
			return env
		}
		n = int(d[pos])
		pos++
		if n == 0 {
			env.OldValue = nil
		} else {
			if pos+n > len(d) {
				return env
			}
			env.OldValue = d[pos : pos+n]
		}
	case 15:
		// Promote Transaction (spec §3.10 Type 15):
		// NewValue = DTC_TOKEN，使用 L_VARBYTE 编码（4B LE 长度前缀 + DTC token 数据）；
		// OldValue = %x00。
		//
		// 关键陷阱: ENVCHANGE 的 2B Length 字段对 Type 15 恒为 0x01，仅覆盖 Type 字节，
		// 客户端须自行读 Length 之外的 L_VARBYTE+OldValue（spec §2.2.7.9 注释）。
		// 因此 parseEnvChange 在 `d` (仅含 Type 字节) 中无法读到 NewValue/OldValue，
		// 调用点 ParseResponse 单独调用 readEnvChangeType15Extra 读取额外负载并填充
		// env.NewValue。这里保持 env.NewValue/OldValue 为空，调用点会覆写。
		// 注释保留 case 以便读者理解 Type 15 的特殊性，避免落入 default 被误判为
		// B_VARBYTE 风格解析。
		env.NewValue = nil
		env.OldValue = nil
	case 11:
		// Enlist DTC Transaction (spec §3.10 Type 11 / §2.2.7.9):
		// NewValue = 8B raw ULONGLONG (无长度前缀)，OldValue = %x00 (1B)。
		// 修复 N4 (MEDIUM): default 分支按 B_VARBYTE 解析会把 NewValue 第一字节
		// 当作 1B 长度前缀，错读前 8 字节并产生错位。这里给 Type 11 专用 case
		// 跳过 8B NewValue + 1B OldValue，共 9 字节。
		pos := 1
		if pos+8 > len(d) {
			// 数据不足 8B NewValue，视为不完整（不解析为 B_VARBYTE）。
			env.NewValue = nil
			env.OldValue = nil
			return env
		}
		env.NewValue = d[pos : pos+8]
		pos += 8
		// OldValue = %x00 (1B 长度前缀为 0)，存在则跳过；不存在不报错。
		if pos < len(d) {
			// d[pos] 应为 0x00 (空 OldValue)；不解析为 B_VARBYTE。
			pos++
		}
		env.OldValue = nil
	default:
		// B_VARBYTE-style for unhandled types (e.g., Type 5/6/18/20/21):
		// 1B BYTELEN + raw bytes. (Type 11/15 已单独处理，见上。)
		pos := 1
		if pos >= len(d) {
			return env
		}
		n := int(d[pos])
		pos++
		if n == 0 {
			env.NewValue = nil
		} else {
			if pos+n > len(d) {
				return env
			}
			env.NewValue = d[pos : pos+n]
			pos += n
		}
		if pos >= len(d) {
			return env
		}
		n = int(d[pos])
		pos++
		if n == 0 {
			env.OldValue = nil
		} else {
			if pos+n > len(d) {
				return env
			}
			env.OldValue = d[pos : pos+n]
		}
	}
	return env
}

// readEnvChangeType15Extra 读取 ENVCHANGE Type 15 (Promote Transaction) 中
// 位于 2B Length 字段之外的额外负载: L_VARBYTE (4B LE 长度 + DTC token 数据)。
//
// 规范背景: MS-TDS §2.2.7.9 注释明确 Type 15 的 LENGTH 固定为 0x01 (仅覆盖
// Type 字节)，"Client drivers are responsible for reading the additional payload
// if type is 15"。因此 NewValue 的 L_VARBYTE 和 OldValue (%x00) 都需调用者在
// Length 之外读取。
//
// b 从 ENVCHANGE Length 字段覆盖的 EnvValueData 之后开始，即 L_VARBYTE 的起始
// 偏移。函数返回 L_VARBYTE 的完整原始字节（含 4B 长度前缀），调用点负责跳过
// 后续的 OldValue (%x00)。
func readEnvChangeType15Extra(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("truncated L_VARBYTE length prefix")
	}
	l := int(binary.LittleEndian.Uint32(b[0:4]))
	if len(b) < 4+l {
		return nil, fmt.Errorf("truncated L_VARBYTE data (want %d, have %d)", l, len(b)-4)
	}
	return b[:4+l], nil
}

// parseLoginAck parses the LOGINACK data (spec §3.12).
func parseLoginAck(d []byte) *LoginAckToken {
	la := &LoginAckToken{}
	if len(d) < 6 {
		return la
	}
	la.Interface = d[0]
	// Server→client TDSVersion is BE on the wire (spec footnote 72).
	la.TDSVersion = uint32(d[1])<<24 | uint32(d[2])<<16 | uint32(d[3])<<8 | uint32(d[4])
	n := int(d[5])
	if 6+n*2 <= len(d) {
		la.ProgName = decodeUCS2(d[6 : 6+n*2])
		if 6+n*2+4 <= len(d) {
			la.ProgVersion = binary.LittleEndian.Uint32(d[6+n*2 : 6+n*2+4])
		}
	}
	return la
}

// decodeUCS2 decodes UCS-2 LE bytes into a Go string.
func decodeUCS2(b []byte) string {
	codes := make([]uint16, len(b)/2)
	for i := range codes {
		codes[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(codesToRunes(codes))
}

// skipUnknownToken skips an unknown token by class (spec §1.6/§4.5).
func skipUnknownToken(b []byte, tok byte) (int, error) {
	if len(b) < 1 {
		return 0, fmt.Errorf("tds: token stream truncated")
	}
	switch {
	case tok&0x40 != 0 && tok&0x20 == 0: // xx01xxxx zero-length
		return 1, nil
	case tok&0x60 == 0x60: // xx11xxxx fixed-length
		return 1, nil
	case tok&0x20 != 0: // xx10xxxx variable-length: 2B length
		if len(b) < 3 {
			return 0, fmt.Errorf("tds: variable token truncated")
		}
		l := int(binary.LittleEndian.Uint16(b[1:3]))
		if len(b) < 3+l {
			return 0, fmt.Errorf("tds: variable token data truncated")
		}
		return 3 + l, nil
	default: // xx00xxxx variable-count: 2B count
		if len(b) < 3 {
			return 0, fmt.Errorf("tds: count token truncated")
		}
		return 3, nil
	}
}

// HasDoneAttn reports whether the response contains a DONE with the
// DONE_ATTN (0x20) bit (spec §3.15 — the Attention confirmation).
func (r *ResponseResult) HasDoneAttn() bool {
	for _, d := range r.Dones {
		if d.Type == TokenDone && d.Status&DONEAttn != 0 {
			return true
		}
	}
	return false
}

// HasDoneError reports whether the response contains a DONE with the
// DONE_ERROR (0x02) bit.
func (r *ResponseResult) HasDoneError() bool {
	for _, d := range r.Dones {
		if d.Status&DONEError != 0 {
			return true
		}
	}
	return false
}

// HasDoneMore reports whether the last DONE carries DONE_MORE.
func (r *ResponseResult) HasDoneMore() bool {
	return len(r.Dones) > 0 && r.Dones[len(r.Dones)-1].Status&DONEMore != 0
}
