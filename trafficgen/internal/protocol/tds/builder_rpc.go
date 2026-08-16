// Package tds: builder_rpc.go — RPC request builder (spec §3.4), TransMgrReq
// (spec §3.5), Attention (spec §3.15), and response-token builders for tests.
package tds

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// BuildRPCNameProcID encodes the RPC NameLenProcID (spec §3.4). When procID
// is non-nil, the short form (0xFFFF + ProcID USHORT LE) is emitted;
// otherwise the long form (US_VARCHAR ProcName) is emitted.
func BuildRPCNameProcID(procName string, procID *uint16) ([]byte, error) {
	if procID != nil {
		if procName != "" {
			return nil, fmt.Errorf("rpc: ProcName and ProcID are mutually exclusive (V-TDS-024)")
		}
		out := make([]byte, 4)
		out[0] = 0xFF
		out[1] = 0xFF
		binary.LittleEndian.PutUint16(out[2:], *procID)
		return out, nil
	}
	if len(procName) > MaxProcNameBytes {
		return nil, fmt.Errorf("rpc: ProcName %d bytes > %d (V-TDS-022)", len(procName), MaxProcNameBytes)
	}
	return usVarChar(procName), nil
}

// BuildRPCOptionFlags encodes the RPC OptionFlags (spec §3.4). Per MS-TDS
// the field is USHORT (2 bytes LE): fWithRecomp(bit0) + fNoMetaData(bit1) +
// fReuseMetaData(bit2) + 13 reserved bits. A 1-byte emission misaligns the
// RPC stream (tshark/FreeTDS both read 2 bytes).
func BuildRPCOptionFlags(withRecomp, noMetaData, reuseMetaData bool) uint16 {
	var f uint16
	if withRecomp {
		f |= 0x0001
	}
	if noMetaData {
		f |= 0x0002
	}
	if reuseMetaData {
		f |= 0x0004
	}
	return f
}

// appendRPCOptionFlags appends the 2-byte LE OptionFlags to a body slice.
func appendRPCOptionFlags(body []byte, withRecomp, noMetaData bool) []byte {
	f := BuildRPCOptionFlags(withRecomp, noMetaData, false)
	return append(body, byte(f), byte(f>>8))
}

// BuildRPCParamStatusFlags encodes the RPC ParameterData StatusFlags byte
// (spec §3.4 / §2.2.6.6). fEncrypted (bit3) is set when encrypted=true
// (v3.0.1 corrected from v3.0.0's wrong bit4).
func BuildRPCParamStatusFlags(byRef, defaultValue, encrypted bool) byte {
	var f byte
	if byRef {
		f |= 0x01
	}
	if defaultValue {
		f |= 0x02
	}
	if encrypted {
		f |= 0x08
	}
	return f
}

// BuildRPCParam encodes one RPC ParameterData (spec §3.4):
//
//	B_VARCHAR ParamName + StatusFlags + TYPE_INFO + TYPE_VARBYTE
//
// Type is one of the supported type names: "int", "bigint", "smallint",
// "tinyint", "bit", "varchar", "nvarchar", "varbinary", "char", "nchar",
// "datetime", "datetime2", "date", "time", "decimal", "numeric",
// "uniqueidentifier", "xml", "json", "udt".
func BuildRPCParam(p ParamSpec) ([]byte, error) {
	var out []byte
	out = append(out, bVarChar(p.Name)...)
	out = append(out, BuildRPCParamStatusFlags(p.ByRef, p.DefaultValue, false))

	ti, data, err := encodeTypeInfoAndValue(p)
	if err != nil {
		return nil, err
	}
	out = append(out, ti...)
	out = append(out, data...)
	return out, nil
}

// encodeTypeInfoAndValue emits TYPE_INFO followed by TYPE_VARBYTE for a
// parameter. For NULL values, TYPE_VARBYTE is the type-appropriate NULL
// sentinel (spec §2.4.3).
func encodeTypeInfoAndValue(p ParamSpec) (typeInfo, data []byte, err error) {
	switch strings.ToLower(p.Type) {
	case "int", "int4":
		typeInfo = []byte{TypeInt4}
		if p.IsNull {
			data = []byte{0, 0, 0, 0}
		} else {
			v, e := parseIntValue(p.Value, 32)
			if e != nil {
				return nil, nil, e
			}
			data = make([]byte, 4)
			binary.LittleEndian.PutUint32(data, uint32(v))
		}
	case "bigint", "int8":
		typeInfo = []byte{TypeInt8}
		if p.IsNull {
			data = make([]byte, 8)
		} else {
			v, e := parseIntValue(p.Value, 64)
			if e != nil {
				return nil, nil, e
			}
			data = make([]byte, 8)
			binary.LittleEndian.PutUint64(data, uint64(v))
		}
	case "smallint", "int2":
		typeInfo = []byte{TypeInt2}
		if p.IsNull {
			data = make([]byte, 2)
		} else {
			v, e := parseIntValue(p.Value, 16)
			if e != nil {
				return nil, nil, e
			}
			data = make([]byte, 2)
			binary.LittleEndian.PutUint16(data, uint16(v))
		}
	case "tinyint", "int1":
		typeInfo = []byte{TypeInt1}
		if p.IsNull {
			data = []byte{0}
		} else {
			v, e := parseIntValue(p.Value, 8)
			if e != nil {
				return nil, nil, e
			}
			data = []byte{byte(v)}
		}
	case "bit":
		typeInfo = []byte{TypeBit}
		if p.IsNull {
			data = []byte{0}
		} else {
			data = []byte{0}
			if p.Value != nil && (*p.Value == "1" || strings.EqualFold(*p.Value, "true")) {
				data[0] = 1
			}
		}
	case "intn":
		typeInfo = []byte{TypeIntN, 0x04}
		if p.IsNull {
			data = []byte{0}
		} else {
			v, e := parseIntValue(p.Value, 32)
			if e != nil {
				return nil, nil, e
			}
			data = make([]byte, 5)
			data[0] = 4
			binary.LittleEndian.PutUint32(data[1:], uint32(v))
		}
	case "varchar", "bigvarchar":
		maxLen := 8000
		if p.MaxLen != nil {
			maxLen = *p.MaxLen
		}
		if p.Max {
			typeInfo = []byte{TypeBigVarChar, 0xFF, 0xFF}
		} else {
			if maxLen > 8000 {
				return nil, nil, fmt.Errorf("varchar max_len %d > 8000 without max=true (V-TDS-026)", maxLen)
			}
			typeInfo = []byte{TypeBigVarChar, byte(maxLen), byte(maxLen >> 8)}
		}
		typeInfo = append(typeInfo, DefaultCollation[:]...)
		if p.IsNull {
			// T-212: varchar(max) NULL → 8B PLP_NULL (0xFF×8)；非 max 才用
			// 2B CHARBIN_NULL (T-211)。修复: 此前 IsNull 先于 Max 判断，max
			// NULL 被误编码为 CHARBIN_NULL。
			if p.Max {
				data = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF} // PLP_NULL
			} else {
				data = []byte{0xFF, 0xFF} // CHARBIN_NULL 2B
			}
		} else if p.Max {
			data = buildPLPFromString(p.Value)
		} else {
			raw := []byte("")
			if p.Value != nil {
				raw = []byte(*p.Value)
			}
			if len(raw) > maxLen {
				return nil, nil, fmt.Errorf("varchar value %d > max_len %d", len(raw), maxLen)
			}
			data = make([]byte, 2+len(raw))
			binary.LittleEndian.PutUint16(data, uint16(len(raw)))
			copy(data[2:], raw)
		}
	case "nvarchar", "bignvarchar":
		maxLen := 4000
		if p.MaxLen != nil {
			maxLen = *p.MaxLen
		}
		if p.Max {
			typeInfo = []byte{TypeNVarChar, 0xFF, 0xFF}
		} else {
			if maxLen > 4000 {
				return nil, nil, fmt.Errorf("nvarchar max_len %d > 4000 without max=true (V-TDS-026)", maxLen)
			}
			typeInfo = []byte{TypeNVarChar, byte(maxLen), byte(maxLen >> 8)}
		}
		typeInfo = append(typeInfo, DefaultCollation[:]...)
		if p.IsNull {
			// T-212: nvarchar(max) NULL 同样 8B PLP_NULL；非 max 用 CHARBIN_NULL。
			if p.Max {
				data = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
			} else {
				data = []byte{0xFF, 0xFF}
			}
		} else if p.Max {
			// nvarchar(max) PLP chunk 数据必须为 UCS-2 LE（T-110 语义:
			// "UCS-2 LE 数据"，每字符 2B）。此前误用 buildPLPFromString →
			// 原始 ASCII 字节入 chunk，与 tshark/FreeTDS 解析不符
			// （"ab" → 61 62 而非 61 00 62 00）。
			var s string
			if p.Value != nil {
				s = *p.Value
			}
			data = buildPLP(encodeUTF16(s))
		} else {
			var s string
			if p.Value != nil {
				s = *p.Value
			}
			ucs := encodeUTF16(s)
			data = make([]byte, 2+len(ucs))
			binary.LittleEndian.PutUint16(data, uint16(len(ucs)))
			copy(data[2:], ucs)
		}
	case "varbinary":
		maxLen := 8000
		if p.MaxLen != nil {
			maxLen = *p.MaxLen
		}
		if p.Max {
			typeInfo = []byte{TypeBigVarBin, 0xFF, 0xFF}
		} else {
			typeInfo = []byte{TypeBigVarBin, byte(maxLen), byte(maxLen >> 8)}
		}
		if p.IsNull {
			// T-212: varbinary(max) NULL → 8B PLP_NULL；非 max → CHARBIN_NULL。
			if p.Max {
				data = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
			} else {
				data = []byte{0xFF, 0xFF}
			}
		} else if p.Max {
			data = buildPLPFromHex(p.Value)
		} else {
			raw, e := parseHexValue(p.Value)
			if e != nil {
				return nil, nil, e
			}
			data = make([]byte, 2+len(raw))
			binary.LittleEndian.PutUint16(data, uint16(len(raw)))
			copy(data[2:], raw)
		}
	case "xml":
		// LONGLEN_TYPE (MS-TDS §2.2.5.5.3): TYPE_INFO = type(1B) +
		// MaxLen(4B)。XML/UDT 固定 0xFFFFFFFF（无限长，数据用 PLP 流）。
		// 此前漏发 4B MaxLen，Wireshark 把 PLP 长度前 4B 误读为 MaxLen
		// → 参数流错位 → "[Malformed Packet: TDS]"。
		typeInfo = []byte{TypeXML, 0xFF, 0xFF, 0xFF, 0xFF}
		if p.IsNull {
			data = make([]byte, 8)
			for i := range data {
				data[i] = 0xFF
			}
		} else {
			data = buildPLPFromString(p.Value)
		}
	case "json":
		typeInfo = []byte{TypeJSON, 0xFF, 0xFF, 0xFF, 0xFF}
		if p.IsNull {
			data = make([]byte, 8)
			for i := range data {
				data[i] = 0xFF
			}
		} else {
			data = buildPLPFromString(p.Value)
		}
	case "udt":
		typeInfo = []byte{TypeUDT, 0xFF, 0xFF, 0xFF, 0xFF}
		if p.IsNull {
			data = make([]byte, 8)
			for i := range data {
				data[i] = 0xFF
			}
		} else {
			data = buildPLPFromHex(p.Value)
		}
	case "uniqueidentifier", "guid":
		typeInfo = []byte{TypeGUID, 0x10}
		if p.IsNull {
			// BYTELEN_TYPE NULL → GEN_NULL (0x00)。
			data = []byte{0}
		} else {
			raw, e := parseHexValue(p.Value)
			if e != nil {
				return nil, nil, e
			}
			if len(raw) != 16 {
				return nil, nil, fmt.Errorf("uniqueidentifier must be 16 bytes, got %d", len(raw))
			}
			// BYTELEN_TYPE (MS-TDS §2.4.6): 值 = [1B 长度][数据]。
			// 此前漏了长度前缀直接拼 16B 裸值，Wireshark 把首字节误读为
			// 长度 → 后续字节错位 → "[Malformed Packet: TDS]"。
			data = append([]byte{0x10}, raw...)
		}
	case "decimal", "numeric":
		// DECIMALN/NUMERICNTYPE TYPE_INFO = type(1B) + maxlen(1B) + precision(1B)
		// + scale(1B) = 4 字节 (spec §2.4.5 / parser.go typeInfoLen 注释)。
		// TYPE_VARBYTE 为 BYTELEN 风格 (1B 长度前缀, 0x00=GEN_NULL) + 1B 符号
		// (0=负, 1=非负) + 有符号整数 (值×10^scale) (spec §2.4.6)。
		// 值字节宽度按 precision: 1-9→4B, 10-19→8B, 20-28→12B, 29-38→16B。
		prec := byte(18)
		if p.Precision != nil {
			prec = *p.Precision
		}
		scale := byte(0)
		if p.Scale != nil {
			scale = *p.Scale
		}
		if prec > 38 {
			return nil, nil, fmt.Errorf("decimal/numeric precision %d > 38 (V-TDS-027)", prec)
		}
		if scale > prec {
			return nil, nil, fmt.Errorf("decimal/numeric scale %d > precision %d (V-TDS-028)", scale, prec)
		}
		var nBytes int
		switch {
		case prec <= 9:
			nBytes = 4
		case prec <= 19:
			nBytes = 8
		case prec <= 28:
			nBytes = 12
		default:
			nBytes = 16
		}
		maxLen := byte(nBytes + 1) // +1 符号字节
		typeToken := byte(TypeDecimalN)
		if p.Type == "numeric" {
			typeToken = byte(TypeNumericN)
		}
		typeInfo = []byte{typeToken, maxLen, prec, scale}
		if p.IsNull {
			data = []byte{0} // GEN_NULL
		} else {
			// 解析十进制整数值 (调用者已按 scale 展开，例如 "1234.50" scale=2 应传 "123450")。
			// 注: 此处不自行做 ×10^scale 计算，调用者负责传入整数形式。
			v, e := parseIntValue(p.Value, 128)
			if e != nil {
				return nil, nil, e
			}
			neg := v < 0
			uv := uint64(v)
			if neg {
				uv = uint64(-v)
			}
			// 校验: 值是否超出当前精度宽度可表达范围。
			// nBytes 字节无符号最大值 = 1<<nByteBits-1。SQL Server 用 4B/8B/12B/16B
			// 整数表示，这里只校验低 64 位 (12B/16B 形式实际能容纳 96/128 位，
			// 但 Go uint64 最大 64 位，对 prec≤19 的常见场景已够用；更高精度
			// 由调用者自行保证值不越界)。
			bitsNeeded := nBytes * 8
			if bitsNeeded <= 64 {
				maxVal := uint64(1)<<uint(bitsNeeded) - 1
				if uv > maxVal {
					return nil, nil, fmt.Errorf("decimal/numeric value %d exceeds %d-byte width (precision %d)",
						v, nBytes, prec)
				}
			}
			data = make([]byte, 1+1+nBytes) // 长度前缀 + 符号 + 整数
			data[0] = byte(nBytes + 1)      // BYTELEN = 符号 + 整数
			if neg {
				data[1] = 0
			} else {
				data[1] = 1
			}
			// 整数 LE 写入 nBytes 字节 (低位先写)。
			for i := 0; i < nBytes; i++ {
				data[2+i] = byte(uv >> uint(8*i))
			}
		}
	default:
		return nil, nil, fmt.Errorf("unsupported param type %q (V-TDS-025)", p.Type)
	}
	return typeInfo, data, nil
}

// parseIntValue parses a string int value within the given bit width.
func parseIntValue(v *string, bits int) (int64, error) {
	if v == nil {
		return 0, fmt.Errorf("int value is nil")
	}
	var n int64
	_, err := fmt.Sscanf(*v, "%d", &n)
	if err != nil {
		return 0, fmt.Errorf("invalid int value %q: %w (V-TDS-030)", *v, err)
	}
	return n, nil
}

// parseHexValue parses a hex string into bytes.
func parseHexValue(v *string) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("hex value is nil")
	}
	return hex.DecodeString(*v)
}

// buildPLPFromString builds a PLP_BODY (spec §2.4.4) from a string. Uses
// the known-length form (ULONGLONGLEN) and splits the data into chunks of
// at most 4096 bytes (spec §2.4.4: "large values are split into chunks of
// ≤ 4096 bytes for streaming").
func buildPLPFromString(v *string) []byte {
	var s string
	if v != nil {
		s = *v
	}
	return buildPLP([]byte(s))
}

// buildPLPFromHex builds a PLP_BODY from a hex string.
func buildPLPFromHex(v *string) []byte {
	var raw []byte
	if v != nil {
		raw, _ = hex.DecodeString(*v)
	}
	return buildPLP(raw)
}

// buildPLP builds a PLP_BODY with chunks of ≤ 4096 bytes.
func buildPLP(raw []byte) []byte {
	out := make([]byte, 8)
	binary.LittleEndian.PutUint64(out, uint64(len(raw)))
	for len(raw) > 0 {
		n := len(raw)
		if n > 4096 {
			n = 4096
		}
		c := make([]byte, 4+n)
		binary.LittleEndian.PutUint32(c, uint32(n))
		copy(c[4:], raw[:n])
		out = append(out, c...)
		raw = raw[n:]
	}
	return append(out, make([]byte, 4)...) // PLP_TERMINATOR
}

// --- RPC message (spec §3.4) ---

// BuildRPCRequest builds a complete RPC message packet (Type=0x03).
// txnDesc/outstanding fill ALL_HEADERS (TDS 7.2+). When the caller wants
// multiple RPCReqBatch entries, use BuildRPCBatch.
func BuildRPCRequest(rpc RpcSpec, tds7Plus bool, txnDesc uint64, outstanding uint32,
	status byte, spid uint16, packetID byte) ([]byte, error) {
	var body []byte
	if tds7Plus {
		body = append(body, AllHeaders(txnDesc, outstanding)...)
	}
	nameID, err := BuildRPCNameProcID(rpc.ProcName, rpc.ProcID)
	if err != nil {
		return nil, err
	}
	body = append(body, nameID...)
	body = appendRPCOptionFlags(body, rpc.WithRecomp, rpc.NoMetaData)
	for _, p := range rpc.Params {
		pb, err := BuildRPCParam(p)
		if err != nil {
			return nil, err
		}
		body = append(body, pb...)
	}
	totalLen := 8 + len(body)
	h := PacketHeader(TypeRPC, status, totalLen, spid, packetID, 0)
	out := make([]byte, totalLen)
	copy(out[:8], h[:])
	copy(out[8:], body)
	return out, nil
}

// BuildRPCBatch builds an RPC message with multiple RPCReqBatch entries
// separated by BatchFlag(0xFF) (spec §3.4 / S13).
func BuildRPCBatch(batch []RpcSpec, tds7Plus bool, txnDesc uint64, outstanding uint32,
	status byte, spid uint16, packetID byte) ([]byte, error) {
	if len(batch) == 0 {
		return nil, fmt.Errorf("rpc batch empty")
	}
	var body []byte
	if tds7Plus {
		body = append(body, AllHeaders(txnDesc, outstanding)...)
	}
	for i, rpc := range batch {
		if i > 0 {
			body = append(body, 0xFF) // BatchFlag
		}
		nameID, err := BuildRPCNameProcID(rpc.ProcName, rpc.ProcID)
		if err != nil {
			return nil, err
		}
		body = append(body, nameID...)
		body = appendRPCOptionFlags(body, rpc.WithRecomp, rpc.NoMetaData)
		for _, p := range rpc.Params {
			pb, err := BuildRPCParam(p)
			if err != nil {
				return nil, err
			}
			body = append(body, pb...)
		}
	}
	totalLen := 8 + len(body)
	h := PacketHeader(TypeRPC, status, totalLen, spid, packetID, 0)
	out := make([]byte, totalLen)
	copy(out[:8], h[:])
	copy(out[8:], body)
	return out, nil
}

// --- TransMgrReq (spec §3.5) ---

// BuildTransMgrReq builds a Transaction Manager Request packet (Type=0x0E).
// payloadHex is an optional hex-encoded RequestPayload.
func BuildTransMgrReq(reqType uint16, payloadHex string, txnDesc uint64, outstanding uint32,
	status byte, spid uint16, packetID byte) ([]byte, error) {
	var body []byte
	body = append(body, AllHeaders(txnDesc, outstanding)...)
	rt := make([]byte, 2)
	binary.LittleEndian.PutUint16(rt, reqType)
	body = append(body, rt...)
	if payloadHex != "" {
		payload, err := hex.DecodeString(payloadHex)
		if err != nil {
			return nil, fmt.Errorf("invalid trans_mgr payload hex: %w", err)
		}
		body = append(body, payload...)
	}
	totalLen := 8 + len(body)
	h := PacketHeader(TypeTransMgrReq, status, totalLen, spid, packetID, 0)
	out := make([]byte, totalLen)
	copy(out[:8], h[:])
	copy(out[8:], body)
	return out, nil
}

// --- Attention (spec §3.15) ---

// BuildAttention builds an Attention request packet (Type=0x06, no body).
func BuildAttention(spid uint16, packetID byte) []byte {
	h := PacketHeader(TypeAttention, StatusEOM, 8, spid, packetID, 0)
	return h[:]
}
