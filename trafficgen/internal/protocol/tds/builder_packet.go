// Package tds: builder_packet.go — TDS packet header, PRELOGIN, LOGIN7,
// ALL_HEADERS, and SQL-Batch request builders.
package tds

// PacketHeader builds an 8-byte TDS packet header (spec §2.1).
// Length is big-endian (total packet length, header+body); SPID is BE.
func PacketHeader(msgType byte, status byte, length int, spid uint16, packetID byte, window byte) [8]byte {
	var h [8]byte
	h[0] = msgType
	h[1] = status
	putBE16(h[2:4], uint16(length))
	putBE16(h[4:6], spid)
	h[6] = packetID
	h[7] = window
	return h
}

// --- PRELOGIN (spec §3.1) ---

// PreLoginOption is one PRELOGIN_OPTION entry.
type PreLoginOption struct {
	Token  byte
	Data   []byte
	Offset int // populated by BuildPreLogin; callers leave as 0
}

// BuildPreLogin builds a complete PRELOGIN packet body. Options are encoded
// as token(1B) + offset(2B BE) + len(2B BE) + TERMINATOR, with data
// appended after the option table. VERSION must be the first option;
// TERMINATOR(0xFF) must be last (these are caller responsibilities).
// Returns (pktHeader + body) as a single byte slice.
func BuildPreLogin(opts []PreLoginOption, status byte, spid uint16, packetID byte) []byte {
	// Option table: each option is 5 bytes (token 1 + offset 2 BE + len 2 BE).
	// TERMINATOR is 1 byte (0xFF).
	tableLen := 5*len(opts) + 1

	// See where the data region starts (after the option table).
	dataOff := tableLen

	// Compute the offset for each option's data.
	var data []byte
	for i := range opts {
		opts[i].Offset = dataOff
		dataOff += len(opts[i].Data)
		data = append(data, opts[i].Data...)
	}

	// Build body.
	body := make([]byte, tableLen+len(data))
	pos := 0
	for _, o := range opts {
		body[pos] = o.Token
		putBE16(body[pos+1:pos+3], uint16(o.Offset))
		putBE16(body[pos+3:pos+5], uint16(len(o.Data)))
		pos += 5
	}
	body[pos] = PLTerminator
	copy(body[pos+1:], data)

	// Header + body.
	totalLen := 8 + len(body)
	h := PacketHeader(TypePreLogin, status, totalLen, spid, packetID, 0)
	out := make([]byte, totalLen)
	copy(out[:8], h[:])
	copy(out[8:], body)
	return out
}

// BuildPreLoginResponse wraps a PRELOGIN body in a Type=0x04 (TabularResult)
// packet for the server response (spec §3.1: server response Type=0x04).
func BuildPreLoginResponse(opts []PreLoginOption, status byte, spid uint16, packetID byte) []byte {
	tableLen := 5*len(opts) + 1
	dataOff := tableLen
	var data []byte
	for i := range opts {
		opts[i].Offset = dataOff
		dataOff += len(opts[i].Data)
		data = append(data, opts[i].Data...)
	}
	body := make([]byte, tableLen+len(data))
	pos := 0
	for _, o := range opts {
		body[pos] = o.Token
		putBE16(body[pos+1:pos+3], uint16(o.Offset))
		putBE16(body[pos+3:pos+5], uint16(len(o.Data)))
		pos += 5
	}
	body[pos] = PLTerminator
	copy(body[pos+1:], data)
	totalLen := 8 + len(body)
	h := PacketHeader(TypeTabularResult, status, totalLen, spid, packetID, 0)
	out := make([]byte, totalLen)
	copy(out[:8], h[:])
	copy(out[8:], body)
	return out
}

// --- LOGIN7 (spec §3.2) ---

// Login7Field describes one login7 offset-table entry (ib + cch, both 2B LE).
type Login7Field struct {
	IB  uint16
	CCH uint16
}

// BuildLogin7 builds a complete LOGIN7 packet (spec §3.2 / S2). Returns
// the encoded packet bytes (header + LOGIN7 body).
//
// The LOGIN7 body layout is:
//
//	Length(4B LE) + TDSVersion(4B LE) + PacketSize(4B LE) + ClientProgVer(4B LE)
//	+ ClientPID(4B LE) + ConnectionID(4B LE)
//	+ OptionFlags1(1B) + OptionFlags2(1B) + TypeFlags(1B) + OptionFlags3(1B)
//	+ ClientTimeZone(4B LE) + ClientLCID(4B LE)
//	+ OffsetLength table (58B for TDS 7.2+) + Data region (UCS-2 LE fields)
//
//nolint:gocritic // large function is acceptable for protocol builder
func BuildLogin7(
	tdsVersion TDSVersion, packetSize int,
	clientPID uint32,
	optFlags1, optFlags2, typeFlags, optFlags3 byte,
	clientLCID uint32,
	hostName, userName, password, appName, serverName string,
	cltIntName, language, database string,
	mac [6]byte,
	featureExt []byte, // nil if !fExtension
) []byte {
	// Encode string fields as UCS-2 LE.
	hostUCS := encodeUTF16(hostName)
	userUCS := encodeUTF16(userName)
	pwUCS := obfuscatePassword(password)
	appUCS := encodeUTF16(appName)
	srvUCS := encodeUTF16(serverName)
	cliUCS := encodeUTF16(cltIntName)
	langUCS := encodeUTF16(language)
	dbUCS := encodeUTF16(database)

	// Compute data region and offsets.
	dataStart := 36 + 58 // TDS 7.2+ fixed header + offset table

	// Build offset table entries (13 pairs: ib(2B)+cch(2B) each, plus ClientID 6B).
	// ib values are relative to LOGIN7 body start (=dataStart for the first used
	// field). Unused fields share the offset of the next used field (monotonic non-dec).
	nextOff := dataStart
	putPair := func(v []byte) (ib, cch uint16) {
		ib = uint16(nextOff)
		cch = uint16(len(v) / 2) // UCS-2 char count
		nextOff += len(v)
		return
	}
	putEmpty := func() (ib, cch uint16) {
		return uint16(nextOff), 0
	}

	var (
		ibHost, cchHost     = putPair(hostUCS)
		ibUser, cchUser     = putPair(userUCS)
		ibPW, cchPW         = uint16(nextOff), uint16(len(pwUCS) / 2)
		ibApp, cchApp       uint16
		ibSrv, cchSrv       uint16
		ibExt, cbExt        uint16
		ibCltInt, cchCltInt uint16
		ibLang, cchLang     uint16
		ibDB, cchDB         uint16
		ibSSPI, cbSSPI      uint16
		ibAtchDB, cchAtchDB uint16
		ibChgPW, cchChgPW   uint16
		cbSSPILong          uint32
	)
	nextOff += len(pwUCS)

	ibApp, cchApp = putPair(appUCS)
	ibSrv, cchSrv = putPair(srvUCS)
	ibCltInt, cchCltInt = putPair(cliUCS)
	ibLang, cchLang = putPair(langUCS)
	ibDB, cchDB = putPair(dbUCS)

	// ibExtension/cbExtension (MS-TDS §2.2.6.4): 当 fExtension=1 时，ibExtension
	// 指向一个 4B 扩展块，该块内容为单个 DWORD `ibFeatureExtLong`；cbExtension
	// 恒为 4。DWORD 值是 FeatureExt 数据相对 LOGIN7 消息体（body）起点的偏移
	// ——与所有 ib* 字段同基准（设计文档 §3.2: ibHostName=0x5E=36+58，不含
	// 8B packet header）。FeatureExt 数据紧跟在 DWORD 之后。
	// 布局: DWORD+FeatureExt 位于 Data 区所有字段之后（设计文档 §3.2
	// `LOGIN7 = ... Data [FeatureExt]`），即 dbUCS 之后。
	// 修复 N1 (CRITICAL): 此前直接把 FeatureExt 数据放在 ibExtension 处并令
	// cbExtension=FeatureExt 长度，缺少 DWORD 间接层，真实 SQL Server 会把
	// FeatureExt 第一个字节误读为 DWORD 偏移。现在先写 4B DWORD 占位
	// （指向 FeatureExt 实际偏移），FeatureExt 数据放在数据区末尾。
	var ibFeatureExt uint32 // DWORD，FeatureExt 相对 body 起点的偏移
	if len(featureExt) > 0 {
		ibExt = uint16(nextOff) // 指向 4B DWORD 占位（body 相对偏移）
		cbExt = 4
		// DWORD 占位在 body 中的偏移 = nextOff；FeatureExt 紧随其后
		// （占位 + 4）。DWORD 值 = body 内 FeatureExt 偏移（与下方数据区
		// 写入位置一致，保证服务器按 ibFeatureExtLong 精确读到 FE 数据）。
		ibFeatureExt = uint32(nextOff + 4)
		nextOff += 4 + len(featureExt)
	} else {
		ibExt, cbExt = putEmpty()
	}

	// Empty fields
	ibSSPI, cbSSPI = putEmpty()
	ibAtchDB, cchAtchDB = putEmpty()
	ibChgPW, cchChgPW = putEmpty()

	offsets := []Login7Field{
		{ibHost, cchHost}, {ibUser, cchUser}, {ibPW, cchPW},
		{ibApp, cchApp}, {ibSrv, cchSrv}, {ibExt, cbExt},
		{ibCltInt, cchCltInt}, {ibLang, cchLang}, {ibDB, cchDB},
	}

	// Body: fixed header + offset table + data
	bodyLen := nextOff
	body := make([]byte, bodyLen)

	// Fixed header (36B).
	putLE32(body[0:4], uint32(bodyLen)) // TotalLength (== bodyLen)
	// TDSVersion 为大端网络序 (spec footnote 72: "client to server" 列即
	// 网络传输值；MS-TDS 4.2/4.4 示例 7.4 wire = 04 00 00 74 = 常量
	// 0x04000074 的 BE 编码)。此前误用 putLE32 产出 74 00 00 04 与规范
	// 示例不符。
	putBE32(body[4:8], uint32(tdsVersion))
	putLE32(body[8:12], uint32(packetSize))
	putLE32(body[12:16], 0x07000000) // ClientProgVer (default)
	putLE32(body[16:20], clientPID)
	putLE32(body[20:24], 0) // ConnectionID
	body[24] = optFlags1
	body[25] = optFlags2
	body[26] = typeFlags
	body[27] = optFlags3
	putLE32(body[28:32], 0) // ClientTimeZone
	putLE32(body[32:36], clientLCID)

	// Offset table (58B for TDS 7.2+, spec §3.2 layout):
	// 9 pairs (Host..Database) + ClientID(6B) + ibSSPI/cbSSPI +
	// ibAtchDBFile/cchAtchDBFile + ibChangePassword/cchChangePassword +
	// cbSSPILong(4B) = 36+6+4+4+4+4 = 58B.
	ot := make([]byte, 58)
	pos := 0
	for _, o := range offsets {
		putLE16(ot[pos:pos+2], o.IB)
		putLE16(ot[pos+2:pos+4], o.CCH)
		pos += 4
	}
	// ClientID (6B) — comes BEFORE the SSPI pair per spec §3.2.
	copy(ot[pos:pos+6], mac[:])
	pos += 6
	// Pair 10: ibSSPI + cbSSPI
	putLE16(ot[pos:pos+2], ibSSPI)
	putLE16(ot[pos+2:pos+4], cbSSPI)
	pos += 4
	// Pair 11: ibAtchDBFile + cchAtchDBFile
	putLE16(ot[pos:pos+2], ibAtchDB)
	putLE16(ot[pos+2:pos+4], cchAtchDB)
	pos += 4
	// Pair 12: ibChangePassword + cchChangePassword
	putLE16(ot[pos:pos+2], ibChgPW)
	putLE16(ot[pos+2:pos+4], cchChgPW)
	pos += 4
	// cbSSPILong (4B LE)
	putLE32(ot[pos:], cbSSPILong)

	copy(body[36:36+58], ot)

	// Data region.
	d := body[dataStart:]
	copy(d, hostUCS)
	d = d[len(hostUCS):]
	copy(d, userUCS)
	d = d[len(userUCS):]
	copy(d, pwUCS)
	d = d[len(pwUCS):]
	copy(d, appUCS)
	d = d[len(appUCS):]
	copy(d, srvUCS)
	d = d[len(srvUCS):]
	copy(d, cliUCS)
	d = d[len(cliUCS):]
	copy(d, langUCS)
	d = d[len(langUCS):]
	copy(d, dbUCS)
	d = d[len(dbUCS):]
	if len(featureExt) > 0 {
		// 4B DWORD: FeatureExt 相对 body 起点的偏移，见上方注释
		// （与所有 ib* 字段同基准）。DWORD 在 body 中的位置 = ibExt；d
		// 当前恰好指向 ibExt 处（DWORD+FeatureExt 位于 Data 区末尾、
		// dbUCS 之后）。FeatureExt 紧跟在 DWORD 之后。
		putLE32(d[:4], ibFeatureExt)
		copy(d[4:], featureExt)
		d = d[4+len(featureExt):]
	}
	_ = d

	// Wrap in packet header.
	totalLen := 8 + len(body)
	h := PacketHeader(TypeLogin7, StatusEOM, totalLen, 0, 1, 0)
	out := make([]byte, totalLen)
	copy(out[:8], h[:])
	copy(out[8:], body)
	return out
}

// --- ALL_HEADERS (spec §2.5) ---

// AllHeaders builds the ALL_HEADERS structure. It always includes the
// mandatory TransactionDescriptor header (Type=0x0002). For TDS < 7.2
// callers should pass tds7Plus=false; the ALL_HEADERS are not included
// in that case (the caller skips this helper entirely).
func AllHeaders(txnDesc uint64, outstanding uint32) []byte {
	// TotalLength includes itself (4B).
	// HeaderLength includes itself (4B).
	// Body: HeaderLength(4)+HeaderType(2)+TransactionDescriptor(8)+OutstandingRequestCount(4) = 18
	const hdrLen = 18
	const totalLen = 4 + hdrLen // 22
	buf := make([]byte, totalLen)
	putLE32(buf[0:4], totalLen)
	putLE32(buf[4:8], hdrLen)
	putLE16(buf[8:10], HeaderTransactionDescriptor)
	putLE64(buf[10:18], txnDesc)
	putLE32(buf[18:22], outstanding)
	return buf
}

// --- SQL Batch (spec §3.3) ---

// BuildSQLBatch builds a SQL Batch message packet (Type=0x01).
// status can include StatusResetConnection/StatusResetConnSkipTran.
func BuildSQLBatch(sqlText string, tds7Plus bool, txnDesc uint64, outstanding uint32,
	status byte, spid uint16, packetID byte) []byte {
	sqlUCS := encodeUTF16(sqlText)
	var body []byte
	if tds7Plus {
		body = append(body, AllHeaders(txnDesc, outstanding)...)
	}
	body = append(body, sqlUCS...)

	totalLen := 8 + len(body)
	h := PacketHeader(TypeSQLBatch, status, totalLen, spid, packetID, 0)
	out := make([]byte, totalLen)
	copy(out[:8], h[:])
	copy(out[8:], body)
	return out
}
