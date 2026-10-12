package pcapparser

// P2c 货架协议解析器（D-PARSE-1 §P3 P2c 表；字段面=引擎层字段字典镜像，
// 规范依据=引擎生成契约引用的规范文本）。全部端口门禁（edp/vmess 教训），
// 签名可核的加签名。专有协议（dameng/moxa/openwire）只做识别+头部安全面，
// 深字段待确认后另批。

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ---- BGP（RFC 4271 §4；TCP 179）----

type bgpParser struct{}

func (bgpParser) Name() string { return "bgp" }

func (bgpParser) CanParse(port uint16, sample []byte) bool {
	if port != 179 || len(sample) < 19 {
		return false
	}
	for i := 0; i < 16; i++ {
		if sample[i] != 0xFF {
			return false
		}
	}
	return true
}

func (bgpParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "bgp", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "bgp", Extra: map[string]any{}}
	typeNames := map[byte]string{1: "open", 2: "update", 3: "notification", 4: "keepalive", 5: "route_refresh"}
	off := 0
	var types []string
	fields := map[string]any{}
	for off+19 <= len(stream) && len(types) < 32 {
		for i := 0; i < 16; i++ {
			if stream[off+i] != 0xFF {
				detail.Truncated = true
				off = len(stream)
				break
			}
		}
		if off >= len(stream) {
			break
		}
		l := int(binary.BigEndian.Uint16(stream[off+16 : off+18]))
		bt := stream[off+18]
		name := typeNames[bt]
		if name == "" {
			name = fmt.Sprintf("type_%d", bt)
		}
		types = append(types, name)
		if bt == 1 && off+19+10 <= len(stream) { // OPEN：version+myAS+hold+BGPID（§4.2）
			fields["version"] = stream[off+19]
			fields["my_as"] = binary.BigEndian.Uint16(stream[off+20 : off+22])
			fields["hold_time"] = binary.BigEndian.Uint16(stream[off+22 : off+24])
			fields["bgp_id"] = netIP4(stream[off+24 : off+28])
		}
		if l < 19 || off+l > len(stream) {
			detail.Truncated = true
			break
		}
		off += l
	}
	fields["message_types"] = types
	res.Metadata["message_types"] = types
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- Modbus（MODBUS V1.1b3 §6 MBAP；TCP 502）----

type modbusParser struct{}

func (modbusParser) Name() string { return "modbus" }

func (modbusParser) CanParse(port uint16, sample []byte) bool {
	if port != 502 || len(sample) < 8 {
		return false
	}
	return binary.BigEndian.Uint16(sample[2:4]) == 0
}

func (modbusParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "modbus", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "modbus", Extra: map[string]any{}}
	fields := map[string]any{
		"transaction_id": binary.BigEndian.Uint16(stream[0:2]),
		"unit_id":        stream[6],
		"function_code":  stream[7],
	}
	res.Metadata["transaction_id"] = fields["transaction_id"]
	// 异常响应：function|0x80 + exception code（§6 MODBUS 异常面）
	if stream[7]&0x80 != 0 && len(stream) >= 9 {
		fields["exception_code"] = stream[8]
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- Redis RESP（redis 官方 protocol spec；TCP 6379）----

type redisParser struct{}

func (redisParser) Name() string { return "redis" }

func (redisParser) CanParse(port uint16, sample []byte) bool {
	if port != 6379 || len(sample) < 4 {
		return false
	}
	switch sample[0] {
	case '+', '-', ':', '$', '*':
		return true
	}
	return false
}

func (redisParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "redis", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "redis", Extra: map[string]any{}}
	lines := linesOf(stream, 128)
	var cmds []string
	for _, ln := range lines {
		if ln == "" {
			continue
		}
		switch ln[0] {
		case '*': // 数组：其后 $len 行为命令词（RESP 请求面）
			continue
		case '$':
			continue
		case '+', '-', ':':
			if strings.IndexByte(ln, ' ') > 0 || len(ln) > 1 {
				// 简化：非空响应面不计命令
			}
		default:
			// inline 命令
			cmds = append(cmds, strings.ToUpper(strings.SplitN(ln, " ", 2)[0]))
		}
	}
	// RESP 数组面：重建命令词（*N 后每个 $len 后随词）
	var words []string
	for i, ln := range lines {
		if ln == "" {
			continue
		}
		if ln[0] == '$' && i+1 < len(lines) {
			words = append(words, lines[i+1])
		}
	}
	if words != nil {
		var realCmds []string
		for i, w := range words {
			if i%2 == 0 || len(words) == 1 { // 奇位=命令词（name/value 对中的 name）
				if strings.ToUpper(w) == w || i == 0 {
					realCmds = append(realCmds, strings.ToUpper(w))
				}
			}
		}
		if realCmds != nil {
			cmds = realCmds
		}
	}
	fields := map[string]any{}
	if cmds != nil {
		fields["commands"] = cmds
		res.Metadata["commands"] = cmds
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- MySQL（MySQL Internals 官方；TCP 3306）----

type mysqlParser struct{}

func (mysqlParser) Name() string { return "mysql" }

func (mysqlParser) CanParse(port uint16, sample []byte) bool {
	// greeting 签名（seq=0+proto=10）独立成立——服务端 greeting 反向到达
	// 瞬态口时端口门禁会漏（双源对账实测），双条件并集
	if port == 3306 && len(sample) >= 6 {
		return true
	}
	return len(sample) >= 6 && sample[3] == 0 && sample[4] == 10
}

func (mysqlParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "mysql", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "mysql", Extra: map[string]any{}}
	fields := map[string]any{
		"sequence": stream[3],
	}
	// greeting：protocol(1) + version NUL 串（Internals §14.1.3）
	if stream[4] == 10 && len(stream) > 5 {
		end := strings.IndexByte(string(stream[5:]), 0)
		if end > 0 {
			fields["server_version"] = string(stream[5 : 5+end])
			res.Metadata["server_version"] = fields["server_version"]
		}
	}
	// 命令面：seq=0 + command byte（0x03 COM_QUERY / 0x0E COM_PING 等）
	if len(stream) >= 6 && stream[3] == 0 && stream[4] != 10 {
		cmdNames := map[byte]string{0x03: "com_query", 0x0E: "com_ping", 0x02: "com_init_db", 0x01: "com_quit"}
		if n, ok := cmdNames[stream[4]]; ok {
			fields["command"] = n
			res.Metadata["command"] = n
		}
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- PostgreSQL（官方 Frontend/Backend Protocol；TCP 5432）----

type postgresqlParser struct{}

func (postgresqlParser) Name() string { return "postgresql" }

func (postgresqlParser) CanParse(port uint16, sample []byte) bool {
	if port != 5432 || len(sample) < 8 {
		return false
	}
	// Startup: len(4) + protocol 196608 (3<<16)
	return binary.BigEndian.Uint32(sample[4:8]) == 196608 ||
		(sample[0] >= 'A' && sample[0] <= 'Z') // 消息面：类型字母
}

func (postgresqlParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "postgresql", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "postgresql", Extra: map[string]any{}}
	fields := map[string]any{}
	proto := binary.BigEndian.Uint32(stream[4:8])
	if proto == 196608 {
		fields["startup"] = true
		// key\0value\0 序列（§3.5.3）：键值成对提取
		off := 8
		var lastKey string
		for off < len(stream) && stream[off] != 0 {
			end := strings.IndexByte(string(stream[off:]), 0)
			if end < 0 {
				break
			}
			kv := string(stream[off : off+end])
			if lastKey == "user" {
				fields["user"] = kv
			} else if lastKey == "database" {
				fields["database"] = kv
			}
			lastKey = kv
			off += end + 1
		}
	} else if stream[0] >= 'A' && stream[0] <= 'Z' {
		// 消息面：type 字母 + len(4)（§4.1：Q query/R auth/C command...）
		msgNames := map[byte]string{'Q': "query", 'R': "authentication", 'C': "command_complete", 'Z': "ready_for_query", 'E': "error", 'T': "row_description", 'D': "data_row"}
		if n, ok := msgNames[stream[0]]; ok {
			fields["message_type"] = n
			res.Metadata["message_type"] = n
		}
		fields["length"] = binary.BigEndian.Uint32(stream[1:5])
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- IEC 60870-5-104（IEC 官方；TCP 2404）----

type iec104Parser struct{}

func (iec104Parser) Name() string { return "iec104" }

func (iec104Parser) CanParse(port uint16, sample []byte) bool {
	if port != 2404 || len(sample) < 6 {
		return false
	}
	return sample[0] == 0x68 && int(sample[1])+2 == len(sample)
}

func (iec104Parser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "iec104", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "iec104", Extra: map[string]any{}}
	c1 := stream[2]
	fields := map[string]any{"apdu_length": stream[1]}
	var kind string
	switch {
	case c1&0x01 == 0: // I-format：信息传输（ASDU 面）
		kind = "message"
		if len(stream) >= 8 {
			fields["type_id"] = stream[6]
			fields["vsq"] = stream[7]
			res.Metadata["type_id"] = stream[6]
		}
	case c1&0x03 == 1: // S-format：监视
		kind = "message"
		fields["format"] = "S"
	default: // U-format：控制（STARTDT/STOPDT/TESTFR，§5.2）
		kind = "message"
		fields["format"] = "U"
		switch c1 {
		case 0x07:
			fields["u_function"] = "startdt_act"
		case 0x13:
			fields["u_function"] = "stopdt"
		case 0x43:
			fields["u_function"] = "testfr_act"
		}
	}
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- DNP3（IEEE 1815；TCP 20000）----

type dnp3Parser struct{}

func (dnp3Parser) Name() string { return "dnp3" }

func (dnp3Parser) CanParse(port uint16, sample []byte) bool {
	if port != 20000 || len(sample) < 10 {
		return false
	}
	return sample[0] == 0x05 && sample[1] == 0x64
}

func (dnp3Parser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "dnp3", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "dnp3", Extra: map[string]any{}}
	fields := map[string]any{
		"length":     stream[2],
		"control":    stream[3],
		"dst_addr":   binary.LittleEndian.Uint16(stream[4:6]),
		"src_addr":   binary.LittleEndian.Uint16(stream[6:8]),
		"crc":        hex.EncodeToString(stream[8:10]),
	}
	// 应用层（TPDU）：0xC0/0xC1 FIR FIN + sequence + app function（IEEE 1815 §6.3）
	if len(stream) >= 12 && stream[10]&0xC0 == 0xC0 {
		fields["fir"] = stream[10]&0x80 != 0
		fields["fin"] = stream[10]&0x40 != 0
		fields["sequence"] = stream[10] & 0x0F
		if len(stream) >= 12 {
			fn := stream[11]
			fnNames := map[byte]string{0x02: "write", 0x01: "confirm", 0x81: "response"}
			if n, ok := fnNames[fn]; ok {
				fields["app_function"] = n
				res.Metadata["app_function"] = n
			}
		}
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- SMB（MS-SMB2 §1.4 NetBIOS 会话头；TCP 445）----

type smbParser struct{}

func (smbParser) Name() string { return "smb" }

func (smbParser) CanParse(port uint16, sample []byte) bool {
	if port != 445 || len(sample) < 8 {
		return false
	}
	return sample[0] == 0 && ((sample[4] == 0xFF && sample[5] == 'S' && sample[6] == 'M' && sample[7] == 'B') ||
		(sample[4] == 0xFE && sample[5] == 'S' && sample[6] == 'M' && sample[7] == 'B'))
}

func (smbParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "smb", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "smb", Extra: map[string]any{}}
	fields := map[string]any{
		"netbios_len": int(stream[1])<<16 | int(binary.BigEndian.Uint16(stream[2:4])),
	}
	if stream[4] == 0xFE { // SMB2 头：protocol id(4) + structure size(2) + credit charge + status(4) + command(2)（§2.2.1）
		if len(stream) >= 16 {
			fields["dialect"] = "smb2"
			fields["command"] = binary.BigEndian.Uint16(stream[14:16])
			cmdNames := map[uint16]string{0: "negotiate", 1: "session_setup", 2: "logoff", 3: "tree_connect", 5: "create", 8: "read", 9: "write", 16: "close"}
			if n, ok := cmdNames[fields["command"].(uint16)]; ok {
				fields["command_name"] = n
				res.Metadata["command"] = n
			}
		}
	} else { // SMB1：command 在 NetBIOS(4B)+protocol(4B) 之后 = @8
		fields["dialect"] = "smb1"
		if len(stream) >= 9 {
			fields["command"] = stream[8]
		}
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- NFS over ONC RPC（RFC 5531 §8/§11 + RFC 1813；TCP 2049）----

type nfsParser struct{}

func (nfsParser) Name() string { return "nfs" }

func (nfsParser) CanParse(port uint16, sample []byte) bool {
	// TCP 载荷带 record mark（引擎 recordMark()=0x80000000|len，RFC 5531
	// §11）：program 在 mark 后 = @16:20
	if port != 2049 || len(sample) < 28 {
		return false
	}
	return binary.BigEndian.Uint32(sample[16:20]) == 100003
}

func (nfsParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "nfs", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "nfs", Extra: map[string]any{}}
	xid := binary.BigEndian.Uint32(stream[4:8])  // record mark 后（引擎 recordMark()，RFC 5531 §11）
	msgType := binary.BigEndian.Uint32(stream[8:12])
	kind := "request"
	if msgType == 1 {
		kind = "response"
	}
	fields := map[string]any{
		"xid":          xid,
		"msg_type":     msgType,
		"rpc_version":  binary.BigEndian.Uint32(stream[12:16]),
		"program":      binary.BigEndian.Uint32(stream[16:20]),
		"proc":         binary.BigEndian.Uint32(stream[24:28]),
	}
	// NFS 版本在 program 版本字段 @20:24
	fields["nfs_version"] = binary.BigEndian.Uint32(stream[20:24])
	res.Metadata["xid"] = xid
	res.Metadata["proc"] = fields["proc"]
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- HL7 v2 MLLP（HL7 v2 官方；TCP 2575）----

type hl7Parser struct{}

func (hl7Parser) Name() string { return "hl7" }

func (hl7Parser) CanParse(port uint16, sample []byte) bool {
	if port != 2575 || len(sample) < 8 {
		return false
	}
	return sample[0] == 0x0B && sample[1] == 'M' && sample[2] == 'S' && sample[3] == 'H'
}

func (hl7Parser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "hl7", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "hl7", Extra: map[string]any{}}
	fields := map[string]any{}
	// MLLP：0x0B + HL7 + 0x1C 0x0D（MLLP framing）
	body := stream[1:]
	if len(body) >= 2 && body[len(body)-2] == 0x1C && body[len(body)-1] == 0x0D {
		body = body[:len(body)-2]
	} else {
		detail.Truncated = true
	}
	// MSH 段（HL7 v2 §2.6）：MSH|^~\&|sending_app|...|message_type...
	segs := strings.Split(string(body), "\r")
	for _, seg := range segs {
		if strings.HasPrefix(seg, "MSH") {
			f := strings.Split(seg, "|")
			if len(f) >= 10 {
				fields["sending_app"] = f[2]
				fields["message_type"] = f[8]
				res.Metadata["message_type"] = f[8]
				fields["control_id"] = f[9]
			}
			break
		}
	}
	segments := strings.Count(string(body), "\r") + 1
	fields["segment_count"] = segments
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- OPC UA（IEC 62541-6 §6.5；TCP 4840）----

type opcuaParser struct{}

func (opcuaParser) Name() string { return "opcua" }

func (opcuaParser) CanParse(port uint16, sample []byte) bool {
	if port != 4840 || len(sample) < 8 {
		return false
	}
	t := string(sample[:3])
	switch t {
	case "HEL", "ACK", "OPN", "MSG", "CLO":
		return true
	}
	return false
}

func (opcuaParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "opcua", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "opcua", Extra: map[string]any{}}
	msgType := string(stream[:3])
	fields := map[string]any{
		"message_type": msgType,
		"chunk":        string(stream[3:4]),
		"size":         binary.BigEndian.Uint32(stream[4:8]),
	}
	res.Metadata["message_type"] = msgType
	if msgType == "HEL" && len(stream) >= 12 { // Hello：protocol version + receive/send buffer（§6.5.2）
		fields["protocol_version"] = binary.BigEndian.Uint32(stream[8:12])
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- AMQP 0-9-1（OASIS/官方 §4.2 帧面；TCP 5672）----

type amqpParser struct{}

func (amqpParser) Name() string { return "amqp" }

func (amqpParser) CanParse(port uint16, sample []byte) bool {
	if port != 5672 || len(sample) < 8 {
		return false
	}
	return string(sample[:4]) == "AMQP"
}

func (amqpParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "amqp", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "amqp", Extra: map[string]any{}}
	fields := map[string]any{
		"protocol_major": stream[6],
		"protocol_minor": stream[7],
	}
	// 帧面（§4.2.1）：type(1) channel(2) size(4)——method=1 heartbeat=8
	off := 8
	if off+7 <= len(stream) {
		ft := stream[off]
		frameNames := map[byte]string{1: "method", 2: "header", 3: "body", 8: "heartbeat"}
		if n, ok := frameNames[ft]; ok {
			fields["frame_type"] = n
		}
		fields["channel"] = binary.BigEndian.Uint16(stream[off+1 : off+3])
		fields["frame_size"] = binary.BigEndian.Uint32(stream[off+3 : off+7])
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- CQL v4（Cassandra 官方 Binary Protocol v4+；TCP 9042）----

type cqlParser struct{}

func (cqlParser) Name() string { return "cql" }

func (cqlParser) CanParse(port uint16, sample []byte) bool {
	if port != 9042 || len(sample) < 9 {
		return false
	}
	v := sample[0] & 0x7F
	return v >= 3 && v <= 5 && sample[2] == 0 && sample[3] == 0 // stream=0 常见于首帧
}

func (cqlParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "cql", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "cql", Extra: map[string]any{}}
	opNames := map[byte]string{
		0x00: "error", 0x01: "startup", 0x02: "ready", 0x05: "options",
		0x06: "supported", 0x07: "query", 0x0A: "execute", 0x08: "prepare",
	}
	op := stream[4] // header: version(1)+flags(1)+stream(2)+opcode(1)+length(4)
	fields := map[string]any{
		"version": stream[0] & 0x7F,
		"opcode":  fmt.Sprintf("0x%02x", op),
		"length":  binary.BigEndian.Uint32(stream[5:9]),
	}
	if n, ok := opNames[op]; ok {
		fields["opcode_name"] = n
		res.Metadata["opcode_name"] = n
	}
	kind := "message"
	if op == 0x07 || op == 0x0A || op == 0x01 || op == 0x05 {
		kind = "request"
	}
	if op == 0x00 || op == 0x02 || op == 0x06 {
		kind = "response"
	}
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- TDS（MS-TDS；TCP 1433）----

type tdsParser struct{}

func (tdsParser) Name() string { return "tds" }

func (tdsParser) CanParse(port uint16, sample []byte) bool {
	if port != 1433 || len(sample) < 8 {
		return false
	}
	t := sample[0]
	return t == 0x12 || t == 0x02 || t == 0x01 || t == 0x04 || t == 0x0F || t == 0x17
}

func (tdsParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "tds", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "tds", Extra: map[string]any{}}
	typeNames := map[byte]string{
		0x12: "prelogin", 0x02: "prelogin_response", 0x01: "sql_batch",
		0x04: "rpc", 0x0F: "logout", 0x17: "attention",
	}
	fields := map[string]any{
		"packet_type": typeNames[stream[0]],
		"status":      stream[1],
		"length":      binary.BigEndian.Uint16(stream[2:4]),
		"spid":        binary.BigEndian.Uint16(stream[4:6]),
	}
	res.Metadata["packet_type"] = fields["packet_type"]
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- Thrift（ASF binary protocol framed；TCP 9090）----

type thriftParser struct{}

func (thriftParser) Name() string { return "thrift" }

func (thriftParser) CanParse(port uint16, sample []byte) bool {
	if port != 9090 || len(sample) < 9 {
		return false
	}
	l := int(binary.BigEndian.Uint32(sample[0:4]))
	if l >= 0 && l <= len(sample)-4 { // framed
		return len(sample) >= 6 && sample[4]&0x80 != 0 // version 高位
	}
	return sample[0]&0x80 != 0 // unframed
}

func (thriftParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "thrift", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "thrift", Extra: map[string]any{}}
	framed := len(stream) >= 6 && stream[4]&0x80 != 0
	unframed := !framed && stream[0]&0x80 != 0
	fields := map[string]any{"framed": framed}
	off := 0
	if unframed {
		off = 0
	} else if framed {
		off = 4
	} else {
		detail.Truncated = true
	}
	if off+2 <= len(stream) {
		ver := int(binary.BigEndian.Uint16(stream[off : off+2])) & 0x7FFF
		fields["version"] = ver                       // 15 位版本号（符号位已掩）
		fields["message_type"] = ver & 0x07 // 1 call 2 reply 3 exception 4 oneway
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- MongoDB OP_MSG（MongoDB 官方 wire protocol；TCP 27017）----

type mongodbParser struct{}

func (mongodbParser) Name() string { return "mongodb" }

func (mongodbParser) CanParse(port uint16, sample []byte) bool {
	if port != 27017 || len(sample) < 16 {
		return false
	}
	return binary.LittleEndian.Uint32(sample[12:16]) == 2013 // OP_MSG（全小端）
}

func (mongodbParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "mongodb", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "mongodb", Extra: map[string]any{}}
	fields := map[string]any{
		// MongoDB wire protocol 全小端（引擎 builder LittleEndian 实证，
		// P2c 复审发现 3：BigEndian 致真实流量永不识别）
		"length":      binary.LittleEndian.Uint32(stream[0:4]),
		"request_id":  binary.LittleEndian.Uint32(stream[4:8]),
		"response_to": binary.LittleEndian.Uint32(stream[8:12]),
		"opcode":      2013,
	}
	kind := "request"
	if fields["response_to"].(uint32) != 0 {
		kind = "response"
	}
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- PCEP（RFC 5440 §6.3；TCP 8181）----

type pcepParser struct{}

func (pcepParser) Name() string { return "pcep" }

func (pcepParser) CanParse(port uint16, sample []byte) bool {
	if port != 8181 || len(sample) < 4 {
		return false
	}
	return sample[0]>>5 == 0 // version 0
}

func (pcepParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "pcep", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "pcep", Extra: map[string]any{}}
	msgType := stream[0] & 0x1F
	typeNames := map[byte]string{
		1: "open", 2: "keepalive", 3: "path_computation_request",
		4: "path_computation_reply", 5: "notification", 6: "error",
	}
	fields := map[string]any{
		"message_type": msgType,
		"length":       binary.BigEndian.Uint16(stream[2:4]),
	}
	if n, ok := typeNames[msgType]; ok {
		fields["message_name"] = n
		res.Metadata["message_name"] = n
	}
	kind := "message"
	switch msgType {
	case 3, 1:
		kind = "request"
	case 4, 2, 6:
		kind = "response"
	}
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- NTLM（MS-NLMP §2.2；签名识别）----

type ntlmParser struct{}

func (ntlmParser) Name() string { return "ntlm" }

func (ntlmParser) CanParse(port uint16, sample []byte) bool {
	return len(sample) >= 12 && string(sample[:8]) == "NTLMSSP\x00"
}

func (ntlmParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "ntlm", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "ntlm", Extra: map[string]any{}}
	t := binary.LittleEndian.Uint32(stream[8:12])
	typeNames := map[uint32]string{1: "negotiate", 2: "challenge", 3: "authenticate"}
	fields := map[string]any{"message_type": typeNames[t]}
	res.Metadata["message_type"] = typeNames[t]
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- SPNEGO（RFC 4178；NegTokenInit OID 签名）----

type spnegoParser struct{}

func (spnegoParser) Name() string { return "spnego" }

func (spnegoParser) CanParse(port uint16, sample []byte) bool {
	// 06 06 2B 06 01 05 05 02 = OID 1.3.6.1.5.5.2（SPNEGO mech）
	return len(sample) >= 8 && sample[0] == 0x06 && sample[1] == 0x06 &&
		sample[2] == 0x2B && sample[3] == 0x06 && sample[4] == 0x01 &&
		sample[5] == 0x05 && sample[6] == 0x05 && sample[7] == 0x02
}

func (spnegoParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "spnego", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "spnego", Extra: map[string]any{}}
	fields := map[string]any{"neg_token_init": true}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- NMEA 0183（IEC 61162-1；TCP 载体）----

type nmeaParser struct{}

func (nmeaParser) Name() string { return "nmea" }

func (nmeaParser) CanParse(port uint16, sample []byte) bool {
	return len(sample) >= 9 && sample[0] == '$' && strings.IndexByte(string(sample), '*') > 0
}

func (nmeaParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "nmea", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "nmea", Extra: map[string]any{}}
	lines := linesOf(stream, 128)
	var sentences []map[string]any
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if len(ln) < 9 || ln[0] != '$' {
			continue
		}
		star := strings.LastIndexByte(ln, '*')
		if star < 0 {
			continue
		}
		// 校验和（IEC 61162-1：$ 与 * 之间异或）
		xor := byte(0)
		for i := 1; i < star; i++ {
			xor ^= ln[i]
		}
		given, err := strconv.ParseUint(ln[star+1:], 16, 8)
		s := map[string]any{
			"talker_sentence": ln[1:min(star, 8)],
			"checksum_ok":     err == nil && byte(given) == xor,
		}
		if strings.IndexByte(ln[:star], ',') > 0 {
			f := strings.Split(ln[1:star], ",")
			s["sentence_type"] = f[0]
		}
		sentences = append(sentences, s)
	}
	fields := map[string]any{"sentences": sentences}
	if sentences != nil {
		res.Metadata["sentence_count"] = len(sentences)
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- GB/T 32960.3（国标；TCP，帧头 0x23 0x23）----

type gbt32960Parser struct{}

func (gbt32960Parser) Name() string { return "gbt32960" }

func (gbt32960Parser) CanParse(port uint16, sample []byte) bool {
	// 端口门禁（引擎缺省 10020）+ 帧头 0x23 0x23（P2c 复审发现 4：无门禁
	// 时跨端口 2323 前缀流量可误标）
	if port != 10020 && port != 32960 {
		return false
	}
	return len(sample) >= 24 && sample[0] == 0x23 && sample[1] == 0x23
}

func (gbt32960Parser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "gbt32960", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "gbt32960", Extra: map[string]any{}}
	cmdNames := map[byte]string{1: "vehicle_login", 2: "vehicle_logout", 3: "realtime_report", 4: "reissue_report", 5: "platform_login", 6: "platform_logout", 7: "heartbeat", 8: "vehicle_check", 0x81: "vehicle_login_resp", 0x82: "vehicle_logout_resp", 0x83: "realtime_report_resp"}
	cmd := stream[2]
	resp := stream[3] // 应答标志（0 下发 1 上行应答）
	fields := map[string]any{
		"command": fmt.Sprintf("0x%02x", cmd),
		"resp":    resp,
		"vin":     strings.TrimRight(string(stream[4:21]), "\x00"),
		"data_len": binary.BigEndian.Uint16(stream[22:24]),
	}
	if n, ok := cmdNames[cmd]; ok {
		fields["command_name"] = n
		res.Metadata["command_name"] = n
	}
	kind := "request"
	if resp == 1 {
		kind = "response"
	}
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- JT/T 808（行标；TCP，帧 0x7E 包裹）----

type jt808Parser struct{}

func (jt808Parser) Name() string { return "jt808" }

func (jt808Parser) CanParse(port uint16, sample []byte) bool {
	// 端口门禁（7611 引擎缺省）+ 帧首 0x7E——0x7E 单字节太弱不能裸签
	if port != 7611 || len(sample) < 22 {
		return false
	}
	return sample[0] == 0x7E
}

func (jt808Parser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "jt808", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "jt808", Extra: map[string]any{}}
	fields := map[string]any{
		"message_id": binary.BigEndian.Uint16(stream[1:3]),
		"properties": binary.BigEndian.Uint16(stream[3:5]),
		"phone":      hex.EncodeToString(stream[5:11]),
		"sequence":   binary.BigEndian.Uint16(stream[11:13]),
	}
	res.Metadata["message_id"] = fields["message_id"]
	kind := "request"
	if fields["message_id"].(uint16)&0x8000 != 0 {
		kind = "response"
	}
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- JT/T 809（行标；TCP，帧头 0x30 0x30）----

type jt809Parser struct{}

func (jt809Parser) Name() string { return "jt809" }

func (jt809Parser) CanParse(port uint16, sample []byte) bool {
	// 引擎线格式（protocol/jt809/builder.go buildFrame）：0x5B + MsgLength(4)
	// + ... + CRC16(2) + 0x5D，无 0x3030 标识（P2c 复审发现 1：0x3030 假设
	// 致引擎帧永不识别）
	if port != 8812 || len(sample) < 26 {
		return false
	}
	return sample[0] == 0x5B && sample[len(sample)-1] == 0x5D
}

func (jt809Parser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "jt809", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "jt809", Extra: map[string]any{}}
	fields := map[string]any{
		"msg_length":     binary.BigEndian.Uint32(stream[1:5]),
		"msg_sn":         binary.BigEndian.Uint32(stream[5:9]),
		"msg_id":         binary.BigEndian.Uint16(stream[9:11]),
		"gnss_center_id": binary.BigEndian.Uint32(stream[11:15]),
		"version":        fmt.Sprintf("%d.%d.%d", stream[15], stream[16], stream[17]),
	}
	res.Metadata["msg_id"] = fields["msg_id"]
	res.Metadata["msg_sn"] = fields["msg_sn"]
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- JT/T 905（粤标；TCP，引擎缺省 10700）----

type jtt905Parser struct{}

func (jtt905Parser) Name() string { return "jtt905" }

func (jtt905Parser) CanParse(port uint16, sample []byte) bool {
	if port != 10700 || len(sample) < 8 {
		return false
	}
	return true
}

func (jtt905Parser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "jtt905", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "jtt905", Extra: map[string]any{}}
	fields := map[string]any{
		"header_hex": hex.EncodeToString(stream[:min(8, len(stream))]),
		"payload_len": len(stream),
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- Moxa（专有；TCP 4800）----

type moxaParser struct{}

func (moxaParser) Name() string { return "moxa" }

func (moxaParser) CanParse(port uint16, sample []byte) bool {
	return port == 4800 && len(sample) >= 8
}

func (moxaParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "moxa", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "moxa", Extra: map[string]any{}}
	fields := map[string]any{
		"magic": hex.EncodeToString(stream[:4]),
		"opcode": stream[4],
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- 达梦 DM（专有；TCP 5236）----

type damengParser struct{}

func (damengParser) Name() string { return "dameng" }

func (damengParser) CanParse(port uint16, sample []byte) bool {
	return port == 5236 && len(sample) >= 8
}

func (damengParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "dameng", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "dameng", Extra: map[string]any{}}
	fields := map[string]any{
		"length": binary.BigEndian.Uint32(stream[0:4]),
		"opcode": binary.BigEndian.Uint16(stream[4:6]),
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- Oracle TNS（专有；TCP 1521，头面公开）----

type tnsParser struct{}

func (tnsParser) Name() string { return "tns" }

func (tnsParser) CanParse(port uint16, sample []byte) bool {
	if port != 1521 || len(sample) < 8 {
		return false
	}
	t := sample[4]
	return t <= 14 && t != 0
}

func (tnsParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "tns", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "tns", Extra: map[string]any{}}
	typeNames := map[byte]string{1: "connect", 2: "accept", 4: "refuse", 5: "redirect", 6: "data", 9: "abort", 11: "marker", 12: "attention", 13: "control", 14: "unknown"}
	fields := map[string]any{
		"length":        binary.BigEndian.Uint16(stream[0:2]),
		"packet_type":   typeNames[stream[4]],
	}
	res.Metadata["packet_type"] = fields["packet_type"]
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- DRDA（IBM DDM；TCP 446，DDM 魔数 0xD0）----

type drdaParser struct{}

func (drdaParser) Name() string { return "drda" }

func (drdaParser) CanParse(port uint16, sample []byte) bool {
	if port != 446 || len(sample) < 6 {
		return false
	}
	return sample[2] == 0xD0
}

func (drdaParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "drda", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "drda", Extra: map[string]any{}}
	fields := map[string]any{
		"length":       binary.BigEndian.Uint16(stream[0:2]),
		"magic":        "0xD0",
		"format":       stream[3],
		"correlation_id": binary.BigEndian.Uint16(stream[4:6]),
	}
	if len(stream) >= 10 {
		codePoints := map[uint16]string{
			0x1041: "excsecins", 0x1061: "accsec", 0x1062: "accsecrd",
			0x2009: "secchk", 0x2010: "secchkd", 0x200D: "cntqry",
			0x200E: "opnqry", 0x2408: "qrydsc", 0x2447: "qrydta",
		}
		cp := binary.BigEndian.Uint16(stream[8:10])
		if n, ok := codePoints[cp]; ok {
			fields["codepoint"] = n
			res.Metadata["codepoint"] = n
		}
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- EtherNet/IP（ODVA；TCP 44818，24B ENIP 头）----

type enipParser struct{}

func (enipParser) Name() string { return "enip" }

func (enipParser) CanParse(port uint16, sample []byte) bool {
	if port != 44818 || len(sample) < 24 {
		return false
	}
	return binary.BigEndian.Uint16(sample[0:2]) <= 100 // command 合理域
}

func (enipParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "enip", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "enip", Extra: map[string]any{}}
	cmd := binary.BigEndian.Uint16(stream[0:2])
	cmdNames := map[uint16]string{0x0004: "register_session", 0x0065: "unregister_session", 0x0066: "send_rr_data", 0x006F: "send_unit_data"}
	fields := map[string]any{
		"command":       fmt.Sprintf("0x%04x", cmd),
		"session":       binary.BigEndian.Uint32(stream[4:8]),
		"status":        binary.BigEndian.Uint32(stream[8:12]),
		"length":        binary.BigEndian.Uint16(stream[2:4]),
	}
	if n, ok := cmdNames[cmd]; ok {
		fields["command_name"] = n
		res.Metadata["command_name"] = n
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- S7（Siemens；TPKT+COTP+0x32 协议 ID，TCP 102）----

type s7Parser struct{}

func (s7Parser) Name() string { return "s7" }

func (s7Parser) CanParse(port uint16, sample []byte) bool {
	if port != 102 || len(sample) < 8 {
		return false
	}
	// TPKT(4) + COTP 头(LI@4) → S7 协议 ID 0x32 在 COTP 后
	li := int(sample[4])
	// LI 含自身字节（X.224/ISO 8073）：S7 协议 ID 在 COTP 后即 4+li 处
	return li > 0 && 4+li+1 <= len(sample) && sample[4+li] == 0x32
}

func (s7Parser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "s7", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "s7", Extra: map[string]any{}}
	li := int(stream[4])
	p := 4 + li // S7 头起点（0x32 协议 ID @p）
	fields := map[string]any{"protocol_id": stream[p]}
	rosctr := stream[p+1] // ROSCTR（S7 Communication §5.1）
	rosNames := map[byte]string{1: "request", 2: "ack", 3: "response"}
	fields["rosctr"] = rosctr
	fields["pdu_reference"] = binary.BigEndian.Uint16(stream[p+2 : p+4])
	if n, ok := rosNames[rosctr]; ok {
		fields["rosctr_name"] = n
	}
	res.Metadata["rosctr"] = rosctr
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- MMS（ISO 9506；TPKT+COTP+ISO 会话，TCP 102——s7 后注册按载荷区分）----

type mmsParser struct{}

func (mmsParser) Name() string { return "mms" }

func (mmsParser) CanParse(port uint16, sample []byte) bool {
	if port != 102 || len(sample) < 12 {
		return false
	}
	// 与 s7 区分：COTP 后非 0x32 → ISO 会话/MMS
	var p2 s7Parser
	return !p2.CanParse(port, sample) && sample[0] == 3
}

func (mmsParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "mms", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "mms", Extra: map[string]any{}}
	li := int(stream[4])
	fields := map[string]any{
		"cotp_length": li,
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- AMS/ADS（Beckhoff；TCP 48898，AMS 头 32B）----

type amsParser struct{}

func (amsParser) Name() string { return "ams" }

func (amsParser) CanParse(port uint16, sample []byte) bool {
	// 引擎 "ams" 层 = 自研 wire profile（protocol/ams/builder.go）：Length(4,
	// 不含自身) | Version(1)=1 | Type(1) | Flags(2) | SessionID(4) |
	// CorrelationID(8) | Payload | FrameEnd(2)=0xAE 0x5A，TCP 61616——非
	// Beckhoff ADS（P2c 复审发现 2）。与 openwire 区分：openwire 首字节 0x01
	// 是 WireFormatInfo 类型，ams 首字段为长度高位（小帧恒 0）
	if port != 61616 || len(sample) < 22 {
		return false
	}
	return binary.BigEndian.Uint32(sample[0:4]) == uint32(len(sample)-4) &&
		sample[4] == 1 &&
		sample[len(sample)-2] == 0xAE && sample[len(sample)-1] == 0x5A
}

func (amsParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "ams", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "ams", Extra: map[string]any{}}
	fields := map[string]any{
		"length":        binary.BigEndian.Uint32(stream[0:4]),
		"version":       stream[4],
		"type":          stream[5],
		"flags":         binary.BigEndian.Uint16(stream[6:8]),
		"session_id":    binary.BigEndian.Uint32(stream[8:12]),
		"correlation_id": hex.EncodeToString(stream[12:20]),
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}


// ---- OpenVPN（UDP/TCP 1194；UDP V2 HMAC 帧 + 内嵌 TLS ClientHello）----

type openvpnParser struct{}

func (openvpnParser) Name() string { return "openvpn" }

func (openvpnParser) CanParse(port uint16, sample []byte) bool {
	if port != 1194 || len(sample) < 1 {
		return false
	}
	// UDP: 首字节 = opcode<<3 | key_id；TCP: 2B length 前缀后才是 opcode
	off := 0
	if len(sample) >= 3 {
		// TCP 封装：2B BE length 前缀（OpenVPN §3.1 TCP transport）
		tcpLen := int(sample[0])<<8 | int(sample[1])
		if tcpLen >= int(len(sample))-2 && tcpLen <= int(len(sample)) {
			off = 2 // TCP 模式：跳过 length 前缀
		}
	}
	if off >= len(sample) {
		return false
	}
	// opcode 高 5 位 1..10（OpenVPN protocol.h）
	op := sample[off] >> 3
	return op >= 1 && op <= 10
}

func (openvpnParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "openvpn", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "openvpn", Extra: map[string]any{}}
	// TCP 封装跳 2B length 前缀（OpenVPN §3.1）；UDP 无前缀
	pkt := stream
	if len(stream) >= 3 {
		tcpLen := int(stream[0])<<8 | int(stream[1])
		if tcpLen >= len(stream)-2 && tcpLen <= len(stream) {
			pkt = stream[2:]
		}
	}
	if len(pkt) < 1 {
		res.Detail = detail
		return res, nil
	}
	opcode := pkt[0] >> 3
	keyID := pkt[0] & 0x07
	opNames := map[byte]string{
		1: "control", 2: "control", 3: "data", 4: "ack",
		5: "ack", 6: "ack_v1", 7: "hard_reset_client_v2", 8: "hard_reset_server_v2",
		9: "hard_reset_client_v3", 10: "hard_reset_server_v3",
	}
	fields := map[string]any{
		"opcode":       opcode,
		"opcode_name":  opNames[opcode],
		"key_id":       keyID,
		"payload_len":  len(pkt),
	}
	// 内嵌 TLS ClientHello（V2 HMAC 后载荷中含 0x16 0x03 记录头）
	embedOff := strings.Index(string(pkt), "\x16\x03")
	if embedOff >= 0 {
		fields["embedded_tls"] = true
		fields["tls_offset"] = embedOff
		if embedOff+3 <= len(pkt) {
			fields["tls_version"] = fmt.Sprintf("%02x%02x", pkt[embedOff+1], pkt[embedOff+2])
		}
		detail.Extra["embedded_tls"] = true
		detail.Extra["tls_version"] = fields["tls_version"]
	}
	// session ID（V2：byte 1 后 8B）
	if len(pkt) >= 9 && opcode >= 7 {
		fields["session_id"] = hex.EncodeToString(pkt[1:9])
	}
	res.Metadata["opcode_name"] = fields["opcode_name"]
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- OpenWire（ActiveMQ；TCP 61616，端口门禁+WireFormatInfo 识别）----

type openwireParser struct{}

func (openwireParser) Name() string { return "openwire" }

func (openwireParser) CanParse(port uint16, sample []byte) bool {
	return port == 61616 && len(sample) >= 10 && sample[0] == 1
}

func (openwireParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "openwire", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "openwire", Extra: map[string]any{}}
	fields := map[string]any{
		"wire_format_info_type": stream[0],
		"marshal_version":       stream[5],
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}
