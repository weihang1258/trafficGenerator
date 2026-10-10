package pcapparser

// P2a UDP 解析器第二段（D-PARSE-1 §P3 P2a 表）。含 BER 助手（SNMP/Kerberos
// 共用）。

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// ---- BER 基元（SNMP/Kerberos 共用；X.690 TLV）----

// berTLV 读取一个 TLV。返回 class(0 universal/2 context)/constructed/tag/
// 内容起点/内容长/下一个 TLV 起点；len 不足返回 ok=false。
func berTLV(data []byte, off int) (cls int, constructed bool, tag int, cOff, cLen, next int, ok bool) {
	if off+2 > len(data) {
		return 0, false, 0, 0, 0, 0, false
	}
	b0 := data[off]
	cls = int(b0 >> 6)
	constructed = b0&0x20 != 0
	tag = int(b0 & 0x1F)
	lOff := off + 1
	if tag == 0x1F { // 多字节 tag：P2a 面不涉及，拒
		return 0, false, 0, 0, 0, 0, false
	}
	l := int(data[lOff])
	next = lOff + 1
	if l&0x80 != 0 {
		n := l & 0x7F
		if n == 0 || n > 4 || lOff+1+n > len(data) {
			return 0, false, 0, 0, 0, 0, false
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(data[lOff+1+i])
		}
		next = lOff + 1 + n
	}
	if next+l > len(data) {
		return 0, false, 0, 0, 0, 0, false
	}
	return cls, constructed, tag, next, l, next + l, true
}

// berInt 读 INTEGER 内容值（大端，最多 8 字节）。
func berInt(data []byte, off int) (int64, int, bool) {
	cls, cons, tag, cOff, cLen, next, ok := berTLV(data, off)
	if !ok || cls != 0 || cons || tag != 2 || cLen == 0 || cLen > 8 {
		return 0, off, false
	}
	var v int64
	if data[cOff]&0x80 != 0 {
		v = -1
	}
	for i := 0; i < cLen; i++ {
		v = v<<8 | int64(data[cOff+i])
	}
	return v, next, true
}

// ---- SNMP（RFC 1157 §4 v1/v2c + RFC 3412 v3；端口 161/162）----

type snmpParser struct{}

func (snmpParser) Name() string { return "snmp" }

func (snmpParser) CanParse(port uint16, sample []byte) bool {
	if port != 161 && port != 162 || len(sample) < 8 {
		return false
	}
	return sample[0] == 0x30 // SEQUENCE
}

func (snmpParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "snmp", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "snmp", Extra: map[string]any{}}
	fields := map[string]any{}
	// 外层 SEQUENCE 先解析（长/短格式都可能），INTEGER version 在其内容起点
	_, _, _, outerCOff, _, _, okOuter := berTLV(stream, 0)
	if !okOuter {
		res.Detail = detail
		return res, nil
	}
	ver, off, ok := berInt(stream, outerCOff)
	if !ok {
		res.Detail = detail
		return res, nil
	}
	fields["version"] = ver
	kind := "message"
	if ver <= 2 { // v1/v2c：community + PDU
		cls, _, _, cOff, cLen, next, ok2 := berTLV(stream, off)
		if ok2 && cls == 0 {
			fields["community"] = string(stream[cOff : cOff+cLen])
			off = next
		}
		if cls2, cons, tag, pOff, _, _, ok3 := berTLV(stream, off); ok3 && cls2 == 2 && cons {
			kind = "message"
			switch tag {
			case 0:
				fields["pdu_type"] = "get-request"
				kind = "request"
			case 1:
				fields["pdu_type"] = "get-next-request"
				kind = "request"
			case 2:
				fields["pdu_type"] = "response"
				kind = "response"
			case 3:
				fields["pdu_type"] = "set-request"
				kind = "request"
			case 4:
				fields["pdu_type"] = "trap"
			case 5:
				fields["pdu_type"] = "get-bulk-request"
				kind = "request"
			}
			// PDU: request-id error-status error-index varbind-bindings
			if rid, n1, ok4 := berInt(stream, pOff); ok4 {
				fields["request_id"] = rid
				_ = n1
			}
			// varbinds：SEQUENCE OF SEQUENCE{OID, value}（OID 面 cap 32）
			off2 := pOff
			skip := 0
			for skip < 3 { // request-id/error-status/error-index 三个 INTEGER
				_, n, ok5 := berInt(stream, off2)
				if !ok5 {
					break
				}
				off2 = n
				skip++
			}
			if cls3, cons3, _, bOff, bLen, _, ok6 := berTLV(stream, off2); ok6 && cls3 == 0 && cons3 {
				_ = bLen
				oidOff := bOff
				var oids []map[string]any
				for n := 0; n < 32; n++ {
					// varbind = SEQUENCE{OID, value}：先取 SEQUENCE，再进内容读 OID
					cls4, cons4, _, vOff, _, vNext, ok7 := berTLV(stream, oidOff)
					if !ok7 || cls4 != 0 || !cons4 {
						break
					}
					if o, c4, l4, ok8 := berOID(stream, vOff); ok8 {
						oids = append(oids, map[string]any{"oid": o, "value_hex": hex.EncodeToString(stream[c4 : c4+l4])})
					}
					oidOff = vNext
				}
				if oids != nil {
					fields["varbinds"] = oids
				}
			}
		}
	} else {
		fields["msg_version"] = "v3"
	}
	res.Metadata["version"] = fields["version"]
	res.Metadata["pdu_type"] = fields["pdu_type"]
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// berOID 渲染 OBJECT IDENTIFIER（X.690 §8.19：首字节 40a+b，后续 base128）。
func berOID(data []byte, off int) (string, int, int, bool) {
	cls, cons, tag, cOff, cLen, _, ok := berTLV(data, off)
	if !ok || cls != 0 || cons || tag != 6 || cLen == 0 {
		return "", 0, 0, false
	}
	first := int(data[cOff])
	out := fmt.Sprintf("%d.%d", first/40, first%40)
	v := 0
	for i := 1; i < cLen; i++ {
		v = v<<7 | int(data[cOff+i]&0x7F)
		if data[cOff+i]&0x80 == 0 {
			out += fmt.Sprintf(".%d", v)
			v = 0
		}
	}
	return out, cOff, cLen, true
}

// ---- Kerberos（RFC 4120 §5；UDP 88）----

type kerberosParser struct{}

func (kerberosParser) Name() string { return "kerberos" }

func (kerberosParser) CanParse(port uint16, sample []byte) bool {
	if port != 88 || len(sample) < 6 {
		return false
	}
	// application 构造型 tag：AS-REQ 6A/AS-REP 6B/TGS-REQ 6C/TGS-REP 6D/
	// AP-REQ 6E/AP-REP 6F/KRB-ERROR 7E（D-KERBEROS-1 权威表）
	switch sample[0] {
	case 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x7E:
		return true
	}
	return false
}

func (kerberosParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "kerberos", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "kerberos", Extra: map[string]any{}}
	fields := map[string]any{"app_tag": fmt.Sprintf("0x%02x", stream[0])}
	kind := "message"
	var msgType int64
	switch stream[0] {
	case 0x6A:
		kind = "request"
		fields["message"] = "as-req"
	case 0x6B:
		kind = "response"
		fields["message"] = "as-rep"
	case 0x6C:
		kind = "request"
		fields["message"] = "tgs-req"
	case 0x6D:
		kind = "response"
		fields["message"] = "tgs-rep"
	case 0x6E:
		kind = "request"
		fields["message"] = "ap-req"
	case 0x6F:
		kind = "response"
		fields["message"] = "ap-rep"
	case 0x7E:
		kind = "response"
		fields["message"] = "krb-error"
	}
	// msg-type：KDC-REQ/REP 内 context [2]（A2 03 02 01 xx）浅扫（RFC 4120
	// §5.4.1 结构面；KRB-ERROR msg-type=30）
	head := stream
	if len(head) > 64 {
		head = head[:64]
	}
	for i := 0; i+5 <= len(head); i++ {
		if head[i] == 0xA2 && head[i+1] == 0x03 && head[i+2] == 0x02 && head[i+3] == 0x01 {
			msgType = int64(head[i+4])
			break
		}
	}
	if stream[0] == 0x7E {
		msgType = 30
	}
	if msgType > 0 {
		fields["msg_type"] = msgType
		res.Metadata["msg_type"] = msgType
	}
	// error-code：context [6]（A6 03 02 01 xx）
	for i := 0; i+5 <= len(head); i++ {
		if head[i] == 0xA6 && head[i+1] == 0x03 && head[i+2] == 0x02 && head[i+3] == 0x01 {
			fields["error_code"] = int64(head[i+4])
			break
		}
	}
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- RIP（RFC 2453 §4；UDP 520）----

type ripParser struct{}

func (ripParser) Name() string { return "rip" }

func (ripParser) CanParse(port uint16, sample []byte) bool {
	if port != 520 || len(sample) < 4 {
		return false
	}
	return (sample[0] == 1 || sample[0] == 2) && sample[1] == 2
}

func (ripParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "rip", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "rip", Extra: map[string]any{}}
	fields := map[string]any{
		"command": stream[0],
		"version": stream[1],
	}
	kind := "request"
	if stream[0] == 2 {
		kind = "response"
	}
	// 路由条目 20B（RFC 2453 §4：family(2) tag(2) ip(4) zero(4) metric(4)）
	var routes []map[string]any
	off := 4
	for off+20 <= len(stream) {
		r := map[string]any{
			"family": binary.BigEndian.Uint16(stream[off : off+2]),
			"ip":     netIP4(stream[off+4 : off+8]),
			"metric": binary.BigEndian.Uint32(stream[off+16 : off+20]),
		}
		routes = append(routes, r)
		off += 20
	}
	fields["routes"] = routes
	res.Metadata["command"] = fields["command"]
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

func netIP4(b []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// ---- NetFlow/IPFIX（RFC 7011/3954 + Cisco v5；端口 2055/9995/9996）----

type cflowParser struct{}

func (cflowParser) Name() string { return "cflow" }

func (cflowParser) CanParse(port uint16, sample []byte) bool {
	if port != 2055 && port != 9995 && port != 9996 || len(sample) < 20 {
		return false
	}
	v := binary.BigEndian.Uint16(sample[0:2])
	return v == 5 || v == 9 || v == 10
}

func (cflowParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "cflow", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "cflow", Extra: map[string]any{}}
	v := binary.BigEndian.Uint16(stream[0:2])
	fields := map[string]any{"version": v, "export_unix_secs": binary.BigEndian.Uint32(stream[8:12])}
	kind := "message"
	switch v {
	case 5:
		fields["count"] = binary.BigEndian.Uint16(stream[2:4])
		fields["sys_uptime"] = binary.BigEndian.Uint32(stream[4:8])
		fields["flow_sequence"] = binary.BigEndian.Uint32(stream[12:16])
	case 9:
		fields["count"] = binary.BigEndian.Uint16(stream[2:4])
		fields["source_id"] = binary.BigEndian.Uint32(stream[16:20])
	case 10: // IPFIX
		fields["length"] = binary.BigEndian.Uint16(stream[2:4])
		fields["export_time"] = binary.BigEndian.Uint32(stream[8:12])
		fields["observation_domain_id"] = binary.BigEndian.Uint32(stream[16:20])
	}
	res.Metadata["version"] = v
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- SOME/IP（AUTOSAR PRS_SOMEIPProtocol；端口 30490）----

type someipParser struct{}

func (someipParser) Name() string { return "someip" }

func (someipParser) CanParse(port uint16, sample []byte) bool {
	if port != 30490 || len(sample) < 16 {
		return false
	}
	// Length 字段从 Client ID 起数（PRS_SOMEIPProtocol §4.2.2）= 总长-8
	// （P2a 复审发现 2：原 ==总长 恒 false，真实报文永不识别）
	return binary.BigEndian.Uint32(sample[4:8]) == uint32(len(sample)-8)
}

func (someipParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "someip", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "someip", Extra: map[string]any{}}
	mt := stream[14]
	kind := "request"
	switch mt {
	case 0x80:
		kind = "response"
	case 0x81:
		kind = "response"
	}
	fields := map[string]any{
		"service_id":        binary.BigEndian.Uint16(stream[0:2]),
		"method_id":         binary.BigEndian.Uint16(stream[2:4]),
		"length":            binary.BigEndian.Uint32(stream[4:8]),
		"client_id":         binary.BigEndian.Uint16(stream[8:10]),
		"session_id":        binary.BigEndian.Uint16(stream[10:12]),
		"interface_version": stream[13],
		"message_type":      mt,
		"return_code":       stream[15],
	}
	res.Metadata["session_id"] = fields["session_id"]
	res.Metadata["message_type"] = mt
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- Megaco/H.248（RFC 3525 文本 ABNF；端口 2944/2427）----

type megacoParser struct{}

func (megacoParser) Name() string { return "megaco" }

func (megacoParser) CanParse(port uint16, sample []byte) bool {
	if port != 2944 && port != 2427 {
		return false
	}
	p := string(sample)
	return strings.HasPrefix(p, "MEGACO/") || strings.HasPrefix(p, "!/")
}

func (megacoParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "megaco", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "megaco", Extra: map[string]any{}}
	text := string(stream)
	fields := map[string]any{}
	// 版本行：MEGACO/1 [ip]:port 或 !/1 [...]
	if i := strings.IndexByte(text, '\n'); i > 0 {
		fields["first_line"] = strings.TrimSpace(text[:i])
	}
	// 事务 id（ABNF: T = transactionID）
	var txids []string
	rest := text
	for {
		// ABNF: T = transactionID（'=' 两侧可有空白，RFC 3525 §9）
		i := strings.Index(rest, "T")
		if i < 0 {
			break
		}
		j := i + 1
		for j < len(rest) && rest[j] == ' ' {
			j++
		}
		if j >= len(rest) || rest[j] != '=' {
			rest = rest[i+1:]
			continue
		}
		j++
		for j < len(rest) && rest[j] == ' ' {
			j++
		}
		var id strings.Builder
		for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
			id.WriteByte(rest[j])
			j++
		}
		if id.Len() > 0 {
			txids = append(txids, id.String())
			rest = rest[j:]
		} else {
			rest = rest[j:]
		}
	}
	if txids != nil {
		fields["transaction_ids"] = txids
	}
	// 命令词面（ADD/MOD/MOVE/DLG/SUB/AS/RS/audit）
	for _, cmd := range []string{"ADD", "MODIFY", "MOVE", "SUBTRACT", "AUDITVALUE", "AUDITCAPABILITY", "NOTIFY", "SERVICECHANGE"} {
		if strings.Contains(text, cmd) {
			fields["command_"+strings.ToLower(cmd)] = true
		}
	}
	if v := strings.Index(text, "MEGACO/"); v >= 0 && v+7 < len(text) {
		fields["version"] = atoiSafe(text[v+7 : v+8])
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- BACnet/IP（ASHRAE 135 Annex J BVLC + NPDU + APDU；端口 47808）----

type bacnetParser struct{}

func (bacnetParser) Name() string { return "bacnet" }

func (bacnetParser) CanParse(port uint16, sample []byte) bool {
	if port != 47808 || len(sample) < 6 {
		return false
	}
	return sample[0] == 0x81 && binary.BigEndian.Uint16(sample[2:4]) == uint16(len(sample))
}

func (bacnetParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "bacnet", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "bacnet", Extra: map[string]any{}}
	fields := map[string]any{
		"bvlc_function": stream[1],
	}
	// NPDU: version(1)=0x01 + control(1)（@4 起）
	if len(stream) >= 6 && stream[4] == 0x01 {
		fields["npdu_version"] = stream[4]
		apduOff := 6
		if ctrl := stream[5]; ctrl&0x20 != 0 {
			// DNET 存在（ASHRAE 135 §6.2.2）：DNET 2B@6:7 + DLEN 整字节@8 +
			// DADR(DLEN)。DLEN=255 为远程广播特例（无 DADR，注记）；路由帧
			// 短于 9B 时跳过 APDU 解析（P2a 复审发现 1：越界 panic 面）。
			if len(stream) < 9 {
				res.Metadata["truncated_npdu"] = true
				detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
				detail.countKinds()
				res.Detail = detail
				return res, nil
			}
			if stream[8] == 255 {
				apduOff += 3
			} else {
				apduOff += 3 + int(stream[8])
			}
		}
		if apduOff+1 <= len(stream) {
			apdu := stream[apduOff:]
			at := apdu[0] & 0xF0 >> 4
			fields["apdu_type"] = at
			switch at {
			case 0: // confirmed-REQ：invoke-id + service-choice
				if len(apdu) >= 3 {
					fields["invoke_id"] = apdu[1]
					fields["service_choice"] = apdu[2]
					res.Metadata["invoke_id"] = apdu[1]
				}
			case 1: // unconfirmed：service-choice（WhoIs=8 等）
				if len(apdu) >= 2 {
					fields["service_choice"] = apdu[1]
				}
			case 3: // complex ACK：invoke-id + service-choice（响应面）
				if len(apdu) >= 3 {
					fields["invoke_id"] = apdu[1]
					fields["service_choice"] = apdu[2]
				}
			}
		}
	}
	kind := "message"
	if t, ok := fields["apdu_type"].(byte); ok && t == 3 {
		kind = "response"
	}
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- FINS（Omron；UDP 9600）----

type finsParser struct{}

func (finsParser) Name() string { return "fins" }

func (finsParser) CanParse(port uint16, sample []byte) bool {
	return port == 9600 && len(sample) >= 12
}

func (finsParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "fins", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "fins", Extra: map[string]any{}}
	fields := map[string]any{
		"icf":  stream[0],
		"gct":  stream[2],
		"dna":  stream[3],
		"da1":  stream[4],
		"da2":  stream[5],
		"sna":  stream[6],
		"sa1":  stream[7],
		"sa2":  stream[8],
		"sid":  stream[9],
		"command": fmt.Sprintf("%02x%02x", stream[10], stream[11]),
	}
	res.Metadata["sid"] = stream[9]
	res.Metadata["command"] = fields["command"]
	if len(stream) >= 14 {
		fields["response_code"] = fmt.Sprintf("%02x%02x", stream[12], stream[13])
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- LDP（RFC 5036 §3；UDP 646 发现面 + TCP 646 会话面）----

type ldpParser struct{}

func (ldpParser) Name() string { return "ldp" }

func (ldpParser) CanParse(port uint16, sample []byte) bool {
	if port != 646 || len(sample) < 14 {
		return false
	}
	return binary.BigEndian.Uint16(sample[0:2]) == 1 // version=1
}

// Parse 单消息面（UDP Hello / TCP 单 PDU 起始——TCP 多 PDU 流随 P2b 载体批）。
func (ldpParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "ldp", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "ldp", Extra: map[string]any{}}
	fields := map[string]any{
		"version":     binary.BigEndian.Uint16(stream[0:2]),
		"pdu_length":  binary.BigEndian.Uint16(stream[2:4]),
		"lsr_id":      netIP4(stream[4:8]),
		"label_space": binary.BigEndian.Uint16(stream[8:10]),
	}
	// 首消息头：U-bit(1)+msg-type(2)+len(2)+msg-id(4)（RFC 5036 §3.5.1）
	if len(stream) >= 18 {
		msgType := binary.BigEndian.Uint16(stream[12:14]) & 0x7FFF
		names := map[uint16]string{
			0x0100: "notification", 0x0200: "hello", 0x0300: "initialization",
			0x0301: "keepalive", 0x0400: "address", 0x0401: "address-withdraw",
			0x0402: "label-mapping", 0x0403: "label-request", 0x0404: "label-withdraw",
			0x0405: "label-release",
		}
		if n, ok := names[msgType]; ok {
			fields["message_type"] = n
			res.Metadata["message_type"] = n
		} else {
			fields["message_type"] = fmt.Sprintf("0x%04x", msgType)
		}
		fields["message_id"] = binary.BigEndian.Uint32(stream[14:18])
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- IKEv2（RFC 7296 §3.1；UDP 500）----

type ikeParser struct{}

func (ikeParser) Name() string { return "ike" }

func (ikeParser) CanParse(port uint16, sample []byte) bool {
	if port != 500 || len(sample) < 28 {
		return false
	}
	return sample[13] == 0x20 || sample[13] == 0x10 // version 2.0/1.0
}

func (ikeParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "ike", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "ike", Extra: map[string]any{}}
	fields := map[string]any{
		"initiator_spi": hex.EncodeToString(stream[0:8]),
		"responder_spi": hex.EncodeToString(stream[8:16]),
		"version":       fmt.Sprintf("%d.%d", stream[13]>>4, stream[13]&0xF),
		"message_id":    binary.BigEndian.Uint32(stream[20:24]),
		"length":        binary.BigEndian.Uint32(stream[24:28]),
	}
	exch := stream[12]
	exchNames := map[byte]string{
		34: "ike_sa_init", 35: "ike_auth", 36: "create_child_sa", 37: "informational",
		2: "identity_protection", 4: "aggressive", 5: "informational_v1",
	}
	if n, ok := exchNames[exch]; ok {
		fields["exchange_type"] = n
		res.Metadata["exchange_type"] = n
	} else {
		fields["exchange_type"] = exch
	}
	flags := stream[14]
	fields["initiator_flag"] = flags&0x08 != 0
	res.Metadata["message_id"] = fields["message_id"]
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- IKE NAT-T（RFC 3948 §2.1；UDP 4500）----

type ikeNattParser struct{}

func (ikeNattParser) Name() string { return "ike_nat_t" }

func (ikeNattParser) CanParse(port uint16, sample []byte) bool {
	if port != 4500 {
		return false
	}
	// keepalive 单字节 0xFF（RFC 3948 §3.1）
	if len(sample) == 1 && sample[0] == 0xFF {
		return true
	}
	// 4B non-ESP marker 0x00000000 + IKE 头（version 位）
	if len(sample) >= 32 && binary.BigEndian.Uint32(sample[0:4]) == 0 {
		return sample[13+4] == 0x20
	}
	return false
}

func (ikeNattParser) Parse(stream []byte) (*L7Result, error) {
	if len(stream) == 1 {
		res := &L7Result{Protocol: "ike_nat_t", Metadata: map[string]any{"keepalive": true}}
		detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "ike_nat_t", Extra: map[string]any{}}
		detail.appendMessage(L7Message{Kind: "message", WireLen: 1, Fields: map[string]any{"keepalive": true}})
		detail.countKinds()
		res.Detail = detail
		return res, nil
	}
	res := &L7Result{Protocol: "ike_nat_t", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "ike_nat_t", Extra: map[string]any{}}
	r, err := ikeParser{}.Parse(stream[4:])
	if err != nil || res == nil || r == nil {
		return res, err
	}
	res.Protocol = "ike_nat_t"
	res.Metadata["non_esp_marker"] = true
	detail.Extra = map[string]any{"non_esp_marker": true}
	if r.Detail != nil {
		for _, m := range r.Detail.Messages {
			m.Fields["non_esp_marker"] = true
			detail.appendMessage(m)
		}
		detail.countKinds()
	}
	res.Detail = detail
	return res, nil
}
