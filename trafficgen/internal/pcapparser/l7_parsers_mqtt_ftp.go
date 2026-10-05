package pcapparser

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// P1-4（2026-10-05 客户端复测）：L7 解析面补齐 mqtt 与 ftp。生成面早已支持
// 两协议（125 协议收官），此前解析面仅 http/dns/tls，mqtt/ftp 流的
// L7Protocol/L7Metadata 全空。

// mqttParser parses MQTT 3.1.1/3.1 control-packet streams (fixed header
// type<<4|flags, varint remaining length, per-type bodies). Extracts the
// packet-type sequence plus the fields users filter by: client_id/keepalive/
// clean_session (CONNECT), topic/qos (PUBLISH).
type mqttParser struct{}

func (mqttParser) Name() string { return "mqtt" }

func (mqttParser) CanParse(port uint16, sample []byte) bool {
	if port == 1883 {
		return true
	}
	// CONNECT 指纹：首字节 0x10 且头 10 字节内出现协议名 "MQTT"/"MQIsdp"
	//（协议名在 varint 剩余长度之后，偏移随长度字节数浮动）。其余报文类型
	// 只认 CONNACK 指纹 0x20 0x02（剩余长度恒 2）——裸 0x20 会对任意二进制
	// 流产生 ~1/256 误标，不能要（复审 F5）。
	head := sample
	if len(head) > 10 {
		head = head[:10]
	}
	if len(sample) >= 6 && sample[0] == 0x10 &&
		(bytes.Contains(head, []byte("MQTT")) || bytes.Contains(head, []byte("MQIsdp"))) {
		return true
	}
	return len(sample) >= 4 && sample[0] == 0x20 && sample[1] == 0x02
}

// mqttTypeNames maps the fixed-header type nibble to its MQTT 3.1.1 name.
var mqttTypeNames = map[byte]string{
	1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC",
	6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK", 10: "UNSUBSCRIBE",
	11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT",
}

func (mqttParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "mqtt", Metadata: map[string]any{}}
	types := make([]string, 0, 8)
	for pos := 0; pos < len(stream); {
		if pos+2 > len(stream) {
			break
		}
		first := stream[pos]
		typeNibble := first >> 4
		// 帧对齐守卫：type 高半字节越界即流尾残包/非 mqtt，停止遍历。
		name, known := mqttTypeNames[typeNibble]
		if !known {
			break
		}
		// varint 剩余长度（每字节低 7 位 LSB 组，高位 continuation）。
		pos++
		remLen, mult := 0, 1
		for {
			if pos >= len(stream) {
				return res, nil
			}
			b := stream[pos]
			pos++
			remLen += int(b&0x7f) * mult
			mult *= 128
			if b&0x80 == 0 {
				break
			}
			if mult >= 128*128*128*128 { // MQTT 上限 4 字节 268435455（含第 4 字节后止步）
				return res, nil
			}
		}
		bodyEnd := pos + remLen
		if bodyEnd > len(stream) || remLen < 0 {
			break
		}
		body := stream[pos:min(bodyEnd, len(stream))]
		if len(types) < 16 {
			types = append(types, name)
		}
		switch typeNibble {
		case 1: // CONNECT: proto name(2B len) level flags keepalive(2B) payload(client_id 2B len)
			// 字段偏移随协议名长浮动（3.1.1 "MQTT" 4 字节 / 3.1 "MQIsdp" 6 字节），
			// 按名长通用寻址——硬编码 3.1.1 偏移读 3.1 包会全错（复审 F1）。
			res.Metadata["method"] = "CONNECT"
			if len(body) >= 2 {
				nl := int(binary.BigEndian.Uint16(body[:2]))
				isMqtt := (nl == 4 && len(body) >= 6 && string(body[2:6]) == "MQTT") ||
					(nl == 6 && len(body) >= 8 && string(body[2:8]) == "MQIsdp")
				if isMqtt {
					p := 2 + nl
					if len(body) >= p+4 {
						res.Metadata["proto_level"] = body[p]
						flags := body[p+1]
						res.Metadata["clean_session"] = flags&0x02 != 0
						res.Metadata["keepalive"] = binary.BigEndian.Uint16(body[p+2 : p+4])
						if len(body) >= p+6 {
							cl := int(binary.BigEndian.Uint16(body[p+4 : p+6]))
							if p+6+cl <= len(body) {
								res.Metadata["client_id"] = string(body[p+6 : p+6+cl])
							}
						}
					}
				}
			}
		case 2: // CONNACK: ack flags + return code
			if len(body) >= 2 && body[1] != 0 {
				res.Metadata["connack_code"] = body[1]
			}
		case 3: // PUBLISH: topic(2B len) [msg_id if qos>0] payload
			// 元数据一律 first-wins：topic/qos/msg_id 同出第一条，多 PUBLISH
			// 流不产生 topic 取 #1 而 qos/msg_id 取 #N 的不成立三元组（复审 F7）。
			if _, ok := res.Metadata["method"]; !ok {
				res.Metadata["method"] = "PUBLISH"
			}
			if len(body) >= 2 {
				tl := int(binary.BigEndian.Uint16(body[:2]))
				if 2+tl <= len(body) && res.Metadata["topic"] == nil {
					res.Metadata["topic"] = string(body[2 : 2+tl])
				}
				if res.Metadata["qos"] == nil {
					qos := (first >> 1) & 0x03
					res.Metadata["qos"] = qos
					if qos > 0 && len(body) >= 2+tl+2 && res.Metadata["msg_id"] == nil {
						res.Metadata["msg_id"] = binary.BigEndian.Uint16(body[2+tl : 2+tl+2])
					}
				}
			}
		}
		pos = bodyEnd
	}
	res.Metadata["msg_types"] = types
	if _, ok := res.Metadata["method"]; !ok && len(types) > 0 {
		// 响应型报文流不占 L7Method 索引：解析按方向各跑一次、s2c 后写覆盖
		// c2s——CONNACK 等响应流不设 method，保留 c2s 的请求动词（CONNECT 等）。
		switch types[0] {
		case "CONNACK", "SUBACK", "UNSUBACK", "PINGRESP", "PUBACK", "PUBREC", "PUBREL", "PUBCOMP":
		default:
			res.Metadata["method"] = types[0]
		}
	}
	return res, nil
}

// ftpParser parses FTP control-channel streams: text lines, client→server
// "VERB [arg]\r\n" commands, server→client "NNN [text]\r\n" replies
// (RFC 959). Extracts the command verb / reply code sequences; the first one
// indexes into L7Method for fast filtering.
type ftpParser struct{}

func (ftpParser) Name() string { return "ftp" }

// ftpVerbs are the RFC 959 (+ RFC 2428 EPSV/EPRT) command words used as a
// port-less detection signal.
var ftpVerbs = map[string]bool{
	"USER": true, "PASS": true, "ACCT": true, "CWD": true, "CDUP": true,
	"SMNT": true, "REIN": true, "QUIT": true, "PORT": true, "PASV": true,
	"TYPE": true, "STRU": true, "MODE": true, "RETR": true, "STOR": true,
	"STOU": true, "APPE": true, "ALLO": true, "REST": true, "RNFR": true,
	"RNTO": true, "ABOR": true, "DELE": true, "RMD": true, "MKD": true,
	"PWD": true, "LIST": true, "NLST": true, "SITE": true, "SYST": true,
	"STAT": true, "HELP": true, "NOOP": true, "FEAT": true, "OPTS": true,
	"EPSV": true, "EPRT": true, "AUTH": true,
}

// ftpMailPorts: POP3/SMTP/IMAP 的明文与 TLS 端口。这些端口上的文本
// （POP3 "USER/PASS"、SMTP "220"）与 ftp 探针形状相同但没有解析器认领，
// 内容探针会偷走它们——错误标注比无标注差（复审 F2）。port==21 恒认 ftp。
var ftpMailPorts = map[uint16]bool{
	25: true, 110: true, 143: true, 465: true, 587: true, 993: true, 995: true,
}

func (ftpParser) CanParse(port uint16, sample []byte) bool {
	if port == 21 {
		return true
	}
	if ftpMailPorts[port] {
		return false
	}
	// 端口未知时认两形状：三位响应行（NNN SP|'-'）或已知命令词行。
	// 只看头 256 字节，不整流拷贝（复审 F8）。
	head := sample
	if len(head) > 256 {
		head = head[:256]
	}
	line := string(head)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimRight(line, "\r")
	if len(line) >= 3 && isDigits(line[:3]) && (len(line) == 3 || line[3] == ' ' || line[3] == '-') {
		return true
	}
	verb := line
	if i := strings.IndexByte(verb, ' '); i > 0 {
		verb = verb[:i]
	}
	return ftpVerbs[verb]
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

func (ftpParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "ftp", Metadata: map[string]any{}}
	commands := make([]string, 0, 8)
	codes := make([]string, 0, 8)
	const cap = 16
	lines := strings.Split(strings.ReplaceAll(string(stream), "\r\n", "\n"), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		if len(line) >= 3 && isDigits(line[:3]) && (len(line) == 3 || line[3] == ' ' || line[3] == '-') {
			if len(codes) < cap {
				codes = append(codes, line[:3])
			}
			// 响应行不占 L7Method 索引（与 mqtt 同语义）：s2c 后写覆盖 c2s，
			// 响应码走 response_codes/banner，保留 c2s 的命令动词。
			if res.Metadata["banner"] == nil && line[:3] == "220" {
				res.Metadata["banner"] = strings.TrimSpace(line[3:])
			}
			continue
		}
		verb := line
		if i := strings.IndexByte(verb, ' '); i > 0 {
			verb = verb[:i]
		}
		if ftpVerbs[verb] {
			if len(commands) < cap {
				commands = append(commands, verb)
			}
			if res.Metadata["method"] == nil {
				res.Metadata["method"] = verb
			}
		}
	}
	if len(commands) > 0 {
		res.Metadata["commands"] = commands
	}
	if len(codes) > 0 {
		res.Metadata["response_codes"] = codes
	}
	// method 缺省（纯响应流）是合法形态：L7Protocol 照常标注，命令动词
	// 由 c2s 方向的解析写入。
	return res, nil
}
