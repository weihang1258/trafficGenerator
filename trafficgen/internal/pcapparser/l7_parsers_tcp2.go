package pcapparser

// P2b TCP 解析器——二进制族。识别+握手/帧面（加密主体不深解，裁定6/范围）。

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ---- SSH（RFC 4253 §4.2/§7.1；TCP 22）----

type sshParser struct{}

func (sshParser) Name() string { return "ssh" }

func (sshParser) CanParse(port uint16, sample []byte) bool {
	if port == 22 {
		return len(sample) > 0
	}
	return strings.HasPrefix(string(sample), "SSH-")
}

func (sshParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "ssh", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "ssh", Extra: map[string]any{}}
	fields := map[string]any{}
	// banner（RFC 4253 §4.2: "SSH-protoversion-softwareversion" SP Comments CR LF）
	end := strings.Index(string(stream), "\r\n")
	if end < 0 {
		end = strings.Index(string(stream), "\n")
	}
	if end > 0 {
		fields["banner"] = string(stream[:end])
		res.Metadata["banner"] = string(stream[:end])
		// KEXINIT（§7.1：4B len + 1B type=20 + 16B cookie + 10 个 name-list）
		off := end + 2
		if off+5 <= len(stream) && stream[off+4] == 20 {
			p := off + 5 + 16
			nameList := func() []string {
				if p+4 > len(stream) {
					return nil
				}
				l := int(binary.BigEndian.Uint32(stream[p : p+4]))
				p += 4
				if l < 0 || p+l > len(stream) {
					return nil
				}
				out := strings.Split(string(stream[p:p+l]), ",")
				p += l
				return out
			}
			for _, key := range []string{"kex_algorithms", "host_key_algorithms", "encryption_c2s", "encryption_s2c", "mac_c2s", "mac_s2c", "compression_c2s", "compression_s2c"} {
				if nl := nameList(); nl != nil {
					fields[key] = nl
				} else {
					break
				}
			}
		}
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- Telnet（RFC 854/855；TCP 23）----

type telnetParser struct{}

func (telnetParser) Name() string { return "telnet" }

func (telnetParser) CanParse(port uint16, sample []byte) bool {
	if port != 23 {
		return false
	}
	// IAC 或可打印文本
	for _, b := range sample {
		if b == 0xFF {
			return true
		}
		if b >= 0x20 && b < 0x7F {
			return true
		}
	}
	return len(sample) > 0
}

func (telnetParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "telnet", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "telnet", Extra: map[string]any{}}
	var cmds []map[string]any
	var text strings.Builder
	for i := 0; i < len(stream); i++ {
		if stream[i] != 0xFF {
			if stream[i] >= 0x20 && stream[i] < 0x7F {
				text.WriteByte(stream[i])
			} else {
				text.WriteByte('.')
			}
			continue
		}
		if i+2 > len(stream) {
			break
		}
		cmd := stream[i+1]
		c := map[string]any{"cmd": fmt.Sprintf("%d", cmd)}
		switch cmd {
		case 251, 252, 253, 254: // WILL/WONT/DO/DONT + option
			if i+3 <= len(stream) {
				c["option"] = stream[i+2]
				if cmd == 253 && stream[i+2] == 24 {
					c["option_name"] = "terminal-type"
				}
				if cmd == 253 && stream[i+2] == 31 {
					c["option_name"] = "window-size"
				}
				i += 2
			}
		case 250: // SB ... IAC SE（跳到 SE）
			j := i + 2
			for j+1 < len(stream) && !(stream[j] == 0xFF && stream[j+1] == 0xF0) {
				j++
			}
			i = j + 1
		default:
			i++
		}
		cmds = append(cmds, c)
	}
	fields := map[string]any{}
	if cmds != nil {
		fields["iac_commands"] = cmds
	}
	fields["text_preview"] = text.String()[:min(len(text.String()), 256)]
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- LDAP（RFC 4511 §4；TCP 389，BER 逐消息）----

type ldapParser struct{}

func (ldapParser) Name() string { return "ldap" }

func (ldapParser) CanParse(port uint16, sample []byte) bool {
	if port != 389 || len(sample) < 6 {
		return false
	}
	// LDAPMessage: SEQUENCE(0x30) + msgID INTEGER + protocolOp（application 0x60-0x7F）
	if sample[0] != 0x30 {
		return false
	}
	// LDAPMessage: SEQUENCE{ messageID INTEGER, protocolOp [APPLICATION n], ... }
	// berTLV 第 5 返回值=内容起点（cOff），第 6=内容终点——逐层用 cOff 下钻
	_, _, _, mCOff, _, _, ok := berTLV(sample, 0)
	if !ok {
		return false
	}
	_, _, _, _, _, opNext, ok2 := berTLV(sample, mCOff)
	if !ok2 {
		return false
	}
	cls, _, _, _, _, _, ok3 := berTLV(sample, opNext)
	return ok3 && cls == 1 // application class
}

func (ldapParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "ldap", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "ldap", Extra: map[string]any{}}
	off := 0
	msgNames := map[int]string{
		0: "bind_request", 1: "bind_response", 2: "unbind", 3: "search_request",
		4: "search_result_entry", 5: "search_result_done", 6: "modify_request",
		7: "modify_response", 8: "add_request", 9: "add_response",
		10: "del_request", 11: "del_response", 12: "modify_dn_request",
		13: "modify_dn_response", 14: "compare_request", 15: "compare_response",
		23: "extended_request", 24: "extended_response",
	}
	for n := 0; n < MaxL7Messages; n++ {
		cls, _, _, cOff, _, next, ok := berTLV(stream, off)
		if !ok || cls != 0 {
			break
		}
		fields := map[string]any{}
		// messageID：内容首 INTEGER
		if id, _, ok2 := berInt(stream, cOff); ok2 {
			fields["message_id"] = id
		}
		// protocolOp：messageID INTEGER 之后的 application TLV（用 berTLV
		// 定位 messageID 终点，短/长格式皆准）
		_, _, _, _, _, midNext, okM := berTLV(stream, cOff)
		if !okM {
			break
		}
		clsOp, _, aTag, aOff, aLen, _, ok3 := berTLV(stream, midNext)
		if ok3 && clsOp == 1 { // protocolOp 自身 = application 类（X.690 §8.1.2）
			// aTag 是低 5 位；application 位在首字节高两位
			if name, ok4 := msgNames[aTag&0x3F]; ok4 {
				fields["protocol_op"] = name
			} else {
				fields["protocol_op"] = fmt.Sprintf("app_%d", aTag&0x3F)
			}
			// bind_request：version+name（RFC 4511 §4.2）
			if aTag&0x3F == 0 && aOff+3 <= aOff+aLen {
				if ver, _, ok5 := berInt(stream, aOff); ok5 {
					fields["ldap_version"] = ver
				}
			}
			// searchResDone：resultCode ENUM + matchedDN + errorMessage
			if aTag&0x3F == 5 {
				if ec, _, ok5 := berInt(stream, aOff+2); ok5 {
					fields["result_code"] = ec
					res.Metadata["result_code"] = ec
				}
			}
		}
		detail.appendMessage(L7Message{Kind: "message", WireLen: next - off, Fields: fields})
		off = next
	}
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- RDP（MS-RDPBCGR + X.224 TPKT；TCP 3389）----

type rdpParser struct{}

func (rdpParser) Name() string { return "rdp" }

func (rdpParser) CanParse(port uint16, sample []byte) bool {
	if port != 3389 || len(sample) < 4 {
		return false
	}
	return sample[0] == 3 // TPKT version 3
}

func (rdpParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "rdp", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "rdp", Extra: map[string]any{}}
	// TPKT（RFC 1006 §6）：version(1)=3 + reserved(1) + length(2)；帧序列走查
	off := 0
	var cotpTypes []string
	for off+4 <= len(stream) {
		if stream[off] != 3 {
			break
		}
		l := int(binary.BigEndian.Uint16(stream[off+2 : off+4]))
		if l < 4 || off+l > len(stream) {
			detail.Truncated = true
			break
		}
		// X.224 COTP：len(1) + type(1)（0xE0 CR / 0xD0 CC / 0xF0 DT data）
		if off+6 <= len(stream) {
			switch stream[off+5] {
			case 0xE0:
				cotpTypes = append(cotpTypes, "connection-request")
				// 协商体（MS-RDPBCGR §2.2.1.1）：type 0x01 requestedProtocol
			case 0xD0:
				cotpTypes = append(cotpTypes, "connection-confirm")
			case 0xF0:
				cotpTypes = append(cotpTypes, "data")
			}
		}
		off += l
	}
	fields := map[string]any{"cotp_types": cotpTypes}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- VNC/RFB（RFC 6143；TCP 5900）----

type vncParser struct{}

func (vncParser) Name() string { return "vnc" }

func (vncParser) CanParse(port uint16, sample []byte) bool {
	if port < 5900 || port > 5910 {
		return false
	}
	return strings.HasPrefix(string(sample), "RFB ")
}

func (vncParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "vnc", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "vnc", Extra: map[string]any{}}
	fields := map[string]any{
		"protocol_version": strings.TrimRight(string(stream[:min(12, len(stream))]), "\n"),
	}
	// security types（RFC 6143 §7.1.2：1B n + n types，服务端→客户端）
	if len(stream) >= 21 && stream[12] <= 8 {
		n := int(stream[12])
		if n > 0 && 13+n <= len(stream) {
			var sec []byte
			for i := 0; i < n; i++ {
				sec = append(sec, stream[13+i])
			}
			fields["security_types"] = sec
		}
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- RTMP（Adobe RTMP spec 1.0 §5/§6；TCP 1935）----

type rtmpParser struct{}

func (rtmpParser) Name() string { return "rtmp" }

func (rtmpParser) CanParse(port uint16, sample []byte) bool {
	if port != 1935 || len(sample) < 1 {
		return false
	}
	return sample[0] == 3 // C0 version 3
}

func (rtmpParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "rtmp", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "rtmp", Extra: map[string]any{}}
	fields := map[string]any{"handshake_version": stream[0]}
	// 握手后 chunk basic header（§6.1.1：fmt(2b)+csid(6b)，fmt=0 时 11B 头）
	off := 1 + 1536*2 // C0 + C1 + C2
	var chunks []map[string]any
	typeNames := map[byte]string{1: "set_chunk_size", 4: "user_control", 5: "ack_window", 20: "amf0_command", 18: "amf0_data"}
	for off+1 <= len(stream) && len(chunks) < 32 {
		fmtb := stream[off] >> 6
		csid := int(stream[off] & 0x3F)
		hdrLen := map[byte]int{0: 11, 1: 7, 2: 3}[fmtb]
		if csid == 0 {
			hdrLen += 1
		}
		if off+1+hdrLen > len(stream) {
			detail.Truncated = true
			break
		}
		c := map[string]any{"fmt": fmtb, "csid": csid}
		if fmtb == 0 && off+12 <= len(stream) {
			// fmt=0：timestamp(3) msglen(3) typeid(1) streamid(4)
			c["msg_len"] = int(stream[off+4])<<16 | int(stream[off+5])<<8 | int(stream[off+6])
			tid := stream[off+7]
			c["type_id"] = int(tid)
			if n, ok := typeNames[tid]; ok {
				c["type_name"] = n
			}
		}
		chunks = append(chunks, c)
		// chunk 长度近似：头 + max chunk data（无完整组装面，走查前 32 个头即可）
		break // P2b 保守：只解首个 basic header（组装面登记随批深化）
	}
	if chunks != nil {
		fields["chunks"] = chunks
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- H.323 / H.225.0 Q.931 over TPKT（ITU-T H.225.0 §7；TCP 1720）----

type h323Parser struct{}

func (h323Parser) Name() string { return "h323" }

func (h323Parser) CanParse(port uint16, sample []byte) bool {
	if port != 1720 || len(sample) < 6 {
		return false
	}
	return sample[0] == 3 && sample[4] == 0x08 // TPKT v3 + Q.931 discriminator
}

func (h323Parser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "h323", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "h323", Extra: map[string]any{}}
	// TPKT + Q.931（§7.1：discriminator 0x08 + CRV 2B + msg type）
	off := 0
	var msgs []string
	q931Names := map[byte]string{
		0x05: "setup", 0x01: "alerting", 0x07: "connect", 0x0F: "connect_ack",
		0x2A: "release", 0x5A: "release_complete", 0x0D: "call_proceeding",
	}
	for off+5 <= len(stream) {
		if stream[off] != 3 {
			break
		}
		l := int(binary.BigEndian.Uint16(stream[off+2 : off+4]))
		if l < 4 || off+l > len(stream) {
			detail.Truncated = true
			break
		}
		if stream[off+4] == 0x08 && off+8 <= len(stream) {
			// crv = stream[off+5:off+7]; msg type @off+7... H.225: cseq 变长——简化面
			mt := stream[off+7]
			if n, ok := q931Names[mt]; ok {
				msgs = append(msgs, n)
			} else {
				msgs = append(msgs, fmt.Sprintf("q931_%02x", mt))
			}
		}
		off += l
	}
	fields := map[string]any{"q931_messages": msgs}
	if msgs != nil {
		res.Metadata["messages"] = msgs
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- PPTP（RFC 2637 §3；TCP 1723）----

type pptpParser struct{}

func (pptpParser) Name() string { return "pptp" }

func (pptpParser) CanParse(port uint16, sample []byte) bool {
	if port != 1723 || len(sample) < 12 {
		return false
	}
	// magic 0x1A2B3C4D：引擎 BE 写线、tshark LE 识别——双序兼容（复审面）
	be := binary.BigEndian.Uint32(sample[4:8])
	le := binary.LittleEndian.Uint32(sample[4:8])
	return be == 0x1A2B3C4D || le == 0x1A2B3C4D
}

func (pptpParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "pptp", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "pptp", Extra: map[string]any{}}
	ctlNames := map[uint16]string{
		1: "start_ctrl_conn_req", 2: "start_ctrl_conn_rep", 3: "stop_ctrl_conn_req",
		4: "stop_ctrl_conn_rep", 7: "outgoing_call_req", 8: "outgoing_call_rep",
		9: "incoming_call_req", 10: "incoming_call_rep", 12: "call_clear_req",
		13: "call_disconnect_notify", 15: "echo_req", 16: "echo_rep",
	}
	off := 0
	var ctl []map[string]any
	for off+12 <= len(stream) {
		if binary.BigEndian.Uint32(stream[off+4:off+8]) != 0x1A2B3C4D {
			break
		}
		l := int(binary.BigEndian.Uint16(stream[off : off+2]))
		ct := binary.BigEndian.Uint16(stream[off+8 : off+10])
		c := map[string]any{"control_type": ct}
		if n, ok := ctlNames[ct]; ok {
			c["control_name"] = n
		}
		// Outgoing/Incoming Call Reply 携带 Call ID（§3.2.7 关联面）
		if off+16 <= len(stream) && (ct == 8 || ct == 10) {
			c["call_id"] = binary.BigEndian.Uint16(stream[off+12 : off+14]) // Call ID @12（RFC 2637 §3.2.7，复审发现 1；14:16 是 Peer Call ID）
		}
		ctl = append(ctl, c)
		if l < 12 || off+l > len(stream) {
			detail.Truncated = true
			break
		}
		off += l
	}
	fields := map[string]any{"control_messages": ctl}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- SOCKS5（RFC 1928/1929；TCP 1080）----

type socks5Parser struct{}

func (socks5Parser) Name() string { return "socks5" }

func (socks5Parser) CanParse(port uint16, sample []byte) bool {
	if port != 1080 || len(sample) < 2 {
		return false
	}
	// SOCKS5: VER(1)=5；SOCKS4: VN(1)=4 + CD(1)=[1,2]
	// SOCKS4 reply: VN(1)=0 + CD(1)=0x5A(granted)/0x5B(failed)
	if sample[0] == 0 && sample[1] >= 0x5A && sample[1] <= 0x5D {
		return true
	}
	return sample[0] == 5 || (sample[0] == 4 && sample[1] >= 1 && sample[1] <= 2)
}

func (socks5Parser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "socks5", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "socks5", Extra: map[string]any{}}
	fields := map[string]any{"version": stream[0]}
	if stream[0] == 0 && len(stream) >= 8 {
		// SOCKS4 reply：VN(1)=0 + CD(1) + dst_port(2) + dst_ip(4)
		rep := stream[1]
		fields["reply_code"] = rep
		fields["reply_granted"] = rep == 0x5A
		detail.appendMessage(L7Message{Kind: "response", WireLen: len(stream), Fields: fields})
		detail.countKinds()
		res.Detail = detail
		return res, nil
	}
	if stream[0] == 4 {
		// SOCKS4：VN(1) CD(1) dst_port(2 BE) dst_ip(4 BE) userid(...) 0x00
		cd := stream[1]
		fields["command"] = map[byte]string{1: "connect", 2: "bind"}[cd]
		if len(stream) >= 8 {
			fields["dst_port"] = binary.BigEndian.Uint16(stream[2:4])
			fields["dst_addr"] = fmt.Sprintf("%d.%d.%d.%d", stream[4], stream[5], stream[6], stream[7])
		}
		// 隧道封装标记（反馈项 2）：CONNECT 后同流 HTTP 载荷
		// （userid NUL 结尾——载荷起点在 userid 终止符后，非固定偏移）
		if nul := bytes.IndexByte(stream[8:], 0); nul >= 0 {
			rest := stream[8+nul+1:]
			if strings.HasPrefix(string(rest), "GET ") || strings.HasPrefix(string(rest), "POST ") ||
				strings.HasPrefix(string(rest), "PUT ") || strings.HasPrefix(string(rest), "HTTP/") {
				fields["encapsulated"] = true
				fields["inner_protocol"] = "http"
			}
		}
		detail.appendMessage(L7Message{Kind: "request", WireLen: len(stream), Fields: fields})
		detail.countKinds()
		res.Detail = detail
		return res, nil
	}
	off := 0
	// 方法协商：VER nmethods methods...
	if len(stream) >= 3 && stream[0] == 5 && stream[1] >= 1 && len(stream) >= 2+int(stream[1]) {
		fields["client_methods"] = hex.EncodeToString(stream[2 : 2+int(stream[1])])
		off = 2 + int(stream[1])
		// 后随请求（客户端流）：VER CMD RSV ATYP addr port
		if off+5 <= len(stream) && stream[off] == 5 {
			cmd := stream[off+1]
			atyp := stream[off+3]
			fields["cmd"] = map[byte]string{1: "connect", 2: "bind", 3: "udp_associate"}[cmd]
			p := off + 4
			switch atyp {
			case 1:
				if p+6 <= len(stream) {
					fields["dst_addr"] = fmt.Sprintf("%d.%d.%d.%d", stream[p], stream[p+1], stream[p+2], stream[p+3])
					fields["dst_port"] = binary.BigEndian.Uint16(stream[p+4 : p+6])
				}
			case 3:
				if p+1 <= len(stream) {
					dl := int(stream[p])
					if p+1+dl+2 <= len(stream) {
						fields["dst_addr"] = string(stream[p+1 : p+1+dl])
						fields["dst_port"] = binary.BigEndian.Uint16(stream[p+1+dl : p+3+dl])
					}
				}
			case 4:
				if p+18 <= len(stream) {
					fields["dst_addr"] = hex.EncodeToString(stream[p : p+16])
					fields["dst_port"] = binary.BigEndian.Uint16(stream[p+16 : p+18])
				}
			}
		}
	} else if len(stream) >= 2 && stream[0] == 5 {
		// 服务端流：method choice +（可续）reply（复审发现 6：REP 曾错标
		// method_choice）
		fields["server_method_choice"] = stream[1]
		off = 2
		if off+4 <= len(stream) && stream[off] == 5 {
			fields["rep"] = stream[off+1]
			if rep, ok := map[byte]string{0: "succeeded", 1: "general_failure", 2: "not_allowed", 3: "network_unreachable"}[stream[off+1]]; ok {
				fields["rep_name"] = rep
			}
		}
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- Shadowsocks（SOCKS5 握手镜像 + 地址头；TCP 8388）----

type shadowsocksParser struct{}

func (shadowsocksParser) Name() string { return "shadowsocks" }

func (shadowsocksParser) CanParse(port uint16, sample []byte) bool {
	return port == 8388 && len(sample) >= 2
}

func (shadowsocksParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "shadowsocks", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "shadowsocks", Extra: map[string]any{}}
	fields := map[string]any{}
	if stream[0] == 5 {
		// SOCKS5 握手镜像（引擎 socks5_* 字段同形）
		r, err := socks5Parser{}.Parse(stream)
		if err == nil && r.Detail != nil && len(r.Detail.Messages) > 0 {
			for k, v := range r.Detail.Messages[0].Fields {
				fields["socks5_"+k] = v
			}
		}
	} else {
		// 地址头：ATYP + addr + port + 载荷（加密体不深解）
		atyp := stream[0]
		fields["atyp"] = atyp
		p := 1
		switch atyp {
		case 1:
			if p+6 <= len(stream) {
				fields["dst_addr"] = fmt.Sprintf("%d.%d.%d.%d", stream[p], stream[p+1], stream[p+2], stream[p+3])
				fields["dst_port"] = binary.BigEndian.Uint16(stream[p+4 : p+6])
			}
		case 3:
			if p+1 <= len(stream) {
				dl := int(stream[p])
				if p+1+dl+2 <= len(stream) {
					fields["dst_addr"] = string(stream[p+1 : p+1+dl])
					fields["dst_port"] = binary.BigEndian.Uint16(stream[p+1+dl : p+3+dl])
				}
			}
		case 4:
			if p+18 <= len(stream) {
				fields["dst_addr"] = hex.EncodeToString(stream[p : p+16])
				fields["dst_port"] = binary.BigEndian.Uint16(stream[p+16 : p+18])
			}
		}
		fields["payload_bytes"] = len(stream) - off2(fields, len(stream))
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// off2 估算地址头长度（shadowsocks 辅助）。
func off2(fields map[string]any, total int) int {
	atyp, ok := fields["atyp"].(byte)
	if !ok {
		return 0
	}
	switch atyp {
	case 1:
		return 7
	case 3:
		if a, ok2 := fields["dst_addr"].(string); ok2 {
			return 2 + len(a) + 2
		}
		return 0
	case 4:
		return 19
	}
	return 0
}

// ---- VMess（识别+指令计数；主体加密不深解）----

type vmessParser struct{}

func (vmessParser) Name() string { return "vmess" }

func (vmessParser) CanParse(port uint16, sample []byte) bool {
	// 无固定端口——签名收紧（P2b 复审发现 4）：16B auth + version 0x01 +
	// dataLen 高字节 0 + 数据长度合理下限，压误标率护 unknown 兜底契约
	return len(sample) >= 19 && sample[16] == 0x01 && sample[17] == 0x00 && sample[18] >= 0x18
}

func (vmessParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "vmess", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "vmess", Extra: map[string]any{}}
	fields := map[string]any{
		"auth_hash": hex.EncodeToString(stream[0:16]),
		"version":   stream[16],
		"payload_len": len(stream),
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- DoIP（ISO 13400-2；TCP/UDP 13400）----

type doipParser struct{}

func (doipParser) Name() string { return "doip" }

func (doipParser) CanParse(port uint16, sample []byte) bool {
	if port != 13400 || len(sample) < 8 {
		return false
	}
	return sample[0] == 2 && sample[1] == 0xFD // version 2 + inverse
}

func (doipParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "doip", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "doip", Extra: map[string]any{}}
	pt := binary.BigEndian.Uint16(stream[2:4])
	ptNames := map[uint16]string{
		0x0000: "generic_header_ack", 0x0001: "vehicle_id_req",
		0x0004: "vehicle_announcement", 0x0005: "routing_activation_req",
		0x0006: "routing_activation_resp", 0x8001: "diagnostic",
		0x8003: "diagnostic_positive_ack", 0x8002: "diagnostic_negative_ack",
	}
	fields := map[string]any{
		"protocol_version": stream[0],
		"payload_type":     fmt.Sprintf("0x%04x", pt),
	}
	if n, ok := ptNames[pt]; ok {
		fields["payload_type_name"] = n
	}
	fields["payload_len"] = binary.BigEndian.Uint32(stream[4:8])
	if len(stream) >= 12 {
		fields["source_address"] = binary.BigEndian.Uint16(stream[8:10])
		fields["target_address"] = binary.BigEndian.Uint16(stream[10:12])
	}
	res.Metadata["payload_type"] = fields["payload_type"]
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- EDP（OneNET 增强设备协议；TCP 明文长连接）----

type edpParser struct{}

func (edpParser) Name() string { return "edp" }

func (edpParser) CanParse(port uint16, sample []byte) bool {
	// 签名极弱（任意二进制 ~40% 命中）——必须端口门禁（P2b 复审发现 2：
	// 无门禁误吞 unknown 兜底流，破坏 §H 契约）。引擎 fixture 4472/变体 12472。
	if port != 4472 && port != 12472 {
		return false
	}
	return len(sample) >= 3 && sample[1] >= 1 && sample[1] <= 0xA
}

func (edpParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "edp", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "edp", Extra: map[string]any{}}
	// 变长头：len 1B（<128）/ 2B(0x80|hi, lo) / 4B（MQTT 风变长，OneNET 文档面）
	off := 0
	var msgLen int
	if stream[0] < 0x80 {
		msgLen = int(stream[0])
		off = 1
	} else {
		msgLen = int(stream[0]&0x7F)<<8 | int(stream[1])
		off = 2
	}
	t := stream[off]
	fields := map[string]any{
		"msg_len":  msgLen,
		"msg_type": t,
	}
	typeNames := map[byte]string{
		1: "connect_req", 2: "connect_resp", 3: "push_data", 4: "push_data_resp",
		5: "save_data", 6: "save_data_resp", 7: "save_ack", 8: "cmd",
		9: "update_req", 0xA: "update_resp",
	}
	if n, ok := typeNames[t]; ok {
		fields["msg_type_name"] = n
	}
	res.Metadata["msg_type"] = t
	if t == 1 && off+1 < len(stream) {
		// connect：rest = 协议描述串 + 设备 ID（引擎 connect 面镜像，简化）
		rest := stream[off+1:]
		if z := strings.IndexByte(string(rest), 0); z > 0 {
			fields["proto_desc"] = string(rest[:z])
		}
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- gRPC（方案 b：h2 识别+帧统计，HPACK 后置；RFC 9113 §3.4/§4）----

type grpcParser struct{}

func (grpcParser) Name() string { return "grpc" }

var h2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

func (grpcParser) CanParse(port uint16, sample []byte) bool {
	if len(sample) < 24 {
		return false
	}
	return string(sample[:24]) == string(h2Preface)
}

func (grpcParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "grpc", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "grpc", Extra: map[string]any{}}
	fields := map[string]any{"h2_preface": true}
	off := 24
	typeNames := map[byte]string{
		0: "data", 1: "headers", 2: "priority", 3: "rst_stream",
		4: "settings", 5: "push_promise", 6: "ping", 7: "goaway", 8: "window_update",
	}
	frameCounts := map[string]int{}
	var streams []uint32
	n := 0
	for off+9 <= len(stream) && n < 128 {
		l := int(stream[off])<<16 | int(stream[off+1])<<8 | int(stream[off+2])
		ft := stream[off+3]
		sid := binary.BigEndian.Uint32(stream[off+5:off+9]) & 0x7FFFFFFF
		name := typeNames[ft]
		if name == "" {
			name = fmt.Sprintf("type_%d", ft)
		}
		frameCounts[name]++
		if sid > 0 {
			streams = appendUniqueU32(streams, sid)
		}
		off += 9 + l
		n++
	}
	fields["frame_counts"] = frameCounts
	fields["stream_count"] = len(streams)
	if fc, ok := frameCounts["settings"]; ok {
		res.Metadata["settings_frames"] = fc
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

func appendUniqueU32(s []uint32, v uint32) []uint32 {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

var _ = strconv.Itoa
