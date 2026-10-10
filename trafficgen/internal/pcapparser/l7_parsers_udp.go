package pcapparser

// P2a UDP 解析器第一段（D-PARSE-1 §P3 P2a 表；字段面=该表"流级字段"列，
// 规范依据见表内引用）。每个解析器：CanParse 端口+载荷 sanity，Parse 单
// 消息（UDP 每包一 datagram）。字段全部 snake_case。

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// ---- helpers ----

// optWalk 遍历 TLV(1B code/type + 1B len + data) 列表（DHCP options）。
func optWalk(data []byte, fn func(code byte, val []byte) bool) {
	off := 0
	for off+2 <= len(data) {
		code := data[off]
		l := int(data[off+1])
		if off+2+l > len(data) {
			return
		}
		if !fn(code, data[off+2:off+2+l]) {
			return
		}
		off += 2 + l
	}
}

// ---- DHCP（RFC 2131 §2；端口 67/68）----

type dhcpParser struct{}

func (dhcpParser) Name() string { return "dhcp" }

func (dhcpParser) CanParse(port uint16, sample []byte) bool {
	if port != 67 && port != 68 {
		return false
	}
	// magic cookie 0x63825363 @236（RFC 2131 §2 长度面 236B 固定头）
	return len(sample) >= 240 && sample[236] == 0x63 && sample[237] == 0x82 && sample[238] == 0x53 && sample[239] == 0x63
}

func (dhcpParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "dhcp", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "dhcp", Extra: map[string]any{}}
	fields := map[string]any{
		"op":     stream[0],
		"htype":  stream[1],
		"hlen":   stream[2],
		"xid":    binary.BigEndian.Uint32(stream[4:8]),
		"secs":   binary.BigEndian.Uint16(stream[8:10]),
		"flags":  binary.BigEndian.Uint16(stream[10:12]),
		"ciaddr": net.IP(stream[12:16]).String(),
		"yiaddr": net.IP(stream[16:20]).String(),
		"siaddr": net.IP(stream[20:24]).String(),
		"giaddr": net.IP(stream[24:28]).String(),
	}
	if hlen := int(stream[2]); hlen <= 16 {
		fields["chaddr"] = hex.EncodeToString(stream[28 : 28+hlen])
	}
	// options（RFC 2131 §2 options 面；cap 48 防爆炸）
	ipStr := func(b []byte) string { return net.IP(b).String() }
	optWalk(stream[240:], func(code byte, val []byte) bool {
		switch code {
		case 53:
			fields["msg_type"] = val[0]
		case 54:
			if len(val) == 4 {
				fields["server_id"] = ipStr(val)
			}
		case 51:
			if len(val) == 4 {
				fields["lease_time"] = binary.BigEndian.Uint32(val)
			}
		case 1:
			if len(val) == 4 {
				fields["subnet_mask"] = ipStr(val)
			}
		case 3:
			if len(val) == 4 {
				fields["router"] = ipStr(val)
			}
		case 6:
			var ips []string
			for i := 0; i+4 <= len(val); i += 4 {
				ips = append(ips, ipStr(val[i:i+4]))
			}
			fields["dns_servers"] = ips
		case 12:
			fields["hostname"] = string(val)
		case 55:
			fields["param_req_list"] = hex.EncodeToString(val)
		case 82:
			fields["agent_info"] = hex.EncodeToString(val)
		case 255:
			return false
		}
		return true
	})
	res.Metadata["xid"] = fields["xid"]
	if mt, ok := fields["msg_type"]; ok {
		res.Metadata["msg_type"] = mt
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- DHCPv6（RFC 8415 §6；端口 546/547）----

type dhcpv6Parser struct{}

func (dhcpv6Parser) Name() string { return "dhcpv6" }

func (dhcpv6Parser) CanParse(port uint16, sample []byte) bool {
	if port != 546 && port != 547 {
		return false
	}
	if len(sample) < 4 {
		return false
	}
	mt := sample[0]
	return mt >= 1 && mt <= 18
}

func (dhcpv6Parser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "dhcpv6", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "dhcpv6", Extra: map[string]any{}}
	fields := map[string]any{
		"msg_type":       stream[0],
		"transaction_id": hex.EncodeToString(stream[1:4]),
	}
	var clientDUID, serverDUID string
	var dnsServers []string
	off := 4
	for off+4 <= len(stream) {
		code := binary.BigEndian.Uint16(stream[off : off+2])
		l := int(binary.BigEndian.Uint16(stream[off+2 : off+4]))
		off += 4
		if off+l > len(stream) {
			detail.Truncated = true
			break
		}
		val := stream[off : off+l]
		switch code {
		case 1:
			clientDUID = hex.EncodeToString(val)
		case 2:
			serverDUID = hex.EncodeToString(val)
		case 3:
			fields["ia_na"] = hex.EncodeToString(val)
		case 7:
			if l == 1 {
				fields["preference"] = val[0]
			}
		case 13:
			if l >= 2 {
				fields["status_code"] = binary.BigEndian.Uint16(val)
			}
		case 23:
			for i := 0; i+16 <= len(val); i += 16 {
				dnsServers = append(dnsServers, net.IP(val[i:i+16]).String())
			}
		case 24:
			fields["domain_list"] = hex.EncodeToString(val)
		}
		off += l
	}
	if clientDUID != "" {
		fields["client_duid"] = clientDUID
	}
	if serverDUID != "" {
		fields["server_duid"] = serverDUID
	}
	if dnsServers != nil {
		fields["dns_servers"] = dnsServers
	}
	res.Metadata["msg_type"] = fields["msg_type"]
	res.Metadata["transaction_id"] = fields["transaction_id"]
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- TFTP（RFC 1350 §5 + RFC 2347/2348/2349；端口 69）----

type tftpParser struct{}

func (tftpParser) Name() string { return "tftp" }

func (tftpParser) CanParse(port uint16, sample []byte) bool {
	return port == 69 && len(sample) >= 4
}

func (tftpParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "tftp", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "tftp", Extra: map[string]any{}}
	op := binary.BigEndian.Uint16(stream[0:2])
	fields := map[string]any{"opcode": op}
	kind := "message"
	switch op {
	case 1, 2:
		kind = "request"
		rest := stream[2:]
		// filename\0 mode\0 [options]
		z := strings.IndexByte(string(rest), 0)
		if z >= 0 {
			fields["filename"] = string(rest[:z])
			rest = rest[z+1:]
			if z2 := strings.IndexByte(string(rest), 0); z2 >= 0 {
				fields["mode"] = string(rest[:z2])
				rest = rest[z2+1:]
			}
			// options（RFC 2347 §5：文本 "name\0value\0" 对）
			var pairs []string
			for len(rest) > 0 {
				z3 := strings.IndexByte(string(rest), 0)
				if z3 < 0 {
					break
				}
				name := string(rest[:z3])
				rest = rest[z3+1:]
				z4 := strings.IndexByte(string(rest), 0)
				if z4 < 0 {
					break
				}
				pairs = append(pairs, name+"="+string(rest[:z4]))
				rest = rest[z4+1:]
			}
			if pairs != nil {
				fields["options"] = pairs
			}
		}
	case 3:
		kind = "message"
		if len(stream) >= 4 {
			fields["block"] = binary.BigEndian.Uint16(stream[2:4])
			fields["data_len"] = len(stream) - 4
		}
	case 4:
		kind = "response"
		if len(stream) >= 4 {
			fields["block"] = binary.BigEndian.Uint16(stream[2:4])
		}
	case 5:
		kind = "response"
		if len(stream) >= 4 {
			fields["error_code"] = binary.BigEndian.Uint16(stream[2:4])
		}
		if z := strings.IndexByte(string(stream[4:]), 0); z >= 0 {
			fields["error_msg"] = string(stream[4 : 4+z])
		}
	case 6:
		kind = "response"
		// OACK: options 文本形 name\0value\0
		rest := stream[2:]
		var pairs []string
		for len(rest) > 0 {
			z := strings.IndexByte(string(rest), 0)
			if z < 0 {
				break
			}
			name := string(rest[:z])
			rest = rest[z+1:]
			z2 := strings.IndexByte(string(rest), 0)
			if z2 < 0 {
				pairs = append(pairs, name+"=")
				break
			}
			pairs = append(pairs, name+"="+string(rest[:z2]))
			rest = rest[z2+1:]
		}
		fields["options"] = pairs
	}
	res.Metadata["opcode"] = op
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- NTP（RFC 5905 §7；端口 123）----

type ntpParser struct{}

func (ntpParser) Name() string { return "ntp" }

func (ntpParser) CanParse(port uint16, sample []byte) bool {
	if port != 123 || len(sample) < 48 {
		return false
	}
	vn := sample[0] >> 3 & 0x7
	return vn >= 1 && vn <= 4
}

func (ntpParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "ntp", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "ntp", Extra: map[string]any{}}
	b0 := stream[0]
	fields := map[string]any{
		"leap_indicator": b0 >> 6,
		"version":        b0 >> 3 & 0x7,
		"mode":           b0 & 0x7,
		"stratum":        stream[1],
		"poll":           int8(stream[2]),
		"precision":      int8(stream[3]),
		"root_delay":     binary.BigEndian.Uint32(stream[4:8]),
		"root_dispersion": binary.BigEndian.Uint32(stream[8:12]),
		"reference_id":   string(stream[12:16]),
	}
	kind := "message"
	switch b0 & 0x7 {
	case 3:
		kind = "request"
		fields["origin_ts"] = binary.BigEndian.Uint64(stream[24:32])
	case 4:
		kind = "response"
		fields["origin_ts"] = binary.BigEndian.Uint64(stream[24:32])
		fields["receive_ts"] = binary.BigEndian.Uint64(stream[32:40])
		fields["transmit_ts"] = binary.BigEndian.Uint64(stream[40:48])
	}
	res.Metadata["mode"] = fields["mode"]
	res.Metadata["version"] = fields["version"]
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- RADIUS（RFC 2865 §3/§5 + RFC 2866；端口 1812/1813）----

type radiusParser struct{}

func (radiusParser) Name() string { return "radius" }

func (radiusParser) CanParse(port uint16, sample []byte) bool {
	if port != 1812 && port != 1813 {
		return false
	}
	if len(sample) < 20 {
		return false
	}
	return binary.BigEndian.Uint16(sample[2:4]) >= 20 && int(binary.BigEndian.Uint16(sample[2:4])) <= len(sample)
}

func (radiusParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "radius", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "radius", Extra: map[string]any{}}
	code := stream[0]
	fields := map[string]any{
		"code":          code,
		"identifier":    stream[1],
		"authenticator": hex.EncodeToString(stream[4:20]),
	}
	kind := "request"
	switch code {
	case 1:
		fields["code_str"] = "access-request"
	case 2:
		kind = "response"
		fields["code_str"] = "access-accept"
	case 3:
		kind = "response"
		fields["code_str"] = "access-reject"
	case 4:
		fields["code_str"] = "accounting-request"
	case 5:
		kind = "response"
		fields["code_str"] = "accounting-response"
	case 11:
		kind = "response"
		fields["code_str"] = "access-challenge"
	default:
		fields["code_str"] = fmt.Sprintf("code_%d", code)
	}
	// attributes（RFC 2865 §5：1B type + 1B len(含头)；cap 64）
	attrs := []map[string]any{}
	off := 20
	for off+2 <= len(stream) {
		at := stream[off]
		al := int(stream[off+1])
		if al < 2 || off+al > len(stream) {
			detail.Truncated = true
			break
		}
		val := stream[off+2 : off+al]
		a := map[string]any{"type": at, "value_hex": hex.EncodeToString(val)}
		switch at {
		case 1:
			a["name"] = "user-name"
			a["value"] = string(val)
			fields["user_name"] = string(val)
		case 4:
			if len(val) == 4 {
				a["name"] = "nas-ip"
				a["value"] = net.IP(val).String()
			}
		case 8:
			if len(val) == 4 {
				a["name"] = "framed-ip"
				a["value"] = net.IP(val).String()
			}
		case 40:
			if len(val) >= 4 {
				a["name"] = "acct-status-type"
				a["value"] = binary.BigEndian.Uint32(val)
			}
		}
		attrs = append(attrs, a)
		off += al
	}
	fields["attributes"] = attrs
	res.Metadata["code"] = code
	res.Metadata["identifier"] = stream[1]
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- SSDP（UPnP Device Architecture §1；端口 1900）----

type ssdpParser struct{}

func (ssdpParser) Name() string { return "ssdp" }

func (ssdpParser) CanParse(port uint16, sample []byte) bool {
	if port != 1900 {
		return false
	}
	p := string(sample)
	return strings.HasPrefix(p, "M-SEARCH ") || strings.HasPrefix(p, "NOTIFY ") || strings.HasPrefix(p, "HTTP/1.1 200")
}

func (ssdpParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "ssdp", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "ssdp", Extra: map[string]any{}}
	lines := strings.Split(string(stream), "\r\n")
	fields := map[string]any{}
	var kind string
	switch {
	case strings.HasPrefix(lines[0], "M-SEARCH"):
		kind = "request"
		fields["method"] = "M-SEARCH"
	case strings.HasPrefix(lines[0], "NOTIFY"):
		kind = "request"
		fields["method"] = "NOTIFY"
	default:
		kind = "response"
		fields["status_line"] = lines[0]
	}
	hdrs := headerMulti(lines[1:])
	hoist := func(field, key string) {
		if v, ok := headerFirst(hdrs, key); ok {
			fields[field] = v
		}
	}
	hoist("st", "st")
	hoist("nt", "nt")
	hoist("nts", "nts")
	hoist("usn", "usn")
	hoist("location", "location")
	hoist("server", "server")
	hoist("mx", "mx")
	hoist("boot_id", "bootid.upnp.org")
	hoist("config_id", "configid.upnp.org")
	hoist("search_target", "st")
	if st, ok := headerFirst(hdrs, "st"); ok {
		res.Metadata["search_target"] = st
	}
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- Syslog（RFC 5424 §6 / RFC 3164；端口 514）----

type syslogParser struct{}

func (syslogParser) Name() string { return "syslog" }

func (syslogParser) CanParse(port uint16, sample []byte) bool {
	if port != 514 || len(sample) < 3 || sample[0] != '<' {
		return false
	}
	scan := sample
	if len(scan) > 8 {
		scan = scan[:8]
	}
	end := strings.IndexByte(string(scan), '>')
	return end > 0
}

func (syslogParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "syslog", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "syslog", Extra: map[string]any{}}
	gt := strings.IndexByte(string(stream), '>')
	pri := atoiSafe(string(stream[1:gt]))
	fields := map[string]any{
		"facility": pri >> 3,
		"severity": pri & 0x7,
		"pri":      pri,
	}
	rest := stream[gt+1:]
	kind := "message"
	// RFC 5424: VERSION 首字符为数字且后随空格分节；RFC 3164: 月名起始
	if len(rest) > 4 && rest[0] >= '0' && rest[0] <= '9' {
		fields["format"] = "rfc5424"
		parts := strings.SplitN(string(rest), " ", 7)
		if len(parts) >= 2 {
			fields["version"] = atoiSafe(parts[0])
		}
		if len(parts) >= 4 {
			fields["timestamp"] = parts[1]
			fields["hostname"] = parts[2]
			fields["app_name"] = parts[3]
		}
		if len(parts) >= 6 {
			fields["procid"] = parts[4]
			fields["msgid"] = parts[5]
		}
		if len(parts) == 7 {
			fields["msg"] = parts[6]
		}
	} else {
		fields["format"] = "rfc3164"
		fields["msg"] = string(rest)
	}
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- STUN（RFC 8489 §5；端口 3478）----

type stunParser struct{}

func (stunParser) Name() string { return "stun" }

func (stunParser) CanParse(port uint16, sample []byte) bool {
	if port != 3478 || len(sample) < 20 {
		return false
	}
	return sample[4] == 0x21 && sample[5] == 0x12 && sample[6] == 0xA4 && sample[7] == 0x42
}

func (stunParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "stun", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "stun", Extra: map[string]any{}}
	msgType := binary.BigEndian.Uint16(stream[0:2])
	method := msgType >> 6 & 0xFFF
	c1c2 := msgType >> 4 & 0x3
	kind := "request"
	if c1c2 == 1 {
		kind = "indication"
	} else if c1c2 == 2 {
		kind = "response"
	} else if c1c2 == 3 {
		kind = "response"
	}
	fields := map[string]any{
		"msg_type":    fmt.Sprintf("0x%04x", msgType),
		"method":      method,
		"magic_ok":    true,
		"txid":        hex.EncodeToString(stream[8:20]),
		"msg_len":     binary.BigEndian.Uint16(stream[2:4]),
	}
	attrs := []map[string]any{}
	off := 20
	end := 20 + int(binary.BigEndian.Uint16(stream[2:4]))
	if end > len(stream) {
		end = len(stream)
	}
	for off+4 <= end {
		at := binary.BigEndian.Uint16(stream[off : off+2])
		al := int(binary.BigEndian.Uint16(stream[off+2 : off+4]))
		if off+4+al > end {
			detail.Truncated = true
			break
		}
		a := map[string]any{"type": fmt.Sprintf("0x%04x", at), "len": al}
		if at == 0x0020 || at == 0x0021 || at == 0x8029 { // XOR-MAPPED-ADDRESS 等
			a["xor"] = true
		}
		attrs = append(attrs, a)
		off += 4 + ((al + 3) / 4 * 4)
	}
	fields["attributes"] = attrs
	res.Metadata["method"] = method
	res.Metadata["txid"] = fields["txid"]
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- CoAP（RFC 7252 §3 + RFC 7959/7641；端口 5683）----

type coapParser struct{}

func (coapParser) Name() string { return "coap" }

func (coapParser) CanParse(port uint16, sample []byte) bool {
	if port != 5683 || len(sample) < 4 {
		return false
	}
	return sample[0]>>6 == 1 // version=1
}

func (coapParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "coap", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "coap", Extra: map[string]any{}}
	b0 := stream[0]
	typ := b0 >> 4 & 0x3
	tkl := int(b0 & 0xF)
	code := stream[1]
	mid := binary.BigEndian.Uint16(stream[2:4])
	kind := "message"
	switch typ {
	case 0, 1:
		kind = "request"
	case 2:
		kind = "response"
	}
	typeNames := []string{"CON", "NON", "ACK", "RST"}
	fields := map[string]any{
		"type":      typeNames[typ],
		"code":      fmt.Sprintf("%d.%02d", code>>5, code&0x1F),
		"code_raw":  code,
		"mid":       mid,
		"token":     hex.EncodeToString(stream[4:4+min(tkl, 8)]),
	}
	// options（RFC 7252 §3.1：nibble delta/len + 扩展字节）
	off := 4 + tkl
	var uriPath, uriQuery []string
	optNo := 0
	for off < len(stream) && stream[off] != 0xFF {
		dn := int(stream[off] >> 4)
		ln := int(stream[off] & 0xF)
		off++
		if dn == 13 {
			if off >= len(stream) {
				break
			}
			dn = int(stream[off]) + 13
			off++
		} else if dn == 14 {
			if off+2 > len(stream) {
				break
			}
			dn = int(binary.BigEndian.Uint16(stream[off:off+2])) + 269
			off += 2
		} else if dn == 15 {
			break
		}
		if ln == 13 {
			if off >= len(stream) {
				break
			}
			ln = int(stream[off]) + 13
			off++
		} else if ln == 14 {
			if off+2 > len(stream) {
				break
			}
			ln = int(binary.BigEndian.Uint16(stream[off:off+2])) + 269
			off += 2
		} else if ln == 15 {
			break
		}
		if off+ln > len(stream) {
			detail.Truncated = true
			break
		}
		optNo += dn
		val := stream[off : off+ln]
		switch optNo {
		case 11: // URI-Path
			uriPath = append(uriPath, string(val))
		case 15: // URI-Query
			uriQuery = append(uriQuery, string(val))
		case 12:
			fields["content_format"] = binary.BigEndian.Uint16(append([]byte{0, 0}, val...))
		case 6:
			fields["observe"] = uint64(0)
			for _, b := range val {
				fields["observe"] = fields["observe"].(uint64)<<8 | uint64(b)
			}
		}
		off += ln
	}
	if uriPath != nil {
		fields["uri_path"] = strings.Join(uriPath, "/")
	}
	if uriQuery != nil {
		fields["uri_query"] = uriQuery
	}
	// CoAP 请求方法与响应码语义（RFC 7252 §5.8/§5.9）
	if code>>5 == 0 {
		switch code & 0x1F {
		case 1:
			fields["method"] = "GET"
		case 2:
			fields["method"] = "POST"
		case 3:
			fields["method"] = "PUT"
		case 4:
			fields["method"] = "DELETE"
		}
	} else if kind == "response" {
		fields["response_code"] = fmt.Sprintf("%d.%02d", code>>5, code&0x1F)
	}
	res.Metadata["mid"] = mid
	res.Metadata["type"] = fields["type"]
	detail.appendMessage(L7Message{Kind: kind, WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
