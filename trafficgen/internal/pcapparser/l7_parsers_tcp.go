package pcapparser

// P2b TCP 解析器——文本族（D-PARSE-1 §P3 P2b 表）。流级解析：单次 Parse 吃
// 重组流，行循环有界。注册序：rtsp/sip 在 http 前（签名优先防 "OPTIONS "
// 被吞），CanParse 双信号（端口或载荷签名）。

import (
	"encoding/binary"
	"encoding/json"
	"strings"
)

// linesOf 切行（兼容 \n 或 \r\n），cap 防爆炸。
func linesOf(stream []byte, capN int) []string {
	s := strings.ReplaceAll(string(stream), "\r\n", "\n")
	lines := strings.Split(s, "\n")
	if len(lines) > capN {
		lines = lines[:capN]
	}
	return lines
}

// ---- SMTP（RFC 5321 §4 + RFC 4954/3207；端口 25）----

type smtpParser struct{}

func (smtpParser) Name() string { return "smtp" }

func (smtpParser) CanParse(port uint16, sample []byte) bool {
	if port == 25 {
		return len(sample) > 0
	}
	p := string(sample)
	// 签名：命令行或 3 位响应码行
	for _, m := range []string{"EHLO ", "HELO ", "MAIL FROM", "RCPT TO"} {
		if strings.HasPrefix(p, m) {
			return true
		}
	}
	return false
}

func (smtpParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "smtp", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "smtp", Extra: map[string]any{}}
	lines := linesOf(stream, 256)
	var banner string
	var commands, replies, mailFrom, rcptTo []string
	inData := false
	inAuth := false
	var authCredentials []string
	for _, ln := range lines {
		if ln == "" {
			continue
		}
		if inData {
			if ln == "." {
				inData = false
			}
			continue
		}
		if inAuth {
			// 已知 SMTP 命令词→AUTH 交互结束（反馈项 3c：AUTH LOGIN 后
			// 无退出条件致 MAIL/RCPT/DATA 全被吞入凭据）
			up := strings.ToUpper(ln)
			isCmd := false
			for _, verb := range []string{"MAIL ", "RCPT ", "DATA", "QUIT", "EHLO ", "HELO ", "RSET"} {
				if strings.HasPrefix(up, verb) {
					isCmd = true
					break
				}
			}
			if isCmd {
				inAuth = false
			} else {
				authCredentials = append(authCredentials, ln)
				continue
			}
		}
		if len(ln) >= 3 && ln[0] >= '0' && ln[0] <= '9' && ln[1] >= '0' && ln[1] <= '9' && ln[2] >= '0' && ln[2] <= '9' {
			if banner == "" {
				banner = ln
				res.Metadata["banner_code"] = atoiSafe(ln[:3])
			}
			replies = append(replies, ln[:3])
			continue
		}
		cmd := strings.ToUpper(strings.SplitN(ln, " ", 2)[0])
		commands = append(commands, cmd)
		switch cmd {
		case "DATA":
			inData = true
		case "AUTH":
			inAuth = true
		case "EHLO", "HELO":
			res.Metadata["helo"] = strings.TrimSpace(ln[4:])
		case "MAIL":
			if i := strings.Index(strings.ToUpper(ln), "FROM:"); i >= 0 {
				mailFrom = append(mailFrom, strings.TrimSpace(ln[i+5:]))
			}
		case "RCPT":
			if i := strings.Index(strings.ToUpper(ln), "TO:"); i >= 0 {
				rcptTo = append(rcptTo, strings.TrimSpace(ln[i+3:]))
			}
		}
	}
	fields := map[string]any{}
	if authCredentials != nil {
		fields["auth_credentials"] = authCredentials
	}
	if banner != "" {
		fields["banner"] = banner
	}
	if commands != nil {
		fields["commands"] = commands
		res.Metadata["commands"] = commands
	}
	if authCredentials != nil {
		fields["auth_credentials"] = authCredentials
	}
	if replies != nil {
		fields["reply_codes"] = replies
	}
	if mailFrom != nil {
		fields["mail_from"] = mailFrom
	}
	if rcptTo != nil {
		fields["rcpt_to"] = rcptTo
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- POP3（RFC 1939 §3；端口 110）----

type pop3Parser struct{}

func (pop3Parser) Name() string { return "pop3" }

func (pop3Parser) CanParse(port uint16, sample []byte) bool {
	if port == 110 {
		return len(sample) > 0
	}
	p := string(sample)
	return strings.HasPrefix(p, "+OK") || strings.HasPrefix(p, "-ERR")
}

func (pop3Parser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "pop3", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "pop3", Extra: map[string]any{}}
	lines := linesOf(stream, 256)
	fields := map[string]any{}
	var commands []string
	for _, ln := range lines {
		if ln == "" {
			continue
		}
		if strings.HasPrefix(ln, "+OK") && fields["banner"] == nil {
			fields["banner"] = ln
			continue
		}
		if strings.HasPrefix(ln, "-ERR") && fields["first_err"] == nil {
			fields["first_err"] = ln
			continue
		}
		// 服务端多行体（RETR 数据）跳过：非命令非状态行按体处理（简化面）
		up := strings.ToUpper(ln)
		for _, c := range []string{"USER ", "PASS ", "STAT", "LIST", "RETR", "DELE", "QUIT", "UIDL"} {
			if strings.HasPrefix(up, c) {
				commands = append(commands, strings.TrimSpace(c))
			}
		}
	}
	if commands != nil {
		fields["commands"] = commands
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- IMAP（RFC 3501 §6；端口 143）----

type imapParser struct{}

func (imapParser) Name() string { return "imap" }

func (imapParser) CanParse(port uint16, sample []byte) bool {
	if port == 143 {
		return len(sample) > 0
	}
	p := string(sample)
	return strings.HasPrefix(p, "* OK") || strings.HasPrefix(p, "* CAPABILITY")
}

func (imapParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "imap", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "imap", Extra: map[string]any{}}
	lines := linesOf(stream, 256)
	fields := map[string]any{}
	var tags, commands []string
	for _, ln := range lines {
		if strings.HasPrefix(ln, "* ") {
			up := strings.ToUpper(ln)
			if strings.Contains(up, "CAPABILITY") {
				fields["capability_line"] = ln
			}
			continue
		}
		// tagged: "a1 LOGIN user pass"
		parts := strings.SplitN(ln, " ", 3)
		if len(parts) >= 2 && len(parts[0]) <= 16 {
			tags = append(tags, parts[0])
			commands = append(commands, strings.ToUpper(parts[1]))
			if strings.ToUpper(parts[1]) == "LOGIN" && len(parts) >= 3 {
				fields["login_line"] = parts[0] + " LOGIN ..."
			}
		}
	}
	if tags != nil {
		fields["tags"] = tags
	}
	if commands != nil {
		fields["commands"] = commands
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- RTSP（RFC 2326 §6/§12；端口 554）----

type rtspParser struct{}

func (rtspParser) Name() string { return "rtsp" }

func (rtspParser) CanParse(port uint16, sample []byte) bool {
	if port == 554 {
		return len(sample) > 0
	}
	// 行首锚定（P2b 复审发现 3：全文 Contains 会劫持体含 "RTSP/1.0" 字样的
	// HTTP 流——HTTP 头是自由文本）：状态行 "RTSP/" 或请求行 "方法 RTSP/x.y"
	line := sample
	if i := strings.IndexByte(string(sample), '\r'); i >= 0 {
		line = sample[:i]
	} else if i := strings.IndexByte(string(sample), '\n'); i >= 0 {
		line = sample[:i]
	}
	ls := string(line)
	if strings.HasPrefix(ls, "RTSP/") {
		return true
	}
	if i := strings.Index(ls, " RTSP/"); i > 0 {
		method := strings.SplitN(ls[:i], " ", 2)[0]
		switch method {
		case "OPTIONS", "DESCRIBE", "SETUP", "PLAY", "PAUSE", "TEARDOWN",
			"GET_PARAMETER", "SET_PARAMETER", "ANNOUNCE", "RECORD", "REDIRECT":
			return true
		}
	}
	return false
}

func (rtspParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "rtsp", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "rtsp", Extra: map[string]any{}}
	blocks := strings.Split(string(stream), "\r\n\r\n")
	var methods []string
	var cseqs, sessions []string
	var sdpMedia []string
	for _, b := range blocks {
		if b == "" {
			continue
		}
		lines := strings.Split(b, "\r\n")
		first := lines[0]
		if strings.HasPrefix(first, "v=0") || strings.HasPrefix(first, "o=") ||
			strings.HasPrefix(first, "c=") || strings.HasPrefix(first, "m=") {
			continue // SDP 行跳过（缺陷 4）
		}
		if strings.HasPrefix(first, "RTSP/") {
			// 响应
			parts := strings.SplitN(first, " ", 3)
			if len(parts) >= 2 {
				res.Metadata["last_status"] = atoiSafe(parts[1])
			}
		} else {
			parts := strings.SplitN(first, " ", 3)
			if len(parts) >= 1 {
				methods = append(methods, parts[0])
			}
		}
		hdrs := headerMulti(lines[1:])
		if v, ok := headerFirst(hdrs, "cseq"); ok {
			cseqs = append(cseqs, v)
		}
		if v, ok := headerFirst(hdrs, "session"); ok {
			sessions = append(sessions, v)
		}
		if v, ok := headerFirst(hdrs, "transport"); ok {
			var transports []string
			if prev, ok2 := detail.Extra["transports"].([]string); ok2 {
				transports = prev
			}
			detail.Extra["transports"] = append(transports, v)
		}
		// SDP 面（DESCRIBE/ANNOUNCE 体）：c=/m= 行
		for _, ln := range lines {
			if strings.HasPrefix(ln, "m=") {
				sdpMedia = append(sdpMedia, ln[2:])
			}
		}
	}
	fields := map[string]any{}
	if methods != nil {
		fields["methods"] = methods
		res.Metadata["methods"] = methods
	}
	if cseqs != nil {
		fields["cseqs"] = cseqs
	}
	if sessions != nil {
		fields["sessions"] = sessions
	}
	if sdpMedia != nil {
		fields["sdp_media"] = sdpMedia
		detail.Extra["sdp_media"] = sdpMedia
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- SIP（RFC 3261 §7/§20 + RFC 8866 SDP；端口 5060）----

type sipParser struct{}

func (sipParser) Name() string { return "sip" }

func (sipParser) CanParse(port uint16, sample []byte) bool {
	if port == 5060 {
		return len(sample) > 0
	}
	p := string(sample)
	return strings.HasPrefix(p, "SIP/2.0 ") || strings.Contains(p, " SIP/2.0\r\n")
}

func (sipParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "sip", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "sip", Extra: map[string]any{}}
	blocks := strings.Split(string(stream), "\r\n\r\n")
	var callIDs, methods []string
	var sdpAddr, sdpMedia []string
	for bi, b := range blocks {
		if b == "" {
			continue
		}
		lines := strings.Split(b, "\r\n")
		first := lines[0]
		if bi > 0 {
			// 非首块 = SDP 体：只扫 c=/m=，不提方法/响应（缺陷 4：v=0 混入 methods）
			for _, ln := range lines {
				if strings.HasPrefix(ln, "c=") {
					sdpAddr = append(sdpAddr, strings.TrimPrefix(ln, "c="))
				}
				if strings.HasPrefix(ln, "m=") {
					sdpMedia = append(sdpMedia, strings.TrimPrefix(ln, "m="))
				}
			}
			continue
		}
		if strings.HasPrefix(first, "SIP/2.0 ") {
			parts := strings.SplitN(first, " ", 3)
			if len(parts) >= 2 {
				res.Metadata["last_status"] = atoiSafe(parts[1])
			}
			if len(parts) >= 3 {
				res.Metadata["last_reason"] = parts[2]
			}
		} else {
			parts := strings.SplitN(first, " ", 3)
			if len(parts) >= 1 {
				methods = append(methods, parts[0])
			}
		}
		hdrs := headerMulti(lines[1:])
		if v, ok := headerFirst(hdrs, "call-id"); ok {
			callIDs = append(callIDs, v)
		}

	}
	fields := map[string]any{}
	if methods != nil {
		fields["methods"] = methods
		res.Metadata["methods"] = methods
	}
	if callIDs != nil {
		fields["call_ids"] = callIDs
		res.Metadata["call_id"] = callIDs[0]
	}
	if sdpAddr != nil {
		fields["sdp_connection"] = sdpAddr
		detail.Extra["sdp_connection"] = sdpAddr
	}
	if sdpMedia != nil {
		fields["sdp_media"] = sdpMedia
		detail.Extra["sdp_media"] = sdpMedia
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- XMPP（RFC 6120 §4/§8；端口 5222）----

type xmppParser struct{}

func (xmppParser) Name() string { return "xmpp" }

func (xmppParser) CanParse(port uint16, sample []byte) bool {
	if port == 5222 {
		return len(sample) > 0
	}
	return strings.Contains(string(sample), ":stream")
}

func (xmppParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "xmpp", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "xmpp", Extra: map[string]any{}}
	s := string(stream)
	fields := map[string]any{}
	// stream 头（§4.2）：from/to 属性
	if i := strings.Index(s, "<stream:stream"); i >= 0 {
		head := s[i:]
		if j := strings.Index(head, ">"); j >= 0 {
			head = head[:j]
			if k := strings.Index(head, "from='"); k >= 0 || true {
				if k = strings.Index(head, "from=\""); k >= 0 {
					rest := head[k+6:]
					if e := strings.IndexByte(rest, '"'); e >= 0 {
						fields["from_jid"] = rest[:e]
					}
				}
				if k = strings.Index(head, "to=\""); k >= 0 {
					rest := head[k+5:]
					if e := strings.IndexByte(rest, '"'); e >= 0 {
						fields["to_jid"] = rest[:e]
					}
				}
			}
		}
	}
	// stanza 面（§8：message/presence/iq 计数）
	counts := map[string]int{}
	for _, tag := range []string{"message", "presence", "iq"} {
		// 开标签计数（<tag 与 <tag: 均计——简化面）
		counts[tag] = strings.Count(s, "<"+tag+">") + strings.Count(s, "<"+tag+" ") + strings.Count(s, "<"+tag+":")
	}
	fields["message_count"] = counts["message"]
	fields["presence_count"] = counts["presence"]
	fields["iq_count"] = counts["iq"]
	// 机制（§5 PLAIN 等）
	if k := strings.Index(s, "<mechanism>"); k >= 0 {
		rest := s[k+11:]
		if e := strings.Index(rest, "</mechanism>"); e >= 0 {
			fields["auth_mechanism"] = rest[:e]
		}
	}
	res.Metadata["message_count"] = fields["message_count"]
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- Gnutella 0.6（GDF；TCP 6346：HTTP 握手 + 23B 描述符头）----

type gnutellaParser struct{}

func (gnutellaParser) Name() string { return "gnutella" }

func (gnutellaParser) CanParse(port uint16, sample []byte) bool {
	if port == 6346 {
		return len(sample) > 0
	}
	return strings.HasPrefix(string(sample), "GNUTELLA ")
}

func (gnutellaParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "gnutella", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "gnutella", Extra: map[string]any{}}
	fields := map[string]any{}
	// 握手面（GDF §0.6：HTTP-like ASCII + CRLF CRLF）
	end := strings.Index(string(stream), "\r\n\r\n")
	if end >= 0 {
		lines := strings.Split(string(stream[:end]), "\r\n")
		fields["handshake_line"] = lines[0]
		fields["client_headers"] = headerMulti(lines[1:])
		// 描述符面（23B 头：GUID16 + type1 + TTL1 + hops1 + len4）
		off := end + 4
		var descriptors []map[string]any
		names := map[byte]string{0x00: "ping", 0x01: "pong", 0x80: "query", 0x81: "queryhit", 0x40: "push"}
		for off+23 <= len(stream) && len(descriptors) < 64 {
			dt := stream[off+16]
			pl := int(binary.BigEndian.Uint32(stream[off+19 : off+23]))
			d := map[string]any{
				"type":        names[dt],
				"type_raw":    dt,
				"ttl":         stream[off+17],
				"hops":        stream[off+18],
				"payload_len": pl,
			}
			descriptors = append(descriptors, d)
			off += 23 + pl
			if off > len(stream) {
				detail.Truncated = true
				break
			}
		}
		if descriptors != nil {
			fields["descriptors"] = descriptors
		}
	} else {
		fields["handshake_line"] = strings.SplitN(string(stream), "\n", 2)[0]
		detail.Truncated = true
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: fields})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ---- Stratum v1（行式 JSON；引擎缺省端口）----

type stratumParser struct{}

func (stratumParser) Name() string { return "stratum" }

func (stratumParser) CanParse(port uint16, sample []byte) bool {
	p := string(sample)
	return strings.HasPrefix(strings.TrimSpace(p), "{\"")
}

func (stratumParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "stratum", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "stratum", Extra: map[string]any{}}
	var methods []string
	for _, ln := range linesOf(stream, MaxL7Messages) {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(ln), &obj); err != nil {
			detail.Truncated = true
			break
		}
		f := map[string]any{}
		if id, ok := obj["id"]; ok {
			f["id"] = id
		}
		if m, ok := obj["method"].(string); ok {
			f["method"] = m
			methods = append(methods, m)
			detail.appendMessage(L7Message{Kind: "request", WireLen: len(ln), Fields: f})
			continue
		}
		if _, ok := obj["result"]; ok {
			f["has_result"] = true
			detail.appendMessage(L7Message{Kind: "response", WireLen: len(ln), Fields: f})
			continue
		}
		detail.appendMessage(L7Message{Kind: "message", WireLen: len(ln), Fields: f})
	}
	if methods != nil {
		res.Metadata["methods"] = methods
	}
	detail.countKinds()
	res.Detail = detail
	return res, nil
}
