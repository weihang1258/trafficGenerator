package pcapparser

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// httpParser parses HTTP request/response streams (§14). HTTP is a text
// protocol on TCP: a request line, headers, blank line, body. The parser
// extracts method/uri/host (for filtering) and the body offset (after \r\n\r\n).
type httpParser struct{}

func (httpParser) Name() string { return "http" }

func (httpParser) CanParse(port uint16, sample []byte) bool {
	if port == 80 || port == 8080 || port == 8000 || port == 8081 {
		return true
	}
	s := sample
	// HTTP request methods or response status line.
	for _, m := range []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/"} {
		if bytes.HasPrefix(s, []byte(m)) {
			return true
		}
	}
	return false
}

func (httpParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "http", Metadata: map[string]any{}, BodyOffset: 0, BodyLength: 0}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "http", Extra: map[string]any{}}
	var uris, methods, statuses []string
	var host string
	off := 0
	firstBody := true
	for off < len(stream) {
		idx := bytes.Index(stream[off:], []byte("\r\n\r\n"))
		if idx < 0 {
			// 残头块：不完整报文（错误表截断行）
			if off < len(stream) {
				detail.Truncated = true
			}
			break
		}
		headEnd := off + idx
		bodyStart := headEnd + 4
		lines := strings.Split(string(stream[off:headEnd]), "\r\n")
		headers := headerMulti(lines[1:])
		fields := map[string]any{}
		kind := "request"
		firstLine := lines[0]
		if strings.HasPrefix(firstLine, "HTTP/") {
			kind = "response"
			parts := strings.SplitN(firstLine, " ", 3)
			if len(parts) >= 2 {
				fields["status_code"] = atoiSafe(parts[1])
				statuses = append(statuses, parts[1])
			}
			if len(parts) >= 3 {
				fields["reason"] = parts[2]
			}
		} else {
			parts := strings.SplitN(firstLine, " ", 3)
			if len(parts) >= 2 {
				fields["method"] = parts[0]
				methods = append(methods, parts[0])
				fields["uri"] = parts[1]
				uris = append(uris, parts[1])
			}
			if len(parts) >= 3 {
				fields["version"] = parts[2]
			}
		}
		hoistHTTPHeaders(headers, fields)
		if h, ok := headerFirst(headers, "host"); ok && host == "" {
			host = h
		}
		// body 定界：Content-Length 精确；chunked 找终止块；其余无体
		bodyLen := 0
		if cl, ok := headerFirst(headers, "content-length"); ok {
			bodyLen = atoiSafe(cl)
		}
		bodyEnd := bodyStart
		if _, chunked := headers["transfer-encoding"]; chunked && bodyLen == 0 {
			if t := bytes.Index(stream[bodyStart:], []byte("0\r\n\r\n")); t >= 0 {
				bodyEnd = bodyStart + t + 5
			} else {
				bodyEnd = len(stream)
				detail.Truncated = true
			}
		} else if bodyLen > 0 {
			bodyEnd = bodyStart + bodyLen
			if bodyEnd > len(stream) {
				bodyEnd = len(stream)
				detail.Truncated = true
			}
		}
		fields["body_len"] = bodyEnd - bodyStart
		// 兼容面：L7Result.Body 語义保持首个头块之后的整段（get_body 既有
		// 消费方不变），逐事务精确 body_len 在 messages 里。
		if firstBody {
			res.BodyOffset = bodyStart
			res.BodyLength = len(stream) - bodyStart
			firstBody = false
		}
		// html title：首个响应体（WHATWG HTML §4.2.4）
		if kind == "response" {
			if _, ok := detail.Extra["html_title"]; !ok && bodyEnd > bodyStart {
				if title := extractHTMLTitle(stream[bodyStart:bodyEnd]); title != "" {
					detail.Extra["html_title"] = title
				}
			}
		}
		detail.appendMessage(L7Message{Kind: kind, WireLen: bodyEnd - off, Fields: fields})
		if bodyEnd <= off {
			break // 防御：异常定界不前进时终止
		}
		off = bodyEnd
	}
	// metadata 双写（首值标量 + 全量列表键，setL7 列表 append 语义兼容）
	if len(methods) > 0 {
		res.Metadata["method"] = methods[0]
		if len(methods) > 1 {
			res.Metadata["methods"] = methods
		}
	}
	if len(uris) > 0 {
		res.Metadata["uri"] = uris[0]
		if len(uris) > 1 {
			res.Metadata["uris"] = uris
		}
	}
	if host != "" {
		res.Metadata["host"] = host
	}
	if len(statuses) > 0 {
		res.Metadata["status"] = statuses[0]
		if len(statuses) > 1 {
			res.Metadata["statuses"] = statuses
		}
	}
	// reason 首响应（既有键）
	for i := len(detail.Messages) - 1; i >= 0; i-- {
		if detail.Messages[i].Kind == "response" {
			if r, ok := detail.Messages[i].Fields["reason"]; ok {
				res.Metadata["reason"] = r
			}
			break
		}
	}
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// dnsParser parses DNS messages (RFC 1035 §4)。UDP：每报文一 datagram 单消
// 息（Parse）；TCP：流带 2B 长度前缀逐消息（ParseTCPStream，RFC 1035
// §4.2.2）。解码走自研 dns_wire（裁定3：gopacket 大响应 DecodeFailure）。
type dnsParser struct{}

func (dnsParser) Name() string { return "dns" }

func (dnsParser) CanParse(port uint16, sample []byte) bool {
	if port == 53 || port == 5353 {
		return true
	}
	// A DNS header is 12 bytes; QR is the high bit of byte 2 (flags). This is a
	// weak heuristic, so port is the primary signal.
	return false
}

// dnsMessageFields renders one wire message into snake_case fields.
func dnsMessageFields(m *DNSWireMessage) map[string]any {
	f := map[string]any{
		"txid":      m.TXID,
		"qr":        m.QR,
		"opcode":    m.Opcode,
		"rcode":     m.RCode,
		"aa":        m.AA,
		"tc":        m.TC,
		"rd":        m.RD,
		"ra":        m.RA,
		"ad":        m.AD,
		"cd":        m.CD,
		"qdcount":   m.QD,
		"ancount":   m.AN,
		"nscount":   m.NS,
		"arcount":   m.AR,
		"wire_len":  m.WireLen,
	}
	qs := make([]map[string]any, 0, len(m.Questions))
	for _, q := range m.Questions {
		qs = append(qs, map[string]any{"name": q.Name, "type": q.Type, "type_str": dnsTypeString(q.Type), "class": q.Class})
	}
	f["questions"] = qs
	rrList := func(rrs []DNSWireRR) []map[string]any {
		// get_packet/流级面 RR 列表上限（超大响应防字段爆炸；计数不受限）
		const capRR = 64
		out := make([]map[string]any, 0, len(rrs))
		for i, rr := range rrs {
			if i >= capRR {
				break
			}
			out = append(out, map[string]any{"name": rr.Name, "type": rr.Type, "type_str": dnsTypeString(rr.Type), "class": rr.Class, "ttl": rr.TTL, "rdata": rr.RData})
		}
		return out
	}
	f["answers"] = rrList(m.Answers)
	f["authority"] = rrList(m.Authority)
	f["additionals"] = rrList(m.Additionals)
	return f
}

func (dnsParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "dns", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "dns", Extra: map[string]any{}}
	m, err := decodeDNSWire(stream)
	if err != nil {
		// 识别成功但解析失败：保留解析器名（L7Protocol 由调用方兜底），错误锚词入 detail
		detail.ParseError = err.Error()
		detail.Truncated = strings.Contains(err.Error(), "truncated")
		detail.countKinds()
		res.Detail = detail
		return res, nil
	}
	kind := "query"
	if m.QR == 1 {
		kind = "response"
	}
	detail.appendMessage(L7Message{Kind: kind, WireLen: m.WireLen, Fields: dnsMessageFields(m)})
	dnsFillMetadata(res.Metadata, detail, m, kind)
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// ParseTCPStream decodes a length-prefixed DNS stream (RFC 1035 §4.2.2).
func (dnsParser) ParseTCPStream(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "dns", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "dns", Extra: map[string]any{}}
	msgs, truncated, ok := splitTCPDNSMessages(stream)
	if !ok {
		// 不是前缀流：退回单消息解码
		return dnsParser{}.Parse(stream)
	}
	detail.Truncated = truncated
	var firstQuery, firstResp *DNSWireMessage
	for _, w := range msgs {
		m, err := decodeDNSWire(w)
		if err != nil {
			if detail.ParseError == "" {
				detail.ParseError = err.Error()
			}
			continue
		}
		kind := "query"
		if m.QR == 1 {
			kind = "response"
		}
		detail.appendMessage(L7Message{Kind: kind, WireLen: m.WireLen, Fields: dnsMessageFields(m)})
		if m.QR == 0 && firstQuery == nil {
			firstQuery = m
		}
		if m.QR == 1 && firstResp == nil {
			firstResp = m
		}
	}
	if firstQuery != nil {
		dnsFillMetadata(res.Metadata, detail, firstQuery, "query")
	}
	if firstResp != nil {
		dnsFillMetadata(res.Metadata, detail, firstResp, "response")
	}
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// dnsFillMetadata writes the compat metadata keys (L7Metadata 双写面)：首查询
// 的 name/type/rcode 与首响应的计数/flags（D-PARSE-1 P1 矩阵行 DNS）。
func dnsFillMetadata(meta map[string]any, detail *L7Detail, m *DNSWireMessage, kind string) {
	meta["txid"] = m.TXID
	meta["rcode"] = m.RCode
	if len(m.Questions) > 0 {
		meta["query_name"] = m.Questions[0].Name
		meta["query_type"] = m.Questions[0].Type
		meta["query_type_str"] = dnsTypeString(m.Questions[0].Type)
		meta["query_class"] = m.Questions[0].Class
	}
	meta["is_response"] = m.QR == 1
	if kind == "response" {
		meta["ancount"] = m.AN
		meta["nscount"] = m.NS
		meta["arcount"] = m.AR
		for _, flag := range []struct {
			k string
			v bool
		}{{"aa", m.AA}, {"tc", m.TC}, {"rd", m.RD}, {"ra", m.RA}} {
			meta[flag.k] = flag.v
		}
		if len(m.Answers) > 0 {
			meta["response_ttl"] = m.Answers[0].TTL
		}
	}
	if detail.Extra != nil {
		if _, ok := detail.Extra["query_wire_len"]; !ok {
			detail.Extra["query_wire_len"] = 0
			detail.Extra["response_wire_len"] = 0
		}
		k := "query_wire_len"
		if kind == "response" {
			k = "response_wire_len"
		}
		detail.Extra[k] = detail.Extra[k].(int) + m.WireLen
	}
}

// tlsParser parses TLS handshake metadata (RFC 8446 §4 / RFC 5246 §7.4):
// SNI (RFC 6066 §3), versions, cipher suites, negotiated suite (ServerHello),
// handshake message sequence, ALPN (RFC 7301), and certificate details
// (RFC 5280 via crypto/x509). Record data remains encrypted-opaque.
type tlsParser struct{}

func (tlsParser) Name() string { return "tls" }

func (tlsParser) CanParse(port uint16, sample []byte) bool {
	if port == 443 || port == 995 || port == 465 || port == 993 {
		return true
	}
	// TLS record: content type 0x16 (handshake) + version 0x03xx + length.
	return len(sample) >= 3 && sample[0] == 0x16 && sample[1] == 0x03
}

// tlsParsed carries the walk results filled by parseTLSHandshake.
type tlsParsed struct {
	SNI          string
	Version      string
	CipherSuites []uint16
	Negotiated   string   // ServerHello 单值（hex 4 位）
	HandshakeSeq []string // 消息类型序列（RFC 8446 §4 面）
	ALPN         []string
	Certs        []map[string]any
}

func (tlsParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "tls", Metadata: map[string]any{}}
	detail := &L7Detail{DetailVersion: L7DetailVersion, Type: "tls", Extra: map[string]any{}}
	parsed := &tlsParsed{}
	// 遗留走查函数复用（extractTLSMetadata 同 walk，签名面旧调用兼容）
	meta := extractTLSMetadata(stream, parsed)
	if meta.SNI != "" {
		res.Metadata["sni"] = meta.SNI
	}
	if meta.Version != "" {
		res.Metadata["version"] = meta.Version
	}
	if len(meta.CipherSuites) > 0 {
		codes := make([]string, 0, len(meta.CipherSuites))
		for _, c := range meta.CipherSuites {
			codes = append(codes, fmt.Sprintf("%04x", c))
		}
		res.Metadata["cipher_suites"] = codes
	}
	if meta.CertChainLen > 0 {
		res.Metadata["cert_chain_length"] = meta.CertChainLen
	}
	// P1 typed 面
	if parsed.SNI != "" {
		detail.Extra["sni"] = parsed.SNI
	}
	if parsed.Version != "" {
		detail.Extra["version"] = parsed.Version
	}
	if len(parsed.CipherSuites) > 0 {
		codes := make([]string, 0, len(parsed.CipherSuites))
		for _, c := range parsed.CipherSuites {
			codes = append(codes, fmt.Sprintf("%04x", c))
		}
		detail.Extra["cipher_suites"] = codes
	}
	if parsed.Negotiated != "" {
		detail.Extra["negotiated_cipher"] = parsed.Negotiated
	}
	if len(parsed.HandshakeSeq) > 0 {
		detail.Extra["handshake_sequence"] = parsed.HandshakeSeq
	}
	if len(parsed.ALPN) > 0 {
		detail.Extra["alpn"] = parsed.ALPN
	}
	if len(parsed.Certs) > 0 {
		detail.Extra["certs"] = parsed.Certs
	}
	detail.appendMessage(L7Message{Kind: "message", WireLen: len(stream), Fields: map[string]any{
		"handshake_sequence": parsed.HandshakeSeq,
		"negotiated_cipher":  parsed.Negotiated,
	}})
	detail.countKinds()
	res.Detail = detail
	return res, nil
}

// walkTLSRecords iterates TLS records + handshake messages.
func walkTLSRecords(stream []byte, parsed *tlsParsed) {
	off := 0
	for off+5 <= len(stream) {
		recType := stream[off]
		recLen := int(stream[off+3])<<8 | int(stream[off+4])
		body := stream[off+5:]
		if recLen > len(body) {
			recLen = len(body)
		}
		if recType == 0x16 {
			parseTLSHandshake(body[:recLen], parsed)
		}
		off += 5 + recLen
	}
}

// parseTLSHandshake walks handshake messages within a TLS record body,
// recording the message sequence and per-message facts.
func parseTLSHandshake(body []byte, parsed *tlsParsed) {
	p := 0
	for p+4 <= len(body) {
		hsType := body[p]
		hsLen := int(body[p+1])<<16 | int(body[p+2])<<8 | int(body[p+3])
		msg := body[p+4:]
		if hsLen > len(msg) {
			hsLen = len(msg)
		}
		parsed.HandshakeSeq = append(parsed.HandshakeSeq, tlsHandshakeName(hsType))
		switch hsType {
		case 0x01:
			parseClientHello(msg[:hsLen], parsed)
		case 0x0B:
			parseCertificate(msg[:hsLen], parsed)
		case 0x02:
			parseServerHello(msg[:hsLen], parsed)
		}
		p += 4 + hsLen
	}
}

// tlsHandshakeName maps a handshake type to its name (RFC 8446 §4).
func tlsHandshakeName(t uint8) string {
	switch t {
	case 0:
		return "hello_request"
	case 1:
		return "client_hello"
	case 2:
		return "server_hello"
	case 4:
		return "new_session_ticket"
	case 8:
		return "encrypted_extensions"
	case 11:
		return "certificate"
	case 12:
		return "server_key_exchange"
	case 13:
		return "certificate_request"
	case 14:
		return "server_hello_done"
	case 15:
		return "certificate_verify"
	case 16:
		return "client_key_exchange"
	case 20:
		return "finished"
	default:
		return fmt.Sprintf("type_%d", t)
	}
}

// parseServerHello extracts the negotiated cipher suite (RFC 5246 §7.4.1.3:
// version(2) random(32) sid(1+n) suite(2)).
func parseServerHello(hs []byte, parsed *tlsParsed) {
	if len(hs) < 2+32+1+2 {
		return
	}
	p := 2 + 32
	sidLen := int(hs[p])
	p += 1 + sidLen
	if p+2 > len(hs) {
		return
	}
	parsed.Negotiated = fmt.Sprintf("%04x", uint16(hs[p])<<8|uint16(hs[p+1]))
}

// parseClientHello extracts version, cipher suites, SNI and ALPN.
func parseClientHello(hs []byte, parsed *tlsParsed) {
	if len(hs) < 2+32+1 {
		return
	}
	p := 0
	hv := uint16(hs[0])<<8 | uint16(hs[1])
	parsed.Version = tlsVersionString(hv)
	p = 2 + 32
	if p+1 > len(hs) {
		return
	}
	sidLen := int(hs[p])
	p += 1 + sidLen
	if p+2 > len(hs) {
		return
	}
	csLen := int(hs[p])<<8 | int(hs[p+1])
	p += 2
	if p+csLen > len(hs) {
		return
	}
	for i := 0; i+1 < csLen; i += 2 {
		parsed.CipherSuites = append(parsed.CipherSuites, uint16(hs[p+i])<<8|uint16(hs[p+i+1]))
	}
	p += csLen
	if p+1 > len(hs) {
		return
	}
	cmLen := int(hs[p])
	p += 1 + cmLen
	if p+2 > len(hs) {
		return
	}
	extLen := int(hs[p])<<8 | int(hs[p+1])
	p += 2
	// extEnd = 扩展头起点 + extensions_length（RFC 5246 §7.4.1.2：该长度含
	// 每扩展的 4B 头）。
	extEnd := p + extLen
	if extEnd > len(hs) {
		extEnd = len(hs)
	}
	for p+4 <= extEnd {
		extType := int(hs[p])<<8 | int(hs[p+1])
		extDataLen := int(hs[p+2])<<8 | int(hs[p+3])
		p += 4
		if p+extDataLen > extEnd {
			break
		}
		switch extType {
		case 0x0000: // SNI
			d := hs[p:]
			if len(d) >= 5 {
				nameLen := int(d[3])<<8 | int(d[4])
				if 5+nameLen <= len(d) {
					parsed.SNI = string(d[5 : 5+nameLen])
				}
			}
		case 0x002b: // supported_versions (TLS 1.3)
			d := hs[p:]
			if len(d) >= 3 {
				listLen := int(d[0])
				if listLen >= 2 && len(d) >= 3 {
					v := uint16(d[1])<<8 | uint16(d[2])
					if v == 0x0304 {
						parsed.Version = "TLS 1.3"
					}
				}
			}
		case 0x0010: // ALPN (RFC 7301 §3.1)
			d := hs[p:]
			if len(d) >= 2 {
				listLen := int(d[0])<<8 | int(d[1])
				if listLen > len(d)-2 {
					listLen = len(d) - 2
				}
				i := 2
				for i < 2+listLen {
					l := int(d[i])
					if l == 0 || i+1+l > 2+listLen {
						break
					}
					parsed.ALPN = append(parsed.ALPN, string(d[i+1:i+1+l]))
					i += 1 + l
				}
			}
		}
		p += extDataLen
	}
}

// parseCertificate parses Certificate entries via crypto/x509 (RFC 5280 面；
// 最多 8 张防字段爆炸)，兼记链总长。
func parseCertificate(hs []byte, parsed *tlsParsed) {
	if len(hs) < 3 {
		return
	}
	listLen := int(hs[0])<<16 | int(hs[1])<<8 | int(hs[2])
	if listLen > len(hs)-3 {
		listLen = len(hs) - 3
	}
	p := 3
	end := 3 + listLen
	for p+3 <= end && len(parsed.Certs) < 8 {
		cl := int(hs[p])<<16 | int(hs[p+1])<<8 | int(hs[p+2])
		p += 3
		if cl <= 0 || p+cl > end {
			break
		}
		cert := map[string]any{"der_len": cl}
		if xc, err := x509.ParseCertificate(hs[p : p+cl]); err == nil {
			cert["version"] = xc.Version
			cert["serial"] = xc.SerialNumber.String()
			cert["signature_algorithm"] = xc.SignatureAlgorithm.String()
			cert["issuer"] = xc.Issuer.String()
			cert["subject"] = xc.Subject.String()
			cert["not_before"] = xc.NotBefore.UTC().Format(time.RFC3339)
			cert["not_after"] = xc.NotAfter.UTC().Format(time.RFC3339)
		} else {
			cert["parse_error"] = err.Error()
		}
		parsed.Certs = append(parsed.Certs, cert)
		p += cl
	}
}

// extractTLSSNI walks a TLS ClientHello to find the SNI extension. Best-effort:
// returns "" if not found or the record isn't a ClientHello.
//
// tlsMetadata holds the legacy flat extraction fields (兼容壳：既有测试与
// 调用面继续可用；typed 面走 tlsParser.Parse 的 tlsParsed).
type tlsMetadata struct {
	SNI           string
	Version       string
	CipherSuites  []uint16
	CertChainLen  int
}

// extractTLSMetadata walks TLS records filling both the legacy flat fields
// and the typed tlsParsed face.
func extractTLSMetadata(stream []byte, parsed *tlsParsed) tlsMetadata {
	var meta tlsMetadata
	off := 0
	for off+5 <= len(stream) {
		recType := stream[off]
		recLen := int(stream[off+3])<<8 | int(stream[off+4])
		body := stream[off+5:]
		if recLen > len(body) {
			recLen = len(body)
		}
		if recType == 0x16 { // handshake
			parseTLSHandshake(body[:recLen], parsed)
		}
		off += 5 + recLen
	}
	meta.SNI = parsed.SNI
	meta.Version = parsed.Version
	meta.CipherSuites = parsed.CipherSuites
	for _, c := range parsed.Certs {
		if l, ok := c["der_len"].(int); ok {
			meta.CertChainLen += l
		}
	}
	return meta
}

// tlsVersionString maps a TLS version code to a human-readable string.
func tlsVersionString(v uint16) string {
	switch v {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// Deprecated: use extractTLSMetadata (which also extracts version/cipher/cert).
// Kept for backward compatibility with tests that call it directly.
func extractTLSSNI(stream []byte) string {
	return extractTLSMetadata(stream, &tlsParsed{}).SNI
}

// parseDNS decodes a DNS message payload using gopacket's layers.DNS. Returns
// nil if the payload isn't a valid DNS message.
func parseDNS(payload []byte) *layers.DNS {
	if len(payload) < 12 {
		return nil
	}
	var d layers.DNS
	if err := d.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}
	return &d
}
