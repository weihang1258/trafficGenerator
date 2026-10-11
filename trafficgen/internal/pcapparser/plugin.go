package pcapparser

import (
	"strings"

	"github.com/google/gopacket"
)

// ProtocolParser is the L7 protocol parser plugin interface (§14). A parser
// works on a raw byte stream -- for TCP, the reassembled L7 stream; for UDP,
// each packet's payload (an independent L7 message). It extracts protocol
// metadata + the body boundary (e.g. HTTP body after the headers).
type ProtocolParser interface {
	// Name returns the protocol name (http, dns, tls, ...).
	Name() string
	// CanParse reports whether this parser handles the given port (well-known
	// service port hint) and/or byte content. Used to select a parser when the
	// layer type isn't known (TCP reassembled streams have no gopacket layer).
	CanParse(port uint16, sample []byte) bool
	// Parse extracts L7 metadata + body boundary from a byte stream.
	Parse(stream []byte) (*L7Result, error)
}

// L7Result is the output of an L7 parser: protocol metadata for display/filter
// (兼容双写面) and the typed detail (D-PARSE-1 裁定2) with the body boundary
// within the stream (for body extraction).
type L7Result struct {
	Protocol   string
	Metadata   map[string]any
	Detail     *L7Detail
	BodyOffset int
	BodyLength int
}

// TCPStreamParser is implemented by parsers that need transport-aware TCP
// stream framing (dns: RFC 1035 §4.2.2 2B 长度前缀逐消息). The TCP parse site
// prefers this over Parse; UDP per-packet callers keep using Parse.
type TCPStreamParser interface {
	ParseTCPStream(stream []byte) (*L7Result, error)
}

// headerMulti parses "Key: value" lines into a lowercased multi-value map.
func headerMulti(lines []string) map[string][]string {
	h := map[string][]string{}
	for _, line := range lines {
		if i := strings.IndexByte(line, ':'); i > 0 {
			k := strings.ToLower(strings.TrimSpace(line[:i]))
			h[k] = append(h[k], strings.TrimSpace(line[i+1:]))
		}
	}
	return h
}

func headerFirst(h map[string][]string, key string) (string, bool) {
	if v, ok := h[key]; ok && len(v) > 0 {
		return v[0], true
	}
	return "", false
}

// atoiSafe parses a non-negative decimal, 0 on failure.
func atoiSafe(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return n
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// hoistHTTPHeaders lifts the common named headers into fields (snake_case).
func hoistHTTPHeaders(h map[string][]string, fields map[string]any) {
	set := func(field, key string) {
		if v, ok := headerFirst(h, key); ok {
			fields[field] = v
		}
	}
	set("content_type", "content-type")
	set("content_length", "content-length")
	set("location", "location")
	set("cookie", "cookie")
	set("user_agent", "user-agent")
	set("referer", "referer")
	set("host", "host")
	if v, ok := h["set-cookie"]; ok {
		fields["set_cookie"] = v
	}
}

// Registry holds registered L7 parsers, tried in order for stream parsing.
type Registry struct {
	parsers []ProtocolParser
}

// NewRegistry creates a registry seeded with the built-in L7 parsers.
func NewRegistry() *Registry {
	r := &Registry{}
	// 注册序=优先级（P2b 复审教训）：载荷签名优先的解析器在前——rtsp/sip
	// 的 "OPTIONS/..." 文本先于 http 方法匹配；grpc h2-preface 先于 tls 的
	// 443 端口通配（443 非 TLS 兜底面保持：非 preface 流量仍落 tls）。
	r.Register(&rtspParser{})
	r.Register(&sipParser{})
	r.Register(&httpParser{})
	r.Register(&dnsParser{})
	r.Register(&grpcParser{})
	r.Register(&tlsParser{})
	r.Register(&mqttParser{})
	r.Register(&ftpParser{})
	// P2a UDP 面（D-PARSE-1 §P3；ssdp 在 http 前防文本协议误吞）
	r.Register(&ssdpParser{})
	r.Register(&dhcpParser{})
	r.Register(&dhcpv6Parser{})
	r.Register(&tftpParser{})
	r.Register(&ntpParser{})
	r.Register(&snmpParser{})
	r.Register(&radiusParser{})
	r.Register(&syslogParser{})
	r.Register(&stunParser{})
	r.Register(&coapParser{})
	r.Register(&kerberosParser{})
	r.Register(&ripParser{})
	r.Register(&cflowParser{})
	r.Register(&someipParser{})
	r.Register(&megacoParser{})
	r.Register(&bacnetParser{})
	r.Register(&finsParser{})
	r.Register(&ldpParser{})
	r.Register(&ikeParser{})
	r.Register(&ikeNattParser{})
	// P2b TCP 二进制/文本面
	r.Register(&sshParser{})
	r.Register(&telnetParser{})
	r.Register(&smtpParser{})
	r.Register(&pop3Parser{})
	r.Register(&imapParser{})
	r.Register(&ldapParser{})
	r.Register(&rdpParser{})
	r.Register(&xmppParser{})
	r.Register(&vncParser{})
	r.Register(&rtmpParser{})
	r.Register(&h323Parser{})
	r.Register(&pptpParser{})
	r.Register(&socks5Parser{})
	r.Register(&shadowsocksParser{})
	r.Register(&vmessParser{})
	r.Register(&gnutellaParser{})
	r.Register(&stratumParser{})
	r.Register(&doipParser{})
	r.Register(&edpParser{})
	// P2c 货架协议面（s7 先于 mms——同端口 102 按载荷区分）
	r.Register(&bgpParser{})
	r.Register(&modbusParser{})
	r.Register(&redisParser{})
	r.Register(&mysqlParser{})
	r.Register(&postgresqlParser{})
	r.Register(&iec104Parser{})
	r.Register(&dnp3Parser{})
	r.Register(&smbParser{})
	r.Register(&nfsParser{})
	r.Register(&hl7Parser{})
	r.Register(&opcuaParser{})
	r.Register(&amqpParser{})
	r.Register(&cqlParser{})
	r.Register(&tdsParser{})
	r.Register(&thriftParser{})
	r.Register(&mongodbParser{})
	r.Register(&pcepParser{})
	r.Register(&ntlmParser{})
	r.Register(&spnegoParser{})
	r.Register(&nmeaParser{})
	r.Register(&gbt32960Parser{})
	r.Register(&jt808Parser{})
	r.Register(&jt809Parser{})
	r.Register(&jtt905Parser{})
	r.Register(&moxaParser{})
	r.Register(&damengParser{})
	r.Register(&tnsParser{})
	r.Register(&drdaParser{})
	r.Register(&enipParser{})
	r.Register(&s7Parser{})
	r.Register(&mmsParser{})
	r.Register(&amsParser{})
	r.Register(&openwireParser{})
	return r
}

// Register adds a parser. Find iterates in registration order and the first
// CanParse match wins — earlier registrations take precedence (HTTP -> DNS ->
// TLS -> MQTT -> FTP); append order is load-bearing for port-less probes.
func (r *Registry) Register(p ProtocolParser) {
	r.parsers = append(r.parsers, p)
}

// Find returns the first parser that can handle the given port + sample bytes,
// or nil if none match.
func (r *Registry) Find(port uint16, sample []byte) ProtocolParser {
	for _, p := range r.parsers {
		if p.CanParse(port, sample) {
			return p
		}
	}
	return nil
}

// ParseStream selects a parser by port + sample and parses the stream. Returns
// nil if no parser matches (raw/unknown L7).
func (r *Registry) ParseStream(port uint16, stream []byte) *L7Result {
	p := r.Find(port, stream)
	if p == nil {
		return nil
	}
	res, err := p.Parse(stream)
	if err != nil || res == nil {
		return nil
	}
	return res
}

// Ensure gopacket import is used (for future layer-type-based detection).
var _ gopacket.LayerType
