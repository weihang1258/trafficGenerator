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
	r.Register(&httpParser{})
	r.Register(&dnsParser{})
	r.Register(&tlsParser{})
	r.Register(&mqttParser{})
	r.Register(&ftpParser{})
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
