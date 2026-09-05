// Package doh implements the DNS-over-HTTPS terminal layer (RFC 8484,
// [ip→tcp→http→doh] chain, plaintext HTTP/1.1 main profile doh_http1_plain).
//
// Wire-format authority: docs/protocol-designs/66-doh-design.md v2.2.1 §3 —
// the two HTTP mappings (POST body / GET base64url query parameter, RFC 8484
// §4.1/§6), the 2xx vs non-2xx response shapes (§4.2.1: non-2xx carries NO
// DNS wire), the pinned HTTP header orders, the RFC 1035 DNS wire encoding
// (12B header + Question + Answer/Authority RRs, all big-endian), the
// base64url no-padding alphabet (RFC 4648 §5), and the length formulas
// (§3.5: query L = 12 + QNAME_len + 4; response adds Σ answer bytes).
//
// The generator emits complete HTTP frames as MessageEvents; the http layer
// forwards them verbatim (identity transformer) and the tcp layer owns
// segmentation, handshake, and teardown.
package doh

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Fixture constants (testcase §4 — 全量钉死).
const (
	FixtureDstIP  = "198.51.100.66"
	FixtureDstIP6 = "2001:db8::100:66"
	FixtureName   = "www.example.com"
	FixtureA      = "192.0.2.1"
	FixtureAAAA   = "2001:db8::1"
	FixtureTTL    = 300
	// FixtureURI is the RFC 8484 §4.1 URI template path.
	FixtureURI = "/dns-query"
	// DefaultDNSID is the empty-config baseline ID (0x1234, dns pkg parity).
	DefaultDNSID = 0x1234
)

// MediaType is the DoH media type (RFC 8484 §6).
const MediaType = "application/dns-message"

// QTYPE/QCLASS token tables (RFC 1035 §3.2.2/§3.2.3; HTTPS/SVCB RFC 9460).
var qtypeTokens = map[string]uint16{
	"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
	"TXT": 16, "AAAA": 28, "SRV": 33, "SVCB": 64, "HTTPS": 65,
}

var qclassTokens = map[string]uint16{
	"IN": 1, "CHAOS": 3, "HS": 4, "NONE": 254, "ANY": 255,
}

var rcodeTokens = map[string]uint8{
	"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3,
	"NOTIMP": 4, "REFUSED": 5,
}

// ParseQType resolves a QTYPE token or numeric string to its wire value
// (any 16-bit numeric passes through, RFC 1035 §3.2.2; unknown non-numeric
// tokens are the qtype_token wire fault). "" defaults to A (1).
func ParseQType(tok string) (uint16, error) {
	if tok == "" {
		return 1, nil
	}
	if v, ok := qtypeTokens[strings.ToUpper(tok)]; ok {
		return v, nil
	}
	n, err := strconv.ParseUint(tok, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("qtype %q is not a known token or numeric value (non-numeric token rejected)", tok)
	}
	return uint16(n), nil
}

// ParseQClass resolves a QCLASS token or numeric string ("" -> IN).
func ParseQClass(tok string) (uint16, error) {
	if tok == "" {
		return 1, nil
	}
	if v, ok := qclassTokens[strings.ToUpper(tok)]; ok {
		return v, nil
	}
	n, err := strconv.ParseUint(tok, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("qclass %q is not a known token or numeric value (non-numeric token rejected)", tok)
	}
	return uint16(n), nil
}

// ParseRCode resolves an RCODE token or numeric string ("" -> 0).
func ParseRCode(tok string) (uint8, error) {
	if tok == "" {
		return 0, nil
	}
	if v, ok := rcodeTokens[strings.ToUpper(tok)]; ok {
		return v, nil
	}
	n, err := strconv.ParseUint(tok, 10, 8)
	if err != nil || n > 15 {
		return 0, fmt.Errorf("rcode %q is not a token or 0..15 value", tok)
	}
	return uint8(n), nil
}

// EncodeQName renders a dotted display name into label encoding (RFC 1035
// §3.1: per-label 1B length prefix (0–63) + terminating 0x00 root; "" = root).
// The caller enforces the 255-byte whole-name bound (§2.3.4).
func EncodeQName(name string) ([]byte, error) {
	if name == "" {
		return []byte{0}, nil
	}
	if name == "." {
		return []byte{0}, nil
	}
	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 {
			return nil, fmt.Errorf("qname %q contains an empty label (trailing dot is implicit)", name)
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("qname label %q exceeds 63 bytes (got %d)", label, len(label))
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

// QuerySpec is the resolved query shape shared by the wire + URI builders.
type QuerySpec struct {
	ID     uint16
	Name   string // display form
	QName  []byte // label encoding
	QType  uint16
	QClass uint16
	RD     bool
}

// EncodeQueryWire renders the DNS query message (RFC 1035 §4.1.1): 12B
// header (QR=0, Opcode=0, RD per spec, Z=0, RCODE=0, QDCOUNT=1) + Question.
func EncodeQueryWire(q QuerySpec) []byte {
	return encodeWire(q.ID, queryFlags(q.RD), 1, 0, 0, 0, questionBytes(q), nil, nil)
}

// ResponseSpec is the resolved response shape.
type ResponseSpec struct {
	ID        uint16
	Query     QuerySpec // question echo source
	RCode     uint8
	AA, TC    bool
	RA        bool
	Answers   []EncodedRR
	Authority []EncodedRR
}

// EncodeResponseWire renders the DNS response: 12B header (QR=1, RD echo,
// RA per spec, RCODE) + Question echo + Answer RRs + Authority RRs. Names are
// never compressed (design §3.3: 响应回带完整 QNAME).
func EncodeResponseWire(r ResponseSpec) []byte {
	q := questionBytes(r.Query)
	var answers, authority []byte
	for _, rr := range r.Answers {
		answers = append(answers, rr.bytes...)
	}
	for _, rr := range r.Authority {
		authority = append(authority, rr.bytes...)
	}
	flags := uint16(0x8000) | rcodeBits(r.RCode)
	if r.Query.RD {
		flags |= 0x0100
	}
	if r.RA {
		flags |= 0x0080
	}
	if r.AA {
		flags |= 0x0400
	}
	if r.TC {
		flags |= 0x0200
	}
	return encodeWire(r.ID, flags, 1, uint16(len(r.Answers)), uint16(len(r.Authority)), 0, q, answers, authority)
}

func queryFlags(rd bool) uint16 {
	if rd {
		return 0x0100
	}
	return 0x0000
}

func rcodeBits(rc uint8) uint16 {
	return uint16(rc) & 0x000F
}

func questionBytes(q QuerySpec) []byte {
	out := make([]byte, 0, len(q.QName)+4)
	out = append(out, q.QName...)
	out = binary.BigEndian.AppendUint16(out, q.QType)
	out = binary.BigEndian.AppendUint16(out, q.QClass)
	return out
}

func encodeWire(id uint16, flags uint16, qd, an, ns, ar uint16, question, answers, authority []byte) []byte {
	out := make([]byte, 0, 12+len(question)+len(answers)+len(authority))
	out = binary.BigEndian.AppendUint16(out, id)
	out = binary.BigEndian.AppendUint16(out, flags)
	out = binary.BigEndian.AppendUint16(out, qd)
	out = binary.BigEndian.AppendUint16(out, an)
	out = binary.BigEndian.AppendUint16(out, ns)
	out = binary.BigEndian.AppendUint16(out, ar)
	out = append(out, question...)
	out = append(out, answers...)
	out = append(out, authority...)
	return out
}

// EncodedRR is one pre-rendered resource record.
type EncodedRR struct {
	bytes []byte
}

// Len returns the record's wire length (RDLENGTH sanity checks).
func (rr EncodedRR) Len() int { return len(rr.bytes) }

// EncodeRR renders one resource record: NAME + TYPE + CLASS + TTL + RDLENGTH
// + RDATA (RFC 1035 §4.1.3; RDLENGTH is computed from the actual RDATA —
// never taken from config, so rdlength mismatch is unrepresentable on the
// positive path).
func EncodeRR(name []byte, rtype, rclass uint16, ttl uint32, rdata []byte) (EncodedRR, error) {
	if len(name) == 0 {
		return EncodedRR{}, fmt.Errorf("rr: empty name")
	}
	out := make([]byte, 0, len(name)+10+len(rdata))
	out = append(out, name...)
	out = binary.BigEndian.AppendUint16(out, rtype)
	out = binary.BigEndian.AppendUint16(out, rclass)
	out = binary.BigEndian.AppendUint32(out, ttl)
	out = binary.BigEndian.AppendUint16(out, uint16(len(rdata)))
	out = append(out, rdata...)
	return EncodedRR{bytes: out}, nil
}

// BuildA renders an A record RDATA (4B IPv4; an IPv6/unparseable literal is
// a config error surfaced to the validator).
func BuildA(ip string) ([]byte, error) {
	v := net.ParseIP(ip)
	if v == nil || v.To4() == nil {
		return nil, fmt.Errorf("A rdata %q is not an IPv4 address", ip)
	}
	return v.To4(), nil
}

// BuildAAAA renders an AAAA record RDATA (16B IPv6).
func BuildAAAA(ip string) ([]byte, error) {
	v := net.ParseIP(ip)
	if v == nil || v.To16() == nil || v.To4() != nil {
		return nil, fmt.Errorf("AAAA rdata %q is not an IPv6 address", ip)
	}
	return v.To16(), nil
}

// BuildTXT renders TXT RDATA as character-strings (each ≤255 with a 1B
// length prefix, RFC 1035 §3.3.14).
func BuildTXT(strs []string) ([]byte, error) {
	var out []byte
	for _, s := range strs {
		if len(s) > 255 {
			return nil, fmt.Errorf("TXT string exceeds 255 bytes (got %d)", len(s))
		}
		out = append(out, byte(len(s)))
		out = append(out, s...)
	}
	return out, nil
}

// BuildSvcParam renders one SvcParam (RFC 9460 §2.2): 2B key + 2B len +
// value (value_hex decoded; empty value = zero-length).
func BuildSvcParam(key int, valueHex string) ([]byte, error) {
	if key < 0 || key > 65535 {
		return nil, fmt.Errorf("svc param key %d out of 16-bit range", key)
	}
	val, err := hex.DecodeString(strings.ToLower(valueHex))
	if err != nil {
		return nil, fmt.Errorf("svc param value_hex %q is not hex", valueHex)
	}
	out := binary.BigEndian.AppendUint16(nil, uint16(key))
	out = binary.BigEndian.AppendUint16(out, uint16(len(val)))
	return append(out, val...), nil
}

// Base64URL renders the GET dns parameter (RFC 4648 §5 alphabet, no padding
// — RFC 8484 §6 MUST NOT).
func Base64URL(wire []byte) string {
	return base64.RawURLEncoding.EncodeToString(wire)
}

// ---- HTTP frame builders (pinned header orders, design §3.1) ----

// HeaderSet is one ordered header list.
type headerList struct {
	names  []string
	values map[string]string
}

func newHeaderList(pairs ...[2]string) *headerList {
	h := &headerList{values: map[string]string{}}
	for _, p := range pairs {
		h.set(p[0], p[1])
	}
	return h
}

func (h *headerList) set(name, value string) {
	for _, n := range h.names {
		if strings.EqualFold(n, name) {
			h.values[n] = value
			return
		}
	}
	h.names = append(h.names, name)
	h.values[name] = value
}

// applyOverrides merges user headers: same-name (case-insensitive) values
// replace in place, "" removes the header, unknown names append in sorted
// order (deterministic output for map-typed overrides).
func (h *headerList) applyOverrides(overrides map[string]string) {
	if len(overrides) == 0 {
		return
	}
	// Pass 1: replace/remove existing.
	for _, n := range h.names {
		for k, v := range overrides {
			if strings.EqualFold(n, k) {
				h.values[n] = v
			}
		}
	}
	// Drop removed ("" value) entries.
	kept := h.names[:0]
	for _, n := range h.names {
		if h.values[n] != "" {
			kept = append(kept, n)
		} else {
			delete(h.values, n)
		}
	}
	h.names = kept
	// Pass 2: append new names, sorted.
	var extras []string
	for k := range overrides {
		if overrides[k] == "" {
			continue
		}
		found := false
		for _, n := range h.names {
			if strings.EqualFold(n, k) {
				found = true
				break
			}
		}
		if !found {
			extras = append(extras, k)
		}
	}
	sort.Strings(extras)
	for _, k := range extras {
		h.set(k, overrides[k])
	}
}

func (h *headerList) render() string {
	var b strings.Builder
	for _, n := range h.names {
		fmt.Fprintf(&b, "%s: %s\r\n", n, h.values[n])
	}
	return b.String()
}

// Get returns the current value of a header ("" when absent).
func (h *headerList) Get(name string) string {
	for _, n := range h.names {
		if strings.EqualFold(n, name) {
			return h.values[n]
		}
	}
	return ""
}

// BuildPOSTRequest renders the POST mapping (RFC 8484 §6: DNS wire used
// directly as the HTTP body, no encoding). Header order pinned: Host,
// Content-Type, Accept, Content-Length, Connection (+ sorted extras).
func BuildPOSTRequest(uri, host string, wire []byte, connection string, overrides map[string]string) []byte {
	h := newHeaderList(
		[2]string{"Host", host},
		[2]string{"Content-Type", MediaType},
		[2]string{"Accept", MediaType},
		[2]string{"Content-Length", strconv.Itoa(len(wire))},
		[2]string{"Connection", connection},
	)
	h.applyOverrides(overrides)
	var b strings.Builder
	fmt.Fprintf(&b, "POST %s HTTP/1.1\r\n", uri)
	b.WriteString(h.render())
	b.WriteString("\r\n")
	b.Write(wire)
	return []byte(b.String())
}

// BuildGETRequest renders the GET mapping (RFC 8484 §4.1 URI template
// /dns-query{?dns}; base64url no padding; no body, Content-Length: 0 — the
// design §3.1 pinned form). Header order: Host, Accept, Content-Length,
// Connection (+ sorted extras; no Content-Type — GET has no body).
func BuildGETRequest(path, host, b64, extraQuery, connection string, overrides map[string]string) []byte {
	uri := path + "?dns=" + b64
	if extraQuery != "" {
		uri += "&" + extraQuery
	}
	h := newHeaderList(
		[2]string{"Host", host},
		[2]string{"Accept", MediaType},
		[2]string{"Content-Length", "0"},
		[2]string{"Connection", connection},
	)
	h.applyOverrides(overrides)
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", uri)
	b.WriteString(h.render())
	b.WriteString("\r\n")
	return []byte(b.String())
}

// StatusText resolves the sanctioned status texts (200/400/404/415 + the
// generic 2xx/5xx spellings the fixtures may add).
func StatusText(code int) string {
	switch code {
	case 200:
		return "OK"
	case 400:
		return "Bad Request"
	case 404:
		return "Not Found"
	case 415:
		return "Unsupported Media Type"
	case 500:
		return "Internal Server Error"
	case 503:
		return "Service Unavailable"
	}
	return "OK"
}

// Build2xxResponse renders the 2xx response (status line + Content-Type +
// Content-Length + Cache-Control, design §3.1/§3.6; no Connection header).
func Build2xxResponse(status int, wire []byte, maxAge int64, overrides map[string]string) []byte {
	h := newHeaderList(
		[2]string{"Content-Type", MediaType},
		[2]string{"Content-Length", strconv.Itoa(len(wire))},
		[2]string{"Cache-Control", "max-age=" + strconv.FormatInt(maxAge, 10)},
	)
	h.applyOverrides(overrides)
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", status, StatusText(status))
	b.WriteString(h.render())
	b.WriteString("\r\n")
	b.Write(wire)
	return []byte(b.String())
}

// BuildErrorResponse renders the non-2xx shape (RFC 8484 §4.2.1 + design
// §3.1 pinned set: status line + Content-Length: 0 only — NO Content-Type,
// NO Cache-Control, no DNS wire).
func BuildErrorResponse(status int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", status, StatusText(status))
	return []byte(b.String())
}
