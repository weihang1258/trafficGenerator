package pcapparser

import (
	"bytes"
	"fmt"
	"strings"

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
	// Find the header/body boundary (blank line \r\n\r\n).
	end := bytes.Index(stream, []byte("\r\n\r\n"))
	if end < 0 {
		// No complete headers; parse what we have.
		end = len(stream)
	}
	headerBlock := stream[:end]
	res := &L7Result{Protocol: "http", Metadata: map[string]any{}, BodyOffset: 0, BodyLength: 0}
	if end+4 <= len(stream) {
		res.BodyOffset = end + 4
		res.BodyLength = len(stream) - res.BodyOffset
	}
	lines := strings.Split(string(headerBlock), "\r\n")
	if len(lines) == 0 {
		return res, nil
	}
	// Request line: METHOD SP URI SP VERSION, or status line: HTTP/... CODE MSG.
	first := lines[0]
	if strings.HasPrefix(first, "HTTP/") {
		// Response: status code + reason.
		parts := strings.SplitN(first, " ", 3)
		if len(parts) >= 2 {
			res.Metadata["status"] = parts[1]
		}
		if len(parts) >= 3 {
			res.Metadata["reason"] = parts[2]
		}
	} else {
		parts := strings.SplitN(first, " ", 3)
		if len(parts) >= 2 {
			res.Metadata["method"] = parts[0]
			res.Metadata["uri"] = parts[1]
		}
	}
	// Headers: Host is the common filter field.
	for _, line := range lines[1:] {
		if i := strings.IndexByte(line, ':'); i > 0 {
			key := strings.ToLower(strings.TrimSpace(line[:i]))
			val := strings.TrimSpace(line[i+1:])
			if key == "host" {
				res.Metadata["host"] = val
			}
		}
	}
	return res, nil
}

// dnsParser parses DNS messages (§14). DNS runs over UDP (one message per
// packet) and sometimes TCP (length-prefixed). It uses gopacket's layers.DNS
// decoder on the raw payload.
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

func (dnsParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "dns", Metadata: map[string]any{}}
	// Use gopacket's DNS decoder. DecodeFromBytes is called by NewPacket; here
	// we decode the payload directly.
	dns := parseDNS(stream)
	if dns == nil {
		return res, nil
	}
	if len(dns.Questions) > 0 {
		q := dns.Questions[0]
		res.Metadata["query_name"] = string(q.Name)
		res.Metadata["query_type"] = uint16(q.Type)
	}
	res.Metadata["rcode"] = uint8(dns.ResponseCode)
	return res, nil
}

// tlsParser parses TLS handshake metadata (§14): SNI from ClientHello, version,
// cipher suites. Record data is marked encrypted-opaque (not decrypted).
type tlsParser struct{}

func (tlsParser) Name() string { return "tls" }

func (tlsParser) CanParse(port uint16, sample []byte) bool {
	if port == 443 {
		return true
	}
	// TLS record: content type 0x16 (handshake) + version 0x03xx + length.
	return len(sample) >= 3 && sample[0] == 0x16 && sample[1] == 0x03
}

func (tlsParser) Parse(stream []byte) (*L7Result, error) {
	res := &L7Result{Protocol: "tls", Metadata: map[string]any{}}
	meta := extractTLSMetadata(stream)
	if meta.SNI != "" {
		res.Metadata["sni"] = meta.SNI
	}
	if meta.Version != "" {
		res.Metadata["version"] = meta.Version
	}
	if len(meta.CipherSuites) > 0 {
		// Store as hex strings for readability (e.g. "c02f").
		codes := make([]string, 0, len(meta.CipherSuites))
		for _, c := range meta.CipherSuites {
			codes = append(codes, fmt.Sprintf("%04x", c))
		}
		res.Metadata["cipher_suites"] = codes
	}
	if meta.CertChainLen > 0 {
		res.Metadata["cert_chain_length"] = meta.CertChainLen
	}
	return res, nil
}

// tlsMetadata holds the fields extracted from a TLS handshake stream.
type tlsMetadata struct {
	SNI            string
	Version        string // e.g. "TLS 1.2", "TLS 1.3"
	CipherSuites   []uint16
	CertChainLen   int // total bytes of the certificate chain (Certificate msg)
}

// extractTLSMetadata walks TLS records to extract SNI, version, cipher suites,
// and cert chain length (§6/§17.8). Best-effort: returns zero values for fields
// not present or unparseable.
func extractTLSMetadata(stream []byte) tlsMetadata {
	var meta tlsMetadata
	// Walk TLS records: type(1) version(2) length(2) body. A stream may carry
	// multiple records (ClientHello + Certificate + ...).
	off := 0
	for off+5 <= len(stream) {
		recType := stream[off]
		recLen := int(stream[off+3])<<8 | int(stream[off+4])
		body := stream[off+5:]
		if recLen > len(body) {
			recLen = len(body) // truncated record
		}
		if recType == 0x16 { // handshake
			parseTLSHandshake(body[:recLen], &meta)
		}
		off += 5 + recLen
	}
	return meta
}

// parseTLSHandshake walks handshake messages within a TLS record body, filling
// SNI/version/cipher (from ClientHello) and cert chain length (from Certificate).
func parseTLSHandshake(body []byte, meta *tlsMetadata) {
	p := 0
	for p+4 <= len(body) {
		hsType := body[p]
		hsLen := int(body[p+1])<<16 | int(body[p+2])<<8 | int(body[p+3])
		msg := body[p+4:]
		if hsLen > len(msg) {
			hsLen = len(msg)
		}
		switch hsType {
		case 0x01: // ClientHello
			parseClientHello(msg[:hsLen], meta)
		case 0x0B: // Certificate
			parseCertificate(msg[:hsLen], meta)
		}
		p += 4 + hsLen
	}
}

// parseClientHello extracts version, cipher suites, and SNI from a ClientHello.
func parseClientHello(hs []byte, meta *tlsMetadata) {
	// hs: version(2) random(32) session_id(1+n) cipher_suites(2+n) compression(1+n) extensions(2+n)
	if len(hs) < 2+32+1 {
		return
	}
	p := 0
	// Version (handshake-level; for TLS 1.3 this is still 0x0303).
	hv := uint16(hs[0])<<8 | uint16(hs[1])
	meta.Version = tlsVersionString(hv)
	p = 2 + 32 // skip version + random
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
	// Cipher suites: 2 bytes each.
	for i := 0; i+1 < csLen; i += 2 {
		meta.CipherSuites = append(meta.CipherSuites, uint16(hs[p+i])<<8|uint16(hs[p+i+1]))
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
	extEnd := p + extLen
	if extEnd > len(hs) {
		extEnd = len(hs)
	}
	// Walk extensions; SNI = 0x0000, supported_versions = 0x002b (TLS 1.3).
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
					meta.SNI = string(d[5 : 5+nameLen])
				}
			}
		case 0x002b: // supported_versions (TLS 1.3)
			d := hs[p:]
			if len(d) >= 3 {
				listLen := int(d[0])
				// List of 2-byte versions; the first is the highest supported.
				if listLen >= 2 && len(d) >= 3 {
					v := uint16(d[1])<<8 | uint16(d[2])
					if v == 0x0304 {
						meta.Version = "TLS 1.3"
					}
				}
			}
		}
		p += extDataLen
	}
}

// parseCertificate extracts the total certificate chain length from a Certificate
// handshake message (server side). Format: cert_list_len(3) then each cert:
// cert_len(3) + cert bytes.
func parseCertificate(hs []byte, meta *tlsMetadata) {
	if len(hs) < 3 {
		return
	}
	listLen := int(hs[0])<<16 | int(hs[1])<<8 | int(hs[2])
	if listLen > len(hs)-3 {
		listLen = len(hs) - 3
	}
	meta.CertChainLen = listLen
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

// extractTLSSNI walks a TLS ClientHello to find the SNI extension. Best-effort:
// returns "" if not found or the record isn't a ClientHello.
//
// Deprecated: use extractTLSMetadata (which also extracts version/cipher/cert).
// Kept for backward compatibility with tests that call it directly.
func extractTLSSNI(stream []byte) string {
	return extractTLSMetadata(stream).SNI
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
