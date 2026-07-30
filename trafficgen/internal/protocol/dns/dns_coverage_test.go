package dns

// Spec-driven coverage tests for the DNS coverage expansion. Each test is
// derived from a specific RFC clause (cited inline) and asserts observable
// wire bytes, not just "no error". Failing-first: these were written before
// the features existed and exercise the new multi-RR / multi-question /
// rcode / TCP / new-RR-type paths added to dns.go and types.go.
//
// Reference: RFC 1034/1035 (DNS), RFC 2782 (SRV), RFC 3401 (NAPTR),
// RFC 3596 (AAAA), RFC 4034 (DS/DNSKEY), RFC 6891 (EDNS0).

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- DNS wire parser helpers (test-only) ---

// parsedHeader holds the decoded 12-byte DNS header (RFC 1035 §4.1.1).
type parsedHeader struct {
	txid                                                            uint16
	flags                                                           uint16
	qr, opcode, aa, tc, rd, ra, z, rcode                            int
	qd, an, ns, ar                                                  uint16
}

func parseHeader(b []byte) parsedHeader {
	var h parsedHeader
	h.txid = binary.BigEndian.Uint16(b[0:2])
	h.flags = binary.BigEndian.Uint16(b[2:4])
	h.qr = int(h.flags >> 15 & 1)
	h.opcode = int(h.flags >> 11 & 0xF)
	h.aa = int(h.flags >> 10 & 1)
	h.tc = int(h.flags >> 9 & 1)
	h.rd = int(h.flags >> 8 & 1)
	h.ra = int(h.flags >> 7 & 1)
	h.z = int(h.flags >> 6 & 1)
	h.rcode = int(h.flags & 0xF)
	h.qd = binary.BigEndian.Uint16(b[4:6])
	h.an = binary.BigEndian.Uint16(b[6:8])
	h.ns = binary.BigEndian.Uint16(b[8:10])
	h.ar = binary.BigEndian.Uint16(b[10:12])
	return h
}

// skipName skips a (possibly compressed) DNS name starting at off and
// returns the offset just past the name (RFC 1035 §4.1.4).
func skipName(b []byte, off int) int {
	for off < len(b) {
		ln := int(b[off])
		if ln == 0 {
			return off + 1
		}
		if ln&0xC0 == 0xC0 {
			return off + 2 // compression pointer ends the name
		}
		off += 1 + ln
	}
	return off
}

// parsedRR holds a decoded resource record (name skipped).
type parsedRR struct {
	nameEnd int
	rtype   uint16
	rclass  uint16
	ttl     uint32
	rdlen   uint16
	rdata   []byte
	// dataEnd is the offset just past this RR's RDATA.
	dataEnd int
}

func parseRR(b []byte, off int) parsedRR {
	var rr parsedRR
	rr.nameEnd = skipName(b, off)
	rr.rtype = binary.BigEndian.Uint16(b[rr.nameEnd : rr.nameEnd+2])
	rr.rclass = binary.BigEndian.Uint16(b[rr.nameEnd+2 : rr.nameEnd+4])
	rr.ttl = binary.BigEndian.Uint32(b[rr.nameEnd+4 : rr.nameEnd+8])
	rr.rdlen = binary.BigEndian.Uint16(b[rr.nameEnd+8 : rr.nameEnd+10])
	start := rr.nameEnd + 10
	rr.rdata = b[start : start+int(rr.rdlen)]
	rr.dataEnd = start + int(rr.rdlen)
	return rr
}

// parsedQuestion holds a decoded question (QNAME skipped).
type parsedQuestion struct {
	nameEnd int
	qtype   uint16
	qclass  uint16
}

func parseQuestion(b []byte, off int) parsedQuestion {
	var q parsedQuestion
	q.nameEnd = skipName(b, off)
	q.qtype = binary.BigEndian.Uint16(b[q.nameEnd : q.nameEnd+2])
	q.qclass = binary.BigEndian.Uint16(b[q.nameEnd+2 : q.nameEnd+4])
	return q
}

// decodeName decodes a (possibly compressed) DNS name starting at off and
// returns the decoded dotted name and the offset just past the name in the
// ORIGINAL byte stream (for a compressed name, 2 bytes past the pointer).
func decodeName(b []byte, off int) (string, int) {
	var labels []string
	var end int
	jumped := false
	for off < len(b) {
		ln := int(b[off])
		if ln == 0 {
			if !jumped {
				end = off + 1
			}
			break
		}
		if ln&0xC0 == 0xC0 {
			if !jumped {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(b[off:off+2]) & 0x3FFF)
			jumped = true
			continue
		}
		off++
		labels = append(labels, string(b[off:off+ln]))
		off += ln
	}
	return strings.Join(labels, "."), end
}

// =====================================================================
// New RR types (RFC 1035 §3.3, RFC 2782, RFC 3401, RFC 4034)
// =====================================================================

// RFC 1035 §3.3.12 (PTR): RDATA is a domain name. A reverse lookup query
// uses the in-addr.arpa name and QTYPE=PTR; the response carries the
// canonical hostname as RDATA.
func TestCoverage_PTR_ReverseLookup(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "1.0.168.192.in-addr.arpa",
		QueryType:  TypePTR,
		IsResponse: true,
		Answers: []core.DNSRR{{
			Name:   "1.0.168.192.in-addr.arpa",
			Type:   TypePTR,
			Target: "host.example.com",
		}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2 (query+response)", len(cfgs))
	}

	// Query: QTYPE must be PTR (12).
	q := cfgs[0].Payload
	qh := parseHeader(q)
	if qh.qd != 1 || qh.an != 0 {
		t.Errorf("query counts: qd=%d an=%d, want qd=1 an=0", qh.qd, qh.an)
	}
	qq := parseQuestion(q, 12)
	if qq.qtype != TypePTR {
		t.Errorf("query qtype=%d, want %d (PTR)", qq.qtype, TypePTR)
	}
	name, _ := decodeName(q, 12)
	if name != "1.0.168.192.in-addr.arpa" {
		t.Errorf("query qname=%q, want in-addr.arpa name", name)
	}

	// Response: one PTR RR whose RDATA is the encoded target domain.
	r := cfgs[1].Payload
	rh := parseHeader(r)
	if rh.an != 1 {
		t.Fatalf("response ancount=%d, want 1", rh.an)
	}
	// Walk: header(12) + question + first answer.
	off := 12
	pq := parseQuestion(r, off)
	off = pq.nameEnd + 4
	rr := parseRR(r, off)
	if rr.rtype != TypePTR {
		t.Errorf("answer rtype=%d, want %d (PTR)", rr.rtype, TypePTR)
	}
	target, _ := decodeName(rr.rdata, 0)
	if target != "host.example.com" {
		t.Errorf("PTR rdata=%q, want host.example.com", target)
	}
}

// RFC 2782 (SRV): RDATA = Priority(2) + Weight(2) + Port(2) + Target.
func TestCoverage_SRV_Response(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "_sip._tcp.example.com",
		QueryType:  TypeSRV,
		IsResponse: true,
		Answers: []core.DNSRR{{
			Name:     "_sip._tcp.example.com",
			Type:     TypeSRV,
			Priority: 10,
			Weight:   20,
			Port:     5060,
			Target:   "sipserver.example.com",
		}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	r := cfgs[1].Payload
	rh := parseHeader(r)
	if rh.an != 1 {
		t.Fatalf("ancount=%d, want 1", rh.an)
	}
	off := 12
	pq := parseQuestion(r, off)
	off = pq.nameEnd + 4
	rr := parseRR(r, off)
	if rr.rtype != TypeSRV {
		t.Fatalf("rtype=%d, want %d (SRV)", rr.rtype, TypeSRV)
	}
	if got := binary.BigEndian.Uint16(rr.rdata[0:2]); got != 10 {
		t.Errorf("priority=%d, want 10", got)
	}
	if got := binary.BigEndian.Uint16(rr.rdata[2:4]); got != 20 {
		t.Errorf("weight=%d, want 20", got)
	}
	if got := binary.BigEndian.Uint16(rr.rdata[4:6]); got != 5060 {
		t.Errorf("port=%d, want 5060", got)
	}
	target, _ := decodeName(rr.rdata, 6)
	if target != "sipserver.example.com" {
		t.Errorf("srv target=%q, want sipserver.example.com", target)
	}
}

// RFC 1035 §3.3.13 (SOA): RDATA = MNAME + RNAME + SERIAL + REFRESH + RETRY
// + EXPIRE + MINIMUM (5 x 32-bit).
func TestCoverage_SOA_Response(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeSOA,
		IsResponse: true,
		Answers: []core.DNSRR{{
			Name:    "example.com",
			Type:    TypeSOA,
			MName:   "ns1.example.com",
			RName:   "admin.example.com",
			Serial:  2026010101,
			Refresh: 3600,
			Retry:   900,
			Expire:  604800,
			Minimum: 86400,
		}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	r := cfgs[1].Payload
	rh := parseHeader(r)
	if rh.an != 1 {
		t.Fatalf("ancount=%d, want 1", rh.an)
	}
	off := 12
	pq := parseQuestion(r, off)
	off = pq.nameEnd + 4
	rr := parseRR(r, off)
	if rr.rtype != TypeSOA {
		t.Fatalf("rtype=%d, want %d (SOA)", rr.rtype, TypeSOA)
	}
	mname, n := decodeName(rr.rdata, 0)
	if mname != "ns1.example.com" {
		t.Errorf("mname=%q, want ns1.example.com", mname)
	}
	rname, n2 := decodeName(rr.rdata, n)
	if rname != "admin.example.com" {
		t.Errorf("rname=%q, want admin.example.com", rname)
	}
	tail := rr.rdata[n2:]
	if len(tail) != 20 {
		t.Fatalf("SOA tail len=%d, want 20 (5x uint32)", len(tail))
	}
	if got := binary.BigEndian.Uint32(tail[0:4]); got != 2026010101 {
		t.Errorf("serial=%d, want 2026010101", got)
	}
	if got := binary.BigEndian.Uint32(tail[4:8]); got != 3600 {
		t.Errorf("refresh=%d, want 3600", got)
	}
	if got := binary.BigEndian.Uint32(tail[8:12]); got != 900 {
		t.Errorf("retry=%d, want 900", got)
	}
	if got := binary.BigEndian.Uint32(tail[12:16]); got != 604800 {
		t.Errorf("expire=%d, want 604800", got)
	}
	if got := binary.BigEndian.Uint32(tail[16:20]); got != 86400 {
		t.Errorf("minimum=%d, want 86400", got)
	}
}

// RFC 1035 §3.3.11 (NS): RDATA is a domain name (the nameserver).
func TestCoverage_NS_Response(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeNS,
		IsResponse: true,
		Answers: []core.DNSRR{{
			Name:   "example.com",
			Type:   TypeNS,
			Target: "ns1.example.com",
		}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	r := cfgs[1].Payload
	off := 12
	pq := parseQuestion(r, off)
	off = pq.nameEnd + 4
	rr := parseRR(r, off)
	if rr.rtype != TypeNS {
		t.Fatalf("rtype=%d, want %d (NS)", rr.rtype, TypeNS)
	}
	ns, _ := decodeName(rr.rdata, 0)
	if ns != "ns1.example.com" {
		t.Errorf("NS rdata=%q, want ns1.example.com", ns)
	}
}

// RFC 4034 §5 (DS): RDATA = KeyTag(2) + Algorithm(1) + DigestType(1) + Digest.
func TestCoverage_DS_Response(t *testing.T) {
	p := NewPlanner()
	digestHex := "AABBCCDDEE" // 5 bytes
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeDS,
		IsResponse: true,
		Answers: []core.DNSRR{{
			Name:       "example.com",
			Type:       TypeDS,
			KeyTag:     12345,
			Algorithm:  8, // RSASHA256
			DigestType: 2, // SHA-256
			Digest:     digestHex,
		}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	r := cfgs[1].Payload
	off := 12
	pq := parseQuestion(r, off)
	off = pq.nameEnd + 4
	rr := parseRR(r, off)
	if rr.rtype != TypeDS {
		t.Fatalf("rtype=%d, want %d (DS)", rr.rtype, TypeDS)
	}
	if got := binary.BigEndian.Uint16(rr.rdata[0:2]); got != 12345 {
		t.Errorf("keytag=%d, want 12345", got)
	}
	if rr.rdata[2] != 8 {
		t.Errorf("algorithm=%d, want 8", rr.rdata[2])
	}
	if rr.rdata[3] != 2 {
		t.Errorf("digesttype=%d, want 2", rr.rdata[3])
	}
	wantDigest := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	if string(rr.rdata[4:]) != string(wantDigest) {
		t.Errorf("digest=%v, want %v", rr.rdata[4:], wantDigest)
	}
}

// RFC 4034 §2 (DNSKEY): RDATA = Flags(2) + Protocol(1) + Algorithm(1) + PublicKey.
func TestCoverage_DNSKEY_Response(t *testing.T) {
	p := NewPlanner()
	// A small base64 public key ("AQAB" = bytes 01 00 01).
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeDNSKEY,
		IsResponse: true,
		Answers: []core.DNSRR{{
			Name:      "example.com",
			Type:      TypeDNSKEY,
			KeyFlags:  256, // ZSK
			Protocol:  3,   // DNSSEC
			Algorithm: 8,   // RSASHA256
			PublicKey: "AQAB",
		}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	r := cfgs[1].Payload
	off := 12
	pq := parseQuestion(r, off)
	off = pq.nameEnd + 4
	rr := parseRR(r, off)
	if rr.rtype != TypeDNSKEY {
		t.Fatalf("rtype=%d, want %d (DNSKEY)", rr.rtype, TypeDNSKEY)
	}
	if got := binary.BigEndian.Uint16(rr.rdata[0:2]); got != 256 {
		t.Errorf("flags=%d, want 256", got)
	}
	if rr.rdata[2] != 3 {
		t.Errorf("protocol=%d, want 3", rr.rdata[2])
	}
	if rr.rdata[3] != 8 {
		t.Errorf("algorithm=%d, want 8", rr.rdata[3])
	}
	wantPub := []byte{0x01, 0x00, 0x01}
	if string(rr.rdata[4:]) != string(wantPub) {
		t.Errorf("publickey=%v, want %v", rr.rdata[4:], wantPub)
	}
}

// RFC 3401 §4.1 (NAPTR): RDATA = Order(2) + Preference(2) + Flags +
// Service + Regexp + Replacement.
func TestCoverage_NAPTR_Response(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeNAPTR,
		IsResponse: true,
		Answers: []core.DNSRR{{
			Name:      "example.com",
			Type:      TypeNAPTR,
			Order:     100,
			Preference: 50,
			Flags:     "S",
			Service:   "sip+E2U",
			Regexp:    "!^.*$!sip:info@example.com!",
			Target:    "_sip._tcp.example.com",
		}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	r := cfgs[1].Payload
	off := 12
	pq := parseQuestion(r, off)
	off = pq.nameEnd + 4
	rr := parseRR(r, off)
	if rr.rtype != TypeNAPTR {
		t.Fatalf("rtype=%d, want %d (NAPTR)", rr.rtype, TypeNAPTR)
	}
	if got := binary.BigEndian.Uint16(rr.rdata[0:2]); got != 100 {
		t.Errorf("order=%d, want 100", got)
	}
	if got := binary.BigEndian.Uint16(rr.rdata[2:4]); got != 50 {
		t.Errorf("preference=%d, want 50", got)
	}
	pos := 4
	// Flags: length-prefixed
	if rr.rdata[pos] != 1 || string(rr.rdata[pos+1:pos+2]) != "S" {
		t.Errorf("flags=%v, want [01 'S']", rr.rdata[pos:pos+2])
	}
	pos += 1 + int(rr.rdata[pos])
	if rr.rdata[pos] != byte(len("sip+E2U")) || string(rr.rdata[pos+1:pos+1+7]) != "sip+E2U" {
		t.Errorf("service mismatch: %v", rr.rdata[pos:pos+8])
	}
	pos += 1 + int(rr.rdata[pos])
	regexpLen := int(rr.rdata[pos])
	if string(rr.rdata[pos+1:pos+1+regexpLen]) != "!^.*$!sip:info@example.com!" {
		t.Errorf("regexp mismatch: %q", string(rr.rdata[pos+1:pos+1+regexpLen]))
	}
	pos += 1 + regexpLen
	repl, _ := decodeName(rr.rdata, pos)
	if repl != "_sip._tcp.example.com" {
		t.Errorf("replacement=%q, want _sip._tcp.example.com", repl)
	}
}

// =====================================================================
// Multi-RR responses (RFC 1035 §4.1.2)
// =====================================================================

// RFC 1035 §4.1.2: ANCOUNT may be > 1. A response may carry several A
// records for the same name (round-robin / multi-homed host).
func TestCoverage_MultiRR_MultipleARecords(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "www.example.com",
		QueryType:  TypeA,
		IsResponse: true,
		Answers: []core.DNSRR{
			{Name: "www.example.com", Type: TypeA, IP: "93.184.216.34"},
			{Name: "www.example.com", Type: TypeA, IP: "93.184.216.35"},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	r := cfgs[1].Payload
	rh := parseHeader(r)
	if rh.an != 2 {
		t.Fatalf("ancount=%d, want 2", rh.an)
	}
	off := 12
	pq := parseQuestion(r, off)
	off = pq.nameEnd + 4
	rr1 := parseRR(r, off)
	rr2 := parseRR(r, rr1.dataEnd)
	if rr1.rtype != TypeA || rr2.rtype != TypeA {
		t.Errorf("rtypes=%d,%d, want A,A", rr1.rtype, rr2.rtype)
	}
	want1 := []byte{93, 184, 216, 34}
	want2 := []byte{93, 184, 216, 35}
	if string(rr1.rdata) != string(want1) {
		t.Errorf("rr1 rdata=%v, want %v", rr1.rdata, want1)
	}
	if string(rr2.rdata) != string(want2) {
		t.Errorf("rr2 rdata=%v, want %v", rr2.rdata, want2)
	}
}

// RFC 1035 §3.3.1 (CNAME): a CNAME chain response carries a CNAME RR
// followed by an A RR for the canonical name. The resolver follows the
// chain: www.example.com -> example.com -> 93.184.216.34.
func TestCoverage_CNAME_Chain(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "www.example.com",
		QueryType:  TypeA,
		IsResponse: true,
		Answers: []core.DNSRR{
			{Name: "www.example.com", Type: TypeCNAME, Target: "example.com"},
			{Name: "example.com", Type: TypeA, IP: "93.184.216.34"},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	r := cfgs[1].Payload
	rh := parseHeader(r)
	if rh.an != 2 {
		t.Fatalf("ancount=%d, want 2", rh.an)
	}
	off := 12
	pq := parseQuestion(r, off)
	off = pq.nameEnd + 4
	rr1 := parseRR(r, off)
	rr2 := parseRR(r, rr1.dataEnd)
	// First answer MUST be CNAME (type 5), second MUST be A (type 1).
	if rr1.rtype != TypeCNAME {
		t.Errorf("first answer rtype=%d, want %d (CNAME)", rr1.rtype, TypeCNAME)
	}
	cname, _ := decodeName(rr1.rdata, 0)
	if cname != "example.com" {
		t.Errorf("CNAME target=%q, want example.com", cname)
	}
	if rr2.rtype != TypeA {
		t.Errorf("second answer rtype=%d, want %d (A)", rr2.rtype, TypeA)
	}
	want := []byte{93, 184, 216, 34}
	if string(rr2.rdata) != string(want) {
		t.Errorf("A rdata=%v, want %v", rr2.rdata, want)
	}
}

// =====================================================================
// RCODE / negative responses (RFC 1035 §4.1.1, §6.2.5)
// =====================================================================

// RFC 1035 §6.2.5: a negative (NXDOMAIN) response carries RCODE=3 and
// typically a SOA RR in the Authority section for negative caching.
func TestCoverage_NXDOMAIN_WithSOA_Authority(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "nonexistent.example.com",
		QueryType:  TypeA,
		IsResponse: true,
		RCode:      RcodeNXDomain,
		Authority: []core.DNSRR{{
			Name:    "example.com",
			Type:    TypeSOA,
			MName:   "ns1.example.com",
			RName:   "admin.example.com",
			Serial:  2026010101,
			Minimum: 3600,
		}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	r := cfgs[1].Payload
	rh := parseHeader(r)
	if rh.rcode != RcodeNXDomain {
		t.Errorf("rcode=%d, want %d (NXDOMAIN)", rh.rcode, RcodeNXDomain)
	}
	if rh.an != 0 {
		t.Errorf("ancount=%d, want 0 (NXDOMAIN has no answers)", rh.an)
	}
	if rh.ns != 1 {
		t.Fatalf("nscount=%d, want 1 (SOA in authority)", rh.ns)
	}
	// Walk to the authority SOA: header + question + (no answers).
	off := 12
	pq := parseQuestion(r, off)
	off = pq.nameEnd + 4
	rr := parseRR(r, off)
	if rr.rtype != TypeSOA {
		t.Errorf("authority rtype=%d, want %d (SOA)", rr.rtype, TypeSOA)
	}
}

// RFC 1035 §4.1.1: RCODE occupies the low 4 bits. A bare NXDOMAIN with no
// authority section is valid (no negative caching).
func TestCoverage_NXDOMAIN_NoAuthority(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "no.example.com",
		QueryType:  TypeA,
		IsResponse: true,
		RCode:      RcodeNXDomain,
	}
	cfgs := drain(mustPlan(t, p, spec))
	r := cfgs[1].Payload
	rh := parseHeader(r)
	if rh.rcode != RcodeNXDomain {
		t.Errorf("rcode=%d, want %d", rh.rcode, RcodeNXDomain)
	}
	if rh.an != 0 || rh.ns != 0 {
		t.Errorf("counts an=%d ns=%d, want 0,0", rh.an, rh.ns)
	}
	// QR must be 1 (response) and the question echoed.
	if rh.qr != 1 {
		t.Errorf("qr=%d, want 1", rh.qr)
	}
	if rh.qd != 1 {
		t.Errorf("qd=%d, want 1 (question echoed)", rh.qd)
	}
}

// RFC 1035 §4.1.1: SERVFAIL is rcode 2.
func TestCoverage_SERVFAIL_RCode(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "fail.example.com",
		QueryType:  TypeA,
		IsResponse: true,
		RCode:      RcodeServFail,
	}
	cfgs := drain(mustPlan(t, p, spec))
	r := cfgs[1].Payload
	rh := parseHeader(r)
	if rh.rcode != RcodeServFail {
		t.Errorf("rcode=%d, want %d (SERVFAIL)", rh.rcode, RcodeServFail)
	}
}

// RFC 6891 §7: a server MAY echo an OPT RR in the response. The general
// response path emits an OPT in the Additional section when EDNS0Enabled.
// The DO bit (bit 15 of the OPT TTL) must be set when DnssecOK is true.
func TestCoverage_EDNS0_ResponseOPT_DOBit(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:       "example.com",
		QueryType:    TypeA,
		IsResponse:   true,
		EDNS0Enabled: true,
		DnssecOK:     true,
		Answers: []core.DNSRR{{Name: "example.com", Type: TypeA, IP: "1.2.3.4"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	r := cfgs[1].Payload
	rh := parseHeader(r)
	if rh.ar != 1 {
		t.Fatalf("arcount=%d, want 1 (EDNS0 OPT in response)", rh.ar)
	}
	// Walk past question + 1 answer to reach the Additional section.
	off := 12
	pq := parseQuestion(r, off)
	off = pq.nameEnd + 4
	rr := parseRR(r, off)
	off = rr.dataEnd
	opt := parseRR(r, off)
	if opt.rtype != TypeOPT {
		t.Fatalf("additional rtype=%d, want %d (OPT)", opt.rtype, TypeOPT)
	}
	// DO bit is bit 15 of the 4-byte TTL -> high bit of TTL byte index 2.
	doByte := (opt.ttl >> 8) & 0xFF
	if doByte&0x80 != 0x80 {
		t.Errorf("OPT DO bit not set: ttl=0x%08x (byte2=0x%02x, want 0x80)", opt.ttl, doByte)
	}
}

// =====================================================================
// DNS over TCP (RFC 1035 §4.2.2 / RFC 7766)
// =====================================================================

// RFC 1035 §4.2.2: "The message is prefixed with a two byte length field
// which gives the message length." DNS-over-TCP rides on TCP (L4 protocol
// = tcp). This test asserts both the 2-byte prefix and the L4 protocol.
func TestCoverage_DNSOverTCP_LengthPrefixAndTransport(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:    "example.com",
		QueryType: TypeA,
		Transport: "tcp",
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 1 {
		t.Fatalf("len=%d, want 1 (query only)", len(cfgs))
	}
	q := cfgs[0]
	// L4 must be TCP, not UDP.
	if q.L4.Protocol != "tcp" {
		t.Errorf("L4.Protocol=%q, want tcp", q.L4.Protocol)
	}
	if q.L3.Protocol != 6 {
		t.Errorf("L3.Protocol=%d, want 6 (TCP)", q.L3.Protocol)
	}
	// The first 2 bytes are the length prefix; the rest is the DNS message.
	if len(q.Payload) < 2 {
		t.Fatal("payload too short for TCP length prefix")
	}
	prefix := binary.BigEndian.Uint16(q.Payload[0:2])
	msg := q.Payload[2:]
	if int(prefix) != len(msg) {
		t.Errorf("TCP length prefix=%d, but message is %d bytes", prefix, len(msg))
	}
	// The DNS message itself must still be a valid query: TxID 0x1234, qr=0.
	h := parseHeader(msg)
	if h.txid != 0x1234 {
		t.Errorf("msg txid=0x%04x, want 0x1234", h.txid)
	}
	if h.qr != 0 {
		t.Errorf("msg qr=%d, want 0 (query)", h.qr)
	}
}

// RFC 1035 §4.2.2: the TCP length prefix applies to the response too.
func TestCoverage_DNSOverTCP_ResponsePrefixed(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeA,
		IsResponse: true,
		ResponseIP: "93.184.216.34",
		Transport:  "tcp",
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2", len(cfgs))
	}
	for i, c := range cfgs {
		prefix := binary.BigEndian.Uint16(c.Payload[0:2])
		msg := c.Payload[2:]
		if int(prefix) != len(msg) {
			t.Errorf("packet[%d] TCP prefix=%d != msg len %d", i, prefix, len(msg))
		}
		if c.L4.Protocol != "tcp" {
			t.Errorf("packet[%d] L4=%q, want tcp", i, c.L4.Protocol)
		}
	}
}

// =====================================================================
// Multiple questions (RFC 1035 §4.1.2)
// =====================================================================

// RFC 1035 §4.1.2: QDCOUNT may be > 1 (multiple questions in one message).
// Rare but valid. The response MUST echo all questions.
func TestCoverage_MultiQuestion(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		IsResponse: true,
		Questions: []core.DNSQuestion{
			{Name: "a.example.com", Type: TypeA},
			{Name: "b.example.com", Type: TypeAAAA},
		},
		Answers: []core.DNSRR{
			{Name: "a.example.com", Type: TypeA, IP: "1.1.1.1"},
			{Name: "b.example.com", Type: TypeAAAA, IP: "::1"},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	q := cfgs[0].Payload
	qh := parseHeader(q)
	if qh.qd != 2 {
		t.Fatalf("query qdcount=%d, want 2", qh.qd)
	}
	// Decode both questions.
	off := 12
	pq1 := parseQuestion(q, off)
	n1, _ := decodeName(q, 12)
	if n1 != "a.example.com" || pq1.qtype != TypeA {
		t.Errorf("q1 name=%q type=%d, want a.example.com/A", n1, pq1.qtype)
	}
	pq2 := parseQuestion(q, pq1.nameEnd+4)
	n2, _ := decodeName(q, pq1.nameEnd+4)
	if n2 != "b.example.com" || pq2.qtype != TypeAAAA {
		t.Errorf("q2 name=%q type=%d, want b.example.com/AAAA", n2, pq2.qtype)
	}
	// Response must echo both questions and carry 2 answers.
	r := cfgs[1].Payload
	rh := parseHeader(r)
	if rh.qd != 2 {
		t.Errorf("response qdcount=%d, want 2 (echo)", rh.qd)
	}
	if rh.an != 2 {
		t.Errorf("response ancount=%d, want 2", rh.an)
	}
}

// =====================================================================
// RD/RA flags (RFC 1035 §4.1.1)
// =====================================================================

// RFC 1035 §4.1.1: RD (Recursion Desired, bit 8) is set by the querier;
// RA (Recursion Available, bit 7) is set by the server in the response.
// The synthetic response is authoritative/recursive, so RA MUST be 1.
func TestCoverage_RD_RA_Flags(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeA,
		IsResponse: true,
		ResponseIP: "1.2.3.4",
	}
	cfgs := drain(mustPlan(t, p, spec))
	qh := parseHeader(cfgs[0].Payload)
	if qh.rd != 1 {
		t.Errorf("query RD=%d, want 1 (recursion desired)", qh.rd)
	}
	if qh.ra != 0 {
		t.Errorf("query RA=%d, want 0 (RA is a response-only bit)", qh.ra)
	}
	rh := parseHeader(cfgs[1].Payload)
	if rh.rd != 1 {
		t.Errorf("response RD=%d, want 1 (echoed from query)", rh.rd)
	}
	if rh.ra != 1 {
		t.Errorf("response RA=%d, want 1 (recursion available)", rh.ra)
	}
}

// =====================================================================
// TTL configurability + backward compatibility
// =====================================================================

// The answer TTL must be configurable via DNSConfig.TTL (default 300).
func TestCoverage_TTL_Configurable(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeA,
		IsResponse: true,
		TTL:        7200,
		Answers: []core.DNSRR{{
			Name: "example.com",
			Type: TypeA,
			IP:   "1.2.3.4",
		}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	r := cfgs[1].Payload
	off := 12
	pq := parseQuestion(r, off)
	off = pq.nameEnd + 4
	rr := parseRR(r, off)
	if rr.ttl != 7200 {
		t.Errorf("answer TTL=%d, want 7200", rr.ttl)
	}
}

// Per-RR TTL takes precedence over DNSConfig.TTL.
func TestCoverage_TTL_PerRROverridesConfig(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeA,
		IsResponse: true,
		TTL:        7200,
		Answers: []core.DNSRR{{
			Name: "example.com",
			Type: TypeA,
			IP:   "1.2.3.4",
			TTL:  60,
		}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	r := cfgs[1].Payload
	off := 12
	pq := parseQuestion(r, off)
	off = pq.nameEnd + 4
	rr := parseRR(r, off)
	if rr.ttl != 60 {
		t.Errorf("answer TTL=%d, want 60 (per-RR overrides config 7200)", rr.ttl)
	}
}

// Backward compatibility: when no Answers/Authority/Questions/RCode are
// set, the legacy single-RR path is used (ResponseIP). The response has
// exactly one answer with TTL 300 and the configured IPv4 RDATA.
func TestCoverage_BackwardCompat_LegacySingleRR(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeA,
		IsResponse: true,
		ResponseIP: "93.184.216.34",
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("len=%d, want 2", len(cfgs))
	}
	r := cfgs[1].Payload
	rh := parseHeader(r)
	if rh.an != 1 {
		t.Fatalf("ancount=%d, want 1 (legacy single RR)", rh.an)
	}
	off := 12
	pq := parseQuestion(r, off)
	off = pq.nameEnd + 4
	rr := parseRR(r, off)
	if rr.ttl != 300 {
		t.Errorf("legacy TTL=%d, want 300 (default)", rr.ttl)
	}
	want := []byte{93, 184, 216, 34}
	if string(rr.rdata) != string(want) {
		t.Errorf("legacy rdata=%v, want %v", rr.rdata, want)
	}
}

// TxID echo must still hold on the general response path.
func TestCoverage_TxIDEcho_GeneralPath(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeA,
		IsResponse: true,
		TxID:       0xCAFE,
		Answers: []core.DNSRR{{Name: "example.com", Type: TypeA, IP: "1.2.3.4"}},
	}
	cfgs := drain(mustPlan(t, p, spec))
	qh := parseHeader(cfgs[0].Payload)
	rh := parseHeader(cfgs[1].Payload)
	if qh.txid != 0xCAFE || rh.txid != 0xCAFE {
		t.Errorf("txid: query=0x%04x response=0x%04x, want CAFE/CAFE", qh.txid, rh.txid)
	}
}

// =====================================================================
// Validate negative paths (CLAUDE.md testing policy §2)
// =====================================================================

func TestValidate_RejectsBadTransport(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS.Transport = "sctp"
	if err := p.Validate(spec); err == nil {
		t.Error("Validate accepted transport=sctp; want error")
	}
}

func TestValidate_RejectsRCodeTooLarge(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS.RCode = 16
	if err := p.Validate(spec); err == nil {
		t.Error("Validate accepted rcode=16; want error (>15 exceeds 4-bit field)")
	}
}

func TestValidate_RejectsEmptyQuestionName(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS.Domain = "" // would normally fail, but Questions overrides
	spec.DNS.Questions = []core.DNSQuestion{{Name: "", Type: TypeA}}
	if err := p.Validate(spec); err == nil {
		t.Error("Validate accepted question with empty name; want error")
	}
}

func TestValidate_RejectsAnswerAFamilyMismatch(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeA,
		IsResponse: true,
		Answers: []core.DNSRR{{
			Name: "example.com",
			Type: TypeA,
			IP:   "2001:db8::1", // IPv6 for an A record
		}},
	}
	if err := p.Validate(spec); err == nil {
		t.Error("Validate accepted TypeA RR with IPv6 ip; want family-mismatch error")
	}
}

func TestValidate_RejectsAAAAWithIPv4(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeAAAA,
		IsResponse: true,
		Answers: []core.DNSRR{{
			Name: "example.com",
			Type: TypeAAAA,
			IP:   "192.0.2.1", // IPv4 for an AAAA record
		}},
	}
	if err := p.Validate(spec); err == nil {
		t.Error("Validate accepted TypeAAAA RR with IPv4 ip; want family-mismatch error")
	}
}

// Validate accepts Questions overriding an empty Domain (the questions
// carry their own QNAMEs).
func TestValidate_QuestionsOverrideEmptyDomain(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		QueryType: 0,
		Questions: []core.DNSQuestion{{Name: "example.com", Type: TypeA}},
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate with Questions + empty Domain: %v", err)
	}
}

// =====================================================================
// Integration: Plan error propagation (CLAUDE.md testing policy §4)
// =====================================================================

// A validation failure must propagate through Plan as an error (no channel).
func TestPlan_ValidationErrorPropagates(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS.Transport = "bogus"
	ch, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if ch != nil {
		t.Errorf("expected nil channel on validation error")
	}
}
