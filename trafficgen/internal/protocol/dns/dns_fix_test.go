package dns

// Adversarial regression tests for findings F1-F3 from the code review.
// F1: DNS Transaction ID hardcoded to 0x1234 (RFC 1035 §4.1.1).
// F2: DNS EDNS0 OPT RR dead code -- builder never emits it via Plan (RFC 6891).
// F3: DNS TypeA/AAAA responseIP IP-family mismatch (RFC 1035 §3.4.1, RFC 3596 §2.2).

import (
	"bytes"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ---------------------------------------------------------------------------
// F1: Transaction ID configurability (RFC 1035 §4.1.1)
// ---------------------------------------------------------------------------

// F1-a: two different TxID configs produce queries with those exact TxIDs.
func TestF1_DNSQuery_TxIDConfigurable(t *testing.T) {
	q1 := buildDNSQuery("example.com", TypeA, 0xABCD, false, 0, false)
	q2 := buildDNSQuery("example.com", TypeA, 0xFFFF, false, 0, false)
	if q1[0] != 0xAB || q1[1] != 0xCD {
		t.Errorf("query1 TxID = [%02x %02x], want [AB CD]", q1[0], q1[1])
	}
	if q2[0] != 0xFF || q2[1] != 0xFF {
		t.Errorf("query2 TxID = [%02x %02x], want [FF FF]", q2[0], q2[1])
	}
}

// F1-b: TxID=0 (unset) falls back to the historical default 0x1234.
func TestF1_DNSQuery_TxIDDefault(t *testing.T) {
	q := buildDNSQuery("example.com", TypeA, 0, false, 0, false)
	if q[0] != 0x12 || q[1] != 0x34 {
		t.Errorf("default TxID = [%02x %02x], want [12 34]", q[0], q[1])
	}
}

// F1-c: the response MUST echo the query's TxID (not a different hardcoded one).
func TestF1_DNSResponse_EchoesQueryTxID(t *testing.T) {
	const txid = 0x4242
	resp := buildDNSResponse("example.com", TypeA, "127.0.0.1", txid)
	if resp[0] != 0x42 || resp[1] != 0x42 {
		t.Errorf("response TxID = [%02x %02x], want [42 42] (must echo query)", resp[0], resp[1])
	}
}

// F1-d: integration -- Plan emits query and response sharing the same TxID.
func TestF1_DNSPlan_QueryResponseSameTxID(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeA,
		IsResponse: true,
		ResponseIP: "192.168.1.100",
		TxID:       0xBEEF,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) != 2 {
		t.Fatalf("expected 2 packets (query+response), got %d", len(cfgs))
	}
	query := cfgs[0].Payload
	resp := cfgs[1].Payload
	if query[0] != 0xBE || query[1] != 0xEF {
		t.Errorf("query TxID = [%02x %02x], want [BE EF]", query[0], query[1])
	}
	if resp[0] != query[0] || resp[1] != query[1] {
		t.Errorf("response TxID = [%02x %02x], must echo query [%02x %02x]",
			resp[0], resp[1], query[0], query[1])
	}
}

// ---------------------------------------------------------------------------
// F2: EDNS0 OPT RR emission (RFC 6891 §6.1)
// ---------------------------------------------------------------------------

// F2-a: an EDNS0-enabled config produces an OPT RR in the Additional section.
func TestF2_DNSPlan_EDNS0EmitsOPTRR(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:         "example.com",
		QueryType:      TypeA,
		EDNS0Enabled:   true,
		UDPPayloadSize: 4096,
		DnssecOK:       true,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("expected at least 1 packet")
	}
	q := cfgs[0].Payload
	// ARCOUNT (bytes 10-11) must be 1 (one Additional RR).
	arcount := uint16(q[10])<<8 | uint16(q[11])
	if arcount != 1 {
		t.Fatalf("ARCOUNT = %d, want 1 (EDNS0 OPT RR in Additional)", arcount)
	}
	// The OPT RR is appended after the question. Locate it: header(12) +
	// question = 12 + len(encoded "example.com") + 4 (qtype+qclass).
	// "example.com" encodes to 13 bytes (7+example+3+com+0) + 4 = 17.
	optStart := 12 + 17
	if optStart+11 > len(q) {
		t.Fatalf("payload too short for OPT RR: %d bytes", len(q))
	}
	// OPT NAME = 0x00 (root)
	if q[optStart] != 0x00 {
		t.Errorf("OPT NAME = 0x%02x, want 0x00 (root)", q[optStart])
	}
	// OPT TYPE = 41 (0x0029)
	optType := uint16(q[optStart+1])<<8 | uint16(q[optStart+2])
	if optType != 41 {
		t.Errorf("OPT TYPE = %d, want 41 (OPT)", optType)
	}
	// OPT CLASS = UDP payload size (4096 = 0x1000)
	udpSize := uint16(q[optStart+3])<<8 | uint16(q[optStart+4])
	if udpSize != 4096 {
		t.Errorf("OPT UDP payload size = %d, want 4096", udpSize)
	}
	// DO bit is bit 15 of the 4-byte TTL field (byte optStart+7 high bit).
	doBit := q[optStart+7] & 0x80
	if doBit != 0x80 {
		t.Errorf("DO bit = 0x%02x, want 0x80 (DNSSEC OK)", doBit)
	}
	// RDLENGTH = 0 (no options)
	rdlen := uint16(q[optStart+9])<<8 | uint16(q[optStart+10])
	if rdlen != 0 {
		t.Errorf("OPT RDLENGTH = %d, want 0", rdlen)
	}
}

// F2-b: EDNS0 disabled (default) produces NO OPT RR (ARCOUNT=0).
func TestF2_DNSPlan_EDNS0DisabledNoOPTRR(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:    "example.com",
		QueryType: TypeA,
	}
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatal("expected at least 1 packet")
	}
	q := cfgs[0].Payload
	arcount := uint16(q[10])<<8 | uint16(q[11])
	if arcount != 0 {
		t.Errorf("ARCOUNT = %d, want 0 (EDNS0 disabled, no OPT RR)", arcount)
	}
}

// ---------------------------------------------------------------------------
// F3: TypeA/AAAA IP-family mismatch (RFC 1035 §3.4.1, RFC 3596 §2.2)
// ---------------------------------------------------------------------------

// F3-a: TypeA response MUST produce 4-byte RDATA (IPv4).
func TestF3_DNSResponse_TypeA_FourByteRDATA(t *testing.T) {
	resp := buildDNSResponse("example.com", TypeA, "192.0.2.1", 0x1234)
	// The RDATA is the last 4 bytes; verify it is exactly 4 bytes of IPv4.
	last := resp[len(resp)-4:]
	want := []byte{192, 0, 2, 1}
	if !bytes.Equal(last, want) {
		t.Errorf("TypeA RDATA (last 4 bytes) = %v, want %v (IPv4)", last, want)
	}
	// RDLENGTH must be 4 (bytes at answerType[8:10], which are the 2 bytes
	// preceding the RDATA). answerType is 10 bytes; RDATA follows.
	rdlen := uint16(resp[len(resp)-4-2])<<8 | uint16(resp[len(resp)-4-1])
	if rdlen != 4 {
		t.Errorf("TypeA RDLENGTH = %d, want 4", rdlen)
	}
}

// F3-b: TypeAAAA response MUST produce 16-byte RDATA (IPv6).
func TestF3_DNSResponse_TypeAAAA_SixteenByteRDATA(t *testing.T) {
	resp := buildDNSResponse("example.com", TypeAAAA, "2001:db8::1", 0x1234)
	last := resp[len(resp)-16:]
	want := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if !bytes.Equal(last, want) {
		t.Errorf("TypeAAAA RDATA (last 16 bytes) = %v, want %v (IPv6)", last, want)
	}
	rdlen := uint16(resp[len(resp)-16-2])<<8 | uint16(resp[len(resp)-16-1])
	if rdlen != 16 {
		t.Errorf("TypeAAAA RDLENGTH = %d, want 16", rdlen)
	}
}

// F3-c: TypeA with an IPv6 responseIP must NOT produce 16-byte RDATA.
// The builder must reject/coerce the family mismatch (never emit 16-byte
// RDATA for a TypeA record, which would be malformed on the wire).
func TestF3_DNSResponse_TypeA_RejectsIPv6(t *testing.T) {
	resp := buildDNSResponse("example.com", TypeA, "2001:db8::1", 0x1234)
	rdlen := uint16(resp[len(resp)-4-2])<<8 | uint16(resp[len(resp)-4-1])
	if rdlen != 4 {
		t.Errorf("TypeA with IPv6 responseIP: RDLENGTH = %d, want 4 (must coerce/reject, not 16)", rdlen)
	}
	// The last 4 bytes must be a valid IPv4 fallback, not IPv6 bytes.
	last := resp[len(resp)-4:]
	if last[0] == 0x20 && last[1] == 0x01 {
		t.Errorf("TypeA with IPv6 responseIP emitted IPv6 bytes %v in 4-byte RDATA", last)
	}
}

// F3-d: TypeAAAA with an IPv4 responseIP must NOT produce 4-byte RDATA.
func TestF3_DNSResponse_TypeAAAA_RejectsIPv4(t *testing.T) {
	resp := buildDNSResponse("example.com", TypeAAAA, "192.0.2.1", 0x1234)
	rdlen := uint16(resp[len(resp)-16-2])<<8 | uint16(resp[len(resp)-16-1])
	if rdlen != 16 {
		t.Errorf("TypeAAAA with IPv4 responseIP: RDLENGTH = %d, want 16 (must coerce/reject, not 4)", rdlen)
	}
	last := resp[len(resp)-16:]
	// Must NOT be the IPv4-in-last-4-bytes pattern (would mean 4-byte RDATA).
	if last[15] == 1 && last[14] == 2 && last[13] == 0 && last[12] == 192 {
		t.Errorf("TypeAAAA with IPv4 responseIP emitted IPv4 bytes %v in 16-byte RDATA", last)
	}
}

// F3-e: integration -- Validate rejects family mismatch when IsResponse.
func TestF3_DNSPlan_ValidateRejectsFamilyMismatch(t *testing.T) {
	p := NewPlanner()
	spec := validDNSSpec()
	spec.DNS = &core.DNSConfig{
		Domain:     "example.com",
		QueryType:  TypeA,
		IsResponse: true,
		ResponseIP: "2001:db8::1", // IPv6 for a TypeA record
	}
	if err := p.Validate(spec); err == nil {
		t.Error("Validate accepted TypeA with IPv6 responseIP; expected family-mismatch error")
	}
}

// ---------------------------------------------------------------------------
// F4: overlong domain names rejected at submit time (RFC 1035 §2.3.4/§3.1,
// T-DNS-17). encodeDomainName truncates label lengths to one byte, so an
// overlong label would silently wrap and emit a malformed QNAME — reject
// loudly instead.
// ---------------------------------------------------------------------------

func TestValidateDNSConfig_LongDomainRejected(t *testing.T) {
	longLabel := strings.Repeat("a", 64) + ".example.com"
	if err := validateDNSConfig(core.FlowSpec{DNS: &core.DNSConfig{Domain: longLabel, QueryType: TypeA}}); err == nil {
		t.Fatal("64-octet label accepted, want rejection (RFC 1035 §3.1)")
	} else if !strings.Contains(err.Error(), "63 octets") {
		t.Fatalf("err = %q, want anchor `63 octets`", err)
	}
	longName := strings.Repeat("a", 250) + ".com"
	if err := validateDNSConfig(core.FlowSpec{DNS: &core.DNSConfig{Domain: longName, QueryType: TypeA}}); err == nil {
		t.Fatal("overlong name accepted, want rejection (RFC 1035 §2.3.4)")
	} else if !strings.Contains(err.Error(), "253 characters") {
		t.Fatalf("err = %q, want anchor `253 characters`", err)
	}
	// RR 名与 target 同门：超长 CNAME target 也必须拒。
	bad := &core.DNSConfig{Domain: "www.example.com", QueryType: TypeA, IsResponse: true,
		Answers: []core.DNSRR{{Name: "www.example.com", Type: TypeCNAME, Target: strings.Repeat("b", 70) + ".example.com"}}}
	if err := validateDNSConfig(core.FlowSpec{DNS: bad}); err == nil {
		t.Fatal("overlong CNAME target accepted, want rejection")
	}
	// 合法边界：63 字节 label 与 253 字符全名放行。
	ok := &core.DNSConfig{Domain: strings.Repeat("a", 63) + ".example.com", QueryType: TypeA}
	if err := validateDNSConfig(core.FlowSpec{DNS: ok}); err != nil {
		t.Fatalf("63-octet label rejected: %v", err)
	}
}
