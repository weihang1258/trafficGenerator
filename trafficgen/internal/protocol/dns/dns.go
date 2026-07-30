// Package dns implements the DNS protocol planner.
package dns

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	DefaultTTL = 64

	// DNS query/record types (RFC 1035 §3.2.2 TYPEs, plus later RR types).
	TypeA      = 1
	TypeNS     = 2
	TypeCNAME  = 5
	TypeSOA    = 6
	TypePTR    = 12
	TypeMX     = 15
	TypeTXT    = 16
	TypeAAAA   = 28
	TypeSRV    = 33
	TypeNAPTR  = 35
	TypeDS     = 43
	TypeDNSKEY = 48

	// TypeOPT is the EDNS0 OPT pseudo-RR type (RFC 6891).
	TypeOPT = 41

	// DNS response codes (RFC 1035 §4.1.1, low 4 bits of flags).
	RcodeNoError  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeNotImp   = 4
	RcodeRefused  = 5
)

// Planner implements the DNS protocol planner.
type Planner struct{}

// NewPlanner creates a new DNS planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string {
	return "dns"
}

// Validate validates a DNS flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	// Validate IP addresses
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("invalid source IP: %s", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("invalid destination IP: %s", spec.DstIP)
		}
	}

	// Validate ports
	if spec.DstPort == 0 {
		spec.DstPort = 53 // Default DNS port
	}

	// Validate DNS config
	if spec.DNS == nil {
		return fmt.Errorf("DNS config is required")
	}

	// Transport (L4 carriage) must be one of the supported values. Empty
	// means the default (UDP). DNS over TCP is RFC 1035 §4.2.2 / RFC 7766.
	switch spec.DNS.Transport {
	case "", "udp", "tcp":
	default:
		return fmt.Errorf("dns transport %q not supported (allowed: udp, tcp)", spec.DNS.Transport)
	}

	// RCode occupies the low 4 bits of the flags (RFC 1035 §4.1.1); values
	// above 15 need EDNS0 extended-rcode which is out of scope here.
	if spec.DNS.RCode > 15 {
		return fmt.Errorf("dns rcode %d exceeds the 4-bit field (max 15)", spec.DNS.RCode)
	}

	// Question source. When Questions is set, it overrides Domain/QueryType
	// and each question must carry a non-empty QNAME. Otherwise Domain is
	// required: an empty domain produces a malformed (zero-length) QNAME.
	if len(spec.DNS.Questions) > 0 {
		for i, q := range spec.DNS.Questions {
			if q.Name == "" {
				return fmt.Errorf("dns questions[%d]: name is required", i)
			}
		}
	} else if spec.DNS.Domain == "" {
		return fmt.Errorf("dns query_name (domain) is required")
	}

	// Validate A/AAAA family for explicit Answer/Authority RRs so we never
	// ship a malformed RDATA length on the wire (RFC 1035 §3.4.1, RFC 3596
	// §2.2). encodeRDATA coerces as defense-in-depth, but a mismatch is a
	// user error worth rejecting at submit time.
	for i, rr := range spec.DNS.Answers {
		if err := validateRRFamily(rr, "answers", i); err != nil {
			return err
		}
	}
	for i, rr := range spec.DNS.Authority {
		if err := validateRRFamily(rr, "authority", i); err != nil {
			return err
		}
	}

	// Legacy single-RR path: when IsResponse and ResponseIP is set and no
	// explicit Answers are given, the ResponseIP carries the RDATA. Reject
	// a TypeA/TypeAAAA family mismatch for that path too.
	if spec.DNS.IsResponse && spec.DNS.ResponseIP != "" && len(spec.DNS.Answers) == 0 {
		switch spec.DNS.QueryType {
		case TypeA, TypeAAAA:
			ip := net.ParseIP(spec.DNS.ResponseIP)
			if ip == nil {
				return fmt.Errorf("dns response_ip %q is not a valid IP address (required for TypeA/TypeAAAA)", spec.DNS.ResponseIP)
			}
			if spec.DNS.QueryType == TypeA && ip.To4() == nil {
				return fmt.Errorf("dns TypeA (A record) requires an IPv4 response_ip, got %q (IPv6)", spec.DNS.ResponseIP)
			}
			if spec.DNS.QueryType == TypeAAAA && ip.To4() != nil {
				return fmt.Errorf("dns TypeAAAA (AAAA record) requires an IPv6 response_ip, got %q (IPv4)", spec.DNS.ResponseIP)
			}
		}
	}

	return nil
}

// validateRRFamily rejects an A/AAAA RR whose IP family does not match the
// record type. Other RR types are unaffected (they carry non-IP RDATA).
func validateRRFamily(rr core.DNSRR, section string, idx int) error {
	switch rr.Type {
	case TypeA, TypeAAAA:
	default:
		return nil
	}
	if rr.IP == "" {
		return nil
	}
	ip := net.ParseIP(rr.IP)
	if ip == nil {
		return fmt.Errorf("dns %s[%d]: ip %q is not a valid IP address", section, idx, rr.IP)
	}
	if rr.Type == TypeA && ip.To4() == nil {
		return fmt.Errorf("dns %s[%d]: TypeA requires an IPv4 ip, got %q (IPv6)", section, idx, rr.IP)
	}
	if rr.Type == TypeAAAA && ip.To4() != nil {
		return fmt.Errorf("dns %s[%d]: TypeAAAA requires an IPv6 ip, got %q (IPv4)", section, idx, rr.IP)
	}
	return nil
}

// Plan generates packet configs for a DNS flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	// Default DstPort to 53 (DNS) if not set. Validate does the same
	// defaulting but receives a value copy, so the default is lost for Plan.
	// Apply the default here so the generated packets carry the correct port.
	if spec.DstPort == 0 {
		spec.DstPort = 53
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		// Check if context was already cancelled before starting work.
		select {
		case <-ctx.Done():
			return
		default:
		}

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}
		now := time.Now()
		packetIndex := uint64(0)
		// IPID random start to avoid cross-flow ID collision.
		ipID := uint16(rand.Uint32())

		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		// Resolve L4 transport. Empty defaults to UDP (RFC 1035 §4.2.1);
		// "tcp" carries DNS over TCP with a 2-byte length prefix (RFC 1035
		// §4.2.2 / RFC 7766).
		transport := spec.DNS.Transport
		if transport == "" {
			transport = "udp"
		}
		l4Proto := "udp"
		protoNum := uint8(17) // UDP
		if transport == "tcp" {
			l4Proto = "tcp"
			protoNum = 6 // TCP
		}

		// Build the DNS query message. The multi-question path (Questions
		// set) goes through the general builder; the single-question path
		// reuses the legacy builder (which also handles EDNS0).
		var queryMsg []byte
		if len(spec.DNS.Questions) > 0 {
			txid := spec.DNS.TxID
			if txid == 0 {
				txid = 0x1234
			}
			qs := make([]wireQuestion, 0, len(spec.DNS.Questions))
			for _, q := range spec.DNS.Questions {
				qc := q.Class
				if qc == 0 {
					qc = 1 // IN
				}
				qs = append(qs, wireQuestion{name: q.Name, qtype: q.Type, qclass: qc})
			}
			var additional []wireRR
			if spec.DNS.EDNS0Enabled {
				additional = []wireRR{optWireRR(spec.DNS.UDPPayloadSize, spec.DNS.DnssecOK)}
			}
			queryMsg = buildDNSMessage(txid, 0x0100, qs, nil, nil, additional)
		} else {
			queryMsg = buildDNSQuery(spec.DNS.Domain, spec.DNS.QueryType, spec.DNS.TxID, spec.DNS.EDNS0Enabled, spec.DNS.UDPPayloadSize, spec.DNS.DnssecOK)
		}
		queryPayload := queryMsg
		if transport == "tcp" {
			queryPayload = prefixTCPLength(queryMsg)
		}

		queryL4 := core.L4Config{
			Protocol: l4Proto,
			SrcPort: spec.SrcPort,
			DstPort: spec.DstPort,
		}
		if transport == "tcp" {
			// A data segment carrying the DNS message: PSH+ACK with a
			// nonzero ISN so the segment looks like established-flow
			// data rather than a bare SYN.
			queryL4.Flags = 0x18 // PSH+ACK
			queryL4.Seq = 1
			queryL4.Ack = 1
		}

		// DNS Query — context-aware send
		select {
		case configChan <- core.PacketConfig{
			FlowID: flowID,
			PacketIndex: packetIndex,
			Direction: "up",
			Timestamp: now,
			L2: core.L2Config{
				SrcMAC: spec.SrcMAC,
				DstMAC: spec.DstMAC,
				EtherType: core.EtherTypeFor(spec.SrcIP),
			},
			L3: core.L3Base(spec.SrcIP, spec.DstIP, protoNum, effectiveTTL, nextIPID(), spec),
			L4:      queryL4,
			Payload: queryPayload,
		}:
		case <-ctx.Done():
			return
		}
		packetIndex++

		// DNS Response — context-aware send
		if spec.DNS.IsResponse {
			var responseMsg []byte
			// The general response path is used when the spec carries
			// multiple answer RRs, an authority section, a non-zero rcode,
			// or multiple questions. Otherwise fall back to the legacy
			// single-RR builder for byte-for-byte backward compatibility.
			if len(spec.DNS.Answers) > 0 || len(spec.DNS.Authority) > 0 || spec.DNS.RCode != 0 || len(spec.DNS.Questions) > 0 {
				responseMsg = buildDNSResponseGeneral(spec.DNS)
			} else {
				responseMsg = buildDNSResponse(spec.DNS.Domain, spec.DNS.QueryType, spec.DNS.ResponseIP, spec.DNS.TxID)
			}
			responsePayload := responseMsg
			if transport == "tcp" {
				responsePayload = prefixTCPLength(responseMsg)
			}

			l4 := core.L4Config{
				Protocol: l4Proto,
				SrcPort: spec.DstPort,
				DstPort: spec.SrcPort,
			}
			if transport == "tcp" {
				// A data segment carrying the DNS message: PSH+ACK with a
				// nonzero ISN so the segment looks like established-flow
				// data rather than a bare SYN.
				l4.Flags = 0x18 // PSH+ACK
				l4.Seq = 1
				l4.Ack = 1
			}

			select {
			case configChan <- core.PacketConfig{
				FlowID: flowID,
				PacketIndex: packetIndex,
				Direction: "down",
				Timestamp: now,
				L2: core.L2Config{
					SrcMAC: spec.DstMAC,
					DstMAC: spec.SrcMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3: core.L3Base(spec.DstIP, spec.SrcIP, protoNum, effectiveTTL, nextIPID(), spec),
				L4:      l4,
				Payload: responsePayload,
			}:
			case <-ctx.Done():
				return
			}
		}
	}()

	return configChan, nil
}

// buildDNSQuery builds a DNS query packet. The TxID is the 16-bit DNS
// Transaction ID (RFC 1035 §4.1.1); txid=0 falls back to the historical
// default 0x1234. When edns0Enabled is true an OPT pseudo-RR is appended to
// the Additional section (ARCOUNT=1) per RFC 6891; udpPayloadSize is the OPT
// CLASS field (max UDP payload the client accepts) and dnssecOK sets the DO
// bit (RFC 4033).
func buildDNSQuery(domain string, queryType uint16, txid uint16, edns0Enabled bool, udpPayloadSize uint16, dnssecOK bool) []byte {
	if txid == 0 {
		txid = 0x1234 // backward-compat default
	}
	if edns0Enabled {
		return buildDNSQueryWithEDNS0(domain, queryType, txid, udpPayloadSize, dnssecOK)
	}
	// DNS header (12 bytes)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], txid) // Transaction ID
	binary.BigEndian.PutUint16(header[2:4], 0x0100) // Flags: standard query
	binary.BigEndian.PutUint16(header[4:6], 1) // Questions
	binary.BigEndian.PutUint16(header[6:8], 0) // Answer RRs
	binary.BigEndian.PutUint16(header[8:10], 0) // Authority RRs
	binary.BigEndian.PutUint16(header[10:12], 0) // Additional RRs

	// DNS question
	question := encodeDomainName(domain)
	qtype := make([]byte, 4)
	binary.BigEndian.PutUint16(qtype[0:2], queryType)
	binary.BigEndian.PutUint16(qtype[2:4], 1) // Class IN

	// Combine
	result := make([]byte, 0, len(header)+len(question)+4)
	result = append(result, header...)
	result = append(result, question...)
	result = append(result, qtype...)

	return result
}

// buildDNSResponse builds a DNS response packet. The txid is the DNS
// Transaction ID (RFC 1035 §4.1.1) — MUST echo the query's TxID; txid=0
// falls back to the historical default 0x1234.
//
// For TypeA/TypeAAAA the RDATA is an IP address (responseIP). The address
// family MUST match the record type: TypeA requires a 4-byte IPv4 address
// (RFC 1035 §3.4.1), TypeAAAA requires a 16-byte IPv6 address (RFC 3596
// §2.2). A mismatch (e.g. IPv6 responseIP for a TypeA record) is coerced:
// the builder falls back to 127.0.0.1 (IPv4) for TypeA or ::1 (IPv6) for
// TypeAAAA so the RDATA length is always correct on the wire.
//
// For TypeCNAME the RDATA is a domain name (responseIP field holds the target domain).
// For TypeMX the RDATA is 2-byte preference + domain name.
// For TypeTXT the RDATA is a length-prefixed text string.
func buildDNSResponse(domain string, queryType uint16, responseIP string, txid uint16) []byte {
	if txid == 0 {
		txid = 0x1234 // backward-compat default
	}
	// DNS header
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], txid) // Transaction ID
	binary.BigEndian.PutUint16(header[2:4], 0x8180) // Flags: response, recursive desired
	binary.BigEndian.PutUint16(header[4:6], 1) // Questions
	binary.BigEndian.PutUint16(header[6:8], 1) // Answer RRs
	binary.BigEndian.PutUint16(header[8:10], 0) // Authority RRs
	binary.BigEndian.PutUint16(header[10:12], 0) // Additional RRs

	// DNS question
	question := encodeDomainName(domain)
	qtype := make([]byte, 4)
	binary.BigEndian.PutUint16(qtype[0:2], queryType)
	binary.BigEndian.PutUint16(qtype[2:4], 1) // Class IN

	// DNS answer
	answer := encodeDomainName(domain)
	answerType := make([]byte, 10)
	binary.BigEndian.PutUint16(answerType[0:2], queryType) // Type
	binary.BigEndian.PutUint16(answerType[2:4], 1) // Class IN
	binary.BigEndian.PutUint32(answerType[4:8], 300) // TTL
	// RDLENGTH is set below after computing RDATA

	// Build RDATA based on query type.
	var rdata []byte
	switch queryType {
	case TypeA:
		// RDATA MUST be a 4-byte IPv4 address (RFC 1035 §3.4.1). If the
		// configured responseIP is IPv6 (or unparseable), fall back to the
		// IPv4 loopback so the RDATA length is always 4.
		ip := net.ParseIP(responseIP)
		v4 := net.IP(nil)
		if ip != nil {
			v4 = ip.To4()
		}
		if v4 == nil {
			v4 = net.IPv4(127, 0, 0, 1).To4()
		}
		rdata = v4
	case TypeAAAA:
		// RDATA MUST be a 16-byte IPv6 address (RFC 3596 §2.2). If the
		// configured responseIP is IPv4 (or unparseable), fall back to the
		// IPv6 loopback so the RDATA length is always 16.
		ip := net.ParseIP(responseIP)
		v4 := net.IP(nil)
		if ip != nil {
			v4 = ip.To4()
		}
		if v4 != nil {
			// IPv4 given for an AAAA record: coerce to IPv6 loopback.
			ip = net.ParseIP("::1")
		}
		if ip == nil {
			ip = net.ParseIP("::1")
		}
		rdata = ip.To16()
	case TypeCNAME:
		// RDATA is a domain name (CNAME target domain).
		// Use responseIP as the target domain name.
		if responseIP == "" {
			responseIP = "target.example.com"
		}
		rdata = encodeDomainName(responseIP)
	case TypeMX:
		// RDATA is 2-byte preference + domain name (MX priority + mail exchanger domain).
		if responseIP == "" {
			responseIP = "mail.example.com"
		}
		pref := make([]byte, 2)
		binary.BigEndian.PutUint16(pref, 10) // default preference
		rdata = append(rdata, pref...)
		rdata = append(rdata, encodeDomainName(responseIP)...)
	case TypeTXT:
		// RDATA is length-prefixed text (TXT record data, length prefix + string).
		// An empty string produces a single 0x00 byte (length=0), which is valid.
		txtData := make([]byte, 1+len(responseIP))
		txtData[0] = byte(len(responseIP))
		copy(txtData[1:], responseIP)
		rdata = txtData
	default:
		// Fallback: treat as A record.
		ip := net.ParseIP(responseIP)
		v4 := net.IP(nil)
		if ip != nil {
			v4 = ip.To4()
		}
		if v4 == nil {
			v4 = net.IPv4(127, 0, 0, 1).To4()
		}
		rdata = v4
	}
	binary.BigEndian.PutUint16(answerType[8:10], uint16(len(rdata)))

	// Combine
	result := make([]byte, 0)
	result = append(result, header...)
	result = append(result, question...)
	result = append(result, qtype...)
	result = append(result, answer...)
	result = append(result, answerType...)
	result = append(result, rdata...)

	return result
}

// encodeDomainName encodes a domain name for DNS.
func encodeDomainName(domain string) []byte {
	result := make([]byte, 0)
	labels := splitLabels(domain)

	for _, label := range labels {
		result = append(result, byte(len(label)))
		result = append(result, []byte(label)...)
	}
	result = append(result, 0) // Null terminator

	return result
}

// splitLabels splits a domain into labels.
func splitLabels(domain string) []string {
	labels := make([]string, 0)
	start := 0

	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			// Always append a label segment, even if empty (consecutive dots
			// produce an empty label per RFC 1035 section 3.1). A trailing dot
			// (FQDN) is handled by the final condition below, not here.
			labels = append(labels, domain[start:i])
			start = i + 1
		}
	}

	// Trailing label after the last dot. When the domain ends with a dot
	// (FQDN), start == len(domain) and nothing is appended -- the root label
	// is represented by the 0x00 terminator in encodeDomainName.
	if start < len(domain) {
		labels = append(labels, domain[start:])
	}

	return labels
}

// buildDNSQueryWithEDNS0 builds a DNS query packet with an EDNS0 OPT
// pseudo-record (RFC 6891). The txid is the DNS Transaction ID (0 → 0x1234).
// When udpPayloadSize is 0 the function falls back to a non-EDNS0 query.
// When non-zero, the query includes an OPT record with the given UDP payload
// size and DO bit.
func buildDNSQueryWithEDNS0(domain string, queryType uint16, txid uint16, udpPayloadSize uint16, dnssecOK bool) []byte {
	if txid == 0 {
		txid = 0x1234
	}
	base := buildDNSQuery(domain, queryType, txid, false, 0, false)
	if udpPayloadSize == 0 {
		return base
	}

	// OPT pseudo-record layout (RFC 6891 section 6.1):
	// NAME: 1 byte (0x00 for root, offset 0)
	// TYPE: 2 bytes (41 = 0x0029, offset 1-2)
	// CLASS: 2 bytes (UDP payload size, offset 3-4)
	// TTL: 4 bytes (extRCODE + version + DO|Z_hi + Z_lo, offset 5-8)
	// RDLEN: 2 bytes (0, offset 9-10)
	// Total: 11 bytes
	opt := make([]byte, 11)
	opt[0] = 0x00 // NAME = root (0x00)
	binary.BigEndian.PutUint16(opt[1:3], 41) // TYPE = 41 (OPT)
	binary.BigEndian.PutUint16(opt[3:5], udpPayloadSize) // CLASS = UDP payload size
	// TTL = [extRCODE, version, DO|Z_hi, Z_lo]
	opt[5] = 0 // extended RCODE
	opt[6] = 0 // version
	if dnssecOK {
		opt[7] = 0x80 // DO bit (bit 15 of TTL, in the high byte of the 2-byte DO|Z field)
	} else {
		opt[7] = 0
	}
	opt[8] = 0 // Z (reserved, low byte)
	// RDLEN = 0 (no options)
	binary.BigEndian.PutUint16(opt[9:11], 0)

	// Update ARCOUNT in the header to 1
	base[10] = 0x00
	base[11] = 0x01

	result := make([]byte, 0, len(base)+len(opt))
	result = append(result, base...)
	result = append(result, opt...)
	return result
}

// prefixTCPLength prepends the 2-byte big-endian DNS-over-TCP length
// prefix (RFC 1035 §4.2.2 / RFC 7766 §7). The length covers the DNS
// message that follows, not the 2-byte prefix itself.
func prefixTCPLength(msg []byte) []byte {
	out := make([]byte, 2+len(msg))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(msg)))
	copy(out[2:], msg)
	return out
}

// wireQuestion is the internal representation of a DNS question used by
// buildDNSMessage. Class defaults to IN (1) when zero.
type wireQuestion struct {
	name   string
	qtype  uint16
	qclass uint16
}

// wireRR is the internal representation of an RR used by buildDNSMessage.
// rdata holds the already-serialized RDATA bytes; the builder fills in
// NAME/TYPE/CLASS/TTL/RDLENGTH around it. When namePtrTo is non-zero it is
// used as a 2-byte compression pointer in place of a serialized name; the
// caller is responsible for using a valid offset (RFC 1035 §4.1.4).
type wireRR struct {
	name      []byte
	namePtrTo uint16
	rtype     uint16
	rclass    uint16
	ttl       uint32
	rdata     []byte
}

// optWireRR builds the OPT pseudo-RR wire representation for EDNS0 (RFC
// 6891 §6.1). udpPayloadSize=0 defaults to 4096. When dnssecOK is true the
// DO bit (bit 15 of the 4-byte TTL field, i.e. 0x8000) is set per RFC 4033.
func optWireRR(udpPayloadSize uint16, dnssecOK bool) wireRR {
	if udpPayloadSize == 0 {
		udpPayloadSize = 4096
	}
	ttl := uint32(0)
	if dnssecOK {
		ttl = 0x8000 // DO bit = bit 15 of the TTL field
	}
	return wireRR{
		name:   []byte{0x00}, // root
		rtype:  TypeOPT,
		rclass: udpPayloadSize,
		ttl:    ttl,
		rdata:  []byte{}, // no options
	}
}

// buildDNSMessage assembles a DNS message from header flags and the four
// sections. qd/an/ns/ar counts are derived from the slice lengths. The
// caller-supplied flags already encode QR/opcode/RD/RA/RCODE (this builder
// does not recompute them).
func buildDNSMessage(txid uint16, flags uint16, questions []wireQuestion, answers, authority, additional []wireRR) []byte {
	var buf []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], txid)
	binary.BigEndian.PutUint16(header[2:4], flags)
	binary.BigEndian.PutUint16(header[4:6], uint16(len(questions)))
	binary.BigEndian.PutUint16(header[6:8], uint16(len(answers)))
	binary.BigEndian.PutUint16(header[8:10], uint16(len(authority)))
	binary.BigEndian.PutUint16(header[10:12], uint16(len(additional)))
	buf = append(buf, header...)
	for _, q := range questions {
		buf = append(buf, encodeDomainName(q.name)...)
		tmp := make([]byte, 4)
		binary.BigEndian.PutUint16(tmp[0:2], q.qtype)
		binary.BigEndian.PutUint16(tmp[2:4], q.qclass)
		buf = append(buf, tmp...)
	}
	for _, rr := range answers {
		buf = appendRR(buf, rr)
	}
	for _, rr := range authority {
		buf = appendRR(buf, rr)
	}
	for _, rr := range additional {
		buf = appendRR(buf, rr)
	}
	return buf
}

// appendRR appends one RR (NAME+TYPE+CLASS+TTL+RDLENGTH+RDATA) to buf.
func appendRR(buf []byte, rr wireRR) []byte {
	if rr.namePtrTo != 0 {
		ptr := make([]byte, 2)
		binary.BigEndian.PutUint16(ptr, 0xC000|rr.namePtrTo)
		buf = append(buf, ptr...)
	} else if rr.name != nil {
		buf = append(buf, rr.name...)
	} else {
		buf = append(buf, 0x00) // root
	}
	fixed := make([]byte, 10)
	binary.BigEndian.PutUint16(fixed[0:2], rr.rtype)
	binary.BigEndian.PutUint16(fixed[2:4], rr.rclass)
	binary.BigEndian.PutUint32(fixed[4:8], rr.ttl)
	binary.BigEndian.PutUint16(fixed[8:10], uint16(len(rr.rdata)))
	buf = append(buf, fixed...)
	buf = append(buf, rr.rdata...)
	return buf
}

// buildDNSResponseGeneral builds a DNS response from the full DNSConfig
// (multi-RR answers, authority section, rcode, multi-question). The
// legacy single-RR path (buildDNSResponse) is kept for backward
// compatibility; this builder is used whenever Answers/Authority/RCode/
// Questions are set.
//
// Flags: QR=1 (response), RD copied from query, RA=1 (recursive available
// for the synthetic authoritative server), rcode from config. opcode=0
// (standard query). When the question set is empty the single Domain/
// QueryType pair is echoed back as the question section (RFC 1035 §4.1:
// the response MUST echo the question(s)).
func buildDNSResponseGeneral(cfg *core.DNSConfig) []byte {
	txid := cfg.TxID
	if txid == 0 {
		txid = 0x1234
	}

	// Questions.
	qs := make([]wireQuestion, 0, len(cfg.Questions))
	if len(cfg.Questions) > 0 {
		for _, q := range cfg.Questions {
			qc := q.Class
			if qc == 0 {
				qc = 1 // IN
			}
			qs = append(qs, wireQuestion{name: q.Name, qtype: q.Type, qclass: qc})
		}
	} else {
		qc := uint16(1) // IN
		qs = append(qs, wireQuestion{name: cfg.Domain, qtype: cfg.QueryType, qclass: qc})
	}

	// Answer RRs.
	answers := make([]wireRR, 0, len(cfg.Answers))
	for _, rr := range cfg.Answers {
		answers = append(answers, rrToWire(rr, cfg))
	}
	// Legacy single-RR path: when no explicit Answers are set, synthesize
	// one from Domain/QueryType/ResponseIP so callers that don't set
	// Answers still get a response RR via this builder.
	if len(answers) == 0 && cfg.ResponseIP != "" {
		rr := core.DNSRR{
			Name:   cfg.Domain,
			Type:   cfg.QueryType,
			IP:     cfg.ResponseIP,
			Target: cfg.ResponseIP,
			Text:   cfg.ResponseIP,
		}
		// For MX/CNAME the target lives in ResponseIP.
		if cfg.QueryType == TypeMX {
			rr.Preference = 10
		}
		answers = append(answers, rrToWire(rr, cfg))
	}

	// Authority RRs.
	auth := make([]wireRR, 0, len(cfg.Authority))
	for _, rr := range cfg.Authority {
		auth = append(auth, rrToWire(rr, cfg))
	}

	// Additional RRs (EDNS0 OPT on the response side, if requested).
	var additional []wireRR
	if cfg.EDNS0Enabled {
		additional = append(additional, optWireRR(cfg.UDPPayloadSize, cfg.DnssecOK))
	}

	// Flags: QR=1, RD=1, RA=1 (recursive available), opcode=0, rcode from cfg.
	flags := uint16(0x8180) | uint16(cfg.RCode&0x0F)
	return buildDNSMessage(txid, flags, qs, answers, auth, additional)
}

// rrToWire serializes a DNSRR from the config into a wireRR. TTL
// resolves to rr.TTL, else cfg.TTL, else 300. Class defaults to IN (1).
func rrToWire(rr core.DNSRR, cfg *core.DNSConfig) wireRR {
	ttl := rr.TTL
	if ttl == 0 {
		ttl = cfg.TTL
	}
	if ttl == 0 {
		ttl = 300
	}
	cls := rr.Class
	if cls == 0 {
		cls = 1 // IN
	}
	name := encodeDomainName(rr.Name)
	if rr.Name == "" {
		name = []byte{0x00}
	}
	return wireRR{
		name:  name,
		rtype: rr.Type,
		rclass: cls,
		ttl:   ttl,
		rdata: encodeRDATA(rr),
	}
}

// encodeRDATA serializes the RDATA for a DNSRR. It switches on rr.Type and
// reads the type-appropriate fields. A/AAAA coerce family mismatches so
// the wire RDATA length is always correct (RFC 1035 §3.4.1, RFC 3596 §2.2).
func encodeRDATA(rr core.DNSRR) []byte {
	switch rr.Type {
	case TypeA:
		ip := net.ParseIP(rr.IP)
		v4 := net.IP(nil)
		if ip != nil {
			v4 = ip.To4()
		}
		if v4 == nil {
			v4 = net.IPv4(127, 0, 0, 1).To4()
		}
		return append([]byte(nil), v4...)
	case TypeAAAA:
		ip := net.ParseIP(rr.IP)
		if ip == nil || ip.To4() != nil {
			ip = net.ParseIP("::1")
		}
		return append([]byte(nil), ip.To16()...)
	case TypeCNAME, TypeNS, TypePTR:
		tgt := rr.Target
		if tgt == "" {
			tgt = "target.example.com"
		}
		return encodeDomainName(tgt)
	case TypeMX:
		tgt := rr.Target
		if tgt == "" {
			tgt = "mail.example.com"
		}
		pref := make([]byte, 2)
		binary.BigEndian.PutUint16(pref, rr.Preference)
		return append(pref, encodeDomainName(tgt)...)
	case TypeTXT:
		// RFC 1035 §3.3.14: TXT is one or more <character-string>s; each is
		// a 1-byte length prefix + bytes. A single string is truncated to
		// 255 bytes (the max a single length byte can describe).
		txt := rr.Text
		if len(txt) > 255 {
			txt = txt[:255]
		}
		out := make([]byte, 1+len(txt))
		out[0] = byte(len(txt))
		copy(out[1:], txt)
		return out
	case TypeSOA:
		// RFC 1035 §3.3.13: MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM.
		mname := rr.MName
		if mname == "" {
			mname = "ns1.example.com"
		}
		rname := rr.RName
		if rname == "" {
			rname = "admin.example.com"
		}
		var b []byte
		b = append(b, encodeDomainName(mname)...)
		b = append(b, encodeDomainName(rname)...)
		fixed := make([]byte, 20)
		binary.BigEndian.PutUint32(fixed[0:4], rr.Serial)
		binary.BigEndian.PutUint32(fixed[4:8], rr.Refresh)
		binary.BigEndian.PutUint32(fixed[8:12], rr.Retry)
		binary.BigEndian.PutUint32(fixed[12:16], rr.Expire)
		binary.BigEndian.PutUint32(fixed[16:20], rr.Minimum)
		b = append(b, fixed...)
		return b
	case TypeSRV:
		// RFC 2782: Priority(2) + Weight(2) + Port(2) + Target(domain).
		tgt := rr.Target
		if tgt == "" {
			tgt = "target.example.com"
		}
		fixed := make([]byte, 6)
		binary.BigEndian.PutUint16(fixed[0:2], rr.Priority)
		binary.BigEndian.PutUint16(fixed[2:4], rr.Weight)
		binary.BigEndian.PutUint16(fixed[4:6], rr.Port)
		var b []byte
		b = append(b, fixed...)
		b = append(b, encodeDomainName(tgt)...)
		return b
	case TypeNAPTR:
		// RFC 3401 §4.1: Order(2) + Preference(2) + Flags + Service +
		// Regexp + Replacement.
		var b []byte
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:2], rr.Order)
		binary.BigEndian.PutUint16(hdr[2:4], rr.Preference)
		b = append(b, hdr...)
		b = appendCharString(b, rr.Flags)
		b = appendCharString(b, rr.Service)
		b = appendCharString(b, rr.Regexp)
		tgt := rr.Target
		if tgt == "" {
			tgt = "."
		}
		b = append(b, encodeDomainName(tgt)...)
		return b
	case TypeDS:
		// RFC 4034 §5: KeyTag(2) + Algorithm(1) + DigestType(1) + Digest.
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:2], rr.KeyTag)
		hdr[2] = rr.Algorithm
		hdr[3] = rr.DigestType
		digest, err := hex.DecodeString(strings.TrimSpace(rr.Digest))
		if err != nil {
			digest = nil
		}
		var b []byte
		b = append(b, hdr...)
		b = append(b, digest...)
		return b
	case TypeDNSKEY:
		// RFC 4034 §2: Flags(2) + Protocol(1) + Algorithm(1) + PublicKey.
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:2], rr.KeyFlags)
		hdr[2] = rr.Protocol
		hdr[3] = rr.Algorithm
		pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rr.PublicKey))
		if err != nil {
			pub = nil
		}
		var b []byte
		b = append(b, hdr...)
		b = append(b, pub...)
		return b
	default:
		// Unknown type: emit empty RDATA so the RR is still structurally
		// valid (NAME+TYPE+CLASS+TTL+RDLENGTH=0).
		return nil
	}
}

// appendCharString appends a DNS character-string (1-byte length + bytes)
// to buf. Strings longer than 255 bytes are truncated.
func appendCharString(buf []byte, s string) []byte {
	if len(s) > 255 {
		s = s[:255]
	}
	out := make([]byte, 1+len(s))
	out[0] = byte(len(s))
	copy(out[1:], s)
	return append(buf, out...)
}