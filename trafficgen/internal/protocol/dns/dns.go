// Package dns implements the DNS protocol planner.
package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	DefaultTTL = 64

	// DNS query types.
	TypeA = 1
	TypeAAAA = 28
	TypeCNAME = 5
	TypeMX = 15
	TypeTXT = 16
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
	// An empty domain produces a malformed DNS question section (zero-length
	// QNAME, just the null terminator), which real resolvers/libradios treat
	// as malformed or ignore. Reject at submit time rather than ship a
	// broken packet.
	if spec.DNS.Domain == "" {
		return fmt.Errorf("dns query_name (domain) is required")
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

		queryPayload := buildDNSQuery(spec.DNS.Domain, spec.DNS.QueryType)

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
			L3: core.L3Base(spec.SrcIP, spec.DstIP, 17, effectiveTTL, nextIPID(), spec),
			L4: core.L4Config{
				Protocol: "udp",
				SrcPort: spec.SrcPort,
				DstPort: spec.DstPort,
			},
			Payload: queryPayload,
		}:
		case <-ctx.Done():
			return
		}
		packetIndex++

		// DNS Response — context-aware send
		if spec.DNS.IsResponse {
			responsePayload := buildDNSResponse(spec.DNS.Domain, spec.DNS.QueryType, spec.DNS.ResponseIP)

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
				L3: core.L3Base(spec.DstIP, spec.SrcIP, 17, effectiveTTL, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "udp",
					SrcPort: spec.DstPort,
					DstPort: spec.SrcPort,
				},
				Payload: responsePayload,
			}:
			case <-ctx.Done():
				return
			}
		}
	}()

	return configChan, nil
}

// buildDNSQuery builds a DNS query packet.
func buildDNSQuery(domain string, queryType uint16) []byte {
	// DNS header (12 bytes)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x1234) // Transaction ID
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

// buildDNSResponse builds a DNS response packet.
// For TypeA/TypeAAAA the RDATA is an IP address (responseIP).
// For TypeCNAME the RDATA is a domain name (responseIP field holds the target domain).
// For TypeMX the RDATA is 2-byte preference + domain name.
// For TypeTXT the RDATA is a length-prefixed text string.
func buildDNSResponse(domain string, queryType uint16, responseIP string) []byte {
	// DNS header
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x1234) // Transaction ID
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
	case TypeA, TypeAAAA:
		// RDATA is an IP address.
		ip := net.ParseIP(responseIP)
		if ip == nil {
			ip = net.ParseIP("127.0.0.1")
		}
		if ip.To4() != nil {
			rdata = ip.To4()
		} else {
			rdata = ip.To16()
		}
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
		if ip == nil {
			ip = net.ParseIP("127.0.0.1")
		}
		if ip.To4() != nil {
			rdata = ip.To4()
		} else {
			rdata = ip.To16()
		}
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
// pseudo-record (RFC 6891). When enabled is false, the result is the same
// as buildDNSQuery (no OPT record). When enabled is true, the query includes
// an OPT record with the given UDP payload size and DO bit.
func buildDNSQueryWithEDNS0(domain string, queryType uint16, udpPayloadSize uint16, dnssecOK bool) []byte {
	base := buildDNSQuery(domain, queryType)
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