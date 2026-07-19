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
	TypeA     = 1
	TypeAAAA  = 28
	TypeCNAME = 5
	TypeMX    = 15
	TypeTXT   = 16
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

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

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

		// DNS Query
		configChan <- core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: packetIndex,
			Direction:   "up",
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    spec.SrcMAC,
				DstMAC:    spec.DstMAC,
				EtherType: 0x0800,
			},
			L3: core.L3Base(spec.SrcIP, spec.DstIP, 17, effectiveTTL, nextIPID(), spec),
			L4: core.L4Config{
				Protocol: "udp",
				SrcPort:  spec.SrcPort,
				DstPort:  spec.DstPort,
			},
			Payload: queryPayload,
		}
		packetIndex++

		// DNS Response
		if spec.DNS.Response {
			responsePayload := buildDNSResponse(spec.DNS.Domain, spec.DNS.QueryType, spec.DNS.ResponseIP)

			configChan <- core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   "down",
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    spec.DstMAC,
					DstMAC:    spec.SrcMAC,
					EtherType: 0x0800,
				},
				L3: core.L3Base(spec.DstIP, spec.SrcIP, 17, effectiveTTL, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "udp",
					SrcPort:  spec.DstPort,
					DstPort:  spec.SrcPort,
				},
				Payload: responsePayload,
			}
		}
	}()

	return configChan, nil
}

// buildDNSQuery builds a DNS query packet.
func buildDNSQuery(domain string, queryType uint16) []byte {
	// DNS header (12 bytes)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x1234)  // Transaction ID
	binary.BigEndian.PutUint16(header[2:4], 0x0100)  // Flags: standard query
	binary.BigEndian.PutUint16(header[4:6], 1)       // Questions
	binary.BigEndian.PutUint16(header[6:8], 0)       // Answer RRs
	binary.BigEndian.PutUint16(header[8:10], 0)      // Authority RRs
	binary.BigEndian.PutUint16(header[10:12], 0)     // Additional RRs

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
func buildDNSResponse(domain string, queryType uint16, responseIP string) []byte {
	// DNS header
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x1234)  // Transaction ID
	binary.BigEndian.PutUint16(header[2:4], 0x8180) // Flags: response, recursive desired
	binary.BigEndian.PutUint16(header[4:6], 1)       // Questions
	binary.BigEndian.PutUint16(header[6:8], 1)       // Answer RRs
	binary.BigEndian.PutUint16(header[8:10], 0)      // Authority RRs
	binary.BigEndian.PutUint16(header[10:12], 0)     // Additional RRs

	// DNS question
	question := encodeDomainName(domain)
	qtype := make([]byte, 4)
	binary.BigEndian.PutUint16(qtype[0:2], queryType)
	binary.BigEndian.PutUint16(qtype[2:4], 1) // Class IN

	// DNS answer
	answer := encodeDomainName(domain)
	answerType := make([]byte, 10)
	binary.BigEndian.PutUint16(answerType[0:2], queryType) // Type
	binary.BigEndian.PutUint16(answerType[2:4], 1)        // Class IN
	binary.BigEndian.PutUint32(answerType[4:8], 300)      // TTL
	binary.BigEndian.PutUint16(answerType[8:10], 4)       // Data length (IPv4)

	// Parse response IP
	ip := net.ParseIP(responseIP)
	if ip == nil {
		ip = net.ParseIP("127.0.0.1")
	}
	ipBytes := ip.To4()

	// Combine
	result := make([]byte, 0)
	result = append(result, header...)
	result = append(result, question...)
	result = append(result, qtype...)
	result = append(result, answer...)
	result = append(result, answerType...)
	result = append(result, ipBytes...)

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
			if i > start {
				labels = append(labels, domain[start:i])
			}
			start = i + 1
		}
	}

	if start < len(domain) {
		labels = append(labels, domain[start:])
	}

	return labels
}
