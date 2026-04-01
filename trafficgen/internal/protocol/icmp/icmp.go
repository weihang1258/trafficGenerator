// Package icmp implements the ICMP protocol planner.
package icmp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	DefaultTTL = 64

	// ICMP types.
	TypeEchoRequest = 8
	TypeEchoReply   = 0
)

// Planner implements the ICMP protocol planner.
type Planner struct{}

// NewPlanner creates a new ICMP planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string {
	return "icmp"
}

// Validate validates an ICMP flow spec.
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

	return nil
}

// Plan generates packet configs for an ICMP flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		// Generate flow ID
		flowID := fmt.Sprintf("%s-%s-icmp", spec.SrcIP, spec.DstIP)

		now := time.Now()

		// Get ICMP config
		icmpConfig := spec.ICMP
		if icmpConfig == nil {
			icmpConfig = &core.ICMPConfig{
				Type:     TypeEchoRequest,
				Code:     0,
				Sequence: 1,
				Data:     []byte("ping"),
			}
		}

		// ICMP Echo Request (client -> server)
		configChan <- core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: 0,
			Direction:   "up",
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    spec.SrcMAC,
				DstMAC:    spec.DstMAC,
				EtherType: 0x0800,
			},
			L3: core.L3Config{
				SrcIP:    spec.SrcIP,
				DstIP:    spec.DstIP,
				Protocol: 1, // ICMP
				TTL:      DefaultTTL,
			},
			L4: core.L4Config{
				Protocol: "icmp",
			},
			Payload: buildICMPPayload(icmpConfig),
			Metadata: map[string]interface{}{
				"icmp_type": icmpConfig.Type,
				"icmp_code": icmpConfig.Code,
			},
		}

		// ICMP Echo Reply (server -> client) if Echo Request
		if icmpConfig.Type == TypeEchoRequest {
			replyConfig := &core.ICMPConfig{
				Type:     TypeEchoReply,
				Code:     0,
				Sequence: icmpConfig.Sequence,
				Data:     icmpConfig.Data,
			}

			configChan <- core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: 1,
				Direction:   "down",
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    spec.DstMAC,
					DstMAC:    spec.SrcMAC,
					EtherType: 0x0800,
				},
				L3: core.L3Config{
					SrcIP:    spec.DstIP,
					DstIP:    spec.SrcIP,
					Protocol: 1,
					TTL:      DefaultTTL,
				},
				L4: core.L4Config{
					Protocol: "icmp",
				},
				Payload: buildICMPPayload(replyConfig),
				Metadata: map[string]interface{}{
					"icmp_type": replyConfig.Type,
					"icmp_code": replyConfig.Code,
				},
			}
		}
	}()

	return configChan, nil
}

// buildICMPPayload builds an ICMP payload.
func buildICMPPayload(config *core.ICMPConfig) []byte {
	// ICMP header: Type (1) + Code (1) + Checksum (2) + ID (2) + Sequence (2) = 8 bytes
	header := make([]byte, 8)
	header[0] = config.Type
	header[1] = config.Code
	// Checksum will be calculated later
	// ID (identifier) - using 0x1234
	header[4] = 0x12
	header[5] = 0x34
	// Sequence
	header[6] = byte(config.Sequence >> 8)
	header[7] = byte(config.Sequence)

	// Combine header and data
	payload := make([]byte, 0, 8+len(config.Data))
	payload = append(payload, header...)
	payload = append(payload, config.Data...)

	// Calculate checksum
	checksum := calculateChecksum(payload)
	payload[2] = byte(checksum >> 8)
	payload[3] = byte(checksum)

	return payload
}

// calculateChecksum calculates the ICMP checksum.
func calculateChecksum(data []byte) uint16 {
	sum := uint32(0)

	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}

	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	return ^uint16(sum)
}
