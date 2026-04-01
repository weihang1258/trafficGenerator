// Package udp implements the UDP protocol planner.
package udp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	DefaultTTL = 64
)

// Planner implements the UDP protocol planner.
type Planner struct{}

// NewPlanner creates a new UDP planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string {
	return "udp"
}

// Validate validates a UDP flow spec.
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
	if spec.SrcPort == 0 {
		return fmt.Errorf("source port is required")
	}
	if spec.DstPort == 0 {
		return fmt.Errorf("destination port is required")
	}

	return nil
}

// Plan generates packet configs for a UDP flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		// Generate flow ID
		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		now := time.Now()

		// UDP Request (client -> server)
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
				Protocol: 17, // UDP
				TTL:      DefaultTTL,
			},
			L4: core.L4Config{
				Protocol: "udp",
				SrcPort:  spec.SrcPort,
				DstPort:  spec.DstPort,
			},
			Payload: spec.Payload,
		}

		// UDP Response (server -> client) if configured
		if spec.UDP != nil && spec.UDP.Response {
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
					Protocol: 17,
					TTL:      DefaultTTL,
				},
				L4: core.L4Config{
					Protocol: "udp",
					SrcPort:  spec.DstPort,
					DstPort:  spec.SrcPort,
				},
				Payload: spec.Payload, // Echo back for now
			}
		}
	}()

	return configChan, nil
}
