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

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}
		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(1)

		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		// UDP Request
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
			Payload: spec.Payload,
		}
		packetIndex++

		// UDP Response if configured
		if spec.UDP != nil && spec.UDP.Response {
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
				Payload: spec.Payload,
			}
		}
	}()

	return configChan, nil
}
