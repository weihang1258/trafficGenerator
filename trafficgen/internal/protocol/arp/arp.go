// Package arp implements the ARP protocol planner.
package arp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	DefaultTTL = 64

	// ARP operations.
	OperationRequest = 1
	OperationReply   = 2
)

// Planner implements the ARP protocol planner.
type Planner struct{}

// NewPlanner creates a new ARP planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string {
	return "arp"
}

// Validate validates an ARP flow spec.
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

	// Validate ARP config
	if spec.ARP == nil {
		return fmt.Errorf("ARP config is required")
	}

	return nil
}

// Plan generates packet configs for an ARP flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 16)

	go func() {
		defer close(configChan)

		// Generate flow ID
		flowID := fmt.Sprintf("arp-%s-%s", spec.SrcIP, spec.DstIP)

		now := time.Now()

		// Get ARP config
		arpConfig := spec.ARP
		if arpConfig == nil {
			arpConfig = &core.ARPConfig{
				Operation: OperationRequest,
			}
		}

		// Build ARP packet
		// ARP packet format:
		// Hardware type (2 bytes): 1 for Ethernet
		// Protocol type (2 bytes): 0x0800 for IPv4
		// Hardware address length (1 byte): 6 for MAC
		// Protocol address length (1 byte): 4 for IPv4
		// Operation (2 bytes): 1=request, 2=reply
		// Sender hardware address (6 bytes)
		// Sender protocol address (4 bytes)
		// Target hardware address (6 bytes)
		// Target protocol address (4 bytes)
		// Total: 28 bytes

		arpPacket := buildARPPacket(spec)

		// ARP Request (sender -> target)
		configChan <- core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: 0,
			Direction:   "up",
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    spec.SrcMAC,
				DstMAC:    "ff:ff:ff:ff:ff:ff", // Broadcast for request
				EtherType: 0x0806,               // ARP
			},
			L3: core.L3Config{
				Protocol: 0, // No L3 for ARP
			},
			L4: core.L4Config{
				Protocol: "arp",
			},
			Payload: arpPacket,
			Metadata: map[string]interface{}{
				"arp_operation": arpConfig.Operation,
			},
		}

		// ARP Reply if configured
		if arpConfig.Operation == OperationRequest {
			// Generate reply
			replyPacket := buildARPReply(spec)

			configChan <- core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: 1,
				Direction:   "down",
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    spec.DstMAC,
					DstMAC:    spec.SrcMAC,
					EtherType: 0x0806,
				},
				L3: core.L3Config{
					Protocol: 0,
				},
				L4: core.L4Config{
					Protocol: "arp",
				},
				Payload: replyPacket,
				Metadata: map[string]interface{}{
					"arp_operation": OperationReply,
				},
			}
		}
	}()

	return configChan, nil
}

// buildARPPacket builds an ARP packet.
func buildARPPacket(spec core.FlowSpec) []byte {
	// ARP packet is 28 bytes
	packet := make([]byte, 28)

	// Hardware type: Ethernet (1)
	packet[0] = 0x00
	packet[1] = 0x01

	// Protocol type: IPv4 (0x0800)
	packet[2] = 0x08
	packet[3] = 0x00

	// Hardware address length: 6 (MAC)
	packet[4] = 0x06

	// Protocol address length: 4 (IPv4)
	packet[5] = 0x04

	// Operation
	operation := uint16(OperationRequest)
	if spec.ARP != nil {
		operation = spec.ARP.Operation
	}
	packet[6] = byte(operation >> 8)
	packet[7] = byte(operation)

	// Sender hardware address (MAC)
	srcMAC, _ := net.ParseMAC(spec.SrcMAC)
	if len(srcMAC) == 6 {
		copy(packet[8:14], srcMAC)
	}

	// Sender protocol address (IP)
	srcIP := net.ParseIP(spec.SrcIP)
	if srcIP != nil {
		srcIP = srcIP.To4()
		if len(srcIP) == 4 {
			copy(packet[14:18], srcIP)
		}
	}

	// Target hardware address (MAC)
	// For request, this is 0
	if spec.ARP != nil && spec.ARP.TargetMAC != "" {
		dstMAC, _ := net.ParseMAC(spec.ARP.TargetMAC)
		if len(dstMAC) == 6 {
			copy(packet[18:24], dstMAC)
		}
	}

	// Target protocol address (IP)
	dstIP := net.ParseIP(spec.DstIP)
	if dstIP != nil {
		dstIP = dstIP.To4()
		if len(dstIP) == 4 {
			copy(packet[24:28], dstIP)
		}
	}

	return packet
}

// buildARPReply builds an ARP reply packet.
func buildARPReply(spec core.FlowSpec) []byte {
	packet := make([]byte, 28)

	// Hardware type: Ethernet
	packet[0] = 0x00
	packet[1] = 0x01

	// Protocol type: IPv4
	packet[2] = 0x08
	packet[3] = 0x00

	// Hardware address length
	packet[4] = 0x06

	// Protocol address length
	packet[5] = 0x04

	// Operation: Reply
	packet[6] = 0x00
	packet[7] = 0x02

	// Sender hardware address (original target)
	dstMAC, _ := net.ParseMAC(spec.DstMAC)
	if len(dstMAC) == 6 {
		copy(packet[8:14], dstMAC)
	}

	// Sender protocol address (original target IP)
	dstIP := net.ParseIP(spec.DstIP)
	if dstIP != nil {
		dstIP = dstIP.To4()
		if len(dstIP) == 4 {
			copy(packet[14:18], dstIP)
		}
	}

	// Target hardware address (original sender)
	srcMAC, _ := net.ParseMAC(spec.SrcMAC)
	if len(srcMAC) == 6 {
		copy(packet[18:24], srcMAC)
	}

	// Target protocol address (original sender IP)
	srcIP := net.ParseIP(spec.SrcIP)
	if srcIP != nil {
		srcIP = srcIP.To4()
		if len(srcIP) == 4 {
			copy(packet[24:28], srcIP)
		}
	}

	return packet
}
