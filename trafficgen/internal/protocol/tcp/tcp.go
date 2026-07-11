// Package tcp implements the TCP protocol planner.
package tcp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// TCP flags.
	FlagFIN = 0x01
	FlagSYN = 0x02
	FlagRST = 0x04
	FlagPSH = 0x08
	FlagACK = 0x10
	FlagURG = 0x20

	// Default values.
	DefaultMSS        = 1460
	DefaultWindowSize = 65535
	DefaultTTL        = 64
)

// Planner implements the TCP protocol planner.
type Planner struct{}

// NewPlanner creates a new TCP planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string {
	return "tcp"
}

// Validate validates a TCP flow spec.
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

// Plan generates packet configs for a TCP flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		// Generate flow ID
		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		// Get TCP config
		tcpConfig := spec.TCP
		if tcpConfig == nil {
			tcpConfig = &core.TCPConfig{
				Handshake:   true,
				Termination: true,
				MSS:         DefaultMSS,
				WindowSize:  DefaultWindowSize,
			}
		}

		// Initialize sequence numbers
		clientSeq := uint32(1000)
		serverSeq := uint32(2000)
		packetIndex := uint64(0)
		ipID := uint16(1)

		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		winSize := uint16(65535)
		if tcpConfig.WindowSize > 0 {
			winSize = tcpConfig.WindowSize
		}

		// Resolve effective TTL from spec
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		now := time.Now()

		// TCP Handshake (SYN, SYN-ACK, ACK)
		if tcpConfig.Handshake {
			// SYN (client -> server)
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
				L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, effectiveTTL, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "tcp",
					SrcPort:  spec.SrcPort,
					DstPort:  spec.DstPort,
					Seq:      clientSeq,
					Flags:    FlagSYN,
					WindowSize: winSize,
				},
			}
			packetIndex++
			clientSeq++

			// SYN-ACK (server -> client)
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
				L3: core.L3Base(spec.DstIP, spec.SrcIP, 6, effectiveTTL, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "tcp",
					SrcPort:  spec.DstPort,
					DstPort:  spec.SrcPort,
					Seq:      serverSeq,
					Ack:      clientSeq,
					Flags:    FlagSYN | FlagACK,
					WindowSize: winSize,
				},
			}
			packetIndex++
			serverSeq++

			// ACK (client -> server)
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
				L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, effectiveTTL, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "tcp",
					SrcPort:  spec.SrcPort,
					DstPort:  spec.DstPort,
					Seq:      clientSeq,
					Ack:      serverSeq,
					Flags:    FlagACK,
					WindowSize: winSize,
				},
			}
			packetIndex++
		}

		// Data segments
		if len(spec.Payload) > 0 {
			// Segment payload based on MSS
			mss := int(tcpConfig.MSS)
			if mss == 0 {
				mss = DefaultMSS
			}

			payload := spec.Payload
			for len(payload) > 0 {
				segmentSize := len(payload)
				if segmentSize > mss {
					segmentSize = mss
				}

				// Data segment (client -> server)
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
					L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, effectiveTTL, nextIPID(), spec),
					L4: core.L4Config{
						Protocol: "tcp",
						SrcPort:  spec.SrcPort,
						DstPort:  spec.DstPort,
						Seq:      clientSeq,
						Ack:      serverSeq,
						Flags:    FlagPSH | FlagACK,
					WindowSize: winSize,
					},
					Payload: payload[:segmentSize],
				}
				packetIndex++
				clientSeq += uint32(segmentSize)
				payload = payload[segmentSize:]

				// ACK (server -> client)
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
					L3: core.L3Base(spec.DstIP, spec.SrcIP, 6, effectiveTTL, nextIPID(), spec),
					L4: core.L4Config{
						Protocol: "tcp",
						SrcPort:  spec.DstPort,
						DstPort:  spec.SrcPort,
						Seq:      serverSeq,
						Ack:      clientSeq,
						Flags:    FlagACK,
					WindowSize: winSize,
					},
				}
				packetIndex++
			}
		}

		// TCP Termination (FIN, ACK, FIN, ACK)
		if tcpConfig.Termination {
			// FIN (client -> server)
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
				L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, effectiveTTL, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "tcp",
					SrcPort:  spec.SrcPort,
					DstPort:  spec.DstPort,
					Seq:      clientSeq,
					Ack:      serverSeq,
					Flags:    FlagFIN | FlagACK,
					WindowSize: winSize,
				},
			}
			packetIndex++
			clientSeq++

			// ACK (server -> client)
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
				L3: core.L3Base(spec.DstIP, spec.SrcIP, 6, effectiveTTL, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "tcp",
					SrcPort:  spec.DstPort,
					DstPort:  spec.SrcPort,
					Seq:      serverSeq,
					Ack:      clientSeq,
					Flags:    FlagACK,
					WindowSize: winSize,
				},
			}
			packetIndex++

			// FIN (server -> client)
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
				L3: core.L3Base(spec.DstIP, spec.SrcIP, 6, effectiveTTL, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "tcp",
					SrcPort:  spec.DstPort,
					DstPort:  spec.SrcPort,
					Seq:      serverSeq,
					Ack:      clientSeq,
					Flags:    FlagFIN | FlagACK,
					WindowSize: winSize,
				},
			}
			packetIndex++
			serverSeq++

			// ACK (client -> server)
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
				L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, effectiveTTL, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "tcp",
					SrcPort:  spec.SrcPort,
					DstPort:  spec.DstPort,
					Seq:      clientSeq,
					Ack:      serverSeq,
					Flags:    FlagACK,
					WindowSize: winSize,
				},
			}
		}
	}()

	return configChan, nil
}

func init() {
	// Register in global registry
	// protocol.Register(NewPlanner())
}
