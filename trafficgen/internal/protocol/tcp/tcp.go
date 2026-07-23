// Package tcp implements the TCP protocol planner.
package tcp

import (
	"context"
	"fmt"
	"math/rand"
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

	// Validate MSS range. RFC 879: minimum MSS is 536 (IP header 20 + TCP
	// header 20 + 536 = 576 byte minimum packet). uint16 max is 65535.
	// Out-of-range MSS produces malformed SYNs or oversized frames.
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < 536 {
			return fmt.Errorf("MSS %d too small (min 536 per RFC 879)", spec.TCP.MSS)
		}
		if spec.TCP.MSS > 65535 {
			return fmt.Errorf("MSS %d too large (max 65535)", spec.TCP.MSS)
		}
	}

	return nil
}

// Plan generates packet configs for a TCP flow.
// synOptions builds TCP options for SYN packets: MSS, Window Scale, and
// SACK-Permitted, matching real-world SYN capture characteristics.
// MSS=0 is normalized to DefaultMSS by callers so the SYN always carries a
// valid MSS option (RFC 879: MSS=0 in SYN is misinterpreted as 536 by some
// stacks).
func synOptions(mss uint16) []core.TCPOption {
	if mss == 0 {
		mss = DefaultMSS
	}
	opts := make([]core.TCPOption, 0, 3)
	opts = append(opts, core.TCPOption{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}})
	// Window Scale option (RFC 7323): shift count 7 expands the 16-bit
	// window field to 65535 << 7 = ~8MB, enough for high-bandwidth paths.
	opts = append(opts, core.TCPOption{Kind: core.TCPOptWinScale, Data: []byte{0x07}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptSACKPermit})
	return opts
}

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

		// Initialize sequence numbers. Random per flow to avoid seq collisions
		// across flows (real TCP randomizes ISN per RFC 6528). User can override
		// client seq via spec.TCP.InitialSeq for reproducible tests.
		clientSeq := uint32(0)
		if spec.TCP != nil {
			clientSeq = spec.TCP.InitialSeq
		}
		if clientSeq == 0 {
			clientSeq = rand.Uint32()
		}
		serverSeq := rand.Uint32()
		packetIndex := uint64(0)
		// IPID random start to avoid cross-flow ID collision.
		ipID := uint16(rand.Uint32())

		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		winSize := uint16(65535)
		if tcpConfig.WindowSize > 0 {
			winSize = tcpConfig.WindowSize
		}

		synOpts := synOptions(tcpConfig.MSS)

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
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3: core.L3Base(spec.SrcIP, spec.DstIP, 6, effectiveTTL, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "tcp",
					SrcPort:  spec.SrcPort,
					DstPort:  spec.DstPort,
					Seq:      clientSeq,
					Flags:    FlagSYN,
					WindowSize: winSize,
					TCPOptions: synOpts,
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
					EtherType: core.EtherTypeFor(spec.SrcIP),
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
					TCPOptions: synOpts,
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
					EtherType: core.EtherTypeFor(spec.SrcIP),
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
						EtherType: core.EtherTypeFor(spec.SrcIP),
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
						EtherType: core.EtherTypeFor(spec.SrcIP),
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
					EtherType: core.EtherTypeFor(spec.SrcIP),
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
					EtherType: core.EtherTypeFor(spec.SrcIP),
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
					EtherType: core.EtherTypeFor(spec.SrcIP),
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
					EtherType: core.EtherTypeFor(spec.SrcIP),
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
