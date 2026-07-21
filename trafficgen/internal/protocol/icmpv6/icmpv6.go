// Package icmpv6 implements the ICMPv6 protocol planner (RFC 4443).
//
// ICMPv6 is the IPv6 equivalent of ICMP. The planner supports the Echo
// Request/Reply message pair (types 128/129), which is the IPv6 ping
// mechanism. Like ICMPv4, an Echo Request carries an Identifier (session
// ID) and a Sequence (per-ping counter); the reply echoes both fields.
//
// ICMPv6 checksum is computed over the IPv6 pseudo-header + ICMPv6 message
// (RFC 8200 §8.1), NOT over the IPv4-style pseudo-header. The planner
// builds the pseudo-header from src/dst IP and the ICMPv6 message length,
// then folds in the ICMPv6 bytes.
//
// Two emission modes mirror the ICMPv4 planner:
//   - Single ping (legacy): when Pattern is empty, emit one Echo Request
//     and an auto-reply Echo Reply if Type=EchoRequest.
//   - Multi-session ping: when Pattern is non-empty, iterate the steps
//     and emit each as its own ping with auto-reply. Identifier is shared
//     across steps (RFC 4443 session semantics).
package icmpv6

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

	// ICMPv6 types (RFC 4443).
	TypeEchoRequestV6 = 128
	TypeEchoReplyV6   = 129

	// ProtocolICMPv6 is the IPv6 Next Header value for ICMPv6.
	ProtocolICMPv6 = 58
)

// Planner implements the ICMPv6 protocol planner.
type Planner struct{}

// NewPlanner creates a new ICMPv6 planner.
func NewPlanner() *Planner {
	return &Planner{}
}

// Name returns the protocol name.
func (p *Planner) Name() string {
	return "icmpv6"
}

// Validate validates an ICMPv6 flow spec. IPv6 addresses are required for
// ICMPv6 (the planner emits EtherType=0x86DD and the IPv6 pseudo-header
// checksum); an IPv4 address would produce a zero checksum and an IPv4
// Ethernet frame, which is not a valid ICMPv6 packet.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		ip := net.ParseIP(spec.SrcIP)
		if ip == nil {
			return fmt.Errorf("invalid source IP: %s", spec.SrcIP)
		}
		if ip.To4() != nil && ip.To16() == nil {
			return fmt.Errorf("source IP must be IPv6: %s", spec.SrcIP)
		}
		if ip.To4() != nil {
			return fmt.Errorf("source IP must be IPv6 (got IPv4): %s", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		ip := net.ParseIP(spec.DstIP)
		if ip == nil {
			return fmt.Errorf("invalid destination IP: %s", spec.DstIP)
		}
		if ip.To4() != nil {
			return fmt.Errorf("destination IP must be IPv6 (got IPv4): %s", spec.DstIP)
		}
	}
	return nil
}

// Plan generates packet configs for an ICMPv6 flow. See the package doc
// for the two emission modes. The IPv6 EtherType (0x86DD) and Next Header
// (58) are set on every packet; the IPv6 header itself is written by the
// Builder's writeL3v6 path (selected by EtherType).
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-icmpv6", spec.SrcIP, spec.DstIP)

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		now := time.Now()

		// IPID random start — IPv6 has no IPID, but the L3Config.IPID field
		// is reused by the IPv4 path. For IPv6 we leave it 0 (the IPv6
		// header does not carry an IPID). Kept here only to mirror the
		// ICMPv4 planner's structure in case future code reads it.
		_ = uint16(rand.Uint32())

		// ICMPv6 config defaults.
		icmpConfig := spec.ICMPv6
		if icmpConfig == nil {
			icmpConfig = &core.ICMPv6Config{
				Type:     TypeEchoRequestV6,
				Code:     0,
				Sequence: 1,
				Data:     []byte("ping"),
			}
		}

		// Multi-session ping path.
		if len(icmpConfig.Pattern) > 0 {
			packetIndex := uint64(0)
			for stepIdx, step := range icmpConfig.Pattern {
				seq := step.Sequence
				if seq == 0 {
					seq = uint16(stepIdx + 1)
				}
				stepCfg := &core.ICMPv6Config{
					Type:       step.Type,
					Code:       step.Code,
					Identifier: icmpConfig.Identifier,
					Sequence:   seq,
					Data:       step.Data,
				}
				configChan <- p.buildPacket(
					spec, flowID, packetIndex, "up",
					spec.SrcIP, spec.DstIP, spec.SrcMAC, spec.DstMAC,
					effectiveTTL, now, stepCfg,
				)
				packetIndex++

				if step.Type == TypeEchoRequestV6 {
					replyCfg := &core.ICMPv6Config{
						Type:       TypeEchoReplyV6,
						Code:       0,
						Identifier: icmpConfig.Identifier,
						Sequence:   seq,
						Data:       step.Data,
					}
					configChan <- p.buildPacket(
						spec, flowID, packetIndex, "down",
						spec.DstIP, spec.SrcIP, spec.DstMAC, spec.SrcMAC,
						effectiveTTL, now, replyCfg,
					)
					packetIndex++
				}
			}
			return
		}

		// Legacy single-ping path.
		configChan <- p.buildPacket(
			spec, flowID, 0, "up",
			spec.SrcIP, spec.DstIP, spec.SrcMAC, spec.DstMAC,
			effectiveTTL, now, icmpConfig,
		)

		if icmpConfig.Type == TypeEchoRequestV6 {
			replyConfig := &core.ICMPv6Config{
				Type:       TypeEchoReplyV6,
				Code:       0,
				Identifier: icmpConfig.Identifier,
				Sequence:   icmpConfig.Sequence,
				Data:       icmpConfig.Data,
			}
			configChan <- p.buildPacket(
				spec, flowID, 1, "down",
				spec.DstIP, spec.SrcIP, spec.DstMAC, spec.SrcMAC,
				effectiveTTL, now, replyConfig,
			)
		}
	}()

	return configChan, nil
}

// buildPacket constructs one ICMPv6 PacketConfig. srcIP/dstIP/srcMAC/dstMAC
// are passed explicitly because the reply swaps them. The ICMPv6 payload
// (Type + Code + Checksum + Identifier + Sequence + Data) is built here,
// including the pseudo-header checksum.
func (p *Planner) buildPacket(
	spec core.FlowSpec,
	flowID string,
	packetIndex uint64,
	direction string,
	srcIP, dstIP, srcMAC, dstMAC string,
	ttl uint8,
	ts time.Time,
	cfg *core.ICMPv6Config,
) core.PacketConfig {
	payload := buildICMPv6Payload(srcIP, dstIP, cfg)
	return core.PacketConfig{
		FlowID:      flowID,
		PacketIndex: packetIndex,
		Direction:   direction,
		Timestamp:   ts,
		L2: core.L2Config{
			SrcMAC:    srcMAC,
			DstMAC:    dstMAC,
			EtherType: core.EtherTypeIPv6,
		},
		L3: core.L3Base(srcIP, dstIP, ProtocolICMPv6, ttl, 0, spec),
		L4: core.L4Config{Protocol: "icmpv6"},
		Payload: payload,
		Metadata: map[string]interface{}{
			"icmpv6_type": cfg.Type,
			"icmpv6_code": cfg.Code,
		},
	}
}

// buildICMPv6Payload builds the ICMPv6 message: Type(1) + Code(1) +
// Checksum(2) + Identifier(2) + Sequence(2) + Data. The checksum is
// computed over the IPv6 pseudo-header + this message (with checksum=0).
//
// Identifier fallback: when config.Identifier == 0, fall back to Sequence
// (matches ICMPv4 behavior — preserves the pre-Identifier-field invariant
// that request and reply within a single ping share the same value).
func buildICMPv6Payload(srcIP, dstIP string, config *core.ICMPv6Config) []byte {
	header := make([]byte, 8)
	header[0] = config.Type
	header[1] = config.Code
	// Checksum filled in after the full message is assembled.

	identifier := config.Identifier
	if identifier == 0 {
		identifier = config.Sequence
	}
	binary.BigEndian.PutUint16(header[4:6], identifier)
	binary.BigEndian.PutUint16(header[6:8], config.Sequence)

	msg := make([]byte, 0, 8+len(config.Data))
	msg = append(msg, header...)
	msg = append(msg, config.Data...)

	checksum := calculateICMPv6Checksum(srcIP, dstIP, msg)
	binary.BigEndian.PutUint16(msg[2:4], checksum)

	return msg
}

// calculateICMPv6Checksum computes the ICMPv6 checksum per RFC 4443 §2.3:
// the one's-complement sum of the IPv6 pseudo-header + the ICMPv6 message
// (with the checksum field treated as zero). Returns 0 when srcIP or dstIP
// is not a valid IPv6 address — this matches IPv4's behavior of zeroing
// the checksum on invalid input rather than crashing the planner.
func calculateICMPv6Checksum(srcIP, dstIP string, msg []byte) uint16 {
	pseudo := core.CalculateIPv6PseudoHeader(srcIP, dstIP, len(msg), ProtocolICMPv6)
	if pseudo == nil {
		return 0
	}
	sum := uint32(0)
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	// ICMPv6 message: skip bytes 2-3 (checksum field, treated as zero).
	for i := 0; i < len(msg); i += 2 {
		if i == 2 {
			continue
		}
		if i+2 <= len(msg) {
			sum += uint32(binary.BigEndian.Uint16(msg[i : i+2]))
		} else {
			sum += uint32(msg[i]) << 8
		}
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return ^uint16(sum)
}
