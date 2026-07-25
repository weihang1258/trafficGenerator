package icmp

import (
	"context"
	"fmt"
	"math/rand"
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
//
// Two emission modes:
//   - Single ping (legacy): when ICMPConfig.Pattern is empty, emit one Echo
//     Request and an auto-reply Echo Reply if Type=EchoRequest. The Sequence
//     and Identifier come from the top-level config fields. This preserves
//     pre-#51 behavior for existing configs.
//   - Multi-session ping: when Pattern is non-empty, iterate the steps and
//     emit each step as its own ping (Type/Code/Sequence/Data per step),
//     auto-replying Echo Request steps. The Identifier is shared across
//     steps (per RFC 792 session semantics: Identifier groups pings into
//     a session, Sequence increments per ping within the session). When
//     Identifier is 0, the per-step fallback uses step.Sequence for the
//     ID field (matching the single-ping fallback rule).
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		// Generate flow ID
		flowID := fmt.Sprintf("%s-%s-icmp", spec.SrcIP, spec.DstIP)

		// Resolve effective TTL from spec
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		now := time.Now()

		// IPID random start to avoid cross-flow ID collision.
		ipID := uint16(rand.Uint32())
		nextIPID := func() uint16 { id := ipID; ipID++; return id }

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

		// Resolve ICMP echo data bytes per the FileSource precedence
		// contract (mirrors FTP Task 11):
		//  1. icmpConfig.FileSource != nil -> PayloadCache.GetOrLoad(ctx, *icmpConfig.FileSource)
		//  2. else icmpConfig.Data (inline)
		//
		// When FileSource is set but no cache is injected, we use the
		// inline Data (do NOT silently fall through to empty). This is
		// the "set Data derived from bytes if Data is nil" caveat from
		// the brief: it applies when FileSource is nil — don't override
		// user-set Data with empty bytes. When FileSource is non-nil,
		// FileSource wins (matches FTP precedence). Production engine
		// (Task 13) always injects the cache.
		//
		// We resolve ONCE here so both the multi-session path and the
		// legacy single-ping path see the same bytes (the multi-session
		// path's per-step Data still wins for steps that set Data
		// explicitly; the top-level FileSource only applies when a step
		// leaves Data nil).
		echoData := icmpConfig.Data
		if icmpConfig.FileSource != nil {
			pc := core.PayloadCacheFrom(ctx)
			if pc != nil {
				if bytes, err := pc.GetOrLoad(ctx, *icmpConfig.FileSource); err == nil {
					echoData = bytes
				}
			}
		}

		// Multi-session ping path: iterate steps, emit each as its own ping
		// with auto-reply for Echo Request steps. Identifier is shared across
		// steps (RFC 792 session semantics). Sequence auto-fills from step
		// index (1-based) when the step leaves Sequence at 0.
		//
		// FileSource precedence for steps: when step.Data is nil, fall
		// back to the top-level resolved echoData (which itself honors
		// icmpConfig.FileSource). When step.Data is non-nil, the step's
		// own bytes win (per-step override). This mirrors the brief's
		// "set Data derived from bytes if Data is nil" caveat.
		if len(icmpConfig.Pattern) > 0 {
			packetIndex := uint64(0)
			for stepIdx, step := range icmpConfig.Pattern {
				seq := step.Sequence
				if seq == 0 {
					seq = uint16(stepIdx + 1)
				}
				stepData := step.Data
				if stepData == nil {
					stepData = echoData
				}
				stepCfg := &core.ICMPConfig{
					Type:       step.Type,
					Code:       step.Code,
					Identifier: icmpConfig.Identifier,
					Sequence:   seq,
					Data:       stepData,
				}
				// Emit the step as an up packet (client -> server).
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
					L3: core.L3Base(spec.SrcIP, spec.DstIP, 1, effectiveTTL, nextIPID(), spec),
					L4: core.L4Config{Protocol: "icmp"},
					Payload: buildICMPPayload(stepCfg),
					Metadata: map[string]interface{}{
						"icmp_type": stepCfg.Type,
						"icmp_code": stepCfg.Code,
					},
				}
				packetIndex++

				// Auto-reply Echo Reply for Echo Request steps.
				if step.Type == TypeEchoRequest {
					replyCfg := &core.ICMPConfig{
						Type:       TypeEchoReply,
						Code:       0,
						Identifier: icmpConfig.Identifier,
						Sequence:   seq,
						Data:       stepData,
					}
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
						L3: core.L3Base(spec.DstIP, spec.SrcIP, 1, effectiveTTL, nextIPID(), spec),
						L4: core.L4Config{Protocol: "icmp"},
						Payload: buildICMPPayload(replyCfg),
						Metadata: map[string]interface{}{
							"icmp_type": replyCfg.Type,
							"icmp_code": replyCfg.Code,
						},
					}
					packetIndex++
				}
			}
			return
		}

		// Legacy single-ping path.
		// ICMP Echo Request (client -> server). The echoData resolved
		// above (honoring FileSource) overrides the inline Data for
		// both the request and the auto-reply.
		reqConfig := &core.ICMPConfig{
			Type:       icmpConfig.Type,
			Code:       icmpConfig.Code,
			Identifier: icmpConfig.Identifier,
			Sequence:   icmpConfig.Sequence,
			Data:       echoData,
		}
		configChan <- core.PacketConfig{
			FlowID:      flowID,
			PacketIndex: 0,
			Direction:   "up",
			Timestamp:   now,
			L2: core.L2Config{
				SrcMAC:    spec.SrcMAC,
				DstMAC:    spec.DstMAC,
				EtherType: core.EtherTypeFor(spec.SrcIP),
			},
			L3: core.L3Base(spec.SrcIP, spec.DstIP, 1, effectiveTTL, nextIPID(), spec),
			L4: core.L4Config{
				Protocol: "icmp",
			},
			Payload: buildICMPPayload(reqConfig),
			Metadata: map[string]interface{}{
				"icmp_type": reqConfig.Type,
				"icmp_code": reqConfig.Code,
			},
		}

		// ICMP Echo Reply (server -> client) if Echo Request
		if icmpConfig.Type == TypeEchoRequest {
			replyConfig := &core.ICMPConfig{
				Type:       TypeEchoReply,
				Code:       0,
				Identifier: icmpConfig.Identifier,
				Sequence:   icmpConfig.Sequence,
				Data:       echoData,
			}

			configChan <- core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: 1,
				Direction:   "down",
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    spec.DstMAC,
					DstMAC:    spec.SrcMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3: core.L3Base(spec.DstIP, spec.SrcIP, 1, effectiveTTL, nextIPID(), spec),
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
//
// RFC 792: Echo Request/Reply header is Type(1) + Code(1) + Checksum(2) +
// Identifier(2) + Sequence(2) = 8 bytes. Identifier and Sequence are
// independent fields — Identifier groups pings into a session, Sequence
// increments per ping within the session.
//
// Backward compatibility: when config.Identifier == 0, we fall back to the
// pre-Identifier-field behavior of using Sequence as the Identifier (so
// request and reply within a single ping share the Identifier = Sequence
// value). Callers that need distinct values must set Identifier to non-zero.
func buildICMPPayload(config *core.ICMPConfig) []byte {
	// ICMP header: Type (1) + Code (1) + Checksum (2) + ID (2) + Sequence (2) = 8 bytes
	header := make([]byte, 8)
	header[0] = config.Type
	header[1] = config.Code
	// Checksum will be calculated later

	// Identifier (bytes 4-5). Fall back to Sequence when Identifier is 0 to
	// preserve the pre-field behavior (request and reply within a single ping
	// shared the same value).
	identifier := config.Identifier
	if identifier == 0 {
		identifier = config.Sequence
	}
	header[4] = byte(identifier >> 8)
	header[5] = byte(identifier)

	// Sequence (bytes 6-7) — independent of Identifier.
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