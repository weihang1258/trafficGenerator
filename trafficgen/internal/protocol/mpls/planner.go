// Package mpls implements the MPLS (MultiProtocol Label Switching, 多协议
// 标签交换, RFC 3031/3032) planner. It emits labeled packets — the data
// plane of an LSP (Label Switched Path):
//
//	Ethernet (optional VLAN, EtherType 0x8847/0x8848) + label stack +
//	inner IPv4/IPv6 packet (TCP/UDP with correct checksums)
//
// MPLS has no control-plane session to model (LDP/RSVP signaling is out of
// scope — trafficgen emits the data plane only): the planner decides which
// labeled packets to emit, what the inner packet carries, and the label
// stack (one 4-byte entry per level, RFC 3032 §3.1).
//
// The core builder writes the label stack (forced EtherType 0x8847 unicast
// / 0x8848 multicast, S bit auto-corrected on the bottom entry, TTL 0 → 64)
// from the per-packet L2Config.MPLS and writes the inner L3/L4 normally
// after it — the inner IP header is written with no MPLS awareness, exactly
// like the unlabeled case.
package mpls

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner emits MPLS label-stack packet configs for an LSP data flow.
type Planner struct{}

// NewPlanner returns a new MPLS planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name used by the registry.
func (p *Planner) Name() string { return "mpls" }

// Validate validates an MPLS flow spec (read-only per validate_conventions.md
// §1.1: never mutate spec, never fill defaults — Plan handles defaults).
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.MPLS == nil {
		return fmt.Errorf("mpls: MPLS config is required")
	}
	cfg := spec.MPLS

	// The labeled packet's IPs must parse when set (empty = planner default
	// filled by Plan). Both IPv4 and IPv6 are valid inner layers (RFC 3032
	// §3.9: MPLS labels any IP packet).
	for _, pair := range []struct {
		name string
		val  string
	}{{"SrcIP", spec.SrcIP}, {"DstIP", spec.DstIP}} {
		if pair.val == "" {
			continue
		}
		if net.ParseIP(pair.val) == nil {
			return fmt.Errorf("mpls: %s %q is not a valid IP address", pair.name, pair.val)
		}
	}

	if len(cfg.Labels) == 0 {
		return fmt.Errorf("mpls: label stack must contain at least one entry (RFC 3032 §2.1)")
	}
	for i, l := range cfg.Labels {
		if l.Label > 0xFFFFF {
			return fmt.Errorf("mpls: label %d (entry %d) exceeds 20 bits (max 0xFFFFF, RFC 3032 §3.1)", l.Label, i)
		}
		if l.TC > 7 {
			return fmt.Errorf("mpls: TC %d (entry %d) exceeds 3 bits (max 7, RFC 5462)", l.TC, i)
		}
		if l.S && i != len(cfg.Labels)-1 {
			return fmt.Errorf("mpls: S=true on entry %d but it is not the bottom of stack (only the last entry may set S, RFC 3032 §2.1)", i)
		}
	}

	switch cfg.InnerProto {
	case 0, 6, 17:
		// ok (0 = auto: TCP when spec.TCP is set, else UDP)
	default:
		return fmt.Errorf("mpls: InnerProto %d not in supported list (allowed: 6=TCP, 17=UDP)", cfg.InnerProto)
	}

	if cfg.Frames < 0 {
		return fmt.Errorf("mpls: Frames %d must be >= 0", cfg.Frames)
	}

	switch cfg.Direction {
	case "", "up", "down":
		// ok
	default:
		return fmt.Errorf("mpls: Direction %q not in supported list (allowed: up, down)", cfg.Direction)
	}

	return nil
}

// Plan emits the labeled packets of the LSP data flow. spec.SrcIP/DstIP/
// SrcMAC/DstMAC are the labeled packet's addresses (the inner L3 header is
// the flow's own packet — MPLS labels a packet in place, RFC 3031 §3.12).
// "up" = client side; "down" swaps the MACs and IPs. Each frame gets a
// distinct inner IP ID. The label stack (MPLSConfig.Labels) is identical
// for every frame; the per-entry TTL defaults to 64 and the bottom entry's
// S bit is auto-corrected to true by the builder.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	configChan := make(chan core.PacketConfig, 256)
	cfg := spec.MPLS

	// Resolve defaults before launching the goroutine (deterministic,
	// same values every frame).
	innerProto := cfg.InnerProto
	if innerProto == 0 {
		if spec.TCP != nil {
			innerProto = 6
		} else {
			innerProto = 17
		}
	}
	frames := cfg.Frames
	if frames == 0 {
		frames = 1
	}
	dir := cfg.Direction
	if dir == "" {
		dir = "up"
	}
	innerPayload := cfg.InnerPayload
	if innerPayload == nil {
		innerPayload = spec.Payload
	}
	// Resolve the label stack once (TTL 0 → 64) so every frame carries the
	// same wire bytes; the builder would default 0 → 64 anyway, but the
	// emitted config should already hold the resolved values.
	labels := make([]core.MPLSLabel, len(cfg.Labels))
	for i, l := range cfg.Labels {
		if l.TTL == 0 {
			l.TTL = core.DefaultMPLSTTL
		}
		labels[i] = l
	}

	go func() {
		defer close(configChan)
		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
		now := time.Now()

		packetIndex := uint64(0)
		emit := func(cfgOut core.PacketConfig) bool {
			cfgOut.FlowID = flowID
			cfgOut.PacketIndex = packetIndex
			cfgOut.Timestamp = now
			select {
			case configChan <- cfgOut:
				packetIndex++
				return true
			case <-ctx.Done():
				return false
			}
		}

		ipidCounter := uint32(0)
		nextIPID := func() uint16 {
			ipidCounter++
			return uint16(ipidCounter)
		}

		for i := 0; i < frames; i++ {
			if err := ctx.Err(); err != nil {
				return
			}
			// Direction: "up" = client side, "down" = swapped.
			srcIP, dstIP := spec.SrcIP, spec.DstIP
			srcMAC, dstMAC := spec.SrcMAC, spec.DstMAC
			if dir == "down" {
				srcIP, dstIP = dstIP, srcIP
				srcMAC, dstMAC = dstMAC, srcMAC
			}

			// Per-frame MPLS config: same label stack every frame.
			mplsCfg := *cfg
			mplsCfg.Labels = labels

			var l4 core.L4Config
			if innerProto == 6 {
				l4 = core.L4Config{
					Protocol: "tcp",
					SrcPort:  spec.SrcPort,
					DstPort:  spec.DstPort,
				}
				if spec.TCP != nil {
					l4.Seq = spec.TCP.Seq
					l4.Ack = spec.TCP.Ack
					l4.Flags = spec.TCP.Flags
					l4.WindowSize = spec.TCP.WindowSize
				}
			} else {
				l4 = core.L4Config{
					Protocol: "udp",
					SrcPort:  spec.SrcPort,
					DstPort:  spec.DstPort,
				}
			}

			cfgOut := core.PacketConfig{
				Direction: dir,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(srcIP), // inner L3 selector
					MPLS:      &mplsCfg,
				},
				L3: core.L3Base(srcIP, dstIP, innerProto, spec.TTL, nextIPID(), spec),
				L4: l4,
				// Inner payload: the labeled packet's L4 payload.
				Payload: innerPayload,
			}
			if !emit(cfgOut) {
				return
			}
		}
	}()

	return configChan, nil
}
