package ldp

import (
	"context"
	"fmt"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner plans LDP traffic (RFC 5036) over UDP or TCP.
type Planner struct{}

func (Planner) Name() string { return "ldp" }

func (Planner) Validate(spec core.FlowSpec) error {
	if spec.LDP == nil {
		return fmt.Errorf("ldp: config is required")
	}
	return ValidateConfig(spec.LDP)
}

func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.DstPort == 0 {
		spec.DstPort = 646
	}
	cfg := spec.LDP
	carrier := cfg.Carrier
	if carrier == "" {
		carrier = "tcp_session"
	}

	payloads, ups, err := parseLDPConfig(cfg)
	if err != nil {
		return nil, err
	}

	out := make(chan core.PacketConfig, 32)
	go func() {
		defer close(out)
		idx := uint64(0)
		emit := func(up bool, payload []byte, flags uint8, srcPort uint16) bool {
			sip, dip, sp, dp := spec.SrcIP, spec.DstIP, srcPort, spec.DstPort
			dir := "up"
			if !up {
				sip, dip, sp, dp = dip, sip, dp, sp
				dir = "down"
			}
			proto := "tcp"
			if carrier == "udp_discovery" {
				proto = "udp"
			}
			select {
			case out <- core.PacketConfig{
				FlowID:      "ldp",
				PacketIndex: idx,
				Direction:   dir,
				L2:          core.L2Config{EtherType: core.EtherTypeFor(sip)},
				L3:          core.L3Base(sip, dip, 6, 64, uint16(idx), spec),
				L4:          core.L4Config{Protocol: proto, SrcPort: sp, DstPort: dp, Flags: flags, WindowSize: 65535},
				Payload:     payload,
				Timestamp:   time.Now(),
			}:
				idx++
				return true
			case <-ctx.Done():
				return false
			}
		}

		runSession := func(srcPort uint16) bool {
			// TCP handshake
			if carrier == "tcp_session" {
				if !emit(true, nil, 0x02, srcPort) || !emit(false, nil, 0x12, srcPort) || !emit(true, nil, 0x10, srcPort) {
					return false
				}
			}
			// Messages
			for i, pdu := range payloads {
				flags := uint8(0x18) // PSH|ACK
				if carrier == "udp_discovery" {
					flags = 0
				}
				if !emit(ups[i], pdu, flags, srcPort) {
					return false
				}
			}
			// TCP teardown
			if carrier == "tcp_session" {
				emit(true, nil, 0x11, srcPort)
				emit(false, nil, 0x10, srcPort)
				emit(false, nil, 0x11, srcPort)
				emit(true, nil, 0x10, srcPort)
			}
			return true
		}

		runSession(spec.SrcPort)
	}()
	return out, nil
}

// normalizeLDPConfig normalizes LDP config defaults.
func normalizeLDPConfig(cfg *core.LDPConfig) {
	if cfg == nil {
		return
	}
	if cfg.LSRID == "" {
		cfg.LSRID = "192.0.2.1"
	}
	if cfg.HoldTime == 0 {
		cfg.HoldTime = 15
	}
	if cfg.KeepaliveTime == 0 {
		cfg.KeepaliveTime = 30
	}
	if cfg.LabelAdvertisement == "" {
		cfg.LabelAdvertisement = "downstream_unsolicited"
	}
}