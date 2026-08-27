package bgp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

type Planner struct{}

func (Planner) Name() string { return "bgp" }

func (Planner) Validate(spec core.FlowSpec) error {
	if spec.BGP == nil {
		// P0b-2：空配置不再报错——Plan 会默认化并产默认流（layers 数组路径
		// 下 layer config 为空/缺省时）。
		return nil
	}
	if spec.BGP.Transport != "" && spec.BGP.Transport != "tcp" {
		return fmt.Errorf("bgp: transport %q invalid; BGP requires tcp", spec.BGP.Transport)
	}
	if spec.Metadata != nil {
		if transport, ok := spec.Metadata["transport"].(string); ok && transport != "" && transport != "tcp" {
			return fmt.Errorf("bgp: transport %q invalid; BGP requires tcp", transport)
		}
	}
	return ValidateConfig(spec.BGP)
}

func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	bgpCfg := spec.BGP
	if bgpCfg == nil {
		bgpCfg = &BGPConfig{}
	}
	cfg := normalized(bgpCfg)
	open, err := BuildOpen(&cfg)
	if err != nil {
		return nil, err
	}
	ka, err := BuildKeepalive()
	if err != nil {
		return nil, err
	}
	out := make(chan core.PacketConfig, 16)
	go func() {
		defer close(out)
		idx := uint64(0)
		emit := func(up bool, payload []byte, flags uint8) bool {
			sip, dip, sp, dp := spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort
			if !up {
				sip, dip, sp, dp = dip, sip, dp, sp
			}
			select {
			case out <- core.PacketConfig{FlowID: "bgp", PacketIndex: idx, Direction: map[bool]string{true: "up", false: "down"}[up], L2: core.L2Config{EtherType: core.EtherTypeFor(sip)}, L3: core.L3Base(sip, dip, 6, 64, uint16(idx), spec), L4: core.L4Config{Protocol: "tcp", SrcPort: sp, DstPort: dp, Flags: flags, WindowSize: 65535}, Payload: payload}:
				idx++
				return true
			case <-ctx.Done():
				return false
			}
		}
		if !emit(true, nil, 2) || !emit(false, nil, 0x12) || !emit(true, nil, 0x10) {
			return
		}
		if !emit(true, open, 0x18) || !emit(false, open, 0x18) || !emit(true, ka, 0x18) || !emit(false, ka, 0x18) || !emit(true, ka, 0x18) || !emit(false, ka, 0x18) {
			return
		}
		emit(true, nil, 0x11)
		emit(false, nil, 0x11)
	}()
	return out, nil
}
