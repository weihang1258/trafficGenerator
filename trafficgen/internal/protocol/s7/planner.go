package s7

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

type Planner struct{}

func (p Planner) Name() string { return "s7" }
func (p Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.S7
	if cfg == nil {
		// P0b-2：空配置不再报错——Plan 会默认化并产默认流（layers 数组路径
		// 下 layer config 为空/缺省时）。Plan(28) 的 cfg==nil 分支已补默认。
		return nil
	}
	if cfg.Transport != "" && cfg.Transport != transportTCP {
		return fmt.Errorf("s7: transport %q is invalid", cfg.Transport)
	}
	for _, c := range cfg.Commands {
		if err := validateCommand(c); err != nil {
			return err
		}
	}
	return nil
}
func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	cfg := spec.S7
	if cfg == nil {
		cfg = &S7Config{Transport: "tcp"}
	}
	if len(cfg.Commands) == 0 {
		copyCfg := *cfg
		copyCfg.Commands = []S7Command{{Kind: "read", Items: []S7Item{{Area: 0x84, DBNumber: 1, Address: 0, TransportSize: 4, Length: 1}}}}
		cfg = &copyCfg
	}
	out := make(chan core.PacketConfig, 16)
	go func() {
		defer close(out)
		idx := uint64(0)
		emit := func(up bool, payload []byte, flags uint8) bool {
			sip, dip := spec.SrcIP, spec.DstIP
			sp, dp := spec.SrcPort, spec.DstPort
			if !up {
				sip, dip = dip, sip
				sp, dp = dp, sp
			}
			select {
			case out <- core.PacketConfig{FlowID: "s7", PacketIndex: idx, Direction: map[bool]string{true: "up", false: "down"}[up], L2: core.L2Config{EtherType: core.EtherTypeFor(sip)}, L3: core.L3Base(sip, dip, 6, 64, uint16(idx), spec), L4: core.L4Config{Protocol: "tcp", SrcPort: sp, DstPort: dp, Flags: flags, WindowSize: 65535}, Payload: payload}:
				idx++
				return true
			case <-ctx.Done():
				return false
			}
		}
		if !emit(true, nil, 2) || !emit(false, nil, 0x12) || !emit(true, nil, 0x10) {
			return
		}
		cr, _ := BuildConnectionRequest(cfg)
		if !emit(true, cr, 0x18) {
			return
		}
		cc := []byte{0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x00, 0x01, 0x00}
		if !emit(false, cc, 0x12) || !emit(true, nil, 0x10) {
			return
		}
		setup, _ := BuildSetup(cfg, false)
		if !emit(true, setup, 0x18) {
			return
		}
		setupResp, _ := BuildSetup(cfg, true)
		if !emit(false, setupResp, 0x18) {
			return
		}
		for _, cmd := range cfg.Commands {
			var msg []byte
			if cmd.Kind == "write" {
				msg, _ = BuildWrite(cfg, cmd)
			} else {
				msg, _ = BuildRead(cfg, cmd)
			}
			if !emit(true, msg, 0x18) {
				return
			}
			if !emit(false, msg, 0x18) {
				return
			}
		}
		emit(true, nil, 0x11)
		emit(false, nil, 0x11)
	}()
	return out, nil
}
