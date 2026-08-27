package opcua

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

type Planner struct{}

func (Planner) Name() string { return "opcua" }

func (Planner) Validate(spec core.FlowSpec) error {
	cfg := spec.OPCUA
	if cfg == nil {
		// P0b-2：空配置不再报错——Generate/Plan 已默认化并产默认流
		// （security none + read + close）。允许 nil。
		return nil
	}
	mode := cfg.SecurityMode
	if mode == "" {
		mode = "none"
	}
	if mode != "none" && mode != "sign" {
		return fmt.Errorf("opcua: security_mode %q invalid", cfg.SecurityMode)
	}
	if cfg.Transport != "" && cfg.Transport != "tcp" {
		return fmt.Errorf("opcua: transport %q invalid", cfg.Transport)
	}
	if cfg.BadMessageSize {
		return fmt.Errorf("opcua: MessageSize is invalid")
	}
	if cfg.BadLength {
		return fmt.Errorf("opcua: String length is invalid")
	}
	if cfg.SkipChannel && cfg.Read {
		return fmt.Errorf("opcua: secureChannel is required before MSG Read")
	}
	return nil
}

func (p Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}
	if spec.OPCUA == nil {
		// P0b-2：空配置默认化（Generate 同款：security none + read + close）。
		spec.OPCUA = &core.OPCUAConfig{Read: true, Close: true}
	}
	cfg := *spec.OPCUA
	if cfg.SecurityMode == "" {
		cfg.SecurityMode = "none"
	}
	if !cfg.Read {
		cfg.Read = true
	}
	if !cfg.Close {
		cfg.Close = true
	}
	out := make(chan core.PacketConfig, 16)
	go func() {
		defer close(out)
		idx := uint64(0)
		emit := func(up bool, b []byte, flags uint8) bool {
			sip, dip, sp, dp := spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort
			if !up {
				sip, dip, sp, dp = dip, sip, dp, sp
			}
			select {
			case out <- core.PacketConfig{FlowID: "opcua", PacketIndex: idx, Direction: map[bool]string{true: "up", false: "down"}[up], L2: core.L2Config{EtherType: core.EtherTypeFor(sip)}, L3: core.L3Base(sip, dip, 6, 64, uint16(idx), spec), L4: core.L4Config{Protocol: "tcp", SrcPort: sp, DstPort: dp, Flags: flags, WindowSize: 65535}, Payload: b}:
				idx++
				return true
			case <-ctx.Done():
				return false
			}
		}
		if !emit(true, nil, 0x02) || !emit(false, nil, 0x12) || !emit(true, nil, 0x10) {
			return
		}
		for _, ev := range buildEvents(&cfg) {
			if !emit(ev.Up, ev.Bytes, 0x18) {
				return
			}
		}
		if !emit(true, nil, 0x11) || !emit(false, nil, 0x10) || !emit(false, nil, 0x11) || !emit(true, nil, 0x10) {
			return
		}
	}()
	return out, nil
}

func buildEvents(cfg *OPCUAConfig) []struct {
	Up    bool
	Bytes []byte
} {
	var out []struct {
		Up    bool
		Bytes []byte
	}
	add := func(up bool, b []byte) {
		out = append(out, struct {
			Up    bool
			Bytes []byte
		}{up, b})
	}
	hel, _ := BuildHEL(0)
	ack, _ := BuildACK()
	opn, _ := BuildOPN(false, cfg.SecurityMode)
	opnResp, _ := BuildOPN(true, cfg.SecurityMode)
	add(true, hel)
	add(false, ack)
	add(true, opn)
	add(false, opnResp)
	if cfg.Read {
		msg, _ := BuildMSG(false)
		msgResp, _ := BuildMSG(true)
		add(true, msg)
		add(false, msgResp)
	}
	if cfg.Close {
		clo, _ := BuildCLO(false)
		cloResp, _ := BuildCLO(true)
		add(true, clo)
		add(false, cloResp)
	}
	return out
}
