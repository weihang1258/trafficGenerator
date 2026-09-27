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
	// D-S7-85 §14 ②（G-S7-4）：sessions 域 1–16（基线 §8.9）。0 = 未设置
	// （生成器 n<1→1 缺省单会话），负值与 >16 拒绝——越界会按会话数线性
	// 展开包序列，静默放行即无界放大。
	if cfg.Sessions < 0 || cfg.Sessions > maxSessions {
		return fmt.Errorf("s7: invalid sessions %d", cfg.Sessions)
	}
	for _, c := range cfg.Commands {
		// D-S7-85 §14 ②（G-S7-2）：未知 kind 拒绝。此前 buildS7Pair 的
		// default 分支静默当 read，配置拼错（"reed"）产出的是合法 read 会话
		// ——假成功。空串是文档缺省（§1：缺省 kind 走 read 分支）。
		switch c.Kind {
		case "", kindRead, "write", "keepalive", "readsZL", "read_szl", "error":
		default:
			return fmt.Errorf("s7: unknown kind %q", c.Kind)
		}
		if c.ForceROSCTR != nil && *c.ForceROSCTR != rosctrJob && *c.ForceROSCTR != rosctrAckData && *c.ForceROSCTR != rosctrUserdata {
			return fmt.Errorf("s7: invalid rosctr %d", *c.ForceROSCTR)
		}
		if c.PadPDULen != nil && *c.PadPDULen {
			return fmt.Errorf("s7: invalid pdu length")
		}
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
	// P0b-2：commands 缺省(nil)时注入默认 read DB1；显式 `[]` 为 setup-only。
	if cfg.Commands == nil {
		copyCfg := *cfg
		copyCfg.Commands = []S7Command{{Kind: "read", Items: []S7Item{{Area: 0x84, DBNumber: 1, Address: 0, TransportSize: 4, Length: 1}}}}
		cfg = &copyCfg
	}
	if cfg.PDURef == 0 {
		copyCfg := *cfg
		copyCfg.PDURef = sessionBaseRef(cfg)
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
		cc := BuildConnectConfirm()
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
		nextRef := sessionBaseRef(cfg)
		for _, cmd := range cfg.Commands {
			nextRef++
			req, res, respond, err := buildS7Pair(cfg, cmd, nextRef)
			if err != nil {
				return
			}
			if req != nil && !emit(true, req, 0x18) {
				return
			}
			if !respond {
				continue
			}
			if !emit(false, res, 0x18) {
				return
			}
		}
		emit(true, nil, 0x11)
		emit(false, nil, 0x11)
	}()
	return out, nil
}
