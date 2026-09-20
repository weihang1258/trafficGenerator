// Package xmpp: layer-chain wiring (D-XMPP-1 裁定1). The raw-IP chain
// terminal generator wraps the legacy Planner.Plan (单一真相：XML 流开/
// features/SASL 四机制认证/流重启/资源绑定/会话建立/presence/messages/
// 流关闭 + 自建 TCP 握手挥手全套复用，零分叉) and re-emits each packet
// through the raw-IP drive branch.
//
// 方向处理（防双换，vnc/pptp 同款）：legacy Plan 对方向已在包内部完成
// 换向并置 Direction="down"；raw-IP drive 的 Emit 包装对 "down" 包会再
// 换一次 L3 地址。本生成器统一把每包 Direction 改写为 "up" 后转 Emit。
// 控制通道 5222 由链路径 DstPort switch 缺省（legacy Plan 无内部缺省，
// 缺省住 flat setDefaultDstPort——xmpp 与 pptp 唯一差异）。
package xmpp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// XMPPGenerator is the xmpp raw-IP terminal-layer generator (D-XMPP-1).
type XMPPGenerator struct{}

func (g *XMPPGenerator) Name() string                     { return "xmpp" }
func (g *XMPPGenerator) GenEvents() layers.EventGenerator { return nil }

// Generate emits the configured XMPP session via req.Emit (raw-IP chain).
func (g *XMPPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("xmpp generator: Emit is nil")
	}
	cfg := req.Meta.Xmpp
	if cfg == nil {
		// 空层 config 已由翻译分支保底非 nil，此分支仅防引擎直调绕过翻译。
		cfg = &core.XmppConfig{}
	}
	spec := core.FlowSpec{
		Xmpp:      cfg,
		SrcIP:     req.Meta.SrcIP,
		DstIP:     req.Meta.DstIP,
		SrcMAC:    req.Meta.SrcMAC,
		DstMAC:    req.Meta.DstMAC,
		SrcPort:   req.Meta.SrcPort,
		DstPort:   req.Meta.DstPort,
		TTL:       req.Meta.TTL,
		Payload:   req.Meta.Payload,
		FlowIndex: req.Meta.FlowIndex,
	}
	ch, err := NewPlanner().Plan(ctx, spec)
	if err != nil {
		return err
	}
	for pkt := range ch {
		pkt.Direction = "up" // 防 raw-IP drive 二次换向（见包注释）
		if err := req.Emit(pkt); err != nil {
			return err
		}
	}
	return nil
}

func init() {
	layers.RegisterLayerGenerator("xmpp", func() (layers.LayerGenerator, error) {
		return &XMPPGenerator{}, nil
	})
	// 链上 ValidateSpec 经 protocolValidator 调用本校验器（不注册则
	// auth 机制/direction 枚举锚全漏）。
	layers.RegisterLayerValidator("xmpp", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
