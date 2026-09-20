// Package pptp: layer-chain wiring (D-PPTP-1 裁定1). The raw-IP chain
// terminal generator wraps the legacy Planner.Plan (单一真相：控制面 15 消息
// 族/GRE 增强头数据面/参考 pcap 逐字节编排/自建 TCP 握手挥手全套复用，零
// 分叉) and re-emits each packet through the raw-IP drive branch.
//
// 方向处理（防双换，pppoe/ldap/rtmp/rtsp 同款）：legacy Plan 对方向已在包
// 内部完成换向并置 Direction="down"；raw-IP drive 的 Emit 包装对 "down" 包
// 会再换一次 L3 地址。本生成器统一把每包 Direction 改写为 "up" 后转 Emit。
// 控制通道 1723 由 legacy Plan :404 缺省。
package pptp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// PPTPGenerator is the pptp raw-IP terminal-layer generator (D-PPTP-1).
type PPTPGenerator struct{}

func (g *PPTPGenerator) Name() string                     { return "pptp" }
func (g *PPTPGenerator) GenEvents() layers.EventGenerator { return nil }

// Generate emits the configured PPTP session via req.Emit (raw-IP chain).
func (g *PPTPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("pptp generator: Emit is nil")
	}
	cfg := req.Meta.PPTP
	if cfg == nil {
		cfg = &core.PPTPConfig{}
	}
	spec := core.FlowSpec{
		PPTP:      cfg,
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
	layers.RegisterLayerGenerator("pptp", func() (layers.LayerGenerator, error) {
		return &PPTPGenerator{}, nil
	})
	layers.RegisterLayerValidator("pptp", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
