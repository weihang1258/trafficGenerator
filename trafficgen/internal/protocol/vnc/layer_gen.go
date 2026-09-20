// Package vnc: layer-chain wiring (D-VNC-1 裁定1). The raw-IP chain
// terminal generator wraps the legacy Planner.Plan (单一真相：RFB 版本
// 协商/三安全路径握手/ServerInit/客户端 6 消息/FBU 循环/自建 TCP 握手
// 挥手全套复用，零分叉) and re-emits each packet through the raw-IP
// drive branch.
//
// 方向处理（防双换，pptp/rtsp 同款）：legacy Plan 对方向已在包内部完成
// 换向并置 Direction="down"；raw-IP drive 的 Emit 包装对 "down" 包会再
// 换一次 L3 地址。本生成器统一把每包 Direction 改写为 "up" 后转 Emit。
// 控制通道 5900 由 legacy Plan :561 缺省。
package vnc

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// VNCGenerator is the vnc raw-IP terminal-layer generator (D-VNC-1).
type VNCGenerator struct{}

func (g *VNCGenerator) Name() string                     { return "vnc" }
func (g *VNCGenerator) GenEvents() layers.EventGenerator { return nil }

// Generate emits the configured VNC session via req.Emit (raw-IP chain).
func (g *VNCGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("vnc generator: Emit is nil")
	}
	cfg := req.Meta.VNC
	if cfg == nil {
		// 空层 config 已由翻译分支保底非 nil，此分支仅防引擎直调绕过翻译。
		cfg = &core.VNCConfig{}
	}
	spec := core.FlowSpec{
		VNC:       cfg,
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
	layers.RegisterLayerGenerator("vnc", func() (layers.LayerGenerator, error) {
		return &VNCGenerator{}, nil
	})
	// 链上 ValidateSpec 经 protocolValidator 调用本校验器（不注册则
	// security_type/宽高/rect 等 13 锚族全漏）。
	layers.RegisterLayerValidator("vnc", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
