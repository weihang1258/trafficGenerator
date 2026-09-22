// Package jtt905: layer-chain wiring (D-JTT905-1 裁定5). The raw-IP chain
// terminal generator wraps the legacy Planner.PlanWithConfig (单一真相：
// 单 TCP 会话/双流水号/5 型消息面/自动会话全套复用，零分叉) and re-emits
// each packet through the raw-IP drive branch.
//
// 协议特有（十一连 raw 自驱家族）：
//   - legacy Plan 直接报错（曾致任务 0 包静默完成）——本生成器唯一入口
//     是 PlanWithConfig，防 0 包静默回归。
//   - 端口=legacy 内部缺省 10700：spec.DstPort==0 时 PlanWithConfig 自补
//     （mapToFlowSpec case "jtt905" 同值——jt808 80 穿透教训移植）。
//
// 方向处理（防双换，jt808/jt809/sctp 同款）：PlanWithConfig 对方向已在
// 包内部完成换向并置 Direction；raw-IP drive 的 Emit 包装对 "down" 包会
// 再换一次 L3 地址。本生成器统一把每包 Direction 改写为 "up" 后转 Emit。
package jtt905

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// JTT905Generator is the jtt905 raw-IP terminal-layer generator (D-JTT905-1).
type JTT905Generator struct{}

func (g *JTT905Generator) Name() string                     { return "jtt905" }
func (g *JTT905Generator) GenEvents() layers.EventGenerator { return nil }

// Generate emits the configured JTT905 session via req.Emit (raw-IP chain).
func (g *JTT905Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("jtt905 generator: Emit is nil")
	}
	cfg := req.Meta.JTT905
	if cfg == nil {
		cfg = &core.JTT905Config{}
	}
	spec := core.FlowSpec{
		JTT905:    cfg,
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
	ch, err := NewPlanner().PlanWithConfig(ctx, spec, cfg)
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
	layers.RegisterLayerGenerator("jtt905", func() (layers.LayerGenerator, error) {
		return &JTT905Generator{}, nil
	})
	// 链上 ValidateSpec 经 protocolValidator 调用本校验器（不注册则锚全
	// 漏）。锚点双段：L3/L4 走 Validate；业务面（isu_id 12 位/plate≤6/
	// Result 0-2/BCD 位数族）走 ValidateConfig——嵌套 procedures V9 不下探，
	// 这是唯一拦截点。
	layers.RegisterLayerValidator("jtt905", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		if spec.JTT905 != nil {
			return ValidateConfig(spec.JTT905)
		}
		// jt808 N5 同款：直构缺协议层链显式拒绝。
		return fmt.Errorf("jtt905: layer config required")
	})
}
