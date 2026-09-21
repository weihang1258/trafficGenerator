// Package jt808: layer-chain wiring (D-JT808-1 裁定1). The raw-IP chain
// terminal generator wraps the legacy Planner.PlanWithConfig (单一真相：
// 3 握手/13 型消息面/双 SN 空间/4 自动绑定/分包转义全套复用，零分叉) and
// re-emits each packet through the raw-IP drive branch.
//
// 两点协议特有（九连首例）：
//   - legacy Plan 直接报错（曾致任务 0 包静默完成）——本生成器唯一入口
//     是 PlanWithConfig，防 0 包静默回归。
//   - 端口=legacy 内部缺省 7611（vnc/pptp 变体）：spec.DstPort==0 时
//     PlanWithConfig 自补，无协议层端口字段、无 DstPort switch case。
//
// 方向处理（防双换，vnc/xmpp/sctp 同款）：legacy PlanWithConfig 对方向已
// 在包内部完成换向并置 Direction="down"；raw-IP drive 的 Emit 包装对
// "down" 包会再换一次 L3 地址。本生成器统一把每包 Direction 改写为 "up"
// 后转 Emit。
package jt808

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// JT808Generator is the jt808 raw-IP terminal-layer generator (D-JT808-1).
type JT808Generator struct{}

func (g *JT808Generator) Name() string                     { return "jt808" }
func (g *JT808Generator) GenEvents() layers.EventGenerator { return nil }

// Generate emits the configured JT808 session via req.Emit (raw-IP chain).
func (g *JT808Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("jt808 generator: Emit is nil")
	}
	cfg := req.Meta.JT808
	if cfg == nil {
		// 空层 config 已由翻译分支保底非 nil，此分支仅防引擎直调绕过翻译。
		cfg = &core.JT808Config{}
	}
	spec := core.FlowSpec{
		JT808:     cfg,
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
	// 唯一入口 PlanWithConfig（legacy Plan 硬错，见包注释）。
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
	layers.RegisterLayerGenerator("jt808", func() (layers.LayerGenerator, error) {
		return &JT808Generator{}, nil
	})
	// 链上 ValidateSpec 经 protocolValidator 调用本校验器（不注册则锚全
	// 漏）。jt808 锚点双段：L3/L4 走 Validate；业务面（phone 12 位/auth
	// 鉴权码必备/车牌互斥/ACKFlag≤3/注册结果≤4）走 ValidateConfig——嵌套
	// procedures V9 不下探，这是唯一拦截点。
	layers.RegisterLayerValidator("jt808", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		if spec.JT808 != nil {
			return ValidateConfig(spec.JT808)
		}
		// 隔离复审 N5：直构缺协议层链（无 jt808 层）在此显式拒绝，防止
		// 静默走 Generate 缺省壳后 PlanWithConfig 报错被 raw 分支吞掉。
		return fmt.Errorf("jt808: layer config required")
	})
}
