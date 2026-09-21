// Package jt809: layer-chain wiring (D-JT809-1 裁定5). The raw-IP chain
// terminal generator wraps the legacy Planner.PlanWithConfig (单一真相：
// 双 TCP 链路/四 SN 计数器/16 型消息面/转义信封全套复用，零分叉) and
// re-emits each packet through the raw-IP drive branch.
//
// 协议特有（十连 raw 自驱家族）：
//   - legacy Plan 直接报错（曾致任务 0 包静默完成）——本生成器唯一入口
//     是 PlanWithConfig，防 0 包静默回归。
//   - 端口=主链 8812 内部缺省：spec.DstPort==0 时 PlanWithConfig 自补
//     （mapToFlowSpec case "jt809" 同值，jt808 80 穿透教训移植）；
//     从链 8813=生成器合成面（emitMsg/从链握手改写），无 spec 字段。
//
// 方向处理（防双换，jt808/xmpp/sctp 同款）：PlanWithConfig 对方向已在
// 包内部完成换向并置 Direction；raw-IP drive 的 Emit 包装对 "down" 包会
// 再换一次 L3 地址。本生成器统一把每包 Direction 改写为 "up" 后转 Emit。
package jt809

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// JT809Generator is the jt809 raw-IP terminal-layer generator (D-JT809-1).
type JT809Generator struct{}

func (g *JT809Generator) Name() string                     { return "jt809" }
func (g *JT809Generator) GenEvents() layers.EventGenerator { return nil }

// Generate emits the configured JT809 session via req.Emit (raw-IP chain).
func (g *JT809Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("jt809 generator: Emit is nil")
	}
	cfg := req.Meta.JT809
	if cfg == nil {
		// 空层 config 已由翻译分支保底非 nil，此分支仅防引擎直调绕过翻译。
		cfg = &core.JT809Config{}
	}
	spec := core.FlowSpec{
		JT809:     cfg,
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
	layers.RegisterLayerGenerator("jt809", func() (layers.LayerGenerator, error) {
		return &JT809Generator{}, nil
	})
	// 链上 ValidateSpec 经 protocolValidator 调用本校验器（不注册则锚全
	// 漏）。jt809 锚点双段：L3/L4 走 Validate；业务面（gnss 区间/version_flag
	// ≤2/password≤8/16 型族/链路归属/Result≤4/ErrorCode·ReasonCode≤2）走
	// ValidateConfig——嵌套 procedures V9 不下探，这是唯一拦截点。
	layers.RegisterLayerValidator("jt809", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		if spec.JT809 != nil {
			return ValidateConfig(spec.JT809)
		}
		// jt808 N5 同款：直构缺协议层链（无 jt809 层）在此显式拒绝，防止
		// 静默走 Generate 缺省壳后 PlanWithConfig 报错被 raw 分支吞掉。
		return fmt.Errorf("jt809: layer config required")
	})
}
