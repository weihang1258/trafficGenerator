// Package pppoe: layer-chain wiring (D-PPPOE-1 裁定1/裁定2). The raw-IP
// chain terminal generator wraps the legacy Planner.Plan (单一真相：
// Discovery/LCP/Auth/数据/PADT 全生命周期、缺省解析、sessions[] 编排
// 全套复用，零分叉) and re-emits each packet through the raw-IP drive
// branch.
//
// 方向处理（防双换，srv6 同款）：Plan 对方向已在包内部完成 MAC/内层 IP
// 换向并置 Direction="down"；raw-IP drive 的 Emit 包装对 "down" 包会再换
// 一次 L3 地址（nvgre/igmp 契约：生成器产 up 向包）。本生成器统一把每包
// Direction 改写为 "up" 后转 Emit——内层 L3 地址保持 Plan 换向结果，L2
// MAC 保持 Plan 写入值（非空，drive 的 l2For 回填跳过），语义与 legacy
// 扁平路径逐字节一致。EtherType 由 Plan 的 emitFrame 按 Code 写入
// （0x8863 Discovery / 0x8864 Session），builder 见 L2.PPPoE 再强制一遍
// （builder.go 常量注释，regardless of L2Config.EtherType）——双保险，
// 驱动分支的 EtherTypeFor 回填不生效。
package pppoe

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// PPPoEGenerator is the pppoe raw-IP terminal-layer generator (D-PPPOE-1).
type PPPoEGenerator struct{}

func (g *PPPoEGenerator) Name() string                     { return "pppoe" }
func (g *PPPoEGenerator) GenEvents() layers.EventGenerator { return nil }

// Generate emits the configured PPPoE lifecycle via req.Emit (raw-IP chain).
func (g *PPPoEGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("pppoe generator: Emit is nil")
	}
	cfg := req.Meta.PPPoE
	if cfg == nil {
		// 空层 config 已由翻译分支保底非 nil，此分支仅防引擎直调绕过翻译。
		cfg = &core.PPPoEConfig{}
	}
	spec := core.FlowSpec{
		PPPoE:     cfg,
		SrcIP:     req.Meta.SrcIP,
		DstIP:     req.Meta.DstIP,
		SrcMAC:    req.Meta.SrcMAC,
		DstMAC:    req.Meta.DstMAC,
		SrcPort:   req.Meta.SrcPort,
		DstPort:   req.Meta.DstPort,
		TTL:       req.Meta.TTL,
		Payload:   req.Meta.Payload,
		FlowIndex: req.Meta.FlowIndex, // sessions[] SessionIDDyn 逐流解析
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
	layers.RegisterLayerGenerator("pppoe", func() (layers.LayerGenerator, error) {
		return &PPPoEGenerator{}, nil
	})
	// D-PPPOE-1 决策（srv6 决策 G 同款）：链上 ValidateSpec 经
	// protocolValidator 调用本校验器（链上不经 legacy planner，不注册则
	// sessions 互斥/重复 ID 等 7 锚全漏）。
	layers.RegisterLayerValidator("pppoe", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
