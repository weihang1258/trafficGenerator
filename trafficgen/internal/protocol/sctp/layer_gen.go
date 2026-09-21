// Package sctp: layer-chain wiring (D-SCTP-1 裁定1). The raw-IP chain
// terminal generator wraps the legacy Planner.Plan (单一真相：4 路握手/
// DATA 双向/分片 B-E-middle/HEARTBEAT 主路径与 AltPath 多宿主/SHUTDOWN
// 三路与 ABORT 突断全套复用，零分叉) and re-emits each packet through
// the raw-IP drive branch.
//
// 方向处理（防双换，xmpp/vnc 同款）：legacy Plan 对方向已在包内部完成
// 换向并置 Direction="down"；raw-IP drive 的 Emit 包装对 "down" 包会再
// 换一次 L3 地址。本生成器统一把每包 Direction 改写为 "up" 后转 Emit。
// 端口住 sctp 层（src_port/dst_port，1.12 补位）经 translate 回填 spec；
// 无协议级缺省（flat 同口径）。
package sctp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// SCTPGenerator is the sctp raw-IP terminal-layer generator (D-SCTP-1).
type SCTPGenerator struct{}

func (g *SCTPGenerator) Name() string                     { return "sctp" }
func (g *SCTPGenerator) GenEvents() layers.EventGenerator { return nil }

// Generate emits the configured SCTP association via req.Emit (raw-IP chain).
func (g *SCTPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("sctp generator: Emit is nil")
	}
	cfg := req.Meta.SCTP
	if cfg == nil {
		// 空层 config 已由翻译分支保底非 nil，此分支仅防引擎直调绕过翻译。
		cfg = &core.SCTPConfig{}
	}
	spec := core.FlowSpec{
		SCTP:      cfg,
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
	layers.RegisterLayerGenerator("sctp", func() (layers.LayerGenerator, error) {
		return &SCTPGenerator{}, nil
	})
	// 链上 ValidateSpec 经 protocolValidator 调用本校验器（不注册则
	// AltPath IP/同族/FragmentSize 下界锚全漏）。
	layers.RegisterLayerValidator("sctp", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
