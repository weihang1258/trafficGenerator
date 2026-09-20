// Package rtsp: layer-chain wiring (D-RTSP-1 裁定1). The raw-IP chain
// terminal generator wraps the legacy Planner.Plan (单一真相：dialog 渲染/
// 头自动补全/RTP 媒面子流/自建 TCP 握手挥手全套复用，零分叉) and re-emits
// each packet through the raw-IP drive branch.
//
// 方向处理（防双换，ldap/rtmp 同款）：legacy Plan 对方向已在包内部完成
// 换向并置 Direction="down"；raw-IP drive 的 Emit 包装对 "down" 包会再换
// 一次 L3 地址。本生成器统一把每包 Direction 改写为 "up" 后转 Emit——
// L3/L4 保持 legacy 换向结果，语义与 legacy 扁平路径逐字节一致。控制通道
// 554 由 validateSpecBase DstPort switch 缺省（dns→53 同款）。
package rtsp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// RTSPGenerator is the rtsp raw-IP terminal-layer generator (D-RTSP-1).
type RTSPGenerator struct{}

func (g *RTSPGenerator) Name() string                     { return "rtsp" }
func (g *RTSPGenerator) GenEvents() layers.EventGenerator { return nil }

// Generate emits the configured RTSP dialog via req.Emit (raw-IP chain).
func (g *RTSPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("rtsp generator: Emit is nil")
	}
	cfg := req.Meta.RTSP
	if cfg == nil {
		cfg = &core.RTSPConfig{}
	}
	spec := core.FlowSpec{
		RTSP:      cfg,
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
	layers.RegisterLayerGenerator("rtsp", func() (layers.LayerGenerator, error) {
		return &RTSPGenerator{}, nil
	})
	layers.RegisterLayerValidator("rtsp", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
