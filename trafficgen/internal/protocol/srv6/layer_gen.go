package srv6

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// SRV6Generator is the srv6 raw-IP terminal-layer generator (D-SRV6-1).
// It wraps the legacy Planner.Plan (单一真相：缺省解析/反序存储/down 换向/
// ICMPv6 缺省 Echo 全套复用，零分叉) and re-emits each packet through the
// raw-IP drive branch.
//
// 方向处理（防双换）：legacy Plan 对 direction=down 已在包内部完成 MAC/IP/
// 端口/SegmentList 反转全套换向并置 Direction="down"；raw-IP drive 的 Emit
// 包装对 "down" 包会再换一次 L3 地址（nvgre/igmp 契约：生成器产 up 向包）。
// 本生成器统一把每包 Direction 改写为 "up" 后转 Emit——L3 地址保持 legacy
// 换向结果，L2 MAC 保持 legacy 换向写入值（非空，drive 的 l2For 回填跳过），
// 语义与 legacy 扁平路径逐字节一致。
//
// hop_limit/IPID：legacy Plan 自带帧序（TTL 64-i 回绕 1..255 永不 0）；drive
// 的 `if pkt.L3.TTL == 0` 分支不触发（恒非 0）。
type SRV6Generator struct{}

func (g *SRV6Generator) Name() string                     { return "srv6" }
func (g *SRV6Generator) GenEvents() layers.EventGenerator { return nil }

// Generate emits the configured SRv6 packets via req.Emit (raw-IP chain).
func (g *SRV6Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil {
		return fmt.Errorf("srv6 generator: Emit is nil")
	}
	cfg := req.Meta.SRv6
	if cfg == nil {
		// 空层 config 已由翻译分支保底非 nil（VR-02 必拒），此分支仅防
		// 引擎直调绕过翻译。
		cfg = &core.SRv6Config{}
	}
	spec := core.FlowSpec{
		SRv6:    cfg,
		SrcIP:   req.Meta.SrcIP,
		DstIP:   req.Meta.DstIP,
		SrcMAC:  req.Meta.SrcMAC,
		DstMAC:  req.Meta.DstMAC,
		SrcPort: req.Meta.SrcPort,
		DstPort: req.Meta.DstPort,
		TTL:     req.Meta.TTL,
		Payload: req.Meta.Payload,
		// HopByHop 不在此注入：raw-IP drive 的 Emit 包装统一写
		// pkt.L3.HopByHop = spec.HopByHop（chain_planner.go raw-IP 分支），
		// spec.HopByHop 由 ValidateSpec 的 ip 层 hop_by_hop 回填供给。
	}
	ch, err := (&Planner{}).Plan(ctx, spec)
	if err != nil {
		return err
	}
	for pkt := range ch {
		pkt.Direction = "up" // 防 raw-IP drive 二次换向（见类型注释）
		if err := req.Emit(pkt); err != nil {
			return err
		}
	}
	return nil
}

func init() {
	layers.RegisterLayerGenerator("srv6", func() (layers.LayerGenerator, error) {
		return &SRV6Generator{}, nil
	})
	// D-SRV6-1 决策 G：链上 ValidateSpec 经 protocolValidator 调用本校验器
	// （链上不经 legacy planner，不注册则 VR-01–23 全漏）。
	layers.RegisterLayerValidator("srv6", func(spec *core.FlowSpec) error {
		return Validate(*spec)
	})
}
