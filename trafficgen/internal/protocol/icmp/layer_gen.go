// Package icmp layer generator (D-ICMP-1): wraps the legacy Planner.Plan
// for the [ip, icmp] raw-IP terminal chain. Echo pairing, Pattern steps,
// checksum and FileSource precedence all reuse the legacy implementation —
// zero byte divergence (icmpv6 对称第 12 连).
package icmp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// Generator adapts the legacy Planner to the layers generator interface.
type Generator struct {
	legacy *Planner
}

func (*Generator) Name() string { return "icmp" }

// GenEvents returns nil: icmp emits raw packets (raw-IP chain), not
// message events for a transport layer.
func (g *Generator) GenEvents() layers.EventGenerator { return nil }

// Generate relays legacy Plan packets to the chain drive. Every packet is
// forced to Direction "up"（icmpv6 同款防双换）：legacy 已完成 request/reply
// 的 L3 地址换向并置 Direction=down；raw-IP 驱动对 down 包再换一次 L3 即
// 双换错。强制 up 后 l2For 沿 up 侧补缺省 MAC。
func (g *Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.Emit == nil || req.Meta.ICMP == nil {
		return fmt.Errorf("icmp generator: invalid request")
	}
	spec := core.FlowSpec{
		SrcIP:  req.Meta.SrcIP,
		DstIP:  req.Meta.DstIP,
		TTL:    req.Meta.TTL,
		SrcMAC: req.Meta.SrcMAC,
		DstMAC: req.Meta.DstMAC,
		ICMP:   req.Meta.ICMP,
	}
	ch, err := g.legacy.Plan(ctx, spec)
	if err != nil {
		return err
	}
	for pkt := range ch {
		pkt.Direction = "up"
		if err := req.Emit(pkt); err != nil {
			return err
		}
	}
	return nil
}

// validateLayer is the chain-path validator (RegisterLayerValidator).
// Echo semantic branches（D-ICMP-1 裁定4，icmpv6 §5 同款）+ legacy IP 格式
// 面复用（HasLayerDynIP 豁免同 icmpv6 D-FTP-4 口径：ip 层动态对象时解析前
// 不得静态判，generate 期 legacy Plan 按解析后地址复验）。
func validateLayer(s core.FlowSpec) error {
	if s.ICMP == nil {
		return fmt.Errorf("icmp config is required")
	}
	c := s.ICMP
	if c.Type != TypeEchoRequest && c.Type != TypeEchoReply {
		return fmt.Errorf("icmp type must be 8 (Echo Request) or 0 (Echo Reply), got %d", c.Type)
	}
	if c.Code != 0 {
		return fmt.Errorf("icmp code must be 0 for Echo, got %d", c.Code)
	}
	for i, st := range c.Pattern {
		if st.Type != TypeEchoRequest && st.Type != TypeEchoReply {
			return fmt.Errorf("icmp pattern step %d type must be 8 or 0, got %d", i+1, st.Type)
		}
	}
	if s.HasLayerDynIP {
		return nil
	}
	var p Planner
	return p.Validate(s)
}

func init() {
	layers.RegisterLayerGenerator("icmp", func() (layers.LayerGenerator, error) { return &Generator{legacy: NewPlanner()}, nil })
	layers.RegisterLayerValidator("icmp", func(s *core.FlowSpec) error { return validateLayer(*s) })
}
