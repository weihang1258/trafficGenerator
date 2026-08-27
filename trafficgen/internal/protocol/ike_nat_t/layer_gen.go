package ike_nat_t

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// IKENATTGenerator is the ike_nat_t terminal-layer generator (ike_nat_t
// 终结层层生成器)。IKEv2 NAT-T（RFC 3948/7296 §2.23）——UDP 承载的密钥交换
// 协议经端口浮动（500→4500）+ Non-ESP Marker 的 NAT 穿透变体，wire 字节由
// buildIKENATTMessage 纯函数产出（由 legacy Plan 重放，不重写）。
//
// 生成器复用 legacy Planner.Plan() 本身（同一包序列、同一字节构造、同一
// 默认化），只把返回的 PacketConfig 流适配成 MessageEvent 流（tftp 同款）。
// L4PortOverride=true 原因：legacy 已按 direction/NAT-T 浮动处理端口
// （planner.go:293-302/473-474/567-568），udp 层对 non-override 事件会再
// 交换一次导致端口错位（tftp/wireguard/dhcp 同款）。
//
// 与 legacy Plan 的差异：seq/ipID/Timestamp/PacketIndex 由 udp 层与
// ChainPlanner 统一回填。ike_nat_t 无 TCP 握手/挥手（UDP，无连接）。
// legacy Validate 硬要求 spec.IKENATT != nil（"IKENATT config is required"），
// 生成器 nil config 报错——与 legacy 一致。
type IKENATTGenerator struct{}

// Name returns "ike_nat_t".
func (g *IKENATTGenerator) Name() string { return "ike_nat_t" }

// Generate replays the legacy ike_nat_t planner as message events (字节级
// 复刻 legacy Planner.Plan——同一 Validate 校验、同一默认化、同一 emit
// 序列)。
func (g *IKENATTGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("ike_nat_t generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.IKENATT
	if cfg == nil {
		return fmt.Errorf("ike_nat_t generator: IKENATT config is nil (legacy Validate requires spec.ike_nat_t)")
	}
	spec := core.FlowSpec{
		SrcIP:   req.Meta.SrcIP,
		DstIP:   req.Meta.DstIP,
		SrcMAC:  req.Meta.SrcMAC,
		DstMAC:  req.Meta.DstMAC,
		IKENATT: cfg,
		// 端口留空：Plan 内按 NAT-T 浮动状态默认 4500。
	}
	ch, err := (&Planner{}).Plan(ctx, spec)
	if err != nil {
		return err
	}
	for pc := range ch {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		ev := layers.MessageEvent{
			Up:             pc.Direction == "up",
			Bytes:          pc.Payload,
			SrcPort:        pc.L4.SrcPort,
			DstPort:        pc.L4.DstPort,
			Metadata:       pc.Metadata,
			L4PortOverride: true, // legacy 已按 direction/NAT-T 处理端口；udp 层不再交换
		}
		if err := g.emitMsg(ctx, req.EmitMsg, ev); err != nil {
			for range ch {
			}
			return err
		}
	}
	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream.
func (g *IKENATTGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *IKENATTGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *IKENATTGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("ike_nat_t generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("ike_nat_t", func() (layers.LayerGenerator, error) {
		return &IKENATTGenerator{}, nil
	})
	layers.RegisterLayerValidator("ike_nat_t", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
