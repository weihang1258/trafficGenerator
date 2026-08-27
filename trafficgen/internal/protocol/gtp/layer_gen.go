package gtp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// GTPGenerator is the gtp terminal-layer generator (gtp 终结层层生成器)。
// GTP-U（TS 29.281）/GTP-C（TS 29.060）——UDP 承载的隧道协议：GTP header +
// 内层 IP 包（GTP-U 承载用户面，GTP-C 承载信令消息），wire 字节由
// buildGTPMessage / buildInnerIPv4Packet / buildInnerIPv6Packet 纯函数产出
// （由 legacy Plan 重放，不重写）。
//
// 生成器复用 legacy Planner.Plan() 本身（同一包序列、同一字节构造、同一
// 默认化——Plan 内 Validate+默认化+emit 全链路），只把返回的 PacketConfig
// 流适配成 MessageEvent 流（tftp 同款）。L4PortOverride=true 原因：legacy
// resolveDirection 已按方向处理外层地址与端口（down 时交换），udp 层对
// non-override 事件会再交换一次导致端口错位（tftp/wireguard/dhcp 同款）。
//
// 与 legacy Plan 的差异：seq/ipID/Timestamp/PacketIndex 由 udp 层与
// ChainPlanner 统一回填。gtp 无 TCP 握手/挥手（UDP，无连接），validator
// 不强制 Handshake/Termination。legacy Validate 硬要求 spec.GTP != nil
// （"GTP config is required"），生成器 nil config 报错——与 legacy 一致。
type GTPGenerator struct{}

// Name returns "gtp".
func (g *GTPGenerator) Name() string { return "gtp" }

// Generate replays the legacy gtp planner as message events (字节级复刻
// legacy Planner.Plan——同一 Validate 校验、同一默认化、同一 emit 序列)。
func (g *GTPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("gtp generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.GTP
	if cfg == nil {
		return fmt.Errorf("gtp generator: GTP config is nil (legacy Validate requires spec.gtp)")
	}
	spec := core.FlowSpec{
		SrcIP:  req.Meta.SrcIP,
		DstIP:  req.Meta.DstIP,
		SrcMAC: req.Meta.SrcMAC,
		DstMAC: req.Meta.DstMAC,
		// 端口留空：Plan 内默认 2152(u)/2123(c)（EffectivePort=0 时填默认）。
		GTP: cfg,
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
			L4PortOverride: true, // legacy resolveDirection 已处理端口；udp 层不再交换
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
func (g *GTPGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *GTPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *GTPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("gtp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("gtp", func() (layers.LayerGenerator, error) {
		return &GTPGenerator{}, nil
	})
	layers.RegisterLayerValidator("gtp", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
