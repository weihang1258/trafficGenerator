package l2tp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// L2TPGenerator is the l2tp terminal-layer generator (l2tp 终结层层生成器)。
// L2TPv2/v3（RFC 2661/3931）——LAC 与 LNS 之间的 UDP 承载隧道会话：控制面
// 消息（SCCRQ/SCCRP/StopCCN/ICRQ/ICRP/CDN...) + PPP 数据帧（可选 Scenario
// 扩展），wire 字节由 buildControlMessage/buildDataMessage/buildInnerIPv4Packet
// 纯函数产出（由 legacy Plan 重放，不重写）。
//
// 生成器复用 legacy Planner.Plan() 本身（同一包序列、同一字节构造、同一
// 默认化——Plan 内 Validate+默认化+emit 全链路），只把返回的 PacketConfig
// 流适配成 MessageEvent 流（tftp 同款：零序列逻辑复制，字节级一致）。
// L4PortOverride=true 原因：legacy emit 已按方向处理端口（down 包源/目的
// 端口已对调），udp 层对 non-override 事件会再交换一次导致端口错位
// （tftp/wireguard/dhcp 同款机制）。
//
// 与 legacy Plan 的差异：seq/ipID/Timestamp/PacketIndex 由 udp 层与
// ChainPlanner 统一回填。l2tp 无 TCP 握手/挥手（UDP，无连接），validator
// 不强制 Handshake/Termination。legacy Validate 硬要求 spec.L2TP != nil
// （"L2TP config is required"），生成器 nil config 报错——与 legacy 一致，
// 不默认化。
type L2TPGenerator struct{}

// Name returns "l2tp".
func (g *L2TPGenerator) Name() string { return "l2tp" }

// Generate replays the legacy l2tp planner as message events (字节级复刻
// legacy Planner.Plan——同一 Validate 校验、同一默认化、同一 emit 序列)。
func (g *L2TPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("l2tp generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.L2TP
	if cfg == nil {
		return fmt.Errorf("l2tp generator: L2TP config is nil (legacy Validate requires spec.l2tp)")
	}
	spec := core.FlowSpec{
		SrcIP:  req.Meta.SrcIP,
		DstIP:  req.Meta.DstIP,
		SrcMAC: req.Meta.SrcMAC,
		DstMAC: req.Meta.DstMAC,
		// 端口留空：Plan 内默认 1701（effectiveSrcPort/effectiveDstPort
		// 为 0 时填 DefaultPort）。
		L2TP: cfg,
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
			L4PortOverride: true, // legacy emit 已按方向处理端口；udp 层不再交换
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
func (g *L2TPGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *L2TPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *L2TPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("l2tp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("l2tp", func() (layers.LayerGenerator, error) {
		return &L2TPGenerator{}, nil
	})
	layers.RegisterLayerValidator("l2tp", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
