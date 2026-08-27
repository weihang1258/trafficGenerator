package wireguard

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// WireGuardGenerator is the wireguard terminal-layer generator (wireguard
// 终结层层生成器)。WireGuard（Noise_IKpsk2）——UDP 数据报序列（Initiation/
// Response/CookieReply/TransportData + 可选 InnerIP 内层包）。每条消息一个
// "报文事件"（方向 + 完整字节），构建字节由 buildInitiation/buildResponse/
// buildCookieReply/buildTransportData/buildInnerIPPackets 纯函数产出（由
// legacy Plan 重放，不重写）。
//
// 生成器复用 legacy Planner.Plan() 本身（同一包序列、同一字节构造、同一
// 默认化），只把返回的 PacketConfig 流适配成 MessageEvent 流（tftp 同款：
// 零序列逻辑复制，字节级一致）。udp 层每事件 1 数据报。L4PortOverride=true
// 原因：legacy emit 已按方向交换端口（down 包 sport/dport 已对调，
// planner.go:307-317），udp 层对 non-override 事件会再交换一次导致
// 端口错位（tftp/dhcp 同款机制）。
//
// 与 legacy Plan 的差异：seq/ipID/Timestamp/PacketIndex 由 udp 层与
// ChainPlanner 统一回填；事件流不产（与 tftp 同款）。wireguard 无 TCP
// 握手/挥手（UDP，无连接），validator 不强制 Handshake/Termination。
type WireGuardGenerator struct{}

// Name returns "wireguard".
func (g *WireGuardGenerator) Name() string { return "wireguard" }

// Generate replays the legacy wireguard planner as message events (字节级
// 复刻 legacy Planner.Plan——同一 Validate 校验、同一默认化、同一 emit 序列)。
func (g *WireGuardGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("wireguard generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	spec := core.FlowSpec{
		SrcIP:     req.Meta.SrcIP,
		DstIP:     req.Meta.DstIP,
		SrcPort:   req.Meta.SrcPort,
		DstPort:   req.Meta.DstPort,
		SrcMAC:    req.Meta.SrcMAC,
		DstMAC:    req.Meta.DstMAC,
		WireGuard: req.Meta.WireGuard,
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
			L4PortOverride: true, // legacy emit 已交换端口；udp 层不再交换
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
func (g *WireGuardGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *WireGuardGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *WireGuardGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("wireguard generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("wireguard", func() (layers.LayerGenerator, error) {
		return &WireGuardGenerator{}, nil
	})
	layers.RegisterLayerValidator("wireguard", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
