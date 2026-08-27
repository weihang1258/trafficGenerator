package ike

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// IKEGenerator is the ike terminal-layer generator (ike 终结层层生成器)。
// IKEv1/v2（RFC 7296 等）——UDP 承载的密钥交换协议：IKE 消息序列
// （SA_INIT/AUTH/CREATE_CHILD 等）+ 可选 ESP 数据面（EncryptMode="opaque"），
// wire 字节由 buildIKEMessageBytes / buildESPPacket / buildInnerIPv4Packet
// 纯函数产出（由 legacy Plan 重放，不重写）。
//
// 生成器复用 legacy Planner.Plan() 本身（同一包序列、同一字节构造、同一
// 默认化——Plan 内 Validate+默认化+emit 全链路），只把返回的 PacketConfig
// 流适配成 MessageEvent 流（tftp 同款）。L4PortOverride=true 原因：legacy
// buildPacketConfig 已按 msg.Direction 交换端口（down 时 srcPort/dstPort
// 对调，planner.go:1571-1575），udp 层对 non-override 事件会再交换一次导致
// 端口错位（tftp/wireguard/dhcp 同款）。
//
// 与 legacy Plan 的差异：seq/ipID/Timestamp/PacketIndex 由 udp 层与
// ChainPlanner 统一回填。ike 无 TCP 握手/挥手（UDP，无连接），validator
// 不强制 Handshake/Termination。legacy Validate 硬要求 spec.IKE != nil
// （"IKE config is required"）且 SrcPort>1024、DstPort=0 或 500——生成器
// nil config 报错，与 legacy 一致。
type IKEGenerator struct{}

// Name returns "ike".
func (g *IKEGenerator) Name() string { return "ike" }

// Generate replays the legacy ike planner as message events (字节级复刻
// legacy Planner.Plan——同一 Validate 校验、同一默认化、同一 emit 序列)。
func (g *IKEGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("ike generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.IKE
	if cfg == nil {
		return fmt.Errorf("ike generator: IKE config is nil (legacy Validate requires spec.ike)")
	}
	spec := core.FlowSpec{
		SrcIP:  req.Meta.SrcIP,
		DstIP:  req.Meta.DstIP,
		SrcMAC: req.Meta.SrcMAC,
		DstMAC: req.Meta.DstMAC,
		// 端口：SrcPort 由用户/chain 给（>1024）；DstPort 留 0 → Plan 默认 500
		// （legacy Validate 允许 0 or 500）。
		IKE: cfg,
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
			L4PortOverride: true, // legacy buildPacketConfig 已按方向处理端口；udp 层不再交换
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
func (g *IKEGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *IKEGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *IKEGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("ike generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("ike", func() (layers.LayerGenerator, error) {
		return &IKEGenerator{}, nil
	})
	layers.RegisterLayerValidator("ike", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
