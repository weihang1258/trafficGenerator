package tftp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// TFTPGenerator is the tftp terminal-layer generator (tftp 终结层层生成器,
// P4a)。TFTP 是无握手 UDP 多包序列（RRQ/WRQ → OACK → ACK#0 → DATA/ACK →
// ERROR/TID 变更/重传/窗口），每条消息的源/目标端口不同（客户端 69 /
// 服务器 TID 交换）且携带协议元数据 (tftp_opcode/tftp_block/tftp_filename)。
//
// 生成器复用 legacy Planner.Plan() 本身（同一包序列、同一字节构造、同一
// 默认化——Plan 内部 Validate+默认化+emit 全链路），只把返回的 PacketConfig
// 流适配成 MessageEvent 流（P2b TLS 委托同架构：零序列逻辑复制，字节级
// 一致）。事件携带 legacy 的 Direction/L4 端口/Payload/Metadata；udp 层每
// 事件 1 数据报、端口交换后直落（tftp 是普通单播，无多播覆盖）。
type TFTPGenerator struct{}

// Name returns "tftp".
func (g *TFTPGenerator) Name() string { return "tftp" }

// Generate replays the legacy TFTP planner as message events (字节级复刻
// legacy Planner.Plan——同一 Validate 校验、同一默认化、同一 emit 序列)。
// Plan 内部经 spec 副本计算确定性 TID / derive BlocksCount，因此层链驱动
// 与 legacy 独立 flow 驱动产出完全一致。
func (g *TFTPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("tftp generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.TFTP
	if cfg == nil {
		return fmt.Errorf("tftp generator: TFTP config is nil (layer not wired to a flow spec)")
	}
	spec := core.FlowSpec{
		SrcIP:   req.Meta.SrcIP,
		DstIP:   req.Meta.DstIP,
		SrcPort: req.Meta.SrcPort,
		DstPort: req.Meta.DstPort,
		TFTP:    cfg,
	}
	// Payload/FileSource 流级字段：FlowMeta 当前不承载 FileSource（链配置
	// 翻译只传协议 config），spec.Payload 是 flow 级应用负载——TFTP 的
	// derive 场景（BlocksCount=0）在层链中经 DataPayloadPattern 或已解析
	// 的 Payload 表达，文件源降级为 1 块（Validate 的 V16 对无源 spec 已
	// 拒绝，不可达）。
	spec.Payload = req.Meta.Payload

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
			Up:       pc.Direction == "up",
			Bytes:    pc.Payload,
			SrcPort:  pc.L4.SrcPort,
			DstPort:  pc.L4.DstPort,
			Metadata: pc.Metadata,
			// L4PortOverride=true（dhcp/dhcpv6 同机制）：legacy emitPacket 已按
			// 方向解析端口——down 包源端口是 ServerTID（服务器端口），不是
			// spec.SrcPort。udp 层对 down 事件会再交换一次
			// （`if !ev.L4PortOverride { srcPort,dstPort = dstPort,srcPort }`），
			// 不覆盖会把已解析的 ServerTID→49152 二次交换成 49152→ServerTID。
			L4PortOverride: true,
		}
		if err := g.emitMsg(ctx, req.EmitMsg, ev); err != nil {
			// 错误路径不得泄漏 legacy producer goroutine：Plan 的 producer
			// 对 configChan 的发送没有 ctx 选择（tftp.go:327-330），我们
			// 停止读取后它会永久阻塞。排空到 channel 关闭，producer 发完
			// 序列自然退出（review MEDIUM-1，goleak 验证）。
			for range ch {
			}
			return err
		}
	}
	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks).
func (g *TFTPGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *TFTPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *TFTPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("tftp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("tftp", func() (layers.LayerGenerator, error) {
		return &TFTPGenerator{}, nil
	})
	layers.RegisterLayerValidator("tftp", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
