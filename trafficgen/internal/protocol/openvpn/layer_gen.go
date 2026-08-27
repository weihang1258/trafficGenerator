package openvpn

// OpenVPNGenerator is the openvpn terminal-layer generator (openvpn 终结层层
// 生成器, P3)。OpenVPN——UDP 承载的加密隧道协议（P_CONTROL_HARD_RESET/
// P_CONTROL_V1/P_DATA_V1/V2 数据报序列，wire 字节由 build* 纯函数产出）。
// 每条消息一个"报文事件"（方向 + 完整字节），构建字节由 legacy Plan 重放
// （tftp 同款：零序列逻辑复制，字节级一致）。udp 层每事件 1 数据报。
// L4PortOverride=true 原因：legacy emit 已按方向交换端口（down 包 sport/dport
// 已对调，planner.go:505-510 syndicate），udp 层对 non-override 事件会再交换
// 一次导致端口错位（wireguard/tftp/dhcp 同款机制）。
//
// 与 legacy Plan 的差异：seq/ipID/Timestamp/PacketIndex 由 udp 层与
// ChainPlanner 统一回填；事件流不产（与 wireguard/tftp 同款）。openvpn 无
// TCP 握手/挥手（默认 Udp，无连接），validator 不强制 Handshake/Termination。
//
// proto=tcp 链上不支持：OpenVPN-over-TCP 用 2 字节长度前缀（emitTCPData
// planner.go:489-493）+ TLS 包裹（buildHardReset* 的 clientHello/serverHello +
// tlsActive），udp 层无等价 TLS 包裹与 TCP 帧前缀机制。validator 显式拒绝
// TCP 模式（tls 链版本/角色、rdp TLS 模式同款先例）。
//
// nil OpenVPN config → 校验拒绝（legacy Validate 硬要求 spec.openvpn，
// planner.go:131"openvpn config is required"，与 rdp/l2tp/gtp/ike 同款）。

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// OpenVPNGenerator is the openvpn terminal-layer generator.
type OpenVPNGenerator struct{}

// Name returns "openvpn".
func (g *OpenVPNGenerator) Name() string { return "openvpn" }

// Generate replays the legacy openvpn planner as message events (字节级复刻
// legacy Planner.Plan——同一 Validate 校验、同一默认化、同一 emit 序列)。
func (g *OpenVPNGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("openvpn generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.OpenVPN
	if cfg == nil {
		return fmt.Errorf("openvpn generator: no config (spec.openvpn required)")
	}
	// TCP 模式链上不支持（validator 已同步拒绝；此处双保险防御，理论上不可达）。
	if cfg.Proto == "tcp" {
		return fmt.Errorf("openvpn generator: proto=tcp is not supported on the layer chain (udp layer cannot do OpenVPN-over-TCP framing + TLS)")
	}
	spec := core.FlowSpec{
		SrcIP:   req.Meta.SrcIP,
		DstIP:   req.Meta.DstIP,
		SrcPort: req.Meta.SrcPort,
		DstPort: req.Meta.DstPort,
		SrcMAC:  req.Meta.SrcMAC,
		DstMAC:  req.Meta.DstMAC,
		OpenVPN: cfg,
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
func (g *OpenVPNGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *OpenVPNGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *OpenVPNGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("openvpn generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("openvpn", func() (layers.LayerGenerator, error) {
		return &OpenVPNGenerator{}, nil
	})
	layers.RegisterLayerValidator("openvpn", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// TCP 模式链上不支持（tls 链版本/角色、rdp TLS 模式同款先例）：
		// legacy proto=tcp 产 2 字节长度前缀 + TLS 包裹 P_CONTROL/P_DATA，
		// 链上 udp 层无等价物。同步拒绝（默认 proto=udp 不受影响）。
		if spec.OpenVPN != nil && spec.OpenVPN.Proto == "tcp" {
			return fmt.Errorf("openvpn: proto=tcp is not supported on the layer chain (udp layer cannot do OpenVPN-over-TCP framing + TLS)")
		}
		return nil
	})
}
