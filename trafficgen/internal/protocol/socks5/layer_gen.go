package socks5

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// SOCKS5Generator is the socks5 terminal-layer generator (socks5 终结层层
// 生成器，J 组组合层)。SOCKS4/5（RFC 1928/1929）——一次 flow = 一条 TCP
// 连接上：信令（greeting → method response → [auth] → request → reply，
// 或 SOCKS4 两阶段）→ 隧道数据面（Rep=0 时 Data 消息逐条上包）。每条
// wire 帧一个"报文事件"（方向 + 完整字节），构建字节由 buildGreeting /
// buildMethodResponse / buildAuthRequest / buildAuthResponse /
// buildSocks5Request / buildSocks5Reply / buildSocks4Request /
// buildSocks4Reply 纯函数产出（复用，不重写）。事件模式（pop3/imap 同款）：
// TCP 语义（握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器。
//
// 与 legacy Plan（socks5.go:252-530）的差异（文档化 divergence）：
//   - legacy 自产 TCP 握手（3 包）与挥手（3 包 FIN 序列，socks5.go:448-456
//     + 514-522）——事件模式不产：tcp 层生成器负责（防双握手）。握手/挥手
//     开关由 tcp 层 schema 默认 true 执行，validator 强制校准 true（legacy
//     恒产握手/挥手）。
//   - seq/ack、ipID、Timestamp、MSS 分段：链上由 tcp 层生成器处理。
//   - UDP relay 子流（udp_associate + UDP 配置）：链事件模型一次 flow =
//     一条 TCP 连接上的字节流，UDP 数据报无法用 MessageEvent 表达——
//     UDP 配置非空显式拒绝（enip session_count/dnp3 multi_outstation/
//     mqtt Sessions 同款先例；udp_associate 的信令字节仍正常产出）。
//   - FileSource 隧道数据在链路径不可用：PayloadCacheFrom 依赖 ctx 携带的
//     engine 级缓存，FlowMeta 不承载——与 imap/tftp layer_gen 对 FileSource
//     的降级同款（validator 拒绝 FileSource 数据项为双保险）。
//   - 多流/GroupID：链一次一个 flow（一个 4-tuple），链路径不展开。
type SOCKS5Generator struct{}

// Name returns "socks5".
func (g *SOCKS5Generator) Name() string { return "socks5" }

// Generate produces one message event per SOCKS wire frame in legacy Plan
// order（signaling → data plane）。TCP 层生成器负责握手/seq-ack/挥手/MSS 分段。
func (g *SOCKS5Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("socks5 generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	c := req.Meta.Socks
	if c == nil {
		// 与 legacy 同款（Plan 对 nil Config 走默认 socks5 no_auth connect）。
		c = &core.SocksConfig{}
	}
	if c.UDP != nil {
		return fmt.Errorf("socks5 generator: udp relay sub-flow not supported on layer chains (UDP relay needs a second 4-tuple); use the flat socks5 protocol instead")
	}
	for i, msg := range c.Data {
		if msg.FileSource != nil {
			return fmt.Errorf("socks5 generator: data[%d] file_source not supported on layer chains (FlowMeta does not carry the payload cache); use inline payload", i)
		}
	}

	normalize := normalizeVersion
	version := normalize(c.Version)
	if version == "" {
		version = "socks5"
	}
	auth := normalizeAuthMethod(c.AuthMethod)
	if version == "socks5" && auth == "" {
		auth = "no_auth"
	}
	cmd := normalizeCmd(c.Cmd)
	if cmd == "" {
		cmd = "connect"
	}

	emit := func(up bool, payload []byte) error {
		return g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: payload})
	}

	// --- SOCKS5 signaling（socks5.go:417-443 同款）---
	if version == "socks5" {
		if err := emit(true, buildGreeting(auth)); err != nil {
			return err
		}
		if err := emit(false, buildMethodResponse(auth)); err != nil {
			return err
		}
		if auth == "password" {
			if err := emit(true, buildAuthRequest(c.Username, c.Password)); err != nil {
				return err
			}
			if err := emit(false, buildAuthResponse()); err != nil {
				return err
			}
		}
		if err := emit(true, buildSocks5Request(cmd, c.DstAddr, c.DstPort)); err != nil {
			return err
		}
		if err := emit(false, buildSocks5Reply(c.Rep, c.BndAddr, c.BndPort)); err != nil {
			return err
		}
	} else {
		// --- SOCKS4 signaling（socks5.go:445-451 同款，两阶段）---
		if err := emit(true, buildSocks4Request(cmd, c.DstAddr, c.DstPort, c.UserID)); err != nil {
			return err
		}
		if err := emit(false, buildSocks4Reply(c.Rep, c.BndAddr, c.BndPort)); err != nil {
			return err
		}
	}

	// --- Data plane（隧道数据面，socks5.go:453-493 同款；Rep=0 才发）---
	if c.Rep == 0 {
		for _, msg := range c.Data {
			dir := normalizeDirection(msg.Direction)
			if dir == "" {
				dir = "up"
			}
			if err := emit(dir != "down", []byte(msg.Payload)); err != nil {
				return err
			}
		}
	}

	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream（pop3 layer_gen.go 同款 escape hatch）。
func (g *SOCKS5Generator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *SOCKS5Generator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *SOCKS5Generator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("socks5 generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("socks5", func() (layers.LayerGenerator, error) {
		return &SOCKS5Generator{}, nil
	})
	layers.RegisterLayerValidator("socks5", func(spec *core.FlowSpec) error {
		// 链路径限制先行拒绝（生成器同款检查作双保险——链上"驱动失败 →
		// 空流"契约会把生成器错误吞成 completed+0 包，enip/mqtt 同款纪律）：
		// UDP relay 需第二个 4-tuple、FileSource 需 engine 级缓存。
		s := spec.Socks
		if s != nil {
			if s.UDP != nil {
				return fmt.Errorf("socks5: udp relay sub-flow not supported on layer chains (UDP relay needs a second 4-tuple); use the flat socks5 protocol instead")
			}
			for i, msg := range s.Data {
				if msg.FileSource != nil {
					return fmt.Errorf("socks5: data[%d] file_source not supported on layer chains (FlowMeta does not carry the payload cache); use inline payload", i)
				}
			}
		}
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 握手/挥手校准进 spec.TCP（pop3/imap layer_gen.go 同款陷阱）：
		// legacy socks5 planner 恒产 TCP 握手/挥手——spec.TCP 零值 false
		// 必须写默认 true，否则 tcp 层生成器跳过握手/挥手。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
