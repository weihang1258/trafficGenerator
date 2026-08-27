package pop3

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// POP3Generator is the pop3 terminal-layer generator (pop3 终结层层生成器)。
// POP3（RFC 1939）——一次 flow = 一条 TCP 连接上：可选 banner → 命令/响应
// 对序列（MailDrop/TOP 合成或用户 Response）。每条 wire 帧一个"报文事件"
// （方向 + 完整字节），构建字节由 buildMailDropResponse / buildTopResponse
// 纯函数产出（复用，不重写）。事件模式（smtp/redis/mqtt 同款）：TCP 语义
// （握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器。
//
// 与 legacy Plan（planner.go:213-406）的差异（文档化 divergence）：
//   - legacy 自产 TCP 握手（3 包）与挥手（4 包 FIN 序列，planner.go:395-405）
//     ——事件模式不产：tcp 层生成器负责（防双握手）。握手/挥手开关由 tcp 层
//     schema 默认 true 执行，validator 强制校准 true（legacy 恒产握手/挥手）。
//   - seq/ack、ipID、Timestamp、MSS 分段：链上由 tcp 层生成器处理，事件流不产。
type POP3Generator struct{}

// Name returns "pop3".
func (g *POP3Generator) Name() string { return "pop3" }

// Generate produces one message event per POP3 wire frame in legacy Plan
// order（banner → commands）。TCP 层生成器负责握手/seq-ack/挥手/MSS 分段。
func (g *POP3Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("pop3 generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	c := req.Meta.POP3
	if c == nil {
		// 与 legacy 同款（Plan 对 nil Config 走默认空会话）：空命令序列。
		c = &core.POP3Config{}
	}
	emit := func(up bool, payload []byte) error {
		return g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: payload})
	}

	// --- Server banner（可选，planner.go:330-337 同款；空 = 跳过）---
	if c.Banner != "" {
		if err := emit(false, []byte(c.Banner+"\r\n")); err != nil {
			return err
		}
	}

	// --- POP3 command/response pairs（planner.go:339-371 同款）---
	for _, cmd := range c.Commands {
		// Command（client→server，CRLF 后缀；空 Cmd = 只发响应的服务端轮次）。
		if cmd.Cmd != "" {
			if err := emit(true, []byte(cmd.Cmd+"\r\n")); err != nil {
				return err
			}
		}

		// Response：EmitMailDrop/EmitTop 合成优先于用户 Response；
		// Multiline=true 用户自带终止符原样发；false 追加 CRLF。
		switch {
		case cmd.EmitMailDrop && c.Mailbox != nil:
			respBytes := buildMailDropResponse(c.Mailbox.Messages[cmd.MsgNum-1])
			if err := emit(false, respBytes); err != nil {
				return err
			}
		case cmd.EmitTop && c.Mailbox != nil:
			respBytes := buildTopResponse(c.Mailbox.Messages[cmd.MsgNum-1], cmd.TopLines)
			if err := emit(false, respBytes); err != nil {
				return err
			}
		case cmd.Response != "":
			payload := []byte(cmd.Response)
			if !cmd.Multiline {
				payload = append(payload, '\r', '\n')
			}
			if err := emit(false, payload); err != nil {
				return err
			}
		}
	}

	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream（smtp layer_gen.go 同款 escape hatch）。
func (g *POP3Generator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *POP3Generator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *POP3Generator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("pop3 generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("pop3", func() (layers.LayerGenerator, error) {
		return &POP3Generator{}, nil
	})
	layers.RegisterLayerValidator("pop3", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 握手/挥手校准进 spec.TCP（smtp/redis layer_gen.go 同款陷阱）：
		// legacy pop3 planner 恒产 TCP 握手/挥手——spec.TCP 零值 false 必须
		// 写默认 true，否则 tcp 层生成器跳过握手/挥手。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
