package mysql

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// MySQLGenerator is the mysql terminal-layer generator (mysql 终结层层生成器)。
// MySQL 客户端/服务端协议——一次 flow = 一条 TCP 连接上：Server Greeting →
// [Client Handshake Response + Server Auth OK]（ServerBypassAuth 时跳过）→
// 逐命令请求/回复。每条 wire 帧一个"报文事件"，构建字节由
// encodeGreetingPayload / encodeHandshakeResponsePayload /
// encodeServerAuthOKPayload / encodeStmtExecuteRequest / buildReplyPackets /
// framePacket 纯函数产出（复用，不重写）。事件模式（smtp/pop3/imap 同款）：
// TCP 语义（握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器。
//
// 与 legacy Plan（planner.go:339-536）的差异（文档化 divergence）：
//   - legacy 自产 TCP 握手（3 包，handshakeEnabled 读 spec.TCP）与挥手
//     （4 包 FIN 序列）——事件模式不产：tcp 层生成器负责；validator 强制
//     spec.TCP.Handshake/Termination=true（legacy 恒产语义一致）。
//   - seq/ack、ipID、Timestamp、MSS 分段：链上由 tcp 层生成器处理。
//   - nil config 默认化与 legacy 同款（mc = &core.MySQLConfig{}）。
type MySQLGenerator struct{}

// Name returns "mysql".
func (g *MySQLGenerator) Name() string { return "mysql" }

// Generate produces one message event per MySQL wire frame in legacy Plan
// order（greeting → auth → commands）。TCP 层生成器负责握手/seq-ack/挥手/
// MSS 分段。
func (g *MySQLGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("mysql generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	mc := req.Meta.MySQL
	if mc == nil {
		// 与 legacy Plan 同款（planner.go:349-351）：空配置走默认。
		mc = &core.MySQLConfig{}
	}
	emit := func(up bool, payload []byte) error {
		return g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: payload})
	}

	// --- 2. Server Greeting (seq=0, planner.go:465-466 同款) ---
	greetingPayload := encodeGreetingPayload(mc)
	if err := emit(false, framePacket(0, greetingPayload)); err != nil {
		return err
	}

	// --- 3+4. Client Handshake Response + Server Auth OK
	// （planner.go:468-482 同款；ServerBypassAuth 跳过）---
	if !mc.ServerBypassAuth {
		responsePayload := encodeHandshakeResponsePayload(mc)
		if err := emit(true, framePacket(1, responsePayload)); err != nil {
			return err
		}
		authReplyPayload := encodeServerAuthOKPayload(mc)
		if err := emit(false, framePacket(2, authReplyPayload)); err != nil {
			return err
		}
	}

	// --- 5. Each MySQLCommand（planner.go:485-517 同款）---
	for _, cmd := range mc.Commands {
		var cmdPacket []byte
		if cmd.Opcode == comStmtExecute && cmd.Body == "" && cmd.StmtID != 0 {
			cmdPacket = encodeStmtExecuteRequest(cmd)
		} else {
			bodyBytes, err := decodeUserBytes(cmd.Body, cmd.BodyEncoding)
			if err != nil {
				return fmt.Errorf("mysql generator: command body decode: %w", err)
			}
			cmdPacket = make([]byte, 0, 1+len(bodyBytes))
			cmdPacket = append(cmdPacket, cmd.Opcode)
			cmdPacket = append(cmdPacket, bodyBytes...)
		}
		if err := emit(true, framePacket(0, cmdPacket)); err != nil {
			return err
		}

		replySeq := uint8(1)
		replies := buildReplyPackets(cmd, mc)
		for _, rp := range replies {
			if err := emit(false, framePacket(replySeq, rp)); err != nil {
				return err
			}
			replySeq++
		}
	}

	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream（smtp layer_gen.go 同款 escape hatch）。
func (g *MySQLGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *MySQLGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *MySQLGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("mysql generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("mysql", func() (layers.LayerGenerator, error) {
		return &MySQLGenerator{}, nil
	})
	layers.RegisterLayerValidator("mysql", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 握手/挥手校准进 spec.TCP（smtp/redis/pop3/imap layer_gen.go 同款
		// 陷阱）：legacy mysql planner 恒产 TCP 握手/挥手——spec.TCP 零值
		// false 必须写默认 true，否则 tcp 层生成器跳过握手/挥手。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
