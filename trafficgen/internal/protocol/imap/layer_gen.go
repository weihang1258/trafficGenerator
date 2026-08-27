package imap

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// IMAPGenerator is the imap terminal-layer generator (imap 终结层层生成器)。
// IMAP4rev1/IMAP4rev2（RFC 3501/9051）——一次 flow = 一条 TCP 连接上：可选
// greeting → 命令/响应序列（literal {N} 占位、AUTHENTICATE 取消、UID 缓存
// 失效、可选 IDLE RFC 2177、可选流水线）。每条 wire 帧一个"报文事件"，
// 构建字节由 formatCommandLine / constructMIMEBody / replaceLiteralPlaceholder
// 纯函数产出（复用，不重写）。事件模式（smtp/pop3 同款）：TCP 语义
// （握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器。
//
// 与 legacy Plan（planner.go:296-668）的差异（文档化 divergence）：
//   - legacy 自产 TCP 握手（3 包）与挥手（4 包 FIN 序列）——事件模式不产：
//     tcp 层生成器负责；validator 强制 spec.TCP.Handshake/Termination=true
//     （legacy 恒产握手/挥手）。
//   - seq/ack、ipID、Timestamp、MSS 分段：链上由 tcp 层生成器处理。
//   - FileSource literal 在链路径不可用：resolveLiteral 的 FileSource 分支
//     依赖 ctx 携带的 PayloadCache（engine 级缓存），FlowMeta 不承载——
//     与 tftp layer_gen 对 FileSource 的降级同款。LiteralBody/LiteralBodyB64/
//     MIMEBody 路径完整可用。
type IMAPGenerator struct{}

// Name returns "imap".
func (g *IMAPGenerator) Name() string { return "imap" }

// Generate produces one message event per IMAP wire frame in legacy Plan
// order（greeting → commands(+responses/IDLE)）。TCP 层生成器负责握手/
// seq-ack/挥手/MSS 分段。
func (g *IMAPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("imap generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	c := req.Meta.IMAP
	if c == nil {
		c = &core.IMAPConfig{}
	}
	emit := func(up bool, payload []byte) error {
		return g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: payload})
	}

	// --- Server greeting（planner.go:430-437 同款；缺 CRLF 自动补）---
	if c.Banner != "" {
		banner := c.Banner
		if !strings.HasSuffix(banner, "\r\n") {
			banner += "\r\n"
		}
		if err := emit(false, []byte(banner)); err != nil {
			return err
		}
	}

	autoTagCounter := 0
	autoTag := func() string {
		autoTagCounter++
		return fmt.Sprintf("A%03d", autoTagCounter)
	}

	// resolveLiteral：MIMEBody > LiteralBodyB64 > LiteralBody（FileSource
	// 链路径不可用——见类型注释）。ok=false = 无 literal 源。
	resolveLiteral := func(cmd core.IMAPCommand) ([]byte, bool) {
		if cmd.MIMEBody != nil {
			return constructMIMEBody(cmd.MIMEBody), true
		}
		if cmd.LiteralBodyB64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(cmd.LiteralBodyB64)
			if err != nil {
				return nil, true // Validate 已检查；防御性跳过
			}
			return decoded, true
		}
		if cmd.LiteralBody != "" {
			return []byte(cmd.LiteralBody), true
		}
		return nil, false
	}

	// emitCommandWithOptionalLiteral（planner.go:479-500 同款）：命令行 +
	// {N} 占位时的 literal 体（up 方向）。
	emitCommandWithOptionalLiteral := func(cmd core.IMAPCommand, tag string) error {
		if cmd.Cmd == "" {
			return nil
		}
		line := formatCommandLine(tag, cmd.Cmd) + "\r\n"
		if err := emit(true, []byte(line)); err != nil {
			return err
		}
		if hasLiteralPlaceholder(cmd.Cmd) {
			if body, ok := resolveLiteral(cmd); ok && len(body) > 0 {
				return emit(true, body)
			}
		}
		return nil
	}

	// emitResponses（planner.go:514-562 同款）：逐响应（{N} 占位替换 + literal
	// 体 + 收尾 CRLF / 单行追加 CRLF）、CancelAfterResponses 中途取消、
	// UIDCacheInvalidation 尾注。
	emitResponses := func(cmd core.IMAPCommand, cancelAfter int) error {
		literalBody, _ := resolveLiteral(cmd)
		cancelEmitted := false
		for j, resp := range cmd.Responses {
			if cancelAfter > 0 && j == cancelAfter && !cancelEmitted {
				if err := emit(true, []byte(AuthCancelLine)); err != nil {
					return err
				}
				cancelEmitted = true
			}
			var payload []byte
			var literalFollows bool
			if hasLiteralPlaceholder(resp) {
				payload = []byte(replaceLiteralPlaceholder(resp, len(literalBody)) + "\r\n")
				literalFollows = true
			} else {
				payload = []byte(resp + "\r\n")
			}
			if err := emit(false, payload); err != nil {
				return err
			}
			if literalFollows {
				if len(literalBody) > 0 {
					if err := emit(false, literalBody); err != nil {
						return err
					}
				}
				// 收尾 CRLF 关 FETCH 响应行（RFC 9051 §2.2.4 同款）。
				if err := emit(false, []byte("\r\n")); err != nil {
					return err
				}
			}
		}
		if cmd.UIDCacheInvalidation {
			return emit(false, []byte(UIDCacheInvalidationResponse))
		}
		return nil
	}

	// emitIDLE（planner.go:573-624 同款）：IDLE → + idling → push → DONE →
	// done response → 可选 timeout BYE。IDLE 命令复用所属命令的 tag
	// （legacy emitIDLE(cmd, tags[i]) 传入 command tag）。
	emitIDLE := func(tag string, idle *core.IMAPIDLE) error {
		if idle == nil {
			return nil
		}
		idleCmd := formatCommandLine(tag, "IDLE") + "\r\n"
		if err := emit(true, []byte(idleCmd)); err != nil {
			return err
		}
		if err := emit(false, []byte(IDLEContuation)); err != nil {
			return err
		}
		for _, push := range idle.PushResponses {
			if err := emit(false, []byte(push+"\r\n")); err != nil {
				return err
			}
		}
		if err := emit(true, []byte(IDLEDone)); err != nil {
			return err
		}
		if idle.DoneResponse != "" {
			if err := emit(false, []byte(idle.DoneResponse+"\r\n")); err != nil {
				return err
			}
		}
		switch idle.ServerTimeoutBehavior {
		case "close_after_idle", "keep_idle":
			if err := emit(false, []byte(IDLETimeoutBye)); err != nil {
				return err
			}
		}
		return nil
	}

	// --- 命令/响应对（PipelinedCommands 双相位 vs 默认逐条，planner.go
	// 653-676 同款）---
	if c.PipelinedCommands {
		tags := make([]string, len(c.Commands))
		for i, cmd := range c.Commands {
			tag := cmd.Tag
			if tag == "" {
				tag = autoTag()
			}
			tags[i] = tag
			if err := emitCommandWithOptionalLiteral(cmd, tag); err != nil {
				return err
			}
		}
		for i, cmd := range c.Commands {
			if err := emitResponses(cmd, cmd.CancelAfterResponses); err != nil {
				return err
			}
			if cmd.EmitIDLE && c.IDLE != nil {
				if err := emitIDLE(tags[i], c.IDLE); err != nil {
					return err
				}
			}
		}
	} else {
		for _, cmd := range c.Commands {
			tag := orAuto(cmd.Tag, autoTag)
			if err := emitCommandWithOptionalLiteral(cmd, tag); err != nil {
				return err
			}
			if err := emitResponses(cmd, cmd.CancelAfterResponses); err != nil {
				return err
			}
			if cmd.EmitIDLE && c.IDLE != nil {
				if err := emitIDLE(tag, c.IDLE); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// orAuto returns tag when non-empty, else the next auto tag.
func orAuto(tag string, next func() string) string {
	if tag != "" {
		return tag
	}
	return next()
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream（smtp layer_gen.go 同款 escape hatch）。
func (g *IMAPGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *IMAPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *IMAPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("imap generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("imap", func() (layers.LayerGenerator, error) {
		return &IMAPGenerator{}, nil
	})
	layers.RegisterLayerValidator("imap", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 握手/挥手校准进 spec.TCP（smtp/redis/pop3 layer_gen.go 同款陷阱）：
		// legacy imap planner 恒产 TCP 握手/挥手——spec.TCP 零值 false 必须
		// 写默认 true，否则 tcp 层生成器跳过握手/挥手。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
