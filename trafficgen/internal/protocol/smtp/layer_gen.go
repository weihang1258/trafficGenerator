// layer_gen.go: SMTP terminal-layer generator (smtp 终结层层生成器)。
//
// SMTP (RFC 5321) 是单条 TCP 连接上的会话级文本协议：一次 flow = 一条 TCP
// 连接（握手 → banner → 命令/响应对 → 挥手）。生成器把每条线上载荷产出一个
// "报文事件"（方向 + 完整字节，CRLF 终止），构建字节与 legacy Plan
// （planner.go Plan 117-340）的 data 帧一一对应：
//
//  1. banner（down）：当 SMTPConfig.Banner 为空时自动生成
//     "220 <DstIP> ESMTP trafficgen"（design_smtp.md §8.6，planner.go:241-252
//     同款）。
//  2. Dialog 逐条 SMTPCommand：客户端命令（up，+ "\r\n"）+ 服务端响应
//     （down，+ "\r\n"），Direction 覆盖语义与 legacy 一致（Cmd 默认 up、
//     Response 默认 down；空 Cmd/Response 跳过——支持纯服务端/纯客户端轮次）。
//  3. SMTPConfig.Email 设置时，DATA/354 对之后注入自动构造的邮件 body
//     （buildSMTPEmailBody，含终止符）+ 自动 250 响应（planner.go:319-323 同款）。
//
// TCP 语义（握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器（事件模式，http
// 波 2 方案 A / smb/mqtt P4a 同款）。生成器不产 TCP 握手/挥手包——防双握手。
//
// 与 legacy Plan 的差异（文档化 divergence，smb/mqtt 层生成器同款先例）：
//   - legacy 自产 TCP 握手（SYN/SYN-ACK/ACK，带 MSS/WinScale/SACK 选项）与
//     挥手（FIN up → ACK down → FIN down → ACK up）——事件模式不产：tcp 层
//     生成器负责。链上挥手是 TCPGenerator 标准 4 包（FIN|ACK up → ACK down →
//     FIN|ACK down → ACK up），与 legacy 4 包挥手为层模型意图的文档化分歧。
//   - MSS 分段：legacy emitData 按 spec.TCP.MSS 切段；链上由 tcp 层生成器
//     执行（事件 = 完整 payload），不预分段。
//   - 握手 seq / 逐包 Timestamp：legacy Plan 内随机 ISN + 恒 now；链上由
//     tcp 层生成器 / ChainPlanner 统一回填。
//   - 源端口：legacy 用 spec.SrcPort 原值（0 也上包，planner.go:215 同款）——
//     validateSpecBase 对 smtp 分支不默认化 srcPort，与 legacy 一致。
//   - 目的端口默认化：legacy 由 strategy_convert 默认 25（submission 587 /
//     SMTPS 465 需用户显式）；链上由 smtp 层 FieldContract tcp.dst_port=25
//     补齐（用户显式非标准端口优先，不强制）。
package smtp

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// SMTPGenerator is the smtp terminal-layer generator.
type SMTPGenerator struct{}

// Name returns "smtp".
func (g *SMTPGenerator) Name() string { return "smtp" }

// Generate produces one message event per SMTP wire payload in legacy Plan
// order（banner → Dialog 命令/响应对 → Email body 注入；planner.go Plan
// 117-340 同序）。TCP 层生成器负责握手/seq-ack/挥手/MSS 分段。
func (g *SMTPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("smtp generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.SMTP
	if cfg == nil {
		// 与 legacy Plan 同款（planner.go:129-132）：空配置走默认 banner +
		// 默认 dialog（HELO + MAIL + RCPT + DATA + 空 body + QUIT）。
		cfg = &core.SMTPConfig{}
	}

	emit := func(ev layers.MessageEvent) error {
		return emitSel(ctx, req.EmitMsg, ev)
	}

	// --- banner（planner.go:236-252 同款）---
	// 恒发（空则自动生成 220 问候）：RFC 5321 §3.1 要求握手后第一条服务端
	// 载荷是 220 问候，缺了不成有效 SMTP 会话。
	banner := cfg.Banner
	if banner == "" {
		banner = fmt.Sprintf("220 %s ESMTP trafficgen", req.Meta.DstIP)
	}
	if err := emit(layers.MessageEvent{Up: false, Bytes: []byte(banner + "\r\n")}); err != nil {
		return err
	}

	// --- Dialog 命令/响应对（planner.go:254-324 同款）---
	dialog := cfg.Dialog
	if len(dialog) == 0 {
		if cfg.Email != nil {
			dialog = defaultEmailDialog()
		} else {
			dialog = defaultDialog()
		}
	}
	var emailBody []byte
	if cfg.Email != nil {
		emailBody = buildSMTPEmailBody(cfg.Email)
	}
	for _, cmd := range dialog {
		// 客户端命令：空 Cmd 跳过（纯服务端轮次，如 354 后的 body）。
		if cmd.Cmd != "" {
			direction := cmd.Direction
			if direction == "" {
				direction = "up"
			}
			if err := emit(layers.MessageEvent{Up: direction != "down", Bytes: []byte(cmd.Cmd + "\r\n")}); err != nil {
				return err
			}
		}
		// 服务端响应：空 Response 跳过（纯客户端轮次，如 DATA body 本身）。
		if cmd.Response != "" {
			direction := cmd.Direction
			if direction == "" {
				direction = "down"
			}
			if err := emit(layers.MessageEvent{Up: direction == "up", Bytes: []byte(cmd.Response + "\r\n")}); err != nil {
				return err
			}
		}
		// Email body 注入（planner.go:319-323 同款）：DATA 命令的 354 响应
		// 之后注入自动构造的 body + 自动 250 响应（Email 设置时 Dialog 不得
		// 再含 body Cmd——重复）。
		if emailBody != nil && isDATACommand(cmd.Cmd) {
			if err := emit(layers.MessageEvent{Up: true, Bytes: emailBody}); err != nil {
				return err
			}
			if err := emit(layers.MessageEvent{Up: false, Bytes: []byte(smtpDefault250Response + "\r\n")}); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitSel sends one event, honoring context cancellation so the generator
// cannot hang when the transport layer stops consuming the event stream.
func emitSel(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return emit(ev)
	}
}

// GenEvents marks this generator as a message event producer.
func (g *SMTPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *SMTPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("smtp generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("smtp", func() (layers.LayerGenerator, error) {
		return &SMTPGenerator{}, nil
	})
	layers.RegisterLayerValidator("smtp", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
