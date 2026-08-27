package redis

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// RedisGenerator is the redis terminal-layer generator (redis 终结层层生成器)。
// Redis RESP 2/3——一次 flow = 一条 TCP 连接上按序命令/回复对：bootstrap
// （RESP3 HELLO / RESP2 AUTH）→ SELECT n → CLIENT SETNAME → SUBSCRIBE /
// PSUBSCRIBE 订阅 → 命令流水线（PipelineSize>1 时先发 N 命令再收 N 回复）→
// PUBLISH → 结束。每条 wire 帧一个"报文事件"（方向 + 完整 RESP 字节），
// 构建字节由 encodeRESPArray / encodeSubConfirm / resolveReply 纯函数产出
// （复用，不重写）。事件模式（mqtt/modbus/dnp3 同款）：TCP 语义（握手/
// seq-ack/挥手/MSS 分段）交给 tcp 层生成器。
//
// 与 legacy Plan（redis planner.go:209-499）的差异（文档化 divergence）：
//   - legacy 自产 TCP 握手（3 包）与挥手（RST 或 4 包 FIN 序列，planner.go
//     443-499）——事件模式不产：tcp 层生成器负责（防双握手）。握手/挥手
//     开关由 tcp 层 schema 默认 true 执行，validator 强制校准 true（legacy
//     恒产握手/挥手，语义一致）。legacy RST 挥手（spec.TCP.RST=true → 单
//     RST 包）不支持：链上 tcp 层终止恒 FIN 4 包，生成器忽略 spec.TCP.RST。
//   - seq/ack、ipID、Timestamp：legacy 由 emit 闭包推进（rand ISN / time.Now
//     / ipID++）；链上由 tcp 层生成器与 ChainPlanner 统一处理，事件流不产。
//   - 端口：legacy 单流用 spec.SrcPort/DstPort 原值；链上由 transport 层
//     持有（validateSpecBase 对 redis 无默认化分支，与 legacy 一致）。
//   - 逐事件错误（commandArgs 失败等）：legacy 静默 return（goroutine 内）；
//     生成器直接返回 error（链"驱动失败 → 空流"契约，validator 同款校验
//     前置）。
type RedisGenerator struct{}

// Name returns "redis".
func (g *RedisGenerator) Name() string { return "redis" }

// Generate produces one message event per Redis wire frame in legacy Plan
// order（bootstrap → select → setname → subscribe → pipeline → publish）。
// TCP 层生成器负责握手/seq-ack/挥手/MSS 分段。
func (g *RedisGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("redis generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	c := req.Meta.Redis
	if c == nil {
		// 与 legacy Plan 同款（planner.go:229-234）：空配置走默认 SelectDB=-1 +
		// 默认命令列表（单 PING）。
		c = &core.RedisConfig{SelectDB: -1}
	}

	cfg := *c

	// 默认化（legacy Plan 同款）：空 Commands 且无订阅/发布 → 默认 PING。
	commands := cfg.Commands
	if len(commands) == 0 && len(cfg.SubscribeTo) == 0 && len(cfg.SubscribePatterns) == 0 && len(cfg.PublishMessages) == 0 {
		commands = defaultCommands()
	}

	emit := func(up bool, payload []byte) error {
		return g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: payload})
	}

	// --- RESP3 HELLO / RESP2 AUTH bootstrap（planner.go 353-382 同款）---
	version := cfg.Version
	if version == 0 {
		version = 2
	}
	if version == 3 && !cfg.SkipHello {
		args := [][]byte{[]byte("HELLO"), []byte("3")}
		if cfg.Password != "" {
			args = append(args, []byte("AUTH"))
			if cfg.Username != "" {
				args = append(args, []byte(cfg.Username))
			}
			args = append(args, []byte(cfg.Password))
		}
		if err := emit(true, encodeRESPArray(args)); err != nil {
			return err
		}
		if err := emit(false, []byte("%0\r\n")); err != nil {
			return err
		}
	} else if version == 2 && cfg.Password != "" {
		args := [][]byte{[]byte("AUTH")}
		if cfg.Username != "" {
			args = append(args, []byte(cfg.Username))
		}
		args = append(args, []byte(cfg.Password))
		if err := emit(true, encodeRESPArray(args)); err != nil {
			return err
		}
		if err := emit(false, []byte("+OK\r\n")); err != nil {
			return err
		}
	}

	// --- SELECT n（planner.go 384-389 同款）---
	if cfg.SelectDB >= 0 {
		if err := emit(true, encodeRESPArray(bytesArgs("SELECT", strconv.Itoa(cfg.SelectDB)))); err != nil {
			return err
		}
		if err := emit(false, []byte("+OK\r\n")); err != nil {
			return err
		}
	}

	// --- CLIENT SETNAME（planner.go 391-395 同款）---
	if cfg.ClientName != "" {
		if err := emit(true, encodeRESPArray(bytesArgs("CLIENT", "SETNAME", cfg.ClientName))); err != nil {
			return err
		}
		if err := emit(false, []byte("+OK\r\n")); err != nil {
			return err
		}
	}

	// --- SUBSCRIBE / PSUBSCRIBE（planner.go 397-417 同款）---
	if len(cfg.SubscribeTo) > 0 {
		args := append([]string{"SUBSCRIBE"}, cfg.SubscribeTo...)
		if err := emit(true, encodeRESPArray(bytesArgs(args...))); err != nil {
			return err
		}
		for i, ch := range cfg.SubscribeTo {
			if err := emit(false, encodeSubConfirm("subscribe", ch, i+1)); err != nil {
				return err
			}
		}
	}
	if len(cfg.SubscribePatterns) > 0 {
		args := append([]string{"PSUBSCRIBE"}, cfg.SubscribePatterns...)
		if err := emit(true, encodeRESPArray(bytesArgs(args...))); err != nil {
			return err
		}
		for i, pat := range cfg.SubscribePatterns {
			if err := emit(false, encodeSubConfirm("psubscribe", pat, i+1)); err != nil {
				return err
			}
		}
	}

	// --- 命令流水线（planner.go 419-459 同款）---
	pipeline := cfg.PipelineSize
	if pipeline < 1 {
		pipeline = 1
	}
	for start := 0; start < len(commands); start += pipeline {
		end := start + pipeline
		if end > len(commands) {
			end = len(commands)
		}
		batch := commands[start:end]
		replies := make([][]byte, 0, len(batch))

		for _, cmd := range batch {
			args, err := commandArgs(cmd)
			if err != nil {
				return err
			}
			if err := emit(true, encodeRESPArray(args)); err != nil {
				return err
			}
			reply := resolveReply(cmd)
			if cmd.EmitAsPush && len(reply) > 0 && reply[0] != '>' {
				reply = encodeRESP3Push([][]byte{reply})
			}
			replies = append(replies, reply)
		}

		for _, reply := range replies {
			if len(reply) > 0 {
				if err := emit(false, reply); err != nil {
					return err
				}
			}
		}
	}

	// --- PUBLISH messages（planner.go 461-476 同款）---
	for _, pub := range cfg.PublishMessages {
		msg := []byte(pub.Message)
		if pub.MessageB64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(pub.MessageB64)
			if err != nil {
				return fmt.Errorf("redis: PUBLISH message_b64: %w", err)
			}
			msg = decoded
		}
		if err := emit(true, encodeRESPArray([][]byte{[]byte("PUBLISH"), []byte(pub.Channel), msg})); err != nil {
			return err
		}
		if err := emit(false, []byte(":1\r\n")); err != nil {
			return err
		}
	}

	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream（mqtt/modbus layer_gen.go 同款 escape hatch）。
func (g *RedisGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *RedisGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *RedisGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("redis generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("redis", func() (layers.LayerGenerator, error) {
		return &RedisGenerator{}, nil
	})
	layers.RegisterLayerValidator("redis", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 握手/挥手校准进 spec.TCP（mqtt/modbus layer_gen.go 同款陷阱）：
		// legacy redis planner.go 恒产 TCP 握手/挥手（443-499 无开关，从不读
		// spec.TCP.Handshake/Termination）——spec.TCP 零值 false 必须写默认
		// true，否则 tcp 层生成器跳过握手/挥手（链测试 spec.TCP 只设
		// InitialSeq 即复现）。与 legacy 语义一致：redis 链上的握手/挥手
		// 不可关（legacy 亦无此表达）。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
