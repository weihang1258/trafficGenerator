package a2a

// A2AGenerator is the a2a terminal-layer generator (a2a 终结层层生成器,
// P4a)。A2A 是 HTTP/JSON-RPC over TCP（A2A spec v0.2.2+）——每条 task 是
// 一个 HTTP POST（JSON-RPC body）+ 一个 HTTP 响应（JSON 或 SSE chunked），
// 可选 Agent Card 发现 GET。TCP 语义（握手/seq-ack/挥手/MSS 分段）全部交给
// tcp 层生成器（http 波 2 方案 A 同款事件模式：终结层只产"报文事件"=
// 方向 + 完整字节）。
//
// 生成器逐任务复用 legacy 纯函数（buildAgentCardRequest/buildA2ARequest/
// buildJSONRPCRequest/buildHTTPResponse/buildSSEResponse——全部无副作用，
// 字节级一致），零序列逻辑复制。A2A 配置经 spec.Payload（A2AConfig JSON）
// 携带（strategy_convert.go:959-966 a2a case 同款），生成器从
// FlowMeta.Payload 解析——core 不引入 A2A 类型，链上零配置负载。
//
// 与 legacy planUnit 的差异（文档化 divergence）：
//   - 独立 ACK（legacy ACKPolicy=immediate 每响应后 0x10 纯 ACK，a2a.go:655）
//     在事件模式下不产：TCPGenerator 段间 piggyback（http 波 2 同款先例）。
//     ACKPolicy=lazy 时 legacy 本就不产独立 ACK，与事件模式天然一致。
//   - 挥手从 legacy 3 包（FIN-ACK/FIN-ACK/ACK，中间 ACK 并入 FIN，
//     a2a.go:663-668）变为 TCPGenerator 标准 4 包（FIN-ACK/ACK/FIN-ACK/ACK，
//     http 波 2 同款先例）。
//   - cfg.TCP 的 MSS/InitialSeq/Handshake/Termination 经 LayerValidator 校准
//     进 spec.TCP，tcp 层生成器按 legacy 值执行（见 init 的 validator）。

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/jsonrpc"
)

// A2AGenerator is the a2a terminal-layer generator.
type A2AGenerator struct{}

// Name returns "a2a".
func (g *A2AGenerator) Name() string { return "a2a" }

// Generate produces one message event per HTTP message in transaction
// order (Agent Card GET → per-task POST/response)。TCP 层生成器负责
// 握手/seq-ack/挥手/MSS 分段。
//
// 与 legacy planUnit（a2a.go:421-673）逐字对齐的事件顺序：
//   - Discover && AgentCard != nil：GET Agent Card（up）→ 200 JSON（down）
//   - 每 task：POST JSON-RPC（up）→ 响应（down；Streaming=true 时 SSE
//     chunked，否则 JSON）
//   - Connection 头：last task && termination → "close"（legacy 同款）
//
// 不做 legacy 的独立 ACK/挥手（divergence 见文件头注释）。
func (g *A2AGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("a2a generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	var cfg A2AConfig
	if len(req.Meta.Payload) == 0 {
		return fmt.Errorf("a2a generator: no config (spec.Payload must carry A2AConfig JSON)")
	}
	if err := json.Unmarshal(req.Meta.Payload, &cfg); err != nil {
		return fmt.Errorf("a2a generator: invalid config JSON in Payload: %w", err)
	}
	// 空任务序列：legacy planUnit 在 Validate 后恒过（Tasks 空 = 只握手+挥手），
	// 但事件模式下无事件 = 链上只剩 TCP 空连接。显式拒绝，不能静默产空连接。
	if len(cfg.Tasks) == 0 {
		return fmt.Errorf("a2a generator: no tasks configured")
	}

	tcpCfg := cfg.TCP

	// 构造 Agent Card 发现请求（legacy a2a.go:552-568 同款字节）。
	if cfg.Discover && cfg.AgentCard != nil {
		path := cfg.AgentCardPath
		if path == "" {
			path = DefaultAgentCardPath
		}
		reqBytes := []byte(buildAgentCardRequest(&cfg, path, req.Meta.DstIP))
		if err := g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: reqBytes}); err != nil {
			return err
		}
		respBody, _ := json.Marshal(cfg.AgentCard)
		resp := []byte(buildHTTPResponse(&cfg, 200, "OK", "application/json", respBody, false))
		if err := g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: resp}); err != nil {
			return err
		}
	}

	// 逐 task 请求/响应（legacy a2a.go:571-658 同款循环）。
	for taskIdx, task := range cfg.Tasks {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		method := task.Method
		if method == "" {
			method = DefaultMethod
		}
		isLastTask := taskIdx == len(cfg.Tasks)-1
		isStreaming := task.Streaming

		reqBody := buildJSONRPCRequest(&cfg, task, method)
		accept := cfg.HTTP.Accept
		if accept == "" {
			accept = DefaultAccept
		}
		if isStreaming {
			accept = "text/event-stream"
		}
		connection := cfg.HTTP.Connection
		if connection == "" {
			connection = DefaultConnection
		}
		if isLastTask && terminationDefaulted(tcpCfg) {
			connection = "close"
		}

		reqBytes := []byte(buildA2ARequest(&cfg, method, reqBody, accept, connection, req.Meta.DstIP))
		if err := g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: reqBytes}); err != nil {
			return err
		}

		// 响应：Streaming=true 时 SSE chunked 帧（legacy a2a.go:601-612），
		// 否则 JSON-RPC 结果/错误（legacy a2a.go:613-652）。
		var resp string
		if isStreaming {
			sseBody := buildSSEResponse(&cfg, task)
			statusCode := task.Response.StatusCode
			if statusCode == 0 {
				statusCode = 200
			}
			resp = buildHTTPResponse(&cfg, statusCode, statusTextFor(statusCode), "text/event-stream", sseBody, true)
		} else {
			var respBody []byte
			if task.Response.Error != nil {
				errObj := map[string]any{
					"code":    task.Response.Error.Code,
					"message": task.Response.Error.Message,
				}
				if task.Response.Error.Data != nil {
					errObj["data"] = task.Response.Error.Data
				}
				rawID := unmarshalID(task.RequestID)
				resolvedID := resolveIDForOutput(rawID)
				respMap := map[string]any{
					"jsonrpc": jsonrpc.Version,
					"error":   errObj,
					"id":      resolvedID,
				}
				respBody, _ = jsonrpc.Marshal(respMap)
			} else {
				rawID := unmarshalID(task.RequestID)
				resolvedID := resolveIDForOutput(rawID)
				respMap := map[string]any{
					"jsonrpc": jsonrpc.Version,
					"result":  json.RawMessage(task.Response.Result),
					"id":      resolvedID,
				}
				respBody, _ = jsonrpc.Marshal(respMap)
			}
			statusCode := task.Response.StatusCode
			if statusCode == 0 {
				statusCode = 200
			}
			resp = buildHTTPResponse(&cfg, statusCode, statusTextFor(statusCode), "application/json", respBody, false)
		}
		if err := g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: []byte(resp)}); err != nil {
			return err
		}
	}
	return nil
}

// terminationDefaulted reports the effective termination flag (legacy
// a2a.go:454-457 同款：nil→true，显式 false→false）。
func terminationDefaulted(tcpCfg A2ATCP) bool {
	if tcpCfg.Termination != nil {
		return *tcpCfg.Termination
	}
	return true
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks).
func (g *A2AGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *A2AGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *A2AGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("a2a generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("a2a", func() (layers.LayerGenerator, error) {
		return &A2AGenerator{}, nil
	})
	layers.RegisterLayerValidator("a2a", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// cfg.TCP 校准进 spec.TCP（legacy a2a.go:466-497 同款优先级：
		// cfg.TCP.MSS > spec.TCP.MSS；Handshake/Termination 默认 true 经
		// 指针区别未设置与显式 false）。tcp 层生成器据此执行 legacy 的
		// TCP 参数（http 波 2 isHTTPChain 同款语义，此处为 a2a 专用）。
		var cfg A2AConfig
		if err := json.Unmarshal(spec.Payload, &cfg); err != nil {
			return err
		}
		tcp := &cfg.TCP
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		if tcp.MSS > 0 {
			spec.TCP.MSS = tcp.MSS
		}
		if tcp.InitialSeq != 0 {
			spec.TCP.InitialSeq = tcp.InitialSeq
		}
		// Handshake/Termination：nil = 未设置 = 默认 true（legacy
		// a2a.go:452-457 同款）。spec.TCP 是零值 false——必须把默认值写进
		// spec.TCP，否则 tcp 层生成器读到 false 会跳过握手/挥手。
		hs, term := true, true
		if tcp.Handshake != nil {
			hs = *tcp.Handshake
		}
		if tcp.Termination != nil {
			term = *tcp.Termination
		}
		spec.TCP.Handshake = hs
		spec.TCP.Termination = term
		return nil
	})
}
