package grpc

// GRPCGenerator is the grpc terminal-layer generator (grpc 终结层层生成器,
// P3)。gRPC over HTTP/2 (h2c, cleartext)——一次 flow = 一个 4-tuple 上的一条
// TCP 连接 + 一个 HTTP/2 连接的完整会话：client preface (24-byte magic +
// SETTINGS) → server SETTINGS + server ACK → client SETTINGS ACK → 逐 call
// [client HEADERS → client DATA → server HEADERS → server DATA → trailers]
// → GOAWAY。每条 wire 帧一个"报文事件"（方向 + 完整字节），构建字节由
// buildFrame / buildSettingsFrame / buildSettingsAck / buildRequestHeaders /
// buildDataFrameStream / buildResponseHeaders / buildTrailers /
// buildGoAwayFrame / buildPingFrame / buildRSTStreamFrame /
// buildWindowUpdateFrame / buildGRPCMessage 纯函数产出（复用，不重写）。
// 事件模式（mqtt/redis/smtp 同款）：TCP 语义（握手/seq-ack/挥手/MSS 分段）
// 交给 tcp 层生成器。
//
// 与 legacy Plan（planner.go Plan）的差异（文档化 divergence）：
//   - legacy 自产 TCP 握手（3 包 SYN/SYN-ACK/ACK，planner.go:460-467）与
//     挥手（4 包 FIN-ACK/ACK/FIN-ACK/ACK，planner.go:776-786）——事件模式
//     不产：tcp 层生成器负责（防双握手）。握手/挥手开关由 tcp 层 schema
//     默认 true 执行，validator 强制校准 true（legacy grpc.go 恒产握手/挥手，
//     从不读 spec.TCP.Handshake/Termination，语义一致）。链上挥手是
//     TCPGenerator 标准 4 包（FIN|ACK up → ACK down → FIN|ACK down → ACK up），
//     与 legacy 4 包挥手一致（mqtt/modbus/dnp3/doip 链测试同款断言形状）。
//   - legacy 逐包 Timestamp：legacy 恒 now；链上由 ChainPlanner 统一回填
//     （chain_planner.go:400），事件流不产。
//   - 握手 seq/ipID：legacy 在 spec.TCP.InitialSeq 为零时随机 ISN；链上由
//     tcp 层生成器持有，事件流不产。
//   - srcPort：legacy 单流用 spec.SrcPort 原值（emit 闭包直传）；
//     validateSpecBase 对 grpc 分支不默认化 srcPort，与 legacy 一致。
//   - dstPort 默认化：legacy Plan 内默认（8604）；链上由 validateSpecBase
//     默认化（chain_planner.go dst 端口 grpc 分支），生成器不再默认。
//   - 生成器在首个事件前同步检查多流（Calls 非空属合法多路复用，不拒绝；
//     Sessions 概念不存在于 GRPCConfig，无多流展开）。Calls 是同一 HTTP/2
//     连接上共享 SETTINGS/HPACK 表的并发流多路复用，非独立 4-tuple——
//     链上单 flow 支持（一连接一 flow，多 call 复用），与 mqtt Sessions
//     的独立 4-tuple 多流派生不同。
//
// 生成器内部顺序与 legacy Plan（466-786）逐帧一致；事件方向/字节与 legacy
// 数据帧（flags=0x18 PSH-ACK payload）一一对应。FileSource 解析（GetOrLoad
// 覆盖 RequestMessages[0]）在 legacy Plan 内（planner.go:520-525）——链上
// 生成器复用同一 getOrLoad 逻辑（见 Generate）。

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// GRPCGenerator is the grpc terminal-layer generator.
type GRPCGenerator struct{}

// Name returns "grpc".
func (g *GRPCGenerator) Name() string { return "grpc" }

// Generate produces one message event per gRPC/HTTP/2 wire frame in legacy
// Plan order（preface → SETTINGS 交换 → 逐 call HEADERS/DATA/trailers →
// GOAWAY）。TCP 层生成器负责握手/seq-ack/挥手/MSS 分段。
func (g *GRPCGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("grpc generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	c := req.Meta.GRPC
	if c == nil {
		// 与 legacy Plan 同款（planner.go:500-502：grpcConfig==nil →
		// &core.GRPCConfig{}）空配置走默认：单 unary 零消息 call，:path 空触发
		// buildRequestHeaders 的 schema 默认（Service/Method 空 → :path "/"）。
		c = &core.GRPCConfig{}
	}

	// --- 默认化（legacy Plan 内 466-520 同款）---
	cfg := *c
	// HeaderTableSize=0 → defaultHeaderTableSize（RFC 7540 §6.5.2）。
	headerTableSize := cfg.HeaderTableSize
	if headerTableSize == 0 {
		headerTableSize = defaultHeaderTableSize
	}

	// FileSource 解析：GetOrLoad 覆盖 RequestMessages[0]（planner.go:521-525
	// 同款）。PayloadCache 可能为 nil（链路径可能未注入）——与 legacy 一致：
	// 加载失败时静默忽略（Validate 已拒绝 FileSource 与 inline 并存）。
	fileSrc := cfg.FileSource
	if fileSrc != nil {
		if pc := core.PayloadCacheFrom(ctx); pc != nil {
			if b, err := pc.GetOrLoad(ctx, *fileSrc); err == nil {
				cfg.RequestMessages = [][]byte{b}
			}
		}
	}

	// 解析 request/response messages（resolveMessages：B64 优先于 raw）。
	reqMsgs := resolveMessages(cfg.RequestMessages, cfg.RequestMessagesB64)
	respMsgs := resolveMessages(cfg.ResponseMessages, cfg.ResponseMessagesB64)

	// 单 call 时 top-level Service/Method 描述（Calls 空）；Calls 非空则逐
	// call（planner.go:528-546 同款）。
	var calls []core.GRPCCall
	if len(cfg.Calls) > 0 {
		calls = cfg.Calls
	} else {
		calls = []core.GRPCCall{{
			Service:          cfg.Service,
			Method:           cfg.Method,
			CallType:         cfg.CallType,
			RequestMessages:  reqMsgs,
			ResponseMessages: respMsgs,
			ResponseStatus:   cfg.ResponseStatus,
			ResponseMessage:  cfg.ResponseMessage,
			Metadata:         cfg.Metadata,
			Timeout:          cfg.Timeout,
		}}
	}

	// HPACK encoder 跨 call 共享（RFC 7541 §4：dynamic table 跨 stream 持久）。
	enc := newHPACKEncoder(headerTableSize)

	// emit 单事件（direction + 完整帧字节）。
	emit := func(up bool, payload []byte) error {
		return g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: payload})
	}

	// --- HTTP/2 Connection Preface (client → server) ---
	// 24-byte magic + 初始 SETTINGS 帧（Type=0x4, ACK=0）。
	clientSettings := buildSettingsFrame(false, &cfg)
	preface := append([]byte(connPreface), clientSettings...)
	if err := emit(true, preface); err != nil {
		return err
	}

	// --- Server SETTINGS + server ACK of client SETTINGS ---
	serverSettings := buildSettingsFrame(false, &cfg)
	settingsAck := buildSettingsAck()
	serverPayload := append(serverSettings, settingsAck...)
	if err := emit(false, serverPayload); err != nil {
		return err
	}

	// --- Client SETTINGS ACK ---
	if err := emit(true, settingsAck); err != nil {
		return err
	}

	// --- 逐 call 帧（planner.go:548-770 同款）---
	lastStreamID := uint32(0)
	for i, call := range calls {
		// Client-initiated stream IDs 奇、单调增（RFC 7540 §5.1.1）。
		streamID := uint32(2*i + 1)
		lastStreamID = streamID

		// 逐 call request/response 解析（planner.go:568-569 同款：Call 自身
		// 消息；空 → 下方 [][]byte{{}} 零长消息）。
		callReq := call.RequestMessages
		callResp := call.ResponseMessages

		// Client HEADERS（HPACK-encoded request headers，ES=0, EH=1）。
		clientHeaders := buildRequestHeaders(enc, call, requestSpec(req), streamID, &cfg)
		if err := emit(true, clientHeaders); err != nil {
			return err
		}

		// 每 call 类型 request DATA END_STREAM 语义（unary/server-stream:
		// 1 请求, 末 DATA ES=1；client-stream/bidi-stream: N 请求）。
		callType := call.CallType
		if callType == "" {
			callType = "unary"
		}
		reqEndStream := true
		switch callType {
		case "client-stream", "bidi-stream":
			// ES 只落在最后一个请求消息上。
		}
		if len(callReq) == 0 {
			callReq = [][]byte{{}}
		}

		encoding := cfg.Encoding
		if encoding == "" {
			encoding = "identity"
		}

		// bidi-stream: server 必须在其 request 循环前发初始响应 HEADERS
		//（RFC 7540 §8.1）。非 bidi 在 request 循环后发（design §3.1-§3.5）。
		serverHeaders := buildResponseHeaders(enc, streamID)
		bidiInterleaved := callType == "bidi-stream" && cfg.CancelAfter == 0
		if bidiInterleaved {
			if err := emit(false, serverHeaders); err != nil {
				return err
			}
		}

		for j, msg := range callReq {
			isLast := j == len(callReq)-1
			grpcBytes := buildGRPCMessage(msg, encoding)
			dataFrames := buildDataFrameStream(grpcBytes, streamID, isLast && reqEndStream, effectiveMaxFrameSize(&cfg))
			if err := emit(true, dataFrames); err != nil {
				return err
			}

			// bidi-stream: response 逐请求交错（design §3.6）。
			if bidiInterleaved && j < len(callResp) {
				grpcBytes := buildGRPCMessage(callResp[j], encoding)
				dataFrames := buildDataFrameStream(grpcBytes, streamID, false, effectiveMaxFrameSize(&cfg))
				if err := emit(false, dataFrames); err != nil {
					return err
				}
			}
		}

		// 可选 RST_STREAM cancel（CancelAfter > 0）。
		if cfg.CancelAfter > 0 {
			rst := buildRSTStreamFrame(streamID, errCodeCancel)
			if err := emit(true, rst); err != nil {
				return err
			}
		}

		// 可选 PING keepalive（连接级 Stream ID 0）。
		if cfg.Pings != nil {
			count := cfg.Pings.Count
			if count == 0 {
				count = 1
			}
			for k := 0; k < count; k++ {
				pingReq := buildPingFrame(false, cfg.Pings.OpaqueData, uint64(k+1))
				pingAck := buildPingFrame(true, cfg.Pings.OpaqueData, uint64(k+1))
				if err := emit(true, pingReq); err != nil {
					return err
				}
				if err := emit(false, pingAck); err != nil {
					return err
				}
			}
		}

		// Server response: HEADERS (initial :status=200) → DATA → trailers。
		if !bidiInterleaved {
			if err := emit(false, serverHeaders); err != nil {
				return err
			}
		}

		// 剩余 response（bidi 已交错部分跳过）。
		respStart := 0
		if bidiInterleaved {
			if len(callReq) < len(callResp) {
				respStart = len(callReq)
			} else {
				respStart = len(callResp)
			}
		}
		for k := respStart; k < len(callResp); k++ {
			grpcBytes := buildGRPCMessage(callResp[k], encoding)
			dataFrames := buildDataFrameStream(grpcBytes, streamID, false, effectiveMaxFrameSize(&cfg))
			if err := emit(false, dataFrames); err != nil {
				return err
			}
		}

		// 可选 WINDOW_UPDATE flow control（RFC 7540 §6.9）。
		wuIncr := cfg.WindowUpdateIncrement
		if call.WindowUpdateIncrement > 0 {
			wuIncr = call.WindowUpdateIncrement
		}
		if wuIncr > 0 {
			connWU := buildWindowUpdateFrame(0, wuIncr)
			if err := emit(false, connWU); err != nil {
				return err
			}
			streamWU := buildWindowUpdateFrame(streamID, wuIncr)
			if err := emit(false, streamWU); err != nil {
				return err
			}
		}

		// Trailers: HEADERS ES=1, EH=1（grpc-status/grpc-message）。
		trailers := buildTrailers(enc, call, streamID)
		if err := emit(false, trailers); err != nil {
			return err
		}
	}

	// --- 可选 GOAWAY（server → client；默认 true emit，planner.go:768-786 同款）---
	// legacy 恒 emit（"default true" 语义；无法区分显式 false 与零值）。链上
	// 同款：始终发 GOAWAY。
	{
		goAway := buildGoAwayFrame(lastStreamID, errCodeNoError, nil)
		if err := emit(false, goAway); err != nil {
			return err
		}
	}

	return nil
}

// requestSpec constructs a minimal FlowSpec for buildRequestHeaders'
// authorityFor(:authority = DstIP:DstPort)。grpc 终结层不持握手/seq，只需
// DstIP/DstPort 解析 authority（legacy authorityFor 读 spec.DstIP/DstPort）。
func requestSpec(req *layers.GenRequest) core.FlowSpec {
	return core.FlowSpec{
		DstIP:   req.Meta.DstIP,
		DstPort: req.Meta.DstPort,
	}
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks)。
func (g *GRPCGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *GRPCGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *GRPCGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("grpc generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("grpc", func() (layers.LayerGenerator, error) {
		return &GRPCGenerator{}, nil
	})
	layers.RegisterLayerValidator("grpc", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 握手/挥手校准进 spec.TCP（mqtt/redis/modbus layer_gen.go 同款陷阱）：
		// legacy grpc planner.go 恒产 TCP 握手/挥手（460-467/776-786 无开关，
		// 从不读 spec.TCP.Handshake/Termination）——spec.TCP 零值 false 必须写
		// 默认 true，否则 tcp 层生成器跳过握手/挥手（链测试 spec.TCP 只设
		// InitialSeq 即复现）。与 legacy 语义一致：grpc 链上的握手/挥手不可关。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
