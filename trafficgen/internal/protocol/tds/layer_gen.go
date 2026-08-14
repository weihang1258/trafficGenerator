package tds

// TDSGenerator is the tds terminal-layer generator (tds 终结层层生成器, P4a)。
// TDS (MS-TDS)——一次 flow = 一个 TCP 连接上的 TDS 会话生命周期：
// PRELOGIN(up) → PRELOGIN response(down) → Login7(up) → Login response(down)
// → sessions（每 session 每 request：SQL Batch / RPC / TransMgr / Attention，
// up 请求 + down 响应）→ TCP 挥手。每条 TDS 报文一个"报文事件"（方向 + 完整
// 字节），构建字节复用 legacy 纯函数（buildPreLoginPacket/buildPreLoginResponse/
// buildLogin7Packet/buildLoginResponse/buildSQLBatchRequest/buildSQLBatchResponse/
// buildRPCRequest/buildRPCResponse/buildTransMgrRequest/buildTransMgrResponse/
// BuildAttention/buildAttentionResponse——全部无副作用，零序列逻辑复制）。
// 事件模式（http 波 2 方案 A 同款）：TCP 语义（握手/seq-ack/挥手/MSS 分段）
// 交给 tcp 层生成器。
//
// TDS 配置经 spec.Payload（TDSConfig JSON）携带（strategy_convert.go:948-955
// tds case 同款——flat 键 tds 的 JSON 解码子 map 重新序列化进 Payload），
// 生成器从 req.Meta.Payload 解析（core 不引入 TDS 类型，链上零配置负载）。
// Payload 空 → 默认配置；非空 → JSON unmarshal + presence-checked 默认
// （configFromSpec 的完整语义：显式空字符串保留，如 T-026 password:"" →
// cchPassword=0）。
//
// 与 legacy Plan（tds.go:353-546）的差异（文档化 divergence）：
//   - legacy 自产 TCP 握手（3 包，tds.go:464-469）与挥手（2 包 FIN-ACK up /
//     FIN-ACK down，tds.go:539-542）——事件模式不产：tcp 层生成器负责（防
//     双握手）。握手/挥手开关由 tcp 层 schema 默认 true 执行，validator 强制
//     校准 true（legacy tds.go 恒产握手/挥手，从不读 spec.TCP.Handshake /
//     Termination，语义一致）。链上挥手是 TCPGenerator 标准 4 包（FIN|ACK
//     up → ACK down → FIN|ACK down → ACK up），与 legacy 2 包挥手为层模型
//     意图的文档化分歧（mqtt/modbus/dnp3/doip 链测试同款断言形状）。
//   - 逐包 Timestamp：legacy 恒 now（tds.go:376）；链上由 ChainPlanner 统一
//     回填（chain_planner.go:505），事件流不产。
//   - 握手 seq：legacy 在 spec.TCP.InitialSeq 为零时自 0 起（tds.go:389-392）
//     ；链上由 tcp 层生成器持有（随机或显式 InitialSeq），事件流不产。
//   - srcPort：legacy Plan 用 spec.SrcPort 原值（0 也上包，tds.go:449）——
//     validateSpecBase 对 tds 分支不默认化 srcPort，与 legacy 一致。
//   - dstPort 默认化：legacy Plan 内默认（tds.go:357-359，1433）；链上由
//     validateSpecBase 默认化（chain_planner.go dst 端口 tds 分支），生成器
//     不再默认。
//   - 应用层分片保留：legacy downMsg 用 BuildTableResponsePackets 按
//     cfg.PacketSize 分片（T-148，tds.go:458-462）——TDS 报文级分片，不是
//     TCP 分段，生成器逐事件原样保留（每片一个 down 事件）。
//
// 生成器内部顺序与 legacy Plan（353-546）逐报文一致；事件方向/字节与
// legacy 数据帧（flags=0x18 PSH-ACK payload）一一对应（含 MARS 的
// spid=0x0042 与动态 OutstandingRequestCount=len(Sessions)、Login.Error !=
// nil 时跳过全部会话直接 teardown）。

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// TDSGenerator is the tds terminal-layer generator.
type TDSGenerator struct{}

// Name returns "tds".
func (g *TDSGenerator) Name() string { return "tds" }

// Generate produces one message event per TDS wire packet in legacy Plan
// order（PRELOGIN → PRELOGIN response → Login7 → Login response → sessions →
// Attention，Login.Error 门控跳过会话）。TCP 层生成器负责握手/seq-ack/挥手/
// MSS 分段。
func (g *TDSGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("tds generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	// 配置解析（configFromSpec 同款语义：Payload 空 → 默认配置 + presence-
	// checked 默认——显式空字符串保留）。configFromSpec 是同一个函数，直接
	// 复用——core.FlowSpec 与链上 FlowMeta.Payload 承载同一个 spec.Payload。
	cfg, err := configFromSpec(core.FlowSpec{Payload: req.Meta.Payload})
	if err != nil {
		return err
	}

	// MARS: spid 共享 0x0042（S12），legacy tds.go:385-388 同款。
	spid := uint16(0)
	if cfg.MarsEnabled {
		spid = 0x0042
	}
	// MARS: OutstandingRequestCount 是动态值 = 该连接上活动请求数
	// （spec §4.4）；trafficgen 的 MARS 模型所有 session 并发活动，每条请求
	// 的 outstanding = len(cfg.Sessions)（tds.go:499-504 同款修复语义）。
	// 非 MARS (AutoCommit) 严格按 spec §2.5/§3.2.4 固定为 1。
	computeOutstanding := func() uint32 {
		if cfg.MarsEnabled {
			return uint32(len(cfg.Sessions))
		}
		return 1
	}

	// 逐报文 emit（每事件方向 + 完整 TDS 报文字节；MSS 分段是 tcp 层的事，
	// 生成器不预分段）。
	emit := func(up bool, payload []byte) error {
		return g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: payload})
	}

	// --- PRELOGIN (S1) ---
	if err := emit(true, buildPreLoginPacket(cfg, packetIDFor(1))); err != nil {
		return err
	}
	if err := emit(false, buildPreLoginResponse(cfg)); err != nil {
		return err
	}

	// --- Login7 (S2) ---
	if err := emit(true, buildLogin7Packet(cfg)); err != nil {
		return err
	}
	// Login response 经 downMsg 按 PacketSize 分片（T-148；应用层分片，与
	// legacy downMsg 同款——TCP 分段是 tcp 层的事）。
	loginResp := buildLoginResponse(cfg)
	for _, pkt := range BuildTableResponsePackets(loginResp, int(cfg.PacketSize)) {
		if err := emit(false, pkt); err != nil {
			return err
		}
	}

	if cfg.Login != nil && cfg.Login.Error != nil {
		// T-147: 登录失败 — ERROR + DONE(DONE_ERROR) 后连接关闭，跳过全部
		// 会话直接进入 teardown（tds.go:482-484 同款门控）。
		return nil
	}

	// --- Sessions ---
	for _, sess := range cfg.Sessions {
		txnDesc := sess.TransactionID
		sessOutstanding := computeOutstanding()
		for ri, reqSpec := range sess.Requests {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			switch reqSpec.Type {
			case RequestSQLBatch:
				payload, err := buildSQLBatchRequest(cfg, reqSpec.Sql, txnDesc, sessOutstanding, spid)
				if err != nil {
					continue
				}
				if err := emit(true, payload); err != nil {
					return err
				}
				for _, pkt := range BuildTableResponsePackets(buildSQLBatchResponse(cfg, &reqSpec, ri), int(cfg.PacketSize)) {
					if err := emit(false, pkt); err != nil {
						return err
					}
				}
			case RequestRPC:
				payload, err := buildRPCRequest(cfg, reqSpec.Rpc, txnDesc, sessOutstanding, spid)
				if err != nil {
					continue
				}
				if err := emit(true, payload); err != nil {
					return err
				}
				for _, pkt := range BuildTableResponsePackets(buildRPCResponse(cfg, &reqSpec, ri), int(cfg.PacketSize)) {
					if err := emit(false, pkt); err != nil {
						return err
					}
				}
			case RequestTransMgr:
				payload, err := buildTransMgrRequest(cfg, reqSpec.TransMgr, txnDesc, sessOutstanding, spid)
				if err != nil {
					continue
				}
				if err := emit(true, payload); err != nil {
					return err
				}
				for _, pkt := range BuildTableResponsePackets(buildTransMgrResponse(cfg, reqSpec.TransMgr), int(cfg.PacketSize)) {
					if err := emit(false, pkt); err != nil {
						return err
					}
				}
			case RequestAttention:
				if err := emit(true, BuildAttention(spid, packetIDFor(1))); err != nil {
					return err
				}
				for _, pkt := range BuildTableResponsePackets(buildAttentionResponse(), int(cfg.PacketSize)) {
					if err := emit(false, pkt); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks)。
func (g *TDSGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *TDSGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *TDSGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("tds generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("tds", func() (layers.LayerGenerator, error) {
		return &TDSGenerator{}, nil
	})
	layers.RegisterLayerValidator("tds", func(spec *core.FlowSpec) error {
		// 复用 legacy Validate（IP 解析 + configFromSpec + ValidateConfig 的
		// 全部 V-TDS-xxx 规则）。链上 spec.Payload 即 TDSConfig JSON（flat 键
		// tds 与 layers 数组零负载两种路径都经 Payload 携带）。
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 握手/挥手校准进 spec.TCP（modbus layer_gen.go:171-184 同款陷阱）：
		// legacy tds.go 恒产 TCP 握手/挥手（tds.go:464-469/539-542 无开关，
		// 从不读 spec.TCP.Handshake/Termination）——spec.TCP 零值 false 必须
		// 写默认 true，否则 tcp 层生成器跳过握手/挥手（链测试 spec.TCP 只设
		// InitialSeq 即复现：applySpecToChain 把零值 false 直落层 config）。
		// 与 legacy 语义一致：tds 链上的握手/挥手不可关（legacy 亦无此表达
		// ——flat 的 tcp:{handshake:false} 在 legacy 被忽略，链上同样强制
		// true）。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
