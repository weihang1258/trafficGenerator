package modbus

// MODBUSGenerator is the modbus terminal-layer generator (modbus 终结层层
// 生成器, P4a)。Modbus TCP——一次 flow = 一个 4-tuple 上的事务序列：
// 每事务一条 request 帧（MBAP 头 + 请求 PDU）→ 可选 response 帧（MBAP 头 +
// 响应/异常 PDU，共享同一 TID）。每条消息一个"报文事件"（方向 + 完整 wire
// 字节），构建字节由 buildRequestPDU / buildResponsePDU / BuildMBAPFrame 纯
// 函数产出（复用，不重写）。事件模式（http 波 2 方案 A 同款）：TCP 语义
// （握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器。
//
// 与 legacy Plan（modbus.go:95-161 / planFlow 414-597）的差异（文档化
// divergence）：
//   - legacy 自产 TCP 握手（3 包）与挥手（4 包，planFlow 525-542/575-596）
//     ——事件模式不产：tcp 层生成器负责（防双握手）。握手/挥手开关由 tcp
//     层 schema 默认 true 执行，validator 强制校准 true（legacy modbus.go
//     恒产握手/挥手，从不读 spec.TCP.Handshake/Termination），语义一致。
//   - 多流展开（MasterCount×FlowCount 每组合独立 srcPort，planFlow 414-436）
//     不支持：链一次一个 flow（一个 4-tuple），MasterCount>1 或 FlowCount>1
//     显式拒绝（enip session_count/flow_count、dnp3 multi_outstation 同款
//     先例）。默认化仍然保留（0 → 1），语义等价单流 legacy（unit 0/flow 0）。
//   - SharedTIDSpace=true 的全局 TID（nextGlobalTID，跨流共享）在链上退化为
//     全局单流仍 +1（包级原子计数器，与 legacy 同函数同语义）。
//   - 逐包 Timestamp：legacy 恒 now（planFlow 468）；链上由 ChainPlanner
//     统一回填（chain_planner.go:400），事件流不产。
//   - srcPort：legacy 多流派生（20000+idx）不适用（链拒绝多流）；单流时
//     legacy 用 spec.SrcPort 原值（planFlow 418-436，u=0 时 baseSrcPort 直
//     用）——validateSpecBase 对 modbus 分支不默认化 srcPort，与 legacy
//     一致（gbt32960/mcp 同款）。
//   - dstPort 默认化：legacy Plan 内默认（planFlow 422-424，502）；链上由
//     validateSpecBase 默认化（chain_planner.go dst 端口 modbus 分支），
//     生成器不再默认。
//   - 生成器在首个事件前同步检查多流（MasterCount>1||FlowCount>1 → 显式
//     error）；链上"驱动失败 → 空流"契约会把生成器错误吞成 completed+0 包
//     （chain_planner.go:382-386），validator 同款拒绝为双保险（enip 同款
//     纪律）。
//
// 生成器内部顺序与 legacy 事务循环（planFlow 544-573）逐事务一致；事件
// 方向/字节与 legacy 数据帧（flags=0x18 PSH-ACK payload）一一对应。

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// MODBUSGenerator is the modbus terminal-layer generator.
type MODBUSGenerator struct{}

// Name returns "modbus".
func (g *MODBUSGenerator) Name() string { return "modbus" }

// Generate produces one message event per Modbus wire frame in legacy
// transaction order（每事务：request up + 可选 response down）。TCP 层生成器
// 负责握手/seq-ack/挥手/MSS 分段。
func (g *MODBUSGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("modbus generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	c := req.Meta.MODBUS
	if c == nil {
		return fmt.Errorf("modbus generator: no config (spec.modbus required)")
	}

	// --- 默认化（legacy Plan modbus.go:107-121 逐行同款）---
	cfg := *c
	masterCount := cfg.MasterCount
	if masterCount <= 0 {
		masterCount = 1
	}
	flowCount := cfg.FlowCount
	if flowCount <= 0 {
		flowCount = 1
	}
	transactions := cfg.Transactions
	if transactions == nil {
		transactions = []core.MODBUSOperation{{FunctionCode: 0x03, Quantity: 1}}
	}

	// --- 多流展开拒绝（enip session_count/flow_count、dnp3 multi_outstation
	// 同款先例）：legacy 每 master×flow 组合独立 srcPort（planFlow 426-436），
	// 链一次一个 flow 无等价物——显式拒绝，不能静默单遍产 1 流（包数缩水）。
	// 与 validator 的双保险检查（Generate 级在事件产出前同步报错）。
	if masterCount > 1 || flowCount > 1 {
		return fmt.Errorf("modbus generator: master_count=%d/flow_count=%d (multi-stream expansion) is not supported on a tcp-layer chain (one flow per chain)",
			masterCount, flowCount)
	}

	unitID := getUnitID(&cfg)

	// --- TID 策略（planFlow 471-482 同款）---
	// SharedTIDSpace=true → 全局原子计数器（nextGlobalTID，legacy 跨流共享；
	// 链拒绝多流后为全局单流仍 +1）。false（默认）→ 流内独立 localTID
	// 从 0 递增。每事务只取一次，req/resp 共享（§2.3 事务匹配语义）。
	var localTID uint16
	getTID := func() uint16 {
		if cfg.SharedTIDSpace {
			return nextGlobalTID()
		}
		t := localTID
		localTID++
		return t
	}

	// --- 事务循环（planFlow 544-573 同款）---
	for _, tx := range transactions {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		reqPDU := buildRequestPDU(&tx)
		txTID := getTID()
		reqFrame := BuildMBAPFrame(txTID, unitID, reqPDU)
		if err := g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: reqFrame}); err != nil {
			return err
		}
		if shouldGenerateResponse(&tx, &cfg) {
			respPDU := buildResponsePDU(&tx)
			respFrame := BuildMBAPFrame(txTID, unitID, respPDU)
			if err := g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: respFrame}); err != nil {
				return err
			}
		}
	}
	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks)。
func (g *MODBUSGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *MODBUSGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *MODBUSGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("modbus generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("modbus", func() (layers.LayerGenerator, error) {
		return &MODBUSGenerator{}, nil
	})
	layers.RegisterLayerValidator("modbus", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 多流展开拒绝（enip 同款纪律）：legacy 每 master×flow 组合独立
		// srcPort（planFlow 426-436），链一次一个 flow 无等价物——Plan 期
		// 同步拒绝（生成器级检查为双保险，驱动错误会被吞成空流）。
		if spec.MODBUS != nil {
			if mc := spec.MODBUS.MasterCount; mc > 1 {
				return fmt.Errorf("modbus: master_count %d is not supported on the layer chain (one flow per chain)", mc)
			}
			if fc := spec.MODBUS.FlowCount; fc > 1 {
				return fmt.Errorf("modbus: flow_count %d is not supported on the layer chain (one flow per chain)", fc)
			}
		}
		// 握手/挥手校准进 spec.TCP（gbt32960 layer_gen.go:192-197 同款陷阱）：
		// legacy modbus.go 恒产 TCP 握手/挥手（planFlow 525-542/575-596 无开关，
		// 从不读 spec.TCP.Handshake/Termination）——spec.TCP 零值 false 必须
		// 写默认 true，否则 tcp 层生成器跳过握手/挥手（链测试 spec.TCP 只设
		// InitialSeq 即复现：applySpecToChain 把零值 false 直落层 config）。
		// 与 legacy 语义一致：modbus 链上的握手/挥手不可关（legacy 亦无此
		// 表达——flat 的 tcp:{handshake:false} 在 legacy 被忽略，链上同样
		// 强制 true）。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
