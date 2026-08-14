package nfs

// NFSGenerator is the nfs terminal-layer generator (nfs 终结层层生成器, P4a)。
// NFSv3/v4 RPC——一次 flow = 一个 4-tuple 上的 op 序列：每 op 一个调用/回复
// 对（call up + reply down，同一 XID）。每条消息一个"报文事件"（方向 + 完整
// wire 字节），构建字节由 buildCall / buildReply 纯函数产出（复用，不重写）。
// 事件模式（http 波 2 方案 A 同款）：TCP 语义（握手/seq-ack/挥手/MSS 分段）
// 交给 tcp 层生成器，UDP 语义（每事件一数据报、方向端口交换）交给 udp 层
// 生成器（UDPGenerator 事件模式自动交换 up/down 端口——NFS 事件不设
// L4PortOverride，tftp 的覆盖需求 NFS 无）。
//
// 与 legacy Plan（nfs.go:371-429 / planSession 432-507）的差异（文档化
// divergence）：
//   - legacy 自产 TCP 握手（3 包）与挥手（3 包，planSession 461-466/500-505）
//     ——事件模式不产：tcp 层生成器负责（防双握手）。握手/挥手开关由 tcp 层
//     schema 默认 true 执行，validator 强制校准 true（legacy nfs.go 恒产
//     握手/挥手，从不读 spec.TCP.Handshake/Termination，语义一致）。
//   - 多流展开（Sessions>1 每会话独立 srcPort，planSession 420-423）不支持：
//     链一次一个 flow（一个 4-tuple），Sessions>1 显式拒绝（enip
//     session_count/flow_count、modbus master_count/flow_count 同款先例）。
//   - 逐包 Timestamp：legacy 恒 now（planSession 437）；链上由 ChainPlanner
//     统一回填（chain_planner.go:400），事件流不产。
//   - 握手 seq：legacy 在 spec.TCP.InitialSeq 为零时随机 ISN（emitHandshake
//     1560-1564）；链上由 tcp 层生成器持有，事件流不产。
//   - srcPort：legacy 多流派生（planSession 420-423）不适用（链拒绝多流）；
//     单流时 legacy 用 spec.SrcPort 原值（0 也上包）——validateSpecBase 对
//     nfs 分支不默认化 srcPort，与 legacy 一致（modbus/gbt32960 同款）。
//   - dstPort 默认化：legacy Plan 内默认（nfs.go:377-379，2049）；链上由
//     validateSpecBase 默认化（chain_planner.go dst 端口 nfs 分支），生成器
//     不再默认。
//   - transport 权威在 cfg（NFSConfig.Transport）：决定 RM 记录标记前缀
//     （buildCall/buildReply 的 wrapRM，"tcp" 才有 4 字节 RM）。链载体与
//     transport 的一致性由 ChainPlanner ValidateSpec 结构性校验（udp 载体 +
//     空 transport 拒绝——空串按 legacy 默认 "tcp" 会把 RM 字节写进 UDP
//     数据报）。生成器不自行判 carrier。
//   - XID 状态：xid 从 xidBase（默认 1）起，每 op 推进 xidIncr。
//     XIDIncr=0 显式支持（T-015 reply-echo：所有调用共享同一 XID），从不
//     强制到 1。
//   - 生成器在首个事件前同步检查多流（Sessions>1 → 显式 error）；链上
//     "驱动失败 → 空流"契约会把生成器错误吞成 completed+0 包
//     （chain_planner.go:382-386），validator 同款拒绝为双保险（enip 同款
//     纪律）。
//
// 生成器内部顺序与 legacy planSession（432-507）逐 op 一致；事件方向/字节与
// legacy 数据帧（TCP: flags=0x18 PSH-ACK payload / UDP: 数据报 payload）
// 一一对应（含自动插入的 MOUNT/UMOUNT 与 v4 SETCLIENTID/SETCLIENTID_CONFIRM
// 对——buildOpSequence 复用）。

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// NFSGenerator is the nfs terminal-layer generator.
type NFSGenerator struct{}

// Name returns "nfs".
func (g *NFSGenerator) Name() string { return "nfs" }

// Generate produces one message event per NFS RPC wire message in legacy
// planSession order（每 op：call up + reply down，同一 XID）。TCP 层生成器
// 负责握手/seq-ack/挥手/MSS 分段，UDP 层生成器负责方向端口交换。
func (g *NFSGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("nfs generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg, err := configFromMeta(req.Meta.NFS)
	if err != nil {
		return err
	}

	// --- 默认化（legacy Plan nfs.go:381-403 逐行同款）---
	// 默认化前先做多流检查：Sessions>1 时 legacy 的 SessionsSrcPortBase
	// 默认 49152/step 默认 1 是多流派生的一部分（链无等价物）。
	sessions := cfg.Sessions
	if sessions == 0 {
		sessions = 1
	}
	// --- 多流展开拒绝（enip session_count/flow_count、dnp3 multi_outstation、
	// modbus master_count/flow_count 同款先例）：legacy 每会话独立 4-tuple +
	// 自动递增 srcPort（planSession 420-423），链一次一个 flow 无等价物——
	// 显式拒绝，不能静默只产 1 流（包数缩水）。与 validator 的双保险检查
	// （Generate 级在事件产出前同步报错）。
	if sessions > 1 {
		return fmt.Errorf("nfs generator: sessions (%d) multi-stream expansion is not supported on a layer chain (one flow per chain)", sessions)
	}
	xidBase := cfg.XIDBase
	if xidBase == 0 {
		xidBase = 1
	}
	// XIDIncr=0 is explicitly supported: all calls share the same XID
	// (used for reply-echo behavior tests; T-015). Do NOT coerce to 1.
	xidIncr := cfg.XIDIncr
	transport := cfg.Transport
	if transport == "" {
		transport = "tcp"
	}

	// Mount filehandle default（planSession 446-452 同款）。
	mountFH := cfg.MountFilehandle
	if mountFH == nil {
		mountFH = make([]byte, 16)
		for i := range mountFH {
			mountFH[i] = 0x01
		}
	}

	// Set up clientid allocation for NFSv4 multi-session（planSession 443
	// 同款；链拒绝多流后 sess=0 恒成立）。
	clientid := uint64(0x10000)*(uint64(0)+1) + 1

	// 逐 op 构建 + 发射（planSession 472-498 同款：buildOpSequence 自动
	// 插入 MOUNT/UMOUNT（v3）或 SETCLIENTID/SETCLIENTID_CONFIRM +
	// PUTROOTFH/OPEN_CONFIRM（v4））。
	p := &Planner{}
	ops := p.buildOpSequence(cfg, mountFH, 0)
	xid := xidBase
	for i := range ops {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		callMsg := p.buildCall(&ops[i], cfg, xid, transport, clientid, 0, core.FlowSpec{}, mountFH)
		replyMsg := p.buildReply(&ops[i], cfg, xid, transport, clientid, 0, core.FlowSpec{}, mountFH, callMsg)
		if err := g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: true, Bytes: callMsg}); err != nil {
			return err
		}
		if err := g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: false, Bytes: replyMsg}); err != nil {
			return err
		}
		xid = uint32(int(xid) + xidIncr)
	}
	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks)。
func (g *NFSGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *NFSGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *NFSGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("nfs generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

// configFromMeta resolves the *NFSConfig from the flow metadata (GetConfig
// 同款三形态：*NFSConfig / map[string]interface{} / json.RawMessage；core 无法
// import 本包，经 spec.Metadata["nfs"] 原样传递)。nil 时返回显式错误（NFS
// 链必须有 nfs 配置，不产任何事件）。
func configFromMeta(v interface{}) (*NFSConfig, error) {
	switch c := v.(type) {
	case nil:
		return nil, fmt.Errorf("nfs generator: no config (spec.nfs required)")
	case *NFSConfig:
		return c, nil
	case map[string]interface{}:
		cfg, err := nfsConfigFromJSONMap(c)
		if err != nil {
			return nil, fmt.Errorf("nfs generator: invalid nfs config: %w", err)
		}
		return cfg, nil
	case json.RawMessage:
		var cfg NFSConfig
		if err := json.Unmarshal(c, &cfg); err != nil {
			return nil, fmt.Errorf("nfs generator: invalid nfs config: %w", err)
		}
		return &cfg, nil
	default:
		return nil, fmt.Errorf("nfs generator: unsupported nfs config type %T", v)
	}
}

func init() {
	layers.RegisterLayerGenerator("nfs", func() (layers.LayerGenerator, error) {
		return &NFSGenerator{}, nil
	})
	layers.RegisterLayerValidator("nfs", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 多流展开拒绝（enip/modbus 同款纪律）：legacy 每会话独立 4-tuple +
		// 自动递增 srcPort（planSession 420-423），链一次一个 flow 无等价
		// 物——Plan 期同步拒绝（生成器级检查为双保险，驱动错误会被吞成空流）。
		if cfg := GetConfig(*spec); cfg != nil && cfg.Sessions > 1 {
			return fmt.Errorf("nfs: sessions (%d) multi-stream expansion is not supported on the layer chain (one flow per chain)", cfg.Sessions)
		}
		// 握手/挥手校准进 spec.TCP（modbus layer_gen.go:171-184 同款陷阱）：
		// legacy nfs.go 恒产 TCP 握手/挥手（planSession 461-466/500-505 无
		// 开关，从不读 spec.TCP.Handshake/Termination）——spec.TCP 零值 false
		// 必须写默认 true，否则 tcp 层生成器跳过握手/挥手（链测试 spec.TCP
		// 只设 InitialSeq 即复现：applySpecToChain 把零值 false 直落层 config）。
		// 与 legacy 语义一致：nfs 链上的握手/挥手不可关（legacy 亦无此表达）。
		// UDP 载体链无 tcp 层生成器（不实例化），此校准无害。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
