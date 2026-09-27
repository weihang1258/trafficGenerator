package enip

// ENIPGenerator is the enip terminal-layer generator (enip 终结层层生成器,
// P4a)。ENIP 命令即 TCP 数据段（无显式三次握手/终止——enip.go:654 注释），
// TCP 语义（握手/seq-ack 推进/挥手）全部交给 tcp 层生成器（http 波 2 方案 A
// 同款事件模式：终结层只产"报文事件"= 方向 + 完整字节）。
//
// 生成器逐命令复用 legacy buildENIPPacket（纯函数，无副作用，字节级一致），
// 零序列逻辑复制。会话状态机（SessionHandle 回写、from_response 提取、
// SenderContext 计数）从 planUnit 提取为生成器内等价逻辑——构建字节不变，
// 仅状态演进方式与 legacy 并行 goroutine 的 planUnit 略有差异（见下）。
//
// 不支持 UDP I/O 帧（IOData）：chain 是单一 tcp 承载流，无 UDP 混合流——
// legacy planUnit 的 I/O 帧走独立 UDP 数据报（enip.go:824-853），事件模式
// 无法表达，配置了 IOData 时显式报错（不能静默丢帧）。

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// ENIPGenerator is the enip terminal-layer generator.
type ENIPGenerator struct{}

// Name returns "enip".
func (g *ENIPGenerator) Name() string { return "enip" }

// Generate produces one message event per ENIP command (方向 + 完整报文
// 字节)，字节级复刻 legacy planUnit 的命令构建（enip.go:672-806）。TCP 层
// 生成器负责握手/seq-ack/挥手。
//
// 与 legacy planUnit 的差异（文档化 divergence）：
//   - UDP I/O 帧（IOData）不支持，显式报错。
//   - transport="udp"（legacy enip.go:626-631 命令发为 UDP 数据报）不支持，
//     显式报错（链上无 UDP 混合流）。
//   - session_count/flow_count > 1 的多单元展开（legacy enip.go:588-590，
//     +u 派生 T-162/169/177）不支持，显式报错（链一次一个 flow，无单元
//     展开；单元 0 与单单元场景字节级一致）。
//
// 其余状态机逻辑（RegisterSession 回写、from_response 全字段提取、
// SenderContext 优先级）与 legacy 逐字对齐。
//
// SenderContext 计数与 legacy 一致（R43 默认全局递增：NOP 恒 0，其余从 1
// 起逐命令 +1，enip.go:1082-1097）。
func (g *ENIPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("enip generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	cfg := req.Meta.ENIP
	if cfg == nil {
		return fmt.Errorf("enip generator: ENIP config is nil (layer not wired to a flow spec)")
	}
	if cfg.IOData != nil {
		return fmt.Errorf("enip generator: io_data (UDP I/O frames) is not supported on a tcp-layer chain")
	}
	// 传输=udp 是 legacy 合法配置（enip.go:626-631：命令发为 UDP 数据报，
	// T-170）——链上无 UDP 混合流表达载体，显式拒绝（同 IOData 先例，
	// 不能静默改发 TCP 段）。
	if cfg.Transport == "udp" {
		return fmt.Errorf("enip generator: transport \"udp\" is not supported on a tcp-layer chain (commands would silently become TCP segments)")
	}
	// 多单元展开（legacy enip.go:588-590：session×flow 逐单元命令序列 +
	// +u 派生，T-162/169/177）在链上无等价物——显式拒绝，不能静默单遍
	// 产 1 单元（包数缩水）。
	if cfg.SessionCount > 1 || cfg.FlowCount > 1 {
		return fmt.Errorf("enip generator: session_count=%d/flow_count=%d (multi-unit expansion) is not supported on a tcp-layer chain (single flow per chain)",
			cfg.SessionCount, cfg.FlowCount)
	}
	if len(cfg.Commands) == 0 {
		return fmt.Errorf("enip generator: no commands configured")
	}

	// from_response 配置合法性校验（H-2，与 legacy Plan 前置一致）：
	// 引用目标必须在响应表（本生成器保留 down 命令的响应，同 planUnit）。
	// 注：Plan 同步面（ValidateSpec→protocolValidator→Planner.Validate）
	// 不覆盖此检查——Generate 跑在 drive goroutine 内，错误被吞成空流
	// （T-117/T-118 实证 "planner produced 0 packet configs"）。
	// TODO(G-ENIP-8)：把 validateFromResponseConfig 并入 Planner.Validate，
	// 让 T-117/T-118 在同步面以原锚词拒绝；届时本检查保留为防御性复核。
	// 当前链级负例锚词按同步面实际错误钉（"planner produced 0 packet"）。
	if err := validateFromResponseConfig(cfg); err != nil {
		return err
	}

	// responseTable 是 (source_command_index → 响应报文含 24B ENIP 头) 索引
	// （H-2，设计 §5.6.1）：down/response 命令的构建结果存入，供后续命令
	// from_response 提取（同 planUnit，enip.go:662-667）。
	responseTable := make(map[int][]byte)
	// sessionHandle 是最近 RegisterSession 响应的 SessionHandle（后续命令
	// 默认会话句柄，enip.go:730-736 同款回写）。
	var sessionHandle uint32
	// senderCtxCounter 是 flow 内 SenderContext 递增计数器（R43，enip.go:583）。
	var senderCtxCounter uint64

	// direction 默认 "up"（client→server），down/response 显式下方向
	// （enip.go:752-755）。
	for i, cmd := range cfg.Commands {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// from_response 注入（H-2）：legacy 的 cmdCopy 派生（ConnSerial/O2T/T2O
		// +u 单元偏移）是 multi-session/multi-flow 展开专用——层链一次一个 flow，
		// 无单元展开，偏移恒 0（cmdCopy 派生在 u=0 时是恒等，enip.go:683-689）。
		// 保留 from_response 字段提取（o2t/t2o/conn_serial/session_handle），
		// 跨命令注入（session_handle 与 legacy enip.go:715-717 同款：提取值
		// 进 cmdCopy.SessionHandle，buildENIPPacket 的显式值优先采用）。
		cmdCopy := cmd
		if cmd.FromResponseField != "" && cmd.SourceCommandIndex >= 0 &&
			cmd.SourceCommandIndex < len(cfg.Commands) {
			if resp := responseTable[cmd.SourceCommandIndex]; len(resp) > 0 {
				if val, ok := extractFromResponse(resp, cmd.FromResponseField); ok {
					switch cmd.FromResponseField {
					case "session_handle":
						cmdCopy.SessionHandle = val
					case "o2t_connection_id":
						cmdCopy.O2TConnID = val
					case "t2o_connection_id":
						cmdCopy.T2OConnID = val
					case "connection_serial_number":
						cmdCopy.ConnSerialNum = uint16(val)
					}
				}
			}
		}

		// RegisterSession 响应回写（enip.go:730-736 逐字对齐）：会话句柄全局
		// 为 0 时，RegisterSession 命令（请求带显式句柄或响应携带句柄）的
		// SessionHandle 成为后续命令默认。条件用 sessionHandle == 0（非
		// Direction != "up"）——legacy 对 up 方向 RegisterSession 的显式
		// 句柄同样回写（review HIGH-2 对齐）。
		if cmdCopy.Command == CmdRegisterSession && sessionHandle == 0 {
			if cmdCopy.SessionHandle != 0 {
				sessionHandle = cmdCopy.SessionHandle
			}
		}

		// 构建 ENIP 报文（纯函数，字节级一致）。SenderContext 计数推进在
		// buildENIPPacket 之后（legacy planUnit 逐命令 +1，enip.go:805）。
		msg := buildENIPPacket(&cmdCopy, sessionHandle, cfg, senderCtxCounter)

		// 记录响应数据（H-2）：down/response 命令存入响应表（含 24B 头）。
		if cmdCopy.Direction == "down" || cmdCopy.Direction == "response" {
			responseTable[i] = msg
		}

		direction := "up"
		if cmdCopy.Direction == "down" || cmdCopy.Direction == "response" {
			direction = "down"
		}

		ev := layers.MessageEvent{
			Up:    direction == "up",
			Bytes: msg,
			// 事件不带端口：tcp 层生成器用 chain 端口（up→src/dst，
			// down→dst/src 交换，generator.go:802-810）。legacy 的 down
			// 端口交换（enip.go:757-760）是 planUnit 内封装的等价物。
			SrcPort: 0,
			DstPort: 0,
		}
		if err := g.emitMsg(ctx, req.EmitMsg, ev); err != nil {
			return err
		}
		senderCtxCounter++
	}
	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks).
func (g *ENIPGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *ENIPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *ENIPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("enip generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("enip", func() (layers.LayerGenerator, error) {
		return &ENIPGenerator{}, nil
	})
	layers.RegisterLayerValidator("enip", func(spec *core.FlowSpec) error {
		return (&Planner{}).Validate(*spec)
	})
}
