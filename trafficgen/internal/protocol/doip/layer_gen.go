package doip

// DoIPGenerator is the doip terminal-layer generator (doip 终结层层生成器,
// P4a)。DoIP over TCP——routing activation / diagnostic messages / alive
// check / generic nack 各阶段逐报文产出"报文事件"（方向 + DoIP 头 + payload，
// build* 纯函数复用），TCP 语义（握手/seq-ack/挥手/MSS 分段）交给 tcp 层
// 生成器。事件模式（http 波 2 方案 A 同款）。
//
// 与 legacy Plan（doip.go:271-795）的差异（文档化 divergence）：
//   - legacy 自产 TCP 握手（3 包）与挥手（4 包，doip.go:587-596/781-790）
//     ——事件模式不产：tcp 层生成器负责（防双握手）。validator 校准
//     Activation 存在性进 spec.TCP：Activation==nil 时 legacy 无 TCP 阶段
//     （doip.go:777 挥手条件恒假），校准 Handshake/Termination=false；
//     Activation!=nil 时默认 true（用户显式 false 尊重，tcp 层执行）。
//   - UDP 阶段（Discovery/EntityStatus/PowerMode，doip.go:454-574）不支持：
//     链上无 UDP 混合流，生成器显式拒绝（enip IOData 同款先例）。
//   - 激活失败路径（ResponseCode 0x00-0x07，或 0x11 无确认——doip.go:
//     636-645 产 FIN+ACK 后提前终止）不支持：TCP 挥手由 tcp 层接管，生成
//     器显式拒绝（RFC 13400 §9.2 语义由 tcp 层 termination 表达）。
//   - 0x36 TransferData 协议级分段（doip.go:677-701：>MSS-40 的 user data
//     按 MSS-40-2 块 + BlockSeq 递增分包）由生成器复刻——MSS 从
//     req.Meta.TCP 解析（spec.TCP.MSS>0 用之，0 回退 DefaultMSS）。
//   - 握手/挥手 gating（文档化 divergence）：legacy 不读 spec.TCP 的
//     Handshake/Termination——Activation!=nil 时握手恒发生（doip.go:582）、
//     挥手只 gate Termination（doip.go:777）。链上由 tcp 层执行这两个开关
//     （applySpecToChain 无条件写入 cfg）：tcp:{handshake:false} 在链上可
//     关握手（层模型意图），legacy 上该键被忽略——flat 策略经
//     strategy_convert 默认化后 spec.TCP 非 nil（true/true），与 legacy
//     一致；唯一分歧是显式 false（legacy 无此表达）。
//   - Activation.Direction="down" 同样不受支持：legacy 硬编码请求 up/
//     响应 down（doip.go:607/611），生成器尊重字段值（字段文档：
//     "up" = 0x0005 request）——设为 down 时事件方向与 legacy 分歧，
//     属层模型意图（与 DoIPMessage.Direction 语义一致）。
//
// 生成器内部顺序与 legacy 阶段循环（Phase 4→5→6→7）逐帧一致。

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// DoIPGenerator is the doip terminal-layer generator.
type DoIPGenerator struct{}

// Name returns "doip".
func (g *DoIPGenerator) Name() string { return "doip" }

// Generate produces one message event per DoIP frame in plan order。
// TCP 层生成器负责握手/seq-ack/挥手/MSS 分段。
func (g *DoIPGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("doip generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	c := req.Meta.DoIP
	if c == nil {
		return fmt.Errorf("doip generator: no config (spec.doip required)")
	}
	// UDP 阶段：链上无 UDP 混合流（enip IOData 同款先例）。
	if c.Discovery != nil {
		return fmt.Errorf("doip generator: discovery (UDP) is not supported on the layer chain (tcp only)")
	}
	if c.EntityStatus != nil {
		return fmt.Errorf("doip generator: entity_status (UDP) is not supported on the layer chain (tcp only)")
	}
	if c.PowerMode != nil {
		return fmt.Errorf("doip generator: power_mode (UDP) is not supported on the layer chain (tcp only)")
	}
	// Messages 依赖 Activation（legacy Validate 已拦，双保险）。
	if len(c.Messages) > 0 && c.Activation == nil {
		return fmt.Errorf("doip generator: messages require activation (routing activation first)")
	}

	pv := c.ProtocolVersion
	if pv == 0 {
		pv = DefaultProtocolVersion
	}
	invPV := inverseProtocolVersion(pv)

	testerAddr := c.TesterAddress
	if testerAddr == 0 {
		testerAddr = DefaultTesterAddress
	}
	logicalAddr := c.LogicalAddress
	if logicalAddr == 0 {
		logicalAddr = DefaultLogicalAddress
	}

	mss := uint16(DefaultMSS)
	if req.Meta.TCP != nil && req.Meta.TCP.MSS > 0 {
		mss = req.Meta.TCP.MSS
	}

	// emit sends one DoIP frame event: 8-byte header + payload.
	emit := func(up bool, pt uint16, payload []byte) error {
		header := make([]byte, DoIPHeaderLen)
		header[0] = pv
		header[1] = invPV
		header[2] = byte(pt >> 8)
		header[3] = byte(pt)
		pl := uint32(len(payload))
		header[4] = byte(pl >> 24)
		header[5] = byte(pl >> 16)
		header[6] = byte(pl >> 8)
		header[7] = byte(pl)
		full := append(header, payload...)
		return g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: full})
	}

	// --- Phase 4: Routing Activation (TCP) ---
	activationSuccess := false
		if act := c.Activation; act != nil {
			// Direction 默认 up（字段文档："up" = 0x0005 request）。值域只有
			// up/down，normalizeDirection 非法值返回 "" → 走默认 up；"down"
			// 使 0x0005 下传（与 legacy 硬编码 dirUp/dirDown 的分歧点，见
			// 文件头 divergence 注释）。
			dir := act.Direction
			if dir != dirUp && dir != dirDown {
				dir = dirUp
			}
			reqPayload := buildRoutingActivationRequest(testerAddr, act.ActivationType, act.OEMSpecific)
			if err := emit(dir == dirUp, PTRoutingActivationReq, reqPayload); err != nil {
				return err
			}
			respPayload := buildRoutingActivationResponse(testerAddr, logicalAddr, act.ResponseCode, act.OEMSpecific)
			if err := emit(dir != dirUp, PTRoutingActivationResp, respPayload); err != nil {
				return err
			}
		if act.ResponseCode == 0x10 {
			activationSuccess = true
		}
		// Confirmation required（doip.go:624-631 同款）：Tester 重发 0x0005，
		// ECU 以最终成功 0x10 答复。
		if act.ResponseCode == 0x11 && act.ConfirmationRequired {
			if err := emit(dir == dirUp, PTRoutingActivationReq, reqPayload); err != nil {
				return err
			}
			finalPayload := buildRoutingActivationResponse(testerAddr, logicalAddr, 0x10, act.OEMSpecific)
			if err := emit(dir != dirUp, PTRoutingActivationResp, finalPayload); err != nil {
				return err
			}
			activationSuccess = true
		}
		// 激活失败：legacy 走 FIN+ACK 提前终止（doip.go:636-645），链上由
		// tcp 层接管 TCP 语义——显式拒绝（不静默分歧）。
		if !activationSuccess {
			return fmt.Errorf("doip generator: activation failed (response_code 0x%02X) is not supported on the layer chain (tcp layer takes over teardown)", act.ResponseCode)
		}
	}

	// --- Phase 5: Diagnostic Messages (TCP) ---
	for _, msg := range c.Messages {
		dir := normalizeDirection(msg.Direction)
		if dir == "" {
			dir = dirUp
		}
		// SA/TA 解析 + down 方向交换（doip.go:658-669 同款）。
		sa := msg.SourceAddress
		ta := msg.TargetAddress
		if sa == 0 {
			sa = testerAddr
		}
		if ta == 0 {
			ta = logicalAddr
		}
		if dir == dirDown {
			sa, ta = ta, sa
		}
		userData := msg.UserData
		if msg.UDS != nil {
			userData = serializeUDS(msg.UDS)
		}
		// 0x36 TransferData 分段（doip.go:677-701 同款）。
		var chunks [][]byte
		if msg.UDS != nil && msg.UDS.ServiceID == 0x36 && len(userData) > int(mss)-40 {
			maxChunk := int(mss) - 40 - 2
			if maxChunk < 1 {
				maxChunk = 1
			}
			data := msg.UDS.TransferData
			blockSeq := msg.UDS.BlockSequenceCounter
			for len(data) > 0 {
				n := maxChunk
				if len(data) < n {
					n = len(data)
				}
				chunk := append([]byte{userData[0], blockSeq}, data[:n]...)
				chunks = append(chunks, chunk)
				data = data[n:]
				blockSeq++
			}
		}
		if len(chunks) == 0 {
			chunks = [][]byte{userData}
		}
		for _, ud := range chunks {
			if err := emit(dir == dirUp, PTDiagnosticMessage, buildDiagnosticMessage(sa, ta, ud)); err != nil {
				return err
			}
			// 0x8002 Ack / 0x8003 Nack：接收侧在相反方向回（doip.go:720-737 同款，
			// ack SA = 0x8001 TA、ack TA = 0x8001 SA）。
			ackDir := dir != dirUp
			if msg.NackCode == nil {
				if err := emit(ackDir, PTDiagnosticMessageAck, buildDiagnosticMessageAck(ta, sa, ud)); err != nil {
					return err
				}
			} else {
				if err := emit(ackDir, PTDiagnosticMessageNack, buildDiagnosticMessageNack(ta, sa, *msg.NackCode, ud)); err != nil {
					return err
				}
			}
		}
	}

	// --- Phase 6: Alive Check (TCP) ---
	if c.AliveCheck != nil {
		ac := c.AliveCheck
		dir := normalizeDirection(ac.Direction)
		if dir == "" {
			dir = dirDown
		}
		if dir == dirDown {
			if err := emit(false, PTAliveCheckRequest, nil); err != nil {
				return err
			}
		} else {
			sa := ac.SourceAddress
			if sa == 0 {
				sa = testerAddr
			}
			if err := emit(true, PTAliveCheckResponse, u16BE(sa)); err != nil {
				return err
			}
		}
	}

	// --- Phase 7: Generic NACK (TCP) ---
	if c.GenericNack != nil {
		if err := emit(false, PTGenericNack, []byte{c.GenericNack.NackCode}); err != nil {
			return err
		}
	}
	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks)。
func (g *DoIPGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *DoIPGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *DoIPGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("doip generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("doip", func() (layers.LayerGenerator, error) {
		return &DoIPGenerator{}, nil
	})
	layers.RegisterLayerValidator("doip", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 链级拒绝（与 enip IOData/transport-udp 同款纪律）：UDP 阶段与激活
		// 失败是 legacy 合法配置（doip.go:454-574/636-645），但链上无表达载体
		// （无 UDP 混合流；TCP 挥手由 tcp 层接管）——生成器显式报错。该错误
		// 在 drive 内被"驱动失败 → 空流"契约吞掉（chain_planner.go:382-386），
		// 任务会报 completed + 0 包（CLAUDE.md 测试策略 §2 反例）。必须在
		// Validate 同步拒绝，Plan 才如实报错。
		c := spec.DoIP
		if c == nil {
			return nil
		}
		if c.Discovery != nil {
			return fmt.Errorf("doip: discovery (UDP) is not supported on the layer chain (tcp only)")
		}
		if c.EntityStatus != nil {
			return fmt.Errorf("doip: entity_status (UDP) is not supported on the layer chain (tcp only)")
		}
		if c.PowerMode != nil {
			return fmt.Errorf("doip: power_mode (UDP) is not supported on the layer chain (tcp only)")
		}
		if c.Activation != nil {
			// 激活失败 = denied（0x00-0x07）或 0x11 无确认；0x10 成功与
			// 0x11+ConfirmationRequired（重发 0x0005 → 最终 0x10）放行。
			// legacy 失败路径走 FIN+ACK 提前终止（doip.go:636-645）；链上
			// TCP 挥手由 tcp 层接管，生成器无法表达"失败即终止"——同步拒绝。
			rc := c.Activation.ResponseCode
			if rc != 0x10 && !(rc == 0x11 && c.Activation.ConfirmationRequired) {
				return fmt.Errorf("doip: activation failed (response_code 0x%02X) is not supported on the layer chain (tcp layer takes over teardown)", rc)
			}
		}
		// Activation 存在性校准进 spec.TCP（legacy doip.go:777 同款：挥手
		// 条件要求 Activation!=nil 且激活成功——Activation==nil 时 legacy
		// 连 TCP 握手都没有，链上必须关掉 tcp 层的握手/挥手，否则多产
		// 3+4 包与 legacy 分歧）。Activation!=nil 时默认 true，用户显式
		// false 尊重（tcp 层执行）。
		if c.Activation != nil {
			return nil
		}
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = false
		spec.TCP.Termination = false
		return nil
	})
}
