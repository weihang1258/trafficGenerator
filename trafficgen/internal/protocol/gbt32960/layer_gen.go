package gbt32960

// GBT32960Generator is the gbt32960 terminal-layer generator (gbt32960 终结
// 层层生成器, P4a)。GB/T 32960.3-2016——一次 flow 建模一辆车（或平台侧会话）
// 的完整业务序列：0x01 登入 → 0x0C 确认 → 0x02 实时上报 ×N（0x08 控制 /
// 0x03 补报 按序插入）→ 0x04 登出（vehicle 状态机）；0x05 平台登入 →
// 0x0B 心跳 ×N → 0x06 平台登出（platform 状态机）。每条消息一个"报文事件"
// （方向 + 完整 wire 字节），构建字节由 buildMessage 纯函数产出（复用）。
// 事件模式（http 波 2 方案 A 同款）：TCP 语义（握手/seq-ack/挥手/MSS 分段）
// 交给 tcp 层生成器。
//
// 与 legacy Plan（gbt32960.go:531-766）的差异（文档化 divergence）：
//   - legacy 自产 TCP 握手（3 包，gbt32960.go:733-741）与挥手（3 包，
//     gbt32960.go:754-762）——事件模式不产：tcp 层生成器负责（防双握手），
//     挥手为 tcp 层标准 4 包（FIN|ACK up → ACK down → FIN|ACK down → ACK
//     up，generator.go:874-943；legacy 是 3 包 FIN up → FIN down → ACK up）。
//     层模型意图：握手/挥手开关由 tcp 层 schema 默认 true 执行，legacy
//     恒开（gbt32960.go 不读 spec.TCP.Handshake/Termination），语义一致。
//   - 逐包 Timestamp：legacy 恒 time.Now()（gbt32960.go:601）；链上由
//     ChainPlanner 统一回填（chain_planner.go:400），事件流不产。
//   - groupIDMeta（gbt32960.go:770-785）：legacy 每包 Metadata 带
//     group_id（显式 group_id > VIN/PlatformID > 无）；链上分组是引擎/
//     worker 层职责，事件流不产（UDP 终结层链同款）。
//   - 生成器在 build 前同步检查 BCC 注入索引边界（InjectBCCError &&
//     BCCErrorIndex 越界 → 显式 error）；legacy 在 Plan 内静默关通道
//     （gbt32960.go:653-660 防御检查，靠 Validate V23/V24 兜底）。链上
//     "驱动失败 → 空流"契约会把生成器错误吞成 completed+0 包
//     （chain_planner.go:382-386），因此 validator 同步拒绝（legacy
//     Validate 同款 V24 检查），生成器内检查为双保险（doip 同款纪律）。
//
// 生成器内部顺序与 legacy 状态机（buildVehicleMessages /
// buildPlatformMessages）逐消息一致；事件方向/字节与 legacy 数据帧
// （flags=0x18 PSH-ACK payload）一一对应。

import (
	"context"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// GBT32960Generator is the gbt32960 terminal-layer generator.
type GBT32960Generator struct{}

// Name returns "gbt32960".
func (g *GBT32960Generator) Name() string { return "gbt32960" }

// Generate produces one message event per GBT32960 wire message in state
// machine order。TCP 层生成器负责握手/seq-ack/挥手/MSS 分段。
func (g *GBT32960Generator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("gbt32960 generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	c := req.Meta.GBT32960
	if c == nil {
		return fmt.Errorf("gbt32960 generator: no config (spec.gbt32960 required)")
	}

	// --- 默认化（legacy Plan gbt32960.go:545-600 逐行同款）---
	role := strings.ToLower(strings.TrimSpace(c.Role))
	if role == "" {
		role = "vehicle"
	}
	vinPad := byte(0x00)
	if c.VINPadByte != nil {
		vinPad = *c.VINPadByte
	}
	loginSerial := c.LoginSerialNumber
	if loginSerial == 0 {
		loginSerial = 1
	}
	logoutSerial := c.LogoutSerialNumber
	if logoutSerial == 0 {
		logoutSerial = loginSerial
	}
	subsysCount := c.RechargeableSubsysCount
	if subsysCount == 0 {
		subsysCount = 1
	}
	subsysCodeLen := c.RechargeableSubsysCodeLength
	if subsysCodeLen == 0 {
		subsysCodeLen = 1
	}
	isTransBattery := true
	if c.IsTransBatteryData != nil {
		isTransBattery = *c.IsTransBatteryData
	}
	encByte := encryptRuleByte(c.EncryptRule)

	// 登录/登出/上报时间（legacy resolveTimes 同款；LoginTime 显式时确定性）。
	loginTime, logoutTime, reportTimes := resolveTimes(c)

	// VIN/PlatformID 字段（17 字节，wire 用）。
	var vinField []byte
	if role == "platform" {
		if c.PlatformID != "" {
			vinField = encodeVIN(c.PlatformID, 0x00)
		} else {
			vinField = make([]byte, VINLen)
		}
	} else {
		vinField = encodeVIN(c.VIN, vinPad)
	}

	// emitMsg 记录待发消息（legacy gbt32960.go:632-640 同款：状态机只填充
	// 数据，build 延后到全部收集后统一执行，BCC 注入按 index 生效）。
	type pendingMsg struct {
		cmd       byte
		resp      byte
		data      []byte
		direction string // "up" or "down"
	}
	var msgs []pendingMsg
	emitMsg := func(direction string, cmd, resp byte, data []byte) {
		msgs = append(msgs, pendingMsg{
			cmd:       cmd,
			resp:      resp,
			data:      data,
			direction: direction,
		})
	}

	if role == "vehicle" {
		buildVehicleMessages(c, emitMsg, loginTime, logoutTime, reportTimes,
			loginSerial, logoutSerial, subsysCount, subsysCodeLen,
			isTransBattery)
	} else {
		buildPlatformMessages(c, emitMsg)
	}

	// BCC 注入索引边界（V24，legacy Plan 内防御检查 gbt32960.go:653-660 的
	// 同步版）。在 build/emit 任何消息**之前**检查，不产出任何事件。
	if c.InjectBCCError && (c.BCCErrorIndex < 0 || c.BCCErrorIndex >= len(msgs)) {
		return fmt.Errorf("gbt32960 generator: BCCErrorIndex %d exceeds message count %d", c.BCCErrorIndex, len(msgs))
	}

	// 逐条构建 wire 字节并注入 BCC 错误（legacy gbt32960.go:661-669 同款）。
	for i, m := range msgs {
		wire := buildMessage(m.cmd, m.resp, vinField, encByte, m.data)
		if c.InjectBCCError && i == c.BCCErrorIndex {
			if flipped, err := flipBCCBit(wire); err == nil {
				wire = flipped
			}
		}
		if err := g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: m.direction == "up", Bytes: wire}); err != nil {
			return err
		}
	}
	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks)。
func (g *GBT32960Generator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *GBT32960Generator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *GBT32960Generator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("gbt32960 generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("gbt32960", func() (layers.LayerGenerator, error) {
		return &GBT32960Generator{}, nil
	})
	layers.RegisterLayerValidator("gbt32960", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 握手/挥手校准进 spec.TCP（dnp3 layer_gen.go:99-101 同款陷阱）：
		// legacy gbt32960.go 恒产 TCP 握手/挥手（gbt32960.go:733-762 无开关，
		// 从不读 spec.TCP.Handshake/Termination）——spec.TCP 零值 false 必须
		// 写默认 true，否则 tcp 层生成器跳过握手/挥手（链测试 spec.TCP 只设
		// InitialSeq 即复现：applySpecToChain 把零值 false 直落层 config）。
		// 与 legacy 语义一致：gbt32960 链上的握手/挥手不可关（legacy 亦无此
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
