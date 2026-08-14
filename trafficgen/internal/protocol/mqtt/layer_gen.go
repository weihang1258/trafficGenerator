package mqtt

// MQTTGenerator is the mqtt terminal-layer generator (mqtt 终结层层生成器,
// P4a)。MQTT 3.1.1/5.0——一次 flow = 一个 4-tuple 上的一条 TCP 连接 + 一个
// client_id 的完整会话：CONNECT(up) → CONNACK(down) → [SUBSCRIBE/SUBACK]×N →
// [PUBLISH/QoS ack 交换]×N → [PINGREQ/PINGRESP] → [Will 发布] → [DISCONNECT]。
// 每条 wire 帧一个"报文事件"（方向 + 完整字节），构建字节由 buildConnect /
// buildConnack / buildPublish / buildPuback / buildPubrec / buildPubrel /
// buildPubcomp / buildSubscribe / buildSuback / buildPingreq / buildPingresp /
// buildDisconnect 纯函数产出（复用，不重写）。事件模式（http 波 2 方案 A
// 同款）：TCP 语义（握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器。
//
// 与 legacy Plan（mqtt.go emitSessionFlow 952-1206）的差异（文档化
// divergence）：
//   - legacy 自产 TCP 握手（3 包）与挥手（3 包 FIN up → FIN down → ACK up，
//     emitSessionFlow 1191-1203）——事件模式不产：tcp 层生成器负责（防双
//     握手）。握手/挥手开关由 tcp 层 schema 默认 true 执行，validator 强制
//     校准 true（legacy mqtt.go 恒产握手/挥手，从不读 spec.TCP.Handshake /
//     Termination，语义一致）。链上挥手是 TCPGenerator 标准 4 包（FIN|ACK
//     up → ACK down → FIN|ACK down → ACK up），与 legacy 3 包挥手为层模型
//     意图的文档化分歧（modbus/dnp3/doip 链测试同款断言形状）。
//   - legacy RST 挥手（spec.TCP.RST=true → 单 RST 包，emitSessionFlow
//     1194-1198）：链上 tcp 层终止不支持 RST 开关，生成器忽略
//     spec.TCP.RST（TCP 层语义见 tcp 层生成器——终止恒 FIN 4 包）。
//   - 多流展开（Sessions[] 每项独立 4-tuple + 自动递增 srcPort，emitAll
//     846-896）不支持：链一次一个 flow（一个 4-tuple），Sessions 非空显式
//     拒绝（enip session_count/flow_count、dnp3 multi_outstation、modbus
//     master_count/flow_count 同款先例）。
//   - 逐包 Timestamp：legacy 恒 now（emitSessionFlow 993）；链上由
//     ChainPlanner 统一回填（chain_planner.go:400），事件流不产。
//   - 握手 seq：legacy 在 spec.TCP.InitialSeq 为零时随机 ISN
//     （emitSessionFlow 1005-1008）；链上由 tcp 层生成器持有，事件流不产。
//   - srcPort：legacy 多流派生（emitAll 877-881）不适用（链拒绝多流）；
//     单流时 legacy 用 spec.SrcPort 原值（emitAll 852-856）——validateSpecBase
//     对 mqtt 分支不默认化 srcPort，与 legacy 一致（modbus/gbt32960/mcp 同款）。
//   - dstPort 默认化：legacy Plan 内默认（emitAll 853-860，1883）；链上由
//     validateSpecBase 默认化（chain_planner.go dst 端口 mqtt 分支），生成器
//     不再默认。
//   - 生成器在首个事件前同步检查多流（Sessions 非空 → 显式 error）；链上
//     "驱动失败 → 空流"契约会把生成器错误吞成 completed+0 包
//     （chain_planner.go:382-386），validator 同款拒绝为双保险（enip 同款
//     纪律）。
//
// 生成器内部顺序与 legacy emitSessionFlow（952-1206）逐帧一致；事件方向/
// 字节与 legacy 数据帧（flags=0x18 PSH-ACK payload）一一对应。

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// MQTTGenerator is the mqtt terminal-layer generator.
type MQTTGenerator struct{}

// Name returns "mqtt".
func (g *MQTTGenerator) Name() string { return "mqtt" }

// Generate produces one message event per MQTT wire frame in legacy
// emitSessionFlow order（CONNECT → CONNACK → 订阅 → 消息 → ping → will →
// DISCONNECT，ConnectAckCode==0 门控）。TCP 层生成器负责握手/seq-ack/挥手/
// MSS 分段。
func (g *MQTTGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.EmitMsg == nil {
		return fmt.Errorf("mqtt generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	c := req.Meta.MQTT
	if c == nil {
		return fmt.Errorf("mqtt generator: no config (spec.mqtt required)")
	}

	// --- 多流展开拒绝（enip session_count/flow_count、dnp3 multi_outstation、
	// modbus master_count/flow_count 同款先例）：legacy 每 Sessions[] 项独立
	// 4-tuple + 自动递增 srcPort（emitAll 846-896），链一次一个 flow 无等价
	// 物——显式拒绝，不能静默只产 1 流（包数缩水）。与 validator 的双保险
	// 检查（Generate 级在事件产出前同步报错）。
	if len(c.Sessions) > 0 {
		return fmt.Errorf("mqtt generator: sessions (%d) multi-stream expansion is not supported on a tcp-layer chain (one flow per chain)", len(c.Sessions))
	}

	// --- 自动 client_id 解析（emitSessionFlow 959-971 逐行同款）---
	// 空 ClientID → "trafficgen-<counter6hex>" 确定性自动生成（原子计数器，
	// 跨任务唯一且可复现——不是随机）+ 强制 CleanSession=true（3.1.1
	// §3.1.3.1：零长 ClientID 仅允许 CleanSession=1）。
	cfg := *c
	if cfg.ClientID == "" {
		cfg.ClientID = fmt.Sprintf("trafficgen-%06x", clientIDCounter.Add(1))
		cs := true
		cfg.CleanSession = &cs
	}

	// --- 默认化（emitSessionFlow 973-981 同款）---
	version := cfg.Version
	if version == 0 {
		version = 4
	}
	disconnect := true
	if cfg.Disconnect != nil {
		disconnect = *cfg.Disconnect
	}

	// 逐帧 emit（emitData 语义同款：每事件方向 + 完整 MQTT 帧字节；MSS 分段
	// 是 tcp 层的事，生成器不预分段——与 legacy 的分段在 TCP 层同位置）。
	emit := func(up bool, payload []byte) error {
		return g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: payload})
	}

	// --- CONNECT (up) ---
	if err := emit(true, buildConnect(&cfg)); err != nil {
		return err
	}

	// --- CONNACK (down) ---
	if err := emit(false, buildConnack(&cfg)); err != nil {
		return err
	}

	// If the CONNACK code != 0, the connection was rejected: skip all
	// subsequent MQTT packets（emitSessionFlow 1124 同款门控）。
	if cfg.ConnectAckCode != 0 {
		return nil
	}

	// Per-flow packet identifier auto-assignment（emitSessionFlow 990/1113-1120
	// 同款：从 1 开始，wrap 从 65535 回到 1，永不 0；subscriptions → messages
	// → will 共享同一计数器）。
	autoPacketID := uint16(1)
	nextID := func() uint16 {
		n := autoPacketID
		autoPacketID++
		if autoPacketID == 0 {
			autoPacketID = 1
		}
		return n
	}

	// --- SUBSCRIBE / SUBACK（emitSessionFlow 1126-1136 同款）---
	for _, sub := range cfg.Subscriptions {
		s := sub
		if s.PacketID == 0 {
			s.PacketID = nextID()
		}
		if err := emit(true, buildSubscribe(s, version)); err != nil {
			return err
		}
		if err := emit(false, buildSuback(s.PacketID, s.AckReasonCodes, len(s.Filters), version)); err != nil {
			return err
		}
	}

	// --- Messages：每个 PUBLISH 后接其 QoS ack 链（emitSessionFlow 1139-1156
	// 同款；buildMessagePackets 的 direction 语义：QoS0 → PUBLISH only，
	// QoS1 → PUBLISH+PUBACK，QoS2 → PUBLISH+PUBREC+PUBREL+PUBCOMP，ack 方向
	// 与 publish 相反）---
	for _, msg := range cfg.Messages {
		m := msg
		if m.PacketID == 0 && m.QoS > 0 {
			m.PacketID = nextID()
		}
		for _, p := range buildMessagePackets(version, m) {
			up := p.direction != "down"
			if err := emit(up, p.payload); err != nil {
				return err
			}
		}
	}

	// --- PINGREQ / PINGRESP（emitSessionFlow 1159-1162 同款）---
	if cfg.PingAfterMessages {
		if err := emit(true, buildPingreq()); err != nil {
			return err
		}
		if err := emit(false, buildPingresp()); err != nil {
			return err
		}
	}

	// --- 异常断开 + 配置了 Will：模拟 broker 侧 Will 发布（emitSessionFlow
	// 1164-1178 同款：disconnect=false 才发布；Will 帧方向恒 down）---
	if !disconnect && cfg.Will != nil {
		will := MQTTMessage{Topic: cfg.Will.Topic, Payload: cfg.Will.Payload, QoS: cfg.Will.QoS, Retain: cfg.Will.Retain, Direction: "down"}
		if will.QoS > 0 {
			will.PacketID = nextID()
		}
		for _, p := range buildMessagePackets(version, will) {
			up := p.direction != "down"
			if err := emit(up, p.payload); err != nil {
				return err
			}
		}
	}

	// --- DISCONNECT（最后一个 MQTT 包，emitSessionFlow 1180-1188 同款；
	// ConnectAckCode != 0 时跳过）---
	if disconnect {
		reason := 0
		if cfg.DisconnectReason != nil {
			reason = *cfg.DisconnectReason
		}
		if err := emit(true, buildDisconnect(version, reason)); err != nil {
			return err
		}
	}

	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks)。
func (g *MQTTGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *MQTTGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *MQTTGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("mqtt generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("mqtt", func() (layers.LayerGenerator, error) {
		return &MQTTGenerator{}, nil
	})
	layers.RegisterLayerValidator("mqtt", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// 多流展开拒绝（enip/modbus 同款纪律）：legacy 每 Sessions[] 项独立
		// 4-tuple + 自动递增 srcPort（emitAll 846-896），链一次一个 flow 无
		// 等价物——Plan 期同步拒绝（生成器级检查为双保险，驱动错误会被吞成
		// 空流）。
		if spec.MQTT != nil && len(spec.MQTT.Sessions) > 0 {
			return fmt.Errorf("mqtt: sessions (%d) multi-stream expansion is not supported on the layer chain (one flow per chain)", len(spec.MQTT.Sessions))
		}
		// 握手/挥手校准进 spec.TCP（modbus layer_gen.go:171-184 同款陷阱）：
		// legacy mqtt.go 恒产 TCP 握手/挥手（emitSessionFlow 1096-1101/
		// 1191-1203 无开关，从不读 spec.TCP.Handshake/Termination）——spec.TCP
		// 零值 false 必须写默认 true，否则 tcp 层生成器跳过握手/挥手（链测试
		// spec.TCP 只设 InitialSeq 即复现：applySpecToChain 把零值 false 直落
		// 层 config）。与 legacy 语义一致：mqtt 链上的握手/挥手不可关（legacy
		// 亦无此表达——flat 的 tcp:{handshake:false} 在 legacy 被忽略，链上
		// 同样强制 true）。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
