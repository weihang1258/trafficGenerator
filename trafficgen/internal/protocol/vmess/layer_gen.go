package vmess

// VmessGenerator is the vmess terminal-layer generator (vmess 终结层层生成器,
// P3)。VMess (V2Ray)——一次 flow = 一个 4-tuple 上的一条 TCP 连接 + 一个
// VMess 会话：TCP 握手 → VMess Request (AEAD 帧) → [Payload chunk] → VMess
// Response → [Response chunk] → [MUX 帧] → TCP 挥手。每条帧一个"报文事件"
//（方向 + 完整字节），构建字节由 buildVMessRequestPayload/
// buildVMessResponsePayload/buildAEADPayloadChunks/buildMUXFrame 纯函数产出
//（复用，不重写）。事件模式（mqtt/grpc/ssh/rdp 同款）：TCP 语义（握手/seq-ack/
// 挥手/MSS 分段）交给 tcp 层生成器。
//
// 与 legacy Plan（planner.go Plan）的差异（文档化 divergence）：
//   - legacy 自产 TCP 握手（3 包 flagSYN/SYNACK/ACK，planner.go:496-500）与
//     挥手（4 包 FIN-ACK/ACK/FIN-ACK/ACK，planner.go:470-475）——事件模式
//     不产：tcp 层生成器负责（防双握手）。握手/挥手开关由 tcp 层 schema
//     默认 true 执行，validator 强制校准 true（legacy vmess.go 恒产握手/挥手，
//     从不读 spec.TCP.Handshake/Termination，语义一致）。
//   - UDP 模式（Command=0x02）链上不支持：legacy 产 UDP 数据报
//     （emitUDP，planner.go:481-491）；链上 tcp 层无等价 UDP 数据报。
//     validator 显式拒绝 UDP 模式（openvpn TCP 模式同款先例）。
//   - legacy 逐包 Timestamp：legacy 恒 now；链上由 ChainPlanner 统一回填
//     （chain_planner.go:400），事件流不产。
//   - 握手 seq/ipID：legacy 在 spec.TCP.InitialSeq 为零时随机 ISN；链上由
//     tcp 层生成器持有，事件流不产。
//   - srcPort：legacy 单流用 spec.SrcPort 原值（emit 闭包直传）；
//     validateSpecBase 对 vmess 分支不默认化 srcPort，与 legacy 一致。
//   - dstPort 默认化：legacy Plan 内默认 443（strategy_convert 无默认，用户
//     须指定）；链上由 validateSpecBase 默认化（chain_planner.go dst 端口
//     vmess 分支），生成器不再默认。
//   - Heartbeat mode：legacy Heartbeat=true 产心跳 req/resp 循环（planner.go:
//     503-529）；生成器同款（Heartbeat 时跳过常规 req/resp/MUX 但保挥手）。
//   - RST 挥手（spec.TCP.RST=true → 单 RST 包，planner.go:592-593）：链上
//     tcp 层终止不支持 RST 开关，生成器忽略 spec.TCP.RST（与 mqtt/grpc
//     同款——TCP 层语义见 tcp 层生成器，终止恒 FIN 4 包）。
//
// 生成器内部顺序与 legacy Plan（496-596）逐帧一致；事件方向/字节与 legacy
// 数据帧（flags=0x18 PSH-ACK payload）一一对应。

import (
	"context"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// VmessGenerator is the vmess terminal-layer generator.
type VmessGenerator struct{}

// Name returns "vmess".
func (g *VmessGenerator) Name() string { return "vmess" }

// Generate produces one message event per VMess wire frame in legacy Plan order
// （TCP-mode request → [payload] → response → [response payload] → [MUX]）。
// TCP 层生成器负责握手/seq-ack/挥手/MSS 分段。
func (g *VmessGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("vmess generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	v := req.Meta.Vmess
	if v == nil {
		return fmt.Errorf("vmess generator: no config (spec.vmess required)")
	}
	// UDP 模式链上不支持（validator 已同步拒绝；此处双保险防御，理论上不可达）。
	if v.Command == CmdUDP {
		return fmt.Errorf("vmess generator: Command=0x02 (UDP) is not supported on the layer chain (tcp layer cannot emit VMess UDP datagrams)")
	}

	// 默认化（planner.go:328-339 同款）。
	enc := normalizeEncryption(v.Encryption)
	if enc == "" {
		enc = "aead_chacha20_poly1305"
	}
	cmd := v.Command
	if cmd == 0 {
		cmd = CmdTCP
	}
	heartbeatCount := v.HeartbeatCount
	if heartbeatCount <= 0 {
		heartbeatCount = 1
	}
	addrType, addrBytes := resolveAddress(v.AddressType, v.Address)
	uuidBytes, _ := parseUUID(v.UUID)

	// emit 单事件（direction + 完整帧字节）。
	emit := func(up bool, payload []byte) error {
		return g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: payload})
	}

	// --- Heartbeat mode ---
	if v.Heartbeat {
		for i := 0; i < heartbeatCount; i++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			hbV := *v
			hbV.HeaderPadLen = 8
			hbV.Payload = nil
			reqPayload := buildVMessRequestPayload(&hbV, uuidBytes, enc, addrType, addrBytes)
			if err := emit(true, reqPayload); err != nil {
				return err
			}
			hbVresp := *v
			hbVresp.ResponsePayload = nil
			respPayload := buildVMessResponsePayload(&hbVresp, uuidBytes, enc)
			if err := emit(false, respPayload); err != nil {
				return err
			}
		}
		// Heartbeat mode skips regular request/response and MUX but still teardown.
		return nil
	}

	// --- VMess Request ---
	reqPayload := buildVMessRequestPayload(v, uuidBytes, enc, addrType, addrBytes)
	if err := emit(true, reqPayload); err != nil {
		return err
	}

	// Payload chunk（AEAD 或 legacy）。
	if len(v.Payload) > 0 {
		if isAEADEncryption(enc) {
			chunked := buildAEADPayloadChunks(v.Payload)
			if err := emit(true, chunked); err != nil {
				return err
			}
		} else {
			if err := emit(true, v.Payload); err != nil {
				return err
			}
		}
	} else if isAEADEncryption(enc) {
		emptyChunk := make([]byte, 2+TagLen)
		if err := emit(true, emptyChunk); err != nil {
			return err
		}
	}

	// --- VMess Response ---
	respPayload := buildVMessResponsePayload(v, uuidBytes, enc)
	if err := emit(false, respPayload); err != nil {
		return err
	}
	if len(v.ResponsePayload) > 0 {
		if isAEADEncryption(enc) {
			chunked := buildAEADPayloadChunks(v.ResponsePayload)
			if err := emit(false, chunked); err != nil {
				return err
			}
		} else {
			if err := emit(false, v.ResponsePayload); err != nil {
				return err
			}
		}
	} else if isAEADEncryption(enc) {
		emptyChunk := make([]byte, 2+TagLen)
		if err := emit(false, emptyChunk); err != nil {
			return err
		}
	}

	// --- MUX mode ---
	if cmd == CmdMUX && len(v.MuxStreams) > 0 {
		for _, ms := range v.MuxStreams {
			if err := ctx.Err(); err != nil {
				return err
			}
			for _, frame := range ms.Frames {
				muxFrame := buildMUXFrame(ms.SessionID, frame, ms.TargetAddr, ms.TargetPort)
				if err := emit(true, muxFrame); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks)。
func (g *VmessGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *VmessGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *VmessGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("vmess generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("vmess", func() (layers.LayerGenerator, error) {
		return &VmessGenerator{}, nil
	})
	layers.RegisterLayerValidator("vmess", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// UDP 模式链上不支持（openvpn TCP 模式同款先例）：legacy Command=0x02
		// 产 UDP 数据报（emitUDP），链上 tcp 层无等价 UDP 数据报。同步拒绝
		//（默认 Command=0x01 TCP 不受影响）。
		if spec.Vmess != nil && spec.Vmess.Command == CmdUDP {
			return fmt.Errorf("vmess: Command=0x02 (UDP) is not supported on the layer chain")
		}
		// 握手/挥手校准进 spec.TCP（mqtt/redis/modbus layer_gen.go 同款陷阱）：
		// legacy vmess planner.go 恒产 TCP 握手/挥手（496-500/470-475 无开关，
		// 从不读 spec.TCP.Handshake/Termination）——spec.TCP 零值 false 必须写
		// 默认 true，否则 tcp 层生成器跳过握手/挥手（链测试 spec.TCP 只设
		// InitialSeq 即复现）。与 legacy 语义一致：vmess 链上的握手/挥手不可关。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
