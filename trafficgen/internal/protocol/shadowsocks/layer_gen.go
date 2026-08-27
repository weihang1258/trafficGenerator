package shadowsocks

// ShadowsocksGenerator is the shadowsocks terminal-layer generator
// (shadowsocks 终结层层生成器, P3)。Shadowsocks——一次 flow = 一个 4-tuple 上
// 的一条 TCP 连接 + 一个 Shadowsocks 会话：TCP 握手 → [可选 SOCKS5 握手] →
// [可选 HTTP 混淆] → [AEAD salt] → [AEAD chunk loop] → TCP 挥手。每条帧一个
// "报文事件"（方向 + 完整字节），构建字节由 buildSOCKS5*/buildHTTPObfuscation/
// buildAEADChunk 纯函数产出（复用，不重写）。事件模式（mqtt/grpc/ssh/rdp/
// vmess 同款）：TCP 语义（握手/seq-ack/挥手/MSS 分段）交给 tcp 层生成器。
//
// 与 legacy Plan（planner.go Plan）的差异（文档化 divergence）：
//   - legacy 自产 TCP 握手（3 包，planner.go:442-446）与挥手（4 包 FIN-ACK/
//     ACK/FIN-ACK/ACK，planner.go:545-550）——事件模式不产：tcp 层生成器负责
//     （防双握手）。握手/挥手开关由 tcp 层 schema 默认 true 执行，validator
//     强制校准 true（legacy shadowsocks.go 恒产握手/挥手，从不读
//     spec.TCP.Handshake/Termination，语义一致）。
//   - UDP 模式（Mode=udp）链上不支持：legacy 产 UDP 数据报（buildUDPPacket，
//     planner.go:405-437）；链上 tcp 层无等价 UDP 数据报。validator 显式
//     拒绝 UDP 模式（openvpn TCP 模式、vmess UDP 模式同款先例）。
//   - legacy 逐包 Timestamp：legacy 恒 now；链上由 ChainPlanner 统一回填
//     （chain_planner.go:400），事件流不产。
//   - 握手 seq/ipID：legacy 在 spec.TCP.InitialSeq 为零时随机 ISN；链上由
//     tcp 层生成器持有，事件流不产。
//   - srcPort：legacy 单流用 spec.SrcPort 原值（emit 闭包直传）；
//     validateSpecBase 对 shadowsocks 分支不默认化 srcPort，与 legacy 一致。
//   - dstPort 默认化：legacy Plan 内默认 8388；链上由 validateSpecBase
//     默认化（chain_planner.go dst 端口 shadowsocks 分支），生成器不再默认。
//   - salt 字节：legacy 在 PayloadBytesFormat != "zeros" 时 rand.Read(salt)
//     （planner.go:490）；生成器同款（zeros 时零初始化，否则随机——复用
//     rand.Read）。
//   - Chunk 解析：Chunks>0 显式计数；Chunks==0 且 spec.Payload 非空时按
//     MaxChunkPayload 拆分（planner.go:496-531）；生成器同款。链上无
//     spec.Payload 直传（FlowMeta.Payload），生成器读 req.Meta.Payload。
//
// 生成器内部顺序与 legacy Plan（442-549）逐帧一致；事件方向/字节与 legacy
// 数据帧（flags=0x18 PSH-ACK payload）一一对应。

import (
	"context"
	"fmt"
	"math/rand"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// ShadowsocksGenerator is the shadowsocks terminal-layer generator.
type ShadowsocksGenerator struct{}

// Name returns "shadowsocks".
func (g *ShadowsocksGenerator) Name() string { return "shadowsocks" }

// Generate produces one message event per Shadowsocks wire frame in legacy Plan
// order（[SOCKS5 握手] → [HTTP 混淆] → salt → AEAD chunk loop）。TCP 层生成器
// 负责握手/seq-ack/挥手/MSS 分段。
func (g *ShadowsocksGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req == nil || req.EmitMsg == nil {
		return fmt.Errorf("shadowsocks generator: EmitMsg is nil (generator not wired to a transport layer)")
	}
	ss := req.Meta.Shadowsocks
	if ss == nil {
		return fmt.Errorf("shadowsocks generator: no config (spec.shadowsocks required)")
	}
	// UDP 模式链上不支持（validator 已同步拒绝；此处双保险防御，理论上不可达）。
	if normalizeMode(ss.Mode) == "udp" {
		return fmt.Errorf("shadowsocks generator: Mode=udp is not supported on the layer chain (tcp layer cannot emit Shadowsocks UDP datagrams)")
	}

	// emit 单事件（direction + 完整帧字节）。
	emit := func(up bool, payload []byte) error {
		return g.emitMsg(ctx, req.EmitMsg, layers.MessageEvent{Up: up, Bytes: payload})
	}

	// --- 可选 SOCKS5 握手 ---
	if ss.SOCKS5Handshake {
		greeting := buildSOCKS5Greeting(ss)
		if err := emit(true, greeting); err != nil {
			return err
		}
		methodResp := buildSOCKS5MethodResponse(ss)
		if err := emit(false, methodResp); err != nil {
			return err
		}
		if ss.SOCKS5AuthMethod == "password" {
			authReq := buildSOCKS5AuthRequest(ss)
			if err := emit(true, authReq); err != nil {
				return err
			}
			authResp := buildSOCKS5AuthResponse()
			if err := emit(false, authResp); err != nil {
				return err
			}
		}
		socks5Req := buildSOCKS5Request(ss)
		if err := emit(true, socks5Req); err != nil {
			return err
		}
		socks5Reply := buildSOCKS5Reply(ss)
		if err := emit(false, socks5Reply); err != nil {
			return err
		}
	}

	// --- 可选 HTTP 混淆 ---
	if ss.Obfuscation == "http" {
		obfHeader := buildHTTPObfuscation(ss)
		if err := emit(true, obfHeader); err != nil {
			return err
		}
	}

	// --- Shadowsocks Salt (32 bytes) ---
	cipher := normalizeCipher(ss.Cipher)
	if isAEADCipher(cipher) {
		salt := make([]byte, SaltLen)
		if ss.PayloadBytesFormat != "zeros" {
			rand.Read(salt)
		}
		if err := emit(true, salt); err != nil {
			return err
		}
	}

	// --- AEAD Chunk loop ---
	var chunkSizes []int
	if ss.Chunks > 0 {
		payloadSize := ss.ChunkPayloadSize
		if payloadSize <= 0 {
			if len(req.Meta.Payload) > 0 {
				payloadSize = len(req.Meta.Payload)
				if payloadSize > MaxChunkPayload {
					payloadSize = MaxChunkPayload
				}
			} else {
				payloadSize = 0
			}
		}
		for i := 0; i < ss.Chunks; i++ {
			chunkSizes = append(chunkSizes, payloadSize)
		}
	} else if len(req.Meta.Payload) > 0 {
		chunkSize := ss.ChunkPayloadSize
		if chunkSize <= 0 || chunkSize > MaxChunkPayload {
			chunkSize = MaxChunkPayload
		}
		remaining := len(req.Meta.Payload)
		for remaining > 0 {
			sz := chunkSize
			if sz > remaining {
				sz = remaining
			}
			chunkSizes = append(chunkSizes, sz)
			remaining -= sz
		}
	} else {
		chunkSizes = append(chunkSizes, ss.ChunkPayloadSize)
	}

	for _, sz := range chunkSizes {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk := buildAEADChunk(ss, sz)
		if err := emit(true, chunk); err != nil {
			return err
		}
	}

	return nil
}

// emitMsg sends one message event, honoring context cancellation so the
// generator cannot hang when the transport layer stops consuming the event
// stream (same escape hatch as the chain_planner wiring callbacks)。
func (g *ShadowsocksGenerator) emitMsg(ctx context.Context, emit func(layers.MessageEvent) error, ev layers.MessageEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return emit(ev)
}

// GenEvents marks this generator as a message event producer.
func (g *ShadowsocksGenerator) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method, present only to satisfy
// the producer marker; events flow through GenRequest.EmitMsg, so calling
// this directly is a wiring error — fail loudly.
func (g *ShadowsocksGenerator) EmitEvent(ev layers.MessageEvent) error {
	return fmt.Errorf("shadowsocks generator: EmitEvent is not wired; events flow through GenRequest.EmitMsg only")
}

func init() {
	layers.RegisterLayerGenerator("shadowsocks", func() (layers.LayerGenerator, error) {
		return &ShadowsocksGenerator{}, nil
	})
	layers.RegisterLayerValidator("shadowsocks", func(spec *core.FlowSpec) error {
		if err := (&Planner{}).Validate(*spec); err != nil {
			return err
		}
		// UDP 模式链上不支持（openvpn TCP 模式、vmess UDP 模式同款先例）：
		// legacy Mode=udp 产 UDP 数据报（buildUDPPacket），链上 tcp 层无等价
		// UDP 数据报。同步拒绝（默认 Mode=tcp 不受影响）。
		if spec.Shadowsocks != nil && normalizeMode(spec.Shadowsocks.Mode) == "udp" {
			return fmt.Errorf("shadowsocks: Mode=udp is not supported on the layer chain")
		}
		// 握手/挥手校准进 spec.TCP（mqtt/redis/modbus layer_gen.go 同款陷阱）：
		// legacy shadowsocks planner.go 恒产 TCP 握手/挥手（442-446/545-550
		// 无开关，从不读 spec.TCP.Handshake/Termination）——spec.TCP 零值 false
		// 必须写默认 true，否则 tcp 层生成器跳过握手/挥手（链测试 spec.TCP 只设
		// InitialSeq 即复现）。与 legacy 语义一致：shadowsocks 链上的握手/挥手
		// 不可关。
		if spec.TCP == nil {
			spec.TCP = &core.TCPConfig{}
		}
		spec.TCP.Handshake = true
		spec.TCP.Termination = true
		return nil
	})
}
