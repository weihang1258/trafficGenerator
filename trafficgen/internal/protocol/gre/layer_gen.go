package gre

import (
	"context"
	"fmt"
	"net"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// GREGenerator is the gre tunnel-layer generator (gre 隧道层生成器, P2e T12)。
// It wraps every packet from the inner chain (内层 ip → tcp → http) into a
// GRE-encapsulated frame: the inner packet bytes are built here (complete
// inner IPv4 header + L4 with checksums — the core builder can't build the
// inner packet because GRE's payload is a bare IP packet, not an Ethernet
// frame), the outer L3.Protocol is set to 47 (IPPROTO_GRE), and the wire
// GRE config (Key/Checksum/Sequence) is written into L2.GRE for the core
// builder's writeGRE/fillGREChecksum to serialize.
//
// The inner IP header and inner L4 checksums are byte-identical to the
// legacy gre planner's buildInnerIPv4Packet / buildInnerL4 (same functions,
// same package). The inner addresses are the inner ip layer's values — for a
// [ip → gre → ip → tcp → http] chain, the ChainPlanner's applySpecToChain
// injects spec.SrcIP/DstIP into both ip layer configs, so outer and inner
// addresses are both the spec addresses (legacy gre: InnerSrcIP/InnerDstIP
// default to spec.SrcIP/DstIP); down 帧的内层地址交换与 legacy gre 的
// inSrc/inDst 交换一致（legacy planner.go:265-269）。
//
// 与 legacy 的差异（结构所致，已接受）：
//   - inner IPID 从 0 起每帧自增（legacy `InnerIPID + i`；链的会话不共享
//     IPID——外层 ip 层生成器持有外层 IPID，隧道层自持内层 counter，避免
//     Sess.IPID 双写竞态）。
//   - inner TTL 恒 64（legacy InnerTTL 默认 64；链层 InnerTTL 无注入路径）。
//   - TCPOptions 不注入（legacy cfg.TCPOptions 由策略直配；链层无该字段）。
//   - 内层 TCP 字段取自内层包 L4（seq/ack/flags/window 已由 tcp 层生成器
//     推进——比 legacy 读静态 spec.TCP 更真实）。
//   - flat spec.GRE（InnerSrcIP/ProtocolType/Frames/Direction...）不作用于
//     链路径：隧道链的接口是 gre 层 config（key/checksum/sequence），其余
//     字段无链层等价物，策略混用 flat gre + gre 链时 flat 静默忽略
//     （legacy 路径不变）。
type GREGenerator struct{}

// Name returns "gre".
func (g *GREGenerator) Name() string { return "gre" }

// GenEvents is unimplemented for the gre layer (gre 是隧道层，不是终结层，
// 无报文事件)。
func (g *GREGenerator) GenEvents() layers.EventGenerator { return nil }

// Generate wraps every packet from the inner chain in GRE encapsulation.
func (g *GREGenerator) Generate(ctx context.Context, req *layers.GenRequest) error {
	if req.Inner == nil {
		return fmt.Errorf("gre generator: Inner is nil (gre is a tunnel layer and requires an inner chain)")
	}
	if req.Emit == nil {
		return fmt.Errorf("gre generator: Emit is nil (gre is a tunnel layer and requires an outer chain)")
	}
	if req.Layer.Name != "gre" {
		return fmt.Errorf("gre generator: layer name %q, want \"gre\"", req.Layer.Name)
	}
	// 层 config → wire GRE 配置（schema 字段 key/checksum/sequence）。
	// key 为 0 时置位 K 无意义（RFC 2890：Key 域语义由上层决定，0 值等价无
	// Key），因此 KeyPresent = key != 0。
	cfg := req.Layer.Config
	key := greConfigUint32(cfg, "key")
	checksum := greConfigBool(cfg, "checksum")
	sequence := greConfigBool(cfg, "sequence")

	innerIPID := uint32(0)
	sequenceNum := uint32(0)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case pkt, ok := <-req.Inner:
			if !ok {
				return nil
			}
			// 内层地址：内层 ip 层已注入 spec 值；down 帧交换（legacy gre
			// inSrc/inDst 交换语义——内层 ip 层生成器不按方向交换，隧道层
			// 是内层地址的换向点）。
			innerSrc, innerDst := pkt.L3.SrcIP, pkt.L3.DstIP
			if pkt.Direction == "down" {
				innerSrc, innerDst = innerDst, innerSrc
			}
			// 内层 IPv4 地址必须有效：链路径只支持 IPv4-over-GRE（builder
			// writeGRE 的 ProtocolType 0x0800 意味着内层是裸 IPv4 包）。
			if net.ParseIP(innerSrc).To4() == nil || net.ParseIP(innerDst).To4() == nil {
				return fmt.Errorf("gre generator: inner IPv4 addresses required (got %q/%q); IPv6-over-GRE not supported by the layer chain yet",
					innerSrc, innerDst)
			}
			// 内层 TCP 配置：从内层包 L4 拷贝（seq/ack/flags/window 已由 tcp
			// 层生成器推进）。无 TCP 选项（链层无注入路径）。
			var innerTCP *core.TCPConfig
			if pkt.L4.Protocol == "tcp" {
				innerTCP = &core.TCPConfig{
					Seq:         pkt.L4.Seq,
					Ack:         pkt.L4.Ack,
					Flags:       pkt.L4.Flags,
					WindowSize:  pkt.L4.WindowSize,
				}
			}
			// 完整内层 IP 包（20B 头 + L4，校验和完整）——legacy
			// buildInnerIPv4Packet 同款。内层 L4 proto 由内层包 L4.Protocol
			// 决定（tcp=6 / udp=17）。
			inner := buildInnerIPv4Packet(innerSrc, innerDst, innerProtoFor(pkt),
				pkt.L4.SrcPort, pkt.L4.DstPort, uint8(DefaultInnerTTL), pkt.Payload,
				uint16(innerIPID), innerTCP, nil)
			innerIPID++
			// 每帧 wire GRE 配置：K/C/S 位 + 自增 Sequence（legacy
			// cfg.Sequence + i 语义；链默认基值 0）。
			greCfg := core.GREConfig{
				ProtocolType:    core.EtherTypeIPv4,
				Checksum:        checksum,
				KeyPresent:      key != 0,
				Key:             key,
				SequencePresent: sequence,
				Sequence:        sequenceNum,
			}
			if sequence {
				sequenceNum++
			}
			out := core.PacketConfig{
				Direction: pkt.Direction,
				L2: core.L2Config{
					GRE: &greCfg,
				},
				L3: core.L3Config{
					Protocol: core.ProtocolGRE,
				},
				Payload: inner,
			}
			// 流级字段透传：外层 ip 层生成器覆盖 src/dst/ttl/dscp 等，finalEmit
			// 回填 FlowID/PacketIndex/Timestamp——隧道层不重复装配。L4 必须为
			// 空（builder validateGREConfig 拒绝非空 L4）。
			if err := req.Emit(out); err != nil {
				return err
			}
		}
	}
}

// innerProtoFor resolves the inner IP protocol number from the inner
// packet's L4 protocol (tcp=6 / udp=17)。
func innerProtoFor(pkt core.PacketConfig) uint8 {
	if pkt.L4.Protocol == "udp" {
		return 17
	}
	return 6
}

// greConfigUint32 reads a numeric layer config field (schema V9 已保证类型
// 合法，这里只做防御性转换：JSON 数字经解码以 float64 到达)。
func greConfigUint32(cfg map[string]interface{}, key string) uint32 {
	switch n := cfg[key].(type) {
	case float64:
		return uint32(n)
	case int64:
		return uint32(n)
	}
	return 0
}

// greConfigBool reads a boolean layer config field.
func greConfigBool(cfg map[string]interface{}, key string) bool {
	b, ok := cfg[key].(bool)
	return ok && b
}

func init() {
	// 反向注册 gre 隧道层生成器工厂（layers 包不依赖 gre 包；注册后
	// BuildLayersPlanner("gre", ...) 的 newGenerator 可实例化 gre 层）。
	layers.RegisterLayerGenerator("gre", func() (layers.LayerGenerator, error) {
		return &GREGenerator{}, nil
	})
}
