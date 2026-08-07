// Planner emits SRv6 packet configs (RFC 8754 / RFC 8200 / RFC 8986).
//
// Each PacketConfig carries an IPv6 outer layer with the SRH metadata
// stored in Metadata ("srv6_*" keys per design §10.1). The actual
// IPv6+SRH bytes are assembled by the ResolvedConfig.BuildFrame helper
// (used by tests for byte-level verification; see planner_test.go).
//
// The planner fills defaults (SrcIPv6, DstIPv6, SegmentsLeft, LastEntry,
// Reduced, PayloadProtocol, Frames, Direction) — it does NOT mutate the
// caller's spec (validate_conventions.md §1.1).
package srv6

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner implements core.Planner for SRv6.
type Planner struct{}

// NewPlanner returns a new SRv6 planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name used by the registry.
func (p *Planner) Name() string { return "srv6" }

// Validate validates the SRv6 flow spec (delegates to package-level Validate).
func (p *Planner) Validate(spec core.FlowSpec) error { return Validate(spec) }

// Plan emits one PacketConfig per Frame. Every frame carries the SAME
// SegmentList/SegmentsLeft/DstIP — "视角递增" (per-frame SL-- / DstIP
// updates) is expressed by chaining multiple FlowSpecs, not by Frames.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := Validate(spec); err != nil {
		return nil, err
	}
	cfg := spec.SRv6

	// Resolve defaults.
	reduced := resolveReduced(cfg)
	segmentsLeft := resolveSegmentsLeft(cfg)
	lastEntry := resolveLastEntry(cfg, reduced)

	// Resolve SrcIPv6 / DstIPv6 with defaults.
	srcStr := cfg.SrcIPv6
	if srcStr == "" {
		srcStr = spec.SrcIP
	}
	if srcStr == "" {
		return nil, fmt.Errorf("srv6: src IPv6 required (spec.SrcIP or srv6.src_ipv6)")
	}
	if net.ParseIP(srcStr) == nil || net.ParseIP(srcStr).To4() != nil {
		return nil, fmt.Errorf("srv6: src IPv6 %q invalid", srcStr)
	}

	dstStr := cfg.DstIPv6
	if dstStr == "" {
		// Default: SegmentList[0] (user-facing first segment = first to
		// process; on wire, this sits at List[n-1] = highest index).
		dstStr = cfg.SegmentList[0]
	}

	// Reverse SegmentList for wire format. RFC 8754 §2: wire[0] = user[n-1]
	// (last segment, final destination), wire[n-1] = user[0] (first segment).
	// For reduced: skip user[0] (already in DstIP).
	userList := cfg.SegmentList
	wireCount := computeWireSegmentCount(len(userList), reduced)
	wireList := make([][]byte, 0, wireCount)
	n := len(userList)
	// Reduced: wire indices 0..n-2; user index for wire k = n-1-k.
	// Non-reduced: wire indices 0..n-1; user index for wire k = n-1-k.
	for wireIdx := 0; wireIdx < wireCount; wireIdx++ {
		userIdx := n - 1 - wireIdx
		ip := net.ParseIP(userList[userIdx])
		if ip == nil {
			return nil, fmt.Errorf("srv6: segment_list[%d] %q invalid", userIdx, userList[userIdx])
		}
		wireList = append(wireList, ip.To16())
	}

	// Payload protocol → NextHeader.
	// Default per design §5.3 S6 / DR-06: "" + spec.TCP != nil → "tcp";
	// otherwise "udp".
	nh := uint8(17) // UDP
	if cfg.PayloadProtocol == "" {
		if spec.TCP != nil {
			nh = 6 // TCP
		}
	} else {
		v, ok := payloadProtocolNextHeader[cfg.PayloadProtocol]
		if !ok {
			return nil, fmt.Errorf("srv6: unknown payload_protocol %q", cfg.PayloadProtocol)
		}
		nh = v
	}

	// Frames.
	frames := cfg.Frames
	if frames == 0 {
		frames = 1
	}

	// Direction.
	dir := cfg.Direction
	if dir == "" {
		dir = "up"
	}

	// Inner L4 ports: 0 → spec ports.
	innerSrcPort := cfg.InnerSrcPort
	if innerSrcPort == 0 {
		innerSrcPort = spec.SrcPort
	}
	innerDstPort := cfg.InnerDstPort
	if innerDstPort == 0 {
		innerDstPort = spec.DstPort
	}

	// Direction "down": swap MACs/IPs/ports and reverse SegmentList.
	srcMAC, dstMAC := spec.SrcMAC, spec.DstMAC
	effectiveSrc, effectiveDst := srcStr, dstStr
	if dir == "down" {
		srcMAC, dstMAC = dstMAC, srcMAC
		effectiveSrc, effectiveDst = effectiveDst, effectiveSrc
		innerSrcPort, innerDstPort = innerDstPort, innerSrcPort
		// Reverse wireList so DstIP = reversed List[n-1] = original List[0]
		// (original final destination).
		for l, r := 0, len(wireList)-1; l < r; l, r = l+1, r-1 {
			wireList[l], wireList[r] = wireList[r], wireList[l]
		}
		// Convert the reversed wireList[n-1] (16-byte big-endian) back to
		// IPv6 text form. string([]byte) would yield a 16-byte raw string
		// that net.ParseIP rejects, zeroing the IPv6 DstIP field.
		effectiveDst = net.IP(wireList[len(wireList)-1]).String()
	}

	// Compute HdrExtLen.
	tlvs := make([]SRv6TLV, len(cfg.TLV))
	copy(tlvs, cfg.TLV)
	hdrExtLen := uint8(computeHdrExtLen(len(cfg.SegmentList), reduced, tlvs))

	// Compute SRH total length (post tail-alignment, HMAC pre-alignment
	// aware; the serializer re-computes the exact value from the same
	// srhTotalLen source so the two can never diverge).
	wireSegCount := len(wireList)
	srhTotal := srhTotalLen(len(cfg.SegmentList), reduced, tlvs)

	// Inner payload (from InnerPayload or spec.Payload).
	innerPayload := cfg.InnerPayload
	if innerPayload == nil {
		innerPayload = spec.Payload
	}

	// M3-NEW (S16, RFC 4443 §4.1)：当 payload_protocol="icmpv6" 且 innerPayload
	// 为空、且用户未提供 spec.ICMPv6 配置时，planner 生成一条默认的 ICMPv6
	// Echo Request（Type=128, Code=0, Identifier=1, Sequence=1, Data="12345678"）。
	// 设计 §6.16 S16 HexDump 字段构成规定该校验和必须按 IPv6 伪头（DstIP=最终目的）
	// 计算。当 spec.ICMPv6 非空或用户已显式提供 innerPayload 时，按用户输入
	// 透传——不覆盖。
	//
	// 伪头 DstIP 选取：RFC 8200 §8.1 + 设计 §3.1 "L4 伪头 DstIP 规则"：
	// 包含 Routing Header 的 IPv6 包，L4 伪头 DstIP = final destination，
	// 而非外层 IPv6 头 DstIP（reduced SRH 下外层 DstIP 是首段）。最终目的
	// 即 wire SegmentList[0]：up 方向 = 用户列表最后一项（SR Policy 最后一段），
	// down 方向反转后 = 用户列表第一项（反转后流的最终目的）。此处在 down
	// 反转之后取 wireList[0]，与 builder 的 pseudoDestIPv6（TCP/UDP 校验和）
	// 语义完全一致，保证同包内 ICMPv6 校验和伪头与其他 L4 校验和一致。
	//
	// 实现说明：因约束"只修改 srv6 目录"，无法直接调用 icmpv6.buildICMPv6Payload
	// （包内未导出）。此处按 RFC 4443 §2.3 内联实现 ICMPv6 报文构造 + 伪头
	// 反码和校验和，逻辑与 internal/protocol/icmpv6/icmpv6.go buildICMPv6Payload
	// 等价。如未来 icmpv6 包导出 BuildICMPv6Payload，可改回直接复用以消除重复。
	if nh == 58 /* ICMPv6 */ && len(innerPayload) == 0 && spec.ICMPv6 == nil {
		// wireList[0] = 最终目的（RFC 8754 反序存储：wire[0] = SR Policy
		// 最后一段；down 反转后 wire[0] = 反转后流的最终目的）。
		pseudoDst := net.IP(wireList[0]).String()
		echoType := uint8(128) // Echo Request (RFC 4443 §4.1)
		echoCode := uint8(0)
		identifier := uint16(1)
		sequence := uint16(1)
		echoData := []byte("12345678") // 设计 §6.16 S16 规定 8 字节数据
		innerPayload = buildDefaultICMPv6Echo(effectiveSrc, pseudoDst,
			echoType, echoCode, identifier, sequence, echoData)
	}

	// FlowID = outer IPv6 SrcIP + DstIP + inner ports + inner protocol.
	// Inner protocol for FlowID is the L4 protocol number (6/17/58),
	// NOT NextHeader (which would include 41/4/59 for tunnel / no-next
	// types — those are NOT L4 protocols).
	flowIDProto := nh
	if flowIDProto == 41 || flowIDProto == 4 || flowIDProto == 59 {
		// ipv6 / ipv4 encapsulation or no-next: no inner L4.
		flowIDProto = 0
	}

	configChan := make(chan core.PacketConfig, 256)

	// Capture resolved values for the goroutine.
	resolved := &ResolvedConfig{
		SrcIPv6:      mustParseIPv6(effectiveSrc),
		DstIPv6:      mustParseIPv6(effectiveDst),
		SegmentsLeft: segmentsLeft,
		LastEntry:    lastEntry,
		Flags:        0,
		Tag:          cfg.Tag,
		SegmentList:  wireList,
		TLV:          tlvs,
		NextHeader:   nh,
		Reduced:      reduced,
		HdrExtLen:    hdrExtLen,
	}

	// HMAC metadata.
	hmacPresent := false
	var hmacKeyID uint32
	var hmacDBit bool
	var hmacTLVTotalLen uint16
	for _, t := range tlvs {
		if t.Type == hmacTLVType {
			hmacPresent = true
			// RFC 8754 §2.1.2: HMAC TLV total = Type(1) + Length(1) + Value.
			// Value = D(1bit)+RES(15bits)=2 bytes + Key ID(4 bytes) +
			// HMAC digest(8n bytes) = 6 + HMAC_len. So total = 2 + len(Value).
			hmacTLVTotalLen = uint16(2 + len(t.Value))
			if len(t.Value) >= 6 {
				hmacDBit = (t.Value[0] & 0x80) != 0
				hmacKeyID = uint32(t.Value[2])<<24 | uint32(t.Value[3])<<16 |
					uint32(t.Value[4])<<8 | uint32(t.Value[5])
			}
		}
	}

	go func() {
		defer close(configChan)
		// H3 修复：resolved.SrcIPv6/DstIPv6 是 16 字节 []byte，直接 %s 会得到
		// 原始字节串（FlowID 不可读且每次地址不同会破坏聚合）。必须用
		// net.IP([]byte).String() 转为规范 IPv6 文本格式。
		flowID := fmt.Sprintf("%s-%s-%d-%d-%d",
			net.IP(resolved.SrcIPv6).String(), net.IP(resolved.DstIPv6).String(),
			innerSrcPort, innerDstPort, flowIDProto)
		now := time.Now()

		for i := 0; i < frames; i++ {
			if err := ctx.Err(); err != nil {
				return
			}
			hopLimit := uint8(64)
			if i > 0 {
				// Compute in int before narrowing: uint8(64-65) would wrap
				// 64-65=-1 to 255 before the <1 check, breaking the wrap.
				v := int(64 - i)
				if v < 1 {
					// BND-06: after 0 the sequence wraps 1..255 (v1 wrap) —
					// 64,63,...,1,255,254,...,1,255,... never emitting 0.
					// Values below 1 map to the 1..255 range: -1→255,
					// -2→254, ..., -255→1, -256→255, ...
					// Go % keeps the dividend sign (-2%255=-2), so add 255.
					v = 1 + ((v-1)%255+255)%255
				}
				hopLimit = uint8(v)
			}

			md := map[string]interface{}{
				"srv6_seg_type":           cfg.SegType,
				"srv6_segments_left":      segmentsLeft,
				"srv6_last_entry":         lastEntry,
				"srv6_segment_count":      wireSegCount, // wire count (reduced → n-1)
				"srv6_policy_segments":    len(cfg.SegmentList),
				"srv6_reduced":            reduced,
				"srv6_hdr_ext_len":        hdrExtLen,
				"srv6_srh_total_len":      srhTotal,
				"srv6_dst_ipv6":           effectiveDst,
				"srv6_tag":                cfg.Tag,
				"srv6_flags":              0,
				"srv6_tlv_count":          len(tlvs),
				"srv6_hmac_present":       hmacPresent,
				"srv6_hmac_key_id":        hmacKeyID,
				"srv6_hmac_d_bit":         hmacDBit,
				"srv6_hmac_tlv_total_len": hmacTLVTotalLen,
				"srv6_frames":             frames,
				"srv6_direction":          dir,
				"srv6_payload_protocol":   cfg.PayloadProtocol,
				"srv6_inner_payload_len":  len(innerPayload),
			}

			l4 := core.L4Config{}
			switch nh {
			case 6: // TCP
				l4.Protocol = "tcp"
				l4.SrcPort = innerSrcPort
				l4.DstPort = innerDstPort
				if spec.TCP != nil {
					l4.Seq = spec.TCP.Seq
					l4.Ack = spec.TCP.Ack
					l4.Flags = spec.TCP.Flags
					l4.WindowSize = spec.TCP.WindowSize
				}
			case 17: // UDP
				l4.Protocol = "udp"
				l4.SrcPort = innerSrcPort
				l4.DstPort = innerDstPort
			case 58: // ICMPv6
				l4.Protocol = "icmpv6"
			}

			cfgOut := core.PacketConfig{
				Direction: dir,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeIPv6,
				},
				L3: core.L3Config{
					SrcIP:    effectiveSrc,
					DstIP:    effectiveDst,
					Protocol: 43, // IPv6 Routing extension header (SRH)
					TTL:      uint8(hopLimit),
					DSCP:     spec.DSCP,
					ECN:      spec.ECN,
					SRH:      resolved.toCoreSRH(),
					HopByHop: spec.HopByHop,
				},
				L4:       l4,
				Payload:  innerPayload,
				Metadata: md,
			}

			// Stamp FlowID and PacketIndex for the consumer.
			cfgOut.FlowID = flowID
			cfgOut.PacketIndex = uint64(i)
			cfgOut.Timestamp = now

			select {
			case configChan <- cfgOut:
			case <-ctx.Done():
				return
			}
		}
	}()

	return configChan, nil
}

// buildDefaultICMPv6Echo 构造一条完整的 ICMPv6 Echo 报文：
// Type(1) + Code(1) + Checksum(2) + Identifier(2) + Sequence(2) + Data，
// 校验和按 RFC 4443 §2.3 计算：IPv6 伪头（srcIP + dstIP + Upper-Layer
// Packet Length + Next Header=58）与报文本身（校验和字段按 0 参与计算）
// 的反码和。此实现与 internal/protocol/icmpv6 包内 buildICMPv6Payload
// 等价（因"只修改 srv6 目录"约束无法直接复用）。
//
// dstIP 必须是 SRv6 场景下的最终目的地址（SegmentList[0]），而非外层
// IPv6 DstIP（设计 §3.1 "L4 伪头 DstIP 规则"，RFC 8200 §8.1）。
func buildDefaultICMPv6Echo(srcIP, dstIP string, typ, code uint8, identifier, sequence uint16, data []byte) []byte {
	msg := make([]byte, 0, 8+len(data))
	msg = append(msg, typ, code, 0, 0) // 校验和占位，稍后回填
	msg = append(msg, byte(identifier>>8), byte(identifier))
	msg = append(msg, byte(sequence>>8), byte(sequence))
	msg = append(msg, data...)

	checksum := calculateICMPv6ChecksumLocal(srcIP, dstIP, msg)
	binary.BigEndian.PutUint16(msg[2:4], checksum)
	return msg
}

// calculateICMPv6ChecksumLocal 按 RFC 4443 §2.3 计算 ICMPv6 反码和校验和：
// IPv6 伪头（40 字节，core.CalculateIPv6PseudoHeader 导出）与 ICMPv6 报文
// （checksum 字段按 0 计）逐 16 位反码和取反。srcIP/dstIP 非 IPv6 时返回 0
// （与 icmpv6 包行为一致：非法输入校验和置 0 而不是崩溃）。
func calculateICMPv6ChecksumLocal(srcIP, dstIP string, msg []byte) uint16 {
	pseudo := core.CalculateIPv6PseudoHeader(srcIP, dstIP, len(msg), 58 /* ICMPv6 */)
	if pseudo == nil {
		return 0
	}
	sum := uint32(0)
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	// ICMPv6 报文：跳过字节 2-3（校验和字段，按 0 计）。
	for i := 0; i < len(msg); i += 2 {
		if i == 2 {
			continue
		}
		if i+2 <= len(msg) {
			sum += uint32(binary.BigEndian.Uint16(msg[i : i+2]))
		} else {
			sum += uint32(msg[i]) << 8
		}
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return ^uint16(sum)
}

// mustParseIPv6 parses an IPv6 string into 16 bytes. Returns zero-filled
// slice on parse failure (caller has already validated).
func mustParseIPv6(s string) []byte {
	ip := net.ParseIP(s)
	if ip == nil {
		return make([]byte, 16)
	}
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return make([]byte, 16)
	}
	return v6
}
