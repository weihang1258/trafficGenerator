package srv6

import (
	"fmt"
	"net"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Validate validates an SRv6 flow spec (read-only per validate_conventions.md
// §1.1: never mutate spec, never fill defaults — Plan handles defaults).
// Implements design §8.1 rules VR-01..VR-23.
func Validate(spec core.FlowSpec) error {
	if spec.SRv6 == nil {
		return fmt.Errorf("srv6: srv6 config is required")
	}
	cfg := spec.SRv6

	// VR-02: segment_list non-empty.
	if len(cfg.SegmentList) == 0 {
		return fmt.Errorf("srv6: segment_list must not be empty")
	}

	// VR-03: ≤ 127 (uint8 HdrExtLen limit).
	if len(cfg.SegmentList) > 127 {
		return fmt.Errorf("srv6: segment_list too large for 8-bit hdr_ext_len (max 127, got %d)", len(cfg.SegmentList))
	}

	// VR-04: each entry must be IPv6.
	for i, s := range cfg.SegmentList {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() != nil || len(ip.To16()) != 16 {
			return fmt.Errorf("srv6: segment_list[%d] must be IPv6 (got %q)", i, s)
		}
	}

	// VR-06: spec.SrcIP must be IPv6 (or empty for default).
	if spec.SrcIP != "" {
		ip := net.ParseIP(spec.SrcIP)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("srv6: spec.SrcIP %q is not IPv6 (srv6 requires IPv6)", spec.SrcIP)
		}
	}

	// VR-05: SrcIPv6 (if non-empty) must be IPv6.
	if cfg.SrcIPv6 != "" {
		ip := net.ParseIP(cfg.SrcIPv6)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("srv6: src_ipv6 %q is not IPv6", cfg.SrcIPv6)
		}
	}

	// VR-07: seg_type must be in supported list.
	if !supportedSegTypes[cfg.SegType] {
		return fmt.Errorf("srv6: unknown seg_type %q", cfg.SegType)
	}

	// VR-08: Flags must be 0x00.
	if cfg.Flags != 0x00 {
		return fmt.Errorf("srv6: flags must be 0 (RFC 8754 §2.1 all bits Unused, got 0x%02x)", cfg.Flags)
	}

	// Resolve SegmentsLeft / LastEntry to validate VR-09.
	segmentsLeft := resolveSegmentsLeft(cfg)
	reduced := resolveReduced(cfg)
	lastEntry := resolveLastEntry(cfg, reduced)

	// VR-15b: reduced SRH 要求 SegmentList 长度 n≥2（RFC 8754 §4.1.1）。
	// Reduced 模式剥离首段（S1 已在 DstIP 中），若 n=1 则剥离后 wire 列表为空，
	// 无法形成有效 SRH（HdrExtLen 至少 1 表示 8 字节固定头 + 0 段，但 SRH
	// 设计要求至少 1 段），且 SegmentsLeft=0 时无段可递减，语义无效。
	if reduced && len(cfg.SegmentList) < 2 {
		return fmt.Errorf("srv6: reduced SRH requires segment_list length >= 2 (RFC 8754 §4.1.1), got %d", len(cfg.SegmentList))
	}

	// VR-09: segments_left ≤ last_entry+1 (RFC 8754 §4.3.1.1 S10-S11).
	if int(segmentsLeft) > int(lastEntry)+1 {
		return fmt.Errorf("srv6: segments_left (%d) > last_entry+1 (%d)", segmentsLeft, lastEntry+1)
	}

	// VR-10..VR-15: TLV validation.
	for i, t := range cfg.TLV {
		if len(t.Value) > 255 {
			return fmt.Errorf("srv6: tlv[%d] value length %d exceeds 255 bytes", i, len(t.Value))
		}
		if autoInsertedTLVTypes[t.Type] {
			if t.Type == 0 {
				return fmt.Errorf("srv6: pad1 must not be set manually (builder auto-inserts)")
			}
			return fmt.Errorf("srv6: padN must not be set manually (builder auto-inserts)")
		}
		if reservedTLVTypes[t.Type] {
			return fmt.Errorf("srv6: reserved TLV type %d must not be set", t.Type)
		}
		// VR-13b (M1-NEW): HMAC TLV（Type=5）的 Value 长度必须为 6+8n
		// （n=1..4），即 D+RES(2) + Key ID(4) + HMAC digest(8/16/24/32) =
		// 14/22/30/38。RFC 8754 §2.1.2："HMAC: Keyed HMAC, in multiples of
		// 8 octets, at most 32 octets"；Length 字段 = Value 字节数，取值
		// 14/22/30/38（设计 §2.4.4 表）。其他长度在 wire 上无法构成合法
		// HMAC TLV，且会被接收端丢弃（RFC 8754 §2.1.2 对齐要求 8n）。
		if t.Type == hmacTLVType {
			valid := false
			for _, n := range []int{1, 2, 3, 4} {
				if len(t.Value) == 6+8*n {
					valid = true
					break
				}
			}
			if !valid {
				return fmt.Errorf("srv6: hmac tlv[%d] value length %d must be 14/22/30/38 (6+8n: D+RES(2)+KeyID(4)+HMAC(8n), RFC 8754 §2.1.2)", i, len(t.Value))
			}
		}
	}

	// VR-15: seg_type × inner_payload × payload_protocol constraints.
	// Resolve payload protocol for rule checks (use "" as "udp" by default).
	pp := cfg.PayloadProtocol
	if pp == "" {
		if spec.TCP != nil {
			pp = "tcp"
		} else {
			pp = "udp"
		}
	}

	needsEncapsIPv6 := false
	needsEncapsIPv4 := false
	needsInner40 := false
	switch cfg.SegType {
	case "end.x":
		// VR-14: end.x requires explicit dst_mac.
		if spec.DstMAC == "" {
			return fmt.Errorf("srv6: end.x requires explicit dst_mac")
		}
	case "end.b6", "end.b6.encaps", "end.b6.encaps.red", "end.dx6", "end.dt6":
		needsEncapsIPv6 = true
		needsInner40 = true
		if cfg.SegType == "end.b6" && pp != "ipv6" {
			return fmt.Errorf("srv6: end.b6 requires payload_protocol=ipv6 (Next Header 41 per RFC 8986 §4.13), got %q", pp)
		}
		if cfg.SegType == "end.dx6" && pp != "ipv6" {
			return fmt.Errorf("srv6: end.dx6 requires payload_protocol=ipv6 (Next Header 41 per RFC 8986 §4.4), got %q", pp)
		}
		if cfg.SegType == "end.b6.encaps" && pp != "ipv6" {
			return fmt.Errorf("srv6: end.b6.encaps requires payload_protocol=ipv6 (Next Header 41 per RFC 8986 §4.13), got %q", pp)
		}
		if cfg.SegType == "end.b6.encaps.red" && pp != "ipv6" {
			return fmt.Errorf("srv6: end.b6.encaps.red requires payload_protocol=ipv6 (Next Header 41 per RFC 8986 §4.14), got %q", pp)
		}
		if cfg.SegType == "end.dt6" && pp != "ipv6" {
			return fmt.Errorf("srv6: end.dt6 requires payload_protocol=ipv6 (Next Header 41 per RFC 8986 §4.9), got %q", pp)
		}
	case "end.dx4", "end.dt4":
		needsEncapsIPv4 = true
		needsInner40 = true
		if cfg.SegType == "end.dx4" && pp != "ipv4" {
			return fmt.Errorf("srv6: end.dx4 requires payload_protocol=ipv4 (Next Header 4 per RFC 8986 §4.5), got %q", pp)
		}
		if cfg.SegType == "end.dt4" && pp != "ipv4" {
			return fmt.Errorf("srv6: end.dt4 requires payload_protocol=ipv4 (Next Header 4 per RFC 8986 §4.8), got %q", pp)
		}
	}
	// Suppress unused warnings (kept for clarity / future rule extensions).
	_ = needsEncapsIPv6
	_ = needsEncapsIPv4
	if needsInner40 && len(cfg.InnerPayload) < 40 {
		return fmt.Errorf("srv6: %s requires inner_payload >= 40 bytes (IPv6/IPv4 header)", cfg.SegType)
	}

	// VR-22: payload_protocol="none" + 非空 inner payload 禁止
	// （RFC 8200 §4.7 丢弃 NH=59 包）。M2-NEW：除 cfg.InnerPayload 外，
	// 还需检查 spec.Payload——planner 的 payload 解析链为
	// cfg.InnerPayload → spec.Payload（planner.go），若用户在顶层
	// spec.Payload 填了数据而 InnerPayload 为空，VR-22 原实现会放行，
	// 但 wire 上仍携带非空 payload（RFC 8200 §4.7 语义被破坏）。
	// 校验必须与实际发出的字节一致。
	if pp == "none" {
		innerLen := 0
		if cfg.InnerPayload != nil {
			innerLen = len(cfg.InnerPayload)
		} else {
			innerLen = len(spec.Payload)
		}
		if innerLen > 0 {
			return fmt.Errorf("srv6: payload_protocol=none with non-empty inner_payload not allowed (RFC 8200 §4.7: No Next Header packets discarded)")
		}
	}

	// VR-16/VR-17: MPLS / GRE mutual exclusion.
	if spec.MPLS != nil {
		return fmt.Errorf("srv6: srv6 cannot combine with mpls (v1 limitation)")
	}
	if spec.GRE != nil {
		return fmt.Errorf("srv6: srv6 cannot combine with gre (v1 limitation)")
	}

	// VR-18/19/20: HdrExtLen overflow.
	hdrExtLen := computeHdrExtLen(len(cfg.SegmentList), reduced, cfg.TLV)
	if hdrExtLen > 255 {
		return fmt.Errorf("srv6: hdr_ext_len overflow (max 255): got %d", hdrExtLen)
	}

	// VR-21: Frames >= 0.
	if cfg.Frames < 0 {
		return fmt.Errorf("srv6: frames must be >= 0 (got %d)", cfg.Frames)
	}

	// VR-23: Direction=down requires source-node view (SegmentsLeftPtr nil).
	if cfg.Direction == "down" && cfg.SegmentsLeftPtr != nil {
		return fmt.Errorf("srv6: direction=down requires source-node view (segments_left not set)")
	}

	return nil
}

// resolveSegmentsLeft returns SegmentsLeft from SegmentsLeftPtr or default
// (len(SegmentList)-1). Design §5.3 S4 / DR-03.
func resolveSegmentsLeft(cfg *SRv6Config) uint8 {
	if cfg.SegmentsLeftPtr != nil {
		return *cfg.SegmentsLeftPtr
	}
	if len(cfg.SegmentList) == 0 {
		return 0
	}
	return uint8(len(cfg.SegmentList) - 1)
}

// resolveReduced returns the effective Reduced flag (design §5.3 S11 /
// DR-11). Precedence: ReducedPtr (explicit user value — including an
// explicit false) > SegType default (true for "end.b6.encaps.red") >
// legacy Reduced bool for backward compatibility. ReducedPtr is populated
// by parseSRv6Config from the same "reduced" JSON key, so the legacy
// fallback only fires for programmatic construction that sets Reduced
// directly without ReducedPtr.
func resolveReduced(cfg *SRv6Config) bool {
	if cfg.ReducedPtr != nil {
		return *cfg.ReducedPtr
	}
	if cfg.SegType == "end.b6.encaps.red" {
		return true
	}
	return cfg.Reduced
}

// resolveLastEntry returns LastEntry from LastEntryPtr or default.
// non-reduced: len-1; reduced: len-2. Design §5.3 S5 / DR-04/05.
func resolveLastEntry(cfg *SRv6Config, reduced bool) uint8 {
	if cfg.LastEntryPtr != nil {
		return *cfg.LastEntryPtr
	}
	n := len(cfg.SegmentList)
	if n == 0 {
		return 0
	}
	if reduced {
		if n < 2 {
			return 0
		}
		return uint8(n - 2)
	}
	return uint8(n - 1)
}

// computeWireSegmentCount returns the number of Segment List entries on
// the wire: non-reduced = len(SegmentList); reduced = len-1.
func computeWireSegmentCount(n int, reduced bool) int {
	if reduced && n > 0 {
		return n - 1
	}
	return n
}

// padForHMACAlignment returns the number of pad bytes that must be inserted
// before a TLV starting at the given offset so that the next TLV begins at an
// 8n boundary (RFC 8754 §2.1.2 HMAC Alignment: 8n). Returns 0 when already
// aligned; a 1-byte gap is filled by Pad1 and a 2..7-byte gap by PadN
// (RFC 8754 §2.1.1.1/.2). serializeTLVs and serializedTLVLen MUST both use
// this function so the planner's HdrExtLen matches the serializer's bytes.
func padForHMACAlignment(offset int) int {
	if offset%8 == 0 {
		return 0
	}
	return 8 - offset%8
}

// serializedTLVLen returns the exact number of bytes serializeTLVs emits for
// the given TLV list: the user TLV bytes PLUS the Pad1/PadN bytes auto-
// inserted before an HMAC TLV to satisfy its 8n alignment requirement.
// It does NOT include the SRH tail padding — tail alignment is applied
// separately by srhTotalLen (which rounds the whole header to 8n).
func serializedTLVLen(tlvs []SRv6TLV) int {
	offset := 0
	for _, t := range tlvs {
		if t.Type == hmacTLVType {
			offset += padForHMACAlignment(offset)
		}
		offset += 2 + len(t.Value)
	}
	return offset
}

// srhTotalLen returns the on-the-wire SRH total length: 8 + 16*wireN +
// serialized TLV bytes (incl. HMAC pre-alignment pads) rounded up to the 8n
// boundary (the tail Pad1/PadN the serializer appends, RFC 8754 §2.1.1.1/.2).
func srhTotalLen(n int, reduced bool, tlvs []SRv6TLV) int {
	wireN := computeWireSegmentCount(n, reduced)
	total := 8 + 16*wireN + serializedTLVLen(tlvs)
	if rem := total % 8; rem != 0 {
		total += 8 - rem
	}
	return total
}

// computeHdrExtLen returns the Hdr Ext Len value (RFC 8200 §4.4):
// (total SRH length / 8) - 1 where total is the post-tail-aligned SRH length
// from srhTotalLen (HMAC pre-alignment padding included — this MUST agree
// with serializeTLVs, otherwise the builder rejects a hdr_ext_len mismatch).
func computeHdrExtLen(n int, reduced bool, tlvs []SRv6TLV) uint16 {
	return uint16(srhTotalLen(n, reduced, tlvs)/8) - 1
}
