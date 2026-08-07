package srv6

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/trafficgen/trafficgen/internal/core"
)

// SRH wire-format constants (RFC 8754 §2 / §2.1.1).
const (
	srhFixedHeaderLen = 8                  // NH(1)+HdrExtLen(1)+RoutingType(1)+SL(1)+LE(1)+Flags(1)+Tag(2)
	routingTypeSRH    = 4                  // SRH Routing Type (RFC 8754 §2)
	nextHeaderRoute   = 43                 // IPv6 Next Header = Routing (RFC 8200 §4.4)
	pad1Type          = 0                  // Pad1 TLV type (RFC 8754 §2.1.1.1)
	padNType          = 4                  // PadN TLV type (RFC 8754 §2.1.1.2)
	hmacTLVType       = 5                  // HMAC TLV type (RFC 8754 §2.1.2)
)

// ResolvedConfig is the planner-side SRH ready for the wire (already
// validated, defaults resolved). This is the builder's input.
type ResolvedConfig struct {
	SrcIPv6     []byte    // 16-byte big-endian
	DstIPv6     []byte    // 16-byte big-endian (source-node: = List[n-1])
	SegmentsLeft uint8    // wire value
	LastEntry    uint8    // wire value (n-1 or n-2)
	Flags        uint8    // 0x00 always
	Tag          uint16   // big-endian on wire
	SegmentList  [][]byte // wire order (reversed): [0]=last segment, [n-1]=first segment; reduced = n-1 entries
	TLV          []SRv6TLV // user TLVs (Pad1/PadN auto-inserted by serializer)
	NextHeader   uint8    // inner protocol (6/17/58/41/4/59)
	Reduced      bool     // true = reduced SRH (RFC 8754 §4.1.1)
	HdrExtLen    uint8    // computed by planner, re-verified by serializer
}

// toCoreSRH converts this resolved config into the core.SRHConfig that the
// core builder consumes (L3Config.SRH). Wire-format SegmentList is converted
// into the fixed-size [16]byte form. The builder serializes the SRH between
// the IPv6 fixed header and the inner L4 payload.
func (r *ResolvedConfig) toCoreSRH() *core.SRHConfig {
	segList := make([][16]byte, len(r.SegmentList))
	for i, seg := range r.SegmentList {
		if len(seg) == 16 {
			copy(segList[i][:], seg)
		}
	}
	tlvs := make([]core.SRv6TLV, len(r.TLV))
	for i, t := range r.TLV {
		tlvs[i] = core.SRv6TLV{Type: t.Type, Value: t.Value}
	}
	return &core.SRHConfig{
		NextHeader:   r.NextHeader,
		HdrExtLen:    r.HdrExtLen,
		SegmentsLeft: r.SegmentsLeft,
		LastEntry:    r.LastEntry,
		Flags:        r.Flags,
		Tag:          r.Tag,
		SegmentList:  segList,
		TLV:          tlvs,
		Reduced:      r.Reduced,
	}
}

// Resolve applies defaults and parses addresses. Returns the wire-ready
// config. Call Validate first (Resolve does NOT re-validate). It mirrors
// the planner's defaulting rules (design §5.3) — including the reduced
// resolution (resolveReduced), the HMAC-aware HdrExtLen computation and the
// 127-segment cap — so direct Resolve callers get byte-identical results to
// the Plan path. The tcpSet flag reflects whether the source FlowSpec.TCP
// was set; when true and PayloadProtocol is empty, NextHeader defaults to
// TCP (design §5.3 S6 / DR-06).
//
// Direction="down" (design §5.4 / §8.3 DD-01..DD-07) applies the same
// transforms as the planner: swap SrcIP/DstIP, reverse the wire SegmentList
// so DstIP = reversed List[n-1] = original List[0] (original final
// destination), swap MACs/ports. SegmentsLeft/LastEntry are left at their
// resolved values (validate's VR-23 already forced source-node view for
// down, so SegmentsLeftPtr was nil → SegmentsLeft = n-1).
func Resolve(spec *SRv6Config, srcIPFallback, dstIPFallback string, tcpSet bool) (*ResolvedConfig, error) {
	if spec == nil {
		return nil, fmt.Errorf("srv6: nil config")
	}
	if len(spec.SegmentList) == 0 {
		return nil, fmt.Errorf("srv6: segment_list must not be empty")
	}
	// Segment-count cap (VR-03): >127 entries cannot be expressed in the
	// 8-bit HdrExtLen. The planner's Plan path rejects this in Validate;
	// direct Resolve callers get the same error here.
	if len(spec.SegmentList) > 127 {
		return nil, fmt.Errorf("srv6: segment_list too large for 8-bit hdr_ext_len (max 127, got %d)", len(spec.SegmentList))
	}

	reduced := resolveReduced(spec)
	segmentsLeft := resolveSegmentsLeft(spec)
	lastEntry := resolveLastEntry(spec, reduced)

	// Parse user-facing SegmentList → wire reversed list.
	userList := spec.SegmentList
	wireCount := computeWireSegmentCount(len(userList), reduced)
	wireList := make([][]byte, 0, wireCount)
	// Wire layout: wire[0] = userList[n-1] (last segment, final destination),
	//              wire[n-1] = userList[0] (first segment).
	// For reduced: skip userList[0] = user index 0 (already in DstIP).
	n := len(userList)
	for wireIdx := 0; wireIdx < wireCount; wireIdx++ {
		userIdx := n - 1 - wireIdx
		ip := net.ParseIP(userList[userIdx])
		if ip == nil {
			return nil, fmt.Errorf("srv6: segment_list[%d] %q is not a valid IP", userIdx, userList[userIdx])
		}
		v6 := ip.To16()
		if v6 == nil || ip.To4() != nil {
			return nil, fmt.Errorf("srv6: segment_list[%d] %q is not IPv6", userIdx, userList[userIdx])
		}
		wireList = append(wireList, v6)
	}

	// Resolve SrcIPv6 / DstIPv6.
	srcStr := spec.SrcIPv6
	if srcStr == "" {
		srcStr = srcIPFallback
	}
	if srcStr == "" {
		return nil, fmt.Errorf("srv6: src IPv6 is required (spec.SrcIP or srv6.src_ipv6)")
	}
	srcIP := net.ParseIP(srcStr)
	if srcIP == nil || srcIP.To4() != nil {
		return nil, fmt.Errorf("srv6: src IPv6 %q invalid", srcStr)
	}

	dstStr := spec.DstIPv6
	if dstStr == "" {
		// Default: first segment = userList[0] (user-facing order) is FIRST.
		// On wire: userList[0] sits at wire index n-1 (= List[n-1]).
		dstStr = userList[0]
	}
	dstIP := net.ParseIP(dstStr)
	if dstIP == nil || dstIP.To4() != nil {
		return nil, fmt.Errorf("srv6: dst IPv6 %q invalid", dstStr)
	}

	// Direction "down" (design §5.4 / DD-01..DD-07): swap SrcIP/DstIP,
	// reverse the wire SegmentList, swap ports. The planner applies the same
	// transforms (planner.go) — keep them byte-identical so Resolve and Plan
	// produce the same ResolvedConfig for the same input.
	effectiveSrc, effectiveDst := srcStr, dstStr
	if spec.Direction == "down" {
		effectiveSrc, effectiveDst = effectiveDst, effectiveSrc
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

	// Resolve NextHeader.
	// Default per design §5.3 S6 / DR-06: "" + tcpSet → "tcp";
	// otherwise "udp".
	nh := uint8(17) // default UDP
	if spec.PayloadProtocol == "" {
		if tcpSet {
			nh = 6 // TCP
		}
	} else {
		v, ok := payloadProtocolNextHeader[spec.PayloadProtocol]
		if !ok {
			return nil, fmt.Errorf("srv6: unknown payload_protocol %q", spec.PayloadProtocol)
		}
		nh = v
	}

	// Copy user TLVs (no mutation of caller's slice).
	tlvs := make([]SRv6TLV, len(spec.TLV))
	copy(tlvs, spec.TLV)

	// Compute HdrExtLen (HMAC pre-alignment aware, same source as the
	// serializer and planner — see validate.go srhTotalLen).
	hdrExtLen := uint8(computeHdrExtLen(len(userList), reduced, tlvs))

	return &ResolvedConfig{
		SrcIPv6:      net.ParseIP(effectiveSrc).To16(),
		DstIPv6:      net.ParseIP(effectiveDst).To16(),
		SegmentsLeft: segmentsLeft,
		LastEntry:    lastEntry,
		Flags:        0, // design §5.1: always 0x00
		Tag:          spec.Tag,
		SegmentList:  wireList,
		TLV:          tlvs,
		NextHeader:   nh,
		Reduced:      reduced,
		HdrExtLen:    hdrExtLen,
	}, nil
}

// BuildFrame serializes the IPv6 header + SRH + payload into bytes. Returns
// the IPv6+SRH+payload bytes (Ethernet wrapping is the caller's job — this
// matches the design §6 HexDump convention where offset 0 = IPv6 byte 0).
//
// innerBytes is the L4/L7 payload AFTER the SRH (e.g. UDP header+data,
// TCP header+data, ICMPv6 Echo, raw IPv6 packet for End.DX6/B6 etc.).
//
// The L4 checksum, when present, MUST already be computed over the IPv6
// pseudo-header with DstIP = final destination = SegmentList[0] (RFC 8200
// §8.1, design §3.1 / BYT-13/14/22).
func (r *ResolvedConfig) BuildFrame(innerBytes []byte) ([]byte, error) {
	// Step 1: serialize user TLVs.
	userTLVBytes, err := serializeTLVs(r.TLV)
	if err != nil {
		return nil, err
	}

	// Step 2: serialize SRH fixed header (8 bytes) + SegmentList + TLVs.
	wireN := len(r.SegmentList)
	srhLen := srhFixedHeaderLen + 16*wireN + len(userTLVBytes)
	if rem := srhLen % 8; rem != 0 {
		// Tail padding per RFC 8754 §2.1.1.1/.2 (design §3.2.1):
		// need (8 - rem) bytes to reach the next 8n boundary.
		need := 8 - rem
		if need == 1 {
			// Pad1: single byte 0x00, no Length/Value
			// (RFC 8754 §2.1.1.1: "A single Pad1 TLV MUST be used when a
			// single byte of padding is required").
			userTLVBytes = append(userTLVBytes, pad1Type)
		} else {
			// PadN: Type(1) + Length(1) + (need-2) zero bytes = need bytes.
			padN := make([]byte, need)
			padN[0] = padNType
			padN[1] = uint8(need - 2)
			// PadN value bytes are already zero (Go zero-init).
			userTLVBytes = append(userTLVBytes, padN...)
		}
		srhLen = srhFixedHeaderLen + 16*wireN + len(userTLVBytes)
	}

	// Step 3: re-verify HdrExtLen matches planner's value.
	hdrExtLen := uint8(srhLen/8 - 1)
	if hdrExtLen != r.HdrExtLen {
		return nil, fmt.Errorf("srv6: hdr_ext_len mismatch (planner=%d, actual=%d)", r.HdrExtLen, hdrExtLen)
	}

	// Step 4: assemble.
	// Total IPv6 PayloadLength = SRH length + innerBytes length.
	totalPayload := srhLen + len(innerBytes)
	if totalPayload > 0xFFFF {
		return nil, fmt.Errorf("srv6: payload length %d exceeds uint16 max", totalPayload)
	}

	frame := make([]byte, 0, 40+srhLen+len(innerBytes))

	// IPv6 fixed header (40 bytes).
	ipv6 := make([]byte, 40)
	ipv6[0] = 0x60 // Version=6, TC high=0
	ipv6[1] = 0x00 // TC low=0, FlowLabel high=0
	ipv6[2] = 0x00 // FlowLabel mid
	ipv6[3] = 0x00 // FlowLabel low
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(totalPayload))
	ipv6[6] = nextHeaderRoute // IPv6 Next Header = 43 (Routing)
	ipv6[7] = 64             // HopLimit default
	copy(ipv6[8:24], r.SrcIPv6)
	copy(ipv6[24:40], r.DstIPv6)
	frame = append(frame, ipv6...)

	// SRH header (srhLen bytes).
	srh := make([]byte, srhLen)
	srh[0] = r.NextHeader
	srh[1] = hdrExtLen
	srh[2] = routingTypeSRH
	srh[3] = r.SegmentsLeft
	srh[4] = r.LastEntry
	srh[5] = r.Flags
	binary.BigEndian.PutUint16(srh[6:8], r.Tag)
	off := 8
	for _, seg := range r.SegmentList {
		copy(srh[off:off+16], seg)
		off += 16
	}
	copy(srh[off:], userTLVBytes)
	frame = append(frame, srh...)

	// Inner payload.
	frame = append(frame, innerBytes...)

	return frame, nil
}

// serializeTLVs writes the user TLVs (excluding Pad1/PadN auto-insertion),
// prepending Pad1/PadN when an HMAC TLV (Type=5) needs 8n alignment
// (RFC 8754 §2.1.2 "Alignment: 8n"). The padding bytes written here MUST
// match serializedTLVLen + padForHMACAlignment (validate.go) so the
// planner's HdrExtLen agrees with the serializer's bytes. Caller MUST NOT
// include Pad1/PadN; auto-insertion happens only at the END for tail padding
// (BuildFrame) and before HMAC TLVs (here).
func serializeTLVs(tlvs []SRv6TLV) ([]byte, error) {
	// Pre-compute total size to know offset of each TLV.
	offset := 0
	out := make([]byte, 0, 64)
	for _, t := range tlvs {
		switch t.Type {
		case 0, 4:
			return nil, fmt.Errorf("srv6: pad1/padN TLV must not be set by user")
		case 5:
			// HMAC: needs 8n alignment (RFC 8754 §2.1.2).
			if pad := padForHMACAlignment(offset); pad != 0 {
				if pad == 1 {
					// Pad1 (single 0x00 byte) for 1-byte padding
					// (RFC 8754 §2.1.1.1: "A single Pad1 TLV MUST be used
					// when a single byte of padding is required").
					out = append(out, pad1Type)
					offset++
				} else {
					// PadN: 1 + 1 + (N-2) bytes, where N = pad (2..7).
					padN := make([]byte, pad)
					padN[0] = padNType
					padN[1] = uint8(pad - 2)
					// PadN value bytes are already zero (Go zero-init).
					out = append(out, padN...)
					offset += len(padN)
				}
			}
		}
		if len(t.Value) > 255 {
			return nil, fmt.Errorf("srv6: TLV type %d value exceeds 255 bytes", t.Type)
		}
		out = append(out, t.Type)
		out = append(out, uint8(len(t.Value)))
		out = append(out, t.Value...)
		offset += 2 + len(t.Value)
	}
	return out, nil
}