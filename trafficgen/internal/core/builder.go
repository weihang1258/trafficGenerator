// Package core provides core functionality.
package core

import (
	"encoding/binary"
	"fmt"
	"go.uber.org/zap"
	"hash/crc32"
	"math"
	"net"
)

const (
	EtherTypeIPv4  = 0x0800
	EtherTypeARP   = 0x0806
	EtherTypeGOOSE = 0x88B8
	EtherTypeSV    = 0x88BA
	EtherTypeIPv6  = 0x86DD
	EtherTypeISIS  = 0x8870

	// PPPoE EtherTypes (RFC 2516 §4). The Ethernet EtherType selects the
	// PPPoE stage: 0x8863 = Discovery (PADI/PADO/PADR/PADS/PADT), 0x8864 =
	// Session Data (carries PPP frames). The builder forces these when
	// L2Config.PPPoE is set, regardless of L2Config.EtherType.
	EtherTypePPPoEDiscovery = 0x8863
	EtherTypePPPoESession   = 0x8864

	// PPP Protocol field values (RFC 1661 §5, the 2-byte field following the
	// PPPoE header in Session Data frames). 0x0021 = IPv4 (the builder writes
	// the L3/L4 from L3Config/L4Config after it); the LCP/IPCP/PAP/CHAP
	// values carry PPP control messages in Payload with no L3/L4.
	PPPProtocolIPv4 = 0x0021
	PPPProtocolLCP  = 0xc021
	PPPProtocolIPCP = 0x8021
	PPPProtocolPAP  = 0xc023
	PPPProtocolCHAP = 0xc223

	// PPPoE code field values (RFC 2516 §5).
	PPPoECodeSessionData = 0x00
	PPPoECodePADI        = 0x09
	PPPoECodePADO        = 0x07
	PPPoECodePADR        = 0x19
	PPPoECodePADS        = 0x65
	PPPoECodePADT        = 0xa7

	// PPPoEHeaderLen is the fixed PPPoE session header size in bytes
	// (RFC 2516 §4): Ver(4)+Type(4)=1 byte, Code=1 byte, SessionID=2 bytes,
	// Payload_Length=2 bytes. It sits between the Ethernet header (with
	// optional VLAN) and the PPP frame. Discovery frames carry TLV tags in
	// the payload after this header; Session Data frames carry the 2-byte
	// PPP Protocol field + PPP information bytes after it.
	PPPoEHeaderLen = 6

	ProtocolICMP   = 1
	ProtocolTCP    = 6
	ProtocolUDP    = 17
	ProtocolSCTP   = 132
	ProtocolICMPv6 = 58
	ProtocolIGMP   = 2
	ProtocolOSPF   = 89
	ProtocolPIM    = 103

	// ProtocolGRE is the IP protocol number for GRE encapsulation
	// (RFC 2784 §4: "GRE packets are encapsulated in IP datagrams" with
	// protocol number 47). The outer IP header of a GRE frame must carry
	// this value — the builder rejects any other protocol with GRE enabled.
	ProtocolGRE = 47

	// GREHeaderLen is the fixed GRE base header size in bytes (RFC 2784
	// §2): Flags(1) + Version(1) + Protocol Type(2). Each C/R/K/S option
	// field adds 4 bytes (RFC 2890: Checksum+Reserved, Routing, Key,
	// Sequence Number).
	GREHeaderLen = 4

	// GRE header flag bits (RFC 2784 §2 / RFC 2890).
	GREFlagChecksum = 0x8000 // C: Checksum Present
	GREFlagRouting  = 0x4000 // R: Routing Present
	GREFlagKey      = 0x2000 // K: Key Present (RFC 2890)
	GREFlagSequence = 0x1000 // S: Sequence Number Present (RFC 2890)

	// MPLS EtherTypes (RFC 3032 §3.10): 0x8847 = MPLS unicast, 0x8848 =
	// MPLS multicast. The builder forces one of these when L2Config.MPLS
	// is set, regardless of L2Config.EtherType (which still selects the
	// INNER L3 layout — the label stack is a shim between L2 and L3).
	EtherTypeMPLSUnicast   = 0x8847
	EtherTypeMPLSMulticast = 0x8848

	// MPLSLabelEntryLen is the size of one MPLS label stack entry in bytes
	// (RFC 3032 §3.1): Label(20 bits) + TC(3 bits) + S(1 bit) + TTL(8
	// bits) = 32 bits, network byte order. The label stack sits between
	// the Ethernet header (with optional VLAN) and the inner L3 header.
	MPLSLabelEntryLen = 4

	// DefaultMPLSTTL is the MPLS TTL written when an entry's TTL is 0
	// (RFC 3032 §3.1 has no default; 64 matches the IP TTL default used
	// by writeL3v4).
	DefaultMPLSTTL = 64

	// IPv6HeaderLen is the fixed IPv6 header length in bytes (RFC 8200 §3).
	// Extension headers are NOT included — they are carried in Payload when
	// present and the planner sets the Next Header field to chain them.
	IPv6HeaderLen = 40

	// MinEthernetFrame is the minimum Ethernet frame size in bytes (excluding
	// the 4-byte FCS) per IEEE 802.3. Frames shorter than this are padded
	// with zero bytes after the L3/L4 payload. The padding is NOT counted in
	// the IP total-length field (RFC 894 §1: "The data field is padded to a
	// minimum of 60 octets") so receivers strip it based on IP total length.
	MinEthernetFrame = 60
)

// EtherTypeFor returns the Ethernet EtherType field for the given source IP:
// EtherTypeIPv6 (0x86DD) for IPv6 addresses, EtherTypeIPv4 (0x0800) for IPv4
// addresses or anything unparseable (the historical default — every planner
// used to hardcode 0x0800, so a parse failure stays on IPv4 rather than
// silently emitting a malformed IPv6 frame).
//
// Planners that previously hardcoded EtherTypeIPv4 should call this with
// spec.SrcIP (or the reply's swapped SrcIP) so a FlowSpec using IPv6
// addresses produces an IPv6 EtherType and the builder's writeL3v6 path.
func EtherTypeFor(srcIP string) uint16 {
	parsed := net.ParseIP(srcIP)
	if parsed == nil {
		return EtherTypeIPv4
	}
	if parsed.To4() == nil {
		return EtherTypeIPv6
	}
	return EtherTypeIPv4
}

// Builder builds binary packets from PacketConfig.
type Builder struct{}

// NewBuilder creates a new packet builder.
func NewBuilder() *Builder {
	return &Builder{}
}

// L3Base builds an L3Config with the common L3 fields plus the flow-level
// DSCP/ECN/IPFlags/FragOffset carried on spec. srcIP/dstIP are passed explicitly
// so reply packets can swap them. Legacy spec.TOS (whole-byte) overrides
// DSCP/ECN when set, for backward compatibility with old configs.
// Planners use this instead of inlining L3Config{} at every packet site.
//
// Defaulting (DF=1, DSCP=0x2E, MACs, etc.) is owned by mapToFlowSpec via
// presence-check helpers. L3Base passes spec.IPFlags through unchanged so an
// explicit user choice of ip_flags=0 (no DF, allow fragmentation) is honored
// end-to-end. Code paths that construct FlowSpec directly (bypassing
// mapToFlowSpec) must set spec.IPFlags explicitly if they want DF=1.
func L3Base(srcIP, dstIP string, protocol uint8, ttl uint8, ipid uint16, spec FlowSpec) L3Config {
	l3 := L3Config{
		SrcIP:      srcIP,
		DstIP:      dstIP,
		Protocol:   protocol,
		TTL:        ttl,
		IPID:       ipid,
		DSCP:       spec.DSCP,
		ECN:        spec.ECN,
		Flags:      spec.IPFlags,
		FragOffset: spec.FragOffset,
		HopByHop:   spec.HopByHop,
	}
	if spec.TOS != 0 {
		l3.DSCP = spec.TOS >> 2
		l3.ECN = spec.TOS & 0x03
	}
	return l3
}

// Build builds a binary packet from a PacketConfig. It allocates a single
// buffer sized for the whole packet and writes each layer directly at its
// offset, avoiding the per-layer temporary allocations of a bottom-up build.
func (b *Builder) Build(config PacketConfig) ([]byte, error) {
	l4Len := l4Length(config)
	// Resolve the L3 EtherType to decide which header layout to emit.
	// EtherType 0 means "default to IPv4" (see writeL2). ARP (0x0806) and
	// other L2 protocols carry their payload directly after the Ethernet
	// header — writing any L3 header would shift the payload and corrupt
	// the packet.
	effectiveEtherType := config.L2.EtherType
	if effectiveEtherType == 0 {
		effectiveEtherType = EtherTypeIPv4
	}
	// MPLS is a shim between L2 and L3: the EtherType on the wire is
	// 0x8847/0x8848 (forced by writeL2), so a config that carries that
	// value must resolve the INNER L3 layout — default to IPv4 (the
	// historical default), like EtherType 0. Any other value (0x0800/
	// 0x86DD) already selects the inner L3 directly; non-IP values are
	// rejected by validateMPLSConfig.
	if config.L2.MPLS != nil &&
		(effectiveEtherType == EtherTypeMPLSUnicast || effectiveEtherType == EtherTypeMPLSMulticast) {
		effectiveEtherType = EtherTypeIPv4
	}
	l3Len := 0
	switch effectiveEtherType {
	case EtherTypeIPv4:
		l3Len = 20
	case EtherTypeIPv6:
		l3Len = IPv6HeaderLen
	}
	l2Len := 14
	if config.L2.LLC != nil {
		// IEEE 802.3 length + 802.2 LLC header (DSAP/SSAP/Control) that
		// follows the Ethernet header: Eth(14) + LLC(3). The PDU is the
		// Payload starting at offset 17.
		l2Len = 17
	}
	if config.L2.VLAN != nil {
		l2Len = 18
	}

	// PPPoE encapsulation (RFC 2516 §4): when L2Config.PPPoE is set, the
	// 6-byte PPPoE header sits between the Ethernet header (with optional
	// VLAN) and the PPP frame. The builder forces the EtherType to 0x8863
	// (Discovery) or 0x8864 (Session Data), ignoring L2Config.EtherType.
	// Session Data frames carry the 2-byte PPP Protocol field right after
	// the PPPoE header; the inner L3/L4 follow only when the PPP protocol
	// is IPv4 (0x0021, or 0 = default). Discovery frames carry TLV tags in
	// Payload (serialized from DiscoveryTags) — no PPP Protocol field, no
	// L3/L4. Contradictory configs are rejected here rather than emitting
	// a corrupt frame.
	pppoe := config.L2.PPPoE
	var pppoeTagBytes []byte
	if pppoe != nil {
		if err := validatePPPoEConfig(pppoe, config, effectiveEtherType); err != nil {
			return nil, err
		}
		l2Len += PPPoEHeaderLen
		if pppoe.Code == PPPoECodeSessionData {
			l2Len += 2 // PPP Protocol field (RFC 1661 §5)
			if pppoe.PPPProtocol == 0 || pppoe.PPPProtocol == PPPProtocolIPv4 {
				l3Len = 20 // inner IPv4 (RFC 1661 §6)
			} else {
				l3Len = 0 // LCP/IPCP/PAP/CHAP: PPP control message in Payload
			}
		} else {
			l3Len = 0 // Discovery: tag TLVs only
			if len(pppoe.DiscoveryTags) > 0 {
				pppoeTagBytes = serializePPPoETags(pppoe.DiscoveryTags)
			}
		}
	}
	payloadBytes := config.Payload
	if pppoeTagBytes != nil {
		payloadBytes = pppoeTagBytes
	}

	// IPv6 hop-by-hop extension header (RFC 8200 §4.3): when an option list
	// is present it grows the L3 region — the fixed header's PayloadLength
	// field must cover it and its NextHeader becomes 0x00, chaining to the
	// extension header whose own NextHeader carries the real protocol. IPv4
	// frames and PPPoE's IPv4-only inner layer are rejected here rather than
	// emitting a corrupt frame.
	hbhoLen := 0
	if len(config.L3.HopByHop) > 0 {
		if err := validateHopByHopConfig(config.L3.HopByHop, effectiveEtherType, pppoe != nil); err != nil {
			return nil, err
		}
		hbhoLen = hopByHopHeaderLen(config.L3.HopByHop)
		l3Len += hbhoLen
	}

	// SRv6 Segment Routing Header (RFC 8754): when L3Config.SRH is set, the
	// SRH is inserted between the IPv6 fixed header (or after HopByHop if
	// present) and the inner L4 payload. The IPv6 fixed header's NH=43
	// chains to the SRH, whose own NextHeader carries the inner protocol.
	// SRH requires IPv6 (validated via EtherType). The core builder does not
	// compute the L4 pseudo-header's checksum itself; the planner must
	// deliver L4 with a valid checksum (pseudo-header DstIP = final
	// destination = SegmentList[0], RFC 8200 §8.1, design §3.1).
	srhLen := 0
	if config.L3.SRH != nil {
		if err := validateSRHConfig(config.L3.SRH, effectiveEtherType, pppoe != nil, len(config.L3.HopByHop) > 0); err != nil {
			return nil, err
		}
		srhLen = srhHeaderLen(config.L3.SRH)
		l3Len += srhLen
	}

	// GRE encapsulation (RFC 2784/2890): when L2Config.GRE is set, the GRE
	// header (4-byte base + 4 bytes per C/R/K/S option field, RFC 2890)
	// sits between the outer IP header and the inner payload, and the
	// outer IP total-length field must cover it. The inner packet (IPv4/
	// IPv6 + TCP/UDP with checksums, or ARP) is carried verbatim in
	// Payload — the builder never interprets it, so l4Len stays 0 and
	// writeL4 is not called (validateGREConfig rejects a non-empty
	// L4Config). Contradictory configs are rejected here rather than
	// emitting a corrupt frame.
	gre := config.L2.GRE
	greLen := 0
	if gre != nil {
		if err := validateGREConfig(gre, config, effectiveEtherType); err != nil {
			return nil, err
		}
		greLen = greHeaderLen(gre)
		l3Len += greLen
	}

	// MPLS label stack (RFC 3031/3032): when L2Config.MPLS is set, one
	// 4-byte entry per stack level sits between the Ethernet header (with
	// optional VLAN) and the inner L3 header. The stack is counted in
	// l2Len (it precedes the IP header, so it is NOT covered by the IP
	// total-length field), the EtherType on the wire is forced to 0x8847/
	// 0x8848 by writeL2, and the inner L3/L4 are written normally after
	// the stack — the IP checksum and total length behave exactly as for
	// an unlabeled packet. Contradictory configs (MPLS+GRE, MPLS+PPPoE,
	// a non-IP inner layer, an invalid stack) are rejected here rather
	// than emitting a corrupt frame.
	mpls := config.L2.MPLS
	if mpls != nil {
		if err := validateMPLSConfig(mpls, config, effectiveEtherType); err != nil {
			return nil, err
		}
		l2Len += MPLSLabelEntryLen * len(mpls.Labels)
	}
	total := l2Len + l3Len + l4Len + len(payloadBytes)

	// Ethernet padding: pad short frames to MinEthernetFrame (60 bytes,
	// excluding FCS) so real NICs don't reject them. L2Config.Pad controls
	// the behavior — nil or *true pads, *false skips. Padding bytes are
	// zero-filled and appended AFTER the L3/L4 payload; IP total length
	// reflects only the real payload so receivers strip padding correctly.
	// For PPPoE the padding is also NOT counted in the PPPoE Payload_Length
	// field — RFC 2516 §4 defines that field as the PPP frame size only.
	if shouldPad(config.L2.Pad) && total < MinEthernetFrame {
		total = MinEthernetFrame
	}

	// PPPoE Payload_Length (RFC 2516 §4) counts the bytes after the 6-byte
	// PPPoE header: 2-byte PPP Protocol + inner L3/L4/payload for Session
	// Data, or the tag TLV bytes for Discovery. Ethernet padding is never
	// counted. PayloadLength > 0 overrides the computed value verbatim —
	// users may craft intentionally wrong lengths to test DUT handling.
	var pppoePayloadLen uint16
	if pppoe != nil {
		pl := len(payloadBytes)
		if pppoe.Code == PPPoECodeSessionData {
			pl += 2 + l3Len + l4Len
		}
		if pppoe.PayloadLength > 0 {
			pppoePayloadLen = pppoe.PayloadLength
		} else {
			if pl > math.MaxUint16 {
				return nil, fmt.Errorf("pppoe: payload length %d exceeds 65535 (16-bit Payload_Length field, RFC 2516 §4)", pl)
			}
			pppoePayloadLen = uint16(pl)
		}
	}

	packet := make([]byte, total)
	l2End := l2Len
	l3End := l2End + l3Len
	l4End := l3End + l4Len

	// ipLen is the outer IP header size (without the GRE header). When GRE
	// is enabled, l3Len = ipLen + greLen: writeL3 emits the outer IP
	// header into packet[l2End:l2End+ipLen] with its total-length field
	// covering GRE + inner payload, then writeGRE emits the GRE header
	// into packet[l2End+ipLen:l3End].
	ipLen := l3Len
	if gre != nil {
		ipLen -= greLen
	}

	// LLC length field = bytes after the 14-byte Ethernet header (802.2 LLC
	// header + PDU). For the isis LLC carrier l3Len/l4Len are 0, so this is
	// just len(payloadBytes).
	var llcPayloadLen uint16
	if config.L2.LLC != nil {
		// LLC(3) + PDU. When the payload is the complete LLC+PDU (l3/l4=0)
		// this equals len(payloadBytes); when L3/L4 follow (not the isis case)
		// the length must also cover them.
		llcPayloadLen = uint16(len(payloadBytes) + l3Len + l4Len)
	}

	b.writeL2(packet[0:l2End], config, pppoePayloadLen, llcPayloadLen)
	if l3Len > 0 {
		b.writeL3(packet[l2End:l2End+ipLen], config, l4Len+len(payloadBytes)+greLen+hbhoLen+srhLen)
		if greLen > 0 {
			b.writeGRE(packet[l2End+ipLen:l3End], config)
		}
	}
	// SRH (RFC 8754) sits right after the IPv6 fixed header (after HopByHop
	// if present) and before the inner L4 payload. writeL3v6 writes the IPv6
	// fixed header (40 bytes) plus the HopByHop extension header (hbhoLen)
	// into packet[l2End : l2End+40+hbhoLen]. The SRH byte region starts at
	// l2End+40+hbhoLen, NOT at l2End+ipLen — ipLen includes srhLen itself
	// (l3Len = 40 + hbhoLen + srhLen + greLen), so l2End+ipLen would point
	// PAST the SRH, corrupting the L4 region (H1).
	ipv6FixedLen := 0
	if effectiveEtherType == EtherTypeIPv6 {
		ipv6FixedLen = 40
	}
	if srhLen > 0 {
		srhStart := l2End + ipv6FixedLen + hbhoLen
		b.writeSRH(packet[srhStart:srhStart+srhLen], config.L3.SRH)
	}
	if l4Len > 0 {
		b.writeL4(packet[l3End:l4End], config)
	}
	copy(packet[l4End:], payloadBytes)

	// GRE checksum (RFC 2784 §3.1) is computed over the GRE header (with
	// the Checksum field zeroed) plus the payload, so it must be filled
	// AFTER the payload bytes are in place (like SCTP). The region ends
	// where the outer IP payload ends — Ethernet padding is excluded.
	if gre != nil && gre.Checksum {
		fillGREChecksum(packet, l2End+ipLen, l4End+len(payloadBytes))
	}
	// PPTP-GRE Payload Length (RFC 2637 §4.1) is the size of the payload
	// after the GRE header — likewise unknown until the payload is in
	// place, so it is filled after build like the GRE checksum.
	if gre != nil && gre.PPTP {
		fillPPTPGRE(packet, l2End+ipLen, l4End+len(payloadBytes))
	}

	// SCTP checksum (RFC 4960 §6.8) is computed over the entire SCTP
	// packet — common header + chunks — so it must be filled AFTER the
	// chunk bytes are in place. Other L4 protocols compute their
	// checksums inside writeL4() because their inputs (TCP pseudo-
	// header, UDP pseudo-header) are already available there.
	if config.L4.Protocol == "sctp" && l4Len > 0 {
		fillSCTPChecksum(packet, l3End)
	}

	return packet, nil
}

// validatePPPoEConfig rejects PPPoE configs that would produce corrupt
// frames instead of emitting them: unknown Code values (RFC 2516 §5), a
// Session Data frame that mixes a non-IPv4 PPP Protocol with L3/L4 config
// (the inner L3 here is IPv4-only, RFC 1661 §6), a Session Data frame with
// an IPv6-resolving EtherType (writeL3 would dispatch the 40-byte IPv6
// header into the 20-byte IPv4 inner slot), and Discovery frames that
// carry L3/L4 or both DiscoveryTags and a user Payload (a Discovery
// payload is a tag TLV list and nothing else, RFC 2516 §5.1).
func validatePPPoEConfig(pppoe *PPPoEConfig, config PacketConfig, effectiveEtherType uint16) error {
	switch pppoe.Code {
	case PPPoECodeSessionData, PPPoECodePADI, PPPoECodePADO, PPPoECodePADR, PPPoECodePADS, PPPoECodePADT:
		// ok
	default:
		return fmt.Errorf("pppoe: invalid code 0x%02x (RFC 2516 §5: 0x00 session data, 0x09 PADI, 0x07 PADO, 0x19 PADR, 0x65 PADS, 0xa7 PADT)", pppoe.Code)
	}
	hasL3L4 := config.L3.SrcIP != "" || config.L3.DstIP != "" || config.L4.Protocol != ""
	if pppoe.Code == PPPoECodeSessionData {
		if pppoe.PPPProtocol != 0 && pppoe.PPPProtocol != PPPProtocolIPv4 && hasL3L4 {
			return fmt.Errorf("pppoe: PPPProtocol 0x%04x carries PPP control bytes in Payload (no inner L3/L4); L3Config/L4Config must be empty", pppoe.PPPProtocol)
		}
		if effectiveEtherType == EtherTypeIPv6 {
			return fmt.Errorf("pppoe: session data carries an IPv4-only inner layer (RFC 1661 §6); the IPv6 EtherType 0x86DD cannot be used")
		}
		return nil
	}
	// Discovery frames: TLV tags only.
	if hasL3L4 {
		return fmt.Errorf("pppoe: discovery code 0x%02x carries TLV tags only (no inner L3/L4); L3Config/L4Config must be empty", pppoe.Code)
	}
	if len(pppoe.DiscoveryTags) > 0 && len(config.Payload) > 0 {
		return fmt.Errorf("pppoe: discovery frame carries both DiscoveryTags and Payload; the payload is the tag TLV list (RFC 2516 §5.1), set only one")
	}
	return nil
}

// serializePPPoETags encodes the Discovery tag TLV sequence (RFC 2516
// §5.1): Tag_Type(2) + Tag_Length(2) + Tag_Value, where Tag_Length counts
// the value bytes only (NOT the 4-byte TLV header).
func serializePPPoETags(tags []PPPoETag) []byte {
	var buf []byte
	for _, t := range tags {
		buf = binary.BigEndian.AppendUint16(buf, t.Type)
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(t.Value)))
		buf = append(buf, t.Value...)
	}
	return buf
}

// validateGREConfig rejects GRE configs that would produce corrupt frames
// instead of emitting them: GRE riding over a non-IP outer layer (RFC 2784
// §4: GRE is encapsulated in IP), an outer IP protocol other than 47
// (IPPROTO_GRE), a non-empty L4Config (the inner packet is carried
// entirely in Payload — an L4 header would sit between the GRE header and
// the inner packet and corrupt it), an unsupported inner ProtocolType, an
// invalid Routing length (RFC 2784 §2: the Routing field is at least 2
// bytes and a multiple of 2), and the PPPoE+GRE combination (both are
// encapsulations between the Ethernet and IP layers; their lengths would
// interleave ambiguously).
func validateGREConfig(gre *GREConfig, config PacketConfig, effectiveEtherType uint16) error {
	if config.L2.PPPoE != nil {
		return fmt.Errorf("gre: cannot combine GRE with PPPoE (both are encapsulations between the Ethernet and IP layers)")
	}
	switch effectiveEtherType {
	case EtherTypeIPv4, EtherTypeIPv6:
		// GRE rides inside IP (RFC 2784 §4).
	default:
		return fmt.Errorf("gre: outer layer must be IP (EtherType 0x0800/0x86DD), got 0x%04x", effectiveEtherType)
	}
	if config.L3.Protocol != ProtocolGRE {
		return fmt.Errorf("gre: outer IP protocol must be 47 (IPPROTO_GRE, RFC 2784 §4), got %d", config.L3.Protocol)
	}
	if config.L4.Protocol != "" {
		return fmt.Errorf("gre: the inner packet is carried entirely in Payload (no L4 header); L4Config.Protocol must be empty, got %q", config.L4.Protocol)
	}
	switch gre.ProtocolType {
	case 0, EtherTypeIPv4, EtherTypeARP, EtherTypeIPv6:
		// ok (0 = auto: defaulted to 0x0800 by writeGRE)
	default:
		return fmt.Errorf("gre: ProtocolType 0x%04x not in supported list (allowed: 0x0800 IPv4, 0x0806 ARP, 0x86DD IPv6, 0 = IPv4)", gre.ProtocolType)
	}
	// PPTP mode (RFC 2637 §4.1) redefines the GRE header: the flags word
	// carries K/S/A/Ver (the standard-mode option bits are reserved),
	// the Protocol Type is forced to 0x880B (PPP), and the Key field is
	// split into Payload Length + Call ID. Standard-mode options are
	// managed by the mode itself, so combining them with PPTP is a
	// contradiction rather than an omission.
	if gre.PPTP {
		if gre.Checksum {
			return fmt.Errorf("gre: PPTP mode (RFC 2637 §4.1) never sets the C bit; remove checksum")
		}
		if gre.RoutingPresent {
			return fmt.Errorf("gre: PPTP mode (RFC 2637 §4.1) never sets the R bit; remove routing")
		}
		if gre.KeyPresent || gre.SequencePresent {
			return fmt.Errorf("gre: PPTP mode (RFC 2637 §4.1) manages the K/S bits itself; remove key/sequence_present")
		}
		if gre.ProtocolType != 0 && gre.ProtocolType != 0x880B {
			return fmt.Errorf("gre: PPTP mode forces Protocol Type 0x880B (PPP, RFC 2637 §4.1), got 0x%04x", gre.ProtocolType)
		}
	}
	if gre.RoutingPresent && (len(gre.Routing) < 2 || len(gre.Routing)%2 != 0) {
		return fmt.Errorf("gre: Routing field must be at least 2 bytes and a multiple of 2 bytes (RFC 2784 §2), got %d bytes", len(gre.Routing))
	}
	return nil
}

// greHeaderLen returns the GRE header size in bytes for the config: the
// 4-byte base header (RFC 2784 §2) plus 4 bytes per enabled option field
// (RFC 2890: Checksum+Reserved, Routing, Key, Sequence Number). In PPTP
// mode (RFC 2637 §4.1) the header is the enhanced-GRE layout: 4-byte base
// (flags with K|S set, protocol 0x880B) + 4-byte Key (Payload Length +
// Call ID) + 4-byte Sequence Number, plus a 4-byte Acknowledgment Number
// when AckPresent (A bit) — 12 or 16 bytes total.
func greHeaderLen(gre *GREConfig) int {
	if gre.PPTP {
		n := 12 // base 4 + Key 4 + Sequence 4
		if gre.AckPresent {
			n += 4
		}
		return n
	}
	n := GREHeaderLen
	if gre.Checksum {
		n += 4
	}
	if gre.RoutingPresent {
		n += 2 + len(gre.Routing)
	}
	if gre.KeyPresent {
		n += 4
	}
	if gre.SequencePresent {
		n += 4
	}
	return n
}

// validateHopByHopConfig rejects hop-by-hop option lists that would produce
// corrupt frames: options on an IPv4 frame (the hop-by-hop header exists only
// in IPv6, RFC 8200 §4.3), inside PPPoE's IPv4-only inner layer (RFC 1661
// §6), an option whose Value exceeds the 8-bit Opt Data Len field (255
// maximum, RFC 8200 §4.2), or a total header length beyond the 8-bit
// HdrExtLen field's reach (RFC 8200 §4.3: header = 8 + 8*HdrExtLen octets,
// so 2048 maximum).
func validateHopByHopConfig(options []IPv6Option, etherType uint16, pppoeInner bool) error {
	if etherType != EtherTypeIPv6 {
		return fmt.Errorf("hop_by_hop: IPv6 extension header options require an IPv6 frame (EtherType 0x86DD, RFC 8200 §4.3), got 0x%04x", etherType)
	}
	if pppoeInner {
		return fmt.Errorf("hop_by_hop: PPPoE session data carries an IPv4-only inner layer (RFC 1661 §6); extension header options cannot be emitted")
	}
	for _, o := range options {
		if len(o.Value) > 255 {
			return fmt.Errorf("hop_by_hop: option type 0x%02x Value is %d bytes, exceeding the 8-bit Opt Data Len field (255 maximum, RFC 8200 §4.2)", o.Type, len(o.Value))
		}
	}
	if n := hopByHopHeaderLen(options); n > 2048 {
		return fmt.Errorf("hop_by_hop: serialized header length %d exceeds the 2048-octet maximum (8-bit HdrExtLen counts 8-octet units after the first 8, RFC 8200 §4.3)", n)
	}
	return nil
}

// hopByHopHeaderLen returns the serialized length of the IPv6 hop-by-hop
// extension header (RFC 8200 §4.3) for the option list: 2 fixed octets
// (NextHeader + HdrExtLen) + the options (Pad1 = 1 octet, all others =
// Type + Len + Value), padded with Pad1/PadN so the total is a multiple of
// 8 — HdrExtLen counts 8-octet units after the first 8, so an integral
// header keeps it exact.
func hopByHopHeaderLen(options []IPv6Option) int {
	n := 2
	for _, o := range options {
		if o.Type == 0x00 {
			n++ // Pad1 (RFC 8200 §4.2): a single Type octet, no Len/Value
			continue
		}
		n += 2 + len(o.Value)
	}
	return (n + 7) &^ 7
}

// serializeIPv6HopByHop encodes the hop-by-hop extension header (RFC 8200
// §4.3) into a new buffer: NextHeader + HdrExtLen + options, padded with
// Pad1 (0x00) / PadN (0x01) to a multiple of 8 octets. nextHeader is the
// protocol of the header that follows (e.g. 17 = UDP); the fixed IPv6
// header's NextHeader field is 0x00, pointing here (see writeL3v6). The
// output length matches hopByHopHeaderLen.
func serializeIPv6HopByHop(options []IPv6Option, nextHeader uint8) []byte {
	total := hopByHopHeaderLen(options)
	buf := make([]byte, total)
	buf[0] = nextHeader
	buf[1] = byte((total - 8) >> 3) // HdrExtLen: 8-octet units after the first 8
	off := 2
	for _, o := range options {
		if o.Type == 0x00 {
			buf[off] = 0x00 // Pad1
			off++
			continue
		}
		buf[off] = o.Type
		buf[off+1] = byte(len(o.Value)) // Opt Data Len = value octet count (RFC 8200 §4.2)
		copy(buf[off+2:], o.Value)
		off += 2 + len(o.Value)
	}
	for off < total {
		pad := total - off
		if pad == 1 {
			buf[off] = 0x00 // Pad1 pads a single octet
			off++
			continue
		}
		buf[off] = 0x01 // PadN: Opt Data Len = N-2 zero octets
		buf[off+1] = byte(pad - 2)
		off += pad
	}
	return buf
}

// srhHeaderLen returns the serialized SRH length (RFC 8754 §2): 8-byte
// fixed header + 16·len(SegmentList) + serialized TLV bytes (including auto
// Pad1/PadN for HMAC 8n alignment and tail alignment).
//
// The computation MUST stay equivalent to the srv6 package's
// srhTotalLen/computeHdrExtLen (internal/protocol/srv6/validate.go): the
// HMAC pre-padding offset is relative to the SRH start (fixed header 8 +
// 16·wire segments), NOT to the TLV area start — a 38-byte HMAC with a
// 16-byte prior TLV sits at offset 48 (8n aligned) and needs no pad, so the
// srv6 package and this function must both compute 8+16+16+38+2 = 80.
// Caller must pass the WIRE segment count (already stripped for reduced).
func srhHeaderLen(srh *SRHConfig) int {
	tlvBytes := 0
	for _, t := range srh.TLV {
		// Handle HMAC 8n alignment (RFC 8754 §2.1.2) — pre-Pad1/PadN before HMAC.
		// 1 字节空缺用 Pad1，否则用 PadN。与 writeSRH 序列化逻辑保持一致。
		if t.Type == 5 {
			// Offset measured from the START of the SRH (fixed header +
			// segments + TLVs so far), matching srv6.serializedTLVLen which
			// accumulates from offset 0 = SRH start.
			offset := 8 + 16*len(srh.SegmentList) + tlvBytes
			if offset%8 != 0 {
				pad := 8 - offset%8
				if pad == 1 {
					tlvBytes += 1 // Pad1：1 字节
				} else {
					tlvBytes += pad // PadN：pad 字节（type+length+payload=2+pad-2=pad）
				}
			}
		}
		tlvBytes += 2 + len(t.Value)
	}
	// Tail alignment (RFC 8754 §2.1.1.1/.2): pad to 8n with Pad1 (1 byte)
	// or PadN (N≥2 bytes). The tail pad bytes are part of the serialized
	// header, so the returned total must include them (a previous version
	// returned the pre-pad total, mis-sizing the SRH whenever a tail pad
	// was needed — e.g. a 2-byte TLV after 1 segment).
	total := 8 + 16*len(srh.SegmentList) + tlvBytes
	if rem := total % 8; rem != 0 {
		total += 8 - rem
	}
	return total
}

// validateSRHConfig rejects SRH configs that would produce corrupt frames.
// It re-verifies HdrExtLen against the actual serialized length (design §7.7
// EXC-01 / §9.2): the planner computes HdrExtLen from the config, but a
// caller may hand the builder an SRHConfig whose HdrExtLen disagrees with
// what srhHeaderLen actually serializes (e.g. planner set HdrExtLen=6 but
// the config carries a 1-segment 24-byte SRH → (24/8)-1 = 2 ≠ 6). Rejecting
// here (before frame allocation) surfaces the mismatch as a build error
// instead of emitting a corrupt frame.
func validateSRHConfig(srh *SRHConfig, etherType uint16, pppoe bool, hasHBH bool) error {
	if etherType != EtherTypeIPv6 {
		return fmt.Errorf("srh: SRH requires IPv6 (EtherType 0x%04x, want 0x86DD)", etherType)
	}
	if pppoe {
		return fmt.Errorf("srh: SRH cannot combine with pppoe (pppoe inner is IPv4-only)")
	}
	// Flags MUST be 0x00 (RFC 8754 §2.1 all bits Unused, HMAC is in TLV).
	if srh.Flags != 0x00 {
		return fmt.Errorf("srh: flags must be 0 (RFC 8754 §2.1 all bits Unused, got 0x%02x)", srh.Flags)
	}
	// HdrExtLen must equal (serialized SRH length / 8) - 1. srhHeaderLen uses
	// the same HMAC pre-alignment and tail-alignment rules as the srv6
	// serializer, so an SRHConfig built by the planner always agrees; a
	// hand-crafted SRHConfig with a stale/mismatched HdrExtLen is rejected
	// (T-SRV6-EXC-01, T-SRV6-NEW-16).
	if len(srh.SegmentList) == 0 {
		// An SRH MUST carry at least one segment (RFC 8754 §2: SegmentsLeft /
		// Segment List). Hand-crafted configs with an empty SegmentList have
		// no defined wire layout — reject rather than emit a corrupt header.
		return fmt.Errorf("srh: SRH segment_list must not be empty")
	}
	if got := uint32(srhHeaderLen(srh)/8) - 1; got != uint32(srh.HdrExtLen) {
		return fmt.Errorf("srh: hdr_ext_len mismatch (config=%d, serialized=%d)", srh.HdrExtLen, got)
	}
	return nil
}

// writeSRH writes the SRH (RFC 8754 §2) into dst. Layout:
//
//	NH(1) + HdrExtLen(1) + RoutingType(1) + SegmentsLeft(1) +
//	LastEntry(1) + Flags(1) + Tag(2) + SegmentList(16·N) + TLVs.
//
// Users MUST NOT set Pad1 (Type=0) or PadN (Type=4) — the builder
// auto-inserts them for: (1) HMAC TLV 8n alignment (pre-PadN), and
// (2) tail alignment to 8n. HMAC TLV (Type=5) requires 8n offset (RFC
// 8754 §2.1.2). dst must be exactly srhHeaderLen(srh) bytes.
func (b *Builder) writeSRH(dst []byte, srh *SRHConfig) {
	// Fixed header (8 bytes).
	dst[0] = srh.NextHeader
	dst[1] = srh.HdrExtLen
	dst[2] = 0x04 // RoutingType = 4 (SRH, RFC 8754 §2)
	dst[3] = srh.SegmentsLeft
	dst[4] = srh.LastEntry
	dst[5] = srh.Flags
	binary.BigEndian.PutUint16(dst[6:8], srh.Tag)

	// SegmentList (16 bytes per entry, wire order).
	// len(srh.SegmentList) is bounded by validateSRHConfig (non-empty SRH)
	// and the builder's srhLen allocation, so off never runs past dst.
	off := 8
	for _, seg := range srh.SegmentList {
		copy(dst[off:off+16], seg[:])
		off += 16
	}

	// User TLVs (with auto Pad1/PadN for HMAC 8n alignment, RFC 8754 §2.1.2).
	// HMAC TLV (Type=5) MUST start at an 8n offset. When the offset before
	// HMAC is not 8n aligned, insert Pad1 (1 byte, type=0x00) for a 1-byte
	// gap or PadN (≥2 bytes, type=0x04) otherwise. RFC 8754 §2.1.1.1:
	// Pad1 MUST be used for single-octet padding — using PadN(0x04 0x00)
	// would be ambiguous with a zero-length PadN and is wrong.
	for _, t := range srh.TLV {
		if t.Type == 5 {
			if off%8 != 0 {
				pad := 8 - off%8
				if pad == 1 {
					dst[off] = 0x00 // Pad1：单字节填充
					off++
				} else {
					dst[off] = byte(0x04)      // PadN Type
					dst[off+1] = byte(pad) - 2 // PadN Length
					off += pad
				}
			}
		}
		// Guard against a TLV value that would overflow dst (hand-crafted
		// configs with a len(Value) > 255 mismatch between srhHeaderLen and
		// the TLV count are already caught by validateSRHConfig; this is a
		// belt-and-braces bounds check so a corrupt config cannot panic).
		if off+2 > len(dst) {
			return
		}
		dst[off] = t.Type
		dst[off+1] = byte(len(t.Value))
		copy(dst[off+2:], t.Value)
		off += 2 + len(t.Value)
	}

	// Tail alignment (pad to 8n with Pad1 or PadN).
	if rem := off % 8; rem != 0 {
		pad := 8 - rem
		if pad == 1 {
			dst[off] = 0x00 // Pad1
			off++
		} else {
			dst[off] = 0x04            // PadN
			dst[off+1] = byte(pad) - 2 // PadN Length（N≥2，Pad1 只用于单字节）
			off += pad
		}
	}
}

// writeGRE writes the GRE header (RFC 2784 §2 + RFC 2890) into dst, which
// sits right after the outer IP header. Layout: Flags+Version(2) +
// Protocol Type(2), then the option fields in the order Checksum+Reserved
// (C), Routing (R), Key (K), Sequence Number (S). The GRE checksum field
// is written as a zero placeholder and filled by fillGREChecksum after the
// payload is in place (the checksum covers the GRE header + payload, RFC
// 2784 §3.1). dst must be exactly greHeaderLen bytes.
//
// In PPTP mode (RFC 2637 §4.1) the header is the enhanced-GRE layout:
// flags 0x3081 (K|S|A set, version 1 — Wireshark identifies PPTP by the
// nonzero version), Protocol Type 0x880B (PPP), then the 4-byte Key field
// redefined as Payload Length (high 16, zero placeholder filled by
// fillPPTPGRE) + Call ID (low 16), then Sequence Number (4), then the
// Acknowledgment Number (4, when AckPresent).
func (b *Builder) writeGRE(dst []byte, config PacketConfig) {
	gre := config.L2.GRE
	if gre.PPTP {
		flags := uint16(0x2000 | 0x1000 | 0x0001) // K|S|Ver=1 (RFC 2637 §4.1)
		if gre.AckPresent {
			flags |= 0x0080 // A: Acknowledgment Number present (bit 8, not RFC 1701's bit 5)
		}
		binary.BigEndian.PutUint16(dst[0:2], flags)
		binary.BigEndian.PutUint16(dst[2:4], 0x880B) // Protocol Type = PPP (RFC 2637 §4.1)
		// Key field = Payload Length (high 16, filled after the payload is
		// in place) + Call ID (low 16, the peer's call id for mux/demux).
		binary.BigEndian.PutUint32(dst[4:8], uint32(gre.CallID))
		binary.BigEndian.PutUint32(dst[8:12], gre.Sequence)
		if gre.AckPresent {
			binary.BigEndian.PutUint32(dst[12:16], gre.Ack)
		}
		return
	}
	flags := uint16(0)
	if gre.Checksum {
		flags |= GREFlagChecksum
	}
	if gre.RoutingPresent {
		flags |= GREFlagRouting
	}
	if gre.KeyPresent {
		flags |= GREFlagKey
	}
	if gre.SequencePresent {
		flags |= GREFlagSequence
	}
	binary.BigEndian.PutUint16(dst[0:2], flags)
	protoType := gre.ProtocolType
	if protoType == 0 {
		protoType = EtherTypeIPv4
	}
	binary.BigEndian.PutUint16(dst[2:4], protoType)
	off := GREHeaderLen
	if gre.Checksum {
		// Checksum(2, zero placeholder) + Reserved(2) — RFC 2784 §2.
		binary.BigEndian.PutUint16(dst[off:off+2], 0)
		off += 4
	}
	if gre.RoutingPresent {
		// Routing Length(2, counting the length field itself) + routing
		// data — RFC 2784 §2 / RFC 1701 SRE length semantics.
		binary.BigEndian.PutUint16(dst[off:off+2], uint16(2+len(gre.Routing)))
		copy(dst[off+2:off+2+len(gre.Routing)], gre.Routing)
		off += 2 + len(gre.Routing)
	}
	if gre.KeyPresent {
		binary.BigEndian.PutUint32(dst[off:off+4], gre.Key)
		off += 4
	}
	if gre.SequencePresent {
		binary.BigEndian.PutUint32(dst[off:off+4], gre.Sequence)
		off += 4
	}
}

// fillGREChecksum computes and writes the GRE checksum (RFC 2784 §3.1)
// into packet[greStart+4:greStart+6]. The checksum is the 16-bit
// one's-complement sum of the GRE header (with the Checksum field zeroed)
// plus the payload, padded with zero octets to a 4-byte boundary. The
// padding is not transmitted and — being zero — does not change the sum,
// so the plain 16-bit word loop below is equivalent. A computed 0x0000 is
// transmitted as 0xFFFF (RFC 2784 §3.1: "If the checksum is calculated to
// be 0x0000, it must be transmitted as 0xFFFF"). end is the offset of the
// first byte after the GRE payload — the outer IP payload end, excluding
// Ethernet padding.
func fillGREChecksum(packet []byte, greStart, end int) {
	// Zero the checksum field before summing (RFC 2784 §3.1).
	binary.BigEndian.PutUint16(packet[greStart+4:greStart+6], 0)
	sum := uint32(0)
	for i := greStart; i+1 < end; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	if (end-greStart)%2 == 1 {
		sum += uint32(packet[end-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	cksum := ^uint16(sum)
	if cksum == 0 {
		cksum = 0xFFFF
	}
	binary.BigEndian.PutUint16(packet[greStart+4:greStart+6], cksum)
}

// fillPPTPGRE writes the Payload Length (RFC 2637 §4.1) into the high 16
// bits of the PPTP-GRE Key field at packet[greStart+4:greStart+6]. The
// value is the byte count of the payload following the GRE header —
// unknown until the payload is in place, so it is filled after build, like
// fillGREChecksum. end is the offset of the first byte after the payload
// (the outer IP payload end, excluding Ethernet padding).
//
// The header length is derived from the flags word instead of the config:
// base(4) + Key(4) + Sequence(4) are mandatory for PPTP data packets, and
// the Acknowledgment Number (4) follows when the A bit (0x0080) is set.
func fillPPTPGRE(packet []byte, greStart, end int) {
	headerLen := 12
	if binary.BigEndian.Uint16(packet[greStart:greStart+2])&0x0080 != 0 {
		headerLen += 4
	}
	payloadLen := end - greStart - headerLen
	binary.BigEndian.PutUint16(packet[greStart+4:greStart+6], uint16(payloadLen))
}

// shouldPad returns true unless the caller explicitly disabled padding via
// *false. nil (L2Config.Pad unset) and *true both pad — matching the
// default-ON behavior the user requested.
func shouldPad(p *bool) bool {
	if p == nil {
		return true
	}
	return *p
}

// l4Length returns the L4 header length in bytes for the config.
func l4Length(config PacketConfig) int {
	switch config.L4.Protocol {
	case "tcp":
		return 20 + len(encodeTCPOptions(config.L4.TCPOptions))
	case "udp":
		return 8
	case "sctp":
		// SCTP common header: SrcPort(2) + DstPort(2) + VerificationTag(4)
		// + Checksum(4) = 12 bytes. Chunks are carried in Payload (the
		// planner serializes DATA/INIT/INIT-ACK/COOKIE-ECHO/SHUTDOWN
		// chunks there), so the L4 header is the fixed 12-byte common
		// header only.
		return 12
	default:
		return 0 // icmp/arp: header data carried in payload
	}
}

// writeL2 writes the Ethernet header (with optional 802.1Q VLAN tag) into
// dst, followed by the 6-byte PPPoE header (RFC 2516 §4) and the 2-byte PPP
// Protocol field when PPPoE Session Data is enabled, and/or the MPLS label
// stack (RFC 3032 §3.1, 4 bytes per entry) when MPLS is enabled — in each
// case forcing the corresponding EtherType. pppoePayloadLen is the value for
// the PPPoE Payload_Length field, computed by Build (0 when PPPoE is
// disabled).
func (b *Builder) writeL2(dst []byte, config PacketConfig, pppoePayloadLen uint16, llcPayloadLen uint16) {
	dstMAC, err := net.ParseMAC(config.L2.DstMAC)
	if err != nil && config.L2.DstMAC != "" {
		zap.L().Warn("invalid dst MAC address", zap.String("mac", config.L2.DstMAC), zap.Error(err))
	}
	if len(dstMAC) == 6 {
		copy(dst[0:6], dstMAC)
	}
	srcMAC, err2 := net.ParseMAC(config.L2.SrcMAC)
	if err2 != nil && config.L2.SrcMAC != "" {
		zap.L().Warn("invalid src MAC address", zap.String("mac", config.L2.SrcMAC), zap.Error(err2))
	}
	if len(srcMAC) == 6 {
		copy(dst[6:12], srcMAC)
	}
	// LLC carrier (IEEE 802.3 + 802.2, IS-IS iso10589_llc): bytes 12-13 hold
	// the 802.3 Length field (LLC + PDU), NOT an EtherType; the LLC DSAP/
	// SSAP/Control header follows at bytes 14-16, and the PDU is the Payload.
	if config.L2.LLC != nil {
		binary.BigEndian.PutUint16(dst[12:14], llcPayloadLen)
		if len(dst) >= 17 {
			dst[14] = config.L2.LLC.DSAP
			dst[15] = config.L2.LLC.SSAP
			dst[16] = config.L2.LLC.Control
		}
		return
	}
	etherType := config.L2.EtherType
	if etherType == 0 {
		etherType = EtherTypeIPv4
	}
	// PPPoE forces the EtherType to the stage selector (RFC 2516 §4):
	// 0x8864 for Session Data, 0x8863 for Discovery — regardless of
	// L2Config.EtherType. The PPPoE header is written right after the
	// Ethernet header (offset 14, or 18 with VLAN).
	pppoeOff := 0
	if config.L2.PPPoE != nil {
		pppoeOff = 14
		if config.L2.VLAN != nil {
			pppoeOff = 18
		}
		if config.L2.PPPoE.Code == PPPoECodeSessionData {
			etherType = EtherTypePPPoESession
		} else {
			etherType = EtherTypePPPoEDiscovery
		}
	}
	// MPLS forces the EtherType to the label-switched-packet selector
	// (RFC 3032 §3.10): 0x8847 unicast, 0x8848 multicast (MPLSConfig.
	// Multicast) — regardless of L2Config.EtherType, which still selects
	// the INNER L3 layout. The label stack is written right after the
	// Ethernet header (offset 14, or 18 with VLAN).
	mplsOff := 0
	if config.L2.MPLS != nil {
		mplsOff = 14
		if config.L2.VLAN != nil {
			mplsOff = 18
		}
		if config.L2.MPLS.Multicast {
			etherType = EtherTypeMPLSMulticast
		} else {
			etherType = EtherTypeMPLSUnicast
		}
	}
	if config.L2.VLAN != nil {
		// [dstMAC(6)][srcMAC(6)][TPID 0x8100(2)][VLAN tag(2)][EtherType(2)]
		binary.BigEndian.PutUint16(dst[12:14], 0x8100)
		vlanTag := (uint16(config.L2.VLAN.Priority) << 13) | (config.L2.VLAN.ID & 0x0FFF)
		binary.BigEndian.PutUint16(dst[14:16], vlanTag)
		binary.BigEndian.PutUint16(dst[16:18], etherType)
	} else {
		binary.BigEndian.PutUint16(dst[12:14], etherType)
	}
	if config.L2.PPPoE != nil {
		// PPPoE header (RFC 2516 §4): Ver(4)+Type(4)=0x11 (1 byte) +
		// Code(1) + Session_ID(2) + Payload_Length(2).
		dst[pppoeOff] = 0x11
		dst[pppoeOff+1] = config.L2.PPPoE.Code
		binary.BigEndian.PutUint16(dst[pppoeOff+2:pppoeOff+4], config.L2.PPPoE.SessionID)
		binary.BigEndian.PutUint16(dst[pppoeOff+4:pppoeOff+6], pppoePayloadLen)
		if config.L2.PPPoE.Code == PPPoECodeSessionData {
			// 2-byte PPP Protocol field (RFC 1661 §5): 0x0021 = IPv4
			// (inner L3/L4 follows at the next layer), 0xc021 = LCP etc.
			// (the PPP control message is carried in Payload).
			pppProto := config.L2.PPPoE.PPPProtocol
			if pppProto == 0 {
				pppProto = PPPProtocolIPv4
			}
			binary.BigEndian.PutUint16(dst[pppoeOff+6:pppoeOff+8], pppProto)
		}
	}
	if config.L2.MPLS != nil {
		// MPLS label stack (RFC 3032 §3.1): one 4-byte entry per level,
		// top of stack first, each Label(20)|TC(3)|S(1)|TTL(8) big-endian.
		writeMPLSLabels(dst[mplsOff:mplsOff+MPLSLabelEntryLen*len(config.L2.MPLS.Labels)], config.L2.MPLS)
	}
}

// writeMPLSLabels serializes the MPLS label stack (RFC 3032 §3.1) into dst
// (exactly MPLSLabelEntryLen * len(Labels) bytes), top of stack first. The
// bottom entry (last in the slice) is always written with the S bit set —
// a user who left it unset (false) is auto-corrected so the stack is valid
// on the wire; an explicit S=true on a non-bottom entry is a contradiction
// already rejected by validateMPLSConfig. A TTL of 0 is written as 64
// (DefaultMPLSTTL), matching the IP TTL default.
func writeMPLSLabels(dst []byte, mpls *MPLSConfig) {
	for i, l := range mpls.Labels {
		s := l.S
		if i == len(mpls.Labels)-1 {
			s = true // bottom of stack (RFC 3032 §2.1) — auto-correct
		}
		ttl := l.TTL
		if ttl == 0 {
			ttl = DefaultMPLSTTL
		}
		entry := (l.Label & 0xFFFFF) << 12 // Label: 20 bits
		entry |= uint32(l.TC&0x07) << 9    // TC: 3 bits
		if s {
			entry |= 1 << 8 // S: 1 bit
		}
		entry |= uint32(ttl) // TTL: 8 bits
		binary.BigEndian.PutUint32(dst[i*MPLSLabelEntryLen:], entry)
	}
}

// validateMPLSConfig rejects MPLS configs that would produce corrupt frames
// instead of emitting them: an empty label stack (RFC 3032 §2.1: the stack
// is one or more entries), a label above 20 bits (0xFFFFF, RFC 3032 §3.1),
// a TC above 3 bits (7, RFC 5462), an explicit S=true on a non-bottom entry
// (the bottom of stack bit is only set on the last entry, RFC 3032 §2.1),
// a non-IP inner layer (the builder only writes IPv4/IPv6 headers after
// the stack), and the MPLS+GRE / MPLS+PPPoE combinations (all three are
// encapsulations between the Ethernet and IP layers; their lengths would
// interleave ambiguously).
func validateMPLSConfig(mpls *MPLSConfig, config PacketConfig, effectiveEtherType uint16) error {
	if config.L2.GRE != nil {
		return fmt.Errorf("mpls: cannot combine MPLS with GRE (both are encapsulations between the Ethernet and IP layers)")
	}
	if config.L2.PPPoE != nil {
		return fmt.Errorf("mpls: cannot combine MPLS with PPPoE (both are encapsulations between the Ethernet and IP layers)")
	}
	switch effectiveEtherType {
	case EtherTypeIPv4, EtherTypeIPv6:
		// The inner L3 is the flow's own IPv4/IPv6 packet (RFC 3032 §3.9).
	default:
		return fmt.Errorf("mpls: inner layer must be IP (EtherType 0x0800/0x86DD), got 0x%04x", effectiveEtherType)
	}
	if len(mpls.Labels) == 0 {
		return fmt.Errorf("mpls: label stack must contain at least one entry (RFC 3032 §2.1)")
	}
	for i, l := range mpls.Labels {
		if l.Label > 0xFFFFF {
			return fmt.Errorf("mpls: label %d (entry %d) exceeds 20 bits (max 0xFFFFF, RFC 3032 §3.1)", l.Label, i)
		}
		if l.TC > 7 {
			return fmt.Errorf("mpls: TC %d (entry %d) exceeds 3 bits (max 7, RFC 5462)", l.TC, i)
		}
		if l.S && i != len(mpls.Labels)-1 {
			return fmt.Errorf("mpls: S=true on entry %d but it is not the bottom of stack (only the last entry may set S, RFC 3032 §2.1)", i)
		}
	}
	return nil
}

// writeL3 writes the IP header into dst. IPv4 uses a 20-byte variable-header
// layout (IHL+TOS+TotalLen+IPID+Flags+FragOffset+TTL+Protocol+HeaderChecksum
// +SrcIP+DstIP); IPv6 uses a 40-byte fixed header (Version+TrafficClass+
// FlowLabel+PayloadLength+NextHeader+HopLimit+SrcIP+DstIP) per RFC 8200.
// The effective EtherType is resolved from L2.EtherType (0 → IPv4 default).
func (b *Builder) writeL3(dst []byte, config PacketConfig, payloadLen int) {
	effectiveEtherType := config.L2.EtherType
	if effectiveEtherType == 0 {
		effectiveEtherType = EtherTypeIPv4
	}
	if effectiveEtherType == EtherTypeIPv6 {
		b.writeL3v6(dst, config, payloadLen)
		return
	}
	b.writeL3v4(dst, config, payloadLen)
}

// writeL3v4 writes the IPv4 header into dst (see writeL3 for layout).
func (b *Builder) writeL3v4(dst []byte, config PacketConfig, payloadLen int) {
	dst[0] = 0x45 // Version 4, IHL 5
	dst[1] = (config.L3.DSCP << 2) | (config.L3.ECN & 0x03)
	binary.BigEndian.PutUint16(dst[2:4], uint16(20+payloadLen))

	ipID := config.L3.IPID
	if ipID == 0 {
		ipID = uint16(config.L4.Seq & 0xFFFF)
	}
	binary.BigEndian.PutUint16(dst[4:6], ipID)
	binary.BigEndian.PutUint16(dst[6:8], (uint16(config.L3.Flags)<<13)|(config.L3.FragOffset&0x1FFF))

	ttl := config.L3.TTL
	if ttl == 0 {
		ttl = 64
	}
	dst[8] = ttl
	dst[9] = config.L3.Protocol

	srcIP := net.ParseIP(config.L3.SrcIP)
	if srcIP == nil && config.L3.SrcIP != "" {
		zap.L().Warn("invalid src IP address", zap.String("ip", config.L3.SrcIP))
	}
	if srcIP != nil {
		srcIP = srcIP.To4()
		if len(srcIP) == 4 {
			copy(dst[12:16], srcIP)
		}
	}
	dstIP := net.ParseIP(config.L3.DstIP)
	if dstIP == nil && config.L3.DstIP != "" {
		zap.L().Warn("invalid dst IP address", zap.String("ip", config.L3.DstIP))
	}
	if dstIP != nil {
		dstIP = dstIP.To4()
		if len(dstIP) == 4 {
			copy(dst[16:20], dstIP)
		}
	}

	checksum := calculateIPChecksum(dst)
	binary.BigEndian.PutUint16(dst[10:12], checksum)
}

// writeL3v6 writes the 40-byte IPv6 header into dst per RFC 8200 §3.
// Layout: Version(4) + TrafficClass(8) + FlowLabel(20) | PayloadLength(16)
// + NextHeader(8) + HopLimit(8) + SrcIP(128) + DstIP(128).
//
// DSCP/ECN map into TrafficClass (same encoding as IPv4 TOS). Flags/
// FragOffset/IPID have no IPv6 equivalent — they stay on the FlowSpec but
// are not emitted (fragmentation in IPv6 is carried by the Fragment
// extension header, not the fixed header).
//
// When L3Config.HopByHop is set, the hop-by-hop extension header is
// serialized into dst[40:] (the caller sizes dst to 40 + extLen) and the
// fixed header's NextHeader becomes 0x00 chaining to it (RFC 8200 §3). The
// payloadLen argument must already include the extension header length —
// Build adds hbhoLen before calling.
//
// When L3Config.SRH is set, the SRH is serialized by Build() after the
// fixed header (and after HopByHop if present). Build() handles the
// dump-write of the SRH at the proper offset; this function only sets the
// IPv6 NextHeader to 43 (Routing) when SRH is present and HopByHop is
// absent, or leaves it at 0 (HopByHop) when both are present. The
// payloadLen argument must include the SRH length when SRH is present.
//
// IPv6 has no header checksum — integrity is protected by the L4 checksum
// with the pseudo-header (see calculateIPv6PseudoHeader).
func (b *Builder) writeL3v6(dst []byte, config PacketConfig, payloadLen int) {
	// Version(4)=6 + TrafficClass(8)=(DSCP<<2)|(ECN&0x03) + FlowLabel(20)=0
	// Pack into the first 4 bytes: 6xxxxxxx yyyyyyyy zzzzzzzz zzzzzzzz where
	// x = TrafficClass high bits, y = low bits, z = FlowLabel. Simplified:
	//   byte[0] = (6<<4) | (tc>>4)
	//   byte[1] = (tc<<4) | (flow>>16)
	//   byte[2] = flow >> 8
	//   byte[3] = flow
	tc := (config.L3.DSCP << 2) | (config.L3.ECN & 0x03)
	dst[0] = (6 << 4) | (tc >> 4)
	dst[1] = (tc << 4) | 0 // FlowLabel high bits = 0
	dst[2] = 0             // FlowLabel mid bits = 0
	dst[3] = 0             // FlowLabel low bits = 0

	binary.BigEndian.PutUint16(dst[4:6], uint16(payloadLen))
	hasHBH := len(config.L3.HopByHop) > 0
	hasSRH := config.L3.SRH != nil
	nextHeader := config.L3.Protocol
	switch {
	case hasHBH && hasSRH:
		// IPv6 NH=0 → HopByHop → SRH (NH=43) → inner L4.
		// HopByHop serialization sets its own NH = 43 (Routing) and the
		// SRH's NH = config.L3.SRH.NextHeader.
		nextHeader = 0x00
		ext := serializeIPv6HopByHop(config.L3.HopByHop, 0x2B) // 43 = Routing (SRH)
		copy(dst[40:40+len(ext)], ext)
	case hasHBH:
		nextHeader = 0x00
		ext := serializeIPv6HopByHop(config.L3.HopByHop, config.L3.Protocol)
		copy(dst[40:40+len(ext)], ext)
	case hasSRH:
		// IPv6 NH=43 → SRH (NH=inner protocol).
		nextHeader = 0x2B // 43 = Routing (SRH)
	}
	dst[6] = nextHeader // Next Header
	hopLimit := config.L3.TTL
	if hopLimit == 0 {
		hopLimit = 64
	}
	dst[7] = hopLimit

	// SrcIP (16 bytes at offset 8). net.ParseIP returns 16-byte for IPv6;
	// To16 returns the canonical form. Reject IPv4-mapped IPv6 here so the
	// caller gets zeroed bytes (matching IPv4 planner's behavior on invalid
	// input).
	srcIP := net.ParseIP(config.L3.SrcIP)
	if srcIP == nil && config.L3.SrcIP != "" {
		zap.L().Warn("invalid src IP address", zap.String("ip", config.L3.SrcIP))
	}
	if srcIP != nil {
		srcIP = srcIP.To16()
		if len(srcIP) == 16 && srcIP.To4() == nil {
			copy(dst[8:24], srcIP)
		}
	}
	dstIP := net.ParseIP(config.L3.DstIP)
	if dstIP == nil && config.L3.DstIP != "" {
		zap.L().Warn("invalid dst IP address", zap.String("ip", config.L3.DstIP))
	}
	if dstIP != nil {
		dstIP = dstIP.To16()
		if len(dstIP) == 16 && dstIP.To4() == nil {
			copy(dst[24:40], dstIP)
		}
	}
}

// writeL4 writes the L4 header (TCP/UDP) into dst. ICMP has no separate header
// (its data is in the payload). SCTP writes the 12-byte common header here;
// SCTP chunks are carried in the payload (the planner serializes them).
func (b *Builder) writeL4(dst []byte, config PacketConfig) {
	switch config.L4.Protocol {
	case "tcp":
		b.writeTCP(dst, config)
	case "udp":
		b.writeUDP(dst, config)
	case "sctp":
		b.writeSCTP(dst, config)
	}
}

// writeSCTP writes the 12-byte SCTP common header into dst. Chunks are
// serialized by the planner into PacketConfig.Payload and copied after
// this header by Build(). The checksum field is left at 0 here as a
// placeholder — Build() calls fillSCTPChecksum() once the chunks have
// been copied, since RFC 4960 §6.8 requires CRC32c over the ENTIRE SCTP
// packet (common header + all chunks). Computing it here would require
// the chunk bytes that are not yet in dst.
func (b *Builder) writeSCTP(dst []byte, config PacketConfig) {
	binary.BigEndian.PutUint16(dst[0:2], config.L4.SrcPort)
	binary.BigEndian.PutUint16(dst[2:4], config.L4.DstPort)
	binary.BigEndian.PutUint32(dst[4:8], config.L4.Ack) // VerificationTag reuses Ack field
	binary.BigEndian.PutUint32(dst[8:12], 0)            // Checksum placeholder (filled by fillSCTPChecksum)
}

// fillSCTPChecksum computes and writes the RFC 4960 §6.8 SCTP v-checksum
// (CRC32c, Castagnoli polynomial 0x1EDC6F41) into packet[l4Start+8:l4Start+12].
// The CRC is computed over the entire SCTP region (common header + chunks)
// with the checksum field zeroed — the standard SCTP checksum algorithm
// (RFC 4960 §6.8 step 3: "the CRC-32c is computed over ... the entire SCTP
// packet including the checksum field set to zero").
//
// Called from Build() after the chunk bytes have been copied into the
// packet. We must NOT use crc32.IEEE — that is the different polynomial
// used by Ethernet/FCS and would be rejected by every RFC 4960-compliant
// receiver.
func fillSCTPChecksum(packet []byte, l4Start int) {
	table := crc32.MakeTable(crc32.Castagnoli)
	// Zero checksum field before computing CRC32c (RFC 4960 §6.8).
	binary.BigEndian.PutUint32(packet[l4Start+8:l4Start+12], 0)
	sum := crc32.Checksum(packet[l4Start:], table)
	binary.BigEndian.PutUint32(packet[l4Start+8:l4Start+12], sum)
}

// writeTCP writes the TCP header (with options) into dst.
func (b *Builder) writeTCP(dst []byte, config PacketConfig) {
	opts := encodeTCPOptions(config.L4.TCPOptions)
	dataOffset := (20 + len(opts)) / 4

	binary.BigEndian.PutUint16(dst[0:2], config.L4.SrcPort)
	binary.BigEndian.PutUint16(dst[2:4], config.L4.DstPort)
	binary.BigEndian.PutUint32(dst[4:8], config.L4.Seq)
	binary.BigEndian.PutUint32(dst[8:12], config.L4.Ack)
	dst[12] = byte(dataOffset << 4)
	dst[13] = config.L4.Flags

	winSize := config.L4.WindowSize
	if winSize == 0 {
		winSize = 65535
	}
	binary.BigEndian.PutUint16(dst[14:16], winSize)
	binary.BigEndian.PutUint16(dst[18:20], 0) // urgent pointer
	copy(dst[20:], opts)

	// Checksum covers the full TCP header (incl options) + payload.
	checksum := calculateTCPChecksum(config, dst, config.Payload)
	binary.BigEndian.PutUint16(dst[16:18], checksum)
}

// writeUDP writes the UDP header into dst.
func (b *Builder) writeUDP(dst []byte, config PacketConfig) {
	binary.BigEndian.PutUint16(dst[0:2], config.L4.SrcPort)
	binary.BigEndian.PutUint16(dst[2:4], config.L4.DstPort)
	binary.BigEndian.PutUint16(dst[4:6], uint16(8+len(config.Payload)))
	checksum := uint16(0)
	disableChecksum, _ := config.Metadata["udp_disable_checksum"].(bool)
	srcIP := net.ParseIP(config.L3.SrcIP)
	dstIP := net.ParseIP(config.L3.DstIP)
	// Honor udp_disable_checksum for both IPv4 and IPv6. The previous IPv6
	// guard (To4() == nil) silently overrode the disable flag on IPv6 flows,
	// which contradicted RFC 6935/6936 (UDP checksum optional for both v4 and
	// v6 when L2 integrity check is present) and broke E2.5 regression. We
	// still require the IP strings to parse before calling the checksum
	// helper, since calculateUDPChecksum needs to build a pseudo-header.
	if !disableChecksum || srcIP == nil || dstIP == nil {
		checksum = calculateUDPChecksum(config, config.Payload)
	}
	binary.BigEndian.PutUint16(dst[6:8], checksum)
}

// encodeTCPOptions serializes TCP options and pads to a 4-byte boundary with
// NOP (Kind=1). Kind 0 (End) and Kind 1 (NOP) are single-byte options with no
// length field; all other kinds are encoded as Kind + Length(2+len(Data)) + Data.
func encodeTCPOptions(opts []TCPOption) []byte {
	var buf []byte
	for _, o := range opts {
		if o.Kind == TCPOptEnd || o.Kind == TCPOptNOP {
			buf = append(buf, o.Kind)
			continue
		}
		buf = append(buf, o.Kind)
		buf = append(buf, byte(2+len(o.Data))) // length includes kind + length byte
		buf = append(buf, o.Data...)
	}
	for len(buf)%4 != 0 {
		buf = append(buf, TCPOptNOP)
	}
	return buf
}

// calculateIPChecksum calculates the IP header checksum.
func calculateIPChecksum(header []byte) uint16 {
	sum := uint32(0)

	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	return ^uint16(sum)
}

// calculateTCPChecksum calculates the TCP checksum with pseudo-header.
// Handles both IPv4 (12-byte pseudo-header, RFC 793) and IPv6 (40-byte
// pseudo-header, RFC 8200 §8.1). The IPv6 path is needed when srcIP/dstIP
// are IPv6 addresses — without it, srcIP.To4() returns nil and the pseudo-
// header is zero-filled, producing a wrong checksum that IPv6 stacks drop.
func calculateTCPChecksum(config PacketConfig, header, payload []byte) uint16 {
	// Detect IPv6: if either IP parses as IPv6 (To4() == nil but To16() != nil),
	// use the IPv6 pseudo-header path.
	srcParsed := net.ParseIP(config.L3.SrcIP)
	dstParsed := net.ParseIP(config.L3.DstIP)
	isV6 := false
	if srcParsed != nil && dstParsed != nil {
		srcV4 := srcParsed.To4()
		dstV4 := dstParsed.To4()
		if (srcV4 == nil) && (dstV4 == nil) {
			isV6 = true
		}
	}

	var pseudoHeader []byte
	if isV6 {
		// IPv6 pseudo-header (40 bytes): SrcIP(16) + DstIP(16) + UpperLayerLen(4) + zero(3) + NextHeader(1)
		// C1 修复：当存在 SRH 时，伪头 DstIP 必须为最终目的地（wire SegmentList[0]），
		// 而非外层 IPv6 头部的 DstIP（reduced SRH 时外层 DstIP 是首段，不是最终目的地）。
		// RFC 8754 §6.2 + RFC 8200 §8.1。
		upperLen := len(header) + len(payload)
		pseudoDst := pseudoDestIPv6(config)
		pseudoHeader = calculateIPv6PseudoHeader(config.L3.SrcIP, pseudoDst, upperLen, 6 /* TCP */)
		if pseudoHeader == nil {
			// Fall back to zero pseudo-header (matches IPv4 invalid-IP behavior).
			pseudoHeader = make([]byte, 40)
		}
	} else {
		// IPv4 pseudo-header (12 bytes): SrcIP(4) + DstIP(4) + zero(1) + Protocol(1) + TCP-len(2)
		pseudoHeader = make([]byte, 12)
		if srcParsed != nil {
			if v4 := srcParsed.To4(); len(v4) == 4 {
				copy(pseudoHeader[0:4], v4)
			}
		} else if config.L3.SrcIP != "" {
			zap.L().Warn("invalid src IP address", zap.String("ip", config.L3.SrcIP))
		}
		if dstParsed != nil {
			if v4 := dstParsed.To4(); len(v4) == 4 {
				copy(pseudoHeader[4:8], v4)
			}
		} else if config.L3.DstIP != "" {
			zap.L().Warn("invalid dst IP address", zap.String("ip", config.L3.DstIP))
		}
		pseudoHeader[8] = 0
		pseudoHeader[9] = 6 // TCP
		tcpLen := uint16(len(header) + len(payload))
		binary.BigEndian.PutUint16(pseudoHeader[10:12], tcpLen)
	}

	// Calculate checksum
	sum := uint32(0)

	// Pseudo-header
	for i := 0; i < len(pseudoHeader); i += 2 {
		if i+2 <= len(pseudoHeader) {
			sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i : i+2]))
		}
	}

	// TCP header (with checksum = 0)
	for i := 0; i < len(header); i += 2 {
		if i == 16 {
			continue // Skip checksum field
		}
		if i+2 <= len(header) {
			sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
		}
	}

	// Payload
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	if len(payload)%2 == 1 {
		sum += uint32(payload[len(payload)-1]) << 8
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	return ^uint16(sum)
}

// calculateUDPChecksum calculates the UDP checksum with pseudo-header.
// Handles both IPv4 (12-byte pseudo-header, RFC 768) and IPv6 (40-byte
// pseudo-header, RFC 8200 §8.1). IPv6 UDP MUST NOT have a zero checksum
// (RFC 6936 §2) — unlike IPv4 where 0 means "no checksum" — so when the
// computed checksum is 0 on IPv6, we emit 0xFFFF (per RFC 768 §4.1).
func calculateUDPChecksum(config PacketConfig, payload []byte) uint16 {
	srcParsed := net.ParseIP(config.L3.SrcIP)
	dstParsed := net.ParseIP(config.L3.DstIP)
	isV6 := false
	if srcParsed != nil && dstParsed != nil {
		if (srcParsed.To4() == nil) && (dstParsed.To4() == nil) {
			isV6 = true
		}
	}

	udpLen := uint16(8 + len(payload))

	var pseudoHeader []byte
	if isV6 {
		// IPv6 pseudo-header (40 bytes). NextHeader=17 (UDP).
		// C1 修复：当存在 SRH 时，伪头 DstIP 必须为最终目的地（wire SegmentList[0]），
		// 而非外层 IPv6 头部的 DstIP。RFC 8754 §6.2 + RFC 8200 §8.1。
		pseudoDst := pseudoDestIPv6(config)
		pseudoHeader = calculateIPv6PseudoHeader(config.L3.SrcIP, pseudoDst, int(udpLen), 17 /* UDP */)
		if pseudoHeader == nil {
			pseudoHeader = make([]byte, 40)
		}
	} else {
		// IPv4 pseudo-header (12 bytes)
		pseudoHeader = make([]byte, 12)
		if srcParsed != nil {
			if v4 := srcParsed.To4(); len(v4) == 4 {
				copy(pseudoHeader[0:4], v4)
			}
		} else if config.L3.SrcIP != "" {
			zap.L().Warn("invalid src IP address", zap.String("ip", config.L3.SrcIP))
		}
		if dstParsed != nil {
			if v4 := dstParsed.To4(); len(v4) == 4 {
				copy(pseudoHeader[4:8], v4)
			}
		} else if config.L3.DstIP != "" {
			zap.L().Warn("invalid dst IP address", zap.String("ip", config.L3.DstIP))
		}
		pseudoHeader[8] = 0
		pseudoHeader[9] = 17 // UDP
		binary.BigEndian.PutUint16(pseudoHeader[10:12], udpLen)
	}

	// Calculate checksum
	sum := uint32(0)

	// Pseudo-header
	for i := 0; i < len(pseudoHeader); i += 2 {
		if i+2 <= len(pseudoHeader) {
			sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i : i+2]))
		}
	}

	// UDP header fields: src_port(2) + dst_port(2) + length(2) + checksum(2).
	// The UDP header's own length field (at UDP offset 4-5) is a SEPARATE
	// field from the pseudo-header's length — both must be in the sum per
	// RFC 768 (IPv4) and RFC 8200 §8.1 (IPv6). The pseudo-header length
	// was already added by the loop above; now add the UDP header fields.
	// (The checksum field at offset 6-7 is zeroed during computation.)
	sum += uint32(config.L4.SrcPort)
	sum += uint32(config.L4.DstPort)
	sum += uint32(udpLen) // UDP header's own length field

	// Payload
	for i := 0; i < len(payload)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[i : i+2]))
	}
	if len(payload)%2 == 1 {
		sum += uint32(payload[len(payload)-1]) << 8
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)

	result := ^uint16(sum)
	// RFC 768 §4.1: "If the computed checksum is zero, it is transmitted as
	// all ones". A zero on the wire is indistinguishable from "no checksum"
	// (RFC 768: "the transmitted checksum is 0 means the sender generated no
	// checksum"), which makes real checksum verification impossible — tshark
	// reports status 3 (Not present). Applies to IPv4 and IPv6 alike; IPv6
	// additionally forbids zero checksums outright (RFC 6936 §2).
	if result == 0 {
		result = 0xFFFF
	}
	return result
}

// pseudoDestIPv6 返回 IPv6 L4 伪头应使用的 DstIP 字符串。
//
// 当 L3Config.SRH 非空时，伪头 DstIP 必须是最终目的地（即 wire SegmentList[0]），
// 而非外层 IPv6 头部的 DstIP。原因：reduced SRH 下外层 DstIP 是首段（被剥离出去的
// 那个），不是最终目的地；非 reduced SRH 下外层 DstIP 虽然也是最终目的地，但
// RFC 8754 §6.2 仍要求伪头按"最终目的地"语义计算。两种情况下 wire SegmentList[0]
// 都是最终目的地。RFC 8754 §6.2 + RFC 8200 §8.1。
//
// 无 SRH 时直接返回 config.L3.DstIP（外层 DstIP 即真实目的地）。
func pseudoDestIPv6(config PacketConfig) string {
	if config.L3.SRH != nil && len(config.L3.SRH.SegmentList) > 0 {
		// wire SegmentList[0] = 用户列表最后一个 = 最终目的地
		return net.IP(config.L3.SRH.SegmentList[0][:]).String()
	}
	return config.L3.DstIP
}

// calculateIPv6PseudoHeader returns the 40-byte IPv6 pseudo-header used by
// ICMPv6/TCP/UDP checksums over IPv6 (RFC 8200 §8.1). Layout:
//
//	SrcIP(16) + DstIP(16) + UpperLayerPacketLength(4) + zero(3) + NextHeader(1)
//
// UpperLayerPacketLength is the L4 length (header + payload) — same value
// the L4 writes into its own Length field (TCP: implied via IP payload
// length; UDP: explicit; ICMPv6: the ICMPv6 message length, which is what
// callers pass here). NextHeader is the IPv6 protocol number (58 for
// ICMPv6, 6 for TCP, 17 for UDP).
//
// Returns nil when either IP is not a valid IPv6 address (To16()==nil or
// IPv4-mapped), signaling the caller to skip pseudo-header checksumming
// (which matches IPv4's behavior of zeroing the checksum field on invalid
// input rather than crashing).
func calculateIPv6PseudoHeader(srcIP, dstIP string, upperLayerLen int, nextHeader uint8) []byte {
	src := net.ParseIP(srcIP)
	if src == nil {
		return nil
	}
	src = src.To16()
	if src == nil || src.To4() != nil {
		return nil
	}
	dst := net.ParseIP(dstIP)
	if dst == nil {
		return nil
	}
	dst = dst.To16()
	if dst == nil || dst.To4() != nil {
		return nil
	}
	ph := make([]byte, 40)
	copy(ph[0:16], src)
	copy(ph[16:32], dst)
	binary.BigEndian.PutUint32(ph[32:36], uint32(upperLayerLen))
	ph[36] = 0
	ph[37] = 0
	ph[38] = 0
	ph[39] = nextHeader
	return ph
}

// CalculateIPv6PseudoHeader is the exported wrapper around
// calculateIPv6PseudoHeader for use by protocol planners (e.g. ICMPv6)
// that need to compute their own checksums without duplicating the
// pseudo-header layout.
func CalculateIPv6PseudoHeader(srcIP, dstIP string, upperLayerLen int, nextHeader uint8) []byte {
	return calculateIPv6PseudoHeader(srcIP, dstIP, upperLayerLen, nextHeader)
}
