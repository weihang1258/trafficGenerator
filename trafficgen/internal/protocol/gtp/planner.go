// Package gtp implements the GTPv1 (GPRS Tunneling Protocol, 通用分组无线
// 业务隧道协议, 3GPP TS 29.060 / TS 29.281) planner. GTP is a UDP
// application-layer protocol with two planes:
//
//	GTP-U (user plane, default port 2152): T-PDU messages (Type 0xFF)
//	    carry an inner IPv4/IPv6 packet — the tunnel's user traffic.
//	GTP-C (control plane, default port 2123): signaling messages (Echo
//	    Request 0x01, Create PDP Context Request 0x10, ...) carry
//	    Information Elements.
//
// The GTPv1 message header (TS 29.281 §5.1):
//
//	Flags(1) + Message Type(1) + Length(2) + TEID(4)
//	    + [Sequence(2) + N-PDU(1) + Next-Ext-Type(1)]  // iff E|S|PN set
//	    + [extension header(s)]                        // iff E set
//	    + payload (inner packet for T-PDU, IEs for GTP-C)
//
// Flags = Version(3 bits) | PT(1) | spare(1) | E(1) | S(1) | PN(1); bit 3
// (spare) is always 0. The Length field counts everything after the first
// 8 octets — optional block + extension headers + payload — and NEVER
// counts the TEID (verified against 2.gtp_tunneling_udp.pcap frame 1:
// flags 0x32, Length 204 = 4 optional + 200 inner, TEID 0x002dc715
// excluded; the Length field of 2-1_gtp.pcap frame 1 is malformed in the
// source capture — 54 vs the actual 44-byte inner packet — and is not
// reproduced).
//
// The planner emits either a GTP-C signaling dialog (one packet per
// GTPStep) or a GTP-U data stream (Frames T-PDU messages carrying the
// inner packet). Each message rides in an outer UDP packet whose L2/L3/L4
// are written by the core builder from the emitted config — the GTP
// message is the UDP payload, so no builder support is needed (GTP is an
// L4 application, not an L2/L3 encapsulation like GRE/MPLS).
package gtp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Defaults.
const (
	// DefaultPortGTPU is the GTP-U user-plane UDP port (TS 29.281 §5.1).
	DefaultPortGTPU uint16 = 2152
	// DefaultPortGTPC is the GTP-C control-plane UDP port (TS 29.060 §6).
	DefaultPortGTPC uint16 = 2123

	// DefaultInnerTTL is the inner IP TTL (IPv4) / hop limit (IPv6) when
	// GTPConfig.InnerTTL is 0 (matches the outer IP default of 64).
	DefaultInnerTTL uint8 = 64

	// GTPv1 is the only supported version (TS 29.281 §5.1).
	GTPv1 uint8 = 1

	// GTP message types (TS 29.060 §7.1).
	msgTypeTPDU        uint8 = 0xFF // T-PDU: user plane data
	msgTypeEchoRequest uint8 = 0x01
	msgTypeEchoResp    uint8 = 0x02

	// Flags bit positions within the first octet (TS 29.281 §5.1):
	// Version occupies bits 7-5, PT bit 4, spare bit 3, E bit 2, S bit
	// 1, PN bit 0.
	flagE byte = 0x04 // Extension header present
	flagS byte = 0x02 // Sequence Number present
	flagPN byte = 0x01 // N-PDU Number present

	// Max extension content: the extension Length octet (TS 29.281 §5.2.1)
	// counts (1 + content + padding) in 4-octet units, so content of at
	// most 1018 bytes fits a Length octet of 255.
	maxExtensionData = 1018
)

// Planner emits GTPv1 messages for a tunnel flow.
type Planner struct{}

// NewPlanner returns a new GTP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name used by the registry.
func (p *Planner) Name() string { return "gtp" }

// Validate validates a GTP flow spec (read-only per validate_conventions.md
// §1.1: never mutate spec, never fill defaults — Plan handles defaults).
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.GTP == nil {
		return fmt.Errorf("gtp: GTP config is required")
	}
	cfg := spec.GTP

	switch cfg.Version {
	case 0, GTPv1:
		// ok (0 = auto, resolved by Plan)
	default:
		return fmt.Errorf("gtp: Version %d not supported (only GTPv1 = 1; GTPv2 TS 29.274 is a different protocol)", cfg.Version)
	}

	switch cfg.Mode {
	case "", "u", "c":
		// ok
	default:
		return fmt.Errorf("gtp: Mode %q not in supported list (allowed: u = GTP-U user plane, c = GTP-C control plane)", cfg.Mode)
	}

	if cfg.PT > 1 {
		return fmt.Errorf("gtp: PT %d must be 0 (GTP') or 1 (GTP)", cfg.PT)
	}

	// The inner packet's IPs must parse when set (empty = planner default
	// filled by Plan). Both IPv4 and IPv6 are valid inner layers.
	for _, pair := range []struct {
		name string
		val  string
	}{{"InnerSrcIP", cfg.InnerSrcIP}, {"InnerDstIP", cfg.InnerDstIP}} {
		if pair.val == "" {
			continue
		}
		if net.ParseIP(pair.val) == nil {
			return fmt.Errorf("gtp: %s %q is not a valid IP address", pair.name, pair.val)
		}
	}

	// The inner L4 protocol must match the inner IP version.
	if cfg.InnerProto != 0 {
		inSrc, inDst := cfg.InnerSrcIP, cfg.InnerDstIP
		if inSrc == "" {
			inSrc = spec.SrcIP
		}
		if inDst == "" {
			inDst = spec.DstIP
		}
		ipv6 := net.ParseIP(inSrc).To4() == nil
		switch cfg.InnerProto {
		case 6, 17:
			// ok for both inner IP versions
		case 1:
			if ipv6 {
				return fmt.Errorf("gtp: InnerProto 1 (ICMP) is for IPv4 inner packets; use 58 (ICMPv6) for IPv6 inner packets")
			}
		case 58:
			if !ipv6 {
				return fmt.Errorf("gtp: InnerProto 58 (ICMPv6) is for IPv6 inner packets; use 1 (ICMP) for IPv4 inner packets")
			}
		default:
			return fmt.Errorf("gtp: InnerProto %d not in supported list (allowed: 6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6)", cfg.InnerProto)
		}
	}

	// The extension Length octet (TS 29.281 §5.2.1) is one byte counting
	// 4-octet units; longer content would overflow it.
	if len(cfg.ExtensionData) > maxExtensionData {
		return fmt.Errorf("gtp: ExtensionData %d bytes exceeds the %d-byte maximum for the 1-octet extension Length field", len(cfg.ExtensionData), maxExtensionData)
	}

	if cfg.Frames < 0 {
		return fmt.Errorf("gtp: Frames %d must be >= 0", cfg.Frames)
	}

	switch cfg.Direction {
	case "", "up", "down":
		// ok
	default:
		return fmt.Errorf("gtp: Direction %q not in supported list (allowed: up, down)", cfg.Direction)
	}

	for i, step := range cfg.Scenarios {
		if step.MessageType == 0 {
			return fmt.Errorf("gtp: scenarios[%d]: message_type is required (0 is the reserved GTP message type, TS 29.060 §7.1)", i)
		}
		switch step.Direction {
		case "", "up", "down":
			// ok
		default:
			return fmt.Errorf("gtp: scenarios[%d]: Direction %q not in supported list (allowed: up, down)", i, step.Direction)
		}
		for j, ie := range step.IEs {
			// TLV IEs carry a 2-octet Length field (TS 29.060 §7.7.0);
			// TV IEs (Type < 0x80) have no Length field at all.
			if ie.Type >= 0x80 && len(ie.Value) > 65535 {
				return fmt.Errorf("gtp: scenarios[%d].ies[%d]: value %d bytes exceeds the 65535-byte maximum for the 2-octet IE Length field (TS 29.060 §7.7.0)", i, j, len(ie.Value))
			}
		}
	}

	return nil
}

// Plan emits the GTP tunnel's messages. spec.SrcIP/DstIP/SrcMAC/DstMAC are
// the OUTER addresses (tunnel endpoints); GTPConfig.InnerSrcIP/InnerDstIP
// (default = the flow's IPs) are the inner packet's addresses of a T-PDU.
//
// Two modes (mutually exclusive):
//
//	Scenarios non-empty: GTP-C dialog — one packet per step, each with
//	    its own message type, TEID override, sequence and IEs. The data
//	    plane (Frames) is skipped.
//	Scenarios empty: GTP-U data plane — Frames T-PDU messages (0xFF)
//	    carrying the inner packet. Each frame gets a distinct inner IPID
//	    and, when SequencePresent, a Sequence Number incremented from the
//	    configured base.
//
// "up" = client side; "down" swaps the outer MACs/IPs/ports (and inner
// addresses), so a dialog's replies come from the peer.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	configChan := make(chan core.PacketConfig, 256)
	cfg := spec.GTP

	// Resolve defaults before launching the goroutine (deterministic,
	// same values every message).
	version := cfg.Version
	if version == 0 {
		version = GTPv1
	}
	pt := cfg.PT
	if pt == 0 {
		pt = 1 // GTP (not GTP')
	}
	port := DefaultPortGTPU
	if cfg.Mode == "c" {
		port = DefaultPortGTPC
	}
	srcPort, dstPort := spec.SrcPort, spec.DstPort
	if srcPort == 0 {
		srcPort = port
	}
	if dstPort == 0 {
		dstPort = port
	}
	innerSrcIP := cfg.InnerSrcIP
	innerDstIP := cfg.InnerDstIP
	if innerSrcIP == "" {
		innerSrcIP = spec.SrcIP
	}
	if innerDstIP == "" {
		innerDstIP = spec.DstIP
	}
	innerProto := cfg.InnerProto
	if innerProto == 0 {
		if spec.TCP != nil {
			innerProto = 6
		} else {
			innerProto = 17
		}
	}
	innerTTL := cfg.InnerTTL
	if innerTTL == 0 {
		innerTTL = DefaultInnerTTL
	}
	frames := cfg.Frames
	if frames == 0 {
		frames = 1
	}
	dir := cfg.Direction
	if dir == "" {
		dir = "up"
	}
	innerPayload := cfg.InnerPayload
	if innerPayload == nil {
		innerPayload = spec.Payload
	}

	go func() {
		defer close(configChan)
		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
		now := time.Now()

		packetIndex := uint64(0)
		ipidCounter := uint32(0)
		nextIPID := func() uint16 {
			ipidCounter++
			return uint16(ipidCounter)
		}
		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, sport, dport uint16, payload []byte) bool {
			cfgOut := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(srcIP),
				},
				L3: core.L3Base(srcIP, dstIP, 17, spec.TTL, nextIPID(), spec),
				L4: core.L4Config{
					Protocol: "udp",
					SrcPort:  sport,
					DstPort:  dport,
				},
				Payload: payload,
			}
			select {
			case configChan <- cfgOut:
				packetIndex++
				return true
			case <-ctx.Done():
				return false
			}
		}

		// resolveDirection maps a direction to concrete outer addresses
		// and ports: "up" = the flow's own side, "down" = the peer's.
		resolveDirection := func(direction string) (srcIP, dstIP, srcMAC, dstMAC string, sport, dport uint16) {
			srcIP, dstIP = spec.SrcIP, spec.DstIP
			srcMAC, dstMAC = spec.SrcMAC, spec.DstMAC
			sport, dport = srcPort, dstPort
			if direction == "down" {
				srcIP, dstIP = dstIP, srcIP
				srcMAC, dstMAC = dstMAC, srcMAC
				sport, dport = dport, sport
			}
			return
		}

		// Flags octet: Version(3) | PT(1) | spare(1, always 0) | E(1) |
		// S(1) | PN(1). The optional 4-octet block is present iff ANY of
		// E/S/PN is set (TS 29.281 §5.1).
		e, s, pn := cfg.ExtensionPresent, cfg.SequencePresent, cfg.NPDUPresent
		flags := byte(version&0x07)<<5 | byte(pt&1)<<4
		if e {
			flags |= flagE
		}
		if s {
			flags |= flagS
		}
		if pn {
			flags |= flagPN
		}

		if len(cfg.Scenarios) > 0 {
			// GTP-C dialog: one packet per step.
			for _, step := range cfg.Scenarios {
				if err := ctx.Err(); err != nil {
					return
				}
				stepDir := step.Direction
				if stepDir == "" {
					stepDir = dir
				}
				srcIP, dstIP, srcMAC, dstMAC, sport, dport := resolveDirection(stepDir)

				teid := cfg.TEID
				if step.TEIDOverride != nil {
					teid = *step.TEIDOverride
				}
				seq := step.Sequence
				if !s {
					seq = 0 // Sequence field is absent when the S flag is clear
				}
				msg := buildGTPMessage(flags, step.MessageType, teid, seq, cfg.NPDUValue, cfg.ExtensionType, cfg.ExtensionData, encodeIEs(step.IEs))
				if !emit(stepDir, srcMAC, dstMAC, srcIP, dstIP, sport, dport, msg) {
					return
				}
			}
			return
		}

		// GTP-U data plane: Frames T-PDU messages.
		for i := 0; i < frames; i++ {
			if err := ctx.Err(); err != nil {
				return
			}
			srcIP, dstIP, srcMAC, dstMAC, sport, dport := resolveDirection(dir)
			inSrc, inDst := innerSrcIP, innerDstIP
			if dir == "down" {
				inSrc, inDst = inDst, inSrc
			}

			var inner []byte
			if innerProto == 6 || innerProto == 17 || innerProto == 1 || innerProto == 58 {
				if net.ParseIP(inSrc).To4() == nil {
					inner = buildInnerIPv6Packet(inSrc, inDst, innerProto, spec.SrcPort, spec.DstPort, innerTTL, innerPayload, spec.TCP, cfg.TCPOptions)
				} else {
					ipid := cfg.InnerIPID + uint16(i)
					inner = buildInnerIPv4Packet(inSrc, inDst, innerProto, spec.SrcPort, spec.DstPort, innerTTL, innerPayload, ipid, spec.TCP, cfg.TCPOptions)
				}
			} else {
				inner = innerPayload
			}

			seq := cfg.Sequence
			if s {
				seq = cfg.Sequence + uint16(i)
			} else {
				seq = 0
			}
			msg := buildGTPMessage(flags, msgTypeTPDU, cfg.TEID, seq, cfg.NPDUValue, cfg.ExtensionType, cfg.ExtensionData, inner)
			if !emit(dir, srcMAC, dstMAC, srcIP, dstIP, sport, dport, msg) {
				return
			}
		}
	}()

	return configChan, nil
}

// buildGTPMessage assembles one complete GTPv1 message:
//
//	Flags(1) + MessageType(1) + Length(2) + TEID(4)
//	    + [Sequence(2) + N-PDU(1) + Next-Ext-Type(1)]  // iff E|S|PN set
//	    + [Next-Ext-Type(1) + Length(1) + content]     // iff E set
//	    + payload
//
// The Length field counts everything after the first 8 octets — the
// optional block, the extension header(s) and the payload — and never the
// TEID (TS 29.281 §5.1). The extension header (TS 29.281 §5.2.1) is
// Next-Ext-Type(1) + Length(1, in 4-octet units including the Length octet
// itself, excluding the Next-Ext-Type octet) + content padded to a 4-octet
// multiple; its own Next-Ext-Type is 0x00 (no further extension).
func buildGTPMessage(flags byte, msgType uint8, teid uint32, seq uint16, npdu uint8, extType uint8, extData []byte, payload []byte) []byte {
	optionalPresent := flags&(flagE|flagS|flagPN) != 0

	var ext []byte // the extension header without its Next-Ext-Type octet
	if flags&flagE != 0 {
		// Len = (1 + content + padding) / 4, rounded up so the total
		// (Length octet + content) is a multiple of 4 octets.
		contentLen := len(extData)
		padded := 1 + contentLen
		for padded%4 != 0 {
			padded++
		}
		ext = make([]byte, padded)
		ext[0] = byte(padded / 4) // Length in 4-octet units
		copy(ext[1:], extData)
	}

	// Length = everything after the first 8 octets.
	length := 0
	if optionalPresent {
		length += 4
	}
	if flags&flagE != 0 {
		length += len(ext) + 1 // +1 for the Next-Ext-Type octet
	}
	length += len(payload)

	msg := make([]byte, 8+length)
	msg[0] = flags
	msg[1] = msgType
	binary.BigEndian.PutUint16(msg[2:4], uint16(length))
	binary.BigEndian.PutUint32(msg[4:8], teid)

	off := 8
	if optionalPresent {
		binary.BigEndian.PutUint16(msg[off:off+2], seq)
		msg[off+2] = npdu
		if flags&flagE != 0 {
			msg[off+3] = extType
		} // else 0: no extension follows
		off += 4
	}
	if flags&flagE != 0 {
		msg[off] = 0x00 // next extension header type: none (TS 29.281 §5.2.1)
		copy(msg[off+1:], ext)
		off += 1 + len(ext)
	}
	copy(msg[off:], payload)
	return msg
}

// encodeIEs serializes Information Elements per TS 29.060 §7.7.0. The IE
// Type's most significant bit selects the format: 0 = TV (Type + Value, no
// Length octet, used by fixed-length IEs such as Recovery type 14), 1 = TLV
// (Type + 2-octet big-endian Length + Value, used by variable-length IEs such
// as APN type 131). Wireshark's GTP dissector and go-gtp agree.
func encodeIEs(ies []core.GTPIE) []byte {
	if len(ies) == 0 {
		return nil
	}
	total := 0
	for _, ie := range ies {
		if ie.Type >= 0x80 {
			total += 3 + len(ie.Value)
		} else {
			total += 1 + len(ie.Value)
		}
	}
	out := make([]byte, 0, total)
	for _, ie := range ies {
		out = append(out, ie.Type)
		if ie.Type >= 0x80 {
			out = append(out, byte(len(ie.Value)>>8), byte(len(ie.Value)))
		}
		out = append(out, ie.Value...)
	}
	return out
}

// buildInnerIPv4Packet builds a complete inner IPv4 packet (20-byte header
// + L4 + payload) for the GTP-U T-PDU. The IPv4 header checksum is computed
// per RFC 791 §3.1; L4 checksums are computed for TCP (RFC 793, mandatory),
// UDP (RFC 768, pseudo-header) and ICMP (RFC 792, over the message only).
// TCP honors the flow's TCP config (Seq/Ack/Flags/WindowSize/TCPOptions) so
// inner handshakes are reproducible byte-for-byte against captured traffic.
//
// Supported protocols: 6 (TCP), 17 (UDP), 1 (ICMP echo).
func buildInnerIPv4Packet(srcIP, dstIP string, proto uint8, srcPort, dstPort uint16, ttl uint8, payload []byte, ipid uint16, tcp *core.TCPConfig, tcpOptions []core.TCPOption) []byte {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()

	l4 := buildInnerL4(proto, srcPort, dstPort, tcp, tcpOptions, payload, src, dst)

	hdr := make([]byte, 20)
	hdr[0] = 0x45 // Version=4, IHL=5
	binary.BigEndian.PutUint16(hdr[2:4], uint16(20+len(l4)))
	binary.BigEndian.PutUint16(hdr[4:6], ipid)
	binary.BigEndian.PutUint16(hdr[6:8], 0x4000) // Flags=DF, FragOffset=0
	if ttl == 0 {
		ttl = DefaultInnerTTL
	}
	hdr[8] = ttl
	hdr[9] = proto
	if len(src) == 4 {
		copy(hdr[12:16], src)
	}
	if len(dst) == 4 {
		copy(hdr[16:20], dst)
	}
	binary.BigEndian.PutUint16(hdr[10:12], ipChecksum16(hdr))

	return append(hdr, l4...)
}

// buildInnerIPv6Packet builds a complete inner IPv6 packet (40-byte header
// + L4 + payload) per RFC 8200 for the GTP-U T-PDU. The IPv6 header has no
// checksum; TCP/UDP/ICMPv6 checksums use the 40-byte IPv6 pseudo-header
// (RFC 8200 §8.1). TrafficClass/FlowLabel are 0; the Next Header is the L4
// protocol.
//
// Supported protocols: 6 (TCP), 17 (UDP), 58 (ICMPv6 echo).
func buildInnerIPv6Packet(srcIP, dstIP string, proto uint8, srcPort, dstPort uint16, hopLimit uint8, payload []byte, tcp *core.TCPConfig, tcpOptions []core.TCPOption) []byte {
	// Accept only real IPv6 addresses (To16 keeps 4-byte input as an
	// IPv4-mapped address; To4() != nil detects and rejects that).
	src := net.ParseIP(srcIP).To16()
	if src.To4() != nil {
		src = nil
	}
	dst := net.ParseIP(dstIP).To16()
	if dst.To4() != nil {
		dst = nil
	}

	l4 := buildInnerL4(proto, srcPort, dstPort, tcp, tcpOptions, payload, src, dst)

	hdr := make([]byte, 40)
	hdr[0] = 0x60 // Version=6, TrafficClass=0, FlowLabel=0
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(l4)))
	hdr[6] = proto
	if hopLimit == 0 {
		hopLimit = DefaultInnerTTL
	}
	hdr[7] = hopLimit
	if len(src) == 16 {
		copy(hdr[8:24], src)
	}
	if len(dst) == 16 {
		copy(hdr[24:40], dst)
	}
	return append(hdr, l4...)
}

// buildInnerL4 builds the inner L4 segment for the protocol. src/dst carry
// the inner addresses (4-byte for IPv4 pseudo-headers, 16-byte for IPv6)
// so the L4 checksums can be computed here, before the IP header exists.
func buildInnerL4(proto uint8, srcPort, dstPort uint16, tcp *core.TCPConfig, tcpOptions []core.TCPOption, payload []byte, src, dst net.IP) []byte {
	switch proto {
	case 6: // TCP (RFC 793)
		var opts []byte
		if tcpOptions != nil {
			opts = encodeTCPOptions(tcpOptions)
		}
		hdr := make([]byte, 20+len(opts))
		binary.BigEndian.PutUint16(hdr[0:2], srcPort)
		binary.BigEndian.PutUint16(hdr[2:4], dstPort)
		seq, ack := uint32(0), uint32(0)
		flags := byte(0x18) // PSH|ACK: data segment default
		win := uint16(65535)
		if tcp != nil {
			seq, ack = tcp.Seq, tcp.Ack
			if tcp.Flags != 0 {
				flags = tcp.Flags
			}
			if tcp.WindowSize != 0 {
				win = tcp.WindowSize
			}
		}
		binary.BigEndian.PutUint32(hdr[4:8], seq)
		binary.BigEndian.PutUint32(hdr[8:12], ack)
		hdr[12] = byte((20+len(opts))/4) << 4 // Data offset
		hdr[13] = flags
		binary.BigEndian.PutUint16(hdr[14:16], win)
		// Checksum at [16:18] computed below (pseudo-header).
		copy(hdr[20:], opts)
		hdr = append(hdr, payload...)
		binary.BigEndian.PutUint16(hdr[16:18], l4Checksum(hdr, 6, src, dst))
		return hdr
	case 17: // UDP (RFC 768)
		hdr := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(hdr[0:2], srcPort)
		binary.BigEndian.PutUint16(hdr[2:4], dstPort)
		binary.BigEndian.PutUint16(hdr[4:6], uint16(8+len(payload)))
		copy(hdr[8:], payload)
		cksum := l4Checksum(hdr, 17, src, dst)
		if len(src) == 16 && cksum == 0 {
			cksum = 0xFFFF // IPv6 UDP must not have a zero checksum (RFC 6936 §2)
		}
		binary.BigEndian.PutUint16(hdr[6:8], cksum)
		return hdr
	case 1: // ICMP echo (RFC 792): checksum over the message only
		msg := make([]byte, 8+len(payload))
		msg[0] = 8 // echo request
		copy(msg[8:], payload)
		binary.BigEndian.PutUint16(msg[2:4], ipChecksum16(msg))
		return msg
	case 58: // ICMPv6 echo (RFC 4443): checksum includes the pseudo-header
		msg := make([]byte, 8+len(payload))
		msg[0] = 128 // echo request
		copy(msg[8:], payload)
		binary.BigEndian.PutUint16(msg[2:4], l4Checksum(msg, 58, src, dst))
		return msg
	default:
		return payload
	}
}

// encodeTCPOptions serializes TCP options and pads to a 4-byte boundary
// with NOP (Kind=1) — same layout as the core builder's encoder. Kind 0
// (End) and Kind 1 (NOP) are single-byte options; all other kinds are
// Kind + Length(2+len(Data)) + Data.
func encodeTCPOptions(opts []core.TCPOption) []byte {
	var buf []byte
	for _, o := range opts {
		if o.Kind == core.TCPOptEnd || o.Kind == core.TCPOptNOP {
			buf = append(buf, o.Kind)
			continue
		}
		buf = append(buf, o.Kind)
		buf = append(buf, byte(2+len(o.Data)))
		buf = append(buf, o.Data...)
	}
	for len(buf)%4 != 0 {
		buf = append(buf, core.TCPOptNOP)
	}
	return buf
}

// ipChecksum16 computes the 16-bit one's-complement checksum used by IPv4
// (RFC 791 §3.1) and ICMP (RFC 792).
func ipChecksum16(b []byte) uint16 {
	sum := uint32(0)
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

// l4Checksum computes the TCP/UDP/ICMPv6 checksum with the pseudo-header:
// the 12-byte IPv4 pseudo-header (RFC 793/RFC 768) when src/dst are 4-byte,
// or the 40-byte IPv6 pseudo-header (RFC 8200 §8.1) when they are 16-byte.
func l4Checksum(l4 []byte, proto uint8, src, dst net.IP) uint16 {
	var pseudo []byte
	if len(src) == 16 {
		// IPv6 pseudo-header: SrcIP(16) + DstIP(16) + UpperLayerLen(4) +
		// zero(3) + NextHeader(1).
		pseudo = make([]byte, 40)
		copy(pseudo[0:16], src)
		copy(pseudo[16:32], dst)
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(l4)))
		pseudo[39] = proto
	} else {
		// IPv4 pseudo-header: SrcIP(4) + DstIP(4) + zero(1) + Protocol(1) +
		// L4-len(2).
		pseudo = make([]byte, 12)
		if len(src) == 4 {
			copy(pseudo[0:4], src)
		}
		if len(dst) == 4 {
			copy(pseudo[4:8], dst)
		}
		pseudo[9] = proto
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(l4)))
	}
	return ipChecksum16(append(pseudo, l4...))
}
