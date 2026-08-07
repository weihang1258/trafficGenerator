// Package gre implements the GRE (Generic Routing Encapsulation, 通用路由
// 封装, RFC 2784/2890) planner. It emits tunneled packets:
//
//	outer Ethernet (optional VLAN) + outer IP (protocol 47) + GRE header +
//	inner packet
//
// where the inner packet is one of:
//
//	ARP-over-GRE:    a 28-byte ARP message (RFC 826), GRE Protocol Type 0x0806
//	IPv4-over-GRE:   a complete inner IPv4 packet (header + TCP/UDP/ICMP with
//	                 correct checksums), Protocol Type 0x0800
//	IPv6-over-GRE:   a complete inner IPv6 packet (header + TCP/UDP/ICMPv6 with
//	                 correct checksums), Protocol Type 0x86DD
//
// The core builder writes the outer IP header (protocol 47, total length
// covering GRE + inner) and the GRE header (4-byte base + 4 bytes per
// C/R/K/S option field, RFC 2890) from the per-packet L2Config.GRE; the
// planner only decides which packets to emit, what each inner packet
// carries, and the per-frame Key/Sequence values.
package gre

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
	// DefaultInnerTTL is the inner IP TTL (IPv4) / hop limit (IPv6) when
	// GREConfig.InnerTTL is 0 (matches the outer IP default of 64).
	DefaultInnerTTL uint8 = 64
)

// Planner emits GRE-encapsulated packet configs for a tunnel flow.
type Planner struct{}

// NewPlanner returns a new GRE planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name used by the registry.
func (p *Planner) Name() string { return "gre" }

// Validate validates a GRE flow spec (read-only per validate_conventions.md
// §1.1: never mutate spec, never fill defaults -- Plan handles defaults).
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.GRE == nil {
		return fmt.Errorf("gre: GRE config is required")
	}
	cfg := spec.GRE

	switch cfg.ProtocolType {
	case 0, core.EtherTypeIPv4, core.EtherTypeARP, core.EtherTypeIPv6:
		// ok (0 = auto, resolved by Plan)
	default:
		return fmt.Errorf("gre: ProtocolType 0x%04x not in supported list (allowed: 0x0800 IPv4, 0x0806 ARP, 0x86DD IPv6, 0 = auto)", cfg.ProtocolType)
	}

	// Resolve the effective mode exactly like Plan does, so the mode-based
	// checks below (ARP-vs-IP contradiction, inner IP version, inner L4
	// protocol) also apply to auto-resolved modes. Plan defaults an empty
	// InnerSrcIP to spec.SrcIP BEFORE resolving, so Validate must mirror
	// that (an empty InnerSrcIP over an IPv4 flow must resolve to IPv4).
	mode := cfg.ProtocolType
	if mode == 0 {
		inSrc := cfg.InnerSrcIP
		if inSrc == "" {
			inSrc = spec.SrcIP
		}
		switch {
		case spec.ARP != nil:
			mode = core.EtherTypeARP
		case net.ParseIP(inSrc).To4() == nil:
			mode = core.EtherTypeIPv6
		default:
			mode = core.EtherTypeIPv4
		}
	}

	// ARP-over-GRE carries a 28-byte ARP message, not an inner IP packet.
	// Configuring inner-IP fields with ProtocolType 0x0806 is a
	// contradiction (the ARP addresses come from the flow's MAC/IP fields).
	arpMode := mode == core.EtherTypeARP
	if arpMode {
		if cfg.InnerProto != 0 || cfg.InnerSrcIP != "" || cfg.InnerDstIP != "" {
			return fmt.Errorf("gre: ProtocolType 0x0806 (ARP) carries an ARP message, not an inner IP packet; InnerProto/InnerSrcIP/InnerDstIP must not be set")
		}
	} else if spec.ARP != nil {
		return fmt.Errorf("gre: ProtocolType 0x%04x carries an inner IP packet; the ARP config is only valid for ARP-over-GRE (ProtocolType 0x0806)", cfg.ProtocolType)
	}

	// Inner IPs must parse when set.
	for _, pair := range []struct {
		name string
		val  string
	}{{"InnerSrcIP", cfg.InnerSrcIP}, {"InnerDstIP", cfg.InnerDstIP}} {
		if pair.val == "" {
			continue
		}
		if net.ParseIP(pair.val) == nil {
			return fmt.Errorf("gre: %s %q is not a valid IP address", pair.name, pair.val)
		}
	}

	// The inner IP version must match the tunnel mode: the inner packet is
	// an IPv4 header (0x0800) or an IPv6 header (0x86DD). Resolve the
	// effective inner addresses (default = flow addresses) and check them
	// against the resolved mode.
	if !arpMode {
		inSrc, inDst := cfg.InnerSrcIP, cfg.InnerDstIP
		if inSrc == "" {
			inSrc = spec.SrcIP
		}
		if inDst == "" {
			inDst = spec.DstIP
		}
		for _, pair := range []struct {
			name string
			val  string
		}{{"inner source IP", inSrc}, {"inner destination IP", inDst}} {
			parsed := net.ParseIP(pair.val)
			if parsed == nil {
				return fmt.Errorf("gre: %s %q is not a valid IP address", pair.name, pair.val)
			}
			if mode == core.EtherTypeIPv6 && parsed.To4() != nil {
				return fmt.Errorf("gre: %s %q is IPv4 but ProtocolType 0x86DD requires an IPv6 inner packet", pair.name, pair.val)
			}
			if mode == core.EtherTypeIPv4 && parsed.To4() == nil {
				return fmt.Errorf("gre: %s %q is IPv6 but ProtocolType 0x0800 requires an IPv4 inner packet", pair.name, pair.val)
			}
		}
	}

	// Inner L4 protocol for the IP modes.
	if !arpMode {
		switch cfg.InnerProto {
		case 0, 6, 17:
			// ok for both modes
		case 1:
			if mode == core.EtherTypeIPv6 {
				return fmt.Errorf("gre: InnerProto 1 (ICMP) is for IPv4 inner packets; use 58 (ICMPv6) for IPv6 inner packets")
			}
		case 58:
			if mode == core.EtherTypeIPv4 {
				return fmt.Errorf("gre: InnerProto 58 (ICMPv6) is for IPv6 inner packets; use 1 (ICMP) for IPv4 inner packets")
			}
		default:
			return fmt.Errorf("gre: InnerProto %d not in supported list (allowed: 6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6)", cfg.InnerProto)
		}
	}

	if cfg.Frames < 0 {
		return fmt.Errorf("gre: Frames %d must be >= 0", cfg.Frames)
	}

	switch cfg.Direction {
	case "", "up", "down":
		// ok
	default:
		return fmt.Errorf("gre: Direction %q not in supported list (allowed: up, down)", cfg.Direction)
	}

	return nil
}

// Plan emits the GRE tunnel's packets. spec.SrcIP/DstIP/SrcMAC/DstMAC are
// the OUTER addresses (tunnel endpoints); GREConfig.InnerSrcIP/InnerDstIP
// (default = the flow's IPs) are the inner packet's addresses. "up" =
// client side on both outer and inner; "down" swaps outer MACs/IPs and the
// inner addresses. Each frame gets a distinct inner IPID and — when
// SequencePresent — a GRE Sequence Number incremented from the configured
// base.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	configChan := make(chan core.PacketConfig, 256)
	cfg := spec.GRE

	// Resolve defaults before launching the goroutine (deterministic,
	// same values every frame).
	protoType := cfg.ProtocolType
	innerSrcIP := cfg.InnerSrcIP
	innerDstIP := cfg.InnerDstIP
	if innerSrcIP == "" {
		innerSrcIP = spec.SrcIP
	}
	if innerDstIP == "" {
		innerDstIP = spec.DstIP
	}
	if protoType == 0 {
		switch {
		case spec.ARP != nil:
			protoType = core.EtherTypeARP
		case net.ParseIP(innerSrcIP).To4() == nil:
			protoType = core.EtherTypeIPv6
		default:
			protoType = core.EtherTypeIPv4
		}
	}
	arpMode := protoType == core.EtherTypeARP
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
	arpOp := uint16(1) // ARP request (RFC 826)
	if spec.ARP != nil && spec.ARP.Operation != 0 {
		arpOp = spec.ARP.Operation
	}

	go func() {
		defer close(configChan)
		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)
		now := time.Now()

		packetIndex := uint64(0)
		emit := func(cfgOut core.PacketConfig) bool {
			cfgOut.FlowID = flowID
			cfgOut.PacketIndex = packetIndex
			cfgOut.Timestamp = now
			select {
			case configChan <- cfgOut:
				packetIndex++
				return true
			case <-ctx.Done():
				return false
			}
		}

		ipidCounter := uint32(0)
		nextIPID := func() uint16 {
			ipidCounter++
			return uint16(ipidCounter)
		}

		for i := 0; i < frames; i++ {
			if err := ctx.Err(); err != nil {
				return
			}
			// Direction: "up" = client side outers, "down" = swapped.
			outerSrc, outerDst := spec.SrcIP, spec.DstIP
			srcMAC, dstMAC := spec.SrcMAC, spec.DstMAC
			inSrc, inDst := innerSrcIP, innerDstIP
			if dir == "down" {
				outerSrc, outerDst = outerDst, outerSrc
				srcMAC, dstMAC = dstMAC, srcMAC
				inSrc, inDst = inDst, inSrc
			}

			// Build the inner packet (ARP message or complete IP packet
			// with checksums).
			var inner []byte
			if arpMode {
				// ARP addresses mirror the flow's MAC/IP fields (matching
				// the ARP planner); down swaps sender and target.
				senderHW, targetHW := srcMAC, dstMAC
				senderProto, targetProto := spec.SrcIP, spec.DstIP
				if dir == "down" {
					senderHW, targetHW = targetHW, senderHW
					senderProto, targetProto = targetProto, senderProto
				}
				if spec.ARP != nil && spec.ARP.TargetMAC != "" {
					targetHW = spec.ARP.TargetMAC
				}
				inner = buildARPMessage(arpOp, senderHW, senderProto, targetHW, targetProto)
			} else if protoType == core.EtherTypeIPv6 {
				inner = buildInnerIPv6Packet(inSrc, inDst, innerProto, spec.SrcPort, spec.DstPort, innerTTL, innerPayload, spec.TCP, cfg.TCPOptions)
			} else {
				ipid := uint32(cfg.InnerIPID) + uint32(i)
				inner = buildInnerIPv4Packet(inSrc, inDst, innerProto, spec.SrcPort, spec.DstPort, innerTTL, innerPayload, uint16(ipid), spec.TCP, cfg.TCPOptions)
			}

			// Per-frame GRE config: the wire-level fields from the user
			// spec, with the Sequence Number incremented per frame.
			greCfg := *cfg
			greCfg.ProtocolType = protoType
			if cfg.SequencePresent {
				greCfg.Sequence = cfg.Sequence + uint32(i)
			}

			cfgOut := core.PacketConfig{
				Direction: dir,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(outerSrc),
					GRE:       &greCfg,
				},
				L3: core.L3Base(outerSrc, outerDst, core.ProtocolGRE, spec.TTL, nextIPID(), spec),
				// No L4: the inner packet is carried entirely in Payload
				// (the builder rejects a non-empty L4Config with GRE).
				Payload: inner,
			}
			if !emit(cfgOut) {
				return
			}
		}
	}()

	return configChan, nil
}

// buildARPMessage builds a 28-byte ARP packet (RFC 826): Hardware Type(2,
// Ethernet=1) + Protocol Type(2, IPv4=0x0800) + HW Addr Len(1) + Proto Addr
// Len(1) + Operation(2) + Sender HW(6) + Sender Proto(4) + Target HW(6) +
// Target Proto(4). Unparseable addresses leave zero bytes (matching the ARP
// planner's behavior on invalid input).
func buildARPMessage(op uint16, senderHW, senderProto, targetHW, targetProto string) []byte {
	packet := make([]byte, 28)
	binary.BigEndian.PutUint16(packet[0:2], 1)      // Hardware type: Ethernet
	binary.BigEndian.PutUint16(packet[2:4], 0x0800) // Protocol type: IPv4
	packet[4] = 6                                   // Hardware address length
	packet[5] = 4                                   // Protocol address length
	binary.BigEndian.PutUint16(packet[6:8], op)
	if mac, err := net.ParseMAC(senderHW); err == nil && len(mac) == 6 {
		copy(packet[8:14], mac)
	}
	if ip := net.ParseIP(senderProto).To4(); len(ip) == 4 {
		copy(packet[14:18], ip)
	}
	if mac, err := net.ParseMAC(targetHW); err == nil && len(mac) == 6 {
		copy(packet[18:24], mac)
	}
	if ip := net.ParseIP(targetProto).To4(); len(ip) == 4 {
		copy(packet[24:28], ip)
	}
	return packet
}

// buildInnerIPv4Packet builds a complete inner IPv4 packet (20-byte header
// + L4 + payload) for encapsulation inside GRE. The IPv4 header checksum is
// computed per RFC 791 §3.1; L4 checksums are computed for TCP (RFC 793,
// mandatory), UDP (RFC 768, pseudo-header — unlike the L2TP planner's
// zero-checksum UDP, a computed value is more faithful to real tunnels) and
// ICMP (RFC 792, over the message only). TCP honors the flow's TCP config
// (Seq/Ack/Flags/WindowSize/TCPOptions) so inner handshakes and data
// segments are reproducible byte-for-byte against captured traffic.
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
// + L4 + payload) per RFC 8200 for encapsulation inside GRE. The IPv6
// header has no checksum; TCP/UDP/ICMPv6 checksums use the 40-byte IPv6
// pseudo-header (RFC 8200 §8.1). TrafficClass/FlowLabel are 0; the Next
// Header is the L4 protocol.
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
// (RFC 791 §3.1), ICMP (RFC 792) and GRE (RFC 2784 §3.1).
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
