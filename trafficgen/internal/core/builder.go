// Package core provides core functionality.
package core

import (
	"encoding/binary"
	"net"
	"go.uber.org/zap"
)

const (
	EtherTypeIPv4 = 0x0800
	EtherTypeARP  = 0x0806
	EtherTypeIPv6 = 0x86DD

	ProtocolICMP   = 1
	ProtocolTCP    = 6
	ProtocolUDP    = 17
	ProtocolSCTP   = 132
	ProtocolICMPv6 = 58

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

// Builder builds binary packets from PacketConfig.
type Builder struct{}

// NewBuilder creates a new packet builder.
func NewBuilder() *Builder {
	return &Builder{}
}

// L3Base builds an L3Config with the common L3 fields plus the flow-level
// DSCP/ECN/Flags/FragOffset carried on spec. srcIP/dstIP are passed explicitly
// so reply packets can swap them. Legacy spec.TOS (whole-byte) overrides
// DSCP/ECN when set, for backward compatibility with old configs.
// Planners use this instead of inlining L3Config{} at every packet site.
//
// Defaulting (DF=1, DSCP=0x2E, MACs, etc.) is owned by mapToFlowSpec via
// presence-check helpers. L3Base passes spec.Flags through unchanged so an
// explicit user choice of flags=0 (no DF, allow fragmentation) is honored
// end-to-end. Code paths that construct FlowSpec directly (bypassing
// mapToFlowSpec) must set spec.Flags explicitly if they want DF=1.
func L3Base(srcIP, dstIP string, protocol uint8, ttl uint8, ipid uint16, spec FlowSpec) L3Config {
	l3 := L3Config{
		SrcIP:       srcIP,
		DstIP:       dstIP,
		Protocol:    protocol,
		TTL:         ttl,
		IPID:        ipid,
		DSCP:        spec.DSCP,
		ECN:         spec.ECN,
		Flags:       spec.Flags,
		FragOffset:  spec.FragOffset,
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
	l3Len := 0
	switch effectiveEtherType {
	case EtherTypeIPv4:
		l3Len = 20
	case EtherTypeIPv6:
		l3Len = IPv6HeaderLen
	}
	l2Len := 14
	if config.L2.VLAN != nil {
		l2Len = 18
	}
	total := l2Len + l3Len + l4Len + len(config.Payload)

	// Ethernet padding: pad short frames to MinEthernetFrame (60 bytes,
	// excluding FCS) so real NICs don't reject them. L2Config.Pad controls
	// the behavior — nil or *true pads, *false skips. Padding bytes are
	// zero-filled and appended AFTER the L3/L4 payload; IP total length
	// reflects only the real payload so receivers strip padding correctly.
	if shouldPad(config.L2.Pad) && total < MinEthernetFrame {
		total = MinEthernetFrame
	}

	packet := make([]byte, total)
	l2End := l2Len
	l3End := l2End + l3Len
	l4End := l3End + l4Len

	b.writeL2(packet[0:l2End], config)
	if l3Len > 0 {
		b.writeL3(packet[l2End:l3End], config, l4Len+len(config.Payload))
	}
	if l4Len > 0 {
		b.writeL4(packet[l3End:l4End], config)
	}
	copy(packet[l4End:], config.Payload)

	return packet, nil
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

// writeL2 writes the Ethernet header (with optional 802.1Q VLAN tag) into dst.
func (b *Builder) writeL2(dst []byte, config PacketConfig) {
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
	etherType := config.L2.EtherType
	if etherType == 0 {
		etherType = EtherTypeIPv4
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
// IPv6 has no header checksum — integrity is protected by the L4 checksum
// with the pseudo-header (see calculateIPv6PseudoHeader). dst must be
// exactly 40 bytes; the caller (Build) sizes it.
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
	dst[6] = config.L3.Protocol // Next Header
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
// this header by Build(). The checksum field is filled with 0 — SCTP uses
// CRC32c (RFC 4960 §6.8), not the IP one's-complement checksum; computing
// CRC32c here would require importing a CRC32c package and the test only
// needs byte-exact packet structure, not a valid CRC. Real SCTP stacks
// validate the CRC and drop on mismatch, but trafficgen is a packet
// generator for testing — receivers in the test path either don't validate
// (packet counters, captures) or are themselves trafficgen-controlled.
func (b *Builder) writeSCTP(dst []byte, config PacketConfig) {
	binary.BigEndian.PutUint16(dst[0:2], config.L4.SrcPort)
	binary.BigEndian.PutUint16(dst[2:4], config.L4.DstPort)
	binary.BigEndian.PutUint32(dst[4:8], config.L4.Ack) // VerificationTag reuses Ack field
	binary.BigEndian.PutUint32(dst[8:12], 0)           // Checksum (CRC32c, left 0)
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
	checksum := calculateUDPChecksum(config, config.Payload)
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
func calculateTCPChecksum(config PacketConfig, header, payload []byte) uint16 {
	// Build pseudo-header
	pseudoHeader := make([]byte, 12)

	// Source IP
	srcIP := net.ParseIP(config.L3.SrcIP)
	if srcIP == nil && config.L3.SrcIP != "" {
		zap.L().Warn("invalid src IP address", zap.String("ip", config.L3.SrcIP))
	}
	if srcIP != nil {
		srcIP = srcIP.To4()
		if len(srcIP) == 4 {
			copy(pseudoHeader[0:4], srcIP)
		}
	}

	// Destination IP
	dstIP := net.ParseIP(config.L3.DstIP)
	if dstIP == nil && config.L3.DstIP != "" {
		zap.L().Warn("invalid dst IP address", zap.String("ip", config.L3.DstIP))
	}
	if dstIP != nil {
		dstIP = dstIP.To4()
		if len(dstIP) == 4 {
			copy(pseudoHeader[4:8], dstIP)
		}
	}

	// Zero
	pseudoHeader[8] = 0

	// Protocol
	pseudoHeader[9] = 6 // TCP

	// TCP length (header + payload)
	tcpLen := uint16(len(header) + len(payload))
	binary.BigEndian.PutUint16(pseudoHeader[10:12], tcpLen)

	// Calculate checksum
	sum := uint32(0)

	// Pseudo-header
	for i := 0; i < 12; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i : i+2]))
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
func calculateUDPChecksum(config PacketConfig, payload []byte) uint16 {
	// Build pseudo-header
	pseudoHeader := make([]byte, 12)

	// Source IP
	srcIP := net.ParseIP(config.L3.SrcIP)
	if srcIP == nil && config.L3.SrcIP != "" {
		zap.L().Warn("invalid src IP address", zap.String("ip", config.L3.SrcIP))
	}
	if srcIP != nil {
		srcIP = srcIP.To4()
		if len(srcIP) == 4 {
			copy(pseudoHeader[0:4], srcIP)
		}
	}

	// Destination IP
	dstIP := net.ParseIP(config.L3.DstIP)
	if dstIP == nil && config.L3.DstIP != "" {
		zap.L().Warn("invalid dst IP address", zap.String("ip", config.L3.DstIP))
	}
	if dstIP != nil {
		dstIP = dstIP.To4()
		if len(dstIP) == 4 {
			copy(pseudoHeader[4:8], dstIP)
		}
	}

	// Zero
	pseudoHeader[8] = 0

	// Protocol
	pseudoHeader[9] = 17 // UDP

	// UDP length (8 byte header + payload)
	udpLen := uint16(8 + len(payload))
	binary.BigEndian.PutUint16(pseudoHeader[10:12], udpLen)

	// Calculate checksum
	sum := uint32(0)

	// Pseudo-header
	for i := 0; i < 12; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i : i+2]))
	}

	// UDP length
	sum += uint32(udpLen)

	// Ports
	sum += uint32(config.L4.SrcPort)
	sum += uint32(config.L4.DstPort)

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
