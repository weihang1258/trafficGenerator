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

	ProtocolICMP = 1
	ProtocolTCP  = 6
	ProtocolUDP  = 17
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
	l3Len := 20
	// Skip the L3 (IPv4) header for any non-IPv4 EtherType. ARP (0x0806) and
	// other L2 protocols carry their payload directly after the Ethernet
	// header; writing a 20-byte IPv4 header would shift the payload and
	// corrupt the packet. EtherType 0 means "default to IPv4" (see writeL2),
	// so resolve the effective type before deciding.
	effectiveEtherType := config.L2.EtherType
	if effectiveEtherType == 0 {
		effectiveEtherType = EtherTypeIPv4
	}
	if effectiveEtherType != EtherTypeIPv4 {
		l3Len = 0
	}
	l2Len := 14
	if config.L2.VLAN != nil {
		l2Len = 18
	}
	total := l2Len + l3Len + l4Len + len(config.Payload)

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

// l4Length returns the L4 header length in bytes for the config.
func l4Length(config PacketConfig) int {
	switch config.L4.Protocol {
	case "tcp":
		return 20 + len(encodeTCPOptions(config.L4.TCPOptions))
	case "udp":
		return 8
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

// writeL3 writes the IPv4 header into dst.
func (b *Builder) writeL3(dst []byte, config PacketConfig, payloadLen int) {
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

// writeL4 writes the L4 header (TCP/UDP) into dst. ICMP has no separate header
// (its data is in the payload).
func (b *Builder) writeL4(dst []byte, config PacketConfig) {
	switch config.L4.Protocol {
	case "tcp":
		b.writeTCP(dst, config)
	case "udp":
		b.writeUDP(dst, config)
	}
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
