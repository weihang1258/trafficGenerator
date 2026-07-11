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
func L3Base(srcIP, dstIP string, protocol uint8, ttl uint8, ipid uint16, spec FlowSpec) L3Config {
	// Default to DF (don't fragment) for normal traffic unless the caller
	// explicitly requests fragmentation (flags set or a fragment offset).
	flags := spec.Flags
	if flags == 0 && spec.FragOffset == 0 {
		flags = IPFlagDF
	}
	l3 := L3Config{
		SrcIP:       srcIP,
		DstIP:       dstIP,
		Protocol:    protocol,
		TTL:         ttl,
		IPID:        ipid,
		DSCP:        spec.DSCP,
		ECN:         spec.ECN,
		Flags:       flags,
		FragOffset:  spec.FragOffset,
	}
	if spec.TOS != 0 {
		l3.DSCP = spec.TOS >> 2
		l3.ECN = spec.TOS & 0x03
	}
	return l3
}

// Build builds a binary packet from a PacketConfig.
func (b *Builder) Build(config PacketConfig) ([]byte, error) {
	// Build bottom-up: L4 -> L3 -> L2

	var packet []byte

	// Build L4 (TCP/UDP/ICMP)
	l4Data := b.buildL4(config)

	// Build L3 (IP) — payload length includes L4 header + actual payload
	totalL4Len := len(l4Data) + len(config.Payload)
	l3Data := b.buildL3(config, totalL4Len)

	// Build L2 (Ethernet)
	l2Data := b.buildL2(config, len(l3Data)+len(l4Data))

	// Combine: L2 + L3 + L4 + Payload
	packet = make([]byte, 0, len(l2Data)+len(l3Data)+len(l4Data)+len(config.Payload))
	packet = append(packet, l2Data...)
	packet = append(packet, l3Data...)
	packet = append(packet, l4Data...)
	packet = append(packet, config.Payload...)

	return packet, nil
}

// buildL2 builds the Ethernet header.
func (b *Builder) buildL2(config PacketConfig, payloadLen int) []byte {
	header := make([]byte, 14) // Ethernet header is 14 bytes

	// Destination MAC
	dstMAC, err := net.ParseMAC(config.L2.DstMAC)
	if err != nil && config.L2.DstMAC != "" {
		zap.L().Warn("invalid dst MAC address", zap.String("mac", config.L2.DstMAC), zap.Error(err))
	}
	if len(dstMAC) == 6 {
		copy(header[0:6], dstMAC)
	}

	// Source MAC
	srcMAC, err2 := net.ParseMAC(config.L2.SrcMAC)
	if err2 != nil && config.L2.SrcMAC != "" {
		zap.L().Warn("invalid src MAC address", zap.String("mac", config.L2.SrcMAC), zap.Error(err2))
	}
	if len(srcMAC) == 6 {
		copy(header[6:12], srcMAC)
	}

	// EtherType
	etherType := config.L2.EtherType
	if etherType == 0 {
		etherType = EtherTypeIPv4
	}
	binary.BigEndian.PutUint16(header[12:14], etherType)

	// Handle VLAN if present
	if config.L2.VLAN != nil {
		vlanHeader := make([]byte, 4)
		// VLAN tag protocol identifier (0x8100 for 802.1Q)
		binary.BigEndian.PutUint16(vlanHeader[0:2], 0x8100)
		// VLAN ID and priority
		vlanTag := (uint16(config.L2.VLAN.Priority) << 13) | (config.L2.VLAN.ID & 0x0FFF)
		binary.BigEndian.PutUint16(vlanHeader[2:4], vlanTag)

		// Insert VLAN header after EtherType
		result := make([]byte, 0, 18)
		result = append(result, header[0:12]...)
		result = append(result, vlanHeader...)
		result = append(result, header[12:14]...)
		return result
	}

	return header
}

// buildL3 builds the IPv4 header.
func (b *Builder) buildL3(config PacketConfig, payloadLen int) []byte {
	header := make([]byte, 20) // IPv4 header is 20 bytes minimum

	// Version (4) and IHL (5, 20 bytes / 4)
	header[0] = 0x45

	// DSCP and ECN: header[1] = (DSCP << 2) | (ECN & 0x03)
	header[1] = (config.L3.DSCP << 2) | (config.L3.ECN & 0x03)

	// Total length
	totalLen := 20 + payloadLen
	binary.BigEndian.PutUint16(header[2:4], uint16(totalLen))

	// Identification — use config value or generate deterministic value from seq
	ipID := config.L3.IPID
	if ipID == 0 {
		// Fallback: use lower 16 bits of sequence number for uniqueness
		ipID = uint16(config.L4.Seq & 0xFFFF)
	}
	binary.BigEndian.PutUint16(header[4:6], ipID)

	// Flags and Fragment Offset. Flags=0 means no flags (fragmentable); the DF
	// default for normal traffic is applied by L3Base at the flow-config layer.
	binary.BigEndian.PutUint16(header[6:8], (uint16(config.L3.Flags)<<13)|(config.L3.FragOffset&0x1FFF))

	// TTL
	ttl := config.L3.TTL
	if ttl == 0 {
		ttl = 64
	}
	header[8] = ttl

	// Protocol
	header[9] = config.L3.Protocol

	// Header checksum (calculated later)
	// header[10:12] = 0

	// Source IP
	srcIP := net.ParseIP(config.L3.SrcIP)
	if srcIP == nil && config.L3.SrcIP != "" {
		zap.L().Warn("invalid src IP address", zap.String("ip", config.L3.SrcIP))
	}
	if srcIP != nil {
		srcIP = srcIP.To4()
		if len(srcIP) == 4 {
			copy(header[12:16], srcIP)
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
			copy(header[16:20], dstIP)
		}
	}

	// Calculate header checksum
	checksum := calculateIPChecksum(header)
	binary.BigEndian.PutUint16(header[10:12], checksum)

	return header
}

// buildL4 builds the L4 header (TCP/UDP/ICMP).
func (b *Builder) buildL4(config PacketConfig) []byte {
	switch config.L4.Protocol {
	case "tcp":
		return b.buildTCP(config)
	case "udp":
		return b.buildUDP(config)
	case "icmp":
		return b.buildICMP(config)
	default:
		return nil
	}
}

// buildTCP builds the TCP header, including any TCP options.
func (b *Builder) buildTCP(config PacketConfig) []byte {
	// Encode options (padded to a 4-byte boundary with NOP).
	opts := encodeTCPOptions(config.L4.TCPOptions)
	dataOffset := (20 + len(opts)) / 4 // TCP header length in 4-byte words

	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], config.L4.SrcPort)
	binary.BigEndian.PutUint16(header[2:4], config.L4.DstPort)
	binary.BigEndian.PutUint32(header[4:8], config.L4.Seq)
	binary.BigEndian.PutUint32(header[8:12], config.L4.Ack)

	// Data offset (high nibble) + reserved (low nibble)
	header[12] = byte(dataOffset << 4)
	header[13] = config.L4.Flags

	winSize := config.L4.WindowSize
	if winSize == 0 {
		winSize = 65535
	}
	binary.BigEndian.PutUint16(header[14:16], winSize)

	// header[16:18] = checksum (computed below)
	binary.BigEndian.PutUint16(header[18:20], 0) // urgent pointer

	// Append options to the header before computing the checksum (the
	// checksum covers header + options + payload).
	header = append(header, opts...)

	checksum := calculateTCPChecksum(config, header, config.Payload)
	binary.BigEndian.PutUint16(header[16:18], checksum)

	return header
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

// buildUDP builds the UDP header.
func (b *Builder) buildUDP(config PacketConfig) []byte {
	header := make([]byte, 8) // UDP header is 8 bytes

	// Source port
	binary.BigEndian.PutUint16(header[0:2], config.L4.SrcPort)

	// Destination port
	binary.BigEndian.PutUint16(header[2:4], config.L4.DstPort)

	// Length (header + payload)
	length := uint16(8 + len(config.Payload))
	binary.BigEndian.PutUint16(header[4:6], length)

	// Checksum (calculated with pseudo-header)
	checksum := calculateUDPChecksum(config, config.Payload)
	binary.BigEndian.PutUint16(header[6:8], checksum)

	return header
}

// buildICMP builds the ICMP header (payload already contains ICMP data).
func (b *Builder) buildICMP(config PacketConfig) []byte {
	// ICMP header is part of the payload in our design
	// This returns empty as ICMP data is in Payload
	return nil
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
