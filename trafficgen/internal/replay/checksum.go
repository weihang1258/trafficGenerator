package replay

import (
	"encoding/binary"

	"github.com/trafficgen/trafficgen/internal/pcapparser"
)

// setIPChecksum recomputes the IPv4 header checksum (§11). The IP header is
// 20 bytes (IHL=5, no options) at layout.L3Start; the checksum field is at
// L3Start+10. Zero the field, sum the 20 bytes as 10 uint16s, ones-complement.
func setIPChecksum(frame []byte, layout pcapparser.OffsetLayout) {
	l3 := layout.L3Start
	if l3 < 0 || l3+20 > len(frame) {
		return
	}
	// Zero the existing checksum.
	binary.BigEndian.PutUint16(frame[l3+10:l3+12], 0)
	sum := uint32(0)
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(frame[l3+i : l3+i+2]))
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	binary.BigEndian.PutUint16(frame[l3+10:l3+12], ^uint16(sum))
}

// setL4Checksum recomputes the L4 (TCP/UDP) checksum with the IPv4 pseudo-header
// (§11). The pseudo-header = SrcIP(4) + DstIP(4) + zero(1) + protocol(1) +
// L4-length(2). L4-length = frame length - L4Start (header + payload).
func setL4Checksum(frame []byte, layout pcapparser.OffsetLayout) {
	l3 := layout.L3Start
	l4 := layout.L4Start
	if l3 < 0 || l4 < 0 || l4 >= len(frame) {
		return
	}
	var proto byte
	var cksumOff int
	switch layout.L4Protocol {
	case "tcp":
		proto = 6
		cksumOff = l4 + 16
	case "udp":
		proto = 17
		cksumOff = l4 + 6
	default:
		return // ICMP/ARP: no pseudo-header checksum to recompute
	}
	if cksumOff+2 > len(frame) {
		return
	}
	// Zero the existing checksum.
	binary.BigEndian.PutUint16(frame[cksumOff:cksumOff+2], 0)

	l4Len := len(frame) - l4 // header + payload

	sum := uint32(0)
	// Pseudo-header: SrcIP(4) + DstIP(4).
	if l3+20 <= len(frame) {
		sum += uint32(binary.BigEndian.Uint16(frame[l3+12 : l3+14])) // SrcIP hi
		sum += uint32(binary.BigEndian.Uint16(frame[l3+14 : l3+16])) // SrcIP lo
		sum += uint32(binary.BigEndian.Uint16(frame[l3+16 : l3+18])) // DstIP hi
		sum += uint32(binary.BigEndian.Uint16(frame[l3+18 : l3+20])) // DstIP lo
	}
	sum += uint32(proto)
	sum += uint32(l4Len)

	// L4 header + payload (checksum field already zeroed).
	for i := 0; i+1 < l4Len; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(frame[l4+i : l4+i+2]))
	}
	if l4Len%2 == 1 {
		// Odd trailing byte: pad with zero (network checksum convention).
		sum += uint32(frame[l4+l4Len-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	binary.BigEndian.PutUint16(frame[cksumOff:cksumOff+2], ^uint16(sum))
}
