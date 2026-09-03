package layers

import (
	"encoding/binary"
	"errors"
	"net"
)

// IPCksumComputer implements end-to-end IP/TCP/UDP checksum computation.
// It is a pure-logic component: given raw bytes, it produces the correct
// checksum value. It does NOT read or write network interfaces.
//
// The primary design constraint is zero-copy checksum computation over slices
// that may be owned by callers. Every method accepts []byte inputs and
// returns uint16 (the checksum field value); callers write the result into
// the appropriate header offset. This matches the legacy builder.go pattern
// but exposes the computation as a standalone, testable unit.
//
// Usage from a transport layer generator:
//
//	// Pseudo-header:
//	sum := c.ComputeIPv4PseudoHdrSum(srcIP, dstIP, 6, uint16(len(tcpHdr)+len(payload)))
//	// L4 data:
//	sum = c.FinalizeTCPOrUDPChecksum(sum, append(tcpHdr, payload...))
//	cksum := c.Finalize(sum)
//
// Fragment reassembly (AssembleAndVerify) is provided as an optional
// pre-computation step for cases where a chain generator receives
// pre-fragmented IP fragments and needs to assemble them before computing
// the transport checksum. Chain-driven generation typically does NOT
// generate fragments by default; the reassembly path covers edge cases
// (e.g. tunneling where an outer layer generator receives pre-fragmented
// inner packets).
//
// Concurrency: IPCksumComputer is stateless and thus safe for concurrent
// use across goroutines without synchronization.

type IPCksumComputer struct{}

// NewIPCksumComputer constructs a new checksum computer.
func NewIPCksumComputer() *IPCksumComputer {
	return &IPCksumComputer{}
}

// ComputeIPv4HdrChecksum computes the IP header checksum per RFC 791 §3.1:
// the 16-bit one's-complement of the one's-complement sum of all 16-bit words
// in the header. The caller supplies the full header (20 or 60 bytes for
// IPv4; v4 option area is included). The checksum field itself (bytes 10–11)
// MUST be zero before calling; the result is returned as a uint16 and the
// caller writes it back at offset 10.
//
// Returns 0 on a zero-length input (degenerate but well-defined: all-ones
// sum → 0 → one's complement = 0xFFFF → ^0xFFFF = 0).
//
// Caller responsibility: the caller zeros the checksum bytes before calling,
// and writes the result back. Failure to zero results in an incorrect sum.
// We deliberately do NOT mutate the input slice to keep this a pure function.
func (c *IPCksumComputer) ComputeIPv4HdrChecksum(header []byte) uint16 {
	sum := c.foldSum16(c.sum16(header))
	return uint16(^sum)
}

// ComputeIPv4PseudoHdrSum computes the TCP/UDP pseudo-header sum for IPv4.
// Per RFC 793 §3.1 and RFC 768: pseudo-header (srcIP + dstIP + zero +
// proto + TCP/UDP length) is summed first; the L4 header and payload are
// added separately via FinalizeTCPOrUDPChecksum.
//
// Proto is the IP protocol number (6 = TCP, 17 = UDP). Length is the
// TCP/UDP header + payload length in bytes (same as network byte order).
//
// Returns a uint32 accumulator; callers pass it to FinalizeTCPOrUDPChecksum
// along with the L4 bytes. Returns 0 on a nil/empty input (degenerate).
func (c *IPCksumComputer) ComputeIPv4PseudoHdrSum(srcIP, dstIP net.IP, proto uint8, length uint16) uint32 {
	// IPv4 pseudo-header (RFC 793 §3.1): src(4) + dst(4) + zero(1) + proto(1) + len(2) = 12 bytes.
	src := srcIP.To4()
	dst := dstIP.To4()
	if src == nil || dst == nil {
		return 0
	}
	// Accumulate into a uint32 as 16-bit words (RFC 793 §3.1):
	// src(2 words) + dst(2 words) + zero+proto(1 word) + length(1 word).
	var acc uint32
	for i := 0; i < 4; i += 2 {
		acc += uint32(src[i])<<8 | uint32(src[i+1])
		acc += uint32(dst[i])<<8 | uint32(dst[i+1])
	}
	acc += uint32(proto)
	acc += uint32(length)
	return acc
}

// ComputeIPv6PseudoHdrSum computes the TCP/UDP pseudo-header sum for IPv6.
// Per RFC 8200 §8.1: srcIP(16) + dstIP(16) + UpperLayerLen(4) + zero(3) +
// NextHeader(1) = 40 bytes. UpperLayerLen is the TCP/UDP header + payload
// length in bytes. Proto is the next-header (6 = TCP, 17 = UDP).
//
// Returns a uint32 accumulator; callers pass it to FinalizeTCPOrUDPChecksum.
// Returns 0 on a nil/empty input.
func (c *IPCksumComputer) ComputeIPv6PseudoHdrSum(srcIP, dstIP net.IP, proto uint8, upperLayerLen uint32) uint32 {
	src := srcIP.To16()
	dst := dstIP.To16()
	if src == nil || dst == nil {
		return 0
	}
	var acc uint32
	for i := 0; i < 16; i++ {
		acc += uint32(src[i])
		acc += uint32(dst[i])
	}
	// Upper layer length (4 bytes, network byte order).
	acc += uint32(upperLayerLen >> 24)
	acc += uint32((upperLayerLen >> 16) & 0xff)
	acc += uint32((upperLayerLen >> 8) & 0xff)
	acc += uint32(upperLayerLen & 0xff)
	// zero(3) + next header.
	acc += uint32(proto)
	return acc
}

// FinalizeTCPOrUDPChecksum adds L4 header + payload bytes to the pseudo-header
// accumulator and returns the intermediate uint32. Callers pass the result
// to Finalize to get the final one's-complement checksum. This two-step
// pattern avoids allocating a merged slice for concatenation: callers can
// call this method once per chunk without copying.
func (c *IPCksumComputer) FinalizeTCPOrUDPChecksum(pseudoSum uint32, data []byte) uint32 {
	// Sum 16-bit words across the L4 data.
	dataSum := c.foldSum16(c.sum16(data))
	return pseudoSum + dataSum
}

// Finalize converts a folded uint32 accumulator (from FinalizeTCPOrUDPChecksum
// or ComputeIPv4PseudoHdrSum + sum16) into the final one's-complement checksum
// uint16 value. RFC 793 §3.1: sum (uint32) → high 16 + low 16 → add carry → one's complement.
//
// The returned uint16 is the checksum field value. Callers write it into
// the header at the appropriate offset (byte 16 for TCP/UDP, byte 10 for IPv4).
//
// Degenerate cases: sum=0 → ^0 = 0xFFFF (correct per RFC 1624 Eq.3 for
// an all-ones header); this correctly handles the all-zeros payload case.
func (c *IPCksumComputer) Finalize(sum uint32) uint16 {
	// Fold 32-bit sum to 16 bits.
	sum = c.foldSum16(sum)
	return ^uint16(sum)
}

// AssembleAndVerify reassembles IPv4 fragments and verifies the IPv4 header
// checksum of the reassembled datagram. It is a pre-computation step for
// edge cases where an outer-layer generator receives pre-fragmented IP
// packets and needs to validate them before computing the transport checksum.
//
// RFC 791 §3.1: every fragment carries the same Identification field; the
// reassembled datagram's total length is the sum of all fragment payload
// lengths. Only the last fragment has MF=0. This function does NOT handle
// IPv6 fragments (fragment header, RFC 8200 §4.5) — callers receiving IPv6
// fragments should use a separate reassembly path.
//
// Errors:
//   - ErrFragmentOverlap: two fragments' data ranges overlap.
//   - ErrFragmentUnderflow: a fragment's offset × 8 > total length.
//   - ErrFragmentIncomplete: MF=1 but no more fragments (incomplete reassembly).
//   - ErrFragmentChecksum: the reassembled header's checksum does not verify
//     (the last fragment carries the header; caller must have verified it
//     before passing it here).
func (c *IPCksumComputer) AssembleAndVerify(frags []FragmentInput) ([]byte, error) {
	if len(frags) == 0 {
		return nil, errors.New("no fragments provided")
	}
	// Find the fragment with the header (offset 0). It must be frags[0]
	// or the function will return an error.
	var hdrFrag *FragmentInput
	for i := range frags {
		if frags[i].Offset == 0 {
			hdrFrag = &frags[i]
			break
		}
	}
	if hdrFrag == nil {
		return nil, errors.New("no header fragment (offset 0) found")
	}
	totalLen := 0
	// seen records each 8-byte page already covered by a fragment
	// (page = absolute byte offset / 8). A page already present when a
	// later fragment touches it means the two fragments' data ranges
	// overlap → reject (RFC 791 fragments must tile the datagram
	// disjointly).
	seen := make(map[uint16]bool)
	for _, f := range frags {
		start := int(f.Offset) * 8
		end := start + len(f.Payload)
		if start < 0 || end < start {
			return nil, ErrFragmentUnderflow
		}
		// Check for overlap with any already-assembled region.
		for off := start; off < end; off += 8 {
			page := uint16(off / 8)
			if seen[page] {
				return nil, ErrFragmentOverlap
			}
			seen[page] = true
		}
		if end > totalLen {
			totalLen = end
		}
	}
	// Verify last fragment has MF=0.
	lastMF := frags[len(frags)-1].MoreFragments
	if lastMF {
		return nil, ErrFragmentIncomplete
	}
	// Assemble into a single buffer.
	buf := make([]byte, totalLen)
	// Copy header.
	copy(buf, hdrFrag.Payload[:len(hdrFrag.Payload)])
	// Copy data fragments.
	for _, f := range frags {
		if f.Offset == 0 {
			continue
		}
		offsetBytes := int(f.Offset) * 8
		copy(buf[offsetBytes:], f.Payload)
	}
	// Verify the reassembled IPv4 header checksum.
	// buf[0] is the version/ihl byte: high nibble = version, low = ihl.
	// ihl is in 32-bit words; header length = ihl * 4 bytes.
	ihl := int(buf[0]&0x0F) * 4
	if ihl < 20 || ihl > len(buf) {
		return nil, errors.New("invalid IPv4 header length in reassembled datagram")
	}
	// Verify checksum of the reassembled header.
	stored := binary.BigEndian.Uint16(buf[10:12])
	buf[10], buf[11] = 0, 0 // zero checksum field per ComputeIPv4HdrChecksum contract
	computed := c.ComputeIPv4HdrChecksum(buf[:ihl])
	if stored != computed {
		return nil, ErrFragmentChecksum
	}
	return buf, nil
}

// ErrFragmentOverlap is returned by AssembleAndVerify when two fragments'
// data ranges overlap.
var ErrFragmentOverlap = errors.New("fragment overlap detected")

// ErrFragmentUnderflow is returned when a fragment's byte offset exceeds
// the total reassembled length.
var ErrFragmentUnderflow = errors.New("fragment offset underflow")

// ErrFragmentIncomplete is returned when MF=1 but reassembly is complete
// (missing the final fragment).
var ErrFragmentIncomplete = errors.New("fragment reassembly incomplete (MF=1)")

// ErrFragmentChecksum is returned when the reassembled IPv4 header checksum
// does not match the stored value.
var ErrFragmentChecksum = errors.New("reassembled IPv4 header checksum mismatch")

// FragmentInput describes one IPv4 fragment for reassembly.
type FragmentInput struct {
	// Payload is the raw IP payload bytes (starting at the IP header).
	// For offset > 0 fragments this includes everything after the IP header
	// that belongs to the fragment; the IP header itself is only needed
	// from the offset-0 fragment.
	Payload []byte
	// Offset is the fragment offset in 8-byte units (IPv4 frag offset field,
	// RFC 791 §3.1). Zero for the fragment carrying the IP header.
	Offset uint16
	// MoreFragments is true when more fragments follow (IPv4 MF flag).
	MoreFragments bool
}

// sum16 computes the uint32 sum of all 16-bit big-endian words in data.
// Trailing odd byte is summed as a zero-padded high byte (RFC 1071 §2).
// The uint32 return avoids overflow in the caller's accumulator.
func (c *IPCksumComputer) sum16(data []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	return sum
}

// foldSum16 folds a uint32 accumulator to 16 bits by adding the high 16
// bits to the low 16 bits until no further carry occurs. This is the
// checksum fold step from RFC 1071 §3 and RFC 793 §3.1.
func (c *IPCksumComputer) foldSum16(sum uint32) uint32 {
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum
}
