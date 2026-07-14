package pcapparser

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
)

// FragmentReassembler buffers IP fragments per (IPID+src+dst+proto) group and
// reassembles a complete IP datagram when all fragments arrive (§8). The
// reassembled datagram is then fed to TCP reassembly instead of the individual
// fragments (which lack the L4 header on non-first fragments).
//
// v1 handles the common cases: in-order and out-of-order arrival, complete
// groups. Incomplete groups (missing fragments) are discarded at flush time --
// their packets are still indexed (FragGroupID/FragOffset on PacketModel) but
// not TCP-reassembled, since a partial segment cannot be reassembled correctly.
type FragmentReassembler struct {
	groups map[string]*fragmentGroup
}

type fragmentGroup struct {
	srcIP, dstIP net.IP
	ipid         uint16
	proto        uint8
	// firstFrag is the first fragment's full frame bytes (L2+L3+L4+payload),
	// used as the base for the reassembled frame (its L2+L3 header is reused).
	firstFrag []byte
	// l3Start is the byte offset of the IP header within firstFrag.
	l3Start int
	// payloads maps fragment-offset (bytes) -> IP payload bytes (the bytes after
	// the IP header). The first fragment's payload includes the L4 header.
	payloads map[int][]byte
	// totalPayloadLen is the reassembled IP payload length once the last
	// fragment (MF=0) arrives; until then it's -1 (unknown).
	totalPayloadLen int
	reassembled     bool
}

// NewFragmentReassembler creates an empty reassembler.
func NewFragmentReassembler() *FragmentReassembler {
	return &FragmentReassembler{groups: make(map[string]*fragmentGroup)}
}

// fragGroupKey builds the fragment-group key (IPID+src+dst+proto).
func fragGroupKey(ipid uint16, src, dst net.IP, proto uint8) string {
	return fmt.Sprintf("%d|%s|%s|%d", ipid, src.String(), dst.String(), proto)
}

// AddFragment records a fragmented packet's frame bytes + IP header offset.
// moreFragments is the IP MF flag; fragOffsetBytes is the fragment offset in
// bytes (IP frag offset * 8). Returns the reassembled frame bytes when the
// group becomes complete, else nil.
func (r *FragmentReassembler) AddFragment(key string, frame []byte, l3Start int, ipid uint16, src, dst net.IP, proto uint8, fragOffsetBytes int, moreFragments bool) []byte {
	g, ok := r.groups[key]
	if !ok {
		g = &fragmentGroup{
			srcIP: src, dstIP: dst, ipid: ipid, proto: proto,
			payloads:        map[int][]byte{},
			totalPayloadLen: -1,
		}
		r.groups[key] = g
	}
	// IP payload = bytes after the IP header, length = IP total length - IHL.
	// Use the IP total-length field (NOT len(frame)-l3End) so Ethernet padding
	// (gopacket pads short frames to 60B) isn't treated as payload.
	if l3Start+4 > len(frame) {
		return nil
	}
	ihl := int(frame[l3Start] & 0x0F) * 4
	if ihl < 20 || l3Start+ihl > len(frame) {
		return nil
	}
	totalLen := int(binary.BigEndian.Uint16(frame[l3Start+2 : l3Start+4]))
	ipPayloadLen := totalLen - ihl
	if ipPayloadLen < 0 || l3Start+ihl+ipPayloadLen > len(frame) {
		return nil
	}
	l3End := l3Start + ihl
	ipPayload := make([]byte, ipPayloadLen)
	copy(ipPayload, frame[l3End:l3End+ipPayloadLen])
	g.payloads[fragOffsetBytes] = ipPayload
	if fragOffsetBytes == 0 {
		// First fragment: keep the full frame as the reassembly base.
		g.firstFrag = frame
		g.l3Start = l3Start
	}
	if !moreFragments {
		// Last fragment: total payload length = this fragment's offset + its
		// payload length.
		g.totalPayloadLen = fragOffsetBytes + len(ipPayload)
	}
	// Try to reassemble if we have the first fragment and know the total length.
	if g.firstFrag != nil && g.totalPayloadLen > 0 && !g.reassembled {
		if reassembled := g.tryReassemble(); reassembled != nil {
			g.reassembled = true
			return reassembled
		}
	}
	return nil
}

// tryReassemble builds the reassembled frame if all fragments are present
// (offsets 0..totalPayloadLen contiguous). Returns nil if a gap remains.
func (g *fragmentGroup) tryReassemble() []byte {
	// Verify contiguity: walk offsets 0..total, ensuring each byte range is filled.
	offsets := make([]int, 0, len(g.payloads))
	for off := range g.payloads {
		offsets = append(offsets, off)
	}
	sort.Ints(offsets)
	cursor := 0
	var assembled []byte
	for _, off := range offsets {
		if off != cursor {
			return nil // gap
		}
		assembled = append(assembled, g.payloads[off]...)
		cursor = off + len(g.payloads[off])
	}
	if cursor != g.totalPayloadLen {
		return nil // missing tail fragment
	}
	// Build the reassembled frame: first fragment's L2+L3 header (updated) +
	// the assembled IP payload.
	l3Start := g.l3Start
	ihl := int(g.firstFrag[l3Start] & 0x0F) * 4
	l3End := l3Start + ihl
	out := make([]byte, l3End+len(assembled))
	copy(out[:l3End], g.firstFrag[:l3End])
	copy(out[l3End:], assembled)
	// Update the IP header: total length (bytes 2:4), MF=0 + frag offset=0 (bytes 6:8).
	binary.BigEndian.PutUint16(out[l3Start+2:l3Start+4], uint16(ihl+len(assembled)))
	binary.BigEndian.PutUint16(out[l3Start+6:l3Start+8], 0)
	// Recompute IP header checksum (zero the field, sum, ones-complement).
	binary.BigEndian.PutUint16(out[l3Start+10:l3Start+12], 0)
	sum := uint32(0)
	for i := 0; i < ihl; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(out[l3Start+i : l3Start+i+2]))
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	binary.BigEndian.PutUint16(out[l3Start+10:l3Start+12], ^uint16(sum))
	return out
}

// Flush discards incomplete fragment groups. Called at end-of-file; returns the
// count of discarded groups (for diagnostics).
func (r *FragmentReassembler) Flush() int {
	n := 0
	for k, g := range r.groups {
		if !g.reassembled {
			n++
		}
		delete(r.groups, k)
	}
	return n
}
