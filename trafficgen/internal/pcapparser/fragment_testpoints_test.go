package pcapparser

// Test points for fragment.go, derived from tools/test_points/pcapparser.md
// (components FR1-FR3). REAL tests exercising FragmentReassembler directly.

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// --- FR1: AddFragment ---

func TestAddFragment_NewGroup(t *testing.T) {
	r := NewFragmentReassembler()
	key := "1|10.0.0.1|10.0.0.2|6"
	frame := buildFragInner(0x1234, 0, true, []byte("AAAA"))
	got := r.AddFragment(key, frame, 14, 0x1234, ipA, ipB, 6, 0, true)
	// Group created but not complete -> nil.
	if got != nil {
		t.Errorf("new group should not reassemble, got %d bytes", len(got))
	}
	if _, ok := r.groups[key]; !ok {
		t.Error("group not created")
	}
}

func TestAddFragment_ExistingGroup(t *testing.T) {
	r := NewFragmentReassembler()
	key := "2|10.0.0.1|10.0.0.2|6"
	r.AddFragment(key, make([]byte, 14+20+4), 14, 0x1234, ipA, ipB, 6, 0, true)
	r.AddFragment(key, make([]byte, 14+20+4), 14, 0x1234, ipA, ipB, 6, 0, true)
	if len(r.groups) != 1 {
		t.Errorf("groups = %d, want 1 (same key reused)", len(r.groups))
	}
}

func TestAddFragment_L3StartBeyondFrame(t *testing.T) {
	r := NewFragmentReassembler()
	key := "3|10.0.0.1|10.0.0.2|6"
	got := r.AddFragment(key, []byte{0, 0, 0, 0}, 100, 0, nil, nil, 0, 0, false)
	if got != nil {
		t.Errorf("l3Start beyond frame should return nil, got %d bytes", len(got))
	}
}

func TestAddFragment_IHLInvalid(t *testing.T) {
	r := NewFragmentReassembler()
	// IHL < 20 (frame[l3Start] & 0x0F) * 4 < 20
	frame := make([]byte, 14+4)
	frame[14] = 0x45 // Version=4, IHL=5 (5*4=20) -- valid, but let's try IHL=0x0 (invalid)
	// Actually we need IHL < 5: set IHL=0 -> 0*4=0 < 20
	frame[14] = 0x40 // IHL=0, invalid
	got := r.AddFragment("k", frame, 14, 0, ipA, ipB, 6, 0, false)
	if got != nil {
		t.Errorf("IHL invalid should return nil, got %d bytes", len(got))
	}
}

func TestAddFragment_FirstFragStoresBase(t *testing.T) {
	r := NewFragmentReassembler()
	key := "4|10.0.0.1|10.0.0.2|6"
	frame := buildFragInner(0x1234, 0, true, []byte("AAAA"))
	r.AddFragment(key, frame, 14, 0x1234, ipA, ipB, 6, 0, true)
	g := r.groups[key]
	if g == nil {
		t.Fatal("group not found")
	}
	if g.firstFrag == nil {
		t.Error("firstFrag not stored")
	}
	if g.l3Start != 14 {
		t.Errorf("l3Start = %d, want 14", g.l3Start)
	}
}

func TestAddFragment_NonFirstFrag(t *testing.T) {
	r := NewFragmentReassembler()
	key := "5|10.0.0.1|10.0.0.2|6"
	frame := buildFragInner(0x1234, 8, false, []byte("BBBB"))
	r.AddFragment(key, frame, 14, 0x1234, ipA, ipB, 6, 8, false)
	g := r.groups[key]
	if g == nil {
		t.Fatal("group not found")
	}
	if g.firstFrag != nil {
		t.Error("firstFrag should be nil for non-first fragment")
	}
}

func TestAddFragment_LastFragSetsTotal(t *testing.T) {
	r := NewFragmentReassembler()
	key := "6|10.0.0.1|10.0.0.2|6"
	frame := buildFragInner(0x1234, 8, false, []byte("BBBB"))
	r.AddFragment(key, frame, 14, 0x1234, ipA, ipB, 6, 8, false)
	g := r.groups[key]
	if g.totalPayloadLen != 12 {
		t.Errorf("totalPayloadLen = %d, want 12 (8+4)", g.totalPayloadLen)
	}
}

func TestAddFragment_NotLastFrag(t *testing.T) {
	r := NewFragmentReassembler()
	key := "7|10.0.0.1|10.0.0.2|6"
	frame := buildFragInner(0x1234, 0, true, []byte("AAAA"))
	r.AddFragment(key, frame, 14, 0x1234, ipA, ipB, 6, 0, true)
	g := r.groups[key]
	if g.totalPayloadLen != -1 {
		t.Errorf("totalPayloadLen = %d, want -1 (MF=1, total unknown)", g.totalPayloadLen)
	}
}

// --- FR2: tryReassemble ---

func TestTryReassemble_GapInOffsets(t *testing.T) {
	r := NewFragmentReassembler()
	key := "gap|10.0.0.1|10.0.0.2|6"
	// Add first fragment (offset 0) and last fragment (offset 8), but
	// payloads are only 4 bytes each -> cursor goes 0->4 but totalPayloadLen=8.
	// No gap between offsets, but totalPayloadLen vs cursor check.
	// Actually let's create a real gap: fragment at offset 0 and offset 16, missing offset 8.
	r.AddFragment(key, buildFragInner(0xaa, 0, true, []byte("AAAA")), 14, 0xaa, ipA, ipB, 6, 0, true)
	// Total length set to 20 (16+4) but offset 8 payload is missing.
	// We set totalPayloadLen = 20 by adding a "last" fragment at offset 16.
	r.AddFragment(key, buildFragInner(0xaa, 16, false, []byte("BBBB")), 14, 0xaa, ipA, ipB, 6, 16, false)
	// Now tryReassemble: offsets [0,16], cursor 0->4, then 16 != 4 -> gap.
	g := r.groups[key]
	if g.reassembled {
		t.Error("group should not be reassembled (gap at offset 8)")
	}
}

func TestTryReassemble_ContiguousAllPresent(t *testing.T) {
	r := NewFragmentReassembler()
	key := "cont|10.0.0.1|10.0.0.2|6"
	frag1 := buildFragInner(0xbb, 0, true, []byte("AAAA"))
	frag2 := buildFragInner(0xbb, 4, false, []byte("BBBB"))
	r.AddFragment(key, frag1, 14, 0xbb, ipA, ipB, 6, 0, true)
	reassembled := r.AddFragment(key, frag2, 14, 0xbb, ipA, ipB, 6, 4, false)
	if reassembled == nil {
		t.Fatal("contiguous fragments should reassemble")
	}
	// Verify IP header was updated.
	l3Start := 14
	totalLen := binary.BigEndian.Uint16(reassembled[l3Start+2 : l3Start+4])
	if totalLen != 28 { // 20 (IP header) + 8 (payload)
		t.Errorf("IP total length = %d, want 28", totalLen)
	}
	flagsFrag := binary.BigEndian.Uint16(reassembled[l3Start+6 : l3Start+8])
	if flagsFrag != 0 {
		t.Errorf("IP flags/frag = 0x%x, want 0 (MF=0, frag=0)", flagsFrag)
	}
	// Verify payload.
	ihl := int(reassembled[l3Start]&0x0F) * 4
	payload := string(reassembled[l3Start+ihl:])
	if payload != "AAAABBBB" {
		t.Errorf("reassembled payload = %q, want AAAABBBB", payload)
	}
}

func TestTryReassemble_SingleFragmentGroup(t *testing.T) {
	r := NewFragmentReassembler()
	key := "single|10.0.0.1|10.0.0.2|6"
	frame := buildFragInner(0xcc, 0, false, []byte("AAAA"))
	reassembled := r.AddFragment(key, frame, 14, 0xcc, ipA, ipB, 6, 0, false)
	if reassembled == nil {
		t.Fatal("single fragment (offset 0, MF=0) should reassemble")
	}
	ihl := int(reassembled[14]&0x0F) * 4
	payload := string(reassembled[14+ihl:])
	if payload != "AAAA" {
		t.Errorf("single-frag payload = %q, want AAAA", payload)
	}
}

func TestTryReassemble_MissingTail(t *testing.T) {
	r := NewFragmentReassembler()
	key := "tail|10.0.0.1|10.0.0.2|6"
	// Fragment at offset 0, MF=1 (no total known). totalPayloadLen stays -1.
	r.AddFragment(key, buildFragInner(0xdd, 0, true, []byte("AAAA")), 14, 0xdd, ipA, ipB, 6, 0, true)
	g := r.groups[key]
	// firstFrag != nil but totalPayloadLen <= 0 -> tryReassemble not called.
	if g.reassembled {
		t.Error("group should not be reassembled (no last fragment)")
	}
}

// --- FR3: Flush ---

func TestFlush_IncompleteGroups(t *testing.T) {
	r := NewFragmentReassembler()
	key := "fl1|10.0.0.1|10.0.0.2|6"
	r.AddFragment(key, buildFragInner(0xee, 0, true, []byte("AAAA")), 14, 0xee, ipA, ipB, 6, 0, true)
	discarded := r.Flush()
	if discarded != 1 {
		t.Errorf("Flush discarded = %d, want 1", discarded)
	}
	if len(r.groups) != 0 {
		t.Errorf("groups after flush = %d, want 0", len(r.groups))
	}
}

func TestFlush_AllCompleted(t *testing.T) {
	r := NewFragmentReassembler()
	key := "fl2|10.0.0.1|10.0.0.2|6"
	r.AddFragment(key, buildFragInner(0xff, 0, false, []byte("AAAA")), 14, 0xff, ipA, ipB, 6, 0, false)
	discarded := r.Flush()
	if discarded != 0 {
		t.Errorf("Flush completed = %d, want 0 (no incomplete groups)", discarded)
	}
}

func TestFlush_NoGroups(t *testing.T) {
	r := NewFragmentReassembler()
	discarded := r.Flush()
	if discarded != 0 {
		t.Errorf("Flush empty = %d, want 0", discarded)
	}
}

// buildFragInner builds a single IP fragment frame (Eth+IPv4+payload) for testing.
// This is a condensed version used by fragment tests.
func buildFragInner(ipid uint16, fragOffsetBytes int, mf bool, payload []byte) []byte {
	// For simplicity, we manually construct the bytes.
	ethLen := 14
	ihl := 20 // 5 * 4
	totalLen := ihl + len(payload)
	frame := make([]byte, ethLen+totalLen)
	// Ethernet header (zeros for src/dst MAC).
	frame[12] = 0x08 // EtherType IPv4
	frame[13] = 0x00
	// IP header.
	l3Start := ethLen
	frame[l3Start] = 0x45 // Version=4, IHL=5
	frame[l3Start+1] = 0  // DSCP/ECN
	binary.BigEndian.PutUint16(frame[l3Start+2:l3Start+4], uint16(totalLen))
	binary.BigEndian.PutUint16(frame[l3Start+4:l3Start+6], ipid)
	flagsFrag := uint16(fragOffsetBytes / 8) // fragment offset in 8-byte units
	if mf {
		flagsFrag |= 0x2000 // MF bit
	}
	binary.BigEndian.PutUint16(frame[l3Start+6:l3Start+8], flagsFrag)
	frame[l3Start+8] = 64  // TTL
	frame[l3Start+9] = 6   // TCP protocol
	// Checksum field (placeholder)
	frame[l3Start+10] = 0
	frame[l3Start+11] = 0
	// Source IP
	copy(frame[l3Start+12:l3Start+16], ipA.To4())
	// Dest IP
	copy(frame[l3Start+16:l3Start+20], ipB.To4())
	// Payload
	copy(frame[l3Start+20:], payload)
	return frame
}

// --- FR-INTG: First-packet-is-fragment (SIMULATED via Parse) ---

// TestParse_FirstPacketIsFragment_NoHandshake verifies that a PCAP whose very
// first packet is an IP fragment (no prior handshake) still creates a TCP flow
// with the reassembled payload in the c2s stream. This is the "first packet
// is fragment" critical path.
func TestParse_FirstPacketIsFragment_NoHandshake(t *testing.T) {
	origData := buildTCPFrame(t, macA, macB, ipA, ipB, 1234, 80, 101, 201, flagPSH|flagACK, []byte("Hello Fragmented Only"))
	ipPayload := origData[34:] // after Eth(14)+IP(20)
	splitAt := 24
	frag1Payload := ipPayload[:splitAt]
	frag2Payload := ipPayload[splitAt:]

	buildFrag := func(ipid uint16, fragOffsetUnits uint16, mf bool, payload []byte) []byte {
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		var fl layers.IPv4Flag
		if mf {
			fl = layers.IPv4MoreFragments
		}
		ipv4 := &layers.IPv4{SrcIP: ipA, DstIP: ipB, Id: ipid, Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, Flags: fl, FragOffset: fragOffsetUnits}
		gopacket.SerializeLayers(buf, opts, &layers.Ethernet{SrcMAC: macA, DstMAC: macB, EthernetType: layers.EthernetTypeIPv4}, ipv4, gopacket.Payload(payload))
		return buf.Bytes()
	}
	frames := [][]byte{
		buildFrag(0xABCD, 0, true, frag1Payload),
		buildFrag(0xABCD, 3, false, frag2Payload),
	}
	ts := []time.Time{time.UnixMicro(1), time.UnixMicro(2)}
	payloadsPath := filepath.Join(t.TempDir(), "frag-first.payloads")
	path := writePcap(t, frames, ts)
	analysis, err := Parse(path, &Options{PcapAssetID: "ast1", UserID: "u1", PayloadsPath: payloadsPath})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var tcpFlow *storage.FlowModel
	for i := range analysis.Flows {
		if analysis.Flows[i].L4Protocol == "tcp" {
			tcpFlow = &analysis.Flows[i]
			break
		}
	}
	if tcpFlow == nil {
		t.Fatal("no TCP flow created from first-packet-is-fragment")
	}
	if tcpFlow.C2SLength == 0 {
		t.Fatal("C2SLength = 0; reassembled stream not materialized")
	}
	got, err := readBytesAt(payloadsPath, tcpFlow.C2SOffset, int(tcpFlow.C2SLength))
	if err != nil {
		t.Fatalf("read payloads: %v", err)
	}
	if !strings.Contains(string(got), "Hello Fragmented Only") {
		t.Errorf("fragmented-only TCP did not reassemble; c2s stream = %q", string(got))
	}
	// HandshakeStatus should be "none" (no SYN captured, only fragments).
	if tcpFlow.HandshakeStatus != "none" {
		t.Errorf("HandshakeStatus = %q, want none (no SYN captured)", tcpFlow.HandshakeStatus)
	}
}