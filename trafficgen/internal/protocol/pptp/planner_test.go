package pptp

// PPTP/RFC 2637 planner tests, derived from
// /tmp/l7_planner_design/testcases_pptp.md (§1 消息字节 / §2 Validate /
// §3 场景与多会话 / §4 端口与数据面) and the reference pcap
// /home/pcap_auto/llcj_mirror/IP-TCP-10.6.2.41-20.6.2.41-49194-1723-12-10-
// 1260-980.pcap (PNS = client 49194, PAC = server 1723).
//
// The default "full" scenario reproduces the reference control plane
// byte-for-byte: SCCRQ 156B → SCCRP 156B → OCRQ 168B → OCRP 32B → SLI×5
// → GRE data → CCRQ down → [CCRQ+CCDN merged 164B] up → CCDN down 148B →
// StopRQ/StopRP, including the reference quirks (SLI-down peer call id =
// the PNS side's TCP source port 0xc02a; CCDN carries the PNS call id in
// both directions). The GRE data plane follows RFC 2637 §4.1 (flags
// 0x3081, protocol 0x880B, Key = Payload Length + peer Call ID).

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- helpers ---

func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return drain(ch)
}

// pptpSpec returns a spec with the reference pcap's tuple (client 49194 →
// server 1723) and the given PPTP config. The reference defaults for the
// frame counts are applied here, mirroring parsePPTPConfig's getIntPresence
// (absent keys → reference defaults; explicit 0 stays 0).
func pptpSpec(cfg *core.PPTPConfig) core.FlowSpec {
	if cfg == nil {
		cfg = &core.PPTPConfig{}
	}
	if cfg.DataFrames == 0 {
		cfg.DataFrames = 3
	}
	if cfg.DownDataFrames == 0 {
		cfg.DownDataFrames = 2
	}
	if cfg.SLICount == 0 {
		cfg.SLICount = 5
	}
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 49194, DstPort: 1723,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
	}
	spec.PPTP = cfg
	return spec
}

func hexStr(b []byte) string { return hex.EncodeToString(b) }

func assertHex(t *testing.T, got []byte, wantHex, what string) {
	t.Helper()
	if h := hexStr(got); h != wantHex {
		t.Fatalf("%s: got %s want %s", what, h, wantHex)
	}
}

// tcpData returns the TCP payloads (direction, bytes) of data frames, in
// order. GRE data frames (no L4) are excluded.
type tcpDataMsg struct {
	dir     string
	payload []byte
}

func tcpData(cfgs []core.PacketConfig) []tcpDataMsg {
	var out []tcpDataMsg
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" && len(c.Payload) > 0 {
			out = append(out, tcpDataMsg{c.Direction, append([]byte(nil), c.Payload...)})
		}
	}
	return out
}

func msgs(cfgs []core.PacketConfig, dir string) [][]byte {
	var out [][]byte
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" && len(c.Payload) > 0 && c.Direction == dir {
			out = append(out, append([]byte(nil), c.Payload...))
		}
	}
	return out
}

// greFrames returns the GRE data frames (L2.GRE set), in order.
func greFrames(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if c.L2.GRE != nil {
			out = append(out, c)
		}
	}
	return out
}

// msgType returns the Control Message Type of a control payload (bytes
// 8:10 of the 12-byte control header).
func msgType(payload []byte) uint16 { return binary.BigEndian.Uint16(payload[8:10]) }

func zeros(n int) string { return strings.Repeat("00", n) }

// checksum16 verifies a 16-bit one's-complement region: folding every
// word (checksum included) must yield 0xFFFF.
func checksum16OK(b []byte) bool {
	sum := uint32(0)
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return uint16(sum) == 0xffff
}

// --- reference message bytes (testcases_pptp.md §3) ---

var (
	hdrSCCRQ = "009c00011a2b3c4d00010000" // 12B headers with Length field
	hdrSCCRP = "009c00011a2b3c4d00020000"
	hdrStopR = "001000011a2b3c4d00030000"
	hdrStopP = "001000011a2b3c4d00040000"
	hdrECRQ  = "001000011a2b3c4d00050000"
	hdrECRP  = "001400011a2b3c4d00060000"
	hdrOCRQ  = "00a800011a2b3c4d00070000"
	hdrOCRP  = "002000011a2b3c4d00080000"
	hdrICRQ  = "00dc00011a2b3c4d00090000"
	hdrICRP  = "001800011a2b3c4d000a0000"
	hdrICCN  = "001c00011a2b3c4d000b0000"
	hdrCCRQ  = "001000011a2b3c4d000c0000"
	hdrCCDN  = "009400011a2b3c4d000d0000"
	hdrWEN   = "002800011a2b3c4d000e0000"
	hdrSLI   = "001800011a2b3c4d000f0000"

	sccrqBytes = hdrSCCRQ + "0100" + "0000" + "00000001" + "00000001" + "0000" + "0000" +
		zeros(64) + "4d6963726f736f6674" + zeros(55) // 156B
	sccrpBytes = hdrSCCRP + "0100" + "01" + "00" + "00000002" + "00000003" + "0000" + "0ece" +
		zeros(64) + "4d6963726f736f6674" + zeros(55) // 156B
	ocrqBytes = hdrOCRQ + "a9c0" + "0003" + "0000012c" + "05f5e100" + "00000003" + "00000003" +
		"0040" + "0000" + "0000" + "0000" +
		zeros(64) + "011f423a6484e94caf72892a29b1d3ab" + zeros(48) // 168B
	ocrpBytes = hdrOCRP + "35c9" + "a9c0" + "01" + "00" + "0000" + "00e1f505" + "4000" + "0000" + "00000000" // 32B
	sliUp   = hdrSLI + "35c9" + "0000" + "ffffffff" + "ffffffff"                                         // 24B
	sliDown = hdrSLI + "c02a" + "0000" + "ffffffff" + "ffffffff" // quirk: PNS side TCP source port
	ccrqUp  = hdrCCRQ + "a9c0" + "0000"                           // 16B
	ccrqDn  = hdrCCRQ + "35c9" + "0000"
	ccdnMsg = hdrCCDN + "a9c0" + "00" + "00" + "0000" + "0000" + zeros(128) // 148B, PNS id both dirs
	stopRQ  = hdrStopR + "01" + "00" + "0000"                               // 16B
	stopRP  = hdrStopP + "01" + "00" + "0000"
	merged  = ccrqUp + ccdnMsg // CCRQ+CCDN merged single segment, 164B
	ecrqMsg = hdrECRQ + "00000001"                                          // 16B
	ecrpMsg = hdrECRP + "00000001" + "01" + "00" + "0000"                   // 20B
	wenMsg  = hdrWEN + "a9c0" + "0000" + zeros(24)                          // 40B
	icrqMsg = hdrICRQ + "35c9" + "0003" + "00000003" + "00000000" + "0000" + "0000" +
		zeros(64) + zeros(64) + "011f423a6484e94caf72892a29b1d3ab" + zeros(48) // 220B
	icrpMsg = hdrICRP + "a9c0" + "35c9" + "01" + "00" + "4000" + "0000" + "0000" // 24B
	iccnMsg = hdrICCN + "a9c0" + "0000" + "00e1f505" + "4000" + "0000" + "00000003" // 28B
)

// --- §1 控制消息字节 (1.1-1.10) ---

// 1.1: every control message carries the 12B fixed header (Length = msg
// size incl. header, Message Type = 1, Magic Cookie = 0x1a2b3c4d, Reserved
// = 0), and the default full flow yields the reference 14 segments / 15
// messages (the merged CCRQ+CCDN segment splits into two messages).
func TestPlanner_ControlHeader(t *testing.T) {
	cfgs := mustPlan(t, NewPlanner(), pptpSpec(&core.PPTPConfig{}))
	segments := 0
	counts := map[uint16]int{}
	for _, m := range tcpData(cfgs) {
		segments++
		pos := 0
		for pos < len(m.payload) {
			if len(m.payload)-pos < 12 {
				t.Fatalf("trailing %d bytes < 12B control header: % x", len(m.payload)-pos, m.payload[pos:])
			}
			length := int(binary.BigEndian.Uint16(m.payload[pos : pos+2]))
			if length < 12 || pos+length > len(m.payload) {
				t.Fatalf("Length field %d out of bounds at offset %d (segment len %d)", length, pos, len(m.payload))
			}
			msg := m.payload[pos : pos+length]
			if got := binary.BigEndian.Uint16(msg[2:4]); got != 1 {
				t.Errorf("Message Type = %d, want 1", got)
			}
			if got := binary.BigEndian.Uint32(msg[4:8]); got != 0x1a2b3c4d {
				t.Errorf("Magic Cookie = %08x, want 1a2b3c4d", got)
			}
			if got := binary.BigEndian.Uint16(msg[10:12]); got != 0 {
				t.Errorf("Reserved = %d, want 0", got)
			}
			if length != len(msg) {
				t.Errorf("Length %d != message bytes %d (must count the header)", length, len(msg))
			}
			counts[binary.BigEndian.Uint16(msg[8:10])]++
			pos += length
		}
	}
	if segments != 14 {
		t.Errorf("TCP data segments = %d, want 14", segments)
	}
	want := map[uint16]int{1: 1, 2: 1, 3: 1, 4: 1, 7: 1, 8: 1, 12: 2, 13: 2, 15: 5}
	for typ, n := range want {
		if counts[typ] != n {
			t.Errorf("control message type %d count = %d, want %d", typ, counts[typ], n)
		}
	}
}

// 1.2: SCCRQ 156B byte-exact (reference pcap, PNS → PAC).
func TestPlanner_SCCRQ_Bytes(t *testing.T) {
	cfgs := mustPlan(t, NewPlanner(), pptpSpec(&core.PPTPConfig{}))
	up := msgs(cfgs, "up")
	if len(up) == 0 {
		t.Fatal("no up data messages")
	}
	assertHex(t, up[0], sccrqBytes, "SCCRQ")
}

// 1.3: SCCRP 156B byte-exact; Result/Error Code are 1 byte each.
func TestPlanner_SCCRP_Bytes(t *testing.T) {
	cfgs := mustPlan(t, NewPlanner(), pptpSpec(&core.PPTPConfig{}))
	down := msgs(cfgs, "down")
	if len(down) == 0 {
		t.Fatal("no down data messages")
	}
	assertHex(t, down[0], sccrpBytes, "SCCRP")
}

// 1.4: OCRQ 168B byte-exact, including the reference sub-address garbage.
func TestPlanner_OCRQ_Bytes(t *testing.T) {
	cfgs := mustPlan(t, NewPlanner(), pptpSpec(&core.PPTPConfig{}))
	up := msgs(cfgs, "up")
	assertHex(t, up[1], ocrqBytes, "OCRQ")
}

// 1.5: OCRP 32B byte-exact (PAC self-reported 0x35c9 + peer 0xa9c0).
func TestPlanner_OCRP_Bytes(t *testing.T) {
	cfgs := mustPlan(t, NewPlanner(), pptpSpec(&core.PPTPConfig{}))
	down := msgs(cfgs, "down")
	assertHex(t, down[1], ocrpBytes, "OCRP")
}

// 1.6: SLI 24B both directions; the PAC-side SLI uses the PNS side's TCP
// source port 0xc02a (reference quirk) instead of the PNS call id.
func TestPlanner_SLI_Bytes(t *testing.T) {
	cfgs := mustPlan(t, NewPlanner(), pptpSpec(&core.PPTPConfig{}))
	up, down := msgs(cfgs, "up"), msgs(cfgs, "down")
	// Reference alternation: up/down/up/down/up.
	assertHex(t, up[2], sliUp, "SLI #0 (up)")
	assertHex(t, down[2], sliDown, "SLI #1 (down, peer = PNS TCP source port)")
	assertHex(t, up[3], sliUp, "SLI #2 (up)")
	assertHex(t, down[3], sliDown, "SLI #3 (down)")
	assertHex(t, up[4], sliUp, "SLI #4 (up)")
}

// 1.7: CCRQ 16B (sender's own id) + CCDN 148B (PNS id in both directions).
func TestPlanner_CCRQ_CCDN_Bytes(t *testing.T) {
	cfgs := mustPlan(t, NewPlanner(), pptpSpec(&core.PPTPConfig{}))
	up, down := msgs(cfgs, "up"), msgs(cfgs, "down")
	assertHex(t, down[4], ccrqDn, "CCRQ down (PAC side, PAC id)")
	assertHex(t, up[5], merged, "merged CCRQ+CCDN up")
	assertHex(t, down[5], ccdnMsg, "CCDN down (PNS id — reference quirk)")
}

// 1.8: StopRQ/StopRP 16B byte-exact.
func TestPlanner_Stop_Bytes(t *testing.T) {
	cfgs := mustPlan(t, NewPlanner(), pptpSpec(&core.PPTPConfig{}))
	up, down := msgs(cfgs, "up"), msgs(cfgs, "down")
	assertHex(t, up[6], stopRQ, "StopRQ up")
	assertHex(t, down[6], stopRP, "StopRP down")
}

// 1.9: the default full control plane reproduces the reference 14-message
// sequence byte-for-byte with the exact directions.
func TestPlanner_FullSequence(t *testing.T) {
	cfgs := mustPlan(t, NewPlanner(), pptpSpec(&core.PPTPConfig{}))
	up, down := msgs(cfgs, "up"), msgs(cfgs, "down")
	wantUp := []string{sccrqBytes, ocrqBytes, sliUp, sliUp, sliUp, merged, stopRQ}
	wantDown := []string{sccrpBytes, ocrpBytes, sliDown, sliDown, ccrqDn, ccdnMsg, stopRP}
	if len(up) != len(wantUp) || len(down) != len(wantDown) {
		t.Fatalf("up segments = %d (want %d), down segments = %d (want %d)",
			len(up), len(wantUp), len(down), len(wantDown))
	}
	for i, want := range wantUp {
		assertHex(t, up[i], want, "up message")
	}
	for i, want := range wantDown {
		assertHex(t, down[i], want, "down message")
	}
}

// 1.10: the merged segment is exactly CCRQ+CCDN (164B) in one TCP segment.
func TestPlanner_MergedTeardownSegment(t *testing.T) {
	cfgs := mustPlan(t, NewPlanner(), pptpSpec(&core.PPTPConfig{}))
	up := msgs(cfgs, "up")
	m := up[5]
	if len(m) != 164 {
		t.Fatalf("merged segment len = %d, want 164", len(m))
	}
	assertHex(t, m[:16], ccrqUp, "merged[0:16] (CCRQ)")
	assertHex(t, m[16:], ccdnMsg, "merged[16:] (CCDN)")
	// The two inner Length fields must both agree with their slices.
	if l := binary.BigEndian.Uint16(m[0:2]); int(l) != 16 {
		t.Errorf("CCRQ Length = %d, want 16", l)
	}
	if l := binary.BigEndian.Uint16(m[16:18]); int(l) != 148 {
		t.Errorf("CCDN Length = %d, want 148", l)
	}
}

// --- §1 数据面 (1.11-1.13) ---

// 1.11: GRE frame config — 16B PPTP-GRE header (flags 0x3081, proto
// 0x880B, Key = Payload Length + peer Call ID), outer IP protocol 47, no
// L4. 1.13: seq/ack — up frames seq 0..2 ack 0; down frames seq 0..1 ack 2.
func TestPlanner_GRE_HeaderAndSeqAck(t *testing.T) {
	cfgs := mustPlan(t, NewPlanner(), pptpSpec(&core.PPTPConfig{}))
	frames := greFrames(cfgs)
	if len(frames) != 5 {
		t.Fatalf("GRE frames = %d, want 5 (3 up + 2 down)", len(frames))
	}
	for i, f := range frames {
		if f.L2.GRE == nil {
			t.Fatalf("frame %d: GRE nil", i)
		}
		if !f.L2.GRE.PPTP {
			t.Errorf("frame %d: PPTP mode not set", i)
		}
		if !f.L2.GRE.AckPresent {
			t.Errorf("frame %d: AckPresent false (16B header required)", i)
		}
		// Outer IP protocol 47, no L4 (4.2).
		if f.L3.Protocol != core.ProtocolGRE {
			t.Errorf("frame %d: outer IP protocol = %d, want 47", i, f.L3.Protocol)
		}
		if f.L4.Protocol != "" {
			t.Errorf("frame %d: L4 must be empty, got %q", i, f.L4.Protocol)
		}
	}
	// Up (PNS side) frames carry the PEER's call id (PAC 0x35c9), seq 0..2,
	// ack 0.
	for i := 0; i < 3; i++ {
		f := frames[i]
		if f.Direction != "up" {
			t.Errorf("frame %d: direction = %s, want up", i, f.Direction)
		}
		if f.L2.GRE.CallID != 0x35c9 {
			t.Errorf("frame %d: GRE CallID = %04x, want 35c9 (peer/PAC id)", i, f.L2.GRE.CallID)
		}
		if f.L2.GRE.Sequence != uint32(i) {
			t.Errorf("frame %d: Sequence = %d, want %d", i, f.L2.GRE.Sequence, i)
		}
		if f.L2.GRE.Ack != 0 {
			t.Errorf("frame %d: Ack = %d, want 0 (nothing received yet)", i, f.L2.GRE.Ack)
		}
	}
	// Down (PAC side) frames carry the PNS call id 0xa9c0, seq 0..1, ack 2
	// (highest received up seq).
	for i := 0; i < 2; i++ {
		f := frames[3+i]
		if f.Direction != "down" {
			t.Errorf("frame %d: direction = %s, want down", 3+i, f.Direction)
		}
		if f.L2.GRE.CallID != 0xa9c0 {
			t.Errorf("frame %d: GRE CallID = %04x, want a9c0 (peer/PNS id)", 3+i, f.L2.GRE.CallID)
		}
		if f.L2.GRE.Sequence != uint32(i) {
			t.Errorf("frame %d: Sequence = %d, want %d", 3+i, f.L2.GRE.Sequence, i)
		}
		if f.L2.GRE.Ack != 2 {
			t.Errorf("frame %d: Ack = %d, want 2", 3+i, f.L2.GRE.Ack)
		}
	}
}

// 1.12: the GRE payload is a PPP frame (FF 03 + 0x0021) wrapping a valid
// inner IPv4 packet: version 4, correct header checksum, src/dst
// 10.10.10.1/10.10.10.2, distinct IPIDs.
func TestPlanner_GRE_PPPFrame(t *testing.T) {
	cfgs := mustPlan(t, NewPlanner(), pptpSpec(&core.PPTPConfig{}))
	frames := greFrames(cfgs)
	for i, f := range frames {
		p := f.Payload
		if len(p) != 4+28 {
			t.Fatalf("frame %d: PPP payload len = %d, want %d (FF 03 0021 + 20B IPv4 + 8B UDP)",
				i, len(p), 4+28)
		}
		if p[0] != 0xFF || p[1] != 0x03 {
			t.Errorf("frame %d: HDLC address/control = %02x %02x, want ff 03", i, p[0], p[1])
		}
		if p[2] != 0x00 || p[3] != 0x21 {
			t.Errorf("frame %d: PPP Protocol = %02x %02x, want 00 21 (IPv4)", i, p[2], p[3])
		}
		inner := p[4:]
		if inner[0] != 0x45 {
			t.Errorf("frame %d: inner version/IHL = %02x, want 45", i, inner[0])
		}
		if !checksum16OK(inner[:20]) {
			t.Errorf("frame %d: inner IPv4 header checksum invalid", i)
		}
		if h := hex.EncodeToString(inner[12:16]); h != "0a0a0a01" {
			t.Errorf("frame %d: inner src = %s, want 0a0a0a01 (10.10.10.1)", i, h)
		}
		if h := hex.EncodeToString(inner[16:20]); h != "0a0a0a02" {
			t.Errorf("frame %d: inner dst = %s, want 0a0a0a02", i, h)
		}
		if inner[8] != 64 {
			t.Errorf("frame %d: inner TTL = %d, want 64", i, inner[8])
		}
		if inner[9] != 17 {
			t.Errorf("frame %d: inner proto = %d, want 17 (UDP)", i, inner[9])
		}
		// Inner IPID must be distinct per frame (1..5).
		if id := binary.BigEndian.Uint16(inner[4:6]); id != uint16(i+1) {
			t.Errorf("frame %d: inner IPID = %d, want %d", i, id, i+1)
		}
		// Inner total length covers the 20B header + 8B UDP.
		if tl := binary.BigEndian.Uint16(inner[2:4]); tl != 28 {
			t.Errorf("frame %d: inner total length = %d, want 28", i, tl)
		}
	}
}

// 3.10-bonus: the inner IPv4 config (PPTPInnerIP) drives the PPP payload:
// TCP inner with explicit ports/TTL/payload and correct L4 checksum. The
// frame counts come out as 1 up + 2 down (a direct-constructed spec cannot
// express explicit 0 — parsePPTPConfig's getIntPresence handles that on the
// convert path), so every frame must carry the custom inner packet.
func TestPlanner_GRE_InnerIPCustom(t *testing.T) {
	spec := pptpSpec(&core.PPTPConfig{
		InnerIP: &core.PPTPInnerIP{
			SrcIP:   "192.168.1.1",
			DstIP:   "192.168.1.2",
			Proto:   6, // TCP
			SrcPort: 1234,
			DstPort: 80,
			TTL:     30,
			Payload: []byte("hi"),
		},
		DataFrames:     1,
		DownDataFrames: 2,
	})
	cfgs := mustPlan(t, NewPlanner(), spec)
	frames := greFrames(cfgs)
	if len(frames) != 3 {
		t.Fatalf("GRE frames = %d, want 3 (1 up + 2 down)", len(frames))
	}
	p := frames[0].Payload
	inner := p[4:]
	if h := hex.EncodeToString(inner[12:16]); h != "c0a80101" {
		t.Errorf("inner src = %s, want c0a80101", h)
	}
	if h := hex.EncodeToString(inner[16:20]); h != "c0a80102" {
		t.Errorf("inner dst = %s, want c0a80102", h)
	}
	if inner[8] != 30 {
		t.Errorf("inner TTL = %d, want 30", inner[8])
	}
	if inner[9] != 6 {
		t.Errorf("inner proto = %d, want 6 (TCP)", inner[9])
	}
	if !checksum16OK(inner[:20]) {
		t.Errorf("inner IPv4 header checksum invalid")
	}
	// TCP header (20B after the IPv4 header): ports, window, checksum.
	tcp := inner[20:]
	if got := binary.BigEndian.Uint16(tcp[0:2]); got != 1234 {
		t.Errorf("inner src port = %d, want 1234", got)
	}
	if got := binary.BigEndian.Uint16(tcp[2:4]); got != 80 {
		t.Errorf("inner dst port = %d, want 80", got)
	}
	if string(tcp[20:]) != "hi" {
		t.Errorf("inner payload = %q, want \"hi\"", tcp[20:])
	}
	// TCP checksum = one's-complement over pseudo-header + TCP segment; the
	// checksum field at tcp[16:18] must be non-zero and sum to 0xFFFF over
	// [pseudo + tcp] with the checksum field zeroed.
	src := []byte{0xc0, 0xa8, 0x01, 0x01}
	dst := []byte{0xc0, 0xa8, 0x01, 0x02}
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	zeroed := append([]byte(nil), tcp...)
	zeroed[16], zeroed[17] = 0, 0
	region := append(pseudo, zeroed...)
	// Sum must equal the wire checksum complement.
	wire := binary.BigEndian.Uint16(tcp[16:18])
	if wire == 0 {
		t.Fatalf("inner TCP checksum = 0, want non-zero")
	}
	sum := uint32(0)
	for i := 0; i+1 < len(region); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(region[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	if got := ^uint16(sum); got != wire {
		t.Errorf("inner TCP checksum = %04x, independent computation = %04x", wire, got)
	}
	// The custom inner config must reach every frame (up and down).
	for i := 1; i < 3; i++ {
		ip := frames[i].Payload[4:]
		if h := hex.EncodeToString(ip[12:16]); h != "c0a80101" {
			t.Errorf("frame %d: inner src = %s, want c0a80101", i, h)
		}
		if got := binary.BigEndian.Uint16(ip[20:22]); got != 1234 {
			t.Errorf("frame %d: inner src port = %d, want 1234", i, got)
		}
	}
}

// --- §2 Validate (2.1-2.6) ---

func TestPlanner_Validate(t *testing.T) {
	p := NewPlanner()
	if err := p.Validate(pptpSpec(&core.PPTPConfig{})); err != nil {
		t.Fatalf("default spec rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*core.FlowSpec)
		want   string
	}{
		{"2.1 invalid role", func(s *core.FlowSpec) { s.PPTP.Role = "pnsx" }, "invalid pptp role"},
		{"2.2 invalid scenario", func(s *core.FlowSpec) { s.PPTP.Scenario = "bad" }, "invalid pptp scenario"},
		{"2.3 negative calls", func(s *core.FlowSpec) { s.PPTP.Calls = -1 }, "invalid pptp calls"},
		{"2.4 negative sli_count", func(s *core.FlowSpec) { s.PPTP.SLICount = -1 }, "invalid pptp sli_count"},
		{"2.4 negative data_frames", func(s *core.FlowSpec) { s.PPTP.DataFrames = -1 }, "invalid pptp data_frames"},
		{"2.4 negative down_data_frames", func(s *core.FlowSpec) { s.PPTP.DownDataFrames = -1 }, "invalid pptp down_data_frames"},
		{"2.5 non-hex sub_address", func(s *core.FlowSpec) { s.PPTP.SubAddress = "zz" }, "invalid pptp sub_address"},
		{"2.6 missing config", func(s *core.FlowSpec) { s.PPTP = nil }, "pptp config is required"},
		{"2.6 oversized host_name", func(s *core.FlowSpec) { s.PPTP.HostName = strings.Repeat("x", 65) }, "exceed 64 bytes"},
		{"2.6 oversized dialed_number", func(s *core.FlowSpec) { s.PPTP.DialedNumber = strings.Repeat("x", 65) }, "exceed 64 bytes"},
		{"2.6 invalid inner proto", func(s *core.FlowSpec) {
			s.PPTP.InnerIP = &core.PPTPInnerIP{Proto: 99}
		}, "invalid pptp inner proto"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := pptpSpec(&core.PPTPConfig{})
			tc.mutate(&spec)
			err := p.Validate(spec)
			if err == nil {
				t.Fatalf("Validate accepted %s, want error", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
	// Valid roles/scenarios still pass.
	for _, role := range []string{"", "pns", "pac"} {
		spec := pptpSpec(&core.PPTPConfig{Role: role})
		if err := p.Validate(spec); err != nil {
			t.Errorf("role %q rejected: %v", role, err)
		}
	}
	for _, sc := range []string{"", "full", "control_only", "tunnel_only", "data_only"} {
		spec := pptpSpec(&core.PPTPConfig{Scenario: sc})
		if err := p.Validate(spec); err != nil {
			t.Errorf("scenario %q rejected: %v", sc, err)
		}
	}
}

// --- §3 多会话与场景 (3.1-3.11) ---

// 3.1: Calls=3 — per-call OCRQ call ids a9c0/a9c1/a9c2, OCRP 35c9/35ca/35cb,
// and the GRE frames' peer call ids increment per call.
func TestPlanner_Calls3(t *testing.T) {
	spec := pptpSpec(&core.PPTPConfig{Calls: 3})
	cfgs := mustPlan(t, NewPlanner(), spec)
	up := msgs(cfgs, "up")
	ocrqs := 0
	for _, m := range up {
		if msgType(m) == msgOCRQ {
			want := []string{"a9c0", "a9c1", "a9c2"}[ocrqs]
			if h := hexStr(m[12:14]); h != want {
				t.Errorf("OCRQ %d call id = %s, want %s", ocrqs, h, want)
			}
			ocrqs++
		}
	}
	if ocrqs != 3 {
		t.Errorf("OCRQ count = %d, want 3", ocrqs)
	}
	down := msgs(cfgs, "down")
	ocrps := 0
	for _, m := range down {
		if msgType(m) == msgOCRP {
			want := []string{"35c9", "35ca", "35cb"}[ocrps]
			if h := hexStr(m[12:14]); h != want {
				t.Errorf("OCRP %d call id = %s, want %s", ocrps, h, want)
			}
			ocrps++
		}
	}
	if ocrps != 3 {
		t.Errorf("OCRP count = %d, want 3", ocrps)
	}
	// 15 SLIs (5 per call: 3 up + 2 down) and 3 merged teardown segments
	// (up side).
	sliCount, mergedCount := 0, 0
	for _, m := range up {
		if msgType(m) == msgSLI {
			sliCount++
		}
		if msgType(m) == msgCCRQ && len(m) == 164 {
			mergedCount++
		}
	}
	downSLI := 0
	for _, m := range down {
		if msgType(m) == msgSLI {
			downSLI++
		}
	}
	if sliCount != 9 {
		t.Errorf("up SLI count = %d, want 9 (3 per call)", sliCount)
	}
	if downSLI != 6 {
		t.Errorf("down SLI count = %d, want 6 (2 per call)", downSLI)
	}
	if mergedCount != 3 {
		t.Errorf("merged segments = %d, want 3", mergedCount)
	}
	// GRE peer call ids, grouped by direction: up (PNS side) 35c9/35ca/35cb
	// ×3 frames, down (PAC side) a9c0/a9c1/a9c2 ×2 frames (per-call
	// interleaving: up×3, down×2, up×3, ...).
	frames := greFrames(cfgs)
	if len(frames) != 15 {
		t.Fatalf("GRE frames = %d, want 15", len(frames))
	}
	var upFrames, downFrames []core.PacketConfig
	for _, f := range frames {
		if f.Direction == "up" {
			upFrames = append(upFrames, f)
		} else {
			downFrames = append(downFrames, f)
		}
	}
	if len(upFrames) != 9 || len(downFrames) != 6 {
		t.Fatalf("GRE up/down = %d/%d, want 9/6", len(upFrames), len(downFrames))
	}
	for i := 0; i < 9; i++ {
		wantID := uint16(0x35c9 + i/3)
		if upFrames[i].L2.GRE.CallID != wantID {
			t.Errorf("GRE up frame %d CallID = %04x, want %04x", i, upFrames[i].L2.GRE.CallID, wantID)
		}
	}
	for i := 0; i < 6; i++ {
		wantID := uint16(0xa9c0 + i/2)
		if downFrames[i].L2.GRE.CallID != wantID {
			t.Errorf("GRE down frame %d CallID = %04x, want %04x", i, downFrames[i].L2.GRE.CallID, wantID)
		}
	}
}

// Explicit zero frame counts (the getIntPresence parse semantics: a JSON
// "data_frames": 0 is a real zero, unlike the reference defaults 3/2) mean
// no GRE frames and no SLI — the control plane alone stays intact.
func TestPlanner_ExplicitZeroDataFrames(t *testing.T) {
	cfg := &core.PPTPConfig{DataFrames: 0, DownDataFrames: 0, SLICount: 0}
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 49194, DstPort: 1723,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		PPTP: cfg,
	}
	cfgs := mustPlan(t, NewPlanner(), spec)
	if n := len(greFrames(cfgs)); n != 0 {
		t.Errorf("GRE frames = %d, want 0 (explicit zero frame counts)", n)
	}
	// SCCRQ/SCCRP/OCRQ/OCRP/CCRQ/merged/CCDN/StopRQ/StopRP = 9 segments.
	if n := len(tcpData(cfgs)); n != 9 {
		t.Errorf("TCP data segments = %d, want 9 (no SLI, no GRE)", n)
	}
}

// 3.2: control_only — no GRE data frames, full control plane retained.
func TestPlanner_ScenarioControlOnly(t *testing.T) {
	spec := pptpSpec(&core.PPTPConfig{Scenario: "control_only"})
	cfgs := mustPlan(t, NewPlanner(), spec)
	if n := len(greFrames(cfgs)); n != 0 {
		t.Errorf("GRE frames = %d, want 0 in control_only", n)
	}
	if n := len(tcpData(cfgs)); n != 14 {
		t.Errorf("TCP data segments = %d, want 14 (control plane only)", n)
	}
}

// 3.3: tunnel_only — no SLI and no GRE, only SCCRQ/SCCRP + OCRQ/OCRP +
// teardown + stop.
func TestPlanner_ScenarioTunnelOnly(t *testing.T) {
	spec := pptpSpec(&core.PPTPConfig{Scenario: "tunnel_only"})
	cfgs := mustPlan(t, NewPlanner(), spec)
	if n := len(greFrames(cfgs)); n != 0 {
		t.Errorf("GRE frames = %d, want 0 in tunnel_only", n)
	}
	for _, m := range tcpData(cfgs) {
		if msgType(m.payload) == msgSLI {
			t.Errorf("tunnel_only must not emit SLI, got % x", m.payload)
		}
	}
	if n := len(tcpData(cfgs)); n != 9 {
		t.Errorf("TCP data segments = %d, want 9 (SCCRQ/SCCRP/OCRQ/OCRP/CCRQ/merged/CCDN/StopRQ/StopRP)", n)
	}
}

// 3.4: data_only — GRE frames only, no TCP at all.
func TestPlanner_ScenarioDataOnly(t *testing.T) {
	spec := pptpSpec(&core.PPTPConfig{Scenario: "data_only"})
	cfgs := mustPlan(t, NewPlanner(), spec)
	if n := len(tcpData(cfgs)); n != 0 {
		t.Errorf("TCP data segments = %d, want 0 in data_only", n)
	}
	frames := greFrames(cfgs)
	if len(frames) != 5 {
		t.Fatalf("GRE frames = %d, want 5", len(frames))
	}
	if len(cfgs) != 5 {
		t.Errorf("total packets = %d, want 5 (GRE only)", len(cfgs))
	}
}

// 3.5: Echo=true — ECRQ down (16B, type 5) after SCCRP, ECRP up (20B,
// type 6) echoing the identifier + result/error codes.
func TestPlanner_Echo(t *testing.T) {
	spec := pptpSpec(&core.PPTPConfig{Echo: true})
	cfgs := mustPlan(t, NewPlanner(), spec)
	up, down := msgs(cfgs, "up"), msgs(cfgs, "down")
	if got := msgType(down[1]); got != msgECRQ {
		t.Fatalf("down[1] type = %d, want %d (ECRQ after SCCRP)", got, msgECRQ)
	}
	assertHex(t, down[1], ecrqMsg, "ECRQ")
	if got := msgType(up[1]); got != msgECRP {
		t.Fatalf("up[1] type = %d, want %d (ECRP after ECRQ)", got, msgECRP)
	}
	assertHex(t, up[1], ecrpMsg, "ECRP")
}

// 3.6: WEN=true — after each call's SLI sequence, a 40B WEN (type 14)
// from the PAC side with Peer Call ID = the PNS id and six zero counters.
func TestPlanner_WEN(t *testing.T) {
	spec := pptpSpec(&core.PPTPConfig{WEN: true, Calls: 2})
	cfgs := mustPlan(t, NewPlanner(), spec)
	down := msgs(cfgs, "down")
	wens := 0
	for _, m := range down {
		if msgType(m) == msgWEN {
			if len(m) != 40 {
				t.Errorf("WEN len = %d, want 40", len(m))
			}
			wantID := []string{"a9c0", "a9c1"}[wens]
			if h := hexStr(m[12:14]); h != wantID {
				t.Errorf("WEN %d Peer Call ID = %s, want %s", wens, h, wantID)
			}
			// Six 4-byte error counters all zero.
			for off := 16; off < 40; off += 4 {
				if v := binary.BigEndian.Uint32(m[off : off+4]); v != 0 {
					t.Errorf("WEN %d counter @%d = %d, want 0", wens, off, v)
				}
			}
			wens++
		}
	}
	if wens != 2 {
		t.Errorf("WEN count = %d, want 2 (one per call)", wens)
	}
}

// 3.7: IncomingCall=true — per call: ICRQ down 220B (type 9, PAC call id,
// dialed/dialing lengths auto-filled), ICRP up 24B (type 10), ICCN down
// 28B (type 11, peer's call id = PNS id).
func TestPlanner_IncomingCall(t *testing.T) {
	spec := pptpSpec(&core.PPTPConfig{
		IncomingCall: true,
		DialedNumber: "0123456789",
		DialingNumber: "12345",
	})
	cfgs := mustPlan(t, NewPlanner(), spec)
	up, down := msgs(cfgs, "up"), msgs(cfgs, "down")
	// ICRQ (PAC side → down) sits between OCRP and the SLIs.
	if got := msgType(down[2]); got != msgICRQ {
		t.Fatalf("down[2] type = %d, want %d (ICRQ after OCRP)", got, msgICRQ)
	}
	m := down[2]
	if len(m) != 220 {
		t.Fatalf("ICRQ len = %d, want 220", len(m))
	}
	if h := hexStr(m[12:14]); h != "35c9" {
		t.Errorf("ICRQ Call ID = %s, want 35c9 (PAC self-report)", h)
	}
	if got := binary.BigEndian.Uint16(m[24:26]); got != 10 {
		t.Errorf("ICRQ Dialed Number Length = %d, want 10", got)
	}
	if got := binary.BigEndian.Uint16(m[26:28]); got != 5 {
		t.Errorf("ICRQ Dialing Number Length = %d, want 5", got)
	}
	if string(m[28:38]) != "0123456789" {
		t.Errorf("ICRQ Dialed Number = %q, want \"0123456789\"", m[28:38])
	}
	if string(m[92:97]) != "12345" {
		t.Errorf("ICRQ Dialing Number = %q, want \"12345\"", m[92:97])
	}
	if got := msgType(up[2]); got != msgICRP {
		t.Fatalf("up[2] type = %d, want %d (ICRP after ICRQ)", got, msgICRP)
	}
	assertHex(t, up[2], icrpMsg, "ICRP")
	if got := msgType(down[3]); got != msgICCN {
		t.Fatalf("down[3] type = %d, want %d (ICCN after ICRP)", got, msgICCN)
	}
	assertHex(t, down[3], iccnMsg, "ICCN")
}

// 3.8: SliPeerCallID overrides the PAC-side SLI peer call id (the
// reference quirk otherwise uses the PNS side's TCP source port).
func TestPlanner_SliPeerCallIDOverride(t *testing.T) {
	spec := pptpSpec(&core.PPTPConfig{SliPeerCallID: 0x1234})
	cfgs := mustPlan(t, NewPlanner(), spec)
	down := msgs(cfgs, "down")
	sli := 0
	for _, m := range down {
		if msgType(m) == msgSLI {
			if h := hexStr(m[12:14]); h != "1234" {
				t.Errorf("PAC-side SLI %d peer call id = %s, want 1234 (override)", sli, h)
			}
			sli++
		}
	}
	if sli != 2 {
		t.Errorf("PAC-side SLI count = %d, want 2", sli)
	}
}

// 3.9: role=pac — direction flip (SCCRQ emitted from the dst side) and
// call-id ownership: OCRP carries the PAC's own id (PeerCallID) and the
// peer (PNS) id, the PAC-side SLI quirk uses the PNS side's TCP port, and
// the GRE frames' call ids swap sides.
func TestPlanner_RolePAC(t *testing.T) {
	spec := pptpSpec(&core.PPTPConfig{Role: "pac"})
	cfgs := mustPlan(t, NewPlanner(), spec)
	up, down := msgs(cfgs, "up"), msgs(cfgs, "down")
	// SCCRQ is now emitted from the dst side (down), not up.
	if got := msgType(down[0]); got != msgSCCRQ {
		t.Fatalf("down[0] type = %d, want SCCRQ (direction flip in role=pac)", got)
	}
	// OCRP (PAC side → up): Call ID = PAC's own id (35c9), Peer = PNS id.
	if got := msgType(up[1]); got != msgOCRP {
		t.Fatalf("up[1] type = %d, want OCRP", got)
	}
	oc := up[1]
	if h := hexStr(oc[12:14]); h != "35c9" {
		t.Errorf("OCRP Call ID = %s, want 35c9 (PAC self-report)", h)
	}
	if h := hexStr(oc[14:16]); h != "a9c0" {
		t.Errorf("OCRP Peer Call ID = %s, want a9c0 (PNS id)", h)
	}
	// PAC-side SLI (up in role=pac) uses the PNS side's TCP port: 1723.
	for _, m := range up {
		if msgType(m) == msgSLI {
			if h := hexStr(m[12:14]); h != "06bb" {
				t.Errorf("PAC-side SLI peer call id = %s, want 06bb (PNS port 1723)", h)
			}
		}
	}
	// GRE: the emission order is PNS-side frames first, then PAC-side
	// frames (design_pptp.md §5.3), regardless of role. In role=pac the
	// PNS side is the destination, so its frames go down carrying the
	// peer's (PAC's) id 35c9, and the PAC-side frames go up carrying the
	// peer's (PNS's) id a9c0.
	frames := greFrames(cfgs)
	if len(frames) != 5 {
		t.Fatalf("GRE frames = %d, want 5", len(frames))
	}
	for i := 0; i < 3; i++ {
		if frames[i].Direction != "down" || frames[i].L2.GRE.CallID != 0x35c9 {
			t.Errorf("PNS-side GRE frame %d: dir=%s callid=%04x, want down 35c9", i, frames[i].Direction, frames[i].L2.GRE.CallID)
		}
	}
	for i := 0; i < 2; i++ {
		if frames[3+i].Direction != "up" || frames[3+i].L2.GRE.CallID != 0xa9c0 {
			t.Errorf("PAC-side GRE frame %d: dir=%s callid=%04x, want up a9c0", i, frames[3+i].Direction, frames[3+i].L2.GRE.CallID)
		}
	}
}

// 3.10: custom fields (host name / vendor / BPS / result codes) reach the
// wire at the RFC 2637 offsets.
func TestPlanner_CustomFields(t *testing.T) {
	spec := pptpSpec(&core.PPTPConfig{
		HostName:   "pptp-host",
		VendorName: "vendx",
		MinBPS:     1000,
		MaxBPS:     200000,
		ScrpResult: 2,
		ScrpError:  3,
		OcrpResult: 2,
		StopReason: 5,
		CcdnResult: 1,
		CcdnCause:  7,
	})
	cfgs := mustPlan(t, NewPlanner(), spec)
	up, down := msgs(cfgs, "up"), msgs(cfgs, "down")
	sccrq, ocrq := up[0], up[1]
	if string(sccrq[28:37]) != "pptp-host" {
		t.Errorf("SCCRQ Host Name = %q, want \"pptp-host\"", sccrq[28:37])
	}
	if string(sccrq[92:97]) != "vendx" {
		t.Errorf("SCCRQ Vendor Name = %q, want \"vendx\"", sccrq[92:97])
	}
	if got := binary.BigEndian.Uint32(ocrq[16:20]); got != 1000 {
		t.Errorf("OCRQ Minimum BPS = %d, want 1000", got)
	}
	if got := binary.BigEndian.Uint32(ocrq[20:24]); got != 200000 {
		t.Errorf("OCRQ Maximum BPS = %d, want 200000", got)
	}
	sccrp := down[0]
	if sccrp[14] != 2 || sccrp[15] != 3 {
		t.Errorf("SCCRP result/error = %d/%d, want 2/3", sccrp[14], sccrp[15])
	}
	if ocrp := down[1]; ocrp[16] != 2 {
		t.Errorf("OCRP Result Code = %d, want 2", ocrp[16])
	}
	if stop := up[6]; stop[12] != 5 {
		t.Errorf("StopRQ Reason = %d, want 5", stop[12])
	}
	// CCDN is the last down data message (down[6] = StopRP, down[5] = CCDN).
	ccdn := down[5]
	if ccdn[14] != 1 {
		t.Errorf("CCDN Result = %d, want 1", ccdn[14])
	}
	if got := binary.BigEndian.Uint16(ccdn[16:18]); got != 7 {
		t.Errorf("CCDN Cause = %d, want 7", got)
	}
}

// 3.11: IPv6 hosts — EtherType 0x86DD for both the TCP control plane and
// the GRE frames; the GRE inner PPP frame stays IPv4.
func TestPlanner_IPv6Hosts(t *testing.T) {
	spec := pptpSpec(&core.PPTPConfig{})
	spec.SrcIP, spec.DstIP = "2001:db8::1", "2001:db8::2"
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcpCount, greCount := 0, 0
	for _, c := range cfgs {
		if c.L2.EtherType != core.EtherTypeIPv6 {
			t.Errorf("EtherType = %04x, want 86dd (IPv6 host)", c.L2.EtherType)
		}
		if c.L4.Protocol == "tcp" {
			tcpCount++
		}
		if c.L2.GRE != nil {
			greCount++
			want := "2001:db8::1"
			if c.Direction == "down" {
				want = "2001:db8::2"
			}
			if c.L3.SrcIP != want {
				t.Errorf("GRE outer src = %s, want %s", c.L3.SrcIP, want)
			}
			if c.Payload[4] != 0x45 {
				t.Errorf("GRE inner PPP frame must stay IPv4, got %02x", c.Payload[4])
			}
		}
	}
	if tcpCount != 21 {
		t.Errorf("TCP packets = %d, want 21 (3 handshake + 14 data + 4 FIN)", tcpCount)
	}
	if greCount != 5 {
		t.Errorf("GRE frames = %d, want 5", greCount)
	}
}

// --- §4 端口与数据面 (4.1-4.2) ---

// 4.1: dst_port omitted → 1723 on the up (PNS-side) TCP control packets;
// down packets carry the source port as their dst (mirror of the tuple).
func TestPlanner_DefaultPort(t *testing.T) {
	spec := pptpSpec(&core.PPTPConfig{})
	spec.DstPort = 0
	cfgs := mustPlan(t, NewPlanner(), spec)
	if len(cfgs) == 0 {
		t.Fatal("no packets")
	}
	upSeen := false
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" && c.Direction == "up" {
			upSeen = true
			if c.L4.DstPort != 1723 {
				t.Errorf("up TCP dst port = %d, want 1723 (RFC 2637 §1)", c.L4.DstPort)
			}
		}
	}
	if !upSeen {
		t.Fatal("no up TCP packets planned")
	}
}

// 4.2 (in 1.11): GRE frames carry outer IP protocol 47 with no L4 — see
// TestPlanner_GRE_HeaderAndSeqAck.
