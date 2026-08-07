package rtsp

// RTP media-plane tests, derived from /tmp/l7_planner_design/testcases_rtsp.md
// §2.3 (RTP header bytes), §2.4 (RTP-Info consistency), §5 (media plane)
// and the reference pcap (frame 12 first RTP packet: 80 60 45 68 32 7b
// 23 c6 8d 99 1a c7 → V=2 PT=96 seq=17768 ts=846930886 ssrc=0x8D991AC7).

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// rtpFields decodes a 12-byte RTP header: seq, ts, ssrc, pt, marker.
func rtpFields(payload []byte) (seq uint16, ts uint32, ssrc uint32, pt uint8, marker bool, ok bool) {
	if len(payload) < 12 {
		return 0, 0, 0, 0, false, false
	}
	if payload[0] != 0x80 { // V=2, P=0, X=0, CC=0
		return 0, 0, 0, 0, false, false
	}
	seq = uint16(payload[2])<<8 | uint16(payload[3])
	ts = uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
	ssrc = uint32(payload[8])<<24 | uint32(payload[9])<<16 | uint32(payload[10])<<8 | uint32(payload[11])
	pt = payload[1] & 0x7F
	marker = payload[1]&0x80 != 0
	return seq, ts, ssrc, pt, marker, true
}

// mediaSpec returns a spec whose dialog is SETUP/200/PLAY/200(EmitMedia),
// the minimal session that emits RTP.
func mediaSpec() core.FlowSpec {
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "SETUP", URI: "rtsp://192.168.1.27/media/trackID=5"},
		{StatusCode: 200, StatusText: "OK"},
		{Method: "PLAY"},
		{StatusCode: 200, StatusText: "OK", EmitMedia: true},
	}
	spec.RTSP.Media = &core.RTSPMedia{
		SrcPort: 1024, DstPort: 1026,
		Frames: 20, PayloadType: 96, FrameSize: 160,
	}
	return spec
}

// --- RTP header bytes (testcases 2.3, 5.2, 5.3) ---

func TestRTSPPlan_RTP_HeaderBytes(t *testing.T) {
	// testcases 2.3.1-2.3.7: first byte 0x80, PT byte 0x60 for 96, seq
	// contiguous, ts advances by FrameSize, SSRC constant and non-zero,
	// M=0, payload length 12+FrameSize.
	cfgs := mustPlan(t, NewPlanner(), mediaSpec())
	udp := rtspUDP(cfgs)
	if len(udp) != 20 {
		t.Fatalf("got %d RTP frames, want 20", len(udp))
	}

	var firstSeq uint16
	var firstTS uint32
	ssrcs := map[uint32]bool{}
	for i, c := range udp {
		p := c.Payload
		if len(p) != 12+160 {
			t.Errorf("frame %d: payload %d bytes, want 172 (12 + FrameSize 160)", i, len(p))
		}
		seq, ts, ssrc, pt, marker, ok := rtpFields(p)
		if !ok {
			t.Fatalf("frame %d: invalid RTP header %x", i, p)
		}
		if pt != 96 {
			t.Errorf("frame %d: PT=%d, want 96", i, pt)
		}
		if marker {
			t.Errorf("frame %d: M bit set, want 0", i)
		}
		ssrcs[ssrc] = true
		if i == 0 {
			firstSeq, firstTS = seq, ts
		} else {
			if seq != firstSeq+uint16(i) {
				t.Errorf("frame %d: seq=%d, want %d (contiguous)", i, seq, firstSeq+uint16(i))
			}
			if ts != firstTS+uint32(i*160) {
				t.Errorf("frame %d: ts=%d, want %d (advance by FrameSize)", i, ts, firstTS+uint32(i*160))
			}
		}
	}
	if len(ssrcs) != 1 {
		t.Errorf("SSRC varies across frames: %v, want constant", ssrcs)
	}
	if udp[0].L4.SrcPort != 1024 || udp[0].L4.DstPort != 1026 {
		t.Errorf("RTP ports %d→%d, want server 1024 → client 1026", udp[0].L4.SrcPort, udp[0].L4.DstPort)
	}
}

func TestRTSPPlan_RTP_PayloadType0_Valid(t *testing.T) {
	// testcase 5.2.4: static PT 0 (PCMU) is valid — no defaulting.
	spec := mediaSpec()
	spec.RTSP.Media.PayloadType = 0
	udp := rtspUDP(mustPlan(t, NewPlanner(), spec))
	if len(udp) == 0 {
		t.Fatal("no RTP frames")
	}
	if _, _, _, pt, _, _ := rtpFields(udp[0].Payload); pt != 0 {
		t.Errorf("PT byte=%d, want 0 (PCMU, valid static type)", pt)
	}
}

func TestRTSPPlan_RTP_Defaults(t *testing.T) {
	// testcases 5.1.1-5.1.2, 5.2.1-5.2.2: Frames=0 → 1 packet, FrameSize=0
	// → 160, ports 0 → 5004, direction empty → down (server→client).
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "SETUP"},
		{StatusCode: 200, StatusText: "OK"},
		{Method: "PLAY"},
		{StatusCode: 200, StatusText: "OK", EmitMedia: true},
	}
	spec.RTSP.Media = &core.RTSPMedia{}
	udp := rtspUDP(mustPlan(t, NewPlanner(), spec))
	if len(udp) != 1 {
		t.Fatalf("got %d RTP frames, want 1 (Frames default)", len(udp))
	}
	c := udp[0]
	if len(c.Payload) != 12+160 {
		t.Errorf("payload %d bytes, want 172 (FrameSize default 160)", len(c.Payload))
	}
	if c.L4.SrcPort != 5004 || c.L4.DstPort != 5004 {
		t.Errorf("ports %d→%d, want 5004→5004 (default RTP port)", c.L4.SrcPort, c.L4.DstPort)
	}
	if c.L3.SrcIP != "192.168.1.27" || c.L3.DstIP != "192.168.45.2" {
		t.Errorf("tuple %s→%s, want server→client (default down)", c.L3.SrcIP, c.L3.DstIP)
	}
	if c.Direction != "down" {
		t.Errorf("Direction=%s, want down", c.Direction)
	}
	if c.FlowID != "192.168.45.2-192.168.1.27-62020-554:rtp" {
		t.Errorf("FlowID=%s, want parent flow + \":rtp\"", c.FlowID)
	}
}

func TestRTSPPlan_RTP_UpDirection(t *testing.T) {
	// testcase 5.1.4: Direction="up" → client→server tuple.
	spec := mediaSpec()
	spec.RTSP.Media.Direction = "up"
	udp := rtspUDP(mustPlan(t, NewPlanner(), spec))
	if len(udp) == 0 {
		t.Fatal("no RTP frames")
	}
	c := udp[0]
	if c.L3.SrcIP != "192.168.45.2" || c.L3.DstIP != "192.168.1.27" {
		t.Errorf("tuple %s→%s, want client→server", c.L3.SrcIP, c.L3.DstIP)
	}
}

func TestRTSPPlan_RTP_DirectionCaseInsensitive(t *testing.T) {
	// testcase 5.1.5: "Down"/"DOWN" treated as down (EqualFold).
	for _, d := range []string{"Down", "DOWN"} {
		spec := mediaSpec()
		spec.RTSP.Media.Direction = d
		udp := rtspUDP(mustPlan(t, NewPlanner(), spec))
		if len(udp) == 0 {
			t.Fatalf("direction %q: no RTP frames", d)
		}
		if udp[0].L3.SrcIP != "192.168.1.27" {
			t.Errorf("direction %q: tuple src=%s, want server 192.168.1.27", d, udp[0].L3.SrcIP)
		}
	}
}

func TestRTSPPlan_RTP_LargeFrameSize_NoUDPFragmentation(t *testing.T) {
	// testcase 6.15: FrameSize=1400 → each datagram is 1412 bytes, no
	// segmentation (UDP never splits).
	spec := mediaSpec()
	spec.RTSP.Media.FrameSize = 1400
	spec.RTSP.Media.Frames = 2
	udp := rtspUDP(mustPlan(t, NewPlanner(), spec))
	if len(udp) != 2 {
		t.Fatalf("got %d frames, want 2", len(udp))
	}
	for i, c := range udp {
		if len(c.Payload) != 1412 {
			t.Errorf("frame %d: payload %d bytes, want 1412", i, len(c.Payload))
		}
	}
}

func TestRTSPPlan_RTP_FileSource(t *testing.T) {
	// testcase 5.2.5: FileSource → payload chunks come from the file,
	// split at FrameSize boundaries (last chunk short).
	spec := mediaSpec()
	spec.RTSP.Media.FrameSize = 160
	spec.RTSP.Media.FileSource = &filesystem.FileSource{Literal: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)
	ch, err := NewPlanner().Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	udp := rtspUDP(cfgs)
	if len(udp) != 3 {
		t.Fatalf("got %d frames, want 3 (400 bytes / 160)", len(udp))
	}
	// Frames advance seq/ts from the same params as the RTP-Info.
	if len(udp[0].Payload) != 12+160 || len(udp[1].Payload) != 12+160 || len(udp[2].Payload) != 12+80 {
		t.Errorf("frame sizes %d/%d/%d, want 172/172/92", len(udp[0].Payload), len(udp[1].Payload), len(udp[2].Payload))
	}
	// All bytes from the file, none synthesized.
	joined := make([]byte, 0, 400)
	for _, c := range udp {
		joined = append(joined, c.Payload[12:]...)
	}
	if string(joined) != strings.Repeat("x", 400) {
		t.Error("FileSource frame payloads do not reproduce the file bytes")
	}
}

func TestRTSPPlan_RTP_FileSourceNoCache_NoEmit(t *testing.T) {
	// testcase 5.2.6: FileSource set but ctx has no cache → no RTP frames
	// emitted, no panic.
	spec := mediaSpec()
	spec.RTSP.Media.FileSource = &filesystem.FileSource{Literal: "abc"}
	cfgs := mustPlan(t, NewPlanner(), spec)
	if len(rtspUDP(cfgs)) != 0 {
		t.Error("FileSource without cache must not emit RTP")
	}
}

func TestRTSPPlan_RTP_RandomInitValues(t *testing.T) {
	// testcase 5.3.3: two independent plans produce different
	// seq/ts/ssrc (random initial values). Probability of a collision is
	// negligible (2^-64).
	s1 := rtpUDPFirst(mustPlan(t, NewPlanner(), mediaSpec()))
	s2 := rtpUDPFirst(mustPlan(t, NewPlanner(), mediaSpec()))
	if s1 == s2 {
		t.Errorf("two plans produced identical stream params %x — expected random", s1)
	}
}

func rtpUDPFirst(cfgs []core.PacketConfig) uint64 {
	udp := rtspUDP(cfgs)
	if len(udp) == 0 {
		return 0
	}
	p := udp[0].Payload
	return uint64(p[2])<<56 | uint64(p[3])<<48 | uint64(p[4])<<40 | uint64(p[5])<<32 |
		uint64(p[6])<<24 | uint64(p[7])<<16 | uint64(p[8])<<8 | uint64(p[9])
}

// --- RTP-Info consistency (testcases 2.4) ---

func TestRTSPPlan_RTPInfo_MatchesEmittedFrames(t *testing.T) {
	// testcases 2.4.1-2.4.4: the PLAY response's RTP-Info carries the
	// exact seq/ssrc/rtptime of the first emitted RTP frame, and
	// url=<last SETUP trackID>.
	cfgs := mustPlan(t, NewPlanner(), mediaSpec())
	payloads := tcpData(cfgs)
	udp := rtspUDP(cfgs)
	if len(udp) == 0 {
		t.Fatal("no RTP frames")
	}
	playResp := payloads[3]
	info, ok := headerValueOf(playResp, "RTP-Info")
	if !ok {
		t.Fatal("PLAY response missing RTP-Info")
	}
	if !strings.HasPrefix(info, "url=trackID=5;") {
		t.Errorf("RTP-Info=%q, want url=trackID=5 (last SETUP trackID)", info)
	}

	seq, ts, ssrc, _, _, _ := rtpFields(udp[0].Payload)
	if got := rtpInfoParam(info, "seq"); got != int64(seq) {
		t.Errorf("RTP-Info seq=%d, first frame seq=%d", got, seq)
	}
	if got := rtpInfoParam(info, "rtptime"); got != int64(ts) {
		t.Errorf("RTP-Info rtptime=%d, first frame ts=%d", got, ts)
	}
	// ssrc is printed as a signed int32 (reference pcap:
	// ssrc=-1919345977 for 0x8D991AC7).
	wantSSRC := int64(int32(ssrc))
	if got := rtpInfoParam(info, "ssrc"); got != wantSSRC {
		t.Errorf("RTP-Info ssrc=%d, want %d (int32 of frame ssrc 0x%08x)", got, wantSSRC, ssrc)
	}
}

func TestRTSPPlan_RTPInfo_UserProvidedWins(t *testing.T) {
	// testcase 2.4.5: user RTP-Info on the PLAY response is kept verbatim.
	spec := mediaSpec()
	spec.RTSP.Dialog[3].Headers = []string{"RTP-Info: url=trackID=6;seq=1;ssrc=2;rtptime=3"}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	info, ok := headerValueOf(payloads[3], "RTP-Info")
	if !ok || info != "url=trackID=6;seq=1;ssrc=2;rtptime=3" {
		t.Errorf("RTP-Info=%q, want user value verbatim", info)
	}
}

func TestRTSPPlan_RTPInfo_MediaNil_NotGenerated(t *testing.T) {
	// testcase 2.4.6: Media=nil → no RTP-Info.
	spec := mediaSpec()
	spec.RTSP.Media = nil
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if _, ok := headerValueOf(payloads[3], "RTP-Info"); ok {
		t.Error("PLAY response must not carry RTP-Info when Media=nil")
	}
}

func TestRTSPPlan_RTPInfo_EmitMediaOnRequest_ResponseGetsNone(t *testing.T) {
	// EmitMedia on the PLAY *request*: frames go out before the response,
	// which then gets no auto RTP-Info (it cannot truthfully announce an
	// already-emitted stream).
	spec := mediaSpec()
	spec.RTSP.Dialog[2].EmitMedia = true
	spec.RTSP.Dialog[3].EmitMedia = false
	cfgs := mustPlan(t, NewPlanner(), spec)
	payloads := tcpData(cfgs)
	if _, ok := headerValueOf(payloads[3], "RTP-Info"); ok {
		t.Error("PLAY response after request-side emission must not carry RTP-Info")
	}
	if len(rtspUDP(cfgs)) == 0 {
		t.Error("EmitMedia on PLAY request must still emit RTP")
	}
	// Wire order: RTP frames land between PLAY request and its response.
	// Assert the first UDP packet appears after the PLAY request packet.
	var playReqIdx, firstRTPIdx = -1, -1
	for i, c := range cfgs {
		if c.L4.Protocol == "tcp" && c.L4.Flags == 0x18 && strings.HasPrefix(string(c.Payload), "PLAY ") && playReqIdx < 0 {
			playReqIdx = i
		}
		if c.L4.Protocol == "udp" && firstRTPIdx < 0 {
			firstRTPIdx = i
		}
	}
	if playReqIdx < 0 || firstRTPIdx <= playReqIdx {
		t.Errorf("RTP first frame at %d must follow PLAY request at %d (wire order)", firstRTPIdx, playReqIdx)
	}
}

func TestRTSPPlan_RTPInfo_MultiPlay_SecondDescribesContinuation(t *testing.T) {
	// Two PLAY responses, both EmitMedia: the second RTP-Info describes
	// the continued stream (seq advances past the first burst).
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{
		{Method: "SETUP", URI: "rtsp://host/media/trackID=5"},
		{StatusCode: 200, StatusText: "OK"},
		{Method: "PLAY"},
		{StatusCode: 200, StatusText: "OK", EmitMedia: true},
		{Method: "PLAY"},
		{StatusCode: 200, StatusText: "OK", EmitMedia: true},
	}
	spec.RTSP.Media = &core.RTSPMedia{SrcPort: 1024, DstPort: 1024, Frames: 5, PayloadType: 96}
	cfgs := mustPlan(t, NewPlanner(), spec)
	payloads := tcpData(cfgs)
	udp := rtspUDP(cfgs)
	if len(udp) != 10 {
		t.Fatalf("got %d RTP frames, want 10", len(udp))
	}
	info1, _ := headerValueOf(payloads[3], "RTP-Info")
	info2, _ := headerValueOf(payloads[5], "RTP-Info")
	seq1, seq2 := rtpInfoParam(info1, "seq"), rtpInfoParam(info2, "seq")
	if seq2 != seq1+5 {
		t.Errorf("second RTP-Info seq=%d, want first seq %d + 5 frames", seq2, seq1)
	}
	// And the second RTP-Info matches the 6th frame.
	seq, _, _, _, _, _ := rtpFields(udp[5].Payload)
	if int64(seq) != seq2 {
		t.Errorf("frame 6 seq=%d, RTP-Info seq=%d — mismatch", seq, seq2)
	}
}

// --- TCP transport correctness (testcases 3.1) ---

func TestRTSPPlan_TCP_SeqAckContinuity(t *testing.T) {
	// testcases 3.1.3-3.1.4: per-direction seq continuity; each packet
	// ACKs the peer's next expected sequence number (all bytes the peer
	// sent so far, handshake and FIN included).
	cfgs := mustPlan(t, NewPlanner(), mediaSpec())
	var expUp, expDown uint32
	var haveUp, haveDown bool
	for _, c := range cfgs {
		if c.L4.Protocol != "tcp" {
			continue
		}
		// Only SYN/FIN consume an extra sequence number; data segments
		// advance by their byte count alone.
		advance := uint32(len(c.Payload))
		if c.L4.Flags&0x03 != 0 { // SYN (0x02) or FIN (0x01)
			advance++
		}
		if c.Direction == "up" {
			if !haveUp {
				expUp = c.L4.Seq
				haveUp = true
			} else if c.L4.Seq != expUp {
				t.Errorf("up seq=%d, want %d (continuity)", c.L4.Seq, expUp)
			}
			if haveDown && c.L4.Ack != expDown {
				t.Errorf("up ack=%d, want %d (all down bytes)", c.L4.Ack, expDown)
			}
			expUp = c.L4.Seq + advance
		} else {
			if !haveDown {
				expDown = c.L4.Seq
				haveDown = true
			} else if c.L4.Seq != expDown {
				t.Errorf("down seq=%d, want %d (continuity)", c.L4.Seq, expDown)
			}
			if haveUp && c.L4.Ack != expUp {
				t.Errorf("down ack=%d, want %d (all up bytes)", c.L4.Ack, expUp)
			}
			expDown = c.L4.Seq + advance
		}
	}
}

// --- Validate via ParseBPS-adjacent helpers: rtspHostOf / extractTrackID ---

func TestRTSPHostOf_IPv6Bracketed(t *testing.T) {
	if got := rtspHostOf("3ffe::4"); got != "[3ffe::4]" {
		t.Errorf("rtspHostOf(IPv6)=%q, want bracketed", got)
	}
	if got := rtspHostOf("192.168.1.27"); got != "192.168.1.27" {
		t.Errorf("rtspHostOf(IPv4)=%q", got)
	}
}

func TestExtractTrackID(t *testing.T) {
	cases := []struct{ uri, want string }{
		{"rtsp://host/media/trackID=5", "trackID=5"},
		{"rtsp://host/media/trackID=6?foo=1", "trackID=6"},
		{"rtsp://host/media/35k_3sec.mov", "35k_3sec.mov"},
		{"rtsp://host/", ""},
	}
	for _, c := range cases {
		if got := extractTrackID(c.uri); got != c.want {
			t.Errorf("extractTrackID(%q)=%q, want %q", c.uri, got, c.want)
		}
	}
}

// --- convert-level checks that mirror the strategy_convert contract ---

func TestRTSP_StatusCodeText_EmptyRendersCodeOnly(t *testing.T) {
	// A status code without a standard phrase (e.g. 299) renders an empty
	// reason phrase — must not panic.
	spec := pointPlaybackSpec()
	spec.RTSP.Dialog = []core.RTSPMessage{{StatusCode: 299}}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	if payloads[0] != "RTSP/1.0 299 \r\nCSeq: 1\r\n\r\n" {
		t.Errorf("got %q, want 'RTSP/1.0 299 \\r\\nCSeq: 1\\r\\n\\r\\n'", payloads[0])
	}
}

func TestRTSPPlan_Headers_NoDuplicateAutoHeaders(t *testing.T) {
	// Auto headers (CSeq/Session/Transport/RTP-Info/Content-Length) must
	// not be duplicated when the user supplies them in any case.
	spec := mediaSpec()
	spec.RTSP.Dialog[0].Headers = []string{"cseq: 9", "transport: RTP/AVP;unicast;client_port=2000-2001"}
	spec.RTSP.Dialog[3].Headers = []string{"session: s1"}
	payloads := tcpData(mustPlan(t, NewPlanner(), spec))
	for i, p := range payloads {
		for _, name := range []string{"CSeq", "Session", "Transport", "RTP-Info", "Content-Length"} {
			n := 0
			for _, line := range strings.Split(p, "\r\n") {
				if idx := strings.Index(line, ":"); idx >= 0 && strings.EqualFold(strings.TrimSpace(line[:idx]), name) {
					n++
				}
			}
			if n > 1 {
				t.Errorf("message %d has %d %q headers, want <= 1", i, n, name)
			}
		}
	}
	// The user cseq value must be preserved.
	if v, _ := headerValueOf(payloads[0], "CSeq"); v != "9" {
		t.Errorf("SETUP request CSeq=%q, want 9", v)
	}
	if v, _ := headerValueOf(payloads[1], "CSeq"); v != "9" {
		t.Errorf("SETUP response CSeq=%q, want echo 9", v)
	}
}

// TestRTSPPlan_SegmentByMSS_EmptyPayload checks the segmentation helper
// on an empty payload (bare PSH-ACK), mirroring SIP's contract.
func TestRTSPPlan_SegmentByMSS_EmptyPayload(t *testing.T) {
	segs := segmentByMSS(nil, 1460)
	if len(segs) != 1 || len(segs[0]) != 0 {
		t.Errorf("segmentByMSS(nil)=%d segments, want 1 empty", len(segs))
	}
	segs = segmentByMSS([]byte("ab"), 0)
	if len(segs) != 1 || string(segs[0]) != "ab" {
		t.Errorf("segmentByMSS with mss<=0 must return the payload whole")
	}
}
