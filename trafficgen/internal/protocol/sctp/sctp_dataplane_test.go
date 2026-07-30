package sctp

// Data-plane coverage tests for the SCTP planner. Derived from RFC 4960:
//   - §3.3.1 DATA chunk (B/E flags for fragmentation, SID/SSN/PPID fields)
//   - §3.2 chunk padding
//   - §9.2 SHUTDOWN teardown
//
// These tests target gaps found in the spec-vs-impl audit:
//   1. Fragmentation: a large user message must be split across multiple
//      DATA chunks with B (beginning) / E (end) flags. Previously the
//      planner hardcoded B+E on every DATA chunk, so a large payload
//      became one giant chunk -- semantically wrong and flagged by DPIs.
//   2. Multi-stream SSN independence: SSN is per-stream (per SID), so two
//      streams can each start at SSN=0. The planner already supports this
//      via per-chunk SID/SSN, but no test asserted the independence.
//   3. Full data-plane session: handshake -> bidirectional multi-DATA ->
//      SHUTDOWN in one flow, asserting the complete packet sequence and
//      per-direction Verification Tag.

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// mustPlanErr returns configs and any plan error (does not fatal on error).
func mustPlanErr(t *testing.T, p *Planner, spec core.FlowSpec) ([]core.PacketConfig, error) {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		return nil, err
	}
	return drain(ch), nil
}

// dataChunkInfo extracts the observable fields of a DATA chunk from a
// PacketConfig payload. Returns ok=false if the payload is not a DATA chunk.
type dataChunkInfo struct {
	tsn    uint32
	sid    uint16
	ssn    uint16
	ppid   uint32
	flags  uint8
	length uint16
	data   []byte
}

func parseDataChunk(payload []byte) (dataChunkInfo, bool) {
	var d dataChunkInfo
	if len(payload) < 4 || payload[0] != ChunkDATA {
		return d, false
	}
	d.flags = payload[1]
	d.length = binary.BigEndian.Uint16(payload[2:4])
	if int(d.length) < 16 || len(payload) < 16 {
		return d, false
	}
	d.tsn = binary.BigEndian.Uint32(payload[4:8])
	d.sid = binary.BigEndian.Uint16(payload[8:10])
	d.ssn = binary.BigEndian.Uint16(payload[10:12])
	d.ppid = binary.BigEndian.Uint32(payload[12:16])
	d.data = payload[16:d.length]
	return d, true
}

// collectDataChunks returns parsed DATA chunk info for every DATA packet in
// cfgs, in emit order.
func collectDataChunks(cfgs []core.PacketConfig) []dataChunkInfo {
	var out []dataChunkInfo
	for _, c := range cfgs {
		if d, ok := parseDataChunk(c.Payload); ok {
			out = append(out, d)
		}
	}
	return out
}

// =============================================================================
// §3.3.1 Fragmentation: B/E flags
// =============================================================================

// TestSCTP_FragmentSize_SplitsLargePayload asserts that when FragmentSize is
// set and a chunk's payload exceeds it, the planner emits multiple DATA
// chunks: the first with B (beginning), the last with E (end), and any
// middle chunks with neither flag. Per RFC 4960 §3.3.1, all fragments share
// the same SID/SSN/PPID (same user message) and have incrementing TSNs.
//
// BEFORE the fix: buildDATAChunk hardcoded B+E (0x03) on every chunk, so
// fragmentation was impossible -- a 900-byte payload on FragmentSize=256
// produced one B+E chunk instead of 4 fragments (B, none, none, E).
func TestSCTP_FragmentSize_SplitsLargePayload(t *testing.T) {
	p := NewPlanner()
	payload := make([]byte, 900) // 4 fragments at 256 bytes each
	for i := range payload {
		payload[i] = byte(i % 256)
	}
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 12346,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			FragmentSize: 256,
			Chunks: []core.SCTPChunk{
				{SID: 0, SSN: 0, PPID: 0, Data: payload, Direction: "up"},
			},
		},
	}
	cfgs, err := mustPlanErr(t, p, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	dataChunks := collectDataChunks(cfgs)
	// 900 bytes / 256 = 3 full + 1 partial (228) = 4 fragments
	if len(dataChunks) != 4 {
		t.Fatalf("expected 4 DATA fragments, got %d", len(dataChunks))
	}
	// First fragment: B flag set (0x02), E NOT set
	if dataChunks[0].flags&0x02 == 0 {
		t.Errorf("fragment[0] flags=%#x, want B (0x02) set", dataChunks[0].flags)
	}
	if dataChunks[0].flags&0x01 != 0 {
		t.Errorf("fragment[0] flags=%#x, want E NOT set", dataChunks[0].flags)
	}
	// Middle fragments: neither B nor E (0x00)
	for i := 1; i < len(dataChunks)-1; i++ {
		if dataChunks[i].flags != 0x00 {
			t.Errorf("fragment[%d] flags=%#x, want 0x00 (neither B nor E)", i, dataChunks[i].flags)
		}
	}
	// Last fragment: E flag set (0x01), B NOT set
	last := dataChunks[len(dataChunks)-1]
	if last.flags&0x01 == 0 {
		t.Errorf("last fragment flags=%#x, want E (0x01) set", last.flags)
	}
	if last.flags&0x02 != 0 {
		t.Errorf("last fragment flags=%#x, want B NOT set", last.flags)
	}
	// All fragments share the same SID/SSN/PPID (same user message)
	for i, d := range dataChunks {
		if d.sid != 0 {
			t.Errorf("fragment[%d] SID=%d, want 0 (shared)", i, d.sid)
		}
		if d.ssn != 0 {
			t.Errorf("fragment[%d] SSN=%d, want 0 (shared)", i, d.ssn)
		}
		if d.ppid != 0 {
			t.Errorf("fragment[%d] PPID=%d, want 0 (shared)", i, d.ppid)
		}
	}
	// TSNs increment across fragments
	for i := 1; i < len(dataChunks); i++ {
		if dataChunks[i].tsn != dataChunks[i-1].tsn+1 {
			t.Errorf("fragment[%d] TSN=%d, want %d (strict +1)", i, dataChunks[i].tsn, dataChunks[i-1].tsn+1)
		}
	}
	// Reassembled payload must equal the original
	var reassembled []byte
	for _, d := range dataChunks {
		reassembled = append(reassembled, d.data...)
	}
	if len(reassembled) != len(payload) {
		t.Fatalf("reassembled len=%d, want %d", len(reassembled), len(payload))
	}
	for i := range payload {
		if reassembled[i] != payload[i] {
			t.Fatalf("reassembled[%d]=%d, want %d", i, reassembled[i], payload[i])
		}
	}
}

// TestSCTP_FragmentSize_ExactlyFitNoFragment asserts that a payload exactly
// equal to FragmentSize produces a single DATA chunk with B+E (complete
// message), NOT a fragment.
func TestSCTP_FragmentSize_ExactlyFitNoFragment(t *testing.T) {
	p := NewPlanner()
	payload := make([]byte, 256) // exactly == FragmentSize
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 12346,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			FragmentSize: 256,
			Chunks: []core.SCTPChunk{
				{SID: 0, SSN: 0, PPID: 0, Data: payload, Direction: "up"},
			},
		},
	}
	cfgs, err := mustPlanErr(t, p, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	dataChunks := collectDataChunks(cfgs)
	if len(dataChunks) != 1 {
		t.Fatalf("expected 1 DATA chunk (exact fit), got %d", len(dataChunks))
	}
	if dataChunks[0].flags != ChunkFlagBeginEnd {
		t.Errorf("flags=%#x, want B+E (0x03) for exact-fit complete message", dataChunks[0].flags)
	}
}

// TestSCTP_FragmentSize_ZeroDisablesFragmentation asserts that FragmentSize=0
// (default) keeps the legacy single-chunk B+E behavior. Backward compat.
func TestSCTP_FragmentSize_ZeroDisablesFragmentation(t *testing.T) {
	p := NewPlanner()
	payload := make([]byte, 900) // large, but no fragmentation
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 12346,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			// FragmentSize intentionally zero (default)
			Chunks: []core.SCTPChunk{
				{SID: 0, SSN: 0, PPID: 0, Data: payload, Direction: "up"},
			},
		},
	}
	cfgs, err := mustPlanErr(t, p, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	dataChunks := collectDataChunks(cfgs)
	if len(dataChunks) != 1 {
		t.Fatalf("expected 1 DATA chunk (FragmentSize=0), got %d", len(dataChunks))
	}
	if dataChunks[0].flags != ChunkFlagBeginEnd {
		t.Errorf("flags=%#x, want B+E (0x03) when fragmentation disabled", dataChunks[0].flags)
	}
}

// TestSCTP_FragmentSize_TwoFragmentOnlyBAndE asserts a payload that produces
// exactly 2 fragments: first has B, last has E (no middle). Edge case.
func TestSCTP_FragmentSize_TwoFragmentOnlyBAndE(t *testing.T) {
	p := NewPlanner()
	payload := make([]byte, 300) // 256 + 44 = 2 fragments at 256
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 12346,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			FragmentSize: 256,
			Chunks: []core.SCTPChunk{
				{SID: 2, SSN: 5, PPID: 47, Data: payload, Direction: "up"},
			},
		},
	}
	cfgs, err := mustPlanErr(t, p, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	dataChunks := collectDataChunks(cfgs)
	if len(dataChunks) != 2 {
		t.Fatalf("expected 2 DATA fragments, got %d", len(dataChunks))
	}
	if dataChunks[0].flags != 0x02 {
		t.Errorf("fragment[0] flags=%#x, want B-only (0x02)", dataChunks[0].flags)
	}
	if dataChunks[1].flags != 0x01 {
		t.Errorf("fragment[1] flags=%#x, want E-only (0x01)", dataChunks[1].flags)
	}
	// Both fragments share SID=2, SSN=5, PPID=47
	for i, d := range dataChunks {
		if d.sid != 2 || d.ssn != 5 || d.ppid != 47 {
			t.Errorf("fragment[%d] SID=%d SSN=%d PPID=%d, want 2/5/47 (shared)", i, d.sid, d.ssn, d.ppid)
		}
	}
}

// TestSCTP_FragmentSize_DownDirectionFragments asserts that down-direction
// DATA chunks also fragment correctly (server->client path).
func TestSCTP_FragmentSize_DownDirectionFragments(t *testing.T) {
	p := NewPlanner()
	payload := make([]byte, 600) // 256 + 256 + 88 = 3 fragments
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 12346,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			FragmentSize: 256,
			Chunks: []core.SCTPChunk{
				{SID: 1, SSN: 0, PPID: 0, Data: payload, Direction: "down"},
			},
		},
	}
	cfgs, err := mustPlanErr(t, p, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	// Find the down-direction DATA packets
	var downData []core.PacketConfig
	for _, c := range cfgs {
		if d, ok := parseDataChunk(c.Payload); ok && c.Direction == "down" {
			_ = d
			downData = append(downData, c)
		}
	}
	if len(downData) != 3 {
		t.Fatalf("expected 3 down-direction DATA fragments, got %d", len(downData))
	}
	d0, _ := parseDataChunk(downData[0].Payload)
	d1, _ := parseDataChunk(downData[1].Payload)
	d2, _ := parseDataChunk(downData[2].Payload)
	if d0.flags != 0x02 {
		t.Errorf("down fragment[0] flags=%#x, want B (0x02)", d0.flags)
	}
	if d1.flags != 0x00 {
		t.Errorf("down fragment[1] flags=%#x, want 0x00", d1.flags)
	}
	if d2.flags != 0x01 {
		t.Errorf("down fragment[2] flags=%#x, want E (0x01)", d2.flags)
	}
	// Down-direction TSNs use the server TSN space and increment
	if d1.tsn != d0.tsn+1 || d2.tsn != d1.tsn+1 {
		t.Errorf("down TSNs not sequential: %d %d %d", d0.tsn, d1.tsn, d2.tsn)
	}
}

// =============================================================================
// §3.3.1 Multi-stream: SSN independence per SID
// =============================================================================

// TestSCTP_MultiStream_SSNIndependence asserts that two streams (SID=0 and
// SID=1) can each carry SSN=0 independently. Per RFC 4960 §3.3.1, SSN is
// per-stream, so SID=0/SSN=0 and SID=1/SSN=0 are both valid in one flow.
// The planner passes SID/SSN through per chunk; this test guards regression.
func TestSCTP_MultiStream_SSNIndependence(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 12346,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			Chunks: []core.SCTPChunk{
				{SID: 0, SSN: 0, PPID: 0, Data: []byte("stream0-msg0"), Direction: "up"},
				{SID: 1, SSN: 0, PPID: 0, Data: []byte("stream1-msg0"), Direction: "up"},
				{SID: 0, SSN: 1, PPID: 0, Data: []byte("stream0-msg1"), Direction: "up"},
				{SID: 1, SSN: 1, PPID: 0, Data: []byte("stream1-msg1"), Direction: "up"},
			},
		},
	}
	cfgs, err := mustPlanErr(t, p, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	dataChunks := collectDataChunks(cfgs)
	if len(dataChunks) != 4 {
		t.Fatalf("expected 4 DATA chunks, got %d", len(dataChunks))
	}
	// Expected (SID, SSN) sequence
	want := [][2]uint16{{0, 0}, {1, 0}, {0, 1}, {1, 1}}
	for i, d := range dataChunks {
		if d.sid != want[i][0] || d.ssn != want[i][1] {
			t.Errorf("chunk[%d] SID=%d SSN=%d, want %d/%d", i, d.sid, d.ssn, want[i][0], want[i][1])
		}
	}
	// TSNs increment monotonically across all chunks regardless of stream
	for i := 1; i < len(dataChunks); i++ {
		if dataChunks[i].tsn != dataChunks[i-1].tsn+1 {
			t.Errorf("chunk[%d] TSN=%d, want %d (TSN is global per direction)", i,
				dataChunks[i].tsn, dataChunks[i-1].tsn+1)
		}
	}
	// Payload data preserved
	wantData := []string{"stream0-msg0", "stream1-msg0", "stream0-msg1", "stream1-msg1"}
	for i, d := range dataChunks {
		if string(d.data) != wantData[i] {
			t.Errorf("chunk[%d] data=%q, want %q", i, string(d.data), wantData[i])
		}
	}
}

// =============================================================================
// Full data-plane session: handshake -> bidi multi-DATA -> SHUTDOWN
// =============================================================================

// TestSCTP_FullDataPlaneSession_Bidirectional asserts a complete SCTP
// session: 4-way handshake, then bidirectional DATA (client sends up, server
// replies down), then 3-way SHUTDOWN. Verifies:
//   - Packet count: 4 (handshake) + N (data) + 3 (shutdown) = 4+5+3 = 12
//   - Handshake packets carry the right Verification Tags
//   - Up DATA uses server's tag, down DATA uses client's tag
//   - SHUTDOWN uses server's tag (client->server)
//   - Direction sequence alternates correctly
func TestSCTP_FullDataPlaneSession_Bidirectional(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 12346,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			VerificationTag: 0x11111111, // client's tag (server -> client)
			InitiateTag:     0x22222222, // server's tag (client -> server)
			Chunks: []core.SCTPChunk{
				{SID: 0, SSN: 0, PPID: 0, Data: []byte("REQ"), Direction: "up"},
				{SID: 0, SSN: 0, PPID: 0, Data: []byte("RESP"), Direction: "down"},
				{SID: 0, SSN: 1, PPID: 0, Data: []byte("REQ2"), Direction: "up"},
				{SID: 0, SSN: 1, PPID: 0, Data: []byte("RESP2"), Direction: "down"},
				{SID: 0, SSN: 2, PPID: 0, Data: []byte("REQ3"), Direction: "up"},
			},
		},
	}
	cfgs, err := mustPlanErr(t, p, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	// 4 handshake + 5 data + 3 shutdown = 12
	if len(cfgs) != 12 {
		t.Fatalf("packet count=%d, want 12 (4 handshake + 5 data + 3 shutdown)", len(cfgs))
	}
	// Handshake: INIT(up, vtag=0), INIT-ACK(down, vtag=clientTag),
	// COOKIE-ECHO(up, vtag=serverTag), COOKIE-ACK(down, vtag=clientTag)
	if cfgs[0].Direction != "up" || cfgs[0].L4.Ack != 0 {
		t.Errorf("INIT: dir=%s vtag=%#x, want up/0", cfgs[0].Direction, cfgs[0].L4.Ack)
	}
	if cfgs[1].Direction != "down" || cfgs[1].L4.Ack != 0x11111111 {
		t.Errorf("INIT-ACK: dir=%s vtag=%#x, want down/0x11111111", cfgs[1].Direction, cfgs[1].L4.Ack)
	}
	if cfgs[2].Direction != "up" || cfgs[2].L4.Ack != 0x22222222 {
		t.Errorf("COOKIE-ECHO: dir=%s vtag=%#x, want up/0x22222222", cfgs[2].Direction, cfgs[2].L4.Ack)
	}
	if cfgs[3].Direction != "down" || cfgs[3].L4.Ack != 0x11111111 {
		t.Errorf("COOKIE-ACK: dir=%s vtag=%#x, want down/0x11111111", cfgs[3].Direction, cfgs[3].L4.Ack)
	}
	// DATA chunks [4..8]: up, down, up, down, up
	wantDirs := []string{"up", "down", "up", "down", "up"}
	for i, wd := range wantDirs {
		idx := 4 + i
		if cfgs[idx].Direction != wd {
			t.Errorf("DATA[%d] dir=%s, want %s", i, cfgs[idx].Direction, wd)
		}
	}
	// Up DATA uses server's tag, down DATA uses client's tag
	for i := 0; i < 5; i++ {
		idx := 4 + i
		wantTag := uint32(0x22222222) // server tag for up
		if wantDirs[i] == "down" {
			wantTag = 0x11111111 // client tag for down
		}
		if cfgs[idx].L4.Ack != wantTag {
			t.Errorf("DATA[%d] (%s) vtag=%#x, want %#x", i, wantDirs[i], cfgs[idx].L4.Ack, wantTag)
		}
	}
	// SHUTDOWN trio [9..11]: up, down, up
	if cfgs[9].Direction != "up" || cfgs[9].L4.Ack != 0x22222222 {
		t.Errorf("SHUTDOWN: dir=%s vtag=%#x, want up/0x22222222", cfgs[9].Direction, cfgs[9].L4.Ack)
	}
	if cfgs[10].Direction != "down" || cfgs[10].L4.Ack != 0x11111111 {
		t.Errorf("SHUTDOWN-ACK: dir=%s vtag=%#x, want down/0x11111111", cfgs[10].Direction, cfgs[10].L4.Ack)
	}
	if cfgs[11].Direction != "up" || cfgs[11].L4.Ack != 0x22222222 {
		t.Errorf("SHUTDOWN-COMPLETE: dir=%s vtag=%#x, want up/0x22222222", cfgs[11].Direction, cfgs[11].L4.Ack)
	}
}

// TestSCTP_FullDataPlaneSession_WithDataPayloads asserts that the bidirectional
// DATA chunks carry the correct user payloads (not just direction/tag).
func TestSCTP_FullDataPlaneSession_WithDataPayloads(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 12346,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			Chunks: []core.SCTPChunk{
				{SID: 0, SSN: 0, PPID: 0, Data: []byte("hello-up"), Direction: "up"},
				{SID: 0, SSN: 0, PPID: 0, Data: []byte("world-down"), Direction: "down"},
			},
		},
	}
	cfgs, err := mustPlanErr(t, p, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	// handshake(4) + data(2) + shutdown(3) = 9
	if len(cfgs) != 9 {
		t.Fatalf("packet count=%d, want 9", len(cfgs))
	}
	d0, ok := parseDataChunk(cfgs[4].Payload)
	if !ok {
		t.Fatal("cfg[4] is not a DATA chunk")
	}
	if string(d0.data) != "hello-up" {
		t.Errorf("up DATA payload=%q, want 'hello-up'", string(d0.data))
	}
	d1, ok := parseDataChunk(cfgs[5].Payload)
	if !ok {
		t.Fatal("cfg[5] is not a DATA chunk")
	}
	if string(d1.data) != "world-down" {
		t.Errorf("down DATA payload=%q, want 'world-down'", string(d1.data))
	}
}

// =============================================================================
// §3.3.1 PPID coverage
// =============================================================================

// TestSCTP_PPID_Values asserts that various PPID values are preserved in the
// DATA chunk. PPID=0 (generic), 47 (M3UA), 60 (NGAP). Per RFC 4960 §3.3.1
// PPID is the payload protocol identifier.
func TestSCTP_PPID_Values(t *testing.T) {
	cases := []uint32{0, 47, 60, 0xFFFFFFFF}
	for _, ppid := range cases {
		t.Run("ppid", func(t *testing.T) {
			p := NewPlanner()
			spec := core.FlowSpec{
				SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
				SrcPort: 12345, DstPort: 12346,
				SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
				SCTP: &core.SCTPConfig{
					Chunks: []core.SCTPChunk{
						{SID: 0, SSN: 0, PPID: ppid, Data: []byte("x"), Direction: "up"},
					},
				},
			}
			cfgs, err := mustPlanErr(t, p, spec)
			if err != nil {
				t.Fatalf("Plan error: %v", err)
			}
			dataChunks := collectDataChunks(cfgs)
			if len(dataChunks) != 1 {
				t.Fatalf("expected 1 DATA chunk, got %d", len(dataChunks))
			}
			if dataChunks[0].ppid != ppid {
				t.Errorf("PPID=%d, want %d", dataChunks[0].ppid, ppid)
			}
		})
	}
}

// =============================================================================
// FragmentSize validation
// =============================================================================

// TestSCTP_FragmentSize_TooSmallRejected asserts that a FragmentSize below
// the minimum (1 byte of user data per fragment is meaningless; enforce a
// sane floor) is rejected at Validate time, not silently producing 900+
// fragments.
func TestSCTP_FragmentSize_TooSmallRejected(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 12346,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			FragmentSize: 1, // absurdly small
			Chunks: []core.SCTPChunk{
				{SID: 0, Data: []byte("hello"), Direction: "up"},
			},
		},
	}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("Validate should reject FragmentSize=1, got nil")
	}
	if !strings.Contains(err.Error(), "fragment_size") {
		t.Errorf("error should mention fragment_size, got: %v", err)
	}
}

// TestSCTP_FragmentSize_WithFileSource asserts that fragmentation works when
// the payload comes from FileSource (resolved via PayloadCache), not just
// inline Data.
func TestSCTP_FragmentSize_WithFileSource(t *testing.T) {
	p := NewPlanner()
	// 600 bytes of file content -> 3 fragments at 256
	payload := make([]byte, 600)
	for i := range payload {
		payload[i] = byte('A' + (i % 26))
	}
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 12345, DstPort: 12346,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			FragmentSize: 256,
			Chunks: []core.SCTPChunk{
				{
					SID: 0, SSN: 0, PPID: 0, Direction: "up",
					FileSource: &filesystem.FileSource{Literal: string(payload)},
				},
			},
		},
	}
	// Inject a PayloadCache so FileSource resolves
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	cache := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), cache)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	cfgs := drain(ch)
	dataChunks := collectDataChunks(cfgs)
	if len(dataChunks) != 3 {
		t.Fatalf("expected 3 DATA fragments from FileSource, got %d", len(dataChunks))
	}
	if dataChunks[0].flags != 0x02 {
		t.Errorf("fragment[0] flags=%#x, want B (0x02)", dataChunks[0].flags)
	}
	if dataChunks[1].flags != 0x00 {
		t.Errorf("fragment[1] flags=%#x, want 0x00", dataChunks[1].flags)
	}
	if dataChunks[2].flags != 0x01 {
		t.Errorf("fragment[2] flags=%#x, want E (0x01)", dataChunks[2].flags)
	}
	// Reassemble and verify
	var reassembled []byte
	for _, d := range dataChunks {
		reassembled = append(reassembled, d.data...)
	}
	if len(reassembled) != len(payload) {
		t.Fatalf("reassembled len=%d, want %d", len(reassembled), len(payload))
	}
}
