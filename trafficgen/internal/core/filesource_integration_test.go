package core_test

// Task 19: end-to-end integration test for the FileSource -> PayloadCache
// -> Filesystem path. This is the regression guard proving that a
// FileSource{File: "path"} referencing a file in the filesystem produces
// matching bytes in the emitted data-channel packets (FTP) and RTP frame
// payloads (SIP), that the cache actually stores the entry (cache-hit
// assertion), and that running the same Plan twice with the same
// FileSource yields one cache entry (dedup assertion).
//
// Path exercised:
//
//	FTPDataChannel.FileSource = &filesystem.FileSource{File: "docs/file.bin"}
//	  -> ftp.Planner.Plan calls core.PayloadCacheFrom(ctx).GetOrLoad(ctx, *dc.FileSource)
//	  -> PayloadCache.resolveBytes sees src.File (relative path)
//	  -> fs.Read(ctx, "docs/file.bin")
//	  -> returns the file's bytes
//	  -> PayloadCache hashes the bytes and caches them
//	  -> FTP planner carries those bytes on the data-channel PSH-ACK
//
// The brief's canonical FTP test is mirrored for SIP (RTP media path) to
// prove the integration works across protocols, not just for one.
//
// Tests:
//  1. TestFileSource_FTPPlannerReadsFromFilesystem — FTP data channel bytes
//     match the file contents, cache Stats shows Entries=1.
//  2. TestFileSource_SIPPlannerReadsFromFilesystem — SIP RTP frame payloads
//     match the file contents.
//  3. TestFileSource_DedupAcrossTwoPlans — running Plan twice with the same
//     FileSource (same bytes) yields one cache entry, not two.

import (
	"bytes"
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/ftp"
	"github.com/trafficgen/trafficgen/internal/protocol/sip"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// findDataChannelPayload returns the payload bytes of the first FTP
// data-channel packet in cfgs (a packet whose L4 ports are NOT 21 —
// the control channel uses port 21 on at least one side). Data-channel
// packets carry the file body as PSH-ACK payload; control-channel
// packets carry FTP command/response text. The data-channel port pair
// is derived by the planner (passive mode: client ephemeral, server
// 50000 by default when no PASV response is parsed).
func findDataChannelPayload(cfgs []core.PacketConfig) []byte {
	for _, c := range cfgs {
		if c.L4.SrcPort != 21 && c.L4.DstPort != 21 && len(c.Payload) > 0 {
			return c.Payload
		}
	}
	return nil
}

// findRTPFramePayloads returns the RTP payload bytes (bytes 12: of each
// UDP packet) for every RTP frame in cfgs. RTP frames have FlowID ending
// in ":rtp" (set by sip.Planner as parentFlowID+":rtp").
func findRTPFramePayloads(cfgs []core.PacketConfig) [][]byte {
	var out [][]byte
	for _, c := range cfgs {
		if len(c.FlowID) < 4 || c.FlowID[len(c.FlowID)-4:] != ":rtp" {
			continue
		}
		if len(c.Payload) < 12 {
			continue
		}
		out = append(out, c.Payload[12:])
	}
	return out
}

// TestFileSource_FTPPlannerReadsFromFilesystem proves the full path:
// FileSource.File -> PayloadCache -> Filesystem.Read -> bytes the FTP
// data-channel packets carry.
//
// Precedence contract (Tasks 9-13):
//  1. dc.FileSource != nil -> PayloadCache.GetOrLoad(ctx, *dc.FileSource)
//  2. PayloadCache calls fs.Read(ctx, "docs/file.bin") because src.File
//     is a relative path.
//  3. The returned bytes are cached (one entry) and emitted on the
//     data-channel PSH-ACK.
//
// This test seeds the filesystem with a file at "docs/file.bin" via
// fs.Upload, then sets dc.FileSource.File = "docs/file.bin" and asserts:
//   - the data-channel payload matches the file bytes exactly,
//   - the cache Stats() shows Entries > 0 and TotalBytes > 0 (cache hit,
//     not bypassed).
func TestFileSource_FTPPlannerReadsFromFilesystem(t *testing.T) {
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	ctx := context.Background()

	// Seed the filesystem with a file at "docs/file.bin". The bytes
	// "FILE-CONTENTS" are uploaded via the Literal source — they
	// become the body of the file at "docs/file.bin" in the filesystem.
	const wantBytes = "FILE-CONTENTS"
	if err := fs.Upload(ctx, "docs/file.bin", filesystem.FileSource{Literal: wantBytes}); err != nil {
		t.Fatalf("seed Upload err=%v", err)
	}

	pc := core.NewPayloadCache(fs)
	ctx = core.WithPayloadCache(ctx, pc)

	p := ftp.NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		TCP: &core.TCPConfig{InitialSeq: 1000},
		FTP: &core.FTPConfig{
			Commands: []core.FTPCommand{
				{Cmd: "RETR /file.bin", Response: "150", EmitDataChannel: true},
				{Cmd: "", Response: "226"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:       "passive",
				Direction:  "down",
				FileSource: &filesystem.FileSource{File: "docs/file.bin"},
			},
		},
	}
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan err=%v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}

	got := findDataChannelPayload(packets)
	if got == nil {
		t.Fatalf("no data-channel payload packet found in %d packets", len(packets))
	}
	if !bytes.Equal(got, []byte(wantBytes)) {
		t.Fatalf("data-channel payload got %q, want %q", string(got), wantBytes)
	}

	// Cache-hit assertion: the cache must have stored the file bytes
	// (one entry, non-zero total bytes). This proves the planner went
	// through PayloadCache.GetOrLoad (which writes to the cache), not
	// some bypass path that reads from the filesystem directly.
	entries, totalBytes := pc.Stats()
	if entries == 0 {
		t.Fatalf("pc.Stats() Entries=0, want >0 (cache must store the file)")
	}
	if totalBytes == 0 {
		t.Fatalf("pc.Stats() TotalBytes=0, want >0 (cache must account for the bytes)")
	}
	if entries != 1 {
		t.Fatalf("pc.Stats() Entries=%d, want 1 (one file = one cache entry)", entries)
	}
	if totalBytes != int64(len(wantBytes)) {
		t.Fatalf("pc.Stats() TotalBytes=%d, want %d", totalBytes, len(wantBytes))
	}
}

// TestFileSource_SIPPlannerReadsFromFilesystem proves the same path for
// SIP: a SIPMedia.FileSource referencing a file in the filesystem
// produces RTP frame payloads that match the file bytes.
//
// SIP's RTP path splits the resolved bytes into FrameSize-sized chunks.
// We use FrameSize=4 with a 10-byte file so the test asserts 3 RTP
// frames carrying "abcd", "efgh", "ij" — exactly the SIP test pattern
// in internal/protocol/sip/sip_filesource_test.go but with bytes coming
// from the filesystem instead of an inline Literal.
func TestFileSource_SIPPlannerReadsFromFilesystem(t *testing.T) {
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	ctx := context.Background()

	const fileBytes = "abcdefghij" // 10 bytes -> 3 RTP frames at FrameSize=4
	if err := fs.Upload(ctx, "media.bin", filesystem.FileSource{Literal: fileBytes}); err != nil {
		t.Fatalf("seed Upload err=%v", err)
	}

	pc := core.NewPayloadCache(fs)
	ctx = core.WithPayloadCache(ctx, pc)

	p := sip.NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 54100, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{Method: "INVITE", URI: "sip:callee@example.com", Direction: "up"},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
				{Method: "ACK", URI: "sip:callee@example.com", Direction: "up", EmitMedia: true},
				{Method: "BYE", URI: "sip:callee@example.com", Direction: "up"},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
			},
			Media: &core.SIPMedia{
				Frames:      5, // ignored when FileSource is set; frames driven by bytes/FrameSize
				PayloadType: 0,
				FrameSize:   4,
				FileSource:  &filesystem.FileSource{File: "media.bin"},
			},
		},
	}
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan err=%v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}

	frames := findRTPFramePayloads(packets)
	wantFrames := [][]byte{
		[]byte("abcd"),
		[]byte("efgh"),
		[]byte("ij"),
	}
	if len(frames) != len(wantFrames) {
		t.Fatalf("len(rtp frames)=%d, want %d (10 bytes / FrameSize=4 -> 3 frames)", len(frames), len(wantFrames))
	}
	for i, got := range frames {
		if !bytes.Equal(got, wantFrames[i]) {
			t.Errorf("rtp[%d] frame bytes=%q, want %q", i, string(got), string(wantFrames[i]))
		}
	}

	// Cache-hit assertion: same as FTP test, the cache must hold the entry.
	entries, totalBytes := pc.Stats()
	if entries != 1 {
		t.Fatalf("pc.Stats() Entries=%d, want 1 (one file = one cache entry)", entries)
	}
	if totalBytes != int64(len(fileBytes)) {
		t.Fatalf("pc.Stats() TotalBytes=%d, want %d", totalBytes, len(fileBytes))
	}
}

// TestFileSource_DedupAcrossTwoPlans proves the cache dedups across
// multiple Plans: running the same FileSource (same file, same bytes)
// through the FTP planner twice produces identical data-channel bytes
// AND the cache shows only ONE entry (not two). This guards against a
// regression where the cache bypasses on the second call (e.g. by
// falling through to a re-read) or double-counts the entry.
//
// We use the FTP planner for both runs because the FTP path carries the
// bytes verbatim on the data-channel PSH-ACK (no FrameSize splitting),
// making the byte-equality assertion direct.
func TestFileSource_DedupAcrossTwoPlans(t *testing.T) {
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	ctx := context.Background()

	const wantBytes = "DEDUP-ME"
	if err := fs.Upload(ctx, "docs/dup.bin", filesystem.FileSource{Literal: wantBytes}); err != nil {
		t.Fatalf("seed Upload err=%v", err)
	}

	pc := core.NewPayloadCache(fs)
	ctx = core.WithPayloadCache(ctx, pc)

	p := ftp.NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		TCP: &core.TCPConfig{InitialSeq: 1000},
		FTP: &core.FTPConfig{
			Commands: []core.FTPCommand{
				{Cmd: "RETR /dup.bin", Response: "150", EmitDataChannel: true},
				{Cmd: "", Response: "226"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:       "passive",
				Direction:  "down",
				FileSource: &filesystem.FileSource{File: "docs/dup.bin"},
			},
		},
	}

	// Run 1.
	ch1, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan run1 err=%v", err)
	}
	var run1 []core.PacketConfig
	for c := range ch1 {
		run1 = append(run1, c)
	}
	got1 := findDataChannelPayload(run1)
	if got1 == nil {
		t.Fatal("run1: no data-channel payload found")
	}
	if !bytes.Equal(got1, []byte(wantBytes)) {
		t.Fatalf("run1 data-channel payload got %q, want %q", string(got1), wantBytes)
	}

	// Snapshot the cache stats after run 1 so we can assert run 2 did
	// not add another entry.
	entriesAfterRun1, bytesAfterRun1 := pc.Stats()
	if entriesAfterRun1 != 1 {
		t.Fatalf("after run1: Entries=%d, want 1", entriesAfterRun1)
	}
	if bytesAfterRun1 != int64(len(wantBytes)) {
		t.Fatalf("after run1: TotalBytes=%d, want %d", bytesAfterRun1, len(wantBytes))
	}

	// Run 2: same FileSource, same bytes. The cache must hit on the
	// existing entry (LoadOrStore returns the existing slice), so no
	// new entry is added.
	ch2, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan run2 err=%v", err)
	}
	var run2 []core.PacketConfig
	for c := range ch2 {
		run2 = append(run2, c)
	}
	got2 := findDataChannelPayload(run2)
	if got2 == nil {
		t.Fatal("run2: no data-channel payload found")
	}
	if !bytes.Equal(got2, []byte(wantBytes)) {
		t.Fatalf("run2 data-channel payload got %q, want %q", string(got2), wantBytes)
	}

	// Dedup assertion: still exactly one cache entry, same total bytes.
	entriesAfterRun2, bytesAfterRun2 := pc.Stats()
	if entriesAfterRun2 != 1 {
		t.Fatalf("after run2: Entries=%d, want 1 (dedup: same file, same hash, same entry)", entriesAfterRun2)
	}
	if bytesAfterRun2 != int64(len(wantBytes)) {
		t.Fatalf("after run2: TotalBytes=%d, want %d (must not double-count)", bytesAfterRun2, len(wantBytes))
	}
}
