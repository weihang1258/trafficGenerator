package sctp_test

// SCTP FileSource integration tests (Task 12). Mirrors the FTP pattern
// (Task 11): when SCTPChunk.FileSource is set, the planner resolves the
// DATA chunk payload bytes via PayloadCache.GetOrLoad (using the cache
// injected through sctp.WithPayloadCache) instead of inline chunk.Data.
//
// Precedence contract (Task 12):
//  1. chunk.FileSource != nil -> PayloadCache.GetOrLoad(ctx, *chunk.FileSource)
//  2. else chunk.Data (inline)
//
// Per-chunk resolution: each chunk with FileSource gets its own bytes.

import (
	"bytes"
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/sctp"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// sctpFileSourceSpec returns a SIP spec with two DATA chunks: one with
// FileSource set (chunk 0) and one with inline Data (chunk 1, for
// backward-compat coverage in a single test flow).
func sctpFileSourceSpec(literal string) core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 38413, DstPort: 38412,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			Chunks: []core.SCTPChunk{
				{
					SID:       1,
					SSN:       0,
					PPID:      60,
					Direction: "up",
					FileSource: &filesystem.FileSource{Literal: literal},
				},
				{
					SID:       1,
					SSN:       1,
					PPID:      60,
					Direction: "up",
					Data:      []byte("INLINE-CHUNK-DATA"),
				},
			},
		},
	}
}

// extractSCTPDataChunkPayload extracts the user-data portion of the first
// DATA chunk in the packet. The SCTP planner stores chunks directly in
// c.Payload (no common-header prefix); the L4 fields carry the ports and
// verification tag. Each chunk layout per RFC 4960 §3.2: Type(1) +
// Flags(1) + Length(2) + value (padded to 4-byte boundary). Length
// includes the 4-byte header. DATA chunk value layout per §3.3.1:
// TSN(4) + SID(2) + SSN(2) + PPID(4) + user-data = 12 bytes of per-chunk
// header + user data.
//
// Returns nil if no DATA chunk (type 0) is found in the packet.
func extractSCTPDataChunkPayload(payload []byte) []byte {
	rest := payload
	for len(rest) >= 4 {
		chunkType := rest[0]
		// Length field is bytes 2-3 (big-endian).
		length := int(rest[2])<<8 | int(rest[3])
		if length < 4 || length > len(rest) {
			return nil
		}
		if chunkType == 0 { // DATA chunk
			// Chunk value starts at offset 4 (after Type+Flags+Length).
			value := rest[4:length]
			if len(value) < 12 {
				return nil
			}
			// user-data is value[12:].
			return value[12:]
		}
		// Advance to next chunk (account for 4-byte padding).
		padded := (length + 3) &^ 3
		rest = rest[padded:]
	}
	return nil
}

// findSCTPDataChunkPackets returns the subset of packets whose first
// chunk is a DATA chunk (type 0). The SCTP planner's emit() stores chunks
// directly in c.Payload; the first byte of c.Payload is the first chunk's
// type byte.
func findSCTPDataChunkPackets(packets []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range packets {
		if c.L4.Protocol != "sctp" || len(c.Payload) == 0 {
			continue
		}
		if c.Payload[0] == 0 { // first chunk type = 0 (DATA)
			out = append(out, c)
		}
	}
	return out
}

// TestSCTPChunk_FileSource_Literal verifies that when SCTPChunk.FileSource
// is set with a Literal, the DATA chunk payload carries the resolved bytes
// instead of inline chunk.Data.
func TestSCTPChunk_FileSource_Literal(t *testing.T) {
	p := sctp.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	spec := sctpFileSourceSpec("SCTP-FILE-BYTES")
	ctx := sctp.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}

	// Find the two DATA chunk packets (chunk 0 with FileSource, chunk 1
	// with inline Data). INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK/SHUTDOWN
	// have non-zero chunk types — the filter finds only DATA chunks.
	dataPkts := findSCTPDataChunkPackets(packets)
	if len(dataPkts) != 2 {
		t.Fatalf("found %d DATA chunk packets, want 2", len(dataPkts))
	}
	payload0 := extractSCTPDataChunkPayload(dataPkts[0].Payload)
	payload1 := extractSCTPDataChunkPayload(dataPkts[1].Payload)
	if !bytes.Equal(payload0, []byte("SCTP-FILE-BYTES")) {
		t.Errorf("chunk 0 DATA payload got %q, want %q (FileSource.Literal)",
			string(payload0), "SCTP-FILE-BYTES")
	}
	if !bytes.Equal(payload1, []byte("INLINE-CHUNK-DATA")) {
		t.Errorf("chunk 1 DATA payload got %q, want %q (inline Data, backward compat)",
			string(payload1), "INLINE-CHUNK-DATA")
	}
}

// TestSCTPChunk_FileSource_BackwardCompat verifies that when FileSource is
// nil on all chunks, the inline Data is used as before (no regression).
func TestSCTPChunk_FileSource_BackwardCompat(t *testing.T) {
	p := sctp.NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 38413, DstPort: 38412,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			Chunks: []core.SCTPChunk{
				{SID: 1, SSN: 0, PPID: 60, Direction: "up", Data: []byte("hello-sctp")},
			},
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	dataPkts := findSCTPDataChunkPackets(packets)
	if len(dataPkts) != 1 {
		t.Fatalf("found %d DATA chunk packets, want 1", len(dataPkts))
	}
	got := extractSCTPDataChunkPayload(dataPkts[0].Payload)
	if !bytes.Equal(got, []byte("hello-sctp")) {
		t.Errorf("DATA payload got %q, want %q (inline Data, backward compat)",
			string(got), "hello-sctp")
	}
}

// TestSCTPChunk_FileSource_NilCacheNoFallback verifies the precedence
// contract: when chunk.FileSource is set but no cache is injected, the
// planner skips the chunk (does NOT fall through to inline Data).
func TestSCTPChunk_FileSource_NilCacheNoFallback(t *testing.T) {
	p := sctp.NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 38413, DstPort: 38412,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			Chunks: []core.SCTPChunk{
				{
					SID: 1, SSN: 0, PPID: 60, Direction: "up",
					FileSource: &filesystem.FileSource{Literal: "FILE-BYTES"},
					// Data set to a sentinel that must NOT appear when
					// FileSource is set without a cache.
					Data: []byte("FALLBACK-MUST-NOT-APPEAR"),
				},
			},
		},
	}
	// No sctp.WithPayloadCache: ctx has no cache.
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	dataPkts := findSCTPDataChunkPackets(packets)
	if len(dataPkts) != 0 {
		t.Errorf("FileSource set without cache: got %d DATA packets, want 0 (chunk skipped)", len(dataPkts))
	}
}

// TestSCTPChunk_FileSource_PrecedenceOverInlineData verifies the
// precedence contract: when BOTH FileSource and inline Data are set,
// FileSource wins.
func TestSCTPChunk_FileSource_PrecedenceOverInlineData(t *testing.T) {
	p := sctp.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 38413, DstPort: 38412,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			Chunks: []core.SCTPChunk{
				{
					SID: 1, SSN: 0, PPID: 60, Direction: "up",
					FileSource: &filesystem.FileSource{Literal: "FROM-FILESOURCE"},
					Data:       []byte("FROM-INLINE-DATA"),
				},
			},
		},
	}
	ctx := sctp.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	dataPkts := findSCTPDataChunkPackets(packets)
	if len(dataPkts) != 1 {
		t.Fatalf("found %d DATA chunk packets, want 1", len(dataPkts))
	}
	got := extractSCTPDataChunkPayload(dataPkts[0].Payload)
	if !bytes.Equal(got, []byte("FROM-FILESOURCE")) {
		t.Errorf("DATA payload got %q, want %q (FileSource must win over inline Data)",
			string(got), "FROM-FILESOURCE")
	}
}

// TestSCTPChunk_FileSource_BinaryWithNUL verifies binary payloads (NUL
// bytes) round-trip through the DATA chunk. SCTP carries bytes directly
// (no JSON string-field marshalling), so NUL bytes ride through without
// issue. The test guards against future refactors that route through a
// string field (which would corrupt NUL bytes via JSON).
func TestSCTPChunk_FileSource_BinaryWithNUL(t *testing.T) {
	p := sctp.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	nulBytes := []byte{0x41, 0x42, 0x00, 0x43, 0x44} // "AB\0CD"
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 38413, DstPort: 38412,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SCTP: &core.SCTPConfig{
			Chunks: []core.SCTPChunk{
				{
					SID: 1, SSN: 0, PPID: 60, Direction: "up",
					FileSource: &filesystem.FileSource{Literal: string(nulBytes)},
				},
			},
		},
	}
	ctx := sctp.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	dataPkts := findSCTPDataChunkPackets(packets)
	if len(dataPkts) != 1 {
		t.Fatalf("found %d DATA chunk packets, want 1", len(dataPkts))
	}
	got := extractSCTPDataChunkPayload(dataPkts[0].Payload)
	if !bytes.Equal(got, nulBytes) {
		t.Errorf("DATA payload got % x, want % x (binary with NUL must round-trip)",
			got, nulBytes)
	}
}
