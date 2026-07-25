package sip_test

// SIP FileSource integration tests (Task 12). Mirrors the FTP pattern
// (Task 11): when SIPMedia.FileSource is set, the planner resolves the
// RTP frame payload bytes via PayloadCache.GetOrLoad (using the cache
// injected through sip.WithPayloadCache) instead of synthesizing
// zero-byte placeholder payloads.
//
// Precedence contract (Task 12):
//  1. media.FileSource != nil -> PayloadCache.GetOrLoad(ctx, *media.FileSource)
//  2. else synthesize FrameSize zero bytes per frame (legacy behavior)
//
// Frame-splitting: when FileSource.Literal = "abcdefghij" (10 bytes) and
// FrameSize=4, expect 3 RTP payloads: "abcd", "efgh", "ij". FrameSize <= 0
// treats the whole bytes as one frame (do not divide by zero).

import (
	"bytes"
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/sip"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// sipFileSourceSpec returns a SIP spec with a 4-message dialog and a
// SIPMedia whose FileSource is set to a known Literal. ACK is flagged
// with EmitMedia=true so RTP frames emit between ACK and BYE.
func sipFileSourceSpec(literal string, frameSize int) core.FlowSpec {
	return core.FlowSpec{
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
				Frames:     5,
				PayloadType: 0,
				FrameSize:  frameSize,
				FileSource: &filesystem.FileSource{Literal: literal},
			},
		},
	}
}

// findRTPPackets returns configs whose FlowID ends with ":rtp".
func findRTPPackets(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if len(c.FlowID) > 4 && c.FlowID[len(c.FlowID)-4:] == ":rtp" {
			out = append(out, c)
		}
	}
	return out
}

// TestSIPMedia_FileSource_Literal verifies that when SIPMedia.FileSource
// is set with a Literal, the RTP frame payloads carry bytes derived from
// the literal instead of zero-byte placeholders.
//
// The brief's example: FileSource.Literal = "abcdefghij" (10 bytes),
// FrameSize=4 -> 3 RTP payloads: "abcd", "efgh", "ij".
func TestSIPMedia_FileSource_Literal(t *testing.T) {
	p := sip.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	spec := sipFileSourceSpec("abcdefghij", 4)
	ctx := sip.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	rtp := findRTPPackets(packets)
	if len(rtp) != 3 {
		t.Fatalf("len(rtp)=%d, want 3 (10 bytes / FrameSize=4 -> 3 frames)", len(rtp))
	}
	want := [][]byte{
		[]byte("abcd"),
		[]byte("efgh"),
		[]byte("ij"),
	}
	for i, c := range rtp {
		// RTP payload is bytes 12: of the UDP payload (12-byte RTP header).
		if len(c.Payload) < 12 {
			t.Fatalf("rtp[%d] payload len=%d, want >= 12 (RTP header)", i, len(c.Payload))
		}
		got := c.Payload[12:]
		if !bytes.Equal(got, want[i]) {
			t.Errorf("rtp[%d] frame bytes=%q, want %q", i, string(got), string(want[i]))
		}
	}
}

// TestSIPMedia_FileSource_FrameSizeZeroNoPanic verifies that FrameSize=0
// with a FileSource set does not panic (no divide-by-zero) and emits one
// RTP frame carrying the whole bytes.
func TestSIPMedia_FileSource_FrameSizeZeroNoPanic(t *testing.T) {
	p := sip.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	spec := sipFileSourceSpec("hello", 0)
	ctx := sip.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	rtp := findRTPPackets(packets)
	if len(rtp) != 1 {
		t.Fatalf("len(rtp)=%d, want 1 (FrameSize=0 -> single frame with whole bytes)", len(rtp))
	}
	if len(rtp[0].Payload) < 12 {
		t.Fatalf("rtp[0] payload len=%d, want >= 12", len(rtp[0].Payload))
	}
	got := rtp[0].Payload[12:]
	if string(got) != "hello" {
		t.Errorf("rtp[0] frame bytes=%q, want %q", string(got), "hello")
	}
}

// TestSIPMedia_FileSource_BackwardCompat verifies that when FileSource is
// nil, the legacy zero-byte placeholder behavior is unchanged (the RTP
// payload is FrameSize zero bytes per frame).
func TestSIPMedia_FileSource_BackwardCompat(t *testing.T) {
	p := sip.NewPlanner()
	spec := sipFileSourceSpec("", 160)
	spec.SIP.Media.FileSource = nil // legacy path
	spec.SIP.Media.Frames = 2
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	rtp := findRTPPackets(packets)
	if len(rtp) != 2 {
		t.Fatalf("len(rtp)=%d, want 2 (Frames=2)", len(rtp))
	}
	for i, c := range rtp {
		if len(c.Payload) != 12+160 {
			t.Errorf("rtp[%d] payload len=%d, want %d (12+FrameSize=160)", i, len(c.Payload), 12+160)
		}
		// Bytes 12: must all be zero (placeholder audio).
		for j, b := range c.Payload[12:] {
			if b != 0 {
				t.Errorf("rtp[%d] frame byte %d = %#02x, want 0 (zero placeholder)", i, j, b)
				break
			}
		}
	}
}

// TestSIPMedia_FileSource_NilCacheNoFallback verifies the precedence
// contract: when FileSource is set but no cache is injected, the planner
// does NOT silently fall through to the zero-byte placeholder. The
// function returns without emitting RTP frames (matching FTP's behavior
// on the same precedence-violation condition).
func TestSIPMedia_FileSource_NilCacheNoFallback(t *testing.T) {
	p := sip.NewPlanner()
	spec := sipFileSourceSpec("FILE-BYTES", 4)
	// No sip.WithPayloadCache: ctx has no cache.
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	rtp := findRTPPackets(packets)
	if len(rtp) != 0 {
		t.Errorf("FileSource set without cache: got %d RTP packets, want 0 (must not fall through to placeholder)", len(rtp))
	}
}

// TestSIPMedia_FileSource_BinaryWithNUL verifies the core.IsText
// heuristic's NUL branch: bytes that pass utf8.Valid but contain a 0x00
// byte must still be carried on the RTP frame (the inline-RTP path uses
// udpPayload directly, no SubFlowSpec indirection, so NUL bytes ride
// through without JSON marshalling issues — but the test exercises the
// path to guard against future refactors that route through a string
// field).
func TestSIPMedia_FileSource_BinaryWithNUL(t *testing.T) {
	p := sip.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	nulBytes := []byte{0x41, 0x42, 0x00, 0x43, 0x44} // "AB\0CD"
	spec := sipFileSourceSpec(string(nulBytes), 0)
	ctx := sip.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	rtp := findRTPPackets(packets)
	if len(rtp) != 1 {
		t.Fatalf("len(rtp)=%d, want 1 (FrameSize=0 -> single frame)", len(rtp))
	}
	if len(rtp[0].Payload) < 12 {
		t.Fatalf("rtp[0] payload len=%d, want >= 12", len(rtp[0].Payload))
	}
	got := rtp[0].Payload[12:]
	if !bytes.Equal(got, nulBytes) {
		t.Errorf("rtp[0] frame bytes=% x, want % x (binary with NUL must round-trip)", got, nulBytes)
	}
}
