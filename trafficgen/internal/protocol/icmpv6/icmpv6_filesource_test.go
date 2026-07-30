package icmpv6_test

// ICMPv6 FileSource integration tests. Mirrors the ICMPv4 FileSource tests
// (icmp_filesource_test.go) and the FTP pattern: when ICMPv6Config.FileSource
// is set, the planner resolves the ICMPv6 echo data bytes via
// PayloadCache.GetOrLoad (using the cache injected through
// core.WithPayloadCache) instead of inline ICMPv6Config.Data.
//
// Precedence contract (mirrors ICMPv4):
//  1. icmpv6Config.FileSource != nil -> PayloadCache.GetOrLoad(ctx, *icmpv6Config.FileSource)
//  2. else icmpv6Config.Data (inline)
//
// "Set Data derived from bytes if Data is nil" caveat: applies when
// FileSource is nil - don't override user-set Data with empty bytes. When
// FileSource is non-nil, FileSource wins (matches ICMPv4 precedence).
//
// Multi-session fallback (mirrors ICMPv4 lines 144-147): when a Pattern
// step leaves Data nil, the step falls back to the top-level resolved
// echoData (which honors FileSource). Steps with their own Data override.

import (
	"bytes"
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/icmpv6"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// extractICMPv6EchoData extracts the echo data bytes from an ICMPv6 packet's
// payload. ICMPv6 Echo Request/Reply header is 8 bytes (Type + Code +
// Checksum + Identifier + Sequence); the echo data follows.
func extractICMPv6EchoData(payload []byte) []byte {
	if len(payload) < 8 {
		return nil
	}
	return payload[8:]
}

// icmpv6BaseSpec returns a valid IPv6 Echo Request spec (ULA addresses).
func icmpv6BaseSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "fd00::1", DstIP: "fd00::2",
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		ICMPv6: &core.ICMPv6Config{
			Type:       icmpv6.TypeEchoRequestV6,
			Code:       0,
			Identifier: 0xbeef,
			Sequence:   7,
		},
	}
}

// findEchoRequest returns the Echo Request packet's echo data from a list
// of packet configs (direction "up", type 128).
func findEchoRequest(t *testing.T, packets []core.PacketConfig) []byte {
	t.Helper()
	for _, c := range packets {
		if c.L4.Protocol != "icmpv6" || len(c.Payload) < 8 {
			continue
		}
		if c.Direction == "up" && c.Payload[0] == icmpv6.TypeEchoRequestV6 {
			return extractICMPv6EchoData(c.Payload)
		}
	}
	t.Fatal("no Echo Request packet found")
	return nil
}

// findEchoReply returns the Echo Reply packet's echo data from a list of
// packet configs (direction "down", type 129).
func findEchoReply(t *testing.T, packets []core.PacketConfig) []byte {
	t.Helper()
	for _, c := range packets {
		if c.L4.Protocol != "icmpv6" || len(c.Payload) < 8 {
			continue
		}
		if c.Direction == "down" && c.Payload[0] == icmpv6.TypeEchoReplyV6 {
			return extractICMPv6EchoData(c.Payload)
		}
	}
	t.Fatal("no Echo Reply packet found")
	return nil
}

// drainCfgs collects all configs from the channel.
func drainCfgs(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// TestICMPv6_FileSource_Literal verifies that when ICMPv6Config.FileSource
// is set with a Literal, the ICMPv6 echo data carries the resolved bytes
// instead of inline ICMPv6Config.Data.
func TestICMPv6_FileSource_Literal(t *testing.T) {
	p := icmpv6.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	spec := icmpv6BaseSpec()
	spec.ICMPv6.FileSource = &filesystem.FileSource{Literal: "ICMPV6-FILE-BYTES"}

	ctx := core.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drainCfgs(ch)

	// Echo Request (up) + Echo Reply (down). Both should carry the
	// resolved bytes as echo data.
	requestEcho := findEchoRequest(t, packets)
	replyEcho := findEchoReply(t, packets)
	if !bytes.Equal(requestEcho, []byte("ICMPV6-FILE-BYTES")) {
		t.Errorf("Echo Request data got %q, want %q (FileSource.Literal)",
			string(requestEcho), "ICMPV6-FILE-BYTES")
	}
	if !bytes.Equal(replyEcho, []byte("ICMPV6-FILE-BYTES")) {
		t.Errorf("Echo Reply data got %q, want %q (FileSource.Literal)",
			string(replyEcho), "ICMPV6-FILE-BYTES")
	}
}

// TestICMPv6_FileSource_BackwardCompat verifies that when FileSource is nil,
// the inline Data is used as before (no regression).
func TestICMPv6_FileSource_BackwardCompat(t *testing.T) {
	p := icmpv6.NewPlanner()
	spec := icmpv6BaseSpec()
	spec.ICMPv6.Data = []byte("inline-ping6")

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drainCfgs(ch)
	got := findEchoRequest(t, packets)
	if !bytes.Equal(got, []byte("inline-ping6")) {
		t.Errorf("Echo Request data got %q, want %q (inline Data, backward compat)",
			string(got), "inline-ping6")
	}
}

// TestICMPv6_FileSource_PrecedenceOverInlineData verifies the precedence
// contract: when BOTH FileSource and inline Data are set, FileSource wins.
func TestICMPv6_FileSource_PrecedenceOverInlineData(t *testing.T) {
	p := icmpv6.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	spec := icmpv6BaseSpec()
	spec.ICMPv6.FileSource = &filesystem.FileSource{Literal: "FROM-FILESOURCE"}
	spec.ICMPv6.Data = []byte("FROM-INLINE-DATA")

	ctx := core.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drainCfgs(ch)
	got := findEchoRequest(t, packets)
	if !bytes.Equal(got, []byte("FROM-FILESOURCE")) {
		t.Errorf("Echo Request data got %q, want %q (FileSource must win over inline Data)",
			string(got), "FROM-FILESOURCE")
	}
}

// TestICMPv6_FileSource_BinaryWithNUL verifies binary payloads (NUL bytes)
// round-trip through the ICMPv6 echo data. ICMPv6 carries bytes directly in
// the packet payload (no JSON string-field marshalling at the planner
// layer), so NUL bytes ride through without issue.
func TestICMPv6_FileSource_BinaryWithNUL(t *testing.T) {
	p := icmpv6.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	nulBytes := []byte{0x41, 0x42, 0x00, 0x43, 0x44} // "AB\0CD"
	spec := icmpv6BaseSpec()
	spec.ICMPv6.FileSource = &filesystem.FileSource{Literal: string(nulBytes)}

	ctx := core.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drainCfgs(ch)
	got := findEchoRequest(t, packets)
	if !bytes.Equal(got, nulBytes) {
		t.Errorf("Echo Request data got % x, want % x (binary with NUL must round-trip)",
			got, nulBytes)
	}
}

// TestICMPv6_FileSource_PatternSteps verifies that FileSource resolution
// applies to multi-session ping steps when the step leaves Data nil. The
// top-level FileSource supplies the bytes for any step without its own
// Data. Steps with their own Data override.
func TestICMPv6_FileSource_PatternSteps(t *testing.T) {
	p := icmpv6.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	spec := icmpv6BaseSpec()
	spec.ICMPv6.Identifier = 0x1234
	spec.ICMPv6.FileSource = &filesystem.FileSource{Literal: "STEP-FILE-BYTES"}
	spec.ICMPv6.Pattern = []core.ICMPv6Step{
		{Type: icmpv6.TypeEchoRequestV6, Code: 0, Sequence: 1},              // Data nil -> FileSource
		{Type: icmpv6.TypeEchoRequestV6, Code: 0, Sequence: 2, Data: []byte("STEP-INLINE")},
	}

	ctx := core.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drainCfgs(ch)

	// Two Echo Request steps, each with an Echo Reply. Step 1 should
	// carry FileSource bytes; step 2 should carry inline Data.
	var step1Req, step2Req []byte
	for _, c := range packets {
		if c.L4.Protocol != "icmpv6" || len(c.Payload) < 8 {
			continue
		}
		if c.Direction != "up" || c.Payload[0] != icmpv6.TypeEchoRequestV6 {
			continue
		}
		// Sequence is bytes 6-7 of the ICMPv6 header.
		seq := uint16(c.Payload[6])<<8 | uint16(c.Payload[7])
		switch seq {
		case 1:
			step1Req = extractICMPv6EchoData(c.Payload)
		case 2:
			step2Req = extractICMPv6EchoData(c.Payload)
		}
	}
	if !bytes.Equal(step1Req, []byte("STEP-FILE-BYTES")) {
		t.Errorf("step 1 Echo Request data got %q, want %q (FileSource falls through to step with nil Data)",
			string(step1Req), "STEP-FILE-BYTES")
	}
	if !bytes.Equal(step2Req, []byte("STEP-INLINE")) {
		t.Errorf("step 2 Echo Request data got %q, want %q (step's own Data overrides FileSource)",
			string(step2Req), "STEP-INLINE")
	}
}

// TestICMPv6_StepDataFallbackToTopLevel verifies that when no FileSource is
// set and a Pattern step leaves Data nil, the step falls back to the
// top-level ICMPv6Config.Data (mirrors ICMPv4 lines 144-147).
func TestICMPv6_StepDataFallbackToTopLevel(t *testing.T) {
	p := icmpv6.NewPlanner()
	spec := icmpv6BaseSpec()
	spec.ICMPv6.Data = []byte("TOP-LEVEL-DATA")
	spec.ICMPv6.Pattern = []core.ICMPv6Step{
		{Type: icmpv6.TypeEchoRequestV6, Code: 0, Sequence: 1},              // Data nil -> top-level
		{Type: icmpv6.TypeEchoRequestV6, Code: 0, Sequence: 2, Data: []byte("STEP-OWN")},
	}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	packets := drainCfgs(ch)

	var step1Req, step2Req []byte
	for _, c := range packets {
		if c.L4.Protocol != "icmpv6" || len(c.Payload) < 8 {
			continue
		}
		if c.Direction != "up" || c.Payload[0] != icmpv6.TypeEchoRequestV6 {
			continue
		}
		seq := uint16(c.Payload[6])<<8 | uint16(c.Payload[7])
		switch seq {
		case 1:
			step1Req = extractICMPv6EchoData(c.Payload)
		case 2:
			step2Req = extractICMPv6EchoData(c.Payload)
		}
	}
	if !bytes.Equal(step1Req, []byte("TOP-LEVEL-DATA")) {
		t.Errorf("step 1 data got %q, want %q (nil step.Data should fall back to top-level Data)",
			string(step1Req), "TOP-LEVEL-DATA")
	}
	if !bytes.Equal(step2Req, []byte("STEP-OWN")) {
		t.Errorf("step 2 data got %q, want %q (step's own Data wins)",
			string(step2Req), "STEP-OWN")
	}
}
