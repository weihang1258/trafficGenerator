package icmp_test

// ICMP FileSource integration tests (Task 12). Mirrors the FTP pattern
// (Task 11): when ICMPConfig.FileSource is set, the planner resolves the
// ICMP echo data bytes via PayloadCache.GetOrLoad (using the cache injected
// through icmp.WithPayloadCache) instead of inline ICMPConfig.Data.
//
// Precedence contract (Task 12):
//  1. icmpConfig.FileSource != nil -> PayloadCache.GetOrLoad(ctx, *icmpConfig.FileSource)
//  2. else icmpConfig.Data (inline)
//
// "Set Data derived from bytes if Data is nil" caveat: applies when
// FileSource is nil — don't override user-set Data with empty bytes. When
// FileSource is non-nil, FileSource wins (matches FTP precedence).

import (
	"bytes"
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/icmp"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// extractICMPEchoData extracts the echo data bytes from an ICMP packet's
// payload. ICMP Echo Request/Reply header is 8 bytes (Type + Code +
// Checksum + Identifier + Sequence); the echo data follows.
func extractICMPEchoData(payload []byte) []byte {
	if len(payload) < 8 {
		return nil
	}
	return payload[8:]
}

// TestICMP_FileSource_Literal verifies that when ICMPConfig.FileSource is
// set with a Literal, the ICMP echo data carries the resolved bytes
// instead of inline ICMPConfig.Data.
func TestICMP_FileSource_Literal(t *testing.T) {
	p := icmp.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		ICMP: &core.ICMPConfig{
			Type:       icmp.TypeEchoRequest,
			Code:       0,
			Sequence:   7,
			FileSource: &filesystem.FileSource{Literal: "ICMP-FILE-BYTES"},
		},
	}
	ctx := icmp.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	// Echo Request (up) + Echo Reply (down). Both should carry the
	// resolved bytes as echo data.
	var requestEcho, replyEcho []byte
	for _, c := range packets {
		if c.L4.Protocol != "icmp" || len(c.Payload) < 8 {
			continue
		}
		if c.Direction == "up" && c.Payload[0] == icmp.TypeEchoRequest {
			requestEcho = extractICMPEchoData(c.Payload)
		}
		if c.Direction == "down" && c.Payload[0] == icmp.TypeEchoReply {
			replyEcho = extractICMPEchoData(c.Payload)
		}
	}
	if !bytes.Equal(requestEcho, []byte("ICMP-FILE-BYTES")) {
		t.Errorf("Echo Request data got %q, want %q (FileSource.Literal)",
			string(requestEcho), "ICMP-FILE-BYTES")
	}
	if !bytes.Equal(replyEcho, []byte("ICMP-FILE-BYTES")) {
		t.Errorf("Echo Reply data got %q, want %q (FileSource.Literal)",
			string(replyEcho), "ICMP-FILE-BYTES")
	}
}

// TestICMP_FileSource_BackwardCompat verifies that when FileSource is nil,
// the inline Data is used as before (no regression).
func TestICMP_FileSource_BackwardCompat(t *testing.T) {
	p := icmp.NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		ICMP: &core.ICMPConfig{
			Type:     icmp.TypeEchoRequest,
			Code:     0,
			Sequence: 7,
			Data:     []byte("inline-ping"),
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
	for _, c := range packets {
		if c.L4.Protocol != "icmp" || len(c.Payload) < 8 {
			continue
		}
		if c.Direction == "up" && c.Payload[0] == icmp.TypeEchoRequest {
			got := extractICMPEchoData(c.Payload)
			if !bytes.Equal(got, []byte("inline-ping")) {
				t.Errorf("Echo Request data got %q, want %q (inline Data, backward compat)",
					string(got), "inline-ping")
			}
			return
		}
	}
	t.Errorf("no Echo Request packet found")
}

// TestICMP_FileSource_DoesNotOverrideUserData verifies the "set Data
// derived from bytes if Data is nil" caveat: when FileSource is nil, the
// user-set Data stays intact (not replaced with empty bytes).
func TestICMP_FileSource_DoesNotOverrideUserData(t *testing.T) {
	p := icmp.NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		ICMP: &core.ICMPConfig{
			Type:     icmp.TypeEchoRequest,
			Code:     0,
			Sequence: 7,
			Data:     []byte("USER-SET-DATA"),
			// FileSource nil: Data must be preserved.
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
	for _, c := range packets {
		if c.L4.Protocol != "icmp" || len(c.Payload) < 8 {
			continue
		}
		if c.Direction == "up" && c.Payload[0] == icmp.TypeEchoRequest {
			got := extractICMPEchoData(c.Payload)
			if !bytes.Equal(got, []byte("USER-SET-DATA")) {
				t.Errorf("user-set Data overridden when FileSource nil: got %q, want %q",
					string(got), "USER-SET-DATA")
			}
			return
		}
	}
	t.Errorf("no Echo Request packet found")
}

// TestICMP_FileSource_PrecedenceOverInlineData verifies the precedence
// contract: when BOTH FileSource and inline Data are set, FileSource wins.
func TestICMP_FileSource_PrecedenceOverInlineData(t *testing.T) {
	p := icmp.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		ICMP: &core.ICMPConfig{
			Type:       icmp.TypeEchoRequest,
			Code:       0,
			Sequence:   7,
			FileSource: &filesystem.FileSource{Literal: "FROM-FILESOURCE"},
			Data:       []byte("FROM-INLINE-DATA"),
		},
	}
	ctx := icmp.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	for _, c := range packets {
		if c.L4.Protocol != "icmp" || len(c.Payload) < 8 {
			continue
		}
		if c.Direction == "up" && c.Payload[0] == icmp.TypeEchoRequest {
			got := extractICMPEchoData(c.Payload)
			if !bytes.Equal(got, []byte("FROM-FILESOURCE")) {
				t.Errorf("Echo Request data got %q, want %q (FileSource must win over inline Data)",
					string(got), "FROM-FILESOURCE")
			}
			return
		}
	}
	t.Errorf("no Echo Request packet found")
}

// TestICMP_FileSource_BinaryWithNUL verifies binary payloads (NUL bytes)
// round-trip through the ICMP echo data. ICMP carries bytes directly in
// the packet payload (no JSON string-field marshalling at the planner
// layer), so NUL bytes ride through without issue. The test guards against
// future refactors that route through a string field (which would corrupt
// NUL bytes via JSON).
func TestICMP_FileSource_BinaryWithNUL(t *testing.T) {
	p := icmp.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	nulBytes := []byte{0x41, 0x42, 0x00, 0x43, 0x44} // "AB\0CD"
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		ICMP: &core.ICMPConfig{
			Type:       icmp.TypeEchoRequest,
			Code:       0,
			Sequence:   7,
			FileSource: &filesystem.FileSource{Literal: string(nulBytes)},
		},
	}
	ctx := icmp.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	for _, c := range packets {
		if c.L4.Protocol != "icmp" || len(c.Payload) < 8 {
			continue
		}
		if c.Direction == "up" && c.Payload[0] == icmp.TypeEchoRequest {
			got := extractICMPEchoData(c.Payload)
			if !bytes.Equal(got, nulBytes) {
				t.Errorf("Echo Request data got % x, want % x (binary with NUL must round-trip)",
					got, nulBytes)
			}
			return
		}
	}
	t.Errorf("no Echo Request packet found")
}

// TestICMP_FileSource_PatternSteps verifies that FileSource resolution
// applies to multi-session ping steps when the step leaves Data nil. The
// top-level FileSource supplies the bytes for any step without its own
// Data. Steps with their own Data override.
func TestICMP_FileSource_PatternSteps(t *testing.T) {
	p := icmp.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		ICMP: &core.ICMPConfig{
			Identifier: 0x1234,
			FileSource: &filesystem.FileSource{Literal: "STEP-FILE-BYTES"},
			Pattern: []core.ICMPStep{
				{Type: icmp.TypeEchoRequest, Code: 0, Sequence: 1}, // Data nil -> FileSource
				{Type: icmp.TypeEchoRequest, Code: 0, Sequence: 2, Data: []byte("STEP-INLINE")},
			},
		},
	}
	ctx := icmp.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	// Two Echo Request steps, each with an Echo Reply. Step 1 should
	// carry FileSource bytes; step 2 should carry inline Data.
	var step1Req, step2Req []byte
	for _, c := range packets {
		if c.L4.Protocol != "icmp" || len(c.Payload) < 8 {
			continue
		}
		if c.Direction != "up" || c.Payload[0] != icmp.TypeEchoRequest {
			continue
		}
		// Sequence is bytes 6-7 of the ICMP header.
		seq := uint16(c.Payload[6])<<8 | uint16(c.Payload[7])
		switch seq {
		case 1:
			step1Req = extractICMPEchoData(c.Payload)
		case 2:
			step2Req = extractICMPEchoData(c.Payload)
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
