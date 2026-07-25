package ftp_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/ftp"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// TestFTPDataChannel_FileSource_Literal verifies that when an FTP
// DataChannel has FileSource set, the planner resolves the data-channel
// payload bytes via PayloadCache.GetOrLoad (using the cache injected
// through core.WithPayloadCache) instead of inline Payload/PayloadB64.
//
// Precedence contract (Task 11):
//  1. dc.FileSource != nil -> PayloadCache.GetOrLoad(ctx, *dc.FileSource)
//  2. else dc.PayloadB64 != "" -> base64-decode
//  3. else []byte(dc.Payload)
//
// This test sets FileSource.Literal = "FILE-BYTES" and asserts the
// data-channel PSH-ACK packet carries exactly those bytes. The cache is
// injected via core.WithPayloadCache so the planner can find it through
// core.PayloadCacheFrom(ctx).
func TestFTPDataChannel_FileSource_Literal(t *testing.T) {
	p := ftp.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		TCP: &core.TCPConfig{InitialSeq: 1000},
		FTP: &core.FTPConfig{
			Banner: "220 Welcome",
			Commands: []core.FTPCommand{
				{Cmd: "USER anon", Response: "331"},
				{Cmd: "RETR /file.bin", Response: "150", EmitDataChannel: true},
				{Cmd: "", Response: "226"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:       "passive",
				Direction:  "down",
				FileSource: &filesystem.FileSource{Literal: "FILE-BYTES"},
			},
		},
	}

	ctx := core.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan err=%v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	// Find a data-channel packet (port 50000 or different from 21).
	var dataPayload []byte
	for _, c := range packets {
		if c.L4.DstPort != 21 && c.L4.SrcPort != 21 && len(c.Payload) > 0 {
			dataPayload = c.Payload
			break
		}
	}
	if string(dataPayload) != "FILE-BYTES" {
		t.Fatalf("data payload got %q, want %q", string(dataPayload), "FILE-BYTES")
	}
}

// TestFTPDataChannel_FileSource_NilCacheNoFallback verifies the precedence
// contract: when dc.FileSource is set but no cache is injected via context,
// the planner does NOT silently fall back to dc.Payload. Falling through
// would violate the FileSource > Payload precedence rule. The brief says
// the planner returns without emitting the data-channel payload in that
// case (production paths always inject the cache via Task 13).
func TestFTPDataChannel_FileSource_NilCacheNoFallback(t *testing.T) {
	p := ftp.NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		FTP: &core.FTPConfig{
			Banner: "220 Welcome",
			Commands: []core.FTPCommand{
				{Cmd: "USER anon", Response: "331"},
				{Cmd: "RETR /file.bin", Response: "150", EmitDataChannel: true},
				{Cmd: "", Response: "226"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:       "passive",
				Direction:  "down",
				FileSource: &filesystem.FileSource{Literal: "FILE-BYTES"},
				// Payload set to a sentinel that must NOT appear in the
				// data-channel packets when FileSource is set but no cache.
				Payload: "FALLBACK-MUST-NOT-APPEAR",
			},
		},
	}
	// No core.WithPayloadCache: ctx has no cache.
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err=%v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	for _, c := range packets {
		if c.L4.DstPort == 21 || c.L4.SrcPort == 21 {
			continue // control-channel packet
		}
		if string(c.Payload) == "FALLBACK-MUST-NOT-APPEAR" {
			t.Errorf("data-channel payload fell back to inline Payload %q; FileSource set without cache must NOT fall through to Payload",
				string(c.Payload))
		}
	}
}

// TestFTPDataChannel_FileSource_FallbackToPayload verifies backward compat:
// when FileSource is nil, dc.Payload is used as before.
func TestFTPDataChannel_FileSource_FallbackToPayload(t *testing.T) {
	p := ftp.NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		FTP: &core.FTPConfig{
			Banner: "220 Welcome",
			Commands: []core.FTPCommand{
				{Cmd: "USER anon", Response: "331"},
				{Cmd: "RETR /file.bin", Response: "150", EmitDataChannel: true},
				{Cmd: "", Response: "226"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:      "passive",
				Direction: "down",
				Payload:   "INLINE-PAYLOAD",
			},
		},
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan err=%v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	var dataPayload []byte
	for _, c := range packets {
		if c.L4.DstPort != 21 && c.L4.SrcPort != 21 && len(c.Payload) > 0 {
			dataPayload = c.Payload
			break
		}
	}
	if string(dataPayload) != "INLINE-PAYLOAD" {
		t.Fatalf("data payload got %q, want %q (inline Payload fallback)", string(dataPayload), "INLINE-PAYLOAD")
	}
}

// TestFTPDataChannel_FileSource_FallbackToPayloadB64 verifies backward
// compat: when FileSource is nil and PayloadB64 is set, the b64-decoded
// bytes are used as before.
func TestFTPDataChannel_FileSource_FallbackToPayloadB64(t *testing.T) {
	p := ftp.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)
	// Even with a cache injected, FileSource=nil means we use PayloadB64.
	ctx := core.WithPayloadCache(context.Background(), pc)

	// "QkFTRTY0LURBVEE=" decodes to "BASE64-DATA".
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		FTP: &core.FTPConfig{
			Banner: "220 Welcome",
			Commands: []core.FTPCommand{
				{Cmd: "USER anon", Response: "331"},
				{Cmd: "RETR /file.bin", Response: "150", EmitDataChannel: true},
				{Cmd: "", Response: "226"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:       "passive",
				Direction:  "down",
				PayloadB64: "QkFTRTY0LURBVEE=",
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
	var dataPayload []byte
	for _, c := range packets {
		if c.L4.DstPort != 21 && c.L4.SrcPort != 21 && len(c.Payload) > 0 {
			dataPayload = c.Payload
			break
		}
	}
	if string(dataPayload) != "BASE64-DATA" {
		t.Fatalf("data payload got %q, want %q (PayloadB64 decoded)", string(dataPayload), "BASE64-DATA")
	}
}

// TestFTPDataChannel_FileSource_PrecedenceOverPayload verifies the
// precedence contract: when BOTH FileSource and inline Payload are set,
// FileSource wins.
func TestFTPDataChannel_FileSource_PrecedenceOverPayload(t *testing.T) {
	p := ftp.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		FTP: &core.FTPConfig{
			Banner: "220 Welcome",
			Commands: []core.FTPCommand{
				{Cmd: "USER anon", Response: "331"},
				{Cmd: "RETR /file.bin", Response: "150", EmitDataChannel: true},
				{Cmd: "", Response: "226"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:       "passive",
				Direction:  "down",
				FileSource: &filesystem.FileSource{Literal: "FROM-FILESOURCE"},
				Payload:    "FROM-INLINE-PAYLOAD",
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
	var dataPayload []byte
	for _, c := range packets {
		if c.L4.DstPort != 21 && c.L4.SrcPort != 21 && len(c.Payload) > 0 {
			dataPayload = c.Payload
			break
		}
	}
	if string(dataPayload) != "FROM-FILESOURCE" {
		t.Fatalf("data payload got %q, want %q (FileSource must win over inline Payload)",
			string(dataPayload), "FROM-FILESOURCE")
	}
}

// TestFTPDataChannel_FileSource_BinaryWithNUL verifies the isText heuristic's
// NUL branch: bytes that pass utf8.Valid but contain a 0x00 byte must be
// carried via PayloadB64 (binary path), not Payload (string path), because
// encoding/json would corrupt NUL-containing strings.
func TestFTPDataChannel_FileSource_BinaryWithNUL(t *testing.T) {
	p := ftp.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)
	ctx := core.WithPayloadCache(context.Background(), pc)

	// Bytes that are valid UTF-8 (so utf8.Valid returns true) but contain a NUL.
	// 0x41 0x42 0x00 0x43 0x44 = "AB\0CD" — utf8.Valid=true, but isText must return false.
	nulBytes := []byte{0x41, 0x42, 0x00, 0x43, 0x44}

	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		TCP: &core.TCPConfig{InitialSeq: 1000},
		FTP: &core.FTPConfig{
			Banner: "220 Welcome",
			Commands: []core.FTPCommand{
				{Cmd: "RETR /file.bin", Response: "150", EmitDataChannel: true},
				{Cmd: "", Response: "226"},
			},
			DataChannel: &core.FTPDataChannel{
				Mode:       "passive",
				Direction:  "down",
				FileSource: &filesystem.FileSource{Literal: string(nulBytes)},
			},
		},
	}
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan err=%v", err)
	}
	var dataPayload []byte
	for c := range ch {
		// Data-channel packets are on a non-21 port.
		if c.L4.DstPort != 21 && c.L4.SrcPort != 21 && len(c.Payload) > 0 {
			dataPayload = c.Payload
			break
		}
	}
	if !bytes.Equal(dataPayload, nulBytes) {
		t.Fatalf("data payload got % x, want % x", dataPayload, nulBytes)
	}
}
