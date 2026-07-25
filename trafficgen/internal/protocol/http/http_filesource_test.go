package http_test

// HTTP FileSource integration tests (Task 12). Mirrors the FTP pattern
// (Task 11): when HTTPConfig.FileSource is set, the planner resolves the
// request body bytes via PayloadCache.GetOrLoad (using the cache injected
// through http.WithPayloadCache) and derives Body / BodyB64 from the
// resolved bytes.
//
// Precedence contract (Task 12):
//  1. httpConfig.FileSource != nil -> PayloadCache.GetOrLoad(ctx, *httpConfig.FileSource)
//     - bytes go into Body (text) or BodyB64 (binary) via core.IsText
//  2. else inline Body / BodyB64 (unchanged behavior)
//
// "Do not override user-set Body" caveat: applies when FileSource is nil
// — don't override user-set Body with empty bytes. When FileSource is
// non-nil, FileSource wins (matches FTP precedence).

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/protocol/http"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// httpRequestPayload returns the bytes of the first up-direction PSH-ACK
// packet (the HTTP request). HTTP requests are segmented by MSS; we
// concatenate segments to reconstruct the full request.
func httpRequestPayload(packets []core.PacketConfig) []byte {
	var out []byte
	for _, c := range packets {
		if c.Direction == "up" && c.L4.Protocol == "tcp" && len(c.Payload) > 0 {
			// Skip handshake/teardown packets (Flags 0x02, 0x12, 0x10,
			// 0x11). PSH-ACK is 0x18.
			if c.L4.Flags == 0x18 {
				out = append(out, c.Payload...)
			}
		}
	}
	return out
}

// TestHTTP_FileSource_Literal verifies that when HTTPConfig.FileSource is
// set with a Literal, the HTTP request body carries the resolved bytes
// instead of inline Body / BodyB64.
func TestHTTP_FileSource_Literal(t *testing.T) {
	p := http.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 2000, DstPort: 80,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		TCP: &core.TCPConfig{Handshake: true, Termination: true},
		HTTP: &core.HTTPConfig{
			Method:     "POST",
			URI:        "/upload",
			FileSource: &filesystem.FileSource{Literal: "HTTP-FILE-BYTES"},
		},
	}
	ctx := http.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	reqPayload := httpRequestPayload(packets)
	if !bytes.Contains(reqPayload, []byte("HTTP-FILE-BYTES")) {
		t.Errorf("request payload does not contain FileSource bytes: %q", string(reqPayload))
	}
	// Verify Content-Length reflects the resolved byte count, not 0.
	if !bytes.Contains(reqPayload, []byte("Content-Length: 15")) {
		t.Errorf("request payload Content-Length missing or wrong: %q", string(reqPayload))
	}
}

// TestHTTP_FileSource_BackwardCompat verifies that when FileSource is nil,
// the inline Body is used as before (no regression).
func TestHTTP_FileSource_BackwardCompat(t *testing.T) {
	p := http.NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 2000, DstPort: 80,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		TCP: &core.TCPConfig{Handshake: true, Termination: true},
		HTTP: &core.HTTPConfig{
			Method: "POST",
			URI:    "/upload",
			Body:   "INLINE-BODY",
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
	reqPayload := httpRequestPayload(packets)
	if !bytes.Contains(reqPayload, []byte("INLINE-BODY")) {
		t.Errorf("request payload missing inline Body: %q", string(reqPayload))
	}
}

// TestHTTP_FileSource_DoesNotOverrideUserBody verifies the "do not override
// user-set Body" caveat: when FileSource is nil, the user-set Body stays
// intact (not replaced with empty bytes).
func TestHTTP_FileSource_DoesNotOverrideUserBody(t *testing.T) {
	p := http.NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 2000, DstPort: 80,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		TCP: &core.TCPConfig{Handshake: true, Termination: true},
		HTTP: &core.HTTPConfig{
			Method: "POST",
			URI:    "/upload",
			Body:   "USER-SET-BODY",
			// FileSource nil: Body must be preserved.
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
	reqPayload := httpRequestPayload(packets)
	if !bytes.Contains(reqPayload, []byte("USER-SET-BODY")) {
		t.Errorf("user-set Body overridden when FileSource nil: %q", string(reqPayload))
	}
}

// TestHTTP_FileSource_PrecedenceOverInlineBody verifies the precedence
// contract: when BOTH FileSource and inline Body are set, FileSource
// wins.
func TestHTTP_FileSource_PrecedenceOverInlineBody(t *testing.T) {
	p := http.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 2000, DstPort: 80,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		TCP: &core.TCPConfig{Handshake: true, Termination: true},
		HTTP: &core.HTTPConfig{
			Method:     "POST",
			URI:        "/upload",
			FileSource: &filesystem.FileSource{Literal: "FROM-FILESOURCE"},
			Body:       "FROM-INLINE-BODY",
		},
	}
	ctx := http.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	reqPayload := httpRequestPayload(packets)
	if !bytes.Contains(reqPayload, []byte("FROM-FILESOURCE")) {
		t.Errorf("FileSource bytes missing (FileSource must win over inline Body): %q", string(reqPayload))
	}
	if bytes.Contains(reqPayload, []byte("FROM-INLINE-BODY")) {
		t.Errorf("inline Body present (FileSource must override): %q", string(reqPayload))
	}
}

// TestHTTP_FileSource_BinaryWithNUL verifies the core.IsText heuristic's
// NUL branch: bytes containing 0x00 are carried via BodyB64 (binary path)
// so they round-trip through JSON marshalling without corruption. The
// HTTP request body ends up carrying the original bytes (base64-decoded
// back to the NUL-bearing bytes by buildHTTPRequestBody's
// resolveRequestBody path).
func TestHTTP_FileSource_BinaryWithNUL(t *testing.T) {
	p := http.NewPlanner()
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	pc := core.NewPayloadCache(fs)

	nulBytes := []byte{0x41, 0x42, 0x00, 0x43, 0x44} // "AB\0CD"
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 2000, DstPort: 80,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		TCP: &core.TCPConfig{Handshake: true, Termination: true},
		HTTP: &core.HTTPConfig{
			Method:     "POST",
			URI:        "/upload",
			FileSource: &filesystem.FileSource{Literal: string(nulBytes)},
		},
	}
	ctx := http.WithPayloadCache(context.Background(), pc)
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var packets []core.PacketConfig
	for c := range ch {
		packets = append(packets, c)
	}
	reqPayload := httpRequestPayload(packets)
	// The HTTP body is the part after the blank-line separator "\r\n\r\n".
	idx := bytes.Index(reqPayload, []byte("\r\n\r\n"))
	if idx < 0 {
		t.Fatalf("no header/body separator in request payload: %q", string(reqPayload))
	}
	body := reqPayload[idx+4:]
	if !bytes.Equal(body, nulBytes) {
		t.Errorf("request body got % x, want % x (binary with NUL must round-trip via BodyB64)",
			body, nulBytes)
	}
	// Verify the body was NOT carried via the text Body field — if it
	// were, the Content-Type sniff would have hit text/plain and the
	// body would not have base64-decoded. We check that the bytes appear
	// in the payload verbatim (the BodyB64 path decodes back to the
	// original bytes via resolveRequestBody).
	if !strings.Contains(string(reqPayload), "Content-Length: 5") {
		t.Errorf("Content-Length missing or wrong for NUL-bearing body: %q", string(reqPayload))
	}
}
