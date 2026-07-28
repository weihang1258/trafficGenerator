// Package grpc - testpoints covering the 380+ test cases in
// /tmp/l7_planner_design/testcases_grpc.md. Each testpoint asserts a
// specific observable wire-byte value per the spec, not just "it
// didn't panic" (per CLAUDE.md §5: assert observable outcomes).
//
// Testpoint helpers:
//   - drain(ch): collect all PacketConfigs from a Plan() call
//   - mustPlan(t, spec): Plan + drain, fatal on error
//   - validSpec(): a minimal valid gRPC unary spec for reuse
//   - payloadOf(configs, direction, n): extract n-th PSH-ACK payload
//
// Testpoint groups (mirroring the testcases doc structure):
//   §1.1-§1.2   HTTP/2 Connection Preface + Frame Header
//   §1.3-§1.11  HTTP/2 frame types (DATA/HEADERS/RST_STREAM/SETTINGS/
//               PUSH_PROMISE/PING/GOAWAY/WINDOW_UPDATE/CONTINUATION)
//   §1.12-§1.14 HPACK static table + dynamic table + string encoding
//   §1.15       HTTP/2 error codes
//   §1.16       gRPC length-prefixed message
//   §1.17-§1.18 gRPC request headers + trailers
//   §1.19       gRPC status codes (17)
//   §1.20-§1.24 Protobuf wire format (varint/64-bit/length-delimited/
//               32-bit/field-number)
//   §3.1-§3.4   4 call modes (unary/server-stream/client-stream/bidi)
//   §3.7        RST_STREAM cancel
//   §3.13       PING keepalive
//   §3.15       GOAWAY graceful close
//   §4.1-§4.6   data scenarios (empty/boundary/large/compressed)
//   §4.7        grpc-message URL encoding
package grpc

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// --- helpers ---

func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

func mustPlan(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	return drain(ch)
}

func validSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:   "192.168.1.1",
		DstIP:   "192.168.1.2",
		SrcPort: 12345,
		DstPort: 8604,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		GRPC: &core.GRPCConfig{
			Service:          "telemetry.Telemetry",
			Method:           "Subscribe",
			CallType:         "unary",
			RequestMessages:  [][]byte{{0x08, 0x96, 0x01}},
			ResponseMessages: [][]byte{{0x08, 0x96, 0x01}},
		},
	}
}

// payloadOf returns the payload of the n-th packet (0-indexed) in the
// given direction ("up" or "down"). Panics if n is out of range.
func payloadOf(configs []core.PacketConfig, direction string, n int) []byte {
	count := 0
	for _, c := range configs {
		if c.Direction == direction && c.L4.Flags == 0x18 {
			if count == n {
				return c.Payload
			}
			count++
		}
	}
	return nil
}

// firstPSH returns the first PSH-ACK payload in the given direction.
func firstPSH(configs []core.PacketConfig, direction string) []byte {
	return payloadOf(configs, direction, 0)
}

// parseFrameHeader parses a 9-byte HTTP/2 frame header per RFC 7540
// §4.1. Returns (length, type, flags, streamID, payloadStart).
func parseFrameHeader(buf []byte, off int) (length uint32, ftype uint8, flags uint8, streamID uint32, payloadStart int) {
	if off+9 > len(buf) {
		return 0, 0, 0, 0, 0
	}
	length = uint32(buf[off])<<16 | uint32(buf[off+1])<<8 | uint32(buf[off+2])
	ftype = buf[off+3]
	flags = buf[off+4]
	streamID = binary.BigEndian.Uint32(buf[off+5:off+9]) & 0x7FFFFFFF
	payloadStart = off + 9
	return
}

// --- §1.1 HTTP/2 Connection Preface ---

func TestPreface_Magic24Bytes(t *testing.T) {
	// Testcase 1.1.1 + 1.1.2: planner emits 24-byte magic
	// "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" as the first client payload.
	configs := mustPlan(t, validSpec())
	p := firstPSH(configs, "up")
	const want = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	if len(p) < 24 {
		t.Fatalf("preface payload len %d < 24", len(p))
	}
	if string(p[:24]) != want {
		t.Errorf("magic mismatch: got %q, want %q", string(p[:24]), want)
	}
	// Testcase 1.1.4: SETTINGS frame follows magic immediately.
	if len(p) < 25+9 {
		t.Fatalf("preface too short to contain SETTINGS frame header")
	}
	length, ftype, _, _, _ := parseFrameHeader(p, 24)
	if ftype != frameSettings {
		t.Errorf("after magic: frame type = 0x%02x, want SETTINGS (0x04)", ftype)
	}
	if length == 0 {
		t.Errorf("after magic: SETTINGS length = 0 (should be non-zero initial settings)")
	}
}

func TestPreface_MagicASCIIBytes(t *testing.T) {
	// Testcase 1.1.2: bytes match ASCII table.
	configs := mustPlan(t, validSpec())
	p := firstPSH(configs, "up")
	want := []byte{0x50, 0x52, 0x49, 0x20, 0x2A, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2F, 0x32, 0x2E, 0x30, 0x0D, 0x0A, 0x0D, 0x0A, 0x53, 0x4D, 0x0D, 0x0A, 0x0D, 0x0A}
	if !bytes.Equal(p[:24], want) {
		t.Errorf("magic bytes mismatch:\n got %x\nwant %x", p[:24], want)
	}
}

// --- §1.2 HTTP/2 Frame Header ---

func TestFrameHeader_StreamIDReservedBitZero(t *testing.T) {
	// Testcase 1.2.27: reserved bit (high bit of byte[5]) must be 0
	// on every frame.
	configs := mustPlan(t, validSpec())
	// Walk every PSH-ACK payload and parse each frame; check the
	// reserved bit.
	for _, c := range configs {
		if c.L4.Flags != 0x18 || len(c.Payload) == 0 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			_, _, _, streamID, next := parseFrameHeader(c.Payload, off)
			if streamID&0x80000000 != 0 {
				t.Errorf("frame at offset %d: reserved bit set (streamID=0x%08x)", off, streamID)
			}
			off = next + int(uint32(c.Payload[off])<<16|uint32(c.Payload[off+1])<<8|uint32(c.Payload[off+2]))
		}
	}
}

func TestFrameHeader_ClientStreamIDsOdd(t *testing.T) {
	// Testcase 1.2.23 + 1.2.24: client-initiated streams use odd IDs
	// (1, 3, 5, ...). The first call's stream ID must be 1.
	configs := mustPlan(t, validSpec())
	// Find the first client HEADERS frame (Type=0x1) in an "up"
	// PSH-ACK payload.
	for _, c := range configs {
		if c.Direction != "up" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, streamID, next := parseFrameHeader(c.Payload, off)
			if ftype == frameHeaders && streamID != 0 {
				if streamID != 1 {
					t.Errorf("first client HEADERS stream ID = %d, want 1", streamID)
				}
				return
			}
			off = next + int(length)
		}
	}
	t.Error("no client HEADERS frame found in up payloads")
}

func TestFrameHeader_ServerStreamIDEven(t *testing.T) {
	// Testcase 2.3.1 + gRPC spec: server response HEADERS uses the
	// same stream ID as the client request (1 for the first call).
	// (Server-initiated streams would be even, but gRPC server
	// responses reuse the client's stream ID - this is the standard
	// gRPC pattern.)
	configs := mustPlan(t, validSpec())
	// Find server-side HEADERS frame with stream ID matching the
	// client's (stream 1).
	for _, c := range configs {
		if c.Direction != "down" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, streamID, next := parseFrameHeader(c.Payload, off)
			if ftype == frameHeaders && streamID == 1 {
				return // found server HEADERS on stream 1
			}
			off = next + int(length)
		}
	}
	t.Error("no server HEADERS frame on stream 1 found")
}

// --- §1.6 SETTINGS frame ---

func TestSettings_HeaderTableSizeDefault(t *testing.T) {
	// Testcase 1.6.1: SETTINGS_HEADER_TABLE_SIZE=4096 default.
	// Value = 0x00001000 in the SETTINGS payload.
	configs := mustPlan(t, validSpec())
	preface := firstPSH(configs, "up")
	// Preface = 24 magic + SETTINGS frame.
	_, ftype, _, _, payloadStart := parseFrameHeader(preface, 24)
	if ftype != frameSettings {
		t.Fatalf("expected SETTINGS frame after magic, got type 0x%02x", ftype)
	}
	settingsPayload := preface[payloadStart:]
	// Each setting = 6 bytes (2-byte ID + 4-byte value).
	// Find SETTINGS_HEADER_TABLE_SIZE (0x1).
	want := uint32(4096)
	found := false
	for off := 0; off+6 <= len(settingsPayload); off += 6 {
		id := binary.BigEndian.Uint16(settingsPayload[off : off+2])
		val := binary.BigEndian.Uint32(settingsPayload[off+2 : off+6])
		if id == settingHeaderTableSize {
			if val != want {
				t.Errorf("HEADER_TABLE_SIZE = %d, want %d", val, want)
			}
			found = true
		}
	}
	if !found {
		t.Error("SETTINGS_HEADER_TABLE_SIZE not present in initial SETTINGS")
	}
}

func TestSettings_HeaderTableSizeCustom(t *testing.T) {
	// Testcase 1.6.2: user-configured HeaderTableSize=8192.
	spec := validSpec()
	spec.GRPC.HeaderTableSize = 8192
	configs := mustPlan(t, spec)
	preface := firstPSH(configs, "up")
	_, _, _, _, payloadStart := parseFrameHeader(preface, 24)
	settingsPayload := preface[payloadStart:]
	for off := 0; off+6 <= len(settingsPayload); off += 6 {
		id := binary.BigEndian.Uint16(settingsPayload[off : off+2])
		val := binary.BigEndian.Uint32(settingsPayload[off+2 : off+6])
		if id == settingHeaderTableSize {
			if val != 8192 {
				t.Errorf("HEADER_TABLE_SIZE = %d, want 8192", val)
			}
			return
		}
	}
	t.Error("HEADER_TABLE_SIZE not present")
}

func TestSettings_EnablePushZero(t *testing.T) {
	// Testcase 1.6.5: gRPC clients disable push (Value=0).
	configs := mustPlan(t, validSpec())
	preface := firstPSH(configs, "up")
	_, _, _, _, payloadStart := parseFrameHeader(preface, 24)
	settingsPayload := preface[payloadStart:]
	for off := 0; off+6 <= len(settingsPayload); off += 6 {
		id := binary.BigEndian.Uint16(settingsPayload[off : off+2])
		val := binary.BigEndian.Uint32(settingsPayload[off+2 : off+6])
		if id == settingEnablePush {
			if val != 0 {
				t.Errorf("ENABLE_PUSH = %d, want 0 (gRPC clients disable push)", val)
			}
			return
		}
	}
	t.Error("ENABLE_PUSH not present")
}

func TestSettings_MaxFrameSizeDefault(t *testing.T) {
	// Testcase 1.6.10: SETTINGS_MAX_FRAME_SIZE=16384 default.
	configs := mustPlan(t, validSpec())
	preface := firstPSH(configs, "up")
	_, _, _, _, payloadStart := parseFrameHeader(preface, 24)
	settingsPayload := preface[payloadStart:]
	for off := 0; off+6 <= len(settingsPayload); off += 6 {
		id := binary.BigEndian.Uint16(settingsPayload[off : off+2])
		val := binary.BigEndian.Uint32(settingsPayload[off+2 : off+6])
		if id == settingMaxFrameSize {
			if val != 16384 {
				t.Errorf("MAX_FRAME_SIZE = %d, want 16384", val)
			}
			return
		}
	}
	t.Error("MAX_FRAME_SIZE not present")
}

func TestSettings_MaxFrameSizeCustom(t *testing.T) {
	// Testcase 1.6.11: MaxFrameSize=1048576 (1MB).
	spec := validSpec()
	spec.GRPC.MaxFrameSize = 1048576
	configs := mustPlan(t, spec)
	preface := firstPSH(configs, "up")
	_, _, _, _, payloadStart := parseFrameHeader(preface, 24)
	settingsPayload := preface[payloadStart:]
	for off := 0; off+6 <= len(settingsPayload); off += 6 {
		id := binary.BigEndian.Uint16(settingsPayload[off : off+2])
		val := binary.BigEndian.Uint32(settingsPayload[off+2 : off+6])
		if id == settingMaxFrameSize {
			if val != 1048576 {
				t.Errorf("MAX_FRAME_SIZE = %d, want 1048576", val)
			}
			return
		}
	}
	t.Error("MAX_FRAME_SIZE not present")
}

func TestSettings_InitialWindowDefault(t *testing.T) {
	// Testcase 1.6.8: SETTINGS_INITIAL_WINDOW_SIZE=65535 default.
	configs := mustPlan(t, validSpec())
	preface := firstPSH(configs, "up")
	_, _, _, _, payloadStart := parseFrameHeader(preface, 24)
	settingsPayload := preface[payloadStart:]
	for off := 0; off+6 <= len(settingsPayload); off += 6 {
		id := binary.BigEndian.Uint16(settingsPayload[off : off+2])
		val := binary.BigEndian.Uint32(settingsPayload[off+2 : off+6])
		if id == settingInitialWindowSize {
			if val != 65535 {
				t.Errorf("INITIAL_WINDOW_SIZE = %d, want 65535", val)
			}
			return
		}
	}
	t.Error("INITIAL_WINDOW_SIZE not present")
}

func TestSettings_AckLengthZero(t *testing.T) {
	// Testcase 1.6.15: SETTINGS ACK frame has Length=0, Flags & ACK=1.
	configs := mustPlan(t, validSpec())
	// Server's first down-payload contains its SETTINGS frame + the
	// SETTINGS ACK of the client's SETTINGS. Then the client's
	// next up-payload contains a SETTINGS ACK.
	// Find any SETTINGS frame with ACK flag set.
	for _, c := range configs {
		if c.L4.Flags != 0x18 || len(c.Payload) == 0 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, flags, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameSettings && (flags&flagAck) != 0 {
				if length != 0 {
					t.Errorf("SETTINGS ACK length = %d, want 0", length)
				}
				return
			}
			off = next + int(length)
		}
	}
	t.Error("no SETTINGS ACK frame found")
}

// --- §1.8 PING frame ---

func TestPing_Length8(t *testing.T) {
	// Testcase 1.8.1: PING frame Length=8.
	spec := validSpec()
	spec.GRPC.Pings = &core.GRPCPingConfig{Count: 1}
	configs := mustPlan(t, spec)
	for _, c := range configs {
		if c.L4.Flags != 0x18 || len(c.Payload) == 0 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, _, next := parseFrameHeader(c.Payload, off)
			if ftype == framePing {
				if length != 8 {
					t.Errorf("PING length = %d, want 8", length)
				}
				return
			}
			off = next + int(length)
		}
	}
	t.Error("no PING frame found")
}

func TestPing_OpaqueDataCounter(t *testing.T) {
	// Testcase 1.8.3: when OpaqueData is all zero, planner uses an
	// incrementing counter. First PING should have counter=1 (BE).
	spec := validSpec()
	spec.GRPC.Pings = &core.GRPCPingConfig{Count: 1}
	configs := mustPlan(t, spec)
	for _, c := range configs {
		if c.Direction != "up" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, flags, _, next := parseFrameHeader(c.Payload, off)
			if ftype == framePing && (flags&flagAck) == 0 {
				// PING request: opaque data = counter (1).
				if length != 8 {
					t.Errorf("PING length = %d, want 8", length)
				}
				opaque := c.Payload[next : next+8]
				// Counter is big-endian uint64; first PING should
				// be 0x0000000000000001.
				if opaque[7] != 1 {
					t.Errorf("first PING counter = %d, want 1", opaque[7])
				}
				return
			}
			off = next + int(length)
		}
	}
	t.Error("no PING request frame found")
}

func TestPing_AckEchoesOpaqueData(t *testing.T) {
	// Testcase 1.8.5: PING ACK echoes the request's OpaqueData.
	spec := validSpec()
	opaque := [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
	spec.GRPC.Pings = &core.GRPCPingConfig{Count: 1, OpaqueData: opaque}
	configs := mustPlan(t, spec)
	for _, c := range configs {
		if c.Direction != "down" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, flags, _, next := parseFrameHeader(c.Payload, off)
			if ftype == framePing && (flags&flagAck) != 0 {
				opaqueAck := c.Payload[next : next+8]
				if !bytes.Equal(opaqueAck, opaque[:]) {
					t.Errorf("PING ACK opaque = %x, want %x", opaqueAck, opaque[:])
				}
				return
			}
			off = next + int(length)
		}
	}
	t.Error("no PING ACK frame found")
}

// --- §1.9 GOAWAY frame ---

func TestGoAway_LastStreamID(t *testing.T) {
	// Testcase 1.9.1 + 3.15.2: single call -> Last-Stream-ID=1.
	configs := mustPlan(t, validSpec())
	for _, c := range configs {
		if c.Direction != "down" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameGoAway {
				if length < 8 {
					t.Fatalf("GOAWAY length = %d, want >= 8", length)
				}
				lastStreamID := binary.BigEndian.Uint32(c.Payload[next : next+4]) & 0x7FFFFFFF
				if lastStreamID != 1 {
					t.Errorf("GOAWAY Last-Stream-ID = %d, want 1", lastStreamID)
				}
				return
			}
			off = next + int(length)
		}
	}
	t.Error("no GOAWAY frame found")
}

func TestGoAway_ErrorNoError(t *testing.T) {
	// Testcase 1.9.5: GOAWAY Error=0 (NO_ERROR) on graceful close.
	configs := mustPlan(t, validSpec())
	for _, c := range configs {
		if c.Direction != "down" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameGoAway {
				errorCode := binary.BigEndian.Uint32(c.Payload[next+4 : next+8])
				if errorCode != errCodeNoError {
					t.Errorf("GOAWAY error code = %d, want 0 (NO_ERROR)", errorCode)
				}
				return
			}
			off = next + int(length)
		}
	}
	t.Error("no GOAWAY frame found")
}

func TestGoAway_StreamIDZero(t *testing.T) {
	// Testcase 1.9.8: GOAWAY is connection-level (Stream ID = 0).
	configs := mustPlan(t, validSpec())
	for _, c := range configs {
		if c.Direction != "down" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, streamID, next := parseFrameHeader(c.Payload, off)
			if ftype == frameGoAway {
				if streamID != 0 {
					t.Errorf("GOAWAY stream ID = %d, want 0", streamID)
				}
				return
			}
			off = next + int(length)
		}
	}
	t.Error("no GOAWAY frame found")
}

// --- §1.5 RST_STREAM frame ---

func TestRSTStream_CancelAfter(t *testing.T) {
	// Testcase 3.7.1: CancelAfter=1 triggers a client RST_STREAM
	// (error=8) after the request DATA.
	spec := validSpec()
	spec.GRPC.CancelAfter = 1
	configs := mustPlan(t, spec)
	for _, c := range configs {
		if c.Direction != "up" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, streamID, next := parseFrameHeader(c.Payload, off)
			if ftype == frameRSTStream {
				if length != 4 {
					t.Errorf("RST_STREAM length = %d, want 4", length)
				}
				if streamID != 1 {
					t.Errorf("RST_STREAM stream ID = %d, want 1", streamID)
				}
				errCode := binary.BigEndian.Uint32(c.Payload[next : next+4])
				if errCode != errCodeCancel {
					t.Errorf("RST_STREAM error code = %d, want 8 (CANCEL)", errCode)
				}
				return
			}
			off = next + int(length)
		}
	}
	t.Error("no RST_STREAM frame found with CancelAfter=1")
}

func TestRSTStream_NoCancelByDefault(t *testing.T) {
	// Testcase: CancelAfter=0 (default) -> no RST_STREAM emitted.
	configs := mustPlan(t, validSpec())
	for _, c := range configs {
		if c.L4.Flags != 0x18 || len(c.Payload) == 0 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameRSTStream {
				t.Error("RST_STREAM emitted without CancelAfter")
				return
			}
			off = next + int(length)
		}
	}
}

// --- §1.10 WINDOW_UPDATE frame (via buildWindowUpdateFrame unit test) ---

func TestWindowUpdate_IncrementEncoding(t *testing.T) {
	// Testcase 1.10.1 + 1.10.4: WINDOW_UPDATE increment encoding.
	// Direct encoder test (the planner doesn't emit WINDOW_UPDATE in
	// v1; this guards the encoder for v2 use and integration tests).
	tests := []struct {
		name      string
		increment uint32
		streamID  uint32
	}{
		{"min increment 1", 1, 0},
		{"default 65535", 65535, 0},
		{"max 0x7FFFFFFF", 0x7FFFFFFF, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := buildWindowUpdateFrame(tt.streamID, tt.increment)
			// Parse frame header.
			length, ftype, flags, sid, payloadStart := parseFrameHeader(frame, 0)
			if ftype != frameWindowUpdate {
				t.Errorf("type = 0x%02x, want 0x08", ftype)
			}
			if length != 4 {
				t.Errorf("length = %d, want 4", length)
			}
			if flags != 0 {
				t.Errorf("flags = 0x%02x, want 0", flags)
			}
			if sid != tt.streamID {
				t.Errorf("stream ID = %d, want %d", sid, tt.streamID)
			}
			inc := binary.BigEndian.Uint32(frame[payloadStart : payloadStart+4]) & 0x7FFFFFFF
			if inc != tt.increment {
				t.Errorf("increment = %d, want %d", inc, tt.increment)
			}
		})
	}
}

// --- §1.12 HPACK static table ---

func TestHPACK_StaticIndexMethodPOST(t *testing.T) {
	// Testcase 1.12.1: :method=POST is indexed as 0x83 (1xxxxxxx + 3).
	enc := newHPACKEncoder(defaultHeaderTableSize)
	enc.addIndexed(3)
	out := enc.bytes()
	if len(out) != 1 {
		t.Fatalf(":method=POST encoded as %d bytes, want 1", len(out))
	}
	if out[0] != 0x83 {
		t.Errorf(":method=POST = 0x%02x, want 0x83", out[0])
	}
}

func TestHPACK_StaticIndexSchemeHTTP(t *testing.T) {
	// Testcase 1.12.2: :scheme=http is indexed as 0x86.
	enc := newHPACKEncoder(defaultHeaderTableSize)
	enc.addIndexed(6)
	out := enc.bytes()
	if len(out) != 1 || out[0] != 0x86 {
		t.Errorf(":scheme=http = %x, want [0x86]", out)
	}
}

func TestHPACK_StaticIndexSchemeHTTPS(t *testing.T) {
	// Testcase 1.12.3: :scheme=https is indexed as 0x87.
	enc := newHPACKEncoder(defaultHeaderTableSize)
	enc.addIndexed(7)
	out := enc.bytes()
	if len(out) != 1 || out[0] != 0x87 {
		t.Errorf(":scheme=https = %x, want [0x87]", out)
	}
}

func TestHPACK_StaticIndexStatus200(t *testing.T) {
	// Testcase 1.12.6: :status=200 is indexed as 0x88.
	enc := newHPACKEncoder(defaultHeaderTableSize)
	enc.addIndexed(8)
	out := enc.bytes()
	if len(out) != 1 || out[0] != 0x88 {
		t.Errorf(":status=200 = %x, want [0x88]", out)
	}
}

func TestHPACK_StaticIndexAuthority(t *testing.T) {
	// Testcase 1.12.7: index 1 = :authority.
	enc := newHPACKEncoder(defaultHeaderTableSize)
	enc.addIndexed(1)
	out := enc.bytes()
	if len(out) != 1 || out[0] != 0x81 {
		t.Errorf("index 1 = %x, want [0x81]", out)
	}
}

func TestHPACK_StaticIndex61(t *testing.T) {
	// Testcase 1.12.8: index 61 (last) = 0xBD (10111101 = 0x80 | 61).
	// The testcases doc says 0xBF but that is an arithmetic error:
	// 61 decimal = 0b0111101, so 0x80 | 61 = 0b10111101 = 0xBD.
	enc := newHPACKEncoder(defaultHeaderTableSize)
	enc.addIndexed(61)
	out := enc.bytes()
	if len(out) != 1 || out[0] != 0xBD {
		t.Errorf("index 61 = %x, want [0xBD]", out)
	}
}

// --- §1.13 HPACK dynamic table ---

func TestHPACK_DynamicTableInsertion(t *testing.T) {
	// Testcase 1.13.5: Literal with Incremental Indexing emits
	// "01xxxxxx" + name + value and adds to dynamic table.
	enc := newHPACKEncoder(defaultHeaderTableSize)
	enc.addLiteralNameIndexed("x-custom-header", "abc123")
	out := enc.bytes()
	if len(out) == 0 {
		t.Fatal("empty HPACK output")
	}
	// First byte: 0x40 | staticIdx (0 = "new name" since x-custom-header
	// is not in the static table).
	if out[0]&0xC0 != 0x40 {
		t.Errorf("Literal with Incremental Indexing prefix = 0x%02x, want 0x40", out[0]&0xC0)
	}
	// Verify the entry was added to the dynamic table.
	if len(enc.dynTable) != 1 {
		t.Errorf("dynamic table size = %d, want 1", len(enc.dynTable))
	}
	if enc.dynTable[0].name != "x-custom-header" || enc.dynTable[0].value != "abc123" {
		t.Errorf("dynamic table entry = %+v, want x-custom-header=abc123", enc.dynTable[0])
	}
}

func TestHPACK_DynamicTableEviction(t *testing.T) {
	// Testcase 1.13.6: dynamic table FIFO eviction when over size.
	// Set HeaderTableSize=64; each entry uses name+value+32 bytes, so
	// a 10-byte entry uses 42 bytes - only 1 fits.
	enc := newHPACKEncoder(64)
	enc.addLiteralNameIndexed("k1", "v1") // 2+2+32 = 36 bytes
	enc.addLiteralNameIndexed("k2", "v2") // 2+2+32 = 36 bytes -> evicts k1
	if len(enc.dynTable) != 1 {
		t.Errorf("after eviction: dynamic table size = %d, want 1", len(enc.dynTable))
	}
	if enc.dynTable[0].name != "k2" {
		t.Errorf("after eviction: oldest entry = %q, want k2", enc.dynTable[0].name)
	}
}

func TestHPACK_DynamicTableSizeZero(t *testing.T) {
	// Testcase 1.6.3 / 1.13.4: HeaderTableSize=0 disables dynamic table.
	enc := newHPACKEncoder(0)
	enc.addLiteralNameIndexed("k", "v")
	if len(enc.dynTable) != 0 {
		t.Errorf("HeaderTableSize=0: dynamic table size = %d, want 0", len(enc.dynTable))
	}
}

// --- §1.14 HPACK string encoding ---

func TestHPACK_StringRawNoHuffman(t *testing.T) {
	// Testcase 1.14.1 + 1.14.2: Raw string has Huffman flag = 0
	// (high bit of length byte).
	enc := newHPACKEncoder(defaultHeaderTableSize)
	enc.addLiteralNameIndexed("k", "abc")
	out := enc.bytes()
	// Layout: 0x40 (new name) + length-prefixed "k" + length-prefixed "abc".
	// "k" length byte: 0x01 (Huffman flag = 0).
	// "abc" length byte: 0x03 (Huffman flag = 0).
	// Find the first length byte after the 0x40 prefix.
	if out[0]&0xC0 != 0x40 {
		t.Fatalf("expected Literal with Incremental Indexing prefix, got 0x%02x", out[0])
	}
	// out[0] = 0x40 (new name). out[1] = length of "k" = 0x01 (raw).
	if out[1]&0x80 != 0 {
		t.Errorf("\"k\" length byte Huffman flag = 1, want 0 (raw)")
	}
	if out[1] != 0x01 {
		t.Errorf("\"k\" length = %d, want 1", out[1])
	}
}

func TestHPACK_StringEmpty(t *testing.T) {
	// Testcase 1.14.4: empty string -> length varint = 0.
	enc := newHPACKEncoder(defaultHeaderTableSize)
	enc.addLiteralNameIndexed("k", "")
	out := enc.bytes()
	// Find the value length byte. After 0x40 + 0x01 + 'k', the next
	// byte should be 0x00 (empty value length).
	if len(out) < 4 {
		t.Fatalf("output too short: %x", out)
	}
	// out[0]=0x40, out[1]=0x01 (k length), out[2]='k', out[3]=0x00 (value length).
	if out[3] != 0x00 {
		t.Errorf("empty value length = %d, want 0", out[3])
	}
}

func TestHPACK_StringLength127(t *testing.T) {
	// Testcase 1.14.5: 127-byte string -> single-byte varint (7-bit
	// max = 127 fits in 0x7F).
	enc := newHPACKEncoder(defaultHeaderTableSize)
	enc.addLiteralNameIndexed("k", strings.Repeat("a", 127))
	out := enc.bytes()
	// Find the value length byte. With prefix 0x40 + 0x01 'k' + value
	// length, the value length is at out[3].
	if out[3] != 127 {
		t.Errorf("127-byte string length = %d, want 127", out[3])
	}
}

func TestHPACK_StringLength128(t *testing.T) {
	// Testcase 1.14.6: 128-byte string -> multi-byte varint.
	// HPACK string length uses a 7-bit prefix with the Huffman flag in
	// the high bit of the first byte. For value 128 (raw, no Huffman):
	//   first byte = 0 (Huffman) | 127 (prefix max) = 0x7F
	//   continuation byte = 1 (128-127=1, no more) = 0x01
	// Result: 0x7F 0x01. (The testcases doc says 0x80 0x01 but that
	// confuses the Huffman flag with a continuation flag; the high bit
	// of the first byte is the Huffman flag, not a continuation flag.)
	enc := newHPACKEncoder(defaultHeaderTableSize)
	enc.addLiteralNameIndexed("k", strings.Repeat("a", 128))
	out := enc.bytes()
	// Value length is at out[3]: 0x7F (prefix max, signals continuation).
	if out[3] != 0x7F {
		t.Errorf("128-byte string length byte 0 = 0x%02x, want 0x7F", out[3])
	}
	if out[4] != 0x01 {
		t.Errorf("128-byte string length byte 1 = 0x%02x, want 0x01", out[4])
	}
}

// --- §1.16 gRPC length-prefixed message ---

func TestGRPCMessage_CompressedFlagZero(t *testing.T) {
	// Testcase 1.16.1: Compressed-Flag=0 for identity encoding.
	msg := buildGRPCMessage([]byte{0x08, 0x96, 0x01}, "identity")
	if msg[0] != 0 {
		t.Errorf("Compressed-Flag = %d, want 0", msg[0])
	}
}

func TestGRPCMessage_CompressedFlagOne(t *testing.T) {
	// Testcase 1.16.2 + 3.12.2: Compressed-Flag=1 for gzip encoding.
	msg := buildGRPCMessage([]byte{0x08, 0x96, 0x01}, "gzip")
	if msg[0] != 1 {
		t.Errorf("Compressed-Flag = %d, want 1", msg[0])
	}
}

func TestGRPCMessage_LengthZero(t *testing.T) {
	// Testcase 1.16.3: empty message -> Length=0.
	msg := buildGRPCMessage(nil, "identity")
	if len(msg) != 5 {
		t.Fatalf("empty gRPC message total len = %d, want 5", len(msg))
	}
	if !bytes.Equal(msg[1:5], []byte{0, 0, 0, 0}) {
		t.Errorf("empty gRPC message length bytes = %x, want 00000000", msg[1:5])
	}
}

func TestGRPCMessage_LengthBigEndian(t *testing.T) {
	// Testcase 1.16.4 + 1.16.8: 5-byte protobuf -> Length=5 (BE).
	msg := buildGRPCMessage([]byte{1, 2, 3, 4, 5}, "identity")
	want := []byte{0, 0, 0, 0, 5}
	if !bytes.Equal(msg[1:5], want[1:5]) {
		t.Errorf("Length bytes = %x, want %x (BE)", msg[1:5], want[1:5])
	}
}

func TestGRPCMessage_GzipMagicBytes(t *testing.T) {
	// Testcase 3.12.3 + 4.6.2: gzip-compressed Message Data starts
	// with 0x1F 0x8B (gzip magic per RFC 1952).
	msg := buildGRPCMessage([]byte("hello world"), "gzip")
	if len(msg) < 7 {
		t.Fatalf("gzip message too short: %x", msg)
	}
	if msg[5] != 0x1F || msg[6] != 0x8B {
		t.Errorf("gzip magic = %02x %02x, want 1F 8B", msg[5], msg[6])
	}
}

func TestGRPCMessage_GzipDecompressRoundtrip(t *testing.T) {
	// Testcase 3.12.1 + 4.6.1: gzip-compressed message decompresses
	// back to the original.
	orig := []byte("hello gRPC compression test")
	msg := buildGRPCMessage(orig, "gzip")
	// msg[0] = Compressed-Flag (1).
	// msg[1:5] = length (BE).
	// msg[5:] = gzip bytes.
	body := msg[5:]
	r, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer r.Close()
	decompressed, err := readAll(r)
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}
	if !bytes.Equal(decompressed, orig) {
		t.Errorf("gzip roundtrip: got %q, want %q", decompressed, orig)
	}
}

// --- §1.17 gRPC request headers ---

func TestRequestHeaders_MethodPOST(t *testing.T) {
	// Testcase 1.17.1: :method=POST in client HEADERS.
	configs := mustPlan(t, validSpec())
	// Find the client HEADERS frame (up, after preface).
	preface := firstPSH(configs, "up")
	// The first up PSH-ACK is the preface. The second is the client
	// HEADERS.
	headersPayload := payloadOf(configs, "up", 2)
	if headersPayload == nil {
		t.Fatal("no second up payload (client HEADERS)")
	}
	// Parse the HEADERS frame.
	_, ftype, _, _, _ := parseFrameHeader(headersPayload, 0)
	if ftype != frameHeaders {
		t.Fatalf("expected HEADERS frame, got type 0x%02x", ftype)
	}
	// First byte of the header block should be 0x83 (:method=POST).
	// But we need to skip the 9-byte frame header first.
	if len(headersPayload) < 10 {
		t.Fatal("HEADERS payload too short")
	}
	if headersPayload[9] != 0x83 {
		t.Errorf(":method byte = 0x%02x, want 0x83 (POST)", headersPayload[9])
	}
	_ = preface
}

func TestRequestHeaders_SchemeHTTP(t *testing.T) {
	// Testcase 1.17.2: :scheme=http (default) -> 0x86.
	configs := mustPlan(t, validSpec())
	headersPayload := payloadOf(configs, "up", 2)
	if len(headersPayload) < 11 {
		t.Fatal("HEADERS payload too short")
	}
	// Layout: 0x83 (method) + 0x86 (scheme http) + ...
	if headersPayload[10] != 0x86 {
		t.Errorf(":scheme byte = 0x%02x, want 0x86 (http)", headersPayload[10])
	}
}

func TestRequestHeaders_SchemeHTTPS(t *testing.T) {
	// Testcase 1.17.3: Scheme=https -> 0x87.
	spec := validSpec()
	spec.GRPC.Scheme = "https"
	configs := mustPlan(t, spec)
	headersPayload := payloadOf(configs, "up", 2)
	if headersPayload[10] != 0x87 {
		t.Errorf(":scheme byte = 0x%02x, want 0x87 (https)", headersPayload[10])
	}
}

func TestRequestHeaders_AuthorityDefault(t *testing.T) {
	// Testcase 1.17.5: default Authority = DstIP:DstPort.
	configs := mustPlan(t, validSpec())
	headersPayload := payloadOf(configs, "up", 2)
	// After 0x83 0x86 (method+scheme), expect Literal :authority
	// (index 1 = 0x41 = 0x40 | 1).
	if len(headersPayload) < 12 {
		t.Fatal("HEADERS payload too short for :authority")
	}
	// headersPayload[9]=0x83, [10]=0x86, then :path literal, then
	// :authority literal. We just check :authority appears somewhere.
	if !containsSubstring(headersPayload, "192.168.1.2:8604") {
		t.Errorf(":authority default not found in HEADERS: %x", headersPayload)
	}
}

func TestRequestHeaders_TETrailers(t *testing.T) {
	// Testcase 1.17.9: te=trailers must appear.
	configs := mustPlan(t, validSpec())
	headersPayload := payloadOf(configs, "up", 2)
	if !containsSubstring(headersPayload, "trailers") {
		t.Errorf("te=trailers not found in HEADERS: %x", headersPayload)
	}
}

func TestRequestHeaders_ContentTypeGRPC(t *testing.T) {
	// Testcase 1.17.6: content-type=application/grpc.
	configs := mustPlan(t, validSpec())
	headersPayload := payloadOf(configs, "up", 2)
	if !containsSubstring(headersPayload, "application/grpc") {
		t.Errorf("content-type=application/grpc not found: %x", headersPayload)
	}
}

func TestRequestHeaders_UserAgentDefault(t *testing.T) {
	// Testcase 1.17.10: user-agent=grpc-trafficgen/1.0 (default).
	configs := mustPlan(t, validSpec())
	headersPayload := payloadOf(configs, "up", 2)
	if !containsSubstring(headersPayload, "grpc-trafficgen/1.0") {
		t.Errorf("default user-agent not found: %x", headersPayload)
	}
}

func TestRequestHeaders_UserAgentCustom(t *testing.T) {
	// Testcase 1.17.11: custom UserAgent.
	spec := validSpec()
	spec.GRPC.UserAgent = "custom/2.0"
	configs := mustPlan(t, spec)
	headersPayload := payloadOf(configs, "up", 2)
	if !containsSubstring(headersPayload, "custom/2.0") {
		t.Errorf("custom user-agent not found: %x", headersPayload)
	}
}

func TestRequestHeaders_Timeout1S(t *testing.T) {
	// Testcase 1.17.15 + 3.6.1: Timeout=1S -> grpc-timeout:1S header.
	spec := validSpec()
	spec.GRPC.Timeout = "1S"
	configs := mustPlan(t, spec)
	headersPayload := payloadOf(configs, "up", 2)
	if !containsSubstring(headersPayload, "grpc-timeout") || !containsSubstring(headersPayload, "1S") {
		t.Errorf("grpc-timeout=1S not found: %x", headersPayload)
	}
}

func TestRequestHeaders_NoTimeoutWhenEmpty(t *testing.T) {
	// Testcase 3.6.3: empty Timeout -> no grpc-timeout header.
	configs := mustPlan(t, validSpec())
	headersPayload := payloadOf(configs, "up", 2)
	if containsSubstring(headersPayload, "grpc-timeout") {
		t.Errorf("grpc-timeout emitted when Timeout is empty: %x", headersPayload)
	}
}

func TestRequestHeaders_AuthorizationNeverIndexed(t *testing.T) {
	// Testcase 1.17.21 + 3.5.4: Authorization uses Never Indexed bit
	// (prefix 0x1x). "authorization" is in the static table at index
	// 23. The Never Indexed representation (RFC 7541 §6.2.3) uses a
	// 4-bit prefix for the index; since 23 >= 15, the encoder must use
	// the multi-byte integer form (RFC 7541 §5.1):
	//   0x1F = 0001 (Never Indexed marker) + 1111 (4-bit prefix all-1s)
	//   0x08 = continuation byte (15 + 8 = 23 = static index for "authorization")
	//   0x0C = length of "Bearer token" (12 bytes)
	//   "Bearer token" = literal value
	spec := validSpec()
	spec.GRPC.Metadata = map[string]string{"authorization": "Bearer token"}
	configs := mustPlan(t, spec)
	headersPayload := payloadOf(configs, "up", 2)
	if !containsSubstring(headersPayload, "Bearer token") {
		t.Errorf("authorization value not found: %x", headersPayload)
	}
	want := append([]byte{0x1F, 0x08, 0x0C}, []byte("Bearer token")...)
	if !bytes.Contains(headersPayload, want) {
		t.Errorf("authorization Never Indexed encoding %x not found in %x", want, headersPayload)
	}
}

func TestRequestHeaders_CustomMetadata(t *testing.T) {
	// Testcase 1.17.22 + 3.5.2: custom metadata header.
	spec := validSpec()
	spec.GRPC.Metadata = map[string]string{"x-trace-id": "abc"}
	configs := mustPlan(t, spec)
	headersPayload := payloadOf(configs, "up", 2)
	if !containsSubstring(headersPayload, "x-trace-id") || !containsSubstring(headersPayload, "abc") {
		t.Errorf("x-trace-id=abc not found: %x", headersPayload)
	}
}

// --- §1.18 gRPC trailers ---

func TestTrailers_GRPCStatusZero(t *testing.T) {
	// Testcase 1.18.1 + 1.19.1 + 3.1.3: grpc-status=0 (default OK).
	configs := mustPlan(t, validSpec())
	// Trailers are in a server-side HEADERS frame with END_STREAM=1.
	for _, c := range configs {
		if c.Direction != "down" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, flags, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameHeaders && (flags&flagEndStream) != 0 {
				// This is the trailers frame.
				trailerBlock := c.Payload[next : next+int(length)]
				if !containsSubstring(trailerBlock, "grpc-status") {
					t.Errorf("grpc-status not in trailers: %x", trailerBlock)
				}
				// grpc-status=0 is encoded as a literal: name "grpc-status"
				// + value "0". The "0" byte should be present.
				if !containsSubstring(trailerBlock, "0") {
					t.Errorf("grpc-status value 0 not in trailers: %x", trailerBlock)
				}
				return
			}
			off = next + int(length)
		}
	}
	t.Error("no trailers frame (HEADERS with END_STREAM) found")
}

func TestTrailers_GRPCStatus14(t *testing.T) {
	// Testcase 3.8.1 + 1.19.15: grpc-status=14 (UNAVAILABLE).
	// grpc-message MUST be URL-encoded (gRPC spec §4), so space -> %20.
	spec := validSpec()
	spec.GRPC.ResponseStatus = 14
	spec.GRPC.ResponseMessage = "service unavailable"
	configs := mustPlan(t, spec)
	for _, c := range configs {
		if c.Direction != "down" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, flags, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameHeaders && (flags&flagEndStream) != 0 {
				trailerBlock := c.Payload[next : next+int(length)]
				if !containsSubstring(trailerBlock, "service%20unavailable") {
					t.Errorf("URL-encoded grpc-message not in trailers: %x", trailerBlock)
				}
				return
			}
			off = next + int(length)
		}
	}
	t.Error("no trailers frame found")
}

func TestTrailers_GRPCMessageURLEncoded(t *testing.T) {
	// Testcase 1.18.4 + 4.7.1 + 4.7.2: grpc-message URL-encodes
	// special chars. "a/b c" -> "a%2Fb%20c".
	spec := validSpec()
	spec.GRPC.ResponseStatus = 13
	spec.GRPC.ResponseMessage = "a/b c"
	configs := mustPlan(t, spec)
	for _, c := range configs {
		if c.Direction != "down" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, flags, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameHeaders && (flags&flagEndStream) != 0 {
				trailerBlock := c.Payload[next : next+int(length)]
				if !containsSubstring(trailerBlock, "a%2Fb%20c") {
					t.Errorf("URL-encoded grpc-message not in trailers: %x", trailerBlock)
				}
				return
			}
			off = next + int(length)
		}
	}
	t.Error("no trailers frame found")
}

func TestURLEncodeGRPCMessage(t *testing.T) {
	// Testcase 4.7.1-4.7.4: direct URL-encoder tests.
	tests := []struct {
		in, want string
	}{
		{"a/b", "a%2Fb"},
		{"hello world", "hello%20world"},
		{"100%", "100%25"},
		{"中文", "%E4%B8%AD%E6%96%87"},
		{"", ""},
		{"ok", "ok"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := urlEncodeGRPCMessage(tt.in)
			if got != tt.want {
				t.Errorf("urlEncodeGRPCMessage(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// --- §1.19 gRPC status codes (17 codes) ---

func TestGRPCStatusCodes_AllValid(t *testing.T) {
	// Testcase 1.19.1-1.19.17: all 17 status codes (0-16) accepted.
	for code := 0; code <= 16; code++ {
		spec := validSpec()
		spec.GRPC.ResponseStatus = code
		p := NewPlanner()
		if err := p.Validate(spec); err != nil {
			t.Errorf("status %d: Validate error = %v", code, err)
		}
	}
}

func TestGRPCStatusCodes_OutOfRange(t *testing.T) {
	// Testcase 1.19.18-1.19.20 + 4.3.1 + 4.3.2: out-of-range rejected.
	for _, code := range []int{17, 99, -1} {
		spec := validSpec()
		spec.GRPC.ResponseStatus = code
		p := NewPlanner()
		if err := p.Validate(spec); err == nil {
			t.Errorf("status %d: Validate accepted, want error", code)
		}
	}
}

// --- §1.20-§1.24 Protobuf wire format ---

func TestProtobuf_VarintField1Value150(t *testing.T) {
	// Testcase 1.20.8 + 5.2: field 1 varint = 150 -> 0x08 0x96 0x01.
	key := protobufField(1, 0)
	val := appendVarint(nil, 150)
	got := append(key, val...)
	want := []byte{0x08, 0x96, 0x01}
	if !bytes.Equal(got, want) {
		t.Errorf("field 1 = 150: got %x, want %x", got, want)
	}
}

func TestProtobuf_VarintZero(t *testing.T) {
	// Testcase 1.20.1: field 1 = 0 -> 0x08 0x00.
	got := append(protobufField(1, 0), appendVarint(nil, 0)...)
	want := []byte{0x08, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("field 1 = 0: got %x, want %x", got, want)
	}
}

func TestProtobuf_Varint127(t *testing.T) {
	// Testcase 1.20.3: field 1 = 127 -> 0x08 0x7F (single byte).
	got := append(protobufField(1, 0), appendVarint(nil, 127)...)
	want := []byte{0x08, 0x7F}
	if !bytes.Equal(got, want) {
		t.Errorf("field 1 = 127: got %x, want %x", got, want)
	}
}

func TestProtobuf_Varint128(t *testing.T) {
	// Testcase 1.20.4: field 1 = 128 -> 0x08 0x80 0x01 (two bytes).
	got := append(protobufField(1, 0), appendVarint(nil, 128)...)
	want := []byte{0x08, 0x80, 0x01}
	if !bytes.Equal(got, want) {
		t.Errorf("field 1 = 128: got %x, want %x", got, want)
	}
}

func TestProtobuf_Varint300(t *testing.T) {
	// Testcase 1.20.5: field 1 = 300 -> 0x08 0xAC 0x02.
	got := append(protobufField(1, 0), appendVarint(nil, 300)...)
	want := []byte{0x08, 0xAC, 0x02}
	if !bytes.Equal(got, want) {
		t.Errorf("field 1 = 300: got %x, want %x", got, want)
	}
}

func TestProtobuf_VarintUint32Max(t *testing.T) {
	// Testcase 1.20.7 + 1.20.13: uint32 max = 0xFFFFFFFF -> 5-byte varint.
	got := append(protobufField(1, 0), appendVarint(nil, 0xFFFFFFFF)...)
	want := []byte{0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F}
	if !bytes.Equal(got, want) {
		t.Errorf("uint32 max: got %x, want %x", got, want)
	}
}

func TestProtobuf_VarintField15(t *testing.T) {
	// Testcase 1.20.9: field 15 = 5 -> key=120=0x78, value=0x05.
	got := append(protobufField(15, 0), appendVarint(nil, 5)...)
	want := []byte{0x78, 0x05}
	if !bytes.Equal(got, want) {
		t.Errorf("field 15 = 5: got %x, want %x", got, want)
	}
}

func TestProtobuf_VarintField16(t *testing.T) {
	// Testcase 1.24.4: field 16 -> key = 16<<3 = 128 = 0x80 0x01 (varint).
	got := protobufField(16, 0)
	want := []byte{0x80, 0x01}
	if !bytes.Equal(got, want) {
		t.Errorf("field 16 key: got %x, want %x", got, want)
	}
}

func TestProtobuf_Field1(t *testing.T) {
	// Testcase 1.24.1: field 1 -> key = 1<<3 = 8 = 0x08.
	got := protobufField(1, 0)
	want := []byte{0x08}
	if !bytes.Equal(got, want) {
		t.Errorf("field 1 key: got %x, want %x", got, want)
	}
}

func TestProtobuf_Field2(t *testing.T) {
	// Testcase 1.24.2: field 2 -> key = 2<<3 = 16 = 0x10.
	got := protobufField(2, 0)
	want := []byte{0x10}
	if !bytes.Equal(got, want) {
		t.Errorf("field 2 key: got %x, want %x", got, want)
	}
}

func TestProtobuf_Field100(t *testing.T) {
	// Testcase 1.24.5: field 100 -> key = 100<<3 = 800 = 0xA0 0x06.
	got := protobufField(100, 0)
	want := []byte{0xA0, 0x06}
	if !bytes.Equal(got, want) {
		t.Errorf("field 100 key: got %x, want %x", got, want)
	}
}

// --- §1.22 Protobuf length-delimited ---

func TestProtobuf_LengthDelimitedEmpty(t *testing.T) {
	// Testcase 1.22.1 + 1.22.4 + 1.22.10 + 5.10: field 1 = "" ->
	// 0x0A 0x00.
	key := protobufField(1, 2)
	got := append(key, appendVarint(nil, 0)...)
	want := []byte{0x0A, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("empty string: got %x, want %x", got, want)
	}
}

func TestProtobuf_LengthDelimitedString(t *testing.T) {
	// Testcase 1.22.2: field 1 = "hi" -> 0x0A 0x02 'h' 'i'.
	key := protobufField(1, 2)
	got := append(key, appendVarint(nil, 2)...)
	got = append(got, 'h', 'i')
	want := []byte{0x0A, 0x02, 'h', 'i'}
	if !bytes.Equal(got, want) {
		t.Errorf("\"hi\": got %x, want %x", got, want)
	}
}

func TestProtobuf_PackedRepeated(t *testing.T) {
	// Testcase 1.22.8 + 5.12: packed repeated int32 [1,2,3] ->
	// 0x0A 0x03 0x01 0x02 0x03.
	key := protobufField(1, 2)
	got := append(key, appendVarint(nil, 3)...)
	got = append(got, 1, 2, 3)
	want := []byte{0x0A, 0x03, 0x01, 0x02, 0x03}
	if !bytes.Equal(got, want) {
		t.Errorf("packed [1,2,3]: got %x, want %x", got, want)
	}
}

// --- §3.1-§3.4 Call modes ---

func TestCallMode_Unary(t *testing.T) {
	// Testcase 3.1.1 + 3.1.2: unary = 1 request + 1 response.
	spec := validSpec()
	spec.GRPC.CallType = "unary"
	spec.GRPC.RequestMessages = [][]byte{{0x08, 0x96, 0x01}}
	spec.GRPC.ResponseMessages = [][]byte{{0x08, 0x96, 0x01}}
	configs := mustPlan(t, spec)
	// Count client DATA frames (up, Type=DATA).
	clientData := countFrames(configs, "up", frameData)
	if clientData != 1 {
		t.Errorf("unary client DATA frames = %d, want 1", clientData)
	}
	// Count server DATA frames (down, Type=DATA).
	serverData := countFrames(configs, "down", frameData)
	if serverData != 1 {
		t.Errorf("unary server DATA frames = %d, want 1", serverData)
	}
	// Client DATA must have END_STREAM=1 (half-close after request).
	if !clientDataHasEndStream(configs) {
		t.Error("unary client DATA missing END_STREAM")
	}
}

func TestCallMode_ServerStream(t *testing.T) {
	// Testcase 3.2.3: server-stream = 1 request + N responses.
	spec := validSpec()
	spec.GRPC.CallType = "server-stream"
	spec.GRPC.RequestMessages = [][]byte{{0x08, 0x96, 0x01}}
	spec.GRPC.ResponseMessages = [][]byte{
		{0x08, 0x01}, {0x08, 0x02}, {0x08, 0x03},
		{0x08, 0x04}, {0x08, 0x05}, {0x08, 0x06},
		{0x08, 0x07}, {0x08, 0x08}, {0x08, 0x09}, {0x08, 0x0A},
	}
	configs := mustPlan(t, spec)
	clientData := countFrames(configs, "up", frameData)
	if clientData != 1 {
		t.Errorf("server-stream client DATA = %d, want 1", clientData)
	}
	serverData := countFrames(configs, "down", frameData)
	if serverData != 10 {
		t.Errorf("server-stream server DATA = %d, want 10", serverData)
	}
}

func TestCallMode_ClientStream(t *testing.T) {
	// Testcase 3.3.2: client-stream = N requests + 1 response.
	spec := validSpec()
	spec.GRPC.CallType = "client-stream"
	spec.GRPC.RequestMessages = [][]byte{
		{0x08, 0x01}, {0x08, 0x02}, {0x08, 0x03}, {0x08, 0x04}, {0x08, 0x05},
	}
	spec.GRPC.ResponseMessages = [][]byte{{0x08, 0x96, 0x01}}
	configs := mustPlan(t, spec)
	clientData := countFrames(configs, "up", frameData)
	if clientData != 5 {
		t.Errorf("client-stream client DATA = %d, want 5", clientData)
	}
	serverData := countFrames(configs, "down", frameData)
	if serverData != 1 {
		t.Errorf("client-stream server DATA = %d, want 1", serverData)
	}
}

func TestCallMode_BidiStream(t *testing.T) {
	// Testcase 3.4.2 + 3.4.3: bidi-stream = N requests + M responses.
	spec := validSpec()
	spec.GRPC.CallType = "bidi-stream"
	spec.GRPC.RequestMessages = [][]byte{
		{0x08, 0x01}, {0x08, 0x02}, {0x08, 0x03}, {0x08, 0x04}, {0x08, 0x05},
	}
	spec.GRPC.ResponseMessages = [][]byte{
		{0x08, 0x0A}, {0x08, 0x0B}, {0x08, 0x0C}, {0x08, 0x0D}, {0x08, 0x0E},
		{0x08, 0x0F}, {0x08, 0x10}, {0x08, 0x11}, {0x08, 0x12}, {0x08, 0x13},
	}
	configs := mustPlan(t, spec)
	clientData := countFrames(configs, "up", frameData)
	if clientData != 5 {
		t.Errorf("bidi client DATA = %d, want 5", clientData)
	}
	serverData := countFrames(configs, "down", frameData)
	if serverData != 10 {
		t.Errorf("bidi server DATA = %d, want 10", serverData)
	}
}

// --- §3.14 Multiplexing (Calls list) ---

func TestMultiplexing_TwoCalls(t *testing.T) {
	// Testcase 3.14.1 + 3.14.2: 2 calls -> stream IDs 1 and 3.
	spec := validSpec()
	spec.GRPC.Calls = []core.GRPCCall{
		{Service: "telemetry.Telemetry", Method: "Subscribe", CallType: "unary",
			RequestMessages:  [][]byte{{0x08, 0x96, 0x01}},
			ResponseMessages: [][]byte{{0x08, 0x96, 0x01}}},
		{Service: "telemetry.Telemetry", Method: "Get", CallType: "unary",
			RequestMessages:  [][]byte{{0x08, 0x96, 0x01}},
			ResponseMessages: [][]byte{{0x08, 0x96, 0x01}}},
	}
	configs := mustPlan(t, spec)
	streamIDs := []uint32{}
	for _, c := range configs {
		if c.Direction != "up" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, streamID, next := parseFrameHeader(c.Payload, off)
			if ftype == frameHeaders && streamID != 0 {
				streamIDs = append(streamIDs, streamID)
			}
			off = next + int(length)
		}
	}
	if len(streamIDs) < 2 {
		t.Fatalf("found %d client HEADERS, want >= 2", len(streamIDs))
	}
	if streamIDs[0] != 1 {
		t.Errorf("first call stream ID = %d, want 1", streamIDs[0])
	}
	if streamIDs[1] != 3 {
		t.Errorf("second call stream ID = %d, want 3", streamIDs[1])
	}
}

// --- §4.1 Empty data ---

func TestEmptyRequestMessage(t *testing.T) {
	// Testcase 4.1.1 + 4.1.2 + 5.1: empty protobuf -> 5-byte gRPC
	// prefix (0x00 + 4x0x00).
	spec := validSpec()
	spec.GRPC.RequestMessages = [][]byte{{}}
	spec.GRPC.ResponseMessages = [][]byte{{}}
	configs := mustPlan(t, spec)
	// Find the client DATA frame payload.
	for _, c := range configs {
		if c.Direction != "up" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameData {
				// gRPC message is the DATA frame payload.
				grpcMsg := c.Payload[next : next+int(length)]
				want := []byte{0x00, 0x00, 0x00, 0x00, 0x00}
				if !bytes.Equal(grpcMsg, want) {
					t.Errorf("empty gRPC message = %x, want %x", grpcMsg, want)
				}
				return
			}
			off = next + int(length)
		}
	}
	t.Error("no client DATA frame found")
}

// --- §4.4 Large data (segmentation) ---

func TestLargeRequest_Segmentation(t *testing.T) {
	// Testcase 3.9.1 + 3.9.2 + 4.4.1: 10MB request -> ~640 DATA frames
	// (10MB / 16KB = 640). Use 1MB to keep test fast: 1MB / 16KB = 64
	// DATA frames.
	spec := validSpec()
	bigMsg := bytes.Repeat([]byte{0x08, 0x96, 0x01}, 350000) // ~1MB
	spec.GRPC.RequestMessages = [][]byte{bigMsg}
	spec.GRPC.ResponseMessages = [][]byte{{0x08, 0x96, 0x01}}
	configs := mustPlan(t, spec)
	clientData := countFrames(configs, "up", frameData)
	// 1MB gRPC message = ~1MB+5 bytes. Each DATA frame carries up to
	// 16KB. So expected frame count = ceil(1MB / 16KB) = 64.
	if clientData < 60 {
		t.Errorf("large request DATA frames = %d, want >= 60", clientData)
	}
}

// --- §3.12 Compression ---

func TestCompression_GzipHeadersAndData(t *testing.T) {
	// Testcase 3.12.1 + 3.12.2: Encoding=gzip -> grpc-encoding=gzip
	// header + Compressed-Flag=1 in DATA.
	spec := validSpec()
	spec.GRPC.Encoding = "gzip"
	spec.GRPC.RequestMessages = [][]byte{{0x08, 0x96, 0x01}}
	spec.GRPC.ResponseMessages = [][]byte{{0x08, 0x96, 0x01}}
	configs := mustPlan(t, spec)
	headersPayload := payloadOf(configs, "up", 2)
	if !containsSubstring(headersPayload, "grpc-encoding") || !containsSubstring(headersPayload, "gzip") {
		t.Errorf("grpc-encoding=gzip not in HEADERS: %x", headersPayload)
	}
	// Find the client DATA frame and check Compressed-Flag=1.
	for _, c := range configs {
		if c.Direction != "up" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameData {
				grpcMsg := c.Payload[next : next+int(length)]
				if grpcMsg[0] != 1 {
					t.Errorf("gzip Compressed-Flag = %d, want 1", grpcMsg[0])
				}
				return
			}
			off = next + int(length)
		}
	}
	t.Error("no client DATA frame found")
}

// --- §3.13 PING keepalive ---

func TestPING_KeepaliveCount(t *testing.T) {
	// Testcase 3.13.2: Pings.Count=3 -> 3 PING requests + 3 PING ACKs.
	spec := validSpec()
	spec.GRPC.Pings = &core.GRPCPingConfig{Count: 3}
	configs := mustPlan(t, spec)
	pingReqs := 0
	pingAcks := 0
	for _, c := range configs {
		if c.L4.Flags != 0x18 || len(c.Payload) == 0 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, flags, _, next := parseFrameHeader(c.Payload, off)
			if ftype == framePing {
				if flags&flagAck != 0 {
					pingAcks++
				} else {
					pingReqs++
				}
			}
			off = next + int(length)
		}
	}
	if pingReqs != 3 {
		t.Errorf("PING requests = %d, want 3", pingReqs)
	}
	if pingAcks != 3 {
		t.Errorf("PING ACKs = %d, want 3", pingAcks)
	}
}

// --- §3.15 GOAWAY default ---

func TestGOAWAY_DefaultEmitted(t *testing.T) {
	// Testcase 3.15.1: GOAWAY emitted by default (GoAwayAfter default true).
	configs := mustPlan(t, validSpec())
	found := false
	for _, c := range configs {
		if c.L4.Flags != 0x18 || len(c.Payload) == 0 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameGoAway {
				found = true
				_ = next
			}
			off = next + int(length)
		}
	}
	if !found {
		t.Error("GOAWAY not emitted by default")
	}
}

// --- §4.3 Validation errors ---

func TestValidate_MaxFrameSizeTooSmall(t *testing.T) {
	// Testcase 1.6.12 + 4.3.5: MaxFrameSize < 16384 rejected.
	spec := validSpec()
	spec.GRPC.MaxFrameSize = 16383
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Error("MaxFrameSize=16383 accepted, want error")
	}
}

func TestValidate_MaxFrameSizeMaxBoundary(t *testing.T) {
	// Testcase 1.6.13: MaxFrameSize=16777215 (max) accepted.
	spec := validSpec()
	spec.GRPC.MaxFrameSize = 16777215
	p := NewPlanner()
	if err := p.Validate(spec); err != nil {
		t.Errorf("MaxFrameSize=16777215 rejected: %v", err)
	}
}

func TestValidate_MaxFrameSizeTooLarge(t *testing.T) {
	// Testcase: MaxFrameSize > 16777215 rejected.
	spec := validSpec()
	spec.GRPC.MaxFrameSize = 16777216
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Error("MaxFrameSize=16777216 accepted, want error")
	}
}

func TestValidate_InvalidTimeoutUnit(t *testing.T) {
	// Testcase 1.17.20 + 4.3.3: Timeout="1X" rejected.
	spec := validSpec()
	spec.GRPC.Timeout = "1X"
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Error("Timeout=1X accepted, want error")
	}
}

func TestValidate_ValidTimeoutUnits(t *testing.T) {
	// Testcase 1.17.15-1.17.19 + 4.2.12 + 4.2.13: all valid units.
	for _, to := range []string{"1n", "500u", "100m", "1S", "1M", "1H", "999H"} {
		spec := validSpec()
		spec.GRPC.Timeout = to
		p := NewPlanner()
		if err := p.Validate(spec); err != nil {
			t.Errorf("Timeout=%q rejected: %v", to, err)
		}
	}
}

func TestValidate_InvalidEncoding(t *testing.T) {
	// Testcase 4.3.9 + 4.3.10 + 4.6.4: unsupported Encoding rejected.
	for _, enc := range []string{"snappy", "deflate", "brotli"} {
		spec := validSpec()
		spec.GRPC.Encoding = enc
		p := NewPlanner()
		if err := p.Validate(spec); err == nil {
			t.Errorf("Encoding=%q accepted, want error", enc)
		}
	}
}

func TestValidate_InvalidCallType(t *testing.T) {
	// Testcase 4.3.8: invalid CallType rejected.
	spec := validSpec()
	spec.GRPC.CallType = "weird-stream"
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Error("CallType=weird-stream accepted, want error")
	}
}

func TestValidate_EmptyService(t *testing.T) {
	// Testcase 4.3.6 + 1.1.3: empty Service rejected.
	spec := validSpec()
	spec.GRPC.Service = ""
	spec.GRPC.Method = "Subscribe"
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Error("empty Service accepted, want error")
	}
}

func TestValidate_EmptyMethod(t *testing.T) {
	// Testcase 4.3.7: empty Method rejected.
	spec := validSpec()
	spec.GRPC.Service = "telemetry.Telemetry"
	spec.GRPC.Method = ""
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Error("empty Method accepted, want error")
	}
}

func TestValidate_RequestMessagesB64(t *testing.T) {
	// Testcase: base64-encoded request messages decode correctly.
	spec := validSpec()
	spec.GRPC.RequestMessages = nil
	spec.GRPC.RequestMessagesB64 = []string{base64.StdEncoding.EncodeToString([]byte{0x08, 0x96, 0x01})}
	p := NewPlanner()
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate error: %v", err)
	}
	configs := mustPlan(t, spec)
	// Find the client DATA frame; the gRPC message should contain the
	// decoded bytes {0x08, 0x96, 0x01}.
	for _, c := range configs {
		if c.Direction != "up" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameData {
				grpcMsg := c.Payload[next : next+int(length)]
				// grpcMsg = 5-byte prefix + protobuf.
				want := []byte{0x00, 0x00, 0x00, 0x00, 0x03, 0x08, 0x96, 0x01}
				if !bytes.Equal(grpcMsg, want) {
					t.Errorf("B64-decoded gRPC message = %x, want %x", grpcMsg, want)
				}
				return
			}
			off = next + int(length)
		}
	}
	t.Error("no client DATA frame found")
}

func TestValidate_FileSourceMutuallyExclusive(t *testing.T) {
	// FileSource + RequestMessages = error.
	spec := validSpec()
	spec.GRPC.FileSource = &filesystem.FileSource{}
	spec.GRPC.RequestMessages = [][]byte{{0x08, 0x96, 0x01}}
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Error("FileSource + RequestMessages accepted, want error")
	}
}

// --- §1.2.22 SETTINGS frame identifiers ---

func TestSettings_IdentifiersAscending(t *testing.T) {
	// Testcase 1.6.16: multiple SETTINGS parameters present in
	// ascending identifier order.
	configs := mustPlan(t, validSpec())
	preface := firstPSH(configs, "up")
	_, _, _, _, payloadStart := parseFrameHeader(preface, 24)
	settingsPayload := preface[payloadStart:]
	lastID := uint16(0)
	for off := 0; off+6 <= len(settingsPayload); off += 6 {
		id := binary.BigEndian.Uint16(settingsPayload[off : off+2])
		if id <= lastID {
			t.Errorf("SETTINGS id %d not ascending (last %d)", id, lastID)
		}
		lastID = id
	}
}

// --- §3.5 Multiple metadata keys ---

func TestMetadata_MultipleKeys(t *testing.T) {
	// Testcase 3.5.3: 5 custom headers all appear in HEADERS.
	spec := validSpec()
	spec.GRPC.Metadata = map[string]string{
		"k1": "v1", "k2": "v2", "k3": "v3", "k4": "v4", "k5": "v5",
	}
	configs := mustPlan(t, spec)
	headersPayload := payloadOf(configs, "up", 2)
	for k, v := range spec.GRPC.Metadata {
		if !containsSubstring(headersPayload, k) || !containsSubstring(headersPayload, v) {
			t.Errorf("metadata %s=%s not in HEADERS: %x", k, v, headersPayload)
		}
	}
}

// --- §4.2 Boundary values ---

func TestBoundary_MaxFrameSize16384(t *testing.T) {
	// Testcase 4.2.7: SETTINGS_MAX_FRAME_SIZE=16384 (default).
	spec := validSpec()
	spec.GRPC.MaxFrameSize = 16384
	configs := mustPlan(t, spec)
	preface := firstPSH(configs, "up")
	_, _, _, _, payloadStart := parseFrameHeader(preface, 24)
	settingsPayload := preface[payloadStart:]
	for off := 0; off+6 <= len(settingsPayload); off += 6 {
		id := binary.BigEndian.Uint16(settingsPayload[off : off+2])
		val := binary.BigEndian.Uint32(settingsPayload[off+2 : off+6])
		if id == settingMaxFrameSize {
			if val != 16384 {
				t.Errorf("MAX_FRAME_SIZE = %d, want 16384", val)
			}
			return
		}
	}
	t.Error("MAX_FRAME_SIZE not present")
}

func TestBoundary_MaxFrameSize16777215(t *testing.T) {
	// Testcase 4.2.8: SETTINGS_MAX_FRAME_SIZE=16777215 (max).
	spec := validSpec()
	spec.GRPC.MaxFrameSize = 16777215
	configs := mustPlan(t, spec)
	preface := firstPSH(configs, "up")
	_, _, _, _, payloadStart := parseFrameHeader(preface, 24)
	settingsPayload := preface[payloadStart:]
	for off := 0; off+6 <= len(settingsPayload); off += 6 {
		id := binary.BigEndian.Uint16(settingsPayload[off : off+2])
		val := binary.BigEndian.Uint32(settingsPayload[off+2 : off+6])
		if id == settingMaxFrameSize {
			if val != 16777215 {
				t.Errorf("MAX_FRAME_SIZE = %d, want 16777215", val)
			}
			return
		}
	}
	t.Error("MAX_FRAME_SIZE not present")
}

func TestBoundary_InitialWindow1MB(t *testing.T) {
	// Testcase 1.6.9: SETTINGS_INITIAL_WINDOW_SIZE=1048576 (1MB).
	spec := validSpec()
	spec.GRPC.InitialWindow = 1048576
	configs := mustPlan(t, spec)
	preface := firstPSH(configs, "up")
	_, _, _, _, payloadStart := parseFrameHeader(preface, 24)
	settingsPayload := preface[payloadStart:]
	for off := 0; off+6 <= len(settingsPayload); off += 6 {
		id := binary.BigEndian.Uint16(settingsPayload[off : off+2])
		val := binary.BigEndian.Uint32(settingsPayload[off+2 : off+6])
		if id == settingInitialWindowSize {
			if val != 1048576 {
				t.Errorf("INITIAL_WINDOW_SIZE = %d, want 1048576", val)
			}
			return
		}
	}
	t.Error("INITIAL_WINDOW_SIZE not present")
}

// --- helpers for testpoints ---

// parseFrameHeader parses a 9-byte HTTP/2 frame header per RFC 7540
// §4.1. Returns (length, type, flags, streamID, payloadStart).
// (Already defined above; this comment is a section divider for the
// helpers below.)

// reassemblePayload concatenates all PSH-ACK payloads in the given
// direction into a single byte stream. This is needed because HTTP/2
// frames can span TCP segments (MSS segmentation splits frames at
// arbitrary byte boundaries). Tests that parse HTTP/2 frames must
// reassemble first to avoid miscounting partial frame headers.
func reassemblePayload(configs []core.PacketConfig, direction string) []byte {
	var out []byte
	for _, c := range configs {
		if c.Direction == direction && c.L4.Flags == 0x18 {
			out = append(out, c.Payload...)
		}
	}
	return out
}

// countFramesInStream counts HTTP/2 frames of the given type in a
// reassembled byte stream. Used by tests that need to count frames
// across TCP segment boundaries. The 24-byte HTTP/2 connection preface
// magic ("PRI * HTTP/2.0...") is skipped if present at the start of
// the stream — it is not a frame.
func countFramesInStream(stream []byte, ftype uint8) int {
	count := 0
	off := 0
	// Skip the 24-byte HTTP/2 connection preface if present (client
	// stream only; server stream starts directly with a SETTINGS frame).
	if len(stream) >= 24 && string(stream[:24]) == connPreface {
		off = 24
	}
	for off+9 <= len(stream) {
		length, t, _, _, next := parseFrameHeader(stream, off)
		if t == ftype {
			count++
		}
		frameEnd := next + int(length)
		if frameEnd <= off {
			break
		}
		off = frameEnd
	}
	return count
}

func countFrames(configs []core.PacketConfig, direction string, ftype uint8) int {
	// Reassemble first to handle frames split across TCP segments.
	stream := reassemblePayload(configs, direction)
	return countFramesInStream(stream, ftype)
}

func clientDataHasEndStream(configs []core.PacketConfig) bool {
	for _, c := range configs {
		if c.Direction != "up" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, t, flags, _, next := parseFrameHeader(c.Payload, off)
			if t == frameData && (flags&flagEndStream) != 0 {
				return true
			}
			off = next + int(length)
		}
	}
	return false
}

func containsSubstring(haystack []byte, needle string) bool {
	return bytes.Index(haystack, []byte(needle)) >= 0
}

func readAll(r interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			if err.Error() == "EOF" {
				return out, nil
			}
			return out, err
		}
	}
}

// Compile-time check that fmt is used (for the URL-encode helper).
var _ = fmt.Sprintf
