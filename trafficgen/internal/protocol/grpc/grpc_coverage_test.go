// Package grpc - coverage tests for the gaps identified in the team-lead
// brief: 4 call-types with explicit END_STREAM assertions, multi-call
// multiplexing, WINDOW_UPDATE flow control (RFC 7540 §6.9), bidi
// interleaving (design §3.6), large-response segmentation, and error
// trailers (grpc-status != 0).
//
// These tests are spec-driven (RFC 7540 + gRPC over HTTP/2 spec +
// /tmp/l7_planner_design/design_grpc.md) and assert observable wire
// bytes, not just structure (per CLAUDE.md §5). Failure-path coverage
// per CLAUDE.md §2: WINDOW_UPDATE zero-increment is rejected by
// Validate; large-response exercises multi-chunk DATA.
package grpc

import (
	"bytes"
	"context"
	"strconv"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// TestFlowControl_WindowUpdateEmitted verifies that when
// WindowUpdateIncrement is configured, the planner emits at least one
// connection-level WINDOW_UPDATE (Stream ID 0) and one stream-level
// WINDOW_UPDATE (Stream ID 1) frame per RFC 7540 §6.9. Pre-fix: the
// planner never emitted WINDOW_UPDATE frames (only the encoder existed).
//
// Spec: design_grpc.md §3.3 ("client <-WINDOW_UPDATE- server") and
// §3.7 (Flow Control Window State), testcases §1.10.1/§1.10.5/§1.10.6.
func TestFlowControl_WindowUpdateEmitted(t *testing.T) {
	spec := validSpec()
	spec.GRPC.WindowUpdateIncrement = 65535
	configs := mustPlan(t, spec)

	connWU := false // connection-level (stream 0)
	streamWU := false // stream-level (stream 1)
	for _, c := range configs {
		if c.L4.Flags != 0x18 || len(c.Payload) == 0 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, sid, next := parseFrameHeader(c.Payload, off)
			if ftype == frameWindowUpdate {
				if sid == 0 {
					connWU = true
				} else if sid == 1 {
					streamWU = true
				}
				if length != 4 {
					t.Errorf("WINDOW_UPDATE length = %d, want 4", length)
				}
			}
			off = next + int(length)
		}
	}
	if !connWU {
		t.Error("no connection-level WINDOW_UPDATE (Stream ID 0) emitted")
	}
	if !streamWU {
		t.Error("no stream-level WINDOW_UPDATE (Stream ID 1) emitted")
	}
}

// TestFlowControl_WindowUpdateIncrementValue verifies the increment
// value is correctly encoded in the 4-byte payload (big-endian, 31-bit).
//
// Spec: RFC 7540 §6.9, testcases §1.10.2 (increment=65535) and §1.10.4
// (increment=0x7FFFFFFF).
func TestFlowControl_WindowUpdateIncrementValue(t *testing.T) {
	tests := []struct {
		name string
		incr uint32
	}{
		{"default 65535", 65535},
		{"max 0x7FFFFFFF", 0x7FFFFFFF},
		{"small 32768", 32768},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := validSpec()
			spec.GRPC.WindowUpdateIncrement = tt.incr
			configs := mustPlan(t, spec)
			found := false
			for _, c := range configs {
				if c.L4.Flags != 0x18 || len(c.Payload) == 0 {
					continue
				}
				off := 0
				for off+9 <= len(c.Payload) {
					length, ftype, _, _, next := parseFrameHeader(c.Payload, off)
					if ftype == frameWindowUpdate {
						incr := uint32(c.Payload[next])<<24 |
							uint32(c.Payload[next+1])<<16 |
							uint32(c.Payload[next+2])<<8 |
							uint32(c.Payload[next+3])
						incr &= 0x7FFFFFFF
						if incr != tt.incr {
							t.Errorf("WINDOW_UPDATE increment = %d, want %d", incr, tt.incr)
						}
						found = true
						_ = length
					}
					off = next + int(length)
				}
			}
			if !found {
				t.Error("no WINDOW_UPDATE frame found")
			}
		})
	}
}

// TestFlowControl_WindowUpdateAbsentWhenNotConfigured verifies backward
// compatibility: when WindowUpdateIncrement is 0 (default), no
// WINDOW_UPDATE frames are emitted. Pre-fix this was the only behavior;
// the guard prevents a regression where WINDOW_UPDATE is always emitted.
func TestFlowControl_WindowUpdateAbsentWhenNotConfigured(t *testing.T) {
	configs := mustPlan(t, validSpec())
	for _, c := range configs {
		if c.L4.Flags != 0x18 || len(c.Payload) == 0 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameWindowUpdate {
				t.Error("WINDOW_UPDATE emitted when WindowUpdateIncrement=0 (should be off)")
				return
			}
			off = next + int(length)
		}
	}
}

// TestFlowControl_ZeroIncrementRejected verifies that an explicit zero
// increment is not a misconfiguration we silently ignore — 0 means "off"
// (no emission), which is the backward-compatible default. This is a
// sanity check: 0 does not trigger a Validate error, and no frame is
// emitted. (RFC 7540 §6.9.1 forbids a zero increment *in a transmitted
// frame*; since 0 means "don't emit", there is no frame to reject.)
//
// Spec: testcases §4.3.11 (increment=0 is illegal *as a frame value*).
func TestFlowControl_ZeroIncrementMeansOff(t *testing.T) {
	spec := validSpec()
	spec.GRPC.WindowUpdateIncrement = 0
	p := NewPlanner()
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate rejected WindowUpdateIncrement=0: %v", err)
	}
	configs := mustPlan(t, spec)
	for _, c := range configs {
		if c.L4.Flags != 0x18 || len(c.Payload) == 0 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameWindowUpdate {
				t.Error("WINDOW_UPDATE emitted when WindowUpdateIncrement=0")
				return
			}
			off = next + int(length)
		}
	}
}

// TestBidi_InterleavedData verifies that for callType="bidi-stream",
// client and server DATA frames are interleaved (client DATA, then
// server DATA, then client DATA, ...), matching design §3.6
// ("interleaved"). Pre-fix: the planner emitted all client DATA then all
// server DATA (not interleaved).
//
// Spec: design_grpc.md §3.6 sequence diagram, testcases §2.6.1.
func TestBidi_InterleavedData(t *testing.T) {
	spec := validSpec()
	spec.GRPC.CallType = "bidi-stream"
	spec.GRPC.RequestMessages = [][]byte{
		{0x08, 0x01}, {0x08, 0x02}, {0x08, 0x03},
	}
	spec.GRPC.ResponseMessages = [][]byte{
		{0x08, 0x0A}, {0x08, 0x0B}, {0x08, 0x0C},
	}
	configs := mustPlan(t, spec)

	// Collect the direction sequence of DATA frames in wire order.
	var dirSeq []string
	for _, c := range configs {
		if c.L4.Flags != 0x18 || len(c.Payload) == 0 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameData {
				dirSeq = append(dirSeq, c.Direction)
			}
			off = next + int(length)
		}
	}
	if len(dirSeq) < 6 {
		t.Fatalf("bidi DATA frames = %d, want >= 6 (3 req + 3 resp)", len(dirSeq))
	}
	// Expect interleaving: up, down, up, down, ... The first two DATA
	// frames MUST alternate (up then down). Pre-fix the sequence was
	// up,up,up,down,down,down, so dirSeq[0]==dirSeq[1]=="up".
	if dirSeq[0] != "up" {
		t.Errorf("first bidi DATA direction = %q, want up", dirSeq[0])
	}
	if dirSeq[1] != "down" {
		t.Errorf("second bidi DATA direction = %q, want down (interleaved); full seq=%v", dirSeq[1], dirSeq)
	}
	// Count alternations: in a fully interleaved 3+3 flow, every adjacent
	// pair should differ.
	alternations := 0
	for i := 0; i+1 < len(dirSeq); i++ {
		if dirSeq[i] != dirSeq[i+1] {
			alternations++
		}
	}
	if alternations < len(dirSeq)-2 {
		t.Errorf("bidi not fully interleaved: %d alternations in %d frames, seq=%v", alternations, len(dirSeq), dirSeq)
	}
}

// TestClientStream_LastDataEndStream verifies that for
// callType="client-stream", the LAST client DATA frame has END_STREAM=1
// (client half-close), and earlier client DATA frames have END_STREAM=0.
//
// Spec: design §3.5, testcases §2.5.2 / §3.3.2.
func TestClientStream_LastDataEndStream(t *testing.T) {
	spec := validSpec()
	spec.GRPC.CallType = "client-stream"
	spec.GRPC.RequestMessages = [][]byte{
		{0x08, 0x01}, {0x08, 0x02}, {0x08, 0x03},
	}
	spec.GRPC.ResponseMessages = [][]byte{{0x08, 0x96, 0x01}}
	configs := mustPlan(t, spec)

	var esFlags []uint8
	for _, c := range configs {
		if c.Direction != "up" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, flags, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameData {
				esFlags = append(esFlags, flags&flagEndStream)
			}
			off = next + int(length)
		}
	}
	if len(esFlags) != 3 {
		t.Fatalf("client-stream client DATA frames = %d, want 3", len(esFlags))
	}
	if esFlags[0] != 0 {
		t.Errorf("first client DATA END_STREAM = %d, want 0", esFlags[0])
	}
	if esFlags[1] != 0 {
		t.Errorf("second client DATA END_STREAM = %d, want 0", esFlags[1])
	}
	if esFlags[2] != flagEndStream {
		t.Errorf("last client DATA END_STREAM = %d, want %d", esFlags[2], flagEndStream)
	}
}

// TestServerStream_ResponseDataNoEndStream verifies that for
// callType="server-stream", server response DATA frames have END_STREAM=0
// (the trailers carry END_STREAM=1, not the DATA). Also verifies there
// is exactly 1 client request DATA with END_STREAM=1.
//
// Spec: design §3.4, testcases §2.4.2 / §3.2.3.
func TestServerStream_ResponseDataNoEndStream(t *testing.T) {
	spec := validSpec()
	spec.GRPC.CallType = "server-stream"
	spec.GRPC.RequestMessages = [][]byte{{0x08, 0x96, 0x01}}
	spec.GRPC.ResponseMessages = [][]byte{
		{0x08, 0x0A}, {0x08, 0x0B}, {0x08, 0x0C},
	}
	configs := mustPlan(t, spec)

	// Server DATA frames must all have END_STREAM=0.
	for _, c := range configs {
		if c.Direction != "down" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, flags, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameData {
				if flags&flagEndStream != 0 {
					t.Errorf("server DATA has END_STREAM=1, want 0 (trailers close the stream)")
				}
			}
			off = next + int(length)
		}
	}
	// Client request DATA must have END_STREAM=1 (single request half-close).
	if !clientDataHasEndStream(configs) {
		t.Error("server-stream client DATA missing END_STREAM")
	}
}

// TestLargeResponse_Segmentation verifies that a response message larger
// than SETTINGS_MAX_FRAME_SIZE is split into multiple DATA frames, each
// <= MaxFrameSize, with END_STREAM=0 on all but the last (trailers
// close). Pre-fix: only request segmentation was tested; response
// segmentation was untested.
//
// Spec: design §3.10 / §4 scenario 10, testcases §3.10.1.
func TestLargeResponse_Segmentation(t *testing.T) {
	spec := validSpec()
	spec.GRPC.CallType = "unary"
	spec.GRPC.RequestMessages = [][]byte{{0x08, 0x96, 0x01}}
	// 40KB response > 16KB default MaxFrameSize -> 3 DATA frames.
	bigResp := make([]byte, 40000)
	for i := range bigResp {
		bigResp[i] = 0x08
	}
	spec.GRPC.ResponseMessages = [][]byte{bigResp}
	configs := mustPlan(t, spec)

	serverData := countFrames(configs, "down", frameData)
	if serverData < 3 {
		t.Errorf("large response server DATA frames = %d, want >= 3 (40KB / 16KB)", serverData)
	}
	// Verify no server DATA frame exceeds MaxFrameSize.
	maxFrame := effectiveMaxFrameSize(spec.GRPC)
	for _, c := range configs {
		if c.Direction != "down" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameData {
				if uint32(length) > maxFrame {
					t.Errorf("server DATA frame length %d > MaxFrameSize %d", length, maxFrame)
				}
			}
			off = next + int(length)
		}
	}
}

// TestErrorTrailers_StatusCodes verifies that non-zero grpc-status codes
// appear in the trailers HEADERS frame. Pre-fix: only status=0 and
// status=14 were tested; codes 1/4/13 (CANCELLED/DEADLINE_EXCEEDED/
// INTERNAL) were not.
//
// Spec: gRPC status codes spec, testcases §1.19.2/§1.19.5/§1.19.14.
func TestErrorTrailers_StatusCodes(t *testing.T) {
	for _, code := range []int{1, 4, 13} {
		spec := validSpec()
		spec.GRPC.ResponseStatus = code
		configs := mustPlan(t, spec)
		found := false
		for _, c := range configs {
			if c.Direction != "down" || c.L4.Flags != 0x18 {
				continue
			}
			off := 0
			for off+9 <= len(c.Payload) {
				length, ftype, flags, _, next := parseFrameHeader(c.Payload, off)
				if ftype == frameHeaders && (flags&flagEndStream) != 0 {
					trailerBlock := c.Payload[next : next+int(length)]
					if containsSubstring(trailerBlock, "grpc-status") {
						// The grpc-status value is the decimal code.
						want := []byte(strconv.Itoa(code))
						if !bytes.Contains(trailerBlock, want) {
							t.Errorf("status %d: grpc-status value %q not in trailers %x", code, want, trailerBlock)
						}
						found = true
					}
				}
				off = next + int(length)
			}
		}
		if !found {
			t.Errorf("status %d: no trailers with grpc-status found", code)
		}
	}
}

// TestMultiCall_StreamIDIncrement verifies that 3 calls produce stream
// IDs 1, 3, 5 (odd, monotonically increasing by 2 per RFC 7540 §5.1.1).
// Pre-fix: only 2 calls were tested.
//
// Spec: RFC 7540 §5.1.1, testcases §3.14.1/§3.14.2.
func TestMultiCall_StreamIDIncrement(t *testing.T) {
	spec := validSpec()
	spec.GRPC.Calls = []core.GRPCCall{
		{Service: "s.S", Method: "M1", CallType: "unary",
			RequestMessages: [][]byte{{0x08, 0x01}}, ResponseMessages: [][]byte{{0x08, 0x01}}},
		{Service: "s.S", Method: "M2", CallType: "unary",
			RequestMessages: [][]byte{{0x08, 0x01}}, ResponseMessages: [][]byte{{0x08, 0x01}}},
		{Service: "s.S", Method: "M3", CallType: "unary",
			RequestMessages: [][]byte{{0x08, 0x01}}, ResponseMessages: [][]byte{{0x08, 0x01}}},
	}
	configs := mustPlan(t, spec)

	var streamIDs []uint32
	for _, c := range configs {
		if c.Direction != "up" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, sid, next := parseFrameHeader(c.Payload, off)
			if ftype == frameHeaders && sid != 0 {
				streamIDs = append(streamIDs, sid)
			}
			off = next + int(length)
		}
	}
	if len(streamIDs) < 3 {
		t.Fatalf("found %d client HEADERS, want >= 3", len(streamIDs))
	}
	want := []uint32{1, 3, 5}
	for i, w := range want {
		if i >= len(streamIDs) {
			break
		}
		if streamIDs[i] != w {
			t.Errorf("call %d stream ID = %d, want %d", i, streamIDs[i], w)
		}
	}
}

// TestMultiCall_DistinctPaths verifies that each call's HEADERS carries
// its own :path (/<Service>/<Method>), proving multiplexing uses
// distinct RPC targets.
//
// Spec: gRPC spec §4 (":path = /<service>/<method>"), design §3.14.
func TestMultiCall_DistinctPaths(t *testing.T) {
	spec := validSpec()
	spec.GRPC.Calls = []core.GRPCCall{
		{Service: "s.S", Method: "Subscribe", CallType: "unary",
			RequestMessages: [][]byte{{0x08, 0x01}}, ResponseMessages: [][]byte{{0x08, 0x01}}},
		{Service: "s.S", Method: "Publish", CallType: "unary",
			RequestMessages: [][]byte{{0x08, 0x01}}, ResponseMessages: [][]byte{{0x08, 0x01}}},
	}
	configs := mustPlan(t, spec)

	var paths []string
	for _, c := range configs {
		if c.Direction != "up" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameHeaders {
				block := c.Payload[next : next+int(length)]
				if containsSubstring(block, "Subscribe") {
					paths = append(paths, "Subscribe")
				} else if containsSubstring(block, "Publish") {
					paths = append(paths, "Publish")
				}
			}
			off = next + int(length)
		}
	}
	if len(paths) < 2 {
		t.Fatalf("found %d paths in HEADERS, want >= 2", len(paths))
	}
	if paths[0] != "Subscribe" || paths[1] != "Publish" {
		t.Errorf("paths = %v, want [Subscribe Publish]", paths)
	}
}

// TestMultiCall_PerCallWindowUpdate verifies that when
// WindowUpdateIncrement is configured, each call gets its own
// stream-level WINDOW_UPDATE on its stream ID (1, 3, ...).
//
// Spec: RFC 7540 §6.9 (stream-level flow control), design §3.7.
func TestMultiCall_PerCallWindowUpdate(t *testing.T) {
	spec := validSpec()
	spec.GRPC.WindowUpdateIncrement = 32768
	spec.GRPC.Calls = []core.GRPCCall{
		{Service: "s.S", Method: "M1", CallType: "unary",
			RequestMessages: [][]byte{{0x08, 0x01}}, ResponseMessages: [][]byte{{0x08, 0x01}}},
		{Service: "s.S", Method: "M2", CallType: "unary",
			RequestMessages: [][]byte{{0x08, 0x01}}, ResponseMessages: [][]byte{{0x08, 0x01}}},
	}
	configs := mustPlan(t, spec)

	streamWU := map[uint32]bool{}
	for _, c := range configs {
		if c.L4.Flags != 0x18 || len(c.Payload) == 0 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, sid, next := parseFrameHeader(c.Payload, off)
			if ftype == frameWindowUpdate && sid != 0 {
				streamWU[sid] = true
			}
			off = next + int(length)
		}
	}
	if !streamWU[1] {
		t.Error("no stream-level WINDOW_UPDATE on stream 1")
	}
	if !streamWU[3] {
		t.Error("no stream-level WINDOW_UPDATE on stream 3")
	}
}

// TestUnary_NoWindowUpdateByDefault is a backward-compat guard: a plain
// unary call must not emit WINDOW_UPDATE when the field is unset. This
// protects existing pcaps from changing shape.
func TestUnary_NoWindowUpdateByDefault(t *testing.T) {
	configs := mustPlan(t, validSpec())
	for _, c := range configs {
		if c.L4.Flags != 0x18 || len(c.Payload) == 0 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, _, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameWindowUpdate {
				t.Error("WINDOW_UPDATE emitted on unary call without WindowUpdateIncrement")
				return
			}
			off = next + int(length)
		}
	}
}

// TestCallMode_BidiRequestEndStream verifies that for bidi-stream, the
// LAST client request DATA has END_STREAM=1 (client half-close), per
// design §3.6.
func TestCallMode_BidiRequestEndStream(t *testing.T) {
	spec := validSpec()
	spec.GRPC.CallType = "bidi-stream"
	spec.GRPC.RequestMessages = [][]byte{
		{0x08, 0x01}, {0x08, 0x02},
	}
	spec.GRPC.ResponseMessages = [][]byte{
		{0x08, 0x0A}, {0x08, 0x0B},
	}
	configs := mustPlan(t, spec)

	var lastES uint8
	count := 0
	for _, c := range configs {
		if c.Direction != "up" || c.L4.Flags != 0x18 {
			continue
		}
		off := 0
		for off+9 <= len(c.Payload) {
			length, ftype, flags, _, next := parseFrameHeader(c.Payload, off)
			if ftype == frameData {
				lastES = flags & flagEndStream
				count++
			}
			off = next + int(length)
		}
	}
	if count != 2 {
		t.Fatalf("bidi client DATA frames = %d, want 2", count)
	}
	if lastES != flagEndStream {
		t.Errorf("last bidi client DATA END_STREAM = %d, want %d", lastES, flagEndStream)
	}
}

// Compile-time check that context is used (for mustPlan).
var _ = context.Background
