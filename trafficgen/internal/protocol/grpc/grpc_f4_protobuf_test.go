package grpc

// F4 regression tests: Wireshark reports "Field Number: 0, Wire Type:
// varint (0)" + "Malformed: Failed to parse value field" when parsing the
// protobuf body inside a gRPC DATA frame for a Telemetry/Subscribe
// request. Field number 0 is illegal in protobuf (legal field_number >= 1).
//
// Root cause investigation: the 5-byte gRPC length-prefixed-message prefix
// (1B Compressed-Flag + 4B big-endian Message-Length) must precede the
// protobuf body, and the protobuf body's first key byte must encode
// field_number >= 1. If the prefix is missing/misaligned, Wireshark reads
// the Compressed-Flag (0x00) as a protobuf tag -> field_number=0,
// wire_type=0 -> illegal.

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// extractFirstGRPCDataPayload reassembles the up-direction TCP stream,
// skips the 24-byte HTTP/2 connection preface + SETTINGS exchange, finds
// the first HEADERS frame, then the first DATA frame, and returns the
// DATA frame's payload (which should be the 5-byte gRPC prefix + protobuf
// body).
func extractFirstGRPCDataPayload(t *testing.T, configs []core.PacketConfig) []byte {
	t.Helper()
	stream := reassemblePayload(configs, "up")
	// Skip the 24-byte connection preface magic.
	off := 0
	if len(stream) >= 24 && string(stream[:24]) == connPreface {
		off = 24
	}
	foundHeaders := false
	for off+9 <= len(stream) {
		length, ftype, _, streamID, next := parseFrameHeader(stream, off)
		frameEnd := next + int(length)
		if frameEnd > len(stream) {
			t.Fatalf("frame at off %d extends past stream end (len=%d, frameEnd=%d)", off, len(stream), frameEnd)
		}
		// Skip SETTINGS frames (streamID=0). Find the first HEADERS frame
		// on a client stream (streamID > 0, odd), then the next DATA frame.
		if ftype == frameHeaders && streamID > 0 {
			foundHeaders = true
		}
		if ftype == frameData && foundHeaders {
			return stream[next:frameEnd]
		}
		if frameEnd <= off {
			break
		}
		off = frameEnd
	}
	t.Fatalf("no DATA frame found after HEADERS in up stream")
	return nil
}

// parseProtobufFieldNumber decodes a protobuf field key (varint) and
// returns (field_number, wire_type, bytes_consumed). Returns (0, 0, 0) on
// error (empty buffer or truncated varint).
func parseProtobufFieldNumber(buf []byte) (fieldNumber int, wireType int, n int) {
	if len(buf) == 0 {
		return 0, 0, 0
	}
	var key uint64
	var shift uint
	for i := 0; i < len(buf); i++ {
		b := buf[i]
		key |= uint64(b&0x7F) << shift
		shift += 7
		n++
		if b&0x80 == 0 {
			fieldNumber = int(key >> 3)
			wireType = int(key & 0x07)
			return
		}
	}
	// Truncated varint.
	return 0, 0, 0
}

// TestF4_GRPCPrefix_Correct verifies the 5-byte gRPC length-prefixed-
// message prefix is correctly placed at the start of the DATA frame
// payload: byte 0 = Compressed-Flag (0 for identity), bytes 1-4 =
// big-endian Message-Length == len(payload[5:]).
func TestF4_GRPCPrefix_Correct(t *testing.T) {
	configs := mustPlan(t, validSpec())
	payload := extractFirstGRPCDataPayload(t, configs)
	if len(payload) < 5 {
		t.Fatalf("DATA frame payload too short: %d bytes (%x)", len(payload), payload)
	}
	// Compressed-Flag must be 0 for identity encoding.
	if payload[0] != 0 {
		t.Errorf("Compressed-Flag = %d, want 0 (identity)", payload[0])
	}
	// Message-Length (4-byte big-endian) must equal len(payload[5:]).
	declaredLen := binary.BigEndian.Uint32(payload[1:5])
	actualLen := uint32(len(payload[5:]))
	if declaredLen != actualLen {
		t.Errorf("gRPC Message-Length = %d, want %d (actual body length)", declaredLen, actualLen)
	}
}

// TestF4_ProtobufBody_FirstFieldNumberValid verifies that the protobuf
// body (payload[5:]) starts with a legal field key: field_number >= 1.
// Field number 0 is illegal per protobuf spec and triggers Wireshark
// "Malformed: Failed to parse value field".
func TestF4_ProtobufBody_FirstFieldNumberValid(t *testing.T) {
	configs := mustPlan(t, validSpec())
	payload := extractFirstGRPCDataPayload(t, configs)
	if len(payload) < 6 {
		t.Fatalf("DATA frame payload too short for protobuf body: %d bytes (%x)", len(payload), payload)
	}
	body := payload[5:]
	if len(body) == 0 {
		t.Skip("empty protobuf body - no fields to validate")
	}
	fn, wt, n := parseProtobufFieldNumber(body)
	if n == 0 {
		t.Fatalf("could not parse protobuf field key from body: %x", body)
	}
	if fn < 1 {
		t.Errorf("protobuf first field_number = %d, want >= 1 (wire_type=%d); body=%x", fn, wt, body)
	}
}

// TestF4_EmptyRequest_GRPCPrefixCorrect verifies the empty-message case
// (no RequestMessages) produces a valid 5-byte gRPC prefix with
// Message-Length=0.
func TestF4_EmptyRequest_GRPCPrefixCorrect(t *testing.T) {
	spec := validSpec()
	spec.GRPC.RequestMessages = nil
	spec.GRPC.RequestMessagesB64 = nil
	configs := mustPlan(t, spec)
	payload := extractFirstGRPCDataPayload(t, configs)
	if len(payload) != 5 {
		t.Fatalf("empty-message DATA payload = %d bytes (%x), want 5", len(payload), payload)
	}
	if payload[0] != 0 {
		t.Errorf("Compressed-Flag = %d, want 0", payload[0])
	}
	declaredLen := binary.BigEndian.Uint32(payload[1:5])
	if declaredLen != 0 {
		t.Errorf("empty-message gRPC Length = %d, want 0", declaredLen)
	}
}

// TestF4_ProtobufKnownBody_Field1Varint150 verifies the canonical
// protobuf example (field 1, varint 150 -> 08 96 01) survives the
// gRPC wrapping intact: prefix(00 00000003) + body(08 96 01).
func TestF4_ProtobufKnownBody_Field1Varint150(t *testing.T) {
	configs := mustPlan(t, validSpec())
	payload := extractFirstGRPCDataPayload(t, configs)
	want := []byte{0x00, 0x00, 0x00, 0x00, 0x03, 0x08, 0x96, 0x01}
	if !bytes.Equal(payload, want) {
		t.Errorf("gRPC DATA payload = %x, want %x", payload, want)
	}
}

// --- Defensive validation: reject protobuf bodies with field_number=0 ---

// TestF4_RejectFieldNumberZero_RequestMessage verifies that Validate
// rejects a user-supplied request message body whose first protobuf
// field key decodes to field_number=0 (illegal per protobuf spec; produces
// Wireshark "Field Number: 0, Wire Type: varint, Failed to parse value
// field"). Pre-fix: Validate accepted any bytes, so users could
// accidentally create malformed gRPC traffic.
func TestF4_RejectFieldNumberZero_RequestMessage(t *testing.T) {
	spec := validSpec()
	spec.GRPC.RequestMessages = [][]byte{{0x00}} // field 0, wire 0
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Error("Validate accepted request body starting with 0x00 (field_number=0), want error")
	}
}

// TestF4_RejectFieldNumberZero_ResponseMessage verifies the same guard
// applies to response messages.
func TestF4_RejectFieldNumberZero_ResponseMessage(t *testing.T) {
	spec := validSpec()
	spec.GRPC.ResponseMessages = [][]byte{{0x00, 0x01}}
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Error("Validate accepted response body starting with 0x00 (field_number=0), want error")
	}
}

// TestF4_RejectFieldNumberZero_MultiByteVarintKey verifies that a
// multi-byte varint key decoding to field_number=0 is also rejected
// (e.g. 0x80 0x00 = key 0 = field 0 wire 0).
func TestF4_RejectFieldNumberZero_MultiByteVarintKey(t *testing.T) {
	spec := validSpec()
	spec.GRPC.RequestMessages = [][]byte{{0x80, 0x00, 0x01}}
	p := NewPlanner()
	if err := p.Validate(spec); err == nil {
		t.Error("Validate accepted body with multi-byte key field_number=0, want error")
	}
}

// TestF4_AcceptFieldNumberOne verifies that a valid body starting with
// field 1 (0x08) is accepted (guard against the validation being too
// strict).
func TestF4_AcceptFieldNumberOne(t *testing.T) {
	spec := validSpec()
	spec.GRPC.RequestMessages = [][]byte{{0x08, 0x96, 0x01}}
	p := NewPlanner()
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate rejected valid field-1 body: %v", err)
	}
}

// TestF4_AcceptEmptyBody verifies that empty bodies (the default
// "no request" case) are accepted — they produce a valid 5-byte gRPC
// prefix with Length=0 and no protobuf body.
func TestF4_AcceptEmptyBody(t *testing.T) {
	spec := validSpec()
	spec.GRPC.RequestMessages = [][]byte{{}}
	p := NewPlanner()
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate rejected empty body: %v", err)
	}
}

// TestF4_AcceptNilMessages verifies that nil/absent request messages are
// accepted (the planner defaults to a zero-length message).
func TestF4_AcceptNilMessages(t *testing.T) {
	spec := validSpec()
	spec.GRPC.RequestMessages = nil
	spec.GRPC.RequestMessagesB64 = nil
	p := NewPlanner()
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate rejected nil messages: %v", err)
	}
}
