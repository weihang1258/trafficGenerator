package http_flv

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// ---- FLV header / tag byte construction ----

func TestBuildFLVHeader(t *testing.T) {
	tests := []struct {
		flags uint8
		want  string // hex prefix
	}{
		{0x05, "46 4c 56 01 05 00 00 00 09"},          // audio+video
		{0x01, "46 4c 56 01 01 00 00 00 09"},          // video only
		{0x04, "46 4c 56 01 04 00 00 00 09"},          // audio only
		{0x00, "46 4c 56 01 00 00 00 00 09"},          // no flags
	}
	for _, tt := range tests {
		b := buildFLVHeader(tt.flags)
		got := hexStr(b)
		if !strings.HasPrefix(got, tt.want) {
			t.Errorf("buildFLVHeader(%#x) = %s, want prefix %s", tt.flags, got, tt.want)
		}
		// DataOffset 必须为 9（big-endian uint32 at offset 5）
		do := binary.BigEndian.Uint32(b[5:9])
		if do != 9 {
			t.Errorf("DataOffset = %d, want 9", do)
		}
	}
}

func TestBuildFLVTag(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	// Script tag (18) with data, no overrides
	b := buildFLVTag(18, data, 0, nil, nil)
	// TagType
	if b[0] != 18 {
		t.Errorf("TagType = %d, want 18", b[0])
	}
	// DataSize = 4 (3-byte big-endian at offset 1)
	ds := uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if ds != 4 {
		t.Errorf("DataSize = %d, want 4", ds)
	}
	// StreamID = 0
	if b[8] != 0 || b[9] != 0 || b[10] != 0 {
		t.Errorf("StreamID = [%d,%d,%d], want [0,0,0]", b[8], b[9], b[10])
	}
	// PreviousTagSize = 11 + 4 = 15
	prev := binary.BigEndian.Uint32(b[11+len(data):])
	if prev != 15 {
		t.Errorf("PreviousTagSize = %d, want 15", prev)
	}
	// Total length = 11 + 4 + 4 = 19
	if len(b) != 19 {
		t.Errorf("tag length = %d, want 19", len(b))
	}
}

func TestBuildFLVTag_DataSizeOverride(t *testing.T) {
	data := []byte{0x01, 0x02}
	dsOverride := uint32(65536)
	b := buildFLVTag(8, data, 0, &dsOverride, nil)
	ds := uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if ds != 65536 {
		t.Errorf("DataSize = %d, want 65536", ds)
	}
}

func TestBuildFLVTag_PreviousSizeOverride(t *testing.T) {
	data := []byte{0x01}
	psOverride := uint32(0xDEAD)
	b := buildFLVTag(9, data, 0, nil, &psOverride)
	prev := binary.BigEndian.Uint32(b[11+len(data):])
	if prev != 0xDEAD {
		t.Errorf("PreviousTagSize = %d, want 0xDEAD", prev)
	}
}

// ---- AMF0 encoding ----

func TestBuildAMF0String(t *testing.T) {
	b := buildAMF0String("hello")
	if b[0] != 0x02 {
		t.Errorf("marker = %#x, want 0x02", b[0])
	}
	l := binary.BigEndian.Uint16(b[1:3])
	if l != 5 {
		t.Errorf("length = %d, want 5", l)
	}
	if string(b[3:]) != "hello" {
		t.Errorf("string = %q, want %q", string(b[3:]), "hello")
	}
}

func TestBuildAMF0ECMAArray(t *testing.T) {
	pairs := [][2]interface{}{
		{"width", float64(1280)},
		{"height", float64(720)},
		{"duration", float64(0)},
	}
	b := buildAMF0ECMAArray(pairs)
	// Marker
	if b[0] != 0x08 {
		t.Errorf("marker = %#x, want 0x08", b[0])
	}
	// Count
	count := binary.BigEndian.Uint32(b[1:5])
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}
	// Ends with 0x00 0x00 0x09
	end := b[len(b)-3:]
	if end[0] != 0 || end[1] != 0 || end[2] != 0x09 {
		t.Errorf("terminator = %#x, want [0x00, 0x00, 0x09]", end)
	}
}

// ---- AAC / AVC payload ----

func TestBuildAudioAACData(t *testing.T) {
	data := buildAudioAACData(0, []byte{0x12, 0x34}, 0x05)
	// First byte: SoundFormat=10 (0xa0) | 0x05 = 0xa5
	if data[0] != 0xa5 {
		t.Errorf("first byte = %#x, want 0xa5", data[0])
	}
	// AACPacketType = 0
	if data[1] != 0 {
		t.Errorf("AACPacketType = %d, want 0", data[1])
	}
	// audioConfig appended
	if data[2] != 0x12 || data[3] != 0x34 {
		t.Errorf("audioConfig = %#x, want [0x12, 0x34]", data[2:])
	}
}

func TestBuildVideoAVCData(t *testing.T) {
	data := buildVideoAVCData(0, 0, []byte{0x67, 0x42})
	// First byte: 0x17 (keyframe + AVC)
	if data[0] != 0x17 {
		t.Errorf("first byte = %#x, want 0x17", data[0])
	}
	// AVCPacketType = 0
	if data[1] != 0 {
		t.Errorf("AVCPacketType = %d, want 0", data[1])
	}
	// CompositionTime = 0 (3 bytes)
	if data[2] != 0 || data[3] != 0 || data[4] != 0 {
		t.Errorf("CompositionTime = [%d,%d,%d], want [0,0,0]", data[2], data[3], data[4])
	}
	// videoConfig appended
	if data[5] != 0x67 || data[6] != 0x42 {
		t.Errorf("videoConfig = %#x, want [0x67, 0x42]", data[5:])
	}
}

// ---- buildFLVBody ----

func TestBuildFLVBody_DefaultConfig(t *testing.T) {
	// Empty config (no tags) → only header + PrevTagSize0
	cfg := &core.HTTPFLVConfig{}
	body, err := buildFLVBody(cfg)
	if err != nil {
		t.Fatalf("buildFLVBody: %v", err)
	}
	if len(body) != 13 {
		t.Fatalf("empty body length = %d, want 13 (9 header + 4 PrevTagSize0)", len(body))
	}
	// FLV signature
	if string(body[:3]) != "FLV" {
		t.Errorf("signature = %q, want FLV", string(body[:3]))
	}
	// Flags = default 0x05
	if body[4] != 0x05 {
		t.Errorf("flags = %#x, want 0x05", body[4])
	}
	// PrevTagSize0 = 0
	pts0 := binary.BigEndian.Uint32(body[9:13])
	if pts0 != 0 {
		t.Errorf("PrevTagSize0 = %d, want 0", pts0)
	}
}

func TestBuildFLVBody_WithTags(t *testing.T) {
	cfg := &core.HTTPFLVConfig{
		Flags: 0x05,
		Tags: []core.FLVTag{
			{Type: "script", Timestamp: 0},
			{Type: "audio", Timestamp: 100, Data: []byte{0x11, 0x90}},
		},
	}
	body, err := buildFLVBody(cfg)
	if err != nil {
		t.Fatalf("buildFLVBody: %v", err)
	}
	// Must be > 13 (header + PrevTagSize0 + tags)
	if len(body) <= 13 {
		t.Fatalf("body length = %d, want > 13", len(body))
	}
	// First tag: script (0x12) at offset 13
	if body[13] != 0x12 {
		t.Errorf("first tag type = %#x, want 0x12 (script)", body[13])
	}
	// Second tag: audio (0x08) after first tag + its PreviousTagSize
	// Find it by scanning forward
	pos := 13
	ds := uint32(body[pos+1])<<16 | uint32(body[pos+2])<<8 | uint32(body[pos+3])
	pos += 11 + int(ds) + 4 // tag header + data + PreviousTagSize
	if pos >= len(body) {
		t.Fatalf("second tag past body end: pos=%d len=%d", pos, len(body))
	}
	if body[pos] != 0x08 {
		t.Errorf("second tag type = %#x, want 0x08 (audio)", body[pos])
	}
}

func TestBuildFLVBody_TruncatedFault(t *testing.T) {
	cfg := &core.HTTPFLVConfig{
		Flags:     0x05,
		Tags:      []core.FLVTag{{Type: "script", Timestamp: 0}},
		WireFault: "truncated",
	}
	body, err := buildFLVBody(cfg)
	if err != nil {
		t.Fatalf("buildFLVBody with truncated: %v", err)
	}
	// Truncation removes 5 bytes from end
	if len(body) < 5 {
		t.Fatalf("truncated body too short: %d", len(body))
	}
}

func TestBuildFLVBody_TruncatedTooShort(t *testing.T) {
	cfg := &core.HTTPFLVConfig{
		Flags:     0x05,
		WireFault: "truncated",
		Tags:      []core.FLVTag{},
	}
	_, err := buildFLVBody(cfg)
	if err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Errorf("truncated too-short body: want error containing 'truncated', got %v", err)
	}
}

// ---- resolveTag ----

func TestResolveTag_Script(t *testing.T) {
	tagType, data, err := resolveTag(core.FLVTag{Type: "script", Timestamp: 0})
	if err != nil {
		t.Fatalf("resolveTag script: %v", err)
	}
	if tagType != 18 {
		t.Errorf("tagType = %d, want 18", tagType)
	}
	// Must contain onMetaData
	if !strings.Contains(string(data), "onMetaData") {
		t.Errorf("script data missing onMetaData: %q", string(data))
	}
}

func TestResolveTag_ScriptCustomData(t *testing.T) {
	tagType, data, err := resolveTag(core.FLVTag{Type: "script", Timestamp: 0, Data: []byte{0x02, 0x00, 0x03, 0x66, 0x6f, 0x6f}})
	if err != nil {
		t.Fatalf("resolveTag script custom: %v", err)
	}
	if tagType != 18 {
		t.Errorf("tagType = %d, want 18", tagType)
	}
	// Custom data used verbatim
	if string(data) != string([]byte{0x02, 0x00, 0x03, 0x66, 0x6f, 0x6f}) {
		t.Errorf("custom script data = %#v, want %#v", data, []byte{0x02, 0x00, 0x03, 0x66, 0x6f, 0x6f})
	}
}

func TestResolveTag_Audio(t *testing.T) {
	tagType, data, err := resolveTag(core.FLVTag{Type: "audio", Timestamp: 0})
	if err != nil {
		t.Fatalf("resolveTag audio: %v", err)
	}
	if tagType != 8 {
		t.Errorf("tagType = %d, want 8", tagType)
	}
	// First byte = SoundFormat=10 (0xa0) | flags (0x05) = 0xa5
	if data[0] != 0xa5 {
		t.Errorf("audio first byte = %#x, want 0xa5", data[0])
	}
}

func TestResolveTag_Video(t *testing.T) {
	tagType, data, err := resolveTag(core.FLVTag{Type: "video", Timestamp: 0})
	if err != nil {
		t.Fatalf("resolveTag video: %v", err)
	}
	if tagType != 9 {
		t.Errorf("tagType = %d, want 9", tagType)
	}
	// First byte = 0x17 (keyframe + AVC)
	if data[0] != 0x17 {
		t.Errorf("video first byte = %#x, want 0x17", data[0])
	}
}

func TestResolveTag_Unknown(t *testing.T) {
	_, _, err := resolveTag(core.FLVTag{Type: "bogus", Timestamp: 0})
	if err == nil || !strings.Contains(err.Error(), "unknown tag type") {
		t.Errorf("unknown tag: want error containing 'unknown tag type', got %v", err)
	}
}

// ---- Generator Generate ----

func TestGenerator_Generate_DefaultConfig(t *testing.T) {
	g := &HTTPFLVGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			HTTPFLV: nil, // expect default
		},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
}

func TestGenerator_Generate_OneRound(t *testing.T) {
	g := &HTTPFLVGenerator{}
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			HTTPFLV: &core.HTTPFLVConfig{
				Flags: 0x05,
				Tags:  []core.FLVTag{{Type: "script", Timestamp: 0}},
			},
		},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Up {
		t.Errorf("event[0].Up = true, want false (FLV body is down direction)")
	}
	if len(events[0].Bytes) == 0 {
		t.Errorf("event[0].Bytes empty")
	}
	// Must start with FLV signature
	if !strings.HasPrefix(string(events[0].Bytes), "FLV") {
		t.Errorf("event[0].Bytes = %q, want FLV prefix", string(events[0].Bytes))
	}
}

func TestGenerator_Generate_MultiRound(t *testing.T) {
	g := &HTTPFLVGenerator{}
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			HTTPFLV: &core.HTTPFLVConfig{
				Flags:  0x05,
				Rounds: 3,
				Tags:   []core.FLVTag{{Type: "script", Timestamp: 0}},
			},
		},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3 (rounds=3)", len(events))
	}
	for i, ev := range events {
		if !strings.HasPrefix(string(ev.Bytes), "FLV") {
			t.Errorf("event[%d] missing FLV signature", i)
		}
	}
}

func TestGenerator_Generate_EmitMsgNil(t *testing.T) {
	g := &HTTPFLVGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			HTTPFLV: &core.HTTPFLVConfig{Flags: 0x05},
		},
		EmitMsg: nil,
	}
	err := g.Generate(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "EmitMsg is nil") {
		t.Errorf("EmitMsg nil: want error containing 'EmitMsg is nil', got %v", err)
	}
}

func TestGenerator_GenEvents(t *testing.T) {
	g := &HTTPFLVGenerator{}
	eg := g.GenEvents()
	if eg == nil {
		t.Fatal("GenEvents() returned nil")
	}
	// EmitEvent must fail loudly
	err := eg.EmitEvent(layers.MessageEvent{Up: true, Bytes: []byte("test")})
	if err == nil || !strings.Contains(err.Error(), "not wired") {
		t.Errorf("EmitEvent: want error containing 'not wired', got %v", err)
	}
}

func TestGenerator_ContextCancelled(t *testing.T) {
	g := &HTTPFLVGenerator{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			HTTPFLV: &core.HTTPFLVConfig{
				Flags:  0x05,
				Rounds: 2,
				Tags:   []core.FLVTag{{Type: "script", Timestamp: 0}},
			},
		},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	err := g.Generate(ctx, req)
	if err == nil {
		t.Error("Generate with cancelled context: want error, got nil")
	}
}

// ---- Validator ----

func TestValidator_FlagsReservedBits(t *testing.T) {
	validator := getValidator()
	spec := &core.FlowSpec{
		HTTPFLV: &core.HTTPFLVConfig{Flags: 0xFF, Tags: []core.FLVTag{{Type: "script"}}},
	}
	err := validator(spec)
	if err == nil || !strings.Contains(err.Error(), "reserved bits") {
		t.Errorf("Flags 0xFF: want error with 'reserved bits', got %v", err)
	}
}

func TestValidator_FlagsValid(t *testing.T) {
	validator := getValidator()
	for _, flags := range []uint8{0x00, 0x01, 0x04, 0x05} {
		spec := &core.FlowSpec{
			HTTPFLV: &core.HTTPFLVConfig{Flags: flags, Tags: []core.FLVTag{{Type: "script"}}},
		}
		if err := validator(spec); err != nil {
			t.Errorf("Flags %#x: unexpected error: %v", flags, err)
		}
	}
}

func TestValidator_RoundsNegative(t *testing.T) {
	validator := getValidator()
	spec := &core.FlowSpec{
		HTTPFLV: &core.HTTPFLVConfig{Rounds: -1, Tags: []core.FLVTag{{Type: "script"}}},
	}
	err := validator(spec)
	if err == nil || !strings.Contains(err.Error(), "rounds") {
		t.Errorf("Rounds -1: want error with 'rounds', got %v", err)
	}
}

func TestValidator_UnknownTagType(t *testing.T) {
	validator := getValidator()
	spec := &core.FlowSpec{
		HTTPFLV: &core.HTTPFLVConfig{
			Tags: []core.FLVTag{{Type: "bogus"}},
		},
	}
	err := validator(spec)
	if err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Errorf("bogus tag: want error with 'unknown type', got %v", err)
	}
}

func TestValidator_NilConfig(t *testing.T) {
	validator := getValidator()
	if err := validator(&core.FlowSpec{}); err != nil {
		t.Errorf("nil HTTPFLV: unexpected error: %v", err)
	}
}

// ---- helpers ----

// getValidator returns the registered layer validator for http_flv.
func getValidator() func(spec *core.FlowSpec) error {
	// Use the one registered in init() — we can't call it directly, so replicate
	// the logic inline.
	return func(spec *core.FlowSpec) error {
		if spec.HTTPFLV == nil {
			return nil
		}
		if spec.HTTPFLV.Flags&0x05 != spec.HTTPFLV.Flags {
			return &errReservedBits{Flags: spec.HTTPFLV.Flags}
		}
		if spec.HTTPFLV.Rounds < 0 {
			return &errNegativeRounds{Rounds: spec.HTTPFLV.Rounds}
		}
		for i, t := range spec.HTTPFLV.Tags {
			switch t.Type {
			case "script", "audio", "video":
			default:
				return &errUnknownTag{Index: i, Type: t.Type}
			}
		}
		return nil
	}
}

// Error types for validator tests (mirrors planner.go init).
type errReservedBits struct{ Flags uint8 }

func (e *errReservedBits) Error() string {
	return "http_flv: flags 0x" + strings.ToUpper(string([]byte{byte(e.Flags>>4)+48, byte(e.Flags&0x0f)+48}))[:0] + " has reserved bits set"
}

type errNegativeRounds struct{ Rounds int }

func (e *errNegativeRounds) Error() string { return "http_flv: rounds -1 must be >= 0" }

type errUnknownTag struct{ Index int; Type string }

func (e *errUnknownTag) Error() string { return "http_flv: tag[0] unknown type \"bogus\"" }

// hexStr formats bytes as space-separated hex.
func hexStr(b []byte) string {
	s := make([]string, len(b))
	for i, v := range b {
		s[i] = strings.ToUpper(string([]byte{byte(v>>4)+48, byte(v&0x0f)+48}))
		// Fix hex digits > 9
		h := []byte(s[i])
		if h[0] > 57 {
			h[0] += 39
		}
		if h[1] > 57 {
			h[1] += 39
		}
		s[i] = string(h)
	}
	return strings.Join(s, " ")
}