package amqp

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// ---- Builder tests ----

func TestProtocolHeader(t *testing.T) {
	h := buildProtocolHeader()
	if len(h) != 8 {
		t.Fatalf("len=%d want 8", len(h))
	}
	if string(h) != "AMQP\x00\x00\x09\x01" {
		t.Errorf("header=%x want AMQP\\x00\\x00\\x09\\x01", h)
	}
}

func TestBuildMethodFrame(t *testing.T) {
	// connection.start on channel 0, no extra args.
	msg := buildMethodFrame(0, 10, 10, nil)
	if len(msg) < 8 {
		t.Fatalf("len=%d too short", len(msg))
	}
	if msg[0] != FrameMethod {
		t.Errorf("frame type=%02x want %02x", msg[0], FrameMethod)
	}
	if msg[1] != 0 || msg[2] != 0 {
		t.Errorf("channel=%02x%02x want 0", msg[1], msg[2])
	}
	// Size = 4 (class+method only)
	if got := int(msg[3])<<24 | int(msg[4])<<16 | int(msg[5])<<8 | int(msg[6]); got != 4 {
		t.Errorf("size=%d want 4", got)
	}
	// Class=10, method=10
	if msg[7] != 0 || msg[8] != 10 {
		t.Errorf("class=%02x%02x want 0x000a", msg[7], msg[8])
	}
	if msg[9] != 0 || msg[10] != 10 {
		t.Errorf("method=%02x%02x want 0x000a", msg[9], msg[10])
	}
	// Frame end marker
	if msg[len(msg)-1] != FrameEnd {
		t.Errorf("end=%02x want %02x", msg[len(msg)-1], FrameEnd)
	}
}

func TestBuildFrame(t *testing.T) {
	// HEARTBEAT: type=8, channel=0, size=0
	msg := buildFrame(FrameHeartbeat, 0, nil)
	if len(msg) != 8 {
		t.Fatalf("len=%d want 8", len(msg))
	}
	if msg[0] != FrameHeartbeat {
		t.Errorf("type=%02x want %02x", msg[0], FrameHeartbeat)
	}
	if msg[1] != 0 || msg[2] != 0 {
		t.Errorf("channel=%02x%02x want 0", msg[1], msg[2])
	}
	if msg[3] != 0 || msg[4] != 0 || msg[5] != 0 || msg[6] != 0 {
		t.Errorf("size=%02x%02x%02x%02x want 0", msg[3], msg[4], msg[5], msg[6])
	}
	if msg[7] != FrameEnd {
		t.Errorf("end=%02x want %02x", msg[7], FrameEnd)
	}
}

func TestBuildHeartbeatFrame(t *testing.T) {
	msg := buildHeartbeatFrame()
	if len(msg) != 8 {
		t.Fatalf("len=%d want 8", len(msg))
	}
	expected := "08 00 00 00 00 00 00 ce"
	if hex.EncodeToString(msg) != strings.ReplaceAll(expected, " ", "") {
		t.Errorf("heartbeat=%x want %s", msg, expected)
	}
}

func TestBuildHeaderFrame(t *testing.T) {
	// Basic header: class=60, weight=0, bodySize=5, no properties.
	msg, err := buildHeaderFrame(1, 60, 5, nil, nil)
	if err != nil {
		t.Fatalf("buildHeaderFrame: %v", err)
	}
	if msg[0] != FrameHeader {
		t.Errorf("type=%02x want %02x", msg[0], FrameHeader)
	}
	// Channel = 1
	if msg[1] != 0 || msg[2] != 1 {
		t.Errorf("channel=%02x%02x want 1", msg[1], msg[2])
	}
	// size = 2+2+8+2 = 14 (no properties)
	payloadStart := 7
	classID := int(msg[payloadStart])<<8 | int(msg[payloadStart+1])
	if classID != 60 {
		t.Errorf("class=%d want 60", classID)
	}
	weight := int(msg[payloadStart+2])<<8 | int(msg[payloadStart+3])
	if weight != 0 {
		t.Errorf("weight=%d want 0", weight)
	}
	// bodySize at offset payloadStart+4
	bodySize := uint64(msg[payloadStart+4])<<56 | uint64(msg[payloadStart+5])<<48 |
		uint64(msg[payloadStart+6])<<40 | uint64(msg[payloadStart+7])<<32 |
		uint64(msg[payloadStart+8])<<24 | uint64(msg[payloadStart+9])<<16 |
		uint64(msg[payloadStart+10])<<8 | uint64(msg[payloadStart+11])
	if bodySize != 5 {
		t.Errorf("bodySize=%d want 5", bodySize)
	}
	// Property flags at payloadStart+12
	flags := int(msg[payloadStart+12])<<8 | int(msg[payloadStart+13])
	if flags != 0 {
		t.Errorf("flags=%04x want 0 (no properties)", flags)
	}
}

func TestBuildHeaderFrameWithProperties(t *testing.T) {
	props := map[string]any{
		"content_type":  "text/plain",
		"delivery_mode": int32(2),
		"priority":      int32(1),
	}
	msg, err := buildHeaderFrame(1, 60, 10, props, nil)
	if err != nil {
		t.Fatalf("buildHeaderFrame: %v", err)
	}
	if msg[0] != FrameHeader {
		t.Errorf("type=%02x want %02x", msg[0], FrameHeader)
	}
	// Property flags should have bits 15 (content_type), 12 (delivery_mode), 11 (priority) set.
	payloadStart := 7
	flags := int(msg[payloadStart+12])<<8 | int(msg[payloadStart+13])
	if flags&(1<<15) == 0 {
		t.Error("content_type flag not set")
	}
	if flags&(1<<12) == 0 {
		t.Error("delivery_mode flag not set")
	}
	if flags&(1<<11) == 0 {
		t.Error("priority flag not set")
	}
	// content_type shortstr at flags+2
	off := payloadStart + 14
	if msg[off] != 10 { // len("text/plain") = 10
		t.Errorf("content_type length=%d want 10", msg[off])
	}
	if string(msg[off+1:off+11]) != "text/plain" {
		t.Errorf("content_type=%q want text/plain", string(msg[off+1:off+11]))
	}
	// delivery_mode (1 byte) after content_type
	off += 1 + 10
	if msg[off] != 2 {
		t.Errorf("delivery_mode=%d want 2", msg[off])
	}
	// priority (1 byte) after delivery_mode
	off++
	if msg[off] != 1 {
		t.Errorf("priority=%d want 1", msg[off])
	}
}

func TestBuildBodyFrame(t *testing.T) {
	body := []byte("hello")
	msg := buildBodyFrame(1, body)
	if msg[0] != FrameBody {
		t.Errorf("type=%02x want %02x", msg[0], FrameBody)
	}
	// size = 5
	sz := int(msg[3])<<24 | int(msg[4])<<16 | int(msg[5])<<8 | int(msg[6])
	if sz != 5 {
		t.Errorf("size=%d want 5", sz)
	}
	// payload
	if string(msg[7:12]) != "hello" {
		t.Errorf("body=%q want hello", string(msg[7:12]))
	}
	if msg[len(msg)-1] != FrameEnd {
		t.Errorf("end=%02x want %02x", msg[len(msg)-1], FrameEnd)
	}
}

func TestEncodeShortstr(t *testing.T) {
	b, err := encodeShortstr("hello")
	if err != nil {
		t.Fatalf("encodeShortstr: %v", err)
	}
	if len(b) != 6 {
		t.Fatalf("len=%d want 6", len(b))
	}
	if b[0] != 5 {
		t.Errorf("len byte=%d want 5", b[0])
	}
	if string(b[1:]) != "hello" {
		t.Errorf("data=%q want hello", string(b[1:]))
	}

	// 256-byte string should fail.
	long := strings.Repeat("x", 256)
	_, err = encodeShortstr(long)
	if err == nil || !strings.Contains(err.Error(), "shortstr") {
		t.Errorf("256-byte shortstr: want error, got %v", err)
	}
}

func TestEncodeLongstr(t *testing.T) {
	b := encodeLongstrStr("hello")
	if len(b) != 9 {
		t.Fatalf("len=%d want 9", len(b))
	}
	// length = 5
	length := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if length != 5 {
		t.Errorf("length=%d want 5", length)
	}
	if string(b[4:]) != "hello" {
		t.Errorf("data=%q want hello", string(b[4:]))
	}
}

func TestEncodeFieldTable(t *testing.T) {
	m := map[string]any{
		"key1": "value1",
		"key2": int32(42),
		"key3": true,
	}
	b, err := encodeFieldTable(m)
	if err != nil {
		t.Fatalf("encodeFieldTable: %v", err)
	}
	if len(b) < 4 {
		t.Fatalf("len=%d too short", len(b))
	}
	// entry count
	count := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if count != 3 {
		t.Errorf("entry count=%d want 3", count)
	}
}

func TestResolveBody(t *testing.T) {
	// body_hex takes precedence.
	got := resolveBody([]byte("text"), "686578")
	if string(got) != "hex" {
		t.Errorf("body=%q want hex (body_hex precedence)", string(got))
	}
	got = resolveBody([]byte("text"), "")
	if string(got) != "text" {
		t.Errorf("body=%q want text", string(got))
	}
	got = resolveBody(nil, "")
	if got != nil {
		t.Errorf("nil body: want nil, got %q", string(got))
	}
}

func TestSplitBody(t *testing.T) {
	// frameMax=0: single chunk.
	body := []byte("hello world")
	chunks := splitBody(body, 0)
	if len(chunks) != 1 {
		t.Fatalf("chunks=%d want 1 (frameMax=0)", len(chunks))
	}
	if string(chunks[0]) != "hello world" {
		t.Errorf("chunk=%q", string(chunks[0]))
	}

	// frameMax=4096 (minimum): payload per frame = 4096-8 = 4088.
	body = make([]byte, 5000)
	chunks = splitBody(body, 4096)
	if len(chunks) != 2 {
		t.Fatalf("chunks=%d want 2 (frameMax=4096, body=5000)", len(chunks))
	}
	if len(chunks[0])+len(chunks[1]) != 5000 {
		t.Errorf("total=%d want 5000", len(chunks[0])+len(chunks[1]))
	}
}

func TestEncodeMethodArguments(t *testing.T) {
	// connection.start arguments: version_major=0, version_minor=9,
	// server_properties={}, mechanisms="PLAIN", locales="en_US"
	args := map[string]any{
		"version_major":     int32(0),
		"version_minor":     int32(9),
		"server_properties": map[string]any{},
		"mechanisms":        "PLAIN",
		"locales":           "en_US",
	}
	b, err := encodeMethodArguments(10, 10, args)
	if err != nil {
		t.Fatalf("encodeMethodArguments: %v", err)
	}
	if len(b) < 2 {
		t.Fatalf("len=%d too short", len(b))
	}
	// version_major=0, version_minor=9 are octets ('o') now.
	if b[0] != 0 {
		t.Errorf("version_major=%d want 0", b[0])
	}
	if b[1] != 9 {
		t.Errorf("version_minor=%d want 9", b[1])
	}
}

// ---- Validator tests ----

func TestValidateNil(t *testing.T) {
	if err := validateAMQPConfig(&core.FlowSpec{}); err != nil {
		t.Fatalf("nil AMQP config: want no error, got %v", err)
	}
}

func TestValidateEmptyConnections(t *testing.T) {
	err := validateAMQPConfig(&core.FlowSpec{AMQP: &core.AMQPConfig{}})
	if err == nil || !strings.Contains(err.Error(), "connections") {
		t.Fatalf("err=%v want connections required", err)
	}
}

func TestValidateUnknownProfile(t *testing.T) {
	err := validateAMQPConfig(&core.FlowSpec{AMQP: &core.AMQPConfig{
		Profile: "unknown",
		Connections: []core.AMQPConnection{{
			Events: []core.AMQPEvent{{Kind: "protocol_header", Direction: "c2s"}},
		}},
	}})
	if err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("err=%v want profile rejection", err)
	}
}

func TestValidateProtocolHeader(t *testing.T) {
	// Valid: protocol_header c2s first.
	err := validateAMQPConfig(&core.FlowSpec{AMQP: &core.AMQPConfig{
		Connections: []core.AMQPConnection{{
			Events: []core.AMQPEvent{{Kind: "protocol_header", Direction: "c2s"}},
		}},
	}})
	if err != nil {
		t.Fatalf("valid protocol header: want no error, got %v", err)
	}

	// Invalid: protocol_header s2c.
	err = validateAMQPConfig(&core.FlowSpec{AMQP: &core.AMQPConfig{
		Connections: []core.AMQPConnection{{
			Events: []core.AMQPEvent{{Kind: "protocol_header", Direction: "s2c"}},
		}},
	}})
	if err == nil || !strings.Contains(err.Error(), "protocol header must be c2s") {
		t.Fatalf("err=%v want protocol header direction rejection", err)
	}
}

func TestValidateHandshakeState(t *testing.T) {
	// Method before protocol header.
	err := validateAMQPConfig(&core.FlowSpec{AMQP: &core.AMQPConfig{
		Connections: []core.AMQPConnection{{
			Events: []core.AMQPEvent{{
				Kind: "method", Direction: "c2s", Channel: 0,
				ClassID: 10, MethodID: 10, // connection.start
			}},
		}},
	}})
	if err == nil || !strings.Contains(err.Error(), "protocol header") {
		t.Fatalf("err=%v want method before protocol header rejection", err)
	}

	// connection.start must be s2c.
	err = validateAMQPConfig(&core.FlowSpec{AMQP: &core.AMQPConfig{
		Connections: []core.AMQPConnection{{
			Events: []core.AMQPEvent{
				{Kind: "protocol_header", Direction: "c2s"},
				{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 10},
			},
		}},
	}})
	if err == nil || !strings.Contains(err.Error(), "start must be s2c") {
		t.Fatalf("err=%v want start direction rejection", err)
	}
}

func TestValidateValidHandshake(t *testing.T) {
	err := validateAMQPConfig(&core.FlowSpec{AMQP: &core.AMQPConfig{
		Connections: []core.AMQPConnection{{
			Events: []core.AMQPEvent{
				{Kind: "protocol_header", Direction: "c2s"},
				{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 10, Arguments: map[string]any{"version_major": int32(0), "version_minor": int32(9)}},
				{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 11, Arguments: map[string]any{"client_properties": map[string]any{}, "mechanism": "PLAIN", "response": "", "locale": "en_US"}},
				{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 30, Arguments: map[string]any{"channel_max": int32(0), "frame_max": int32(0), "heartbeat": int32(0)}},
				{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 31, Arguments: map[string]any{"channel_max": int32(0), "frame_max": int32(0), "heartbeat": int32(0)}},
				{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 40, Arguments: map[string]any{"virtual_host": "/", "capabilities": "", "insist": false}},
				{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 41},
				{Kind: "method", Direction: "c2s", Channel: 1, ClassID: 20, MethodID: 10},
				{Kind: "method", Direction: "s2c", Channel: 1, ClassID: 20, MethodID: 11},
			},
		}},
	}})
	if err != nil {
		t.Fatalf("valid handshake: want no error, got %v", err)
	}
}

func TestValidateChannelState(t *testing.T) {
	// Method on unopened channel.
	err := validateAMQPConfig(&core.FlowSpec{AMQP: &core.AMQPConfig{
		Connections: []core.AMQPConnection{{
			Events: []core.AMQPEvent{
				{Kind: "protocol_header", Direction: "c2s"},
				{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 10},
				{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 11},
				{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 30},
				{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 31},
				{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 40},
				{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 41},
				// exchange.declare on channel 5 without opening it.
				{Kind: "method", Direction: "c2s", Channel: 5, ClassID: 40, MethodID: 10},
			},
		}},
	}})
	if err == nil || !strings.Contains(err.Error(), "unopened channel") {
		t.Fatalf("err=%v want unopened channel rejection", err)
	}
}

func TestValidateHeartbeatBeforeOpen(t *testing.T) {
	err := validateAMQPConfig(&core.FlowSpec{AMQP: &core.AMQPConfig{
		Connections: []core.AMQPConnection{{
			Events: []core.AMQPEvent{
				{Kind: "protocol_header", Direction: "c2s"},
				{Kind: "heartbeat", Direction: "c2s"},
			},
		}},
	}})
	if err == nil || !strings.Contains(err.Error(), "heartbeat before connection opened") {
		t.Fatalf("err=%v want heartbeat before open rejection", err)
	}
}

// aGuardHandshake 返回最小合法六步握手（不含 protocol header）。
func aGuardHandshake() []core.AMQPEvent {
	return []core.AMQPEvent{
		{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 10},
		{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 11},
		{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 30},
		{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 31},
		{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 40},
		{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 41},
	}
}

func aGuardMethod(dir string, ch uint16, class, method uint16) core.AMQPEvent {
	return core.AMQPEvent{Kind: "method", Direction: dir, Channel: ch, ClassID: class, MethodID: method}
}

// TestValidateChannelAndStateGuards 覆盖 P6 m1 点名的未测分支（CLAUDE.md §3
// 一条分支一测试）：channel.open on channel 0 (reserved)、open before open-ok、
// open-ok without open、method after connection close、unknown method、
// content interleave、unknown kind。每条钉各自锚词。
func TestValidateChannelAndStateGuards(t *testing.T) {
	withHeader := func(evs ...core.AMQPEvent) []core.AMQPEvent {
		return append([]core.AMQPEvent{{Kind: "protocol_header", Direction: "c2s"}}, evs...)
	}
	openCh := func(evs []core.AMQPEvent, ch uint16) []core.AMQPEvent {
		return append(evs, aGuardMethod("c2s", ch, 20, 10), aGuardMethod("s2c", ch, 20, 11))
	}

	interleave := openCh(aGuardHandshake(), 1)
	interleave = openCh(interleave, 2)
	interleave = append(interleave,
		aGuardMethod("c2s", 1, 60, 40), // contentSeq 起于 ch1
		aGuardMethod("c2s", 2, 60, 80)) // ch2 上的非 content 事件 → 交错

	tests := []struct {
		name   string
		events []core.AMQPEvent
		anchor string
	}{
		{
			// planner.go:293 守卫：channel 0 保留给连接控制，禁止业务 channel.open。
			name:   "channel.open on reserved channel 0",
			events: withHeader(append(aGuardHandshake(), aGuardMethod("c2s", 0, 20, 10))...),
			anchor: "channel.open on channel 0 (reserved)",
		},
		{
			// planner.go:289：握手未完成即开 channel。
			name:   "channel.open before connection open-ok",
			events: withHeader(aGuardMethod("c2s", 1, 20, 10)),
			anchor: "channel.open before connection open-ok",
		},
		{
			// planner.go:296：未 open 直接回 open-ok。
			name:   "channel.open-ok without open",
			events: withHeader(append(aGuardHandshake(), aGuardMethod("s2c", 3, 20, 11))...),
			anchor: "channel.open-ok without open on channel 3",
		},
		{
			// planner.go:201-211：connection.close 之后只许 close/close-ok。
			name: "method after connection close",
			events: withHeader(append(aGuardHandshake(),
				aGuardMethod("c2s", 0, 10, 50),
				aGuardMethod("c2s", 1, 20, 10))...),
			anchor: "method after connection close",
		},
		{
			// planner.go:356：class/method 不在受理集。
			name:   "unknown method",
			events: withHeader(append(aGuardHandshake(), aGuardMethod("c2s", 1, 99, 99))...),
			anchor: "unknown method class 99 method 99",
		},
		{
			// planner.go:361：content 序列未结束即切 channel（AMQP 禁止交错）。
			name:   "content interleave across channels",
			events: withHeader(interleave...),
			anchor: "content interleave across channels",
		},
		{
			// planner.go:414：kind 不在 {method,header,body,heartbeat}。
			name:   "unknown kind",
			events: withHeader(append(aGuardHandshake(), core.AMQPEvent{Kind: "bogus", Direction: "c2s"})...),
			anchor: "unknown kind",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAMQPConfig(&core.FlowSpec{AMQP: &core.AMQPConfig{
				Connections: []core.AMQPConnection{{Events: tc.events}},
			}})
			if err == nil || !strings.Contains(err.Error(), tc.anchor) {
				t.Fatalf("err=%v want anchor %q", err, tc.anchor)
			}
		})
	}
}

func TestValidateContentLength(t *testing.T) {
	// Header bodySize=5 but body event sends 3 bytes.
	err := validateAMQPConfig(&core.FlowSpec{AMQP: &core.AMQPConfig{
		Connections: []core.AMQPConnection{{
			Events: []core.AMQPEvent{
				{Kind: "protocol_header", Direction: "c2s"},
				{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 10},
				{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 11},
				{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 30},
				{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 31},
				{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 40},
				{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 41},
				{Kind: "method", Direction: "c2s", Channel: 1, ClassID: 20, MethodID: 10},
				{Kind: "method", Direction: "s2c", Channel: 1, ClassID: 20, MethodID: 11},
				{Kind: "method", Direction: "c2s", Channel: 1, ClassID: 60, MethodID: 40},
				{Kind: "header", Direction: "c2s", Channel: 1, ClassID: 60, BodySizeOverride: uint64ptr(5)},
				{Kind: "body", Direction: "c2s", Channel: 1, Body: []byte("hel")},
			},
		}},
	}})
	if err == nil || !strings.Contains(err.Error(), "body size mismatch") {
		t.Fatalf("err=%v want body size mismatch", err)
	}
}

func TestValidateWireFaultAnchorWords(t *testing.T) {
	cases := []struct {
		kind, anchor string
	}{
		{"protocol_version", "protocol"},
		{"bad_frame_type", "frame"},
		{"bad_frame_end", "frame"},
		{"frame_size_overflow", "frame"},
		{"handshake_state", "handshake"},
		{"channel_state", "channel"},
		{"body_length", "body"},
		{"session_reference", "session"},
		{"shortstr_overflow", "shortstr"},
	}
	for _, tc := range cases {
		err := validateAMQPConfig(&core.FlowSpec{AMQP: &core.AMQPConfig{
			WireFault: tc.kind,
		}})
		if err == nil || !strings.Contains(err.Error(), tc.anchor) {
			t.Errorf("wire_fault %s: err=%v want anchor %q", tc.kind, err, tc.anchor)
		}
	}
}

// ---- Generator tests ----

func TestGeneratorName(t *testing.T) {
	gen := &AMQPGenerator{}
	if gen.Name() != "amqp" {
		t.Errorf("Name=%s want amqp", gen.Name())
	}
	if gen.GenEvents() == nil {
		t.Error("GenEvents() should not return nil")
	}
	err := gen.EmitEvent(layers.MessageEvent{})
	if err == nil || !strings.Contains(err.Error(), "not wired") {
		t.Fatalf("EmitEvent: want not wired error, got %v", err)
	}
}

func TestGeneratorProtocolHeader(t *testing.T) {
	gen := &AMQPGenerator{}
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
		Meta: layers.FlowMeta{
			AMQP: &core.AMQPConfig{
				Connections: []core.AMQPConnection{{
					Events: []core.AMQPEvent{
						{Kind: "protocol_header", Direction: "c2s"},
					},
				}},
			},
		},
	}
	if err := gen.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events=%d want 1", len(events))
	}
	if !events[0].Up {
		t.Error("event 0: want Up=true (c2s)")
	}
	if string(events[0].Bytes) != "AMQP\x00\x00\x09\x01" {
		t.Errorf("bytes=%x want AMQP header", events[0].Bytes)
	}
}

func TestGeneratorHeartbeatEvent(t *testing.T) {
	gen := &AMQPGenerator{}
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
		Meta: layers.FlowMeta{
			AMQP: &core.AMQPConfig{
				Connections: []core.AMQPConnection{{
					Events: []core.AMQPEvent{
						{Kind: "protocol_header", Direction: "c2s"},
						{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 10},
						{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 11},
						{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 30},
						{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 31},
						{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 40},
						{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 41},
						{Kind: "heartbeat", Direction: "c2s"},
					},
				}},
			},
		},
	}
	if err := gen.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 8 {
		t.Fatalf("events=%d want 8", len(events))
	}
	// Last event should be heartbeat.
	last := events[len(events)-1]
	if len(last.Bytes) != 8 {
		t.Errorf("heartbeat len=%d want 8", len(last.Bytes))
	}
	if last.Bytes[0] != FrameHeartbeat {
		t.Errorf("heartbeat type=%02x want %02x", last.Bytes[0], FrameHeartbeat)
	}
}

func TestGeneratorBodySegmentation(t *testing.T) {
	gen := &AMQPGenerator{}
	var events []layers.MessageEvent
	body := make([]byte, 5000)
	req := &layers.GenRequest{
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
		Meta: layers.FlowMeta{
			AMQP: &core.AMQPConfig{
				FrameMax: 4096,
				Connections: []core.AMQPConnection{{
					Events: []core.AMQPEvent{
						{Kind: "protocol_header", Direction: "c2s"},
						{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 10},
						{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 11},
						{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 30},
						{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 31},
						{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 40},
						{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 41},
						{Kind: "method", Direction: "c2s", Channel: 1, ClassID: 20, MethodID: 10},
						{Kind: "method", Direction: "s2c", Channel: 1, ClassID: 20, MethodID: 11},
						{Kind: "method", Direction: "c2s", Channel: 1, ClassID: 60, MethodID: 40},
						{Kind: "header", Direction: "c2s", Channel: 1, ClassID: 60, Body: body},
						{Kind: "body", Direction: "c2s", Channel: 1, Body: body},
					},
				}},
			},
		},
	}
	if err := gen.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Count body frames: 5000 bytes with frame_max=4096 → 2 BODY frames
	bodyFrameCount := 0
	for _, ev := range events {
		if len(ev.Bytes) > 0 && ev.Bytes[0] == FrameBody {
			bodyFrameCount++
		}
	}
	if bodyFrameCount != 2 {
		t.Errorf("body frames=%d want 2 (5000 bytes, frame_max=4096)", bodyFrameCount)
	}
}

func TestGeneratorEmitMsgNil(t *testing.T) {
	gen := &AMQPGenerator{}
	err := gen.Generate(context.Background(), &layers.GenRequest{})
	if err == nil || !strings.Contains(err.Error(), "EmitMsg") {
		t.Fatalf("err=%v want EmitMsg nil rejection", err)
	}
}

func TestGeneratorBodyHex(t *testing.T) {
	gen := &AMQPGenerator{}
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
		Meta: layers.FlowMeta{
			AMQP: &core.AMQPConfig{
				Connections: []core.AMQPConnection{{
					Events: []core.AMQPEvent{
						{Kind: "protocol_header", Direction: "c2s"},
						{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 10},
						{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 11},
						{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 30},
						{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 31},
						{Kind: "method", Direction: "c2s", Channel: 0, ClassID: 10, MethodID: 40},
						{Kind: "method", Direction: "s2c", Channel: 0, ClassID: 10, MethodID: 41},
						{Kind: "method", Direction: "c2s", Channel: 1, ClassID: 20, MethodID: 10},
						{Kind: "method", Direction: "s2c", Channel: 1, ClassID: 20, MethodID: 11},
						{Kind: "method", Direction: "c2s", Channel: 1, ClassID: 60, MethodID: 40},
						{Kind: "header", Direction: "c2s", Channel: 1, ClassID: 60, BodyHex: "686578", Body: []byte("text")},
						{Kind: "body", Direction: "c2s", Channel: 1, BodyHex: "686578", Body: []byte("text")},
					},
				}},
			},
		},
	}
	if err := gen.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 12 {
		t.Fatalf("events=%d want 12", len(events))
	}
	// body_hex takes precedence: body should be "hex" (0x686578)
	bodyEv := events[len(events)-1]
	if string(bodyEv.Bytes[7:len(bodyEv.Bytes)-1]) != "hex" {
		t.Errorf("body=%q want hex (body_hex precedence)", string(bodyEv.Bytes[7:len(bodyEv.Bytes)-1]))
	}
}

func uint64ptr(v uint64) *uint64 { return &v }
