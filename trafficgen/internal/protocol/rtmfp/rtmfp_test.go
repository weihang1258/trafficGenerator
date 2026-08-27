package rtmfp

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// ---- Builder tests ----

func TestBuildHello(t *testing.T) {
	msg := buildHello(1)
	if len(msg) != HeaderMinLen {
		t.Fatalf("len=%d want %d", len(msg), HeaderMinLen)
	}
	if msg[0] != MarkerControl {
		t.Errorf("marker=%02x want %02x (control)", msg[0], MarkerControl)
	}
	if msg[1] != KindHello {
		t.Errorf("kind=%02x want %02x", msg[1], KindHello)
	}
	if got := binary.BigEndian.Uint32(msg[4:8]); got != 1 {
		t.Errorf("sessionID=%d want 1", got)
	}
	if got := binary.BigEndian.Uint16(msg[2:4]); got != uint16(HeaderMinLen) {
		t.Errorf("length=%d want %d", got, HeaderMinLen)
	}
}

func TestBuildReliableMarker(t *testing.T) {
	msg := buildReliable(1, 2, 7, []byte("hello"))
	// Reliable data uses data marker (0x0C).
	if msg[0] != MarkerData {
		t.Errorf("marker=%02x want %02x (data)", msg[0], MarkerData)
	}
	if msg[1] != KindReliable {
		t.Errorf("kind=%02x want %02x", msg[1], KindReliable)
	}
	if got := binary.BigEndian.Uint32(msg[8:12]); got != 2 {
		t.Errorf("flowID=%d want 2", got)
	}
	if got := binary.BigEndian.Uint32(msg[12:16]); got != 7 {
		t.Errorf("sequence=%d want 7", got)
	}
	if string(msg[HeaderMinLen:]) != "hello" {
		t.Errorf("body=%q want hello", string(msg[HeaderMinLen:]))
	}
}

func TestBuildFragment(t *testing.T) {
	msg := buildFragment(1, 2, 8, 1, 3, 9, []byte("def"))
	// Fragment uses data marker.
	if msg[0] != MarkerData {
		t.Errorf("marker=%02x want %02x", msg[0], MarkerData)
	}
	if msg[1] != KindFragment {
		t.Errorf("kind=%02x want %02x", msg[1], KindFragment)
	}
	if got := binary.BigEndian.Uint32(msg[HeaderMinLen : HeaderMinLen+4]); got != 1 {
		t.Errorf("frag index=%d want 1", got)
	}
	if got := binary.BigEndian.Uint32(msg[HeaderMinLen+4 : HeaderMinLen+8]); got != 3 {
		t.Errorf("frag count=%d want 3", got)
	}
	if got := binary.BigEndian.Uint32(msg[HeaderMinLen+8 : HeaderMinLen+12]); got != 9 {
		t.Errorf("totalLength=%d want 9", got)
	}
	if string(msg[HeaderMinLen+12:]) != "def" {
		t.Errorf("frag data=%q want def", string(msg[HeaderMinLen+12:]))
	}
}

func TestBuildAck(t *testing.T) {
	ranges := [][2]uint32{{1, 1}, {3, 3}}
	msg := buildAck(1, 2, 0, ranges)
	if msg[0] != MarkerControl {
		t.Errorf("marker=%02x want %02x (control)", msg[0], MarkerControl)
	}
	if msg[1] != KindAck {
		t.Errorf("kind=%02x want %02x", msg[1], KindAck)
	}
	if got := binary.BigEndian.Uint16(msg[HeaderMinLen : HeaderMinLen+2]); got != 2 {
		t.Errorf("range count=%d want 2", got)
	}
	// First range at offset HeaderMinLen+2
	off := HeaderMinLen + 2
	if got := binary.BigEndian.Uint32(msg[off : off+4]); got != 1 {
		t.Errorf("range0.start=%d want 1", got)
	}
	if got := binary.BigEndian.Uint32(msg[off+4 : off+8]); got != 1 {
		t.Errorf("range0.end=%d want 1", got)
	}
	// message length in header accounts for payload
	if got := binary.BigEndian.Uint16(msg[2:4]); got != uint16(HeaderMinLen+2+2*8) {
		t.Errorf("length=%d want %d", got, HeaderMinLen+2+2*8)
	}
}

func TestBuildCookie(t *testing.T) {
	// Explicit hex cookie.
	msg := buildCookie(1, "deadbeef")
	if msg[1] != KindCookie {
		t.Errorf("kind=%02x want %02x", msg[1], KindCookie)
	}
	if hex.EncodeToString(msg[HeaderMinLen:]) != "deadbeef" {
		t.Errorf("cookie=%s want deadbeef", hex.EncodeToString(msg[HeaderMinLen:]))
	}
}

func TestResolveBodyBase64Precedence(t *testing.T) {
	got := resolveBody("text", base64.StdEncoding.EncodeToString([]byte("binary")))
	if string(got) != "binary" {
		t.Errorf("body=%q want binary (base64 precedence)", string(got))
	}
	got = resolveBody("", "")
	if got != nil {
		t.Errorf("empty body: want nil, got %q", string(got))
	}
}

// ---- Validator tests ----

func TestValidateNil(t *testing.T) {
	if err := validateRTMFPConfig(&core.FlowSpec{}); err != nil {
		t.Fatalf("nil RTMFP config: want no error, got %v", err)
	}
}

func TestValidateEmptySessions(t *testing.T) {
	err := validateRTMFPConfig(&core.FlowSpec{RTMFP: &core.RTMFPConfig{}})
	if err == nil || !strings.Contains(err.Error(), "sessions") {
		t.Fatalf("err=%v want sessions required", err)
	}
}

func TestValidateUnknownProfile(t *testing.T) {
	err := validateRTMFPConfig(&core.FlowSpec{RTMFP: &core.RTMFPConfig{
		Profile:  "unknown_profile",
		Sessions: []core.RTMFPSession{{SessionID: 1, Events: []core.RTMFPEvent{{Kind: "hello", Direction: "c2s"}}}},
	}})
	if err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("err=%v want profile rejection", err)
	}
}

func TestValidateUnknownRole(t *testing.T) {
	err := validateRTMFPConfig(&core.FlowSpec{RTMFP: &core.RTMFPConfig{
		Role:     "invalid",
		Sessions: []core.RTMFPSession{{SessionID: 1, Events: []core.RTMFPEvent{{Kind: "hello", Direction: "c2s"}}}},
	}})
	if err == nil || !strings.Contains(err.Error(), "role") {
		t.Fatalf("err=%v want role rejection", err)
	}
}

func TestValidateUnknownKind(t *testing.T) {
	err := validateRTMFPConfig(&core.FlowSpec{RTMFP: &core.RTMFPConfig{
		Profile:  "rtmfp_baseline",
		Role:     "initiator",
		Sessions: []core.RTMFPSession{{SessionID: 1, Events: []core.RTMFPEvent{{Kind: "bogus", Direction: "c2s"}}}},
	}})
	if err == nil || !strings.Contains(err.Error(), "kind") {
		t.Fatalf("err=%v want unknown kind rejection", err)
	}
}

func TestValidateStateOrder(t *testing.T) {
	// Data before handshake.
	err := validateRTMFPConfig(&core.FlowSpec{RTMFP: &core.RTMFPConfig{
		Profile:  "rtmfp_baseline",
		Sessions: []core.RTMFPSession{{SessionID: 1, Events: []core.RTMFPEvent{{Kind: "reliable", Direction: "c2s", FlowID: 1, Sequence: 1, Message: "x"}}}},
	}})
	if err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("err=%v want state order rejection", err)
	}
}

func TestValidateCloseThenData(t *testing.T) {
	err := validateRTMFPConfig(&core.FlowSpec{RTMFP: &core.RTMFPConfig{
		Profile: "rtmfp_baseline",
		Sessions: []core.RTMFPSession{{SessionID: 1, Events: []core.RTMFPEvent{
			{Kind: "hello", Direction: "c2s"},
			{Kind: "hello_ack", Direction: "s2c"},
			{Kind: "close", Direction: "c2s"},
			{Kind: "reliable", Direction: "c2s", FlowID: 1, Sequence: 1, Message: "after close"},
		}}},
	}})
	if err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("err=%v want state order (after close) rejection", err)
	}
}

func TestValidateSequenceRegression(t *testing.T) {
	err := validateRTMFPConfig(&core.FlowSpec{RTMFP: &core.RTMFPConfig{
		Profile: "rtmfp_baseline",
		Sessions: []core.RTMFPSession{{SessionID: 1, Events: []core.RTMFPEvent{
			{Kind: "hello", Direction: "c2s"},
			{Kind: "hello_ack", Direction: "s2c"},
			{Kind: "reliable", Direction: "c2s", FlowID: 1, Sequence: 2, Message: "two"},
			{Kind: "reliable", Direction: "c2s", FlowID: 1, Sequence: 1, Message: "one"},
		}}},
	}})
	if err == nil || !strings.Contains(err.Error(), "sequence") {
		t.Fatalf("err=%v want sequence regression rejection", err)
	}
}

func TestValidateFragmentIndexOutOfRange(t *testing.T) {
	err := validateRTMFPConfig(&core.FlowSpec{RTMFP: &core.RTMFPConfig{
		Profile: "rtmfp_baseline",
		Sessions: []core.RTMFPSession{{SessionID: 1, Events: []core.RTMFPEvent{
			{Kind: "hello", Direction: "c2s"},
			{Kind: "hello_ack", Direction: "s2c"},
			{Kind: "fragment", Direction: "c2s", FlowID: 1, Sequence: 1,
				Fragment: &core.RTMFPFragment{Index: 3, Count: 3, TotalLength: 9, Payload: "x"}},
		}}},
	}})
	if err == nil || !strings.Contains(err.Error(), "fragment") {
		t.Fatalf("err=%v want fragment rejection", err)
	}
}

func TestValidateValidConfig(t *testing.T) {
	err := validateRTMFPConfig(&core.FlowSpec{RTMFP: &core.RTMFPConfig{
		Profile: "rtmfp_baseline",
		Role:    "initiator",
		Sessions: []core.RTMFPSession{{SessionID: 1, Events: []core.RTMFPEvent{
			{Kind: "hello", Direction: "c2s"},
			{Kind: "hello_ack", Direction: "s2c"},
			{Kind: "cookie", Direction: "s2c"},
			{Kind: "session_confirm", Direction: "c2s"},
			{Kind: "reliable", Direction: "c2s", FlowID: 1, Sequence: 1, Message: "fixture"},
			{Kind: "ack", Direction: "s2c", FlowID: 1, Sequence: 1, Ranges: [][2]uint32{{1, 1}}},
			{Kind: "close", Direction: "c2s"},
		}}},
	}})
	if err != nil {
		t.Fatalf("valid config: want no error, got %v", err)
	}
}

// ---- Wire fault tests ----

func TestValidateWireFaultAnchorWords(t *testing.T) {
	cases := []struct {
		kind, anchor string
	}{
		{"short_header", "header"},
		{"bad_length", "length"},
		{"session_mismatch", "session"},
		{"sequence_regress", "sequence"},
		{"fragment_gap", "fragment"},
		{"ack_unknown", "ack"},
		{"state_order", "state"},
		{"session_leak", "session"},
	}
	for _, tc := range cases {
		err := validateRTMFPConfig(&core.FlowSpec{RTMFP: &core.RTMFPConfig{
			WireFault: &core.RTMFPFault{Kind: tc.kind},
		}})
		if err == nil || !strings.Contains(err.Error(), tc.anchor) {
			t.Errorf("wire_fault %s: err=%v want anchor %q", tc.kind, err, tc.anchor)
		}
	}
}

// ---- Generator tests ----

func TestGeneratorName(t *testing.T) {
	gen := &RTMFPGenerator{}
	if gen.Name() != "rtmfp" {
		t.Errorf("Name=%s want rtmfp", gen.Name())
	}
	if gen.GenEvents() == nil {
		t.Error("GenEvents() should not return nil")
	}
	err := gen.EmitEvent(layers.MessageEvent{})
	if err == nil || !strings.Contains(err.Error(), "not wired") {
		t.Fatalf("EmitEvent: want not wired error, got %v", err)
	}
}

func TestGeneratorGenerateEventCountAndDirection(t *testing.T) {
	gen := &RTMFPGenerator{}
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
		Meta: layers.FlowMeta{
			RTMFP: &core.RTMFPConfig{
				Profile: "rtmfp_baseline",
				Role:    "initiator",
				Sessions: []core.RTMFPSession{{SessionID: 1, Events: []core.RTMFPEvent{
					{Kind: "hello", Direction: "c2s"},
					{Kind: "hello_ack", Direction: "s2c"},
					{Kind: "reliable", Direction: "c2s", FlowID: 1, Sequence: 1, Message: "fixture"},
					{Kind: "close", Direction: "c2s"},
				}}},
			},
		},
	}
	if err := gen.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("events=%d want 4", len(events))
	}
	if !events[0].Up {
		t.Error("event 0 (hello c2s): want Up=true")
	}
	if events[1].Up {
		t.Error("event 1 (hello_ack s2c): want Up=false")
	}
	for i, ev := range events {
		if len(ev.Bytes) < HeaderMinLen {
			t.Errorf("event %d: bytes too short (%d)", i, len(ev.Bytes))
		}
	}
}

func TestGeneratorMultiSessionSrcPort(t *testing.T) {
	gen := &RTMFPGenerator{}
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
		Meta: layers.FlowMeta{
			RTMFP: &core.RTMFPConfig{
				Profile: "rtmfp_baseline",
				Sessions: []core.RTMFPSession{
					{SessionID: 10, SrcPort: 40009, Events: []core.RTMFPEvent{{Kind: "hello", Direction: "c2s"}}},
					{SessionID: 11, SrcPort: 40010, Events: []core.RTMFPEvent{{Kind: "hello", Direction: "c2s"}}},
				},
			},
		},
	}
	if err := gen.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d want 2", len(events))
	}
	if events[0].SrcPort != 40009 {
		t.Errorf("event 0 SrcPort=%d want 40009", events[0].SrcPort)
	}
	if events[1].SrcPort != 40010 {
		t.Errorf("event 1 SrcPort=%d want 40010", events[1].SrcPort)
	}
}

func TestGeneratorEmitMsgNil(t *testing.T) {
	gen := &RTMFPGenerator{}
	err := gen.Generate(context.Background(), &layers.GenRequest{})
	if err == nil || !strings.Contains(err.Error(), "EmitMsg") {
		t.Fatalf("err=%v want EmitMsg nil rejection", err)
	}
}

func TestGeneratorBase64Payload(t *testing.T) {
	gen := &RTMFPGenerator{}
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
		Meta: layers.FlowMeta{
			RTMFP: &core.RTMFPConfig{
				Profile: "rtmfp_baseline",
				Sessions: []core.RTMFPSession{{SessionID: 1, Events: []core.RTMFPEvent{
					{Kind: "hello", Direction: "c2s"},
					{Kind: "hello_ack", Direction: "s2c"},
					{Kind: "reliable", Direction: "c2s", FlowID: 1, Sequence: 1, MessageB64: "UkZN"},
				}}},
			},
		},
	}
	if err := gen.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("events=%d want 3", len(events))
	}
	if got := string(events[2].Bytes[HeaderMinLen:]); got != "RFM" {
		t.Errorf("b64 body=%q want RFM (UkZN→RFM)", got)
	}
}
