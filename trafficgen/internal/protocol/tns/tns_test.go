package tns

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func hex(b []byte) string {
	const hextable = "0123456789abcdef"
	r := make([]byte, len(b)*2)
	for i, v := range b {
		r[i*2] = hextable[v>>4]
		r[i*2+1] = hextable[v&0x0f]
	}
	return string(r)
}

// --- Builder tests ---

func TestTypeCode(t *testing.T) {
	tests := []struct {
		s    string
		want byte
		ok   bool
	}{
		{"CONNECT", TypeConnect, true},
		{"ACCEPT", TypeAccept, true},
		{"REFUSE", TypeRefuse, true},
		{"REDIRECT", TypeRedirect, true},
		{"DATA", TypeData, true},
		{"UNKNOWN", 0, false},
		{"", 0, false},
		{"connect", 0, false}, // case-sensitive
	}
	for _, tc := range tests {
		got, ok := typeCode(tc.s)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("typeCode(%q)=%d,%v want %d,%v", tc.s, got, ok, tc.want, tc.ok)
		}
	}
}

func TestBuildHeader(t *testing.T) {
	// §2.1: 8-byte header: length(2) + packet_checksum(2) + type(1) + reserved(1) + header_checksum(2)
	b := buildHeader(21, TypeConnect, 0)
	if len(b) != 8 {
		t.Fatalf("header len=%d want 8", len(b))
	}
	// length = 21 = 0x0015
	if got := binary.BigEndian.Uint16(b[0:2]); got != 21 {
		t.Fatalf("length=%d want 21", got)
	}
	// packet_checksum = 0
	if got := binary.BigEndian.Uint16(b[2:4]); got != 0 {
		t.Fatalf("packet_checksum=%d want 0", got)
	}
	// type = CONNECT (0x01)
	if b[4] != TypeConnect {
		t.Fatalf("type=%02x want %02x", b[4], TypeConnect)
	}
	// reserved = 0
	if b[5] != 0x00 {
		t.Fatalf("reserved=%02x want 00", b[5])
	}
	// header_checksum = 0
	if got := binary.BigEndian.Uint16(b[6:8]); got != 0 {
		t.Fatalf("header_checksum=%d want 0", got)
	}
	// Canonical hex: 0015 0000 01 00 0000
	want := "0015000001000000"
	if hex(b) != want {
		t.Fatalf("hex=%s want %s", hex(b), want)
	}
}

func TestBuildHeaderAllTypes(t *testing.T) {
	// Verify each packet type produces the correct type byte in the header.
	tests := []struct {
		pt   byte
		name string
	}{
		{TypeConnect, "CONNECT"},
		{TypeAccept, "ACCEPT"},
		{TypeRefuse, "REFUSE"},
		{TypeRedirect, "REDIRECT"},
		{TypeData, "DATA"},
	}
	for _, tc := range tests {
		b := buildHeader(8, tc.pt, 0)
		if b[4] != tc.pt {
			t.Fatalf("%s: type=%02x want %02x", tc.name, b[4], tc.pt)
		}
	}
}

func TestBuildHeaderChecksumPassthrough(t *testing.T) {
	// Checksum fields carry the checksum parameter value.
	// For disabled mode this is 0, but the builder passes through whatever is given.
	b := buildHeader(8, TypeConnect, 0x1234)
	if got := binary.BigEndian.Uint16(b[2:4]); got != 0x1234 {
		t.Fatalf("packet_checksum=%04x want 1234", got)
	}
	if got := binary.BigEndian.Uint16(b[6:8]); got != 0x1234 {
		t.Fatalf("header_checksum=%04x want 1234", got)
	}
}

func TestBuildDataPacket(t *testing.T) {
	// DATA packet: header(8) + data_flags(2) + payload
	payload := []byte("ttc_connect")
	b := buildDataPacket(8+2+uint16(len(payload)), 0, payload)
	// Total length = 8 + 2 + 11 = 21
	wantLen := 21
	if len(b) != wantLen {
		t.Fatalf("data packet len=%d want %d", len(b), wantLen)
	}
	// Header length field = total
	if got := binary.BigEndian.Uint16(b[0:2]); got != uint16(wantLen) {
		t.Fatalf("length=%d want %d", got, wantLen)
	}
	// Type = DATA (0x06)
	if b[4] != TypeData {
		t.Fatalf("type=%02x want %02x", b[4], TypeData)
	}
	// data_flags = 0x0000 at offset 8
	if got := binary.BigEndian.Uint16(b[8:10]); got != 0 {
		t.Fatalf("data_flags=%04x want 0000", got)
	}
	// payload at offset 10
	if string(b[10:]) != "ttc_connect" {
		t.Fatalf("payload=%q want ttc_connect", b[10:])
	}
}

func TestBuildPacketConnect(t *testing.T) {
	ev := core.TNSEvent{Type: "CONNECT", PayloadProfile: "connect_basic"}
	pkt, err := buildPacket(ev)
	if err != nil {
		t.Fatal(err)
	}
	// Minimal connect_common body: header(8) + 16 prefix + 10 (len/off/max/flags)
	// + 24 (trace fields) + 48 connect_data = 8+98 = 106.
	if len(pkt) != 106 {
		t.Fatalf("len=%d want 106", len(pkt))
	}
	if pkt[4] != TypeConnect {
		t.Fatalf("type=%02x want %02x", pkt[4], TypeConnect)
	}
	// length field at offset 0 = total packet length.
	if got := binary.BigEndian.Uint16(pkt[0:2]); got != 106 {
		t.Fatalf("length=%d want 106", got)
	}
	// Body must not echo the ASCII profile name (design §3.1).
	if bytes.Contains(pkt[8:], []byte("connect_basic")) {
		t.Fatalf("body must not contain ASCII profile name")
	}
}

func TestBuildPacketAccept(t *testing.T) {
	ev := core.TNSEvent{Type: "ACCEPT", PayloadProfile: "accept_basic"}
	pkt, err := buildPacket(ev)
	if err != nil {
		t.Fatal(err)
	}
	// header(8) + 16 prefix + accept_data_length(2) + offset(2) = 28.
	if len(pkt) != 28 {
		t.Fatalf("len=%d want 28", len(pkt))
	}
	if pkt[4] != TypeAccept {
		t.Fatalf("type=%02x want %02x", pkt[4], TypeAccept)
	}
	if bytes.Contains(pkt[8:], []byte("accept_basic")) {
		t.Fatalf("body must not contain ASCII profile name")
	}
}

func TestBuildPacketRefuse(t *testing.T) {
	ev := core.TNSEvent{Type: "REFUSE", PayloadProfile: "refuse_basic"}
	pkt, err := buildPacket(ev)
	if err != nil {
		t.Fatal(err)
	}
	if pkt[4] != TypeRefuse {
		t.Fatalf("type=%02x want %02x", pkt[4], TypeRefuse)
	}
	// header(8) + refuse user/system(2) + refuse_data_length(2) + pad(4) = 16.
	if len(pkt) != 16 {
		t.Fatalf("len=%d want 16", len(pkt))
	}
	if bytes.Contains(pkt[8:], []byte("refuse_basic")) {
		t.Fatalf("body must not contain ASCII profile name")
	}
}

func TestBuildPacketRedirect(t *testing.T) {
	ev := core.TNSEvent{Type: "REDIRECT", PayloadProfile: "redirect_basic"}
	pkt, err := buildPacket(ev)
	if err != nil {
		t.Fatal(err)
	}
	if pkt[4] != TypeRedirect {
		t.Fatalf("type=%02x want %02x", pkt[4], TypeRedirect)
	}
	// header(8) + redirect_data_length(2) + pad(2) = 12.
	if len(pkt) != 12 {
		t.Fatalf("len=%d want 12", len(pkt))
	}
	if bytes.Contains(pkt[8:], []byte("redirect_basic")) {
		t.Fatalf("body must not contain ASCII profile name")
	}
}

func TestBuildPacketData(t *testing.T) {
	ev := core.TNSEvent{Type: "DATA", PayloadProfile: "ttc_connect", DataFlags: 0}
	pkt, err := buildPacket(ev)
	if err != nil {
		t.Fatal(err)
	}
	// DATA: header(8) + data_flags(2) + payload(0) = 10.
	if len(pkt) != 10 {
		t.Fatalf("len=%d want 10", len(pkt))
	}
	if pkt[4] != TypeData {
		t.Fatalf("type=%02x want %02x", pkt[4], TypeData)
	}
	// data_flags at offset 8
	if got := binary.BigEndian.Uint16(pkt[8:10]); got != 0 {
		t.Fatalf("data_flags=%04x want 0000", got)
	}
}

func TestBuildPacketDataNonzeroFlags(t *testing.T) {
	// §2.3: v1 rejects nonzero data_flags
	ev := core.TNSEvent{Type: "DATA", DataFlags: 1, PayloadProfile: "x"}
	_, err := buildPacket(ev)
	if err == nil || !strings.Contains(err.Error(), "data_flags must be 0") {
		t.Fatalf("err=%v want data_flags must be 0", err)
	}
}

func TestBuildPacketEmptyProfile(t *testing.T) {
	// Empty profile still builds a valid connect_common body (not the ASCII "tns").
	ev := core.TNSEvent{Type: "CONNECT", PayloadProfile: ""}
	pkt, err := buildPacket(ev)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt) != 106 {
		t.Fatalf("len=%d want 106", len(pkt))
	}
	if bytes.Contains(pkt[8:], []byte("tns")) {
		t.Fatalf("body must not contain ASCII profile name")
	}
}

func TestEventTypeString(t *testing.T) {
	tests := []struct {
		s    string
		want byte
	}{
		{"CONNECT", TypeConnect},
		{"ACCEPT", TypeAccept},
		{"REFUSE", TypeRefuse},
		{"REDIRECT", TypeRedirect},
		{"DATA", TypeData},
	}
	for _, tc := range tests {
		ev := core.TNSEvent{Type: tc.s}
		got, err := eventType(ev)
		if err != nil {
			t.Fatalf("eventType(%q): %v", tc.s, err)
		}
		if got != tc.want {
			t.Fatalf("eventType(%q)=%02x want %02x", tc.s, got, tc.want)
		}
	}
}

func TestEventTypeNumeric(t *testing.T) {
	tests := []struct {
		v    interface{}
		want byte
	}{
		{float64(1), TypeConnect},
		{float64(2), TypeAccept},
		{float64(4), TypeRefuse},
		{float64(5), TypeRedirect},
		{float64(6), TypeData},
		{int(1), TypeConnect},
		{int32(2), TypeAccept},
	}
	for _, tc := range tests {
		ev := core.TNSEvent{Type: tc.v}
		got, err := eventType(ev)
		if err != nil {
			t.Fatalf("eventType(%v): %v", tc.v, err)
		}
		if got != tc.want {
			t.Fatalf("eventType(%v)=%02x want %02x", tc.v, got, tc.want)
		}
	}
}

func TestEventTypeUnknown(t *testing.T) {
	// Unknown string type
	ev := core.TNSEvent{Type: "BOGUS"}
	_, err := eventType(ev)
	if err == nil || !strings.Contains(err.Error(), "unknown packet type") {
		t.Fatalf("err=%v want unknown packet type", err)
	}
	// Unknown numeric type (127 from N2)
	ev = core.TNSEvent{Type: 127}
	_, err = eventType(ev)
	if err == nil || !strings.Contains(err.Error(), "unknown packet type") {
		t.Fatalf("err=%v want unknown packet type", err)
	}
	// Invalid type
	ev = core.TNSEvent{Type: struct{}{}}
	_, err = eventType(ev)
	if err == nil || !strings.Contains(err.Error(), "unknown packet type") {
		t.Fatalf("err=%v want unknown packet type", err)
	}
}

func TestCheckWireFault(t *testing.T) {
	// Nil
	if err := checkWireFault(nil); err != nil {
		t.Fatalf("nil: %v", err)
	}
	// Empty
	if err := checkWireFault(json.RawMessage{}); err != nil {
		t.Fatalf("empty: %v", err)
	}
	// Length fault
	raw := json.RawMessage(`{"kind":"length","value":7}`)
	err := checkWireFault(raw)
	if err == nil || !strings.Contains(err.Error(), "length") {
		t.Fatalf("err=%v want length", err)
	}
	// Packet checksum fault
	raw = json.RawMessage(`{"kind":"packet_checksum","value":1}`)
	err = checkWireFault(raw)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("err=%v want checksum", err)
	}
	// Data flags fault
	raw = json.RawMessage(`{"kind":"data_flags","value":1}`)
	err = checkWireFault(raw)
	if err == nil || !strings.Contains(err.Error(), "data_flags") {
		t.Fatalf("err=%v want data_flags", err)
	}
	// Unknown kind
	raw = json.RawMessage(`{"kind":"bogus","value":0}`)
	err = checkWireFault(raw)
	if err == nil || !strings.Contains(err.Error(), "unknown kind") {
		t.Fatalf("err=%v want unknown kind", err)
	}
	// Invalid JSON
	raw = json.RawMessage(`{invalid}`)
	err = checkWireFault(raw)
	if err == nil || !strings.Contains(err.Error(), "invalid wire_fault") {
		t.Fatalf("err=%v want invalid wire_fault", err)
	}
}

// --- Planner Validate tests ---

func TestValidateTNSConfigRequired(t *testing.T) {
	// P0b-2: 空配置（nil）允许——Plan/Generate 会默认化并产默认流。
	if err := (Planner{}).Validate(core.FlowSpec{}); err != nil {
		t.Fatalf("Validate(nil config) err=%v want nil", err)
	}
}

func TestValidateTNSEventsRequired(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{TNS: &core.TNSConfig{}})
	if err == nil || !strings.Contains(err.Error(), "at least one event") {
		t.Fatalf("err=%v want at least one event", err)
	}
}

func TestValidateTNSMutuallyExclusive(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		TNS: &core.TNSConfig{
			Events:   []core.TNSEvent{{Type: "CONNECT"}},
			Sessions: []core.TNSSession{{Events: []core.TNSEvent{{Type: "CONNECT"}}}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err=%v want mutually exclusive", err)
	}
}

func TestValidateTNSUnknownChecksumMode(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		TNS: &core.TNSConfig{
			Events:       []core.TNSEvent{{Type: "CONNECT"}},
			ChecksumMode: "enabled",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported checksum mode") {
		t.Fatalf("err=%v want unsupported checksum mode", err)
	}
}

func TestValidateTNSUnknownPacketType(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{{Type: 127}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown packet type") {
		t.Fatalf("err=%v want unknown packet type", err)
	}
}

func TestValidateTNSFirstEventDirection(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{
				{Type: "CONNECT", Direction: "s2c"},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "first event must be") {
		t.Fatalf("err=%v want first event must be client->server", err)
	}
}

func TestValidateTNSDataFlags(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{
				{Type: "CONNECT"},
				{Type: "DATA", DataFlags: 1},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "data_flags must be 0") {
		t.Fatalf("err=%v want data_flags must be 0", err)
	}
}

func TestValidateTNSBadIP(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		TNS:   &core.TNSConfig{Events: []core.TNSEvent{{Type: "CONNECT"}}},
		SrcIP: "not-an-ip",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Fatalf("err=%v want invalid source IP", err)
	}
}

func TestValidateTNSWireFault(t *testing.T) {
	// N3: wire_fault length
	err := (Planner{}).Validate(core.FlowSpec{
		TNS: &core.TNSConfig{
			Events:    []core.TNSEvent{{Type: "CONNECT"}},
			WireFault: json.RawMessage(`{"kind":"length","value":7}`),
		},
	})
	if err == nil || !strings.Contains(err.Error(), "length") {
		t.Fatalf("err=%v want length fault", err)
	}
}

func TestValidateTNSSessionEmptyEvents(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		TNS: &core.TNSConfig{
			Sessions: []core.TNSSession{
				{SrcPort: 12345, Events: []core.TNSEvent{}},
			},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "empty events") {
		t.Fatalf("err=%v want empty events", err)
	}
}

func TestValidateTNSValid(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{
				{Type: "CONNECT", PayloadProfile: "connect_basic"},
				{Type: "ACCEPT", PayloadProfile: "accept_basic"},
			},
		},
		SrcIP: "10.0.0.1",
		DstIP: "20.0.0.1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTNSValidSessions(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{
		TNS: &core.TNSConfig{
			Sessions: []core.TNSSession{
				{SrcPort: 12345, Events: []core.TNSEvent{{Type: "CONNECT"}, {Type: "ACCEPT"}}},
				{SrcPort: 12346, Events: []core.TNSEvent{{Type: "CONNECT"}, {Type: "ACCEPT"}}},
			},
		},
		SrcIP: "10.0.0.1",
		DstIP: "20.0.0.1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Plan tests ---

// collectPackets reads up to max packets from the channel.
func collectPackets(ch <-chan core.PacketConfig, max int) []core.PacketConfig {
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
		if len(pkts) >= max {
			break
		}
	}
	return pkts
}

// TestPlanS1: S1/T-TNS-S1: CONNECT→ACCEPT→DATA→DATA, 11 packets
func TestPlanS1ConnectAcceptData(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 1521,
		Count:   1,
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{
				{Type: "CONNECT", Direction: "c2s", PayloadProfile: "connect_basic"},
				{Type: "ACCEPT", Direction: "s2c", PayloadProfile: "accept_basic"},
				{Type: "DATA", Direction: "c2s", PayloadProfile: "ttc_connect", DataFlags: 0},
				{Type: "DATA", Direction: "s2c", PayloadProfile: "ttc_accept", DataFlags: 0},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	pkts := collectPackets(ch, 20)
	if len(pkts) != 11 {
		t.Fatalf("packet_count=%d want 11 (3 handshake + 4 events + 4 teardown)", len(pkts))
	}
	// Handshake: SYN, SYN-ACK, ACK
	if pkts[0].L4.Flags != 0x02 {
		t.Fatalf("pkt[0] flags=%02x want SYN", pkts[0].L4.Flags)
	}
	if pkts[1].L4.Flags != 0x12 {
		t.Fatalf("pkt[1] flags=%02x want SYN-ACK", pkts[1].L4.Flags)
	}
	if pkts[2].L4.Flags != 0x10 {
		t.Fatalf("pkt[2] flags=%02x want ACK", pkts[2].L4.Flags)
	}
	// pkt[3]: CONNECT up, dst_port=1521
	if pkts[3].Direction != "up" {
		t.Fatalf("pkt[3] direction=%q want up", pkts[3].Direction)
	}
	if pkts[3].L4.DstPort != 1521 {
		t.Fatalf("pkt[3] dst_port=%d want 1521", pkts[3].L4.DstPort)
	}
	// CONNECT type byte at offset 4 of payload
	if len(pkts[3].Payload) < 5 {
		t.Fatalf("pkt[3] payload too short: %d", len(pkts[3].Payload))
	}
	if pkts[3].Payload[4] != TypeConnect {
		t.Fatalf("pkt[3] tns.type=%02x want %02x (CONNECT)", pkts[3].Payload[4], TypeConnect)
	}
	// pkt[4]: ACCEPT down
	if pkts[4].Direction != "down" {
		t.Fatalf("pkt[4] direction=%q want down", pkts[4].Direction)
	}
	if pkts[4].Payload[4] != TypeAccept {
		t.Fatalf("pkt[4] type=%02x want %02x (ACCEPT)", pkts[4].Payload[4], TypeAccept)
	}
	// pkt[5]: DATA up (c2s)
	if pkts[5].Direction != "up" {
		t.Fatalf("pkt[5] direction=%q want up", pkts[5].Direction)
	}
	if pkts[5].Payload[4] != TypeData {
		t.Fatalf("pkt[5] type=%02x want %02x (DATA)", pkts[5].Payload[4], TypeData)
	}
	// DATA flags at offset 8: 0x0000
	if got := binary.BigEndian.Uint16(pkts[5].Payload[8:10]); got != 0 {
		t.Fatalf("pkt[5] data_flags=%04x want 0000", got)
	}
	// pkt[6]: DATA down (s2c)
	if pkts[6].Direction != "down" {
		t.Fatalf("pkt[6] direction=%q want down", pkts[6].Direction)
	}
	if pkts[6].Payload[4] != TypeData {
		t.Fatalf("pkt[6] type=%02x want %02x (DATA)", pkts[6].Payload[4], TypeData)
	}
	// Teardown: FIN/ACK up, ACK down, FIN/ACK down, ACK up
	if pkts[7].L4.Flags != 0x11 {
		t.Fatalf("pkt[7] flags=%02x want FIN/ACK", pkts[7].L4.Flags)
	}
	if pkts[8].L4.Flags != 0x10 {
		t.Fatalf("pkt[8] flags=%02x want ACK", pkts[8].L4.Flags)
	}
	if pkts[9].L4.Flags != 0x11 {
		t.Fatalf("pkt[9] flags=%02x want FIN/ACK", pkts[9].L4.Flags)
	}
	if pkts[10].L4.Flags != 0x10 {
		t.Fatalf("pkt[10] flags=%02x want ACK", pkts[10].L4.Flags)
	}
	// Verify wire format at offset 54 + 4 = 58 (CONNECT type byte)
	// Header: [length(2)][checksum(2)][type(1)][reserved(1)][hdr_checksum(2)]
	// CONNECT: length=0x006a (106 = 8 header + 98 connect_common body),
	// checksum=0x0000, type=01, reserved=00, hdr_checksum=0x0000.
	hdr := pkts[3].Payload[:8]
	wantHdr := "006a000001000000"
	if hex(hdr) != wantHdr {
		t.Fatalf("CONNECT header hex=%s want %s", hex(hdr), wantHdr)
	}
	// DATA header: length=0x000a (10 = 8 + 2 data_flags + 0 payload),
	// checksum=0x0000, type=06, reserved=00, hdr_checksum=0x0000
	hdr = pkts[5].Payload[:8]
	wantDataHdr := "000a000006000000"
	if hex(hdr) != wantDataHdr {
		t.Fatalf("DATA header hex=%s want %s", hex(hdr), wantDataHdr)
	}
}

// TestPlanS2: S2/T-TNS-S2: CONNECT→REFUSE, 9 packets
func TestPlanS2Refuse(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 1521,
		Count:   1,
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{
				{Type: "CONNECT", Direction: "c2s", PayloadProfile: "connect_basic"},
				{Type: "REFUSE", Direction: "s2c", PayloadProfile: "refuse_basic"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	pkts := collectPackets(ch, 20)
	if len(pkts) != 9 {
		t.Fatalf("packet_count=%d want 9 (3 handshake + 2 events + 4 teardown)", len(pkts))
	}
	// CONNECT type=1
	if pkts[3].Payload[4] != TypeConnect {
		t.Fatalf("pkt[3] type=%02x want 01 (CONNECT)", pkts[3].Payload[4])
	}
	// REFUSE type=4
	if pkts[4].Payload[4] != TypeRefuse {
		t.Fatalf("pkt[4] type=%02x want 04 (REFUSE)", pkts[4].Payload[4])
	}
	// No DATA events
	// Check that remaining packets are teardown
	for _, p := range pkts[5:] {
		if len(p.Payload) > 0 {
			t.Fatalf("teardown packet has payload %d bytes", len(p.Payload))
		}
	}
}

// TestPlanS3: S3/T-TNS-S3: CONNECT→REDIRECT, 9 packets
func TestPlanS3Redirect(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 1521,
		Count:   1,
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{
				{Type: "CONNECT", Direction: "c2s", PayloadProfile: "connect_basic"},
				{Type: "REDIRECT", Direction: "s2c", PayloadProfile: "redirect_basic"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	pkts := collectPackets(ch, 20)
	if len(pkts) != 9 {
		t.Fatalf("packet_count=%d want 9", len(pkts))
	}
	if pkts[3].Payload[4] != TypeConnect {
		t.Fatalf("pkt[3] type=%02x want 01", pkts[3].Payload[4])
	}
	if pkts[4].Payload[4] != TypeRedirect {
		t.Fatalf("pkt[4] type=%02x want 05 (REDIRECT)", pkts[4].Payload[4])
	}
}

// TestPlanS4: S4/T-TNS-S4: TTC/SQL*Net sequence, 13 packets
func TestPlanS4TTCSQLNet(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 1521,
		Count:   1,
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{
				{Type: "CONNECT", Direction: "c2s", PayloadProfile: "connect_basic"},
				{Type: "ACCEPT", Direction: "s2c", PayloadProfile: "accept_basic"},
				{Type: "DATA", Direction: "c2s", PayloadProfile: "ttc_connect", DataFlags: 0},
				{Type: "DATA", Direction: "s2c", PayloadProfile: "ttc_accept", DataFlags: 0},
				{Type: "DATA", Direction: "c2s", PayloadProfile: "sqlnet_request", DataFlags: 0},
				{Type: "DATA", Direction: "s2c", PayloadProfile: "sqlnet_response", DataFlags: 0},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	pkts := collectPackets(ch, 20)
	if len(pkts) != 13 {
		t.Fatalf("packet_count=%d want 13 (3 handshake + 6 events + 4 teardown)", len(pkts))
	}
	// Check all 4 DATA events (packets 5, 6, 7, 8)
	for i := 5; i <= 8; i++ {
		if pkts[i].Payload[4] != TypeData {
			t.Fatalf("pkt[%d] type=%02x want 06 (DATA)", i, pkts[i].Payload[4])
		}
		// data_flags = 0
		if got := binary.BigEndian.Uint16(pkts[i].Payload[8:10]); got != 0 {
			t.Fatalf("pkt[%d] data_flags=%04x want 0000", i, got)
		}
	}
	// packet_checksum and header_checksum are 0 on all packets
	for i, p := range pkts {
		if len(p.Payload) >= 8 {
			if got := binary.BigEndian.Uint16(p.Payload[2:4]); got != 0 {
				t.Fatalf("pkt[%d] packet_checksum=%04x want 0000", i, got)
			}
			if got := binary.BigEndian.Uint16(p.Payload[6:8]); got != 0 {
				t.Fatalf("pkt[%d] header_checksum=%04x want 0000", i, got)
			}
		}
	}
}

// TestPlanS5: S5/T-TNS-S5: IPv6 CONNECT→ACCEPT, 9 packets
func TestPlanS5IPv6(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "2001:db8::1",
		DstIP:   "2001:db8::2",
		SrcPort: 12345,
		DstPort: 1521,
		Count:   1,
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{
				{Type: "CONNECT", Direction: "c2s", PayloadProfile: "connect_basic"},
				{Type: "ACCEPT", Direction: "s2c", PayloadProfile: "accept_basic"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	pkts := collectPackets(ch, 20)
	if len(pkts) != 9 {
		t.Fatalf("packet_count=%d want 9", len(pkts))
	}
	// Check IPv6 addresses
	if pkts[0].L3.SrcIP != "2001:db8::1" {
		t.Fatalf("pkt[0] src_ip=%q want 2001:db8::1", pkts[0].L3.SrcIP)
	}
	if pkts[0].L3.DstIP != "2001:db8::2" {
		t.Fatalf("pkt[0] dst_ip=%q want 2001:db8::2", pkts[0].L3.DstIP)
	}
	// TNS wire bytes are the same regardless of IP version
	if pkts[3].Payload[4] != TypeConnect {
		t.Fatalf("pkt[3] type=%02x want 01", pkts[3].Payload[4])
	}
	if pkts[4].Payload[4] != TypeAccept {
		t.Fatalf("pkt[4] type=%02x want 02", pkts[4].Payload[4])
	}
	// Checksum fields are 0
	if got := binary.BigEndian.Uint16(pkts[3].Payload[2:4]); got != 0 {
		t.Fatalf("pkt[3] packet_checksum=%04x want 0000", got)
	}
	if got := binary.BigEndian.Uint16(pkts[4].Payload[6:8]); got != 0 {
		t.Fatalf("pkt[4] header_checksum=%04x want 0000", got)
	}
}

// TestPlanS6: S6/T-TNS-S6: two independent sessions, 18 packets
func TestPlanS6MultiSession(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		DstPort: 1521,
		Count:   1,
		TNS: &core.TNSConfig{
			Sessions: []core.TNSSession{
				{SrcPort: 12345, Events: []core.TNSEvent{
					{Type: "CONNECT", Direction: "c2s", PayloadProfile: "connect_basic"},
					{Type: "ACCEPT", Direction: "s2c", PayloadProfile: "accept_basic"},
				}},
				{SrcPort: 12346, Events: []core.TNSEvent{
					{Type: "CONNECT", Direction: "c2s", PayloadProfile: "connect_basic"},
					{Type: "ACCEPT", Direction: "s2c", PayloadProfile: "accept_basic"},
				}},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	pkts := collectPackets(ch, 20)
	if len(pkts) != 18 {
		t.Fatalf("packet_count=%d want 18 (2 × (3 handshake + 2 events + 4 teardown))", len(pkts))
	}
	// Session 0: src_port=12345
	// pkt[0-2]: handshake session 0
	if pkts[0].L4.SrcPort != 12345 {
		t.Fatalf("session0 handshake src_port=%d want 12345", pkts[0].L4.SrcPort)
	}
	// pkt[3]: CONNECT session 0
	if pkts[3].Payload[4] != TypeConnect {
		t.Fatalf("session0 CONNECT type=%02x", pkts[3].Payload[4])
	}
	if pkts[3].L4.SrcPort != 12345 {
		t.Fatalf("session0 CONNECT src_port=%d want 12345", pkts[3].L4.SrcPort)
	}
	// pkt[4]: ACCEPT session 0
	if pkts[4].Payload[4] != TypeAccept {
		t.Fatalf("session0 ACCEPT type=%02x", pkts[4].Payload[4])
	}
	// pkt[5-8]: teardown session 0
	// Session 1: src_port=12346
	// pkt[9-11]: handshake session 1
	if pkts[9].L4.SrcPort != 12346 {
		t.Fatalf("session1 handshake src_port=%d want 12346", pkts[9].L4.SrcPort)
	}
	// pkt[12]: CONNECT session 1
	if pkts[12].Payload[4] != TypeConnect {
		t.Fatalf("session1 CONNECT type=%02x", pkts[12].Payload[4])
	}
	if pkts[12].L4.SrcPort != 12346 {
		t.Fatalf("session1 CONNECT src_port=%d want 12346", pkts[12].L4.SrcPort)
	}
	// pkt[13]: ACCEPT session 1
	if pkts[13].Payload[4] != TypeAccept {
		t.Fatalf("session1 ACCEPT type=%02x", pkts[13].Payload[4])
	}
	// pkt[14-17]: teardown session 1
}

// TestPlanS7: S7/T-TNS-S7: header fields and DATA flags, 11 packets
func TestPlanS7HeaderFields(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 1521,
		Count:   1,
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{
				{Type: "CONNECT", Direction: "c2s", PayloadProfile: "connect_basic"},
				{Type: "ACCEPT", Direction: "s2c", PayloadProfile: "accept_basic"},
				{Type: "DATA", Direction: "c2s", PayloadProfile: "ttc_connect", DataFlags: 0},
				{Type: "DATA", Direction: "s2c", PayloadProfile: "ttc_accept", DataFlags: 0},
			},
			ChecksumMode: "disabled",
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	pkts := collectPackets(ch, 20)
	if len(pkts) != 11 {
		t.Fatalf("packet_count=%d want 11", len(pkts))
	}
	// Check all 4 event packets have proper header fields
	eventIdx := []int{3, 4, 5, 6}
	for _, idx := range eventIdx {
		p := pkts[idx]
		if len(p.Payload) < 8 {
			t.Fatalf("pkt[%d] payload too short: %d", idx, len(p.Payload))
		}
		// length non-zero
		length := binary.BigEndian.Uint16(p.Payload[0:2])
		if length < 8 {
			t.Fatalf("pkt[%d] length=%d < 8", idx, length)
		}
		// packet_checksum = 0
		if got := binary.BigEndian.Uint16(p.Payload[2:4]); got != 0 {
			t.Fatalf("pkt[%d] packet_checksum=%04x want 0000", idx, got)
		}
		// reserved = 0
		if p.Payload[5] != 0 {
			t.Fatalf("pkt[%d] reserved=%02x want 00", idx, p.Payload[5])
		}
		// header_checksum = 0
		if got := binary.BigEndian.Uint16(p.Payload[6:8]); got != 0 {
			t.Fatalf("pkt[%d] header_checksum=%04x want 0000", idx, got)
		}
	}
	// DATA packets have data_flags=0 at offset 8
	for _, idx := range []int{5, 6} {
		if got := binary.BigEndian.Uint16(pkts[idx].Payload[8:10]); got != 0 {
			t.Fatalf("pkt[%d] data_flags=%04x want 0000", idx, got)
		}
	}
}

// TestPlanDefaultPort: verify default port 1521
func TestPlanDefaultPort(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1",
		DstIP: "20.0.0.1",
		Count: 1,
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{
				{Type: "CONNECT", Direction: "c2s", PayloadProfile: "connect_basic"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	pkts := collectPackets(ch, 20)
	if len(pkts) != 8 {
		t.Fatalf("packet_count=%d want 8", len(pkts))
	}
	if pkts[3].L4.DstPort != 1521 {
		t.Fatalf("dst_port=%d want 1521", pkts[3].L4.DstPort)
	}
}

// TestPlanSessionDefaultSrcPort: session with zero SrcPort uses spec.SrcPort
func TestPlanSessionDefaultSrcPort(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		Count:   1,
		TNS: &core.TNSConfig{
			Sessions: []core.TNSSession{
				{Events: []core.TNSEvent{
					{Type: "CONNECT", Direction: "c2s"},
				}},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	pkts := collectPackets(ch, 20)
	if len(pkts) != 8 {
		t.Fatalf("packet_count=%d want 8", len(pkts))
	}
	if pkts[3].L4.SrcPort != 12345 {
		t.Fatalf("src_port=%d want 12345", pkts[3].L4.SrcPort)
	}
}

// TestPlanNegativeN2: unknown packet type rejected
func TestPlanNegativeN2(t *testing.T) {
	spec := core.FlowSpec{
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{
				{Type: 127, Direction: "c2s", PayloadProfile: "connect_basic"},
			},
		},
	}
	_, err := (Planner{}).Plan(context.Background(), spec)
	if err == nil || !strings.Contains(err.Error(), "unknown packet type") {
		t.Fatalf("err=%v want unknown packet type", err)
	}
}

// TestPlanNegativeN3: wire_fault length rejected
func TestPlanNegativeN3(t *testing.T) {
	spec := core.FlowSpec{
		TNS: &core.TNSConfig{
			Events:    []core.TNSEvent{{Type: "CONNECT"}, {Type: "ACCEPT"}},
			WireFault: json.RawMessage(`{"kind":"length","value":7}`),
		},
	}
	_, err := (Planner{}).Plan(context.Background(), spec)
	if err == nil || !strings.Contains(err.Error(), "length") {
		t.Fatalf("err=%v want length fault", err)
	}
}

// TestPlanNegativeN4: wire_fault checksum rejected
func TestPlanNegativeN4(t *testing.T) {
	spec := core.FlowSpec{
		TNS: &core.TNSConfig{
			Events:       []core.TNSEvent{{Type: "CONNECT"}, {Type: "ACCEPT"}},
			ChecksumMode: "disabled",
			WireFault:    json.RawMessage(`{"kind":"packet_checksum","value":1}`),
		},
	}
	_, err := (Planner{}).Plan(context.Background(), spec)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("err=%v want checksum fault", err)
	}
}

// TestPlanNegativeN5: nonzero data_flags rejected
func TestPlanNegativeN5(t *testing.T) {
	spec := core.FlowSpec{
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{
				{Type: "CONNECT"},
				{Type: "ACCEPT"},
				{Type: "DATA", DataFlags: 1, PayloadProfile: "ttc_connect"},
			},
		},
	}
	_, err := (Planner{}).Plan(context.Background(), spec)
	if err == nil || !strings.Contains(err.Error(), "data_flags") {
		t.Fatalf("err=%v want data_flags must be 0", err)
	}
}

// --- Layer Generator tests ---

func TestTNSGeneratorName(t *testing.T) {
	g := &TNSGenerator{}
	if g.Name() != "tns" {
		t.Fatalf("Name=%q want tns", g.Name())
	}
}

func TestTNSGeneratorGenerateConnectAccept(t *testing.T) {
	cfg := &core.TNSConfig{
		Events: []core.TNSEvent{
			{Type: "CONNECT", Direction: "c2s", PayloadProfile: "connect_basic"},
			{Type: "ACCEPT", Direction: "s2c", PayloadProfile: "accept_basic"},
		},
	}
	var events []layers.MessageEvent
	emit := func(ev layers.MessageEvent) error {
		events = append(events, ev)
		return nil
	}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{TNS: cfg},
		EmitMsg: emit,
	}
	ctx := context.Background()
	g := &TNSGenerator{}
	err := g.Generate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d want 2", len(events))
	}
	// First event: CONNECT up
	if !events[0].Up {
		t.Fatalf("event[0] Up=false want true")
	}
	if events[0].Bytes[4] != TypeConnect {
		t.Fatalf("event[0] type=%02x want %02x", events[0].Bytes[4], TypeConnect)
	}
	// Second event: ACCEPT down
	if events[1].Up {
		t.Fatalf("event[1] Up=true want false")
	}
	if events[1].Bytes[4] != TypeAccept {
		t.Fatalf("event[1] type=%02x want %02x", events[1].Bytes[4], TypeAccept)
	}
}

func TestTNSGeneratorGenerateTTCDATA(t *testing.T) {
	cfg := &core.TNSConfig{
		Events: []core.TNSEvent{
			{Type: "CONNECT", Direction: "c2s", PayloadProfile: "connect_basic"},
			{Type: "ACCEPT", Direction: "s2c", PayloadProfile: "accept_basic"},
			{Type: "DATA", Direction: "c2s", PayloadProfile: "ttc_connect", DataFlags: 0},
			{Type: "DATA", Direction: "s2c", PayloadProfile: "ttc_accept", DataFlags: 0},
		},
	}
	var events []layers.MessageEvent
	emit := func(ev layers.MessageEvent) error {
		events = append(events, ev)
		return nil
	}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{TNS: cfg},
		EmitMsg: emit,
	}
	ctx := context.Background()
	g := &TNSGenerator{}
	err := g.Generate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 {
		t.Fatalf("events=%d want 4", len(events))
	}
	// Check DATA events have correct type and data_flags=0
	for i := 2; i < 4; i++ {
		if events[i].Bytes[4] != TypeData {
			t.Fatalf("event[%d] type=%02x want 06 (DATA)", i, events[i].Bytes[4])
		}
		flags := binary.BigEndian.Uint16(events[i].Bytes[8:10])
		if flags != 0 {
			t.Fatalf("event[%d] data_flags=%04x want 0000", i, flags)
		}
	}
}

func TestTNSGeneratorGenerateSessions(t *testing.T) {
	cfg := &core.TNSConfig{
		Sessions: []core.TNSSession{
			{Events: []core.TNSEvent{
				{Type: "CONNECT", Direction: "c2s"},
				{Type: "ACCEPT", Direction: "s2c"},
			}},
		},
	}
	var events []layers.MessageEvent
	emit := func(ev layers.MessageEvent) error {
		events = append(events, ev)
		return nil
	}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{TNS: cfg},
		EmitMsg: emit,
	}
	ctx := context.Background()
	g := &TNSGenerator{}
	err := g.Generate(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d want 2", len(events))
	}
}

func TestTNSGeneratorGenerateNilConfig(t *testing.T) {
	// P0b-2: 空配置（nil）默认化并产默认流——至少产一条 DATA 报文事件。
	var events []layers.MessageEvent
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{},
		EmitMsg: func(ev layers.MessageEvent) error { events = append(events, ev); return nil },
	}
	ctx := context.Background()
	g := &TNSGenerator{}
	if err := g.Generate(ctx, req); err != nil {
		t.Fatalf("Generate(nil config) err=%v want nil", err)
	}
	if len(events) != 1 {
		t.Fatalf("events=%d want 1 (default DATA)", len(events))
	}
	if events[0].Bytes[4] != TypeData {
		t.Fatalf("event[0] type=%02x want %02x (DATA)", events[0].Bytes[4], TypeData)
	}
}

func TestPlanTNSNilConfigProducesFlow(t *testing.T) {
	// P0b-2: 空配置（nil）→ 链层 Plan 默认化并产默认流（>0 包）。
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345}
	ch, err := (Planner{}).Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan(nil config) err=%v want nil", err)
	}
	pkts := collectPackets(ch, 20)
	if len(pkts) == 0 {
		t.Fatal("Plan(nil config) produced 0 packets, want default flow")
	}
}

func TestTNSGeneratorGenerateNilReq(t *testing.T) {
	g := &TNSGenerator{}
	err := g.Generate(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "EmitMsg is nil") {
		t.Fatalf("err=%v want EmitMsg is nil", err)
	}
}

func TestTNSGeneratorGenerateNilEmitMsg(t *testing.T) {
	req := &layers.GenRequest{Meta: layers.FlowMeta{}}
	g := &TNSGenerator{}
	err := g.Generate(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "EmitMsg is nil") {
		t.Fatalf("err=%v want EmitMsg is nil", err)
	}
}

func TestTNSGeneratorGenerateEmptyEvents(t *testing.T) {
	cfg := &core.TNSConfig{}
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{TNS: cfg},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	g := &TNSGenerator{}
	err := g.Generate(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "at least one event") {
		t.Fatalf("err=%v want at least one event", err)
	}
}

func TestTNSGeneratorGenerateContextCancel(t *testing.T) {
	cfg := &core.TNSConfig{
		Events: []core.TNSEvent{
			{Type: "CONNECT", Direction: "c2s"},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := &layers.GenRequest{
		Meta:    layers.FlowMeta{TNS: cfg},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	g := &TNSGenerator{}
	err := g.Generate(ctx, req)
	if err == nil {
		t.Fatalf("expected context error")
	}
}

func TestTNSRegister(t *testing.T) {
	gen, err := layers.NewLayerGenerator("tns")
	if err != nil {
		t.Fatalf("NewLayerGenerator(tns): %v", err)
	}
	if gen == nil {
		t.Fatalf("generator is nil")
	}
	if gen.Name() != "tns" {
		t.Fatalf("name=%q want tns", gen.Name())
	}
}

// TestEvUp verifies direction resolution
func TestEvUp(t *testing.T) {
	tests := []struct {
		dir  string
		want bool
	}{
		{"", true},
		{"up", true},
		{"c2s", true},
		{"down", false},
		{"s2c", false},
		{"bogus", false},
	}
	for _, tc := range tests {
		ev := core.TNSEvent{Direction: tc.dir}
		got := evUp(ev)
		if got != tc.want {
			t.Fatalf("evUp(%q)=%v want %v", tc.dir, got, tc.want)
		}
	}
}

// TestPlanS1WireFormat verifies the exact wire bytes for S1 packets
// as specified in the cases JSON frame assertions.
func TestPlanS1WireFormat(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 1521,
		Count:   1,
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{
				{Type: "CONNECT", Direction: "c2s", PayloadProfile: "connect_basic"},
				{Type: "ACCEPT", Direction: "s2c", PayloadProfile: "accept_basic"},
				{Type: "DATA", Direction: "c2s", PayloadProfile: "ttc_connect", DataFlags: 0},
				{Type: "DATA", Direction: "s2c", PayloadProfile: "ttc_accept", DataFlags: 0},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	pkts := collectPackets(ch, 20)
	if len(pkts) != 11 {
		t.Fatalf("packet_count=%d want 11", len(pkts))
	}
	// Compute frame offsets. For IPv4, no TCP options:
	// eth(14) + ip(20) + tcp(20) = 54
	base := 54
	// Simulate frames: eth + ip + tcp + payload
	// We just need to verify the payload portion at the right offset.
	makeFrame := func(payload []byte) []byte {
		frame := make([]byte, base+len(payload))
		copy(frame[base:], payload)
		return frame
	}

	// pkt[4] = CONNECT (index 3 in 0-based), but pcap packet numbering starts from 0
	// In the JSON, "packet": 4 means the 5th packet (0-indexed 4).
	// pkt[3] = CONNECT, pkt[4] = ACCEPT, pkt[5] = DATA(c2s), pkt[6] = DATA(s2c)

	// CONNECT: frame offset 58 = base(54) + 4(type)
	frame := makeFrame(pkts[3].Payload)
	if frame[58] != TypeConnect {
		t.Fatalf("CONNECT frame[58]=%02x want %02x", frame[58], TypeConnect)
	}

	// ACCEPT: frame offset 58 = base(54) + 4(type)
	frame = makeFrame(pkts[4].Payload)
	if frame[58] != TypeAccept {
		t.Fatalf("ACCEPT frame[58]=%02x want %02x", frame[58], TypeAccept)
	}

	// DATA(c2s): frame offset 58 = type=06, offset 62 = data_flags
	frame = makeFrame(pkts[5].Payload)
	if frame[58] != TypeData {
		t.Fatalf("DATA(c2s) frame[58]=%02x want %02x", frame[58], TypeData)
	}
	if frame[62] != 0x00 || frame[63] != 0x00 {
		t.Fatalf("DATA(c2s) frame[62:64]=%02x%02x want 0000", frame[62], frame[63])
	}

	// DATA(s2c): frame offset 59 = reserved=00
	frame = makeFrame(pkts[6].Payload)
	if frame[59] != 0x00 {
		t.Fatalf("DATA(s2c) frame[59]=%02x want 00", frame[59])
	}
}

// TestPlanS5IPv6WireFormat verifies IPv6 frame offsets
func TestPlanS5IPv6WireFormat(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "2001:db8::1",
		DstIP:   "2001:db8::2",
		SrcPort: 12345,
		DstPort: 1521,
		Count:   1,
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{
				{Type: "CONNECT", Direction: "c2s", PayloadProfile: "connect_basic"},
				{Type: "ACCEPT", Direction: "s2c", PayloadProfile: "accept_basic"},
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	pkts := collectPackets(ch, 20)
	if len(pkts) != 9 {
		t.Fatalf("packet_count=%d want 9", len(pkts))
	}
	// IPv6 frame offset: eth(14) + ipv6(40) + tcp(20) = 74
	base := 74

	// CONNECT: frame offset 78 = base(74) + 4(type)
	makeFrame := func(payload []byte) []byte {
		frame := make([]byte, base+len(payload))
		copy(frame[base:], payload)
		return frame
	}
	frame := makeFrame(pkts[3].Payload)
	if frame[78] != TypeConnect {
		t.Fatalf("CONNECT IPv6 frame[78]=%02x want %02x", frame[78], TypeConnect)
	}
	// ACCEPT: frame offset 78 = type
	frame = makeFrame(pkts[4].Payload)
	if frame[78] != TypeAccept {
		t.Fatalf("ACCEPT IPv6 frame[78]=%02x want %02x", frame[78], TypeAccept)
	}
}

// TestPlanS7HeaderFrameOffsets verifies the exact frame offsets for S7
func TestPlanS7HeaderFrameOffsets(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 1521,
		Count:   1,
		TNS: &core.TNSConfig{
			Events: []core.TNSEvent{
				{Type: "CONNECT", Direction: "c2s", PayloadProfile: "connect_basic"},
				{Type: "ACCEPT", Direction: "s2c", PayloadProfile: "accept_basic"},
				{Type: "DATA", Direction: "c2s", PayloadProfile: "ttc_connect", DataFlags: 0},
				{Type: "DATA", Direction: "s2c", PayloadProfile: "ttc_accept", DataFlags: 0},
			},
			ChecksumMode: "disabled",
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch, err := (Planner{}).Plan(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	pkts := collectPackets(ch, 20)
	if len(pkts) != 11 {
		t.Fatalf("packet_count=%d want 11", len(pkts))
	}
	base := 54
	makeFrame := func(payload []byte) []byte {
		frame := make([]byte, base+len(payload))
		copy(frame[base:], payload)
		return frame
	}
	// CONNECT (pkt[3]): frame[56]=packet_checksum(2), frame[58]=type, frame[59]=reserved, frame[60]=header_checksum(2)
	frame := makeFrame(pkts[3].Payload)
	if frame[56] != 0x00 || frame[57] != 0x00 {
		t.Fatalf("CONNECT frame[56:58]=%02x%02x want 0000 (packet_checksum)", frame[56], frame[57])
	}
	if frame[58] != TypeConnect {
		t.Fatalf("CONNECT frame[58]=%02x want 01 (type)", frame[58])
	}
	if frame[59] != 0x00 {
		t.Fatalf("CONNECT frame[59]=%02x want 00 (reserved)", frame[59])
	}
	if frame[60] != 0x00 || frame[61] != 0x00 {
		t.Fatalf("CONNECT frame[60:62]=%02x%02x want 0000 (header_checksum)", frame[60], frame[61])
	}
	// DATA(c2s) (pkt[5]): frame[62]=data_flags(2)
	frame = makeFrame(pkts[5].Payload)
	if frame[62] != 0x00 || frame[63] != 0x00 {
		t.Fatalf("DATA(c2s) frame[62:64]=%02x%02x want 0000 (data_flags)", frame[62], frame[63])
	}
}
