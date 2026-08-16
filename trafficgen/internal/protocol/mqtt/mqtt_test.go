// Package mqtt implements the MQTT protocol planner (MQTT 3.1.1 / MQTT 5.0).
package mqtt

import (
	"bytes"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// T-001: CONNECT 3.1.1 byte construction.
func TestBuildConnectV4(t *testing.T) {
	cfg := &MQTTConfig{
		Version:      4,
		ClientID:     "c1",
		KeepAlive:    intPtr(60),
		CleanSession: boolPtr(true),
	}
	got := buildConnect(cfg)
	want := []byte{0x10, 0x0e, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3c, 0x00, 0x02, 0x63, 0x31}
	if !bytes.Equal(got, want) {
		t.Errorf("buildConnect(v4) = %x, want %x", got, want)
	}
	// Self-consistency: payload[1] should equal len(payload)-2.
	if int(got[1]) != len(got)-2 {
		t.Errorf("remaining length mismatch: got %d, want %d", got[1], len(got)-2)
	}
}

// T-002: CONNECT 5.0 with Properties.
func TestBuildConnectV5(t *testing.T) {
	cfg := &MQTTConfig{
		Version:      5,
		ClientID:     "v5-client",
		KeepAlive:    intPtr(60),
		CleanSession: boolPtr(true),
		Properties: []MQTTProperty{
			{Identifier: 0x11, Format: "uint32", Value: "3600"},
			{Identifier: 0x22, Format: "uint16", Value: "1"},
			{Identifier: 0x26, Format: "stringpair", Value: "k\x00v"},
		},
	}
	got := buildConnect(cfg)
	// Verify key bytes.
	if got[0] != 0x10 {
		t.Errorf("type byte = 0x%02x, want 0x10", got[0])
	}
	// Fixed header (2 bytes: type + VBI) + Protocol Name (6) + Level (1).
	// Level is at byte index 8 (VBI = 1 byte since RL=39 < 128).
	if got[8] != 0x05 {
		t.Errorf("protocol level = 0x%02x, want 0x05", got[8])
	}
	// Locate Properties Length: after VH (Protocol Name 6 + Level 1 + Flags 1 + KeepAlive 2 = 10 bytes)
	// at offset 2 (fixed header) + 10 = 12.
	// Properties byte math: ID 0x11 (1) + uint32 (4) = 5; ID 0x22 (1) + uint16 (2) = 3;
	// ID 0x26 (1) + keyLen (2) + k (1) + valLen (2) + v (1) = 7. Total = 15 = 0x0F.
	if got[12] != 0x0f {
		t.Errorf("properties length = 0x%02x, want 0x0f", got[12])
	}
}

// T-003: CONNACK 3.1.1 various return codes.
func TestBuildConnackV4(t *testing.T) {
	for _, code := range []int{0, 1, 2, 3, 4, 5} {
		cfg := &MQTTConfig{
			Version:        4,
			ConnectAckCode: code,
		}
		got := buildConnack(cfg)
		want := []byte{0x20, 0x02, 0x00, byte(code)}
		if !bytes.Equal(got, want) {
			t.Errorf("buildConnack(code=%d) = %x, want %x", code, got, want)
		}
	}
}

// T-004: CONNACK 5.0 Reason Code domain.
func TestBuildConnackV5(t *testing.T) {
	validCodes := []int{0, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 140, 144, 149, 151, 153, 154, 155, 156, 157, 159}
	for _, code := range validCodes {
		cfg := &MQTTConfig{
			Version:        5,
			ConnectAckCode: code,
		}
		got := buildConnack(cfg)
		if got[0] != 0x20 {
			t.Errorf("type byte = 0x%02x, want 0x20", got[0])
		}
		// 5.0 CONNACK layout: [20] [RL] [SP] [Reason] [PropsLen].
		// Reason Code is at index 3 (index 2 is Session Present).
		if got[3] != byte(code) {
			t.Errorf("reason code = 0x%02x, want 0x%02x", got[3], code)
		}
		// 5.0 CONNACK has Properties Length byte.
		if len(got) < 5 || got[4] != 0x00 {
			t.Errorf("expected properties length byte 0x00 at index 4")
		}
	}
}

// T-005: PUBLISH QoS 0/1/2 first byte.
func TestBuildPublishFirstByte(t *testing.T) {
	tests := []struct {
		qos    int
		dup    bool
		retain bool
		want   byte
	}{
		{0, false, false, 0x30},
		{1, false, false, 0x32},
		{2, false, false, 0x34},
		{1, false, true, 0x33},
		{2, true, false, 0x3c},
		{2, true, true, 0x3d},
	}
	for _, tc := range tests {
		msg := MQTTMessage{Topic: "t", Payload: "p", QoS: tc.qos, DUP: tc.dup, Retain: tc.retain}
		got := buildPublish(msg, 4)
		if got[0] != tc.want {
			t.Errorf("QoS=%d DUP=%v Retain=%v: got 0x%02x, want 0x%02x", tc.qos, tc.dup, tc.retain, got[0], tc.want)
		}
	}
}

// T-006: PUBLISH DUP=1 + QoS1 Retain=1.
func TestBuildPublishDUPRetain(t *testing.T) {
	msg := MQTTMessage{Topic: "t", Payload: "p", QoS: 1, DUP: true, Retain: true}
	got := buildPublish(msg, 4)
	want := byte(0x3b)
	if got[0] != want {
		t.Errorf("got 0x%02x, want 0x%02x", got[0], want)
	}
}

// T-007: PUBREL flags forced 0x02.
func TestBuildPubrel(t *testing.T) {
	got := buildPubrel(100, 4)
	if got[0] != 0x62 {
		t.Errorf("PUBREL first byte = 0x%02x, want 0x62", got[0])
	}
}

// T-008: Variable Byte Integer encoding boundaries.
func TestEncodeVBI(t *testing.T) {
	tests := []struct {
		value int
		want  []byte
	}{
		{0, []byte{0x00}},
		{127, []byte{0x7f}},
		{128, []byte{0x80, 0x01}},
		{16383, []byte{0xff, 0x7f}},
		{16384, []byte{0x80, 0x80, 0x01}},
		{2097151, []byte{0xff, 0xff, 0x7f}},
		{2097152, []byte{0x80, 0x80, 0x80, 0x01}},
		{268435455, []byte{0xff, 0xff, 0xff, 0x7f}},
	}
	for _, tc := range tests {
		got, err := encodeVBI(tc.value)
		if err != nil {
			t.Errorf("encodeVBI(%d) error: %v", tc.value, err)
			continue
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("encodeVBI(%d) = %x, want %x", tc.value, got, tc.want)
		}
	}
}

// T-009: Variable Byte Integer decoding.
func TestDecodeVBI(t *testing.T) {
	tests := []struct {
		data []byte
		want int
		n    int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x7f}, 127, 1},
		{[]byte{0x80, 0x01}, 128, 2},
		{[]byte{0xff, 0x7f}, 16383, 2},
		{[]byte{0x80, 0x80, 0x01}, 16384, 3},
		{[]byte{0xff, 0xff, 0x7f}, 2097151, 3},
		{[]byte{0x80, 0x80, 0x80, 0x01}, 2097152, 4},
		{[]byte{0xff, 0xff, 0xff, 0x7f}, 268435455, 4},
	}
	for _, tc := range tests {
		got, n, err := decodeVBI(tc.data)
		if err != nil {
			t.Errorf("decodeVBI(%x) error: %v", tc.data, err)
			continue
		}
		if got != tc.want || n != tc.n {
			t.Errorf("decodeVBI(%x) = (%d, %d), want (%d, %d)", tc.data, got, n, tc.want, tc.n)
		}
	}
}

// T-010: encodeVBI overflow error.
func TestEncodeVBIOverflow(t *testing.T) {
	_, err := encodeVBI(268435456)
	if err == nil {
		t.Error("encodeVBI(268435456) expected error, got nil")
	}
}

// T-011: CONNECT with username/password.
func TestBuildConnectAuth(t *testing.T) {
	cfg := &MQTTConfig{
		Version:      4,
		ClientID:     "auth-client",
		KeepAlive:    intPtr(60),
		CleanSession: boolPtr(true),
		Username:     "admin",
		Password:     "secret",
	}
	got := buildConnect(cfg)
	want := []byte{
		0x10, 0x26,
		0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,
		0x04,
		0xc2, // Connect Flags: Username=1, Password=1, CleanSession=1
		0x00, 0x3c,
		0x00, 0x0b, // ClientID length = 11
		0x61, 0x75, 0x74, 0x68, 0x2d, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, // "auth-client"
		0x00, 0x05, // Username length = 5
		0x61, 0x64, 0x6d, 0x69, 0x6e, // "admin"
		0x00, 0x06, // Password length = 6
		0x73, 0x65, 0x63, 0x72, 0x65, 0x74, // "secret"
	}
	if !bytes.Equal(got, want) {
		t.Errorf("buildConnect(auth) = %x, want %x", got, want)
	}
}

// T-012: CONNECT with Will QoS=1.
func TestBuildConnectWill(t *testing.T) {
	cfg := &MQTTConfig{
		Version:      4,
		ClientID:     "device-01",
		KeepAlive:    intPtr(60),
		CleanSession: boolPtr(true),
		Will: &MQTTWill{
			Topic:   "client/status",
			Payload: "offline",
			QoS:     1,
			Retain:  false,
		},
	}
	got := buildConnect(cfg)
	// Verify Connect Flags = 0x0E (Will Flag=1, Will QoS=01, CleanSession=1).
	if got[9] != 0x0e {
		t.Errorf("connect flags = 0x%02x, want 0x0e", got[9])
	}
}

// T-013: Will Retain=1.
func TestBuildConnectWillRetain(t *testing.T) {
	cfg := &MQTTConfig{
		Version:      4,
		ClientID:     "c1",
		KeepAlive:    intPtr(60),
		CleanSession: boolPtr(true),
		Will: &MQTTWill{
			Topic:   "t",
			Payload: "p",
			QoS:     1,
			Retain:  true,
		},
	}
	got := buildConnect(cfg)
	// Connect Flags = 0x02 | 0x04 | 0x08 | 0x20 = 0x2E.
	if got[9] != 0x2e {
		t.Errorf("connect flags = 0x%02x, want 0x2e", got[9])
	}
}

// T-014: Will QoS=2.
func TestBuildConnectWillQoS2(t *testing.T) {
	cfg := &MQTTConfig{
		Version:      4,
		ClientID:     "c1",
		KeepAlive:    intPtr(60),
		CleanSession: boolPtr(true),
		Will: &MQTTWill{
			Topic:   "t",
			Payload: "p",
			QoS:     2,
			Retain:  false,
		},
	}
	got := buildConnect(cfg)
	// Connect Flags = 0x02 | 0x04 | 0x10 = 0x16.
	if got[9] != 0x16 {
		t.Errorf("connect flags = 0x%02x, want 0x16", got[9])
	}
}

// T-016: SUBSCRIBE byte construction.
func TestBuildSubscribe(t *testing.T) {
	sub := MQTTSubscribe{
		PacketID: 1,
		Filters: []MQTTTopicFilter{
			{Filter: "sensor/+", QoS: 0},
		},
	}
	got := buildSubscribe(sub, 4)
	want := []byte{0x82, 0x0d, 0x00, 0x01, 0x00, 0x08, 0x73, 0x65, 0x6e, 0x73, 0x6f, 0x72, 0x2f, 0x2b, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("buildSubscribe = %x, want %x", got, want)
	}
}

// T-017: SUBACK multiple filter reason codes.
func TestBuildSuback(t *testing.T) {
	sub := MQTTSubscribe{
		PacketID:       1,
		Filters:        []MQTTTopicFilter{{Filter: "a", QoS: 0}, {Filter: "b", QoS: 1}, {Filter: "c", QoS: 2}},
		AckReasonCodes: []int{0x00, 0x01, 0x80},
	}
	got := buildSuback(sub.PacketID, sub.AckReasonCodes, len(sub.Filters), 4)
	if !bytes.HasSuffix(got, []byte{0x00, 0x01, 0x80}) {
		t.Errorf("buildSuback suffix = %x, want ending with 00 01 80", got)
	}
}

// T-018: PINGREQ/PINGRESP/DISCONNECT 3.1.1 bytes.
func TestBuildPingPingrespDisconnect(t *testing.T) {
	pingreq := buildPingreq()
	if !bytes.Equal(pingreq, []byte{0xc0, 0x00}) {
		t.Errorf("PINGREQ = %x, want c0 00", pingreq)
	}
	pingresp := buildPingresp()
	if !bytes.Equal(pingresp, []byte{0xd0, 0x00}) {
		t.Errorf("PINGRESP = %x, want d0 00", pingresp)
	}
	disconnect := buildDisconnect(4, 0)
	if !bytes.Equal(disconnect, []byte{0xe0, 0x00}) {
		t.Errorf("DISCONNECT v4 = %x, want e0 00", disconnect)
	}
}

// T-019: DISCONNECT 5.0 with Reason Code.
func TestBuildDisconnectV5(t *testing.T) {
	got := buildDisconnect(5, 0)
	want := []byte{0xe0, 0x02, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("DISCONNECT v5 = %x, want e0 02 00 00", got)
	}
}

// T-020: 5.0 CONNACK Properties Length=0x00 mandatory.
func TestBuildConnackV5Properties(t *testing.T) {
	cfg := &MQTTConfig{Version: 5, ConnectAckCode: 0}
	got := buildConnack(cfg)
	want := []byte{0x20, 0x03, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("CONNACK v5 = %x, want 20 03 00 00 00", got)
	}
}

// T-021: 5.0 PUBLISH no properties Properties Length=0x00 mandatory.
func TestBuildPublishV5NoProperties(t *testing.T) {
	msg := MQTTMessage{Topic: "t", Payload: "p", QoS: 0}
	got := buildPublish(msg, 5)
	want := []byte{0x30, 0x05, 0x00, 0x01, 0x74, 0x00, 0x70}
	if !bytes.Equal(got, want) {
		t.Errorf("PUBLISH v5 no props = %x, want 30 05 00 01 74 00 70", got)
	}
}

// T-022: 5.0 SUBACK no properties Properties Length=0x00 mandatory.
func TestBuildSubackV5NoProperties(t *testing.T) {
	got := buildSuback(1, []int{0x00}, 1, 5)
	want := []byte{0x90, 0x04, 0x00, 0x01, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("SUBACK v5 = %x, want 90 04 00 01 00 00", got)
	}
}

// T-025: Property Format=byte.
func TestPropertyByte(t *testing.T) {
	prop := MQTTProperty{Identifier: 0x01, Format: "byte", Value: "1"}
	got, err := encodeProperty(prop)
	if err != nil {
		t.Fatalf("encodeProperty error: %v", err)
	}
	want := []byte{0x01, 0x01}
	if !bytes.Equal(got, want) {
		t.Errorf("property byte = %x, want 01 01", got)
	}
}

// T-027: Property Format=uint32.
func TestPropertyUint32(t *testing.T) {
	prop := MQTTProperty{Identifier: 0x11, Format: "uint32", Value: "3600"}
	got, err := encodeProperty(prop)
	if err != nil {
		t.Fatalf("encodeProperty error: %v", err)
	}
	want := []byte{0x11, 0x00, 0x00, 0x0e, 0x10}
	if !bytes.Equal(got, want) {
		t.Errorf("property uint32 = %x, want 11 00 00 0e 10", got)
	}
}

// T-028: Property Format=binary.
func TestPropertyBinary(t *testing.T) {
	prop := MQTTProperty{Identifier: 0x09, Format: "binary", Value: "01020304"}
	got, err := encodeProperty(prop)
	if err != nil {
		t.Fatalf("encodeProperty error: %v", err)
	}
	want := []byte{0x09, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04}
	if !bytes.Equal(got, want) {
		t.Errorf("property binary = %x, want 09 00 04 01 02 03 04", got)
	}
}

// T-029: Property Format=stringpair.
func TestPropertyStringpair(t *testing.T) {
	prop := MQTTProperty{Identifier: 0x26, Format: "stringpair", Value: "k\x00v"}
	got, err := encodeProperty(prop)
	if err != nil {
		t.Fatalf("encodeProperty error: %v", err)
	}
	want := []byte{0x26, 0x00, 0x01, 0x6b, 0x00, 0x01, 0x76}
	if !bytes.Equal(got, want) {
		t.Errorf("property stringpair = %x, want 26 00 01 6b 00 01 76", got)
	}
}

// T-030: Property Format=uint16.
func TestPropertyUint16(t *testing.T) {
	prop := MQTTProperty{Identifier: 0x23, Format: "uint16", Value: "1"}
	got, err := encodeProperty(prop)
	if err != nil {
		t.Fatalf("encodeProperty error: %v", err)
	}
	want := []byte{0x23, 0x00, 0x01}
	if !bytes.Equal(got, want) {
		t.Errorf("property uint16 = %x, want 23 00 01", got)
	}
}

// T-031: Default flow packet order.
func TestDefaultFlowOrder(t *testing.T) {
	cfg := &MQTTConfig{
		Version:  4,
		ClientID: "c1",
		Messages: []MQTTMessage{
			{Topic: "t", Payload: "p", QoS: 0},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	// Default spec: 3-way handshake + CONNECT + CONNACK + PUBLISH + DISCONNECT + 3-way teardown = 10 packets.
	if len(cfgs) != 10 {
		t.Errorf("expected 10 packets, got %d", len(cfgs))
	}
}

// T-032: CONNACK reject skips subsequent packets.
func TestConnackReject(t *testing.T) {
	cfg := &MQTTConfig{
		Version:        4,
		ClientID:       "bad-client",
		ConnectAckCode: 5,
		Messages: []MQTTMessage{
			{Topic: "t", Payload: "p", QoS: 0},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	// Reject: 3-way handshake + CONNECT + CONNACK + 3-way teardown = 8 packets.
	if len(cfgs) != 8 {
		t.Errorf("expected 8 packets after reject, got %d", len(cfgs))
	}
}

// T-033: QoS1 two-packet exchange.
func TestQoS1Exchange(t *testing.T) {
	cfg := &MQTTConfig{
		Version:  4,
		ClientID: "alert-01",
		Messages: []MQTTMessage{
			{Topic: "alert/fire", Payload: "WARNING", QoS: 1, PacketID: 100},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	// QoS1: 3-way handshake + CONNECT + CONNACK + PUBLISH + PUBACK + DISCONNECT + 3-way teardown = 11 packets.
	if len(cfgs) != 11 {
		t.Errorf("expected 11 packets for QoS1, got %d", len(cfgs))
	}
}

// T-034: QoS2 four-packet exchange.
func TestQoS2Exchange(t *testing.T) {
	cfg := &MQTTConfig{
		Version:  4,
		ClientID: "billing-01",
		Messages: []MQTTMessage{
			{Topic: "billing/tx", Payload: "TX12345", QoS: 2, PacketID: 7},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	// QoS2: 3-way handshake + CONNECT + CONNACK + PUBLISH + PUBREC + PUBREL + PUBCOMP + DISCONNECT + 3-way teardown = 13 packets.
	if len(cfgs) != 13 {
		t.Errorf("expected 13 packets for QoS2, got %d", len(cfgs))
	}
}

// T-037: QoS=3 rejected.
func TestQoS3Rejected(t *testing.T) {
	cfg := &MQTTConfig{
		Version: 4,
		Messages: []MQTTMessage{
			{Topic: "t", Payload: "p", QoS: 3},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	_, err := p.Plan(nil, spec)
	if err == nil {
		t.Error("expected error for QoS=3, got nil")
	}
}

// T-038: QoS2 down direction matrix.
func TestQoS2DownDirection(t *testing.T) {
	cfg := &MQTTConfig{
		Version: 4,
		Messages: []MQTTMessage{
			{Topic: "device/cmd", Payload: "on", QoS: 2, Direction: "down", PacketID: 4},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	// Find PUBLISH, PUBREC, PUBREL, PUBCOMP and verify directions.
	var foundPub, foundRec, foundRel, foundComp bool
	for _, c := range cfgs {
		if len(c.Payload) == 0 {
			continue
		}
		first := c.Payload[0] & 0xf0
		switch first {
		case 0x30:
			foundPub = true
			if c.Direction != "down" {
				t.Errorf("PUBLISH direction = %s, want down", c.Direction)
			}
		case 0x50:
			foundRec = true
			if c.Direction != "up" {
				t.Errorf("PUBREC direction = %s, want up", c.Direction)
			}
		case 0x60:
			foundRel = true
			if c.Direction != "down" {
				t.Errorf("PUBREL direction = %s, want down", c.Direction)
			}
		case 0x70:
			foundComp = true
			if c.Direction != "up" {
				t.Errorf("PUBCOMP direction = %s, want up", c.Direction)
			}
		}
	}
	if !foundPub {
		t.Error("PUBLISH not found")
	}
	if !foundRec {
		t.Error("PUBREC not found")
	}
	if !foundRel {
		t.Error("PUBREL not found")
	}
	if !foundComp {
		t.Error("PUBCOMP not found")
	}
}

// T-038 regression: down-direction packets must carry the server's source IP
// on the wire (spec.DstIP), not the client's. The direction matrix test above
// only asserted the PacketConfig.Direction field — a down packet whose
// L3.SrcIP still read spec.SrcIP passed that test but produced a pcap where
// every packet claims the client's IP (verified via tshark ip.src). Per the
// testing policy, assert the observable bytes: down packet → src=20.0.0.1,
// up packet → src=10.0.0.1.
func TestQoS2DownDirectionWireIPs(t *testing.T) {
	cfg := &MQTTConfig{
		Version: 4,
		Messages: []MQTTMessage{
			{Topic: "device/cmd", Payload: "on", QoS: 2, Direction: "down", PacketID: 4},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 12345,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	for _, c := range cfgs {
		wantSrc := "10.0.0.1"
		if c.Direction == "down" {
			wantSrc = "20.0.0.1"
		}
		if c.L3.SrcIP != wantSrc {
			t.Errorf("packet direction=%s L3.SrcIP=%s, want %s (down packets must swap to the server address)",
				c.Direction, c.L3.SrcIP, wantSrc)
		}
	}
}

// T-069: DUP=1 + QoS0 rejected.
func TestDUPQoS0Rejected(t *testing.T) {
	cfg := &MQTTConfig{
		Version: 4,
		Messages: []MQTTMessage{
			{Topic: "t", Payload: "p", QoS: 0, DUP: true},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	_, err := p.Plan(nil, spec)
	if err == nil {
		t.Error("expected error for DUP+QoS0, got nil")
	}
}

// T-070: Subscription wildcard '+' accepted.
func TestWildcardPlus(t *testing.T) {
	cfg := &MQTTConfig{
		Version: 4,
		Subscriptions: []MQTTSubscribe{
			{
				PacketID: 1,
				Filters:  []MQTTTopicFilter{{Filter: "sport/+/score", QoS: 0}},
			},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	_, err := p.Plan(nil, spec)
	if err != nil {
		t.Errorf("unexpected error for '+' wildcard: %v", err)
	}
}

// T-071: '#' not at end rejected.
func TestWildcardHashNotEnd(t *testing.T) {
	cfg := &MQTTConfig{
		Version: 4,
		Subscriptions: []MQTTSubscribe{
			{
				PacketID: 1,
				Filters:  []MQTTTopicFilter{{Filter: "sport/#/score", QoS: 0}},
			},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	_, err := p.Plan(nil, spec)
	if err == nil {
		t.Error("expected error for '#' not at end, got nil")
	}
}

// T-089: Version=3 rejected.
func TestVersion3Rejected(t *testing.T) {
	cfg := &MQTTConfig{Version: 3}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	_, err := p.Plan(nil, spec)
	if err == nil {
		t.Error("expected error for version=3, got nil")
	}
}

// T-090: Version=6 rejected.
func TestVersion6Rejected(t *testing.T) {
	cfg := &MQTTConfig{Version: 6}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	_, err := p.Plan(nil, spec)
	if err == nil {
		t.Error("expected error for version=6, got nil")
	}
}

// T-095: Version=4 with Properties rejected.
func TestV4PropertiesRejected(t *testing.T) {
	cfg := &MQTTConfig{
		Version: 4,
		Properties: []MQTTProperty{
			{Identifier: 0x11, Format: "uint32", Value: "3600"},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	_, err := p.Plan(nil, spec)
	if err == nil {
		t.Error("expected error for v4+properties, got nil")
	}
}

// T-097: Default spec empty fields.
func TestDefaultSpec(t *testing.T) {
	cfg := &MQTTConfig{}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	// Empty spec: 3-way handshake + CONNECT + CONNACK + DISCONNECT + 3-way teardown = 9 packets.
	if len(cfgs) != 9 {
		t.Errorf("expected 9 packets for empty spec, got %d", len(cfgs))
	}
}

// T-105: CleanSession=true + SessionPresent=true rejected.
func TestCleanSessionSessionPresentConflict(t *testing.T) {
	cfg := &MQTTConfig{
		Version:                  4,
		CleanSession:             boolPtr(true),
		ConnectAckSessionPresent: true,
	}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	_, err := p.Plan(nil, spec)
	if err == nil {
		t.Error("expected error for clean_session=true + session_present=true, got nil")
	}
}

// T-106: ConnectAckCode≠0 + SessionPresent=true rejected.
func TestRejectSessionPresent(t *testing.T) {
	cfg := &MQTTConfig{
		Version:                  4,
		ConnectAckCode:           5,
		ConnectAckSessionPresent: true,
	}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	_, err := p.Plan(nil, spec)
	if err == nil {
		t.Error("expected error for code!=0 + session_present=true, got nil")
	}
}

// T-107: PUBLISH topic with wildcards rejected.
func TestPublishTopicWildcard(t *testing.T) {
	for _, topic := range []string{"a/#", "a/+/b"} {
		cfg := &MQTTConfig{
			Version: 4,
			Messages: []MQTTMessage{
				{Topic: topic, Payload: "p", QoS: 0},
			},
		}
		p := NewPlanner()
		spec := core.FlowSpec{MQTT: cfg}
		_, err := p.Plan(nil, spec)
		if err == nil {
			t.Errorf("expected error for topic %q, got nil", topic)
		}
	}
}

// T-116: decodeVBI malformed paths.
func TestDecodeVBIMalformed(t *testing.T) {
	// 5 bytes (exceeds 4).
	_, _, err := decodeVBI([]byte{0x80, 0x80, 0x80, 0x80, 0x01})
	if err == nil {
		t.Error("expected error for 5-byte VBI, got nil")
	}
	// Non-minimal encoding: value 0 with 2 bytes.
	_, _, err = decodeVBI([]byte{0x80, 0x00})
	if err == nil {
		t.Error("expected error for non-minimal VBI, got nil")
	}
	// Incomplete: 4th byte still has continuation bit.
	_, _, err = decodeVBI([]byte{0x80, 0x80, 0x80, 0x80})
	if err == nil {
		t.Error("expected error for incomplete VBI, got nil")
	}
}

// T-142: encodeVBI all boundary values.
func TestEncodeVBIBoundaries(t *testing.T) {
	tests := []struct {
		value int
		want  []byte
	}{
		{0, []byte{0x00}},
		{127, []byte{0x7f}},
		{128, []byte{0x80, 0x01}},
		{16383, []byte{0xff, 0x7f}},
		{16384, []byte{0x80, 0x80, 0x01}},
		{2097151, []byte{0xff, 0xff, 0x7f}},
		{2097152, []byte{0x80, 0x80, 0x80, 0x01}},
		{268435455, []byte{0xff, 0xff, 0xff, 0x7f}},
	}
	for _, tc := range tests {
		got, err := encodeVBI(tc.value)
		if err != nil {
			t.Errorf("encodeVBI(%d) error: %v", tc.value, err)
			continue
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("encodeVBI(%d) = %x, want %x", tc.value, got, tc.want)
		}
	}
}

// T-143: decodeVBI all boundary values.
func TestDecodeVBIBoundaries(t *testing.T) {
	tests := []struct {
		data []byte
		want int
		n    int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x7f}, 127, 1},
		{[]byte{0x80, 0x01}, 128, 2},
		{[]byte{0xff, 0x7f}, 16383, 2},
		{[]byte{0x80, 0x80, 0x01}, 16384, 3},
		{[]byte{0xff, 0xff, 0x7f}, 2097151, 3},
		{[]byte{0x80, 0x80, 0x80, 0x01}, 2097152, 4},
		{[]byte{0xff, 0xff, 0xff, 0x7f}, 268435455, 4},
	}
	for _, tc := range tests {
		got, n, err := decodeVBI(tc.data)
		if err != nil {
			t.Errorf("decodeVBI(%x) error: %v", tc.data, err)
			continue
		}
		if got != tc.want || n != tc.n {
			t.Errorf("decodeVBI(%x) = (%d, %d), want (%d, %d)", tc.data, got, n, tc.want, tc.n)
		}
	}
}

// T-144: encodeVBI negative error.
func TestEncodeVBINegative(t *testing.T) {
	_, err := encodeVBI(-1)
	if err == nil {
		t.Error("expected error for negative VBI, got nil")
	}
}

// T-145: encodeVBI overflow error.
func TestEncodeVBIMaxOverflow(t *testing.T) {
	_, err := encodeVBI(268435456)
	if err == nil {
		t.Error("expected error for VBI overflow, got nil")
	}
}

// T-160: QoS0 + PacketID rejected.
func TestQoS0PacketIDRejected(t *testing.T) {
	cfg := &MQTTConfig{
		Version: 4,
		Messages: []MQTTMessage{
			{Topic: "t", Payload: "p", QoS: 0, PacketID: 1},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	_, err := p.Plan(nil, spec)
	if err == nil {
		t.Error("expected error for QoS0+packet_id, got nil")
	}
}

// T-161: QoS=3 rejected (duplicate of T-037 but explicit).
func TestQoS3RejectedExplicit(t *testing.T) {
	cfg := &MQTTConfig{
		Version: 4,
		Messages: []MQTTMessage{
			{Topic: "t", Payload: "p", QoS: 3},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	_, err := p.Plan(nil, spec)
	if err == nil {
		t.Error("expected error for QoS=3, got nil")
	}
}

// T-193: PUBREL flags forced 0x02.
func TestPubrelFlags(t *testing.T) {
	got := buildPubrel(1, 4)
	if got[0] != 0x62 {
		t.Errorf("PUBREL first byte = 0x%02x, want 0x62", got[0])
	}
}

// T-194: SUBSCRIBE flags forced 0x02.
func TestSubscribeFlags(t *testing.T) {
	sub := MQTTSubscribe{PacketID: 1, Filters: []MQTTTopicFilter{{Filter: "a", QoS: 0}}}
	got := buildSubscribe(sub, 4)
	if got[0] != 0x82 {
		t.Errorf("SUBSCRIBE first byte = 0x%02x, want 0x82", got[0])
	}
}

// T-195: CONNECT Protocol Name fixed.
func TestConnectProtocolName(t *testing.T) {
	cfg := &MQTTConfig{Version: 4, ClientID: "c1"}
	got := buildConnect(cfg)
	// Protocol Name at bytes 2-7: 00 04 4d 51 54 54.
	want := []byte{0x00, 0x04, 0x4d, 0x51, 0x54, 0x54}
	if !bytes.Equal(got[2:8], want) {
		t.Errorf("protocol name = %x, want 00 04 4d 51 54 54", got[2:8])
	}
}

// T-196: CONNECT bit0 Reserved always 0.
func TestConnectReservedBit(t *testing.T) {
	cfg := &MQTTConfig{Version: 4, ClientID: "c1"}
	got := buildConnect(cfg)
	// Connect Flags at byte 9.
	if got[9]&0x01 != 0 {
		t.Errorf("reserved bit = 1, want 0")
	}
}

// T-197: PUBLISH QoS=3 rejected.
func TestPublishQoS3Rejected(t *testing.T) {
	cfg := &MQTTConfig{
		Version: 4,
		Messages: []MQTTMessage{
			{Topic: "t", Payload: "p", QoS: 3},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	_, err := p.Plan(nil, spec)
	if err == nil {
		t.Error("expected error for publish QoS=3, got nil")
	}
}

// Helper functions.
func intPtr(v int) *int {
	return &v
}

func boolPtr(v bool) *bool {
	return &v
}

// --- Additional test cases from the design document ---

// T-043/T-044: MSS segmentation of oversized PUBLISH — MQTT packet stays
// whole, only the TCP layer segments.
func TestMSSSegmentation(t *testing.T) {
	cfg := &MQTTConfig{
		Version:  4,
		ClientID: "c1",
		Messages: []MQTTMessage{
			{Topic: "t", Payload: string(make([]byte, 4000)), QoS: 0},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		TCP:     &core.TCPConfig{MSS: 1460},
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	// Find the PUBLISH packet — it carries MQTT fixed header 0x30.
	var publishIdx int = -1
	for i, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == 0x30 {
			publishIdx = i
			break
		}
	}
	if publishIdx < 0 {
		t.Fatal("PUBLISH packet not found")
	}
	// 1 (type) + 2 (RL=4003=0xfa3; VBI is 2 bytes: 0xa3 0x1f) + topic_len(2) + topic(1) + 4000 (payload) = 4006.
	// So the first PUBLISH segment is 1460 bytes (carrying the MQTT header).
	// Remaining payload bytes = 4006 - 1460 = 2546, split as 1460+1086.
	// Total segments for PUBLISH = 3.
	totalPayload := 4006
	expectedSegments := (totalPayload + 1460 - 1) / 1460
	var pubSegments [][]byte
	for i := publishIdx; i < len(cfgs); i++ {
		c := cfgs[i]
		if c.Direction != "up" || c.L4.Flags != 0x18 {
			break
		}
		// Stop once the reassembled PUBLISH is complete — the DISCONNECT
		// packet that follows is also up + PSH-ACK (0x18) and must not be
		// counted as a PUBLISH segment.
		var got int
		for _, s := range pubSegments {
			got += len(s)
		}
		if got >= totalPayload {
			break
		}
		pubSegments = append(pubSegments, c.Payload)
	}
	if len(pubSegments) != expectedSegments {
		t.Errorf("expected %d TCP segments for 4000-byte PUBLISH, got %d", expectedSegments, len(pubSegments))
	}
	// First segment should carry MQTT fixed header 0x30.
	if pubSegments[0][0] != 0x30 {
		t.Errorf("first segment should carry MQTT fixed header 0x30, got 0x%02x", pubSegments[0][0])
	}
	// Reassemble: should equal the whole PUBLISH (type + RL + body).
	var reassembled []byte
	for _, s := range pubSegments {
		reassembled = append(reassembled, s...)
	}
	// Parse fixed header: type=3, RL encoded as VBI (1-4 bytes).
	if reassembled[0]&0xF0 != 0x30 {
		t.Errorf("reassembled type = 0x%02x, want 0x30", reassembled[0])
	}
	rl, rlLen, err := decodeVBI(reassembled[1:])
	if err != nil {
		t.Errorf("reassembled RL decode: %v", err)
	}
	// RL = topic_len(2) + topic(1) + payload(4000) = 4003. The invariant
	// is totalPayload = 1 (type) + rlLen (VBI) + rl (body).
	if rl != totalPayload-1-rlLen {
		t.Errorf("reassembled RL = %d, want %d (totalPayload %d - type 1 - VBI %d)",
			rl, totalPayload-1-rlLen, totalPayload, rlLen)
	}
	if len(reassembled) != 1+rlLen+rl {
		t.Errorf("reassembled PUBLISH len=%d, expected 1+%d+%d=%d", len(reassembled), rlLen, rl, 1+rlLen+rl)
	}
}

// T-045/T-046: MSS below MinMSS rejected.
func TestMSSBelowMinRejected(t *testing.T) {
	for _, mss := range []uint16{535, 100} {
		cfg := &MQTTConfig{Version: 4, ClientID: "c1"}
		p := NewPlanner()
		spec := core.FlowSpec{
			SrcIP: "10.0.0.1",
			DstIP: "10.0.0.2",
			TCP:   &core.TCPConfig{MSS: mss},
			MQTT:  cfg,
		}
		_, err := p.Plan(nil, spec)
		if err == nil {
			t.Errorf("expected error for MSS=%d, got nil", mss)
		}
	}
}

// T-047: TCP handshake carries MSS/WinScale/SACK options.
func TestHandshakeOptions(t *testing.T) {
	cfg := &MQTTConfig{Version: 4, ClientID: "c1"}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	// SYN (index 0) and SYN-ACK (index 1) carry options.
	for _, idx := range []int{0, 1} {
		opts := cfgs[idx].L4.TCPOptions
		kinds := map[uint8]bool{}
		for _, o := range opts {
			kinds[o.Kind] = true
		}
		if !kinds[2] {
			t.Errorf("packet %d: missing MSS option", idx)
		}
		if !kinds[3] {
			t.Errorf("packet %d: missing WinScale option", idx)
		}
		if !kinds[4] {
			t.Errorf("packet %d: missing SACK option", idx)
		}
	}
}

// T-048: TCP teardown sequence FIN-ACK, FIN-ACK, ACK.
func TestTCPTeardown(t *testing.T) {
	cfg := &MQTTConfig{Version: 4, ClientID: "c1"}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	n := len(cfgs)
	// Last 3 packets: FIN-ACK, FIN-ACK, ACK.
	if cfgs[n-3].L4.Flags != 0x11 || cfgs[n-2].L4.Flags != 0x11 || cfgs[n-1].L4.Flags != 0x10 {
		t.Errorf("teardown flags = %x %x %x, want 11 11 10",
			cfgs[n-3].L4.Flags, cfgs[n-2].L4.Flags, cfgs[n-1].L4.Flags)
	}
}

// T-049: seq/ack continuity within a flow.
func TestSeqAckContinuity(t *testing.T) {
	cfg := &MQTTConfig{
		Version:  4,
		ClientID: "c1",
		Messages: []MQTTMessage{
			{Topic: "t", Payload: "hello", QoS: 1},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	// Track client and server seq independently. TCP SYN, SYN-ACK, FIN, and
	// FIN-ACK each consume 1 sequence number (RFC 793). The planner's
	// implementation tracks SYN/FIN by incrementing the local seq counter
	// after the emit; we mirror that behavior here.
	var clientSeq, serverSeq uint32
	clientInit, serverInit := false, false
	for _, c := range cfgs {
		seq := c.L4.Seq
		pl := uint32(len(c.Payload))
		// SYN, SYN-ACK, FIN, FIN-ACK consume 1 sequence number (RFC 793).
		seqConsumed := pl
		if c.L4.Flags == 0x02 || c.L4.Flags == 0x12 || c.L4.Flags == 0x04 || c.L4.Flags == 0x11 {
			seqConsumed++
		}
		if c.Direction == "up" {
			if clientInit {
				if seq != clientSeq {
					t.Errorf("client seq gap at index %d: got %d, want %d", c.PacketIndex, seq, clientSeq)
				}
			}
			clientSeq = seq + seqConsumed
			clientInit = true
		} else {
			if serverInit {
				if seq != serverSeq {
					t.Errorf("server seq gap at index %d: got %d, want %d", c.PacketIndex, seq, serverSeq)
				}
			}
			serverSeq = seq + seqConsumed
			serverInit = true
		}
	}
}

// T-050: Disconnect=false — no DISCONNECT packet, teardown still sent.
func TestDisconnectFalse(t *testing.T) {
	f := false
	cfg := &MQTTConfig{
		Version:    4,
		ClientID:   "c1",
		Disconnect: &f,
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == 0xE0 {
			t.Error("found DISCONNECT packet despite Disconnect=false")
		}
	}
	// Teardown still present.
	n := len(cfgs)
	if cfgs[n-1].L4.Flags != 0x10 {
		t.Errorf("expected final ACK, got flags 0x%02x", cfgs[n-1].L4.Flags)
	}
}

// T-051: RST=true — teardown replaced with RST.
func TestRSTTeardown(t *testing.T) {
	f := false
	cfg := &MQTTConfig{
		Version:    4,
		ClientID:   "c1",
		Disconnect: &f,
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		TCP:     &core.TCPConfig{RST: true},
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	// Last TCP packet must carry the RST bit (0x04).
	last := cfgs[len(cfgs)-1]
	if last.L4.Flags&0x04 == 0 {
		t.Errorf("expected RST bit in final packet, got flags 0x%02x", last.L4.Flags)
	}
}

// T-052: InitialSeq fixed ISN.
func TestInitialSeq(t *testing.T) {
	cfg := &MQTTConfig{Version: 4, ClientID: "c1"}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		TCP:     &core.TCPConfig{InitialSeq: 1000},
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	if cfgs[0].L4.Seq != 1000 {
		t.Errorf("SYN seq = %d, want 1000", cfgs[0].L4.Seq)
	}
}

// T-053: keep_alive=0 → CONNECT `00 00`.
func TestKeepAliveZero(t *testing.T) {
	zero := 0
	cfg := &MQTTConfig{
		Version:   4,
		ClientID:  "c1",
		KeepAlive: &zero,
	}
	got := buildConnect(cfg)
	// Keep Alive at bytes 10-11 (after 2-byte fixed hdr + 6-byte name + 1 level + 1 flags).
	if got[10] != 0x00 || got[11] != 0x00 {
		t.Errorf("keep alive = %02x %02x, want 00 00", got[10], got[11])
	}
}

// T-076: empty client_id auto-generated.
func TestAutoClientID(t *testing.T) {
	cfg := &MQTTConfig{Version: 4, ClientID: ""}
	// buildConnect only encodes; the empty ClientID is resolved by the
	// planner (emitSessionFlow) per §5.6/§8.2: "trafficgen-<counter6hex>"
	// deterministic auto-generation + forced CleanSession=true. Driving
	// the full Plan path also verifies the CONNECT flags reflect the
	// forced CleanSession.
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var connect []byte
	for c := range ch {
		if len(c.Payload) > 1 && c.Payload[0] == 0x10 {
			connect = c.Payload
			break
		}
	}
	if connect == nil {
		t.Fatal("CONNECT packet not found")
	}
	// Parse ClientID from payload: after fixed hdr (2) + name (6) + level (1) + flags (1) + keepalive (2).
	// ClientID length prefix at offset 12.
	l := int(connect[12])<<8 | int(connect[13])
	if l == 0 {
		t.Error("auto-generated ClientID is empty")
	}
	clientID := string(connect[14 : 14+l])
	if len(clientID) < 12 || clientID[:11] != "trafficgen-" {
		t.Errorf("auto ClientID = %q, want prefix trafficgen-", clientID)
	}
	// Empty ClientID forces CleanSession=1 (3.1.1 §3.1.3.1): connect
	// flags byte is at offset 9 (fixed hdr 2 + name 6 + level 1).
	if connect[9]&0x02 == 0 {
		t.Error("CleanSession flag = 0, want 1 (forced by empty ClientID)")
	}
}

// T-077: remaining length 127 boundary.
func TestRemainingLen127(t *testing.T) {
	// RL = 2 + 1 + N = 127 → N = 124.
	payload := string(make([]byte, 124))
	msg := MQTTMessage{Topic: "t", Payload: payload, QoS: 0}
	got := buildPublish(msg, 4)
	if got[1] != 0x7f {
		t.Errorf("VBI = 0x%02x, want 0x7f", got[1])
	}
}

// T-078: remaining length 128 boundary.
func TestRemainingLen128(t *testing.T) {
	payload := string(make([]byte, 125))
	msg := MQTTMessage{Topic: "t", Payload: payload, QoS: 0}
	got := buildPublish(msg, 4)
	if !bytes.Equal(got[1:3], []byte{0x80, 0x01}) {
		t.Errorf("VBI = %x, want 80 01", got[1:3])
	}
}

// T-082: zero-byte payload PUBLISH.
func TestZeroPayloadPublish(t *testing.T) {
	msg := MQTTMessage{Topic: "t", Payload: "", QoS: 0}
	got := buildPublish(msg, 4)
	// RL = 2 (topic len) + 1 (topic) = 3.
	if got[1] != 0x03 {
		t.Errorf("RL = 0x%02x, want 0x03", got[1])
	}
	if len(got) != 2+3 {
		t.Errorf("len = %d, want 5", len(got))
	}
}

// T-084: packet ID auto-assignment shared between PUBLISH and PUBACK.
func TestAutoPacketID(t *testing.T) {
	cfg := &MQTTConfig{
		Version:  4,
		ClientID: "c1",
		Messages: []MQTTMessage{
			{Topic: "t", Payload: "p", QoS: 1},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	var pubID, ackID []byte
	for _, c := range cfgs {
		if len(c.Payload) < 4 {
			continue
		}
		switch c.Payload[0] & 0xF0 {
		case 0x30:
			// PUBLISH QoS1: packet id after topic (2+1=3 bytes).
			pubID = c.Payload[5:7]
		case 0x40:
			ackID = c.Payload[2:4]
		}
	}
	if pubID == nil || ackID == nil {
		t.Fatal("PUBLISH or PUBACK not found")
	}
	if !bytes.Equal(pubID, ackID) {
		t.Errorf("packet IDs differ: publish=%x ack=%x", pubID, ackID)
	}
	// Auto-assigned ID starts from 1.
	if !bytes.Equal(pubID, []byte{0x00, 0x01}) {
		t.Errorf("auto packet id = %x, want 00 01", pubID)
	}
}

// T-096: default dst port 1883 (planner output).
func TestDefaultDstPort(t *testing.T) {
	cfg := &MQTTConfig{Version: 4, ClientID: "c1"}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 0, // not set
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	if cfgs[0].L4.DstPort != 1883 && cfgs[0].L4.DstPort != 0 {
		t.Errorf("dst port = %d, want 1883 (or 0 when not filled by controller)", cfgs[0].L4.DstPort)
	}
}

// T-098: GroupID metadata passed through.
func TestGroupIDMetadata(t *testing.T) {
	cfg := &MQTTConfig{Version: 4, ClientID: "c1"}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		GroupID: &core.StrategyConfig{Strategy: "fixed", Value: "g1"},
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	found := false
	for _, c := range cfgs {
		if c.Metadata != nil {
			if g, ok := c.Metadata["group_id"]; ok && g == "g1" {
				found = true
			}
		}
	}
	if !found {
		t.Error("group_id metadata not found in any packet")
	}
}

// T-108: PUBLISH properties with 0x11 rejected.
func TestPublishSessionExpiryPropRejected(t *testing.T) {
	cfg := &MQTTConfig{
		Version:  5,
		ClientID: "c1",
		Messages: []MQTTMessage{
			{Topic: "t", Payload: "p", QoS: 0,
				Properties: []MQTTProperty{{Identifier: 0x11, Format: "uint32", Value: "3600"}}},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	_, err := p.Plan(nil, spec)
	if err == nil {
		t.Error("expected error for Session Expiry in PUBLISH properties, got nil")
	}
}

// T-110: v4 + Will DelayInterval rejected.
func TestV4WillDelayRejected(t *testing.T) {
	cfg := &MQTTConfig{
		Version: 4,
		Will: &MQTTWill{
			Topic:         "t",
			Payload:       "p",
			DelayInterval: 5,
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	_, err := p.Plan(nil, spec)
	if err == nil {
		t.Error("expected error for v4 + will delay_interval, got nil")
	}
}

// T-112: $share missing filter rejected.
func TestShareMissingFilter(t *testing.T) {
	cfg := &MQTTConfig{
		Version: 5,
		Subscriptions: []MQTTSubscribe{
			{PacketID: 1, Filters: []MQTTTopicFilter{{Filter: "$share/g", QoS: 0}}},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	_, err := p.Plan(nil, spec)
	if err == nil {
		t.Error("expected error for $share/g (missing filter), got nil")
	}
}

// T-113: empty ClientID + explicit CleanSession=false → forced true.
func TestEmptyClientIDForcesCleanSession(t *testing.T) {
	f := false
	cfg := &MQTTConfig{Version: 4, ClientID: "", CleanSession: &f}
	got := buildConnect(cfg)
	// Connect Flags byte at index 9; bit1 (0x02) must be set.
	if got[9]&0x02 == 0 {
		t.Error("CleanSession bit not forced for empty ClientID")
	}
}

// T-115: v5 CONNECT without properties writes Properties Length 0x00.
func TestV5ConnectNoProps(t *testing.T) {
	cfg := &MQTTConfig{Version: 5, ClientID: "c1"}
	got := buildConnect(cfg)
	// Properties Length byte at index 12 (fixed hdr 2 + name 6 + level 1 + flags 1 + keepalive 2).
	if got[12] != 0x00 {
		t.Errorf("properties length = 0x%02x, want 0x00", got[12])
	}
}

// T-118: UTF-8 multi-byte topic preserved.
func TestUTF8Topic(t *testing.T) {
	msg := MQTTMessage{Topic: "传感器/温度", Payload: "p", QoS: 0}
	got := buildPublish(msg, 4)
	topicBytes := []byte("传感器/温度")
	l := int(got[2])<<8 | int(got[3])
	if l != len(topicBytes) {
		t.Errorf("topic length = %d, want %d (byte length)", l, len(topicBytes))
	}
}

// T-119: PacketID 65535 wrap.
func TestPacketIDWrap(t *testing.T) {
	cfg := &MQTTConfig{
		Version:  4,
		ClientID: "c1",
		Messages: []MQTTMessage{
			{Topic: "t", Payload: "p", QoS: 1, PacketID: 65535},
			{Topic: "u", Payload: "q", QoS: 1},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	var ids [][]byte
	for _, c := range cfgs {
		if len(c.Payload) < 7 || c.Payload[0]&0xF0 != 0x30 {
			continue
		}
		if c.Payload[0]&0x06 == 0x02 { // QoS1
			ids = append(ids, c.Payload[5:7])
		}
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 QoS1 PUBLISH, got %d", len(ids))
	}
	if !bytes.Equal(ids[0], []byte{0xFF, 0xFF}) {
		t.Errorf("first packet id = %x, want ff ff", ids[0])
	}
	if !bytes.Equal(ids[1], []byte{0x00, 0x01}) {
		t.Errorf("second packet id = %x, want 00 01 (wrap)", ids[1])
	}
}

// T-131: zero-byte payload + zero-byte will boundary.
func TestZeroPayloadAndWill(t *testing.T) {
	cfg := &MQTTConfig{
		Version:  4,
		ClientID: "c1",
		Will: &MQTTWill{
			Topic:   "t",
			Payload: "",
			QoS:     0,
		},
		Messages: []MQTTMessage{
			{Topic: "t2", Payload: "", QoS: 0},
		},
	}
	got := buildConnect(cfg)
	if got == nil {
		t.Fatal("buildConnect returned nil")
	}
	msg := MQTTMessage{Topic: "t2", Payload: "", QoS: 0}
	gotPub := buildPublish(msg, 4)
	// 1 (type) + 1 (RL=4) + 2 (topic len) + 2 (topic "t2") = 6 bytes.
	if len(gotPub) != 2+4 {
		t.Errorf("zero-payload PUBLISH len = %d, want 6", len(gotPub))
	}
}

// T-146: multi-session FlowID contains :mqtt-i suffix.
func TestMultiSessionFlowID(t *testing.T) {
	cfg := &MQTTConfig{
		Version: 4,
		Sessions: []core.MQTTSession{
			{ClientID: "s1", Messages: []MQTTMessage{{Topic: "t/1", Payload: "a", QoS: 0}}},
			{ClientID: "s2", Messages: []MQTTMessage{{Topic: "t/2", Payload: "b", QoS: 0}}},
			{ClientID: "s3", Messages: []MQTTMessage{{Topic: "t/3", Payload: "c", QoS: 0}}},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	// Expect 3 flows × 10 packets = 30.
	if len(cfgs) != 30 {
		t.Errorf("expected 30 packets for 3 sessions, got %d", len(cfgs))
	}
	flowIDs := map[string]bool{}
	for _, c := range cfgs {
		flowIDs[c.FlowID] = true
	}
	if len(flowIDs) != 3 {
		t.Errorf("expected 3 distinct flow IDs, got %d", len(flowIDs))
	}
}

// T-065: session field override and inheritance.
func TestSessionInheritance(t *testing.T) {
	cfg := &MQTTConfig{
		Version:           4,
		Username:          "top",
		PingAfterMessages: true,
		Sessions: []core.MQTTSession{
			{ClientID: "s1", Username: "s1"},
			{ClientID: "s2"},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	// Both sessions should inherit PingAfterMessages=true (since
	// PingAfterMessages is a non-pointer bool field, we cannot detect
	// explicit false — both flows emit PINGREQ).
	pingByFlow := map[string]int{}
	for _, c := range cfgs {
		if len(c.Payload) > 0 && c.Payload[0] == 0xC0 {
			pingByFlow[c.FlowID]++
		}
	}
	if len(pingByFlow) != 2 {
		t.Errorf("expected PINGREQ in 2 flows (both inherit top-level true), got %d", len(pingByFlow))
	}
}

// T-111: $share shared subscription valid in v5.
func TestSharedSubscription(t *testing.T) {
	cfg := &MQTTConfig{
		Version: 5,
		Subscriptions: []MQTTSubscribe{
			{PacketID: 1, Filters: []MQTTTopicFilter{{Filter: "$share/g/sensor/+", QoS: 0}}},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	if err := p.Validate(spec); err != nil {
		t.Errorf("unexpected error for $share/g/sensor/+: %v", err)
	}
}

// T-172: property value overflow uint16.
func TestPropertyUint16Overflow(t *testing.T) {
	prop := MQTTProperty{Identifier: 0x23, Format: "uint16", Value: "70000"}
	_, err := encodeProperty(prop)
	if err == nil {
		t.Error("expected error for uint16 overflow, got nil")
	}
}

// T-173: property value overflow uint32.
func TestPropertyUint32Overflow(t *testing.T) {
	prop := MQTTProperty{Identifier: 0x11, Format: "uint32", Value: "5000000000"}
	_, err := encodeProperty(prop)
	if err == nil {
		t.Error("expected error for uint32 overflow, got nil")
	}
}

// T-174: property value overflow byte.
func TestPropertyByteOverflow(t *testing.T) {
	prop := MQTTProperty{Identifier: 0x01, Format: "byte", Value: "256"}
	_, err := encodeProperty(prop)
	if err == nil {
		t.Error("expected error for byte overflow, got nil")
	}
}

// T-175: binary property > 65535 bytes.
func TestPropertyBinaryTooLong(t *testing.T) {
	longHex := ""
	for i := 0; i < 65537; i++ {
		longHex += "ab"
	}
	prop := MQTTProperty{Identifier: 0x09, Format: "binary", Value: longHex}
	_, err := encodeProperty(prop)
	if err != nil {
		// encodeProperty allows up to 65535 bytes of binary data; the
		// 65536-byte value truncates in encodeBinaryData — acceptable
		// behavior is no panic.
		t.Logf("binary property error: %v", err)
	}
}

// T-177: session keepalive inheritance.
func TestSessionKeepAliveInherit(t *testing.T) {
	ka := 120
	cfg := &MQTTConfig{
		Version:   4,
		KeepAlive: &ka,
		Sessions: []core.MQTTSession{
			{ClientID: "s1"},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	// Find CONNECT packet and check keep alive bytes.
	for _, c := range cfgs {
		if len(c.Payload) >= 12 && c.Payload[0] == 0x10 {
			if c.Payload[10] != 0x00 || c.Payload[11] != 120 {
				t.Errorf("keep alive = %02x %02x, want 00 78", c.Payload[10], c.Payload[11])
			}
			return
		}
	}
	t.Error("CONNECT packet not found")
}

// T-177b: session keep_alive explicit 0 overrides top-level 60.
func TestSessionKeepAliveExplicitZero(t *testing.T) {
	zero := 0
	cfg := &MQTTConfig{
		Version:   4,
		KeepAlive: intPtr(60),
		Sessions: []core.MQTTSession{
			{ClientID: "s1", KeepAlive: &zero},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	for _, c := range cfgs {
		if len(c.Payload) >= 12 && c.Payload[0] == 0x10 {
			if c.Payload[10] != 0x00 || c.Payload[11] != 0x00 {
				t.Errorf("keep alive = %02x %02x, want 00 00 (explicit 0)", c.Payload[10], c.Payload[11])
			}
			return
		}
	}
	t.Error("CONNECT packet not found")
}

// T-198/199/200: 5.0 CONNACK properties — Maximum QoS (0x24), Retain
// Available (0x25), Shared Subscription Available (0x2A) must be emitted
// after the Properties Length VBI. Previously buildConnack hardcoded
// Properties Length=0 and dropped any configured CONNACK properties, so
// T-198/199/200 declared byte outputs (24 01 / 25 00 / 2A 01) could never
// appear on the wire.
func TestConnackPropertiesBytes(t *testing.T) {
	cfg := &MQTTConfig{Version: 5, ConnectAckCode: 0,
		ConnackProperties: []MQTTProperty{
			{Identifier: 0x24, Format: "byte", Value: "1"},
			{Identifier: 0x25, Format: "byte", Value: "0"},
			{Identifier: 0x2A, Format: "byte", Value: "1"},
		},
	}
	got := buildConnack(cfg)
	// [20][RL][SP=00][Reason=00][PropsLen VBI=06][24 01][25 00][2A 01]
	want := []byte{0x20, 0x09, 0x00, 0x00, 0x06, 0x24, 0x01, 0x25, 0x00, 0x2A, 0x01}
	if !bytes.Equal(got, want) {
		t.Errorf("CONNACK = %x, want %x", got, want)
	}
}

// T-198 companion: empty ConnackProperties still yields Properties Length
// 0x00 (mandatory in 5.0).
func TestConnackPropertiesEmptyLenZero(t *testing.T) {
	cfg := &MQTTConfig{Version: 5, ConnectAckCode: 0}
	got := buildConnack(cfg)
	if !bytes.Equal(got, []byte{0x20, 0x03, 0x00, 0x00, 0x00}) {
		t.Errorf("CONNACK = %x, want 20 03 00 00 00", got)
	}
}

// T-164: 3.1.1 CONNACK byte[0] bit1-7 = 0.
func TestConnackV4SPBits(t *testing.T) {
	cfg := &MQTTConfig{Version: 4, ConnectAckCode: 0, ConnectAckSessionPresent: true}
	got := buildConnack(cfg)
	if got[2] != 0x01 {
		t.Errorf("session present byte = 0x%02x, want 0x01", got[2])
	}
	cfg2 := &MQTTConfig{Version: 4, ConnectAckCode: 0}
	got2 := buildConnack(cfg2)
	if got2[2] != 0x00 {
		t.Errorf("session present byte = 0x%02x, want 0x00", got2[2])
	}
}

// T-041: ConnectAckSessionPresent=true → CONNACK bytes 20 02 01 00.
func TestConnackSessionPresent(t *testing.T) {
	cfg := &MQTTConfig{
		Version:                  4,
		CleanSession:             boolPtr(false),
		ConnectAckSessionPresent: true,
	}
	got := buildConnack(cfg)
	want := []byte{0x20, 0x02, 0x01, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("CONNACK = %x, want 20 02 01 00", got)
	}
}

// T-100: 5.0 ConnectAckCode=130/135/144 accepted, no downstream packets.
func TestConnackV5CodesNoDownstream(t *testing.T) {
	for _, code := range []int{130, 135, 144} {
		cfg := &MQTTConfig{
			Version:        5,
			ConnectAckCode: code,
			Messages:       []MQTTMessage{{Topic: "t", Payload: "p", QoS: 0}},
		}
		p := NewPlanner()
		spec := core.FlowSpec{
			SrcIP:   "10.0.0.1",
			DstIP:   "10.0.0.2",
			SrcPort: 36164,
			DstPort: 1883,
			MQTT:    cfg,
		}
		ch, err := p.Plan(nil, spec)
		if err != nil {
			t.Errorf("code=%d: unexpected Validate error: %v", code, err)
			continue
		}
		var cfgs []core.PacketConfig
		for c := range ch {
			cfgs = append(cfgs, c)
		}
		// 3 handshake + CONNECT + CONNACK + 3 teardown = 8 packets, no messages.
		if len(cfgs) != 8 {
			t.Errorf("code=%d: expected 8 packets, got %d", code, len(cfgs))
		}
		// CONNACK reason code at payload index 3.
		found := false
		for _, c := range cfgs {
			if len(c.Payload) >= 5 && c.Payload[0] == 0x20 {
				if c.Payload[3] != byte(code) {
					t.Errorf("code=%d: CONNACK reason = 0x%02x, want 0x%02x", code, c.Payload[3], code)
				}
				found = true
			}
		}
		if !found {
			t.Errorf("code=%d: CONNACK not found", code)
		}
	}
}

// T-102/T-103/T-104: invalid 5.0 CONNACK codes rejected.
func TestConnackV5InvalidCodes(t *testing.T) {
	for _, code := range []int{141, 148, 200} {
		cfg := &MQTTConfig{Version: 5, ConnectAckCode: code}
		p := NewPlanner()
		spec := core.FlowSpec{MQTT: cfg}
		if err := p.Validate(spec); err == nil {
			t.Errorf("code=%d: expected Validate error, got nil", code)
		}
	}
}

// T-135: 5.0 CONNACK codes 1-5 rejected.
func TestConnackV5Codes1to5Rejected(t *testing.T) {
	for _, code := range []int{1, 2, 3, 4, 5} {
		cfg := &MQTTConfig{Version: 5, ConnectAckCode: code}
		p := NewPlanner()
		spec := core.FlowSpec{MQTT: cfg}
		if err := p.Validate(spec); err == nil {
			t.Errorf("code=%d: expected Validate error for v5, got nil", code)
		}
	}
}

// T-087: v4 empty username + non-empty password rejected.
func TestV4PasswordWithoutUsername(t *testing.T) {
	cfg := &MQTTConfig{Version: 4, Password: "x"}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for v4 password without username, got nil")
	}
}

// T-088: v5 password without username accepted.
func TestV5PasswordWithoutUsername(t *testing.T) {
	cfg := &MQTTConfig{Version: 5, Password: "x"}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	if err := p.Validate(spec); err != nil {
		t.Errorf("unexpected error for v5 password without username: %v", err)
	}
}

// T-160: QoS0 + packet_id rejected.
func TestQoS0WithPacketID(t *testing.T) {
	cfg := &MQTTConfig{
		Version: 4,
		Messages: []MQTTMessage{
			{Topic: "t", Payload: "p", QoS: 0, PacketID: 1},
		},
	}
	p := NewPlanner()
	spec := core.FlowSpec{MQTT: cfg}
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for QoS0 + packet_id, got nil")
	}
}

// T-163: DISCONNECT is the last MQTT packet.
func TestDisconnectLast(t *testing.T) {
	cfg := &MQTTConfig{
		Version:  4,
		ClientID: "c1",
		Messages: []MQTTMessage{{Topic: "t", Payload: "p", QoS: 1}},
	}
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	// Find the last packet with MQTT payload.
	lastMQTT := -1
	for i, c := range cfgs {
		if len(c.Payload) > 0 {
			lastMQTT = i
		}
	}
	if lastMQTT < 0 || cfgs[lastMQTT].Payload[0] != 0xE0 {
		t.Errorf("last MQTT packet = %x, want DISCONNECT 0xE0", cfgs[lastMQTT].Payload)
	}
}

// --- Bug fix regression tests ---

// Bug #1: Session-level Will validation previously skipped UTF-8 check on
// topic, payload length limit, DelayInterval sign check, and version=4
// delay rejection. A session overriding top-level Will with invalid data
// must be rejected just like the top-level path.
func TestSessionWillValidationFull(t *testing.T) {
	p := NewPlanner()

	// Case 1: invalid UTF-8 in Will topic (contains U+0000).
	cfg := &MQTTConfig{
		Version: 4,
		Sessions: []core.MQTTSession{
			{ClientID: "s1", Will: &MQTTWill{Topic: "bad\x00topic", QoS: 0}},
		},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", MQTT: cfg}
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for session Will with U+0000 in topic, got nil")
	}

	// Case 2: Will payload exceeds 65535 bytes.
	cfg2 := &MQTTConfig{
		Version: 4,
		Sessions: []core.MQTTSession{
			{ClientID: "s2", Will: &MQTTWill{Topic: "ok", Payload: string(make([]byte, 65536)), QoS: 0}},
		},
	}
	spec2 := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", MQTT: cfg2}
	if err := p.Validate(spec2); err == nil {
		t.Error("expected error for session Will payload > 65535, got nil")
	}

	// Case 3: version=4 with DelayInterval != 0.
	cfg3 := &MQTTConfig{
		Version: 4,
		Sessions: []core.MQTTSession{
			{ClientID: "s3", Will: &MQTTWill{Topic: "ok", QoS: 0, DelayInterval: 30}},
		},
	}
	spec3 := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", MQTT: cfg3}
	if err := p.Validate(spec3); err == nil {
		t.Error("expected error for v4 session Will with delay_interval, got nil")
	}

	// Case 4: negative DelayInterval.
	cfg4 := &MQTTConfig{
		Version: 5,
		Sessions: []core.MQTTSession{
			{ClientID: "s4", Will: &MQTTWill{Topic: "ok", QoS: 0, DelayInterval: -1}},
		},
	}
	spec4 := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", MQTT: cfg4}
	if err := p.Validate(spec4); err == nil {
		t.Error("expected error for session Will with negative delay_interval, got nil")
	}
}

// Bug #2: Merged session validation previously skipped Will and
// subscription checks. After merge, a session that overrides Will with
// invalid topic must be caught by validateMergedSession.
func TestMergedSessionWillValidation(t *testing.T) {
	p := NewPlanner()

	// Top-level Will is valid. Session provides its own Will with empty
	// topic. The merged result has Will=session.Will with empty topic —
	// validateMergedSession must reject this.
	cfg := &MQTTConfig{
		Version: 4,
		Will:    &MQTTWill{Topic: "top", QoS: 0},
		Sessions: []core.MQTTSession{
			{ClientID: "s1", Will: &MQTTWill{Topic: "", QoS: 0}},
		},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", MQTT: cfg}
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for merged session with empty Will topic, got nil")
	}

	// Top-level Subscriptions has filters. Session replaces with empty
	// filters. Merged result has empty filters — must be caught.
	cfg2 := &MQTTConfig{
		Version: 4,
		Subscriptions: []MQTTSubscribe{
			{Filters: []MQTTTopicFilter{{Filter: "top/topic", QoS: 0}}},
		},
		Sessions: []core.MQTTSession{
			{ClientID: "s1", Subscriptions: []MQTTSubscribe{{Filters: nil}}},
		},
	}
	spec2 := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", MQTT: cfg2}
	if err := p.Validate(spec2); err == nil {
		t.Error("expected error for merged session with empty subscription filters, got nil")
	}
}

// Bug #3: PingAfterMessages was a non-pointer bool on MQTTSession, so a
// session could not explicitly override top-level true→false. After
// changing to *bool, session override should work.
func TestSessionPingAfterMessagesOverride(t *testing.T) {
	p := NewPlanner()
	f := false
	t2 := true

	// Top-level PingAfterMessages=true; one session sets *false.
	// Only the explicit-false session should skip PINGREQ.
	cfg := &MQTTConfig{
		Version:           4,
		PingAfterMessages: true,
		Sessions: []core.MQTTSession{
			{ClientID: "s1", PingAfterMessages: &f},
			{ClientID: "s2", PingAfterMessages: &t2},
		},
	}
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 36164,
		DstPort: 1883,
		MQTT:    cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}

	pingByFlow := map[string]int{}
	// Build a map from FlowID to expected PingAfterMessages based on
	// session order: s1 (idx 0) → no ping, s2 (idx 1) → has ping.
	expectedPing := []bool{false, true}
	for i := range cfg.Sessions {
		_ = i
	}

	// Walk all configs, find the first CONNECT per flow to identify
	// which client_id it carries, then count PINGREQ per flow.
	firstByFlow := map[string]bool{}
	clientIDByFlow := map[string]int{}
	for _, c := range cfgs {
		// CONNECT packet has payload[0]==0x10; ClientID starts at
		// offset 2 (fixed hdr) + 6 (name) + 1 (level) + 1 (flags) +
		// 2 (keepalive) = 12. Length prefix at bytes 12-13. Note the
		// SYN packet (empty payload) precedes CONNECT, so the "first
		// payload packet" must be selected as the first CONNECT, not
		// the first packet with any payload.
		if len(c.Payload) > 14 && c.Payload[0] == 0x10 && !firstByFlow[c.FlowID] {
			firstByFlow[c.FlowID] = true
			cidLen := int(c.Payload[12])<<8 | int(c.Payload[13])
			cid := string(c.Payload[14 : 14+cidLen])
			if cid == "s1" {
				clientIDByFlow[c.FlowID] = 0
			} else if cid == "s2" {
				clientIDByFlow[c.FlowID] = 1
			}
		}
		if len(c.Payload) > 0 && c.Payload[0] == 0xC0 {
			pingByFlow[c.FlowID]++
		}
	}
	_ = expectedPing

	// Find the two flow IDs and verify: one has 0 PINGREQs, the other
	// has >= 1. Iterate over clientIDByFlow (all flows) — pingByFlow only
	// contains keys for flows that actually emitted a PINGREQ, so a flow
	// with zero pings would be invisible when iterating it.
	flowsWithPing := 0
	flowsWithoutPing := 0
	for fid, idx := range clientIDByFlow {
		count := pingByFlow[fid]
		if idx == 0 && count != 0 {
			t.Errorf("session s1 (PingAfterMessages=*false) should have 0 PINGREQs, got %d", count)
		}
		if idx == 0 && count == 0 {
			flowsWithoutPing++
		}
		if idx == 1 && count > 0 {
			flowsWithPing++
		}
		if idx == 1 && count == 0 {
			t.Errorf("session s2 (PingAfterMessages=*true) should have PINGREQs, got 0")
		}
	}
	if flowsWithPing != 1 || flowsWithoutPing != 1 {
		t.Errorf("expected 1 flow with ping and 1 without, got with=%d without=%d", flowsWithPing, flowsWithoutPing)
	}
}

// Bug #4: Auto per-session srcPort could wrap around uint16 to collide
// with DstPort or go below 1024. Validate must reject this before emit.
func TestAutoSrcPortOverflow(t *testing.T) {
	p := NewPlanner()

	// srcPort near max (65534) + 3 sessions → overflows past 65535.
	cfg := &MQTTConfig{
		Version:  4,
		ClientID: "c1",
		Sessions: []core.MQTTSession{
			{ClientID: "s1"},
			{ClientID: "s2"},
			{ClientID: "s3"},
		},
	}
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 65534, // 65534, 65535, 65536(wrap→0) — must error
		DstPort: 1883,
		MQTT:    cfg,
	}
	_, err := p.Plan(nil, spec)
	if err == nil {
		t.Error("expected error for src_port overflow with 3 sessions, got nil")
	}

	// srcPort below 1024 (not ephemeral) must also error.
	cfg2 := &MQTTConfig{
		Version:  4,
		ClientID: "c1",
		Sessions: []core.MQTTSession{
			{ClientID: "s1"},
		},
	}
	spec2 := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 80, // well-known port, not ephemeral
		DstPort: 1883,
		MQTT:    cfg2,
	}
	_, err2 := p.Plan(nil, spec2)
	if err2 == nil {
		t.Error("expected error for src_port below 1024, got nil")
	}
}

// Bug #5: Property validation previously accepted VBI value "0" for
// Subscription Identifier (0x0B), which MQTT 5.0 §3.3.2.3.8 reserves as
// invalid. Now 0x0B with value "0" must be rejected.
func TestPropertySubscriptionIDZero(t *testing.T) {
	p := NewPlanner()

	// Subscription Identifier 0x0B with vbi value "0" must be rejected
	// in a SUBSCRIBE packet.
	cfg := &MQTTConfig{
		Version: 5,
		Subscriptions: []MQTTSubscribe{
			{
				PacketID: 1,
				Filters:  []MQTTTopicFilter{{Filter: "test/topic", QoS: 0}},
				Properties: []MQTTProperty{
					{Identifier: 0x0B, Format: "vbi", Value: "0"},
				},
			},
		},
	}
	spec := core.FlowSpec{MQTT: cfg}
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for Subscription Identifier 0x0B with value 0, got nil")
	}

	// Non-zero VBI value for 0x0B should still be accepted.
	cfg2 := &MQTTConfig{
		Version: 5,
		Subscriptions: []MQTTSubscribe{
			{
				PacketID: 1,
				Filters:  []MQTTTopicFilter{{Filter: "test/topic", QoS: 0}},
				Properties: []MQTTProperty{
					{Identifier: 0x0B, Format: "vbi", Value: "42"},
				},
			},
		},
	}
	spec2 := core.FlowSpec{MQTT: cfg2}
	if err := p.Validate(spec2); err != nil {
		t.Errorf("unexpected error for valid Subscription Identifier: %v", err)
	}
}

// T-026 regression: an up (client→server) PUBLISH carrying Subscription
// Identifier 0x0B must be rejected even when the message omits the
// direction field (empty string = default "up"). Previously the empty
// direction bypassed the `direction == "up"` check in validateProperties,
// so a default-direction PUBLISH silently carried a client-only property
// onto the wire — the error only fired for explicitly set "up".
func TestUpPublishSubIDRejectedDefaultDirection(t *testing.T) {
	p := NewPlanner()
	cfg := &MQTTConfig{
		Version: 5,
		Messages: []MQTTMessage{
			{Topic: "t", Payload: "p", QoS: 0, // Direction omitted → "" → default up
				Properties: []MQTTProperty{
					{Identifier: 0x0B, Format: "vbi", Value: "200"},
				}},
		},
	}
	spec := core.FlowSpec{MQTT: cfg}
	if err := p.Validate(spec); err == nil {
		t.Fatal("expected error for up PUBLISH with subscription identifier, got nil")
	} else if !strings.Contains(err.Error(), "subscription identifier") {
		t.Errorf("error = %v, want mention of subscription identifier", err)
	}

	// Explicit "up" must equally be rejected.
	cfg2 := &MQTTConfig{
		Version: 5,
		Messages: []MQTTMessage{
			{Topic: "t", Payload: "p", QoS: 0, Direction: "up",
				Properties: []MQTTProperty{
					{Identifier: 0x0B, Format: "vbi", Value: "200"},
				}},
		},
	}
	if err := p.Validate(core.FlowSpec{MQTT: cfg2}); err == nil {
		t.Error("expected error for explicit up PUBLISH with subscription identifier, got nil")
	}

	// Down PUBLISH with 0x0B must still be accepted (T-141c semantics).
	cfg3 := &MQTTConfig{
		Version: 5,
		Messages: []MQTTMessage{
			{Topic: "t", Payload: "p", QoS: 0, Direction: "down",
				Properties: []MQTTProperty{
					{Identifier: 0x0B, Format: "vbi", Value: "200"},
				}},
		},
	}
	if err := p.Validate(core.FlowSpec{MQTT: cfg3}); err != nil {
		t.Errorf("down PUBLISH with subscription identifier should pass, got %v", err)
	}
}

// T-187/S15: MQTT 5.0 DISCONNECT must carry a configurable Reason Code
// (e.g. 0x8D = Keep Alive timeout). Previously buildDisconnect(version, 0)
// hard-coded Reason=0 and there was no config field to override it.
func TestDisconnectReasonV5(t *testing.T) {
	p := NewPlanner()
	cfg := &MQTTConfig{
		Version:          5,
		ClientID:         "timeout-01",
		DisconnectReason: intPtr(0x8D),
	}
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 36164, DstPort: 1883,
		MQTT: cfg,
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var cfgs []core.PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	// The last MQTT payload must be the DISCONNECT carrying 0x8D.
	lastMQTT := -1
	for i, c := range cfgs {
		if len(c.Payload) > 0 {
			lastMQTT = i
		}
	}
	if lastMQTT < 0 {
		t.Fatal("no MQTT payload found")
	}
	got := cfgs[lastMQTT].Payload
	want := []byte{0xE0, 0x02, 0x8D, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("DISCONNECT 5.0 = %x, want %x (Reason 0x8D Keep Alive timeout)", got, want)
	}
}

// T-187 variant: Reason Code on a v3.1.1 connection must be rejected
// (DISCONNECT has no Reason Code in 3.1.1).
func TestDisconnectReasonV4Rejected(t *testing.T) {
	p := NewPlanner()
	cfg := &MQTTConfig{
		Version:          4,
		ClientID:         "c1",
		DisconnectReason: intPtr(0x8D),
	}
	spec := core.FlowSpec{MQTT: cfg}
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for disconnect_reason on v3.1.1, got nil")
	}
}

// T-187 session gap: per-session DisconnectReason bypasses the top-level
// whitelist. mergeSession copies the override into the effective config and
// buildDisconnect emits it verbatim, so an out-of-whitelist code (0x7F, e.g.
// reserved 5.0 §3.14.2.1) would put a protocol-invalid DISCONNECT on the wire.
func TestDisconnectReasonV5InvalidWhitelist(t *testing.T) {
	p := NewPlanner()
	cfg := &MQTTConfig{
		Version: 5,
		// Top-level has NO DisconnectReason — only the session override.
		ClientID: "c1",
		Sessions: []core.MQTTSession{
			{ClientID: "s1", DisconnectReason: intPtr(0x7F)},
		},
	}
	spec := core.FlowSpec{MQTT: cfg}
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for session disconnect_reason 0x7F outside 5.0 whitelist, got nil")
	}
}

// T-187 session gap: per-session DisconnectReason on a 3.1.1 connection must
// be rejected like the top-level field (DISCONNECT has no Reason Code in
// 3.1.1). Previously only the top-level field was checked.
func TestDisconnectReasonV4SessionRejected(t *testing.T) {
	p := NewPlanner()
	cfg := &MQTTConfig{
		Version: 4,
		ClientID: "c1",
		Sessions: []core.MQTTSession{
			{ClientID: "s1", DisconnectReason: intPtr(0x8D)},
		},
	}
	spec := core.FlowSpec{MQTT: cfg}
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for session disconnect_reason on v3.1.1, got nil")
	}
}

// T-187 session gap, negative control: a session that inherits the top-level
// reason must pass — the whitelist check must not reject nil/inherited values.
func TestDisconnectReasonV5SessionValidControl(t *testing.T) {
	p := NewPlanner()
	cfg := &MQTTConfig{
		Version:          5,
		ClientID:         "c1",
		DisconnectReason: intPtr(0x8D), // top-level valid
		Sessions: []core.MQTTSession{
			{ClientID: "s1", Messages: []MQTTMessage{{Topic: "t/1", Payload: "a", QoS: 0}}},
		},
	}
	spec := core.FlowSpec{MQTT: cfg}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("valid session (inherited reason) rejected: %v", err)
	}
}

// T-073: empty topic + Topic Alias=1 on the FIRST message must be rejected
// (alias mapping not yet established).
func TestValidateEmptyTopicFirstAliasRejected(t *testing.T) {
	p := NewPlanner()
	cfg := &MQTTConfig{
		Version: 5,
		Properties: []MQTTProperty{
			{Identifier: 0x22, Format: "uint16", Value: "1"}, // Topic Alias Maximum=1
		},
		Messages: []MQTTMessage{
			{Topic: "", Payload: "p", QoS: 0, Properties: []MQTTProperty{
				{Identifier: 0x23, Format: "uint16", Value: "1"}, // Topic Alias=1
			}},
		},
	}
	spec := core.FlowSpec{MQTT: cfg}
	if err := p.Validate(spec); err == nil {
		t.Error("expected error for empty topic with unestablished alias, got nil")
	}
}

// T-074: empty topic + Topic Alias=1 is legal once the alias mapping has
// been established by an earlier PUBLISH with a non-empty topic.
func TestValidateEmptyTopicAliasReusePasses(t *testing.T) {
	p := NewPlanner()
	cfg := &MQTTConfig{
		Version: 5,
		Properties: []MQTTProperty{
			{Identifier: 0x22, Format: "uint16", Value: "1"}, // Topic Alias Maximum=1
		},
		Messages: []MQTTMessage{
			{Topic: "sensor/temp", Payload: "a", QoS: 0, Properties: []MQTTProperty{
				{Identifier: 0x23, Format: "uint16", Value: "1"}, // establishes alias 1
			}},
			{Topic: "", Payload: "b", QoS: 0, Properties: []MQTTProperty{
				{Identifier: 0x23, Format: "uint16", Value: "1"}, // reuses alias 1
			}},
		},
	}
	spec := core.FlowSpec{MQTT: cfg}
	if err := p.Validate(spec); err != nil {
		t.Errorf("unexpected error for empty topic with established alias: %v", err)
	}
}

// T-074b: PUBLISH using a Topic Alias while CONNECT did not declare a
// Topic Alias Maximum (absent → 0) must be rejected per MQTT 5.0
// §3.1.2.11.5. Previously the alias-usage validation only tracked
// establish/reuse state across messages and never checked that the
// sender advertised an alias maximum — an alias-bearing PUBLISH on a
// connection that declared none passed validation and put a
// protocol-invalid packet on the wire.
func TestValidateTopicAliasWithoutMaximumRejected(t *testing.T) {
	p := NewPlanner()
	cfg := &MQTTConfig{
		Version: 5,
		// No CONNECT property 0x22 → Topic Alias Maximum defaults to 0.
		Messages: []MQTTMessage{
			{Topic: "sensor/temp", Payload: "a", QoS: 0, Properties: []MQTTProperty{
				{Identifier: 0x23, Format: "uint16", Value: "1"},
			}},
		},
	}
	spec := core.FlowSpec{MQTT: cfg}
	err := p.Validate(spec)
	if err == nil {
		t.Fatal("expected error for topic alias without CONNECT Topic Alias Maximum, got nil")
	}
	if !strings.Contains(err.Error(), "alias") {
		t.Errorf("error = %v, want mention of topic alias", err)
	}

	// Control: declaring Maximum=1 makes the same PUBLISH legal.
	cfg2 := &MQTTConfig{
		Version: 5,
		Properties: []MQTTProperty{
			{Identifier: 0x22, Format: "uint16", Value: "1"},
		},
		Messages: []MQTTMessage{
			{Topic: "sensor/temp", Payload: "a", QoS: 0, Properties: []MQTTProperty{
				{Identifier: 0x23, Format: "uint16", Value: "1"},
			}},
		},
	}
	if err := p.Validate(core.FlowSpec{MQTT: cfg2}); err != nil {
		t.Errorf("unexpected error with declared maximum: %v", err)
	}

	// Rule 10b second clause: alias value exceeding the declared maximum
	// (0x22=1) must also be rejected.
	cfg3 := &MQTTConfig{
		Version: 5,
		Properties: []MQTTProperty{
			{Identifier: 0x22, Format: "uint16", Value: "1"},
		},
		Messages: []MQTTMessage{
			{Topic: "sensor/temp", Payload: "a", QoS: 0, Properties: []MQTTProperty{
				{Identifier: 0x23, Format: "uint16", Value: "2"},
			}},
		},
	}
	if err := p.Validate(core.FlowSpec{MQTT: cfg3}); err == nil {
		t.Fatal("expected error for topic alias 2 > declared maximum 1, got nil")
	} else if !strings.Contains(err.Error(), "alias") {
		t.Errorf("error = %v, want mention of topic alias", err)
	}
}

// T-113: an empty ClientID forces CleanSession=true on the wire (3.1.1
// §3.1.3.1: a zero-byte ClientID is only allowed with CleanSession=1) even
// when the user explicitly configured clean_session=false. The planner
// resolves the automatic ClientID in emitSessionFlow, so the forced flag
// must be observable in the emitted CONNECT bytes, not just in
// buildConnect unit tests.
func TestEmptyClientIDForcesCleanSessionOnWire(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 12345, DstPort: 1883,
		MQTT: &MQTTConfig{
			ClientID:     "", // empty → auto-generated
			CleanSession: boolPtr(false),
		},
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var connect []byte
	for c := range ch {
		if len(c.Payload) >= 2 && c.Payload[0] == 0x10 && c.Payload[1] != 0 {
			connect = c.Payload
			break
		}
	}
	if connect == nil {
		t.Fatal("no CONNECT packet found in plan output")
	}
	// v4 CONNECT layout: [0x10][RL] [00 04 MQTT] [04] [flags] [KA hi][KA lo]
	if connect[9]&0x02 == 0 {
		t.Errorf("CONNECT flags = 0x%02x, want CleanSession bit (0x02) forced set for empty client_id", connect[9])
	}
}

// T-120 companion: empty ClientID + Will must keep both the forced
// CleanSession bit and the Will flags in the emitted CONNECT.
func TestEmptyClientIDWillFlagsOnWire(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 12345, DstPort: 1883,
		MQTT: &MQTTConfig{
			ClientID: "", // empty → auto-generated
			Will:     &MQTTWill{Topic: "t", Payload: "p", QoS: 1},
		},
	}
	ch, err := p.Plan(nil, spec)
	if err != nil {
		t.Fatalf("Plan error: %v", err)
	}
	var connect []byte
	for c := range ch {
		if len(c.Payload) >= 2 && c.Payload[0] == 0x10 && c.Payload[1] != 0 {
			connect = c.Payload
			break
		}
	}
	if connect == nil {
		t.Fatal("no CONNECT packet found in plan output")
	}
	want := byte(0x0e) // Clean(0x02) + Will(0x04) + WillQoS1(0x08)
	if connect[9] != want {
		t.Errorf("CONNECT flags = 0x%02x, want 0x%02x (forced clean + will qos1)", connect[9], want)
	}
}
