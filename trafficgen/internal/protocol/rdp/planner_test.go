// Package rdp tests for the RDP planner.
//
// This file contains integration-style tests that exercise the high-level
// Planner API (Name / Validate / Plan) and verify that the planner emits
// the expected packet sequence at the wire-shape level. Byte-level
// invariants for individual encoders live in planner_testpoints_test.go.
package rdp

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// makeBaseSpec returns a minimal valid RDP FlowSpec for testing.
func makeBaseSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:  "192.168.1.1",
		DstIP:  "192.168.1.2",
		SrcPort: 12345,
		SrcMAC: "aa:bb:cc:dd:ee:ff",
		DstMAC: "11:22:33:44:55:66",
		RDP: &core.RDPConfig{
			SecurityLayer: "tls",
			DesktopWidth:  1920,
			DesktopHeight: 1080,
			ColorDepth:    5,
			ClientName:    "WIN10-CL",
			UserName:      "Administrator",
			Password:      "P@ssw0rd",
		},
	}
}

// drainConfigs reads everything from configChan into a slice.
func drainConfigs(t *testing.T, ch <-chan core.PacketConfig) []core.PacketConfig {
	t.Helper()
	var configs []core.PacketConfig
	for cfg := range ch {
		configs = append(configs, cfg)
	}
	return configs
}

func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if got := p.Name(); got != "rdp" {
		t.Errorf("Name() = %s, want rdp", got)
	}
}

func TestPlanner_Validate_NilRDP(t *testing.T) {
	p := NewPlanner()
	err := p.Validate(core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, DstPort: 3389,
	})
	if err == nil || !strings.Contains(err.Error(), "RDP config is required") {
		t.Errorf("expected RDP-required error, got %v", err)
	}
}

func TestPlanner_Validate_InvalidIP(t *testing.T) {
	p := NewPlanner()
	err := p.Validate(core.FlowSpec{
		SrcIP: "not-an-ip", DstIP: "192.168.1.2",
		SrcPort: 1000,
		RDP:     &core.RDPConfig{},
	})
	if err == nil || !strings.Contains(err.Error(), "invalid source IP") {
		t.Errorf("expected invalid-source-IP error, got %v", err)
	}
}

func TestPlanner_Validate_BadPort(t *testing.T) {
	p := NewPlanner()
	err := p.Validate(core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000, DstPort: 80,
		RDP: &core.RDPConfig{},
	})
	if err == nil || !strings.Contains(err.Error(), "DstPort must be 3389") {
		t.Errorf("expected DstPort-must-be-3389 error, got %v", err)
	}
}

func TestPlanner_Validate_BadSecurityLayer(t *testing.T) {
	p := NewPlanner()
	err := p.Validate(core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000,
		RDP:     &core.RDPConfig{SecurityLayer: "bogus"},
	})
	if err == nil || !strings.Contains(err.Error(), "not in {standard,tls,nla,nla_ex}") {
		t.Errorf("expected bad-security-layer error, got %v", err)
	}
}

func TestPlanner_Validate_ClientNameTooLong(t *testing.T) {
	p := NewPlanner()
	err := p.Validate(core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000,
		RDP:     &core.RDPConfig{ClientName: "WIN10-CLIENT"}, // 12 chars -> 24 bytes > 16
	})
	if err == nil || !strings.Contains(err.Error(), "clientName must be <= 16 bytes") {
		t.Errorf("expected clientName-too-long error, got %v", err)
	}
}

func TestPlanner_Validate_BadDesktop(t *testing.T) {
	p := NewPlanner()
	err := p.Validate(core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000,
		RDP:     &core.RDPConfig{DesktopWidth: 100}, // < 200
	})
	if err == nil || !strings.Contains(err.Error(), "desktopWidth") {
		t.Errorf("expected desktopWidth error, got %v", err)
	}
}

func TestPlanner_Validate_BadColorDepth(t *testing.T) {
	p := NewPlanner()
	err := p.Validate(core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000,
		RDP:     &core.RDPConfig{ColorDepth: 6},
	})
	if err == nil || !strings.Contains(err.Error(), "colorDepth") {
		t.Errorf("expected colorDepth error, got %v", err)
	}
}

func TestPlanner_Validate_TooManyChannels(t *testing.T) {
	p := NewPlanner()
	chans := make([]core.RDPChannel, 32)
	for i := range chans {
		chans[i] = core.RDPChannel{Name: "ch"}
	}
	err := p.Validate(core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000,
		RDP:     &core.RDPConfig{Channels: chans},
	})
	if err == nil || !strings.Contains(err.Error(), "channelCount must be <= 31") {
		t.Errorf("expected channelCount error, got %v", err)
	}
}

func TestPlanner_Validate_BadChannelName(t *testing.T) {
	p := NewPlanner()
	err := p.Validate(core.FlowSpec{
		SrcIP: "1.1.1.1", DstIP: "2.2.2.2",
		SrcPort: 1000,
		RDP: &core.RDPConfig{
			Channels: []core.RDPChannel{{Name: "too-long-name"}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Errorf("expected channel-name-too-long error, got %v", err)
	}
}

func TestPlanner_Plan_DefaultFlow(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec()

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// Sanity: at minimum we expect 3 (SYN/SYN-ACK/ACK) + the
	// RDP-specific PDUs + 4 teardown packets. For the default flow
	// with no channels/data events that is ~17 packets.
	if len(configs) < 10 {
		t.Fatalf("Expected at least 10 packets in default flow, got %d", len(configs))
	}

	// First three packets must be the TCP handshake.
	if configs[0].L4.Flags != 0x02 {
		t.Errorf("configs[0].Flags = 0x%x, want SYN (0x02)", configs[0].L4.Flags)
	}
	if configs[1].L4.Flags != 0x12 {
		t.Errorf("configs[1].Flags = 0x%x, want SYN-ACK (0x12)", configs[1].L4.Flags)
	}
	if configs[2].L4.Flags != 0x10 {
		t.Errorf("configs[2].Flags = 0x%x, want ACK (0x10)", configs[2].L4.Flags)
	}

	// All handshake packets have no payload.
	for i := 0; i < 3; i++ {
		if len(configs[i].Payload) != 0 {
			t.Errorf("handshake configs[%d].Payload should be empty, got %d bytes", i, len(configs[i].Payload))
		}
	}

	// Packet indices must be strictly increasing.
	for i := 1; i < len(configs); i++ {
		if configs[i].PacketIndex != configs[i-1].PacketIndex+1 {
			t.Errorf("PacketIndex not monotonic at i=%d: %d -> %d", i, configs[i-1].PacketIndex, configs[i].PacketIndex)
		}
	}
}

func TestPlanner_Plan_DirectionFlip(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec()

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// Index 0 is client->server (SYN).
	if configs[0].Direction != "up" {
		t.Errorf("configs[0].Direction = %s, want up", configs[0].Direction)
	}
	// Index 1 is server->client (SYN-ACK).
	if configs[1].Direction != "down" {
		t.Errorf("configs[1].Direction = %s, want down", configs[1].Direction)
	}
}

func TestPlanner_Plan_TLSPayloadByte(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec() // SecurityLayer=tls

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// Find the first up packet after the handshake (index 3). It is the
	// X.224 CR payload, wrapped in TPKT. First byte = 0x03 (TPKT version).
	if len(configs) < 4 {
		t.Fatalf("Expected at least 4 packets, got %d", len(configs))
	}
	pkt := configs[3]
	if pkt.Direction != "up" {
		t.Errorf("configs[3].Direction = %s, want up", pkt.Direction)
	}
	if len(pkt.Payload) < 4 {
		t.Fatalf("configs[3].Payload too short: %d", len(pkt.Payload))
	}
	if pkt.Payload[0] != TPKTVersion {
		t.Errorf("TPKT version = 0x%x, want 0x03", pkt.Payload[0])
	}
	// TPKT length is the next two bytes (big-endian) and must equal
	// 4 + len(payload).
	wantLen := uint16(len(pkt.Payload))
	gotLen := binary.BigEndian.Uint16(pkt.Payload[2:4])
	if gotLen != wantLen {
		t.Errorf("TPKT length = %d, want %d", gotLen, wantLen)
	}
}

func TestPlanner_Plan_StandardSecurityAddsSecurityExchange(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec()
	spec.RDP.SecurityLayer = "standard"
	spec.RDP.EncryptionMethods = 0x02 // 128-bit RC4

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// In Standard mode there must be a Security Exchange PDU (SEC_EXCHANGE_PKT
	// flag 0x0080 appears inside the X.224 DT-wrapped payload). Look for
	// it among the up packets. The PDU's TPKT header is followed by an
	// X.224 DT header (LI=2, Code=0xF0), then by an RDP security header.
	// The RDP header's 4-byte flags field starts with SEC_EXCHANGE_PKT=0x0080
	// in little-endian, so the bytes are 0x80 0x00 0x00 0x00.
	found := false
	for _, cfg := range configs {
		if cfg.Direction != "up" {
			continue
		}
		if bytes.Contains(cfg.Payload, []byte{0x80, 0x00, 0x00, 0x00}) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Standard mode: no SEC_EXCHANGE_PKT (0x80 0x00 0x00 0x00) payload found")
	}
}

func TestPlanner_Plan_NLASkipsClientInfo(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec()
	spec.RDP.SecurityLayer = "nla"

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// In NLA mode the planner does NOT emit a Client Info PDU. We can
	// detect this by the absence of the INFO_UNICODE=0x10 byte sequence
	// (the Client Info PDU flags appear as LE 0x10 0x00 followed by the
	// codePage field). However, a more robust check is that the sequence
	// of PDU-up-packet-counts is shorter than the TLS equivalent.
	spec.RDP.SecurityLayer = "tls"
	ch2, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs2 := drainConfigs(t, ch2)

	if len(configs) >= len(configs2) {
		t.Errorf("NLA flow should be shorter than TLS flow (no Client Info); NLA=%d, TLS=%d", len(configs), len(configs2))
	}
}

func TestPlanner_Plan_ChannelJoinEmit(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec()
	spec.RDP.Channels = []core.RDPChannel{
		{Name: "cliprdr", Options: 0xC0000000},
		{Name: "rdpdr", Options: 0xC0000000},
	}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// Channel-Join Requests carry the MCS reason byte 0x38 inside the
	// X.224 DT-wrapped payload. Count up-payloads containing 0x38.
	countCJReq := 0
	for _, cfg := range configs {
		if cfg.Direction != "up" {
			continue
		}
		// The MCS reason byte follows TPKT(4) + X.224 DT(3).
		if len(cfg.Payload) >= 8 && cfg.Payload[7] == MCSChannelJoinRequest {
			countCJReq++
		}
	}
	// We expect: I/O (1003) + cliprdr (1004) + rdpdr (1005) = 3.
	if countCJReq != 3 {
		t.Errorf("Channel-Join Requests = %d, want 3 (I/O + 2 static)", countCJReq)
	}
}

func TestPlanner_Plan_ChannelJoinIDsAreCorrect(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec()
	spec.RDP.Channels = []core.RDPChannel{
		{Name: "cliprdr"},
		{Name: "rdpdr"},
	}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// Collect MCS ChannelId values from each up packet's Channel-Join
	// request. Layout after TPKT+X.224 DT (7 bytes): reason(1) + initiator(2)
	// + channelId(2).
	var chanIDs []uint16
	for _, cfg := range configs {
		if cfg.Direction != "up" || len(cfg.Payload) < 12 {
			continue
		}
		if cfg.Payload[7] != MCSChannelJoinRequest {
			continue
		}
		chanID := uint16(cfg.Payload[10])<<8 | uint16(cfg.Payload[11])
		chanIDs = append(chanIDs, chanID)
	}
	wantIDs := []uint16{1003, 1004, 1005}
	if len(chanIDs) != len(wantIDs) {
		t.Fatalf("Got %d Channel-Join IDs, want %d", len(chanIDs), len(wantIDs))
	}
	for i, want := range wantIDs {
		if chanIDs[i] != want {
			t.Errorf("chanIDs[%d] = %d, want %d", i, chanIDs[i], want)
		}
	}
}

func TestPlanner_Plan_ContextCancel(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec()
	spec.RDP.DataEvents = []core.RDPDataEvent{
		{Type: "fastpath_input_keyboard"},
		{Type: "fastpath_input_keyboard"},
		{Type: "fastpath_input_keyboard"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// With a pre-cancelled context the goroutine should bail out
	// quickly. We accept anything up to 3 packets (the goroutine may
	// have already emitted the TCP handshake before the first ctx
	// check, plus the next phase's first emit).
	if len(configs) > 3 {
		t.Errorf("Expected at most 3 packets after ctx cancel, got %d", len(configs))
	}
}

func TestPlanner_Plan_DataEventAddsFastPath(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec()
	spec.RDP.DataEvents = []core.RDPDataEvent{
		{Type: "fastpath_input_keyboard"},
	}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// Look for a FastPath Input PDU. The actionHeader high 2 bits = 0
	// (Input). The header byte will be (numEvents & 0x0F).
	found := false
	for _, cfg := range configs {
		if cfg.Direction != "up" {
			continue
		}
		if len(cfg.Payload) >= 2 && cfg.Payload[0]&0xC0 == FastPathInputAction {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("No FastPath Input PDU emitted for fastpath_input_keyboard event")
	}
}

func TestPlanner_Plan_ChannelJoinFailureSkipsChannel(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec()
	spec.RDP.Channels = []core.RDPChannel{
		{Name: "cliprdr"},
		{Name: "rdpdr"},
	}
	// Simulate server rejecting the second channel via a ServerResponses marker.
	spec.RDP.ServerResponses = []core.RDPServerResponse{
		{Type: "channel_join_failure", Payload: []byte("rdpdr")},
	}

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// Count down-payloads whose MCS Channel-Join Confirm result byte = 4.
	countRej := 0
	for _, cfg := range configs {
		if cfg.Direction != "down" || len(cfg.Payload) < 13 {
			continue
		}
		if cfg.Payload[7] != MCSChannelJoinConfirm {
			continue
		}
		if cfg.Payload[12] == 4 { // result byte
			countRej++
		}
	}
	if countRej != 1 {
		t.Errorf("Expected 1 rejected channel (rdpdr), got %d", countRej)
	}
}

func TestPlanner_Plan_TCPTeardown(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec()

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs := drainConfigs(t, ch)

	// Last 4 packets are the TCP teardown: FIN, ACK, FIN, ACK.
	if len(configs) < 4 {
		t.Fatalf("Need >= 4 packets, got %d", len(configs))
	}
	tail := configs[len(configs)-4:]
	if tail[0].L4.Flags != 0x11 || tail[1].L4.Flags != 0x10 || tail[2].L4.Flags != 0x11 || tail[3].L4.Flags != 0x10 {
		t.Errorf("TCP teardown flags = [%x %x %x %x], want [11 10 11 10]",
			tail[0].L4.Flags, tail[1].L4.Flags, tail[2].L4.Flags, tail[3].L4.Flags)
	}
}

func TestPlanner_Plan_SkipCapability(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec()
	spec.RDP.SkipCapability = true

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs1 := drainConfigs(t, ch)

	// Compare with non-skipped version.
	spec.RDP.SkipCapability = false
	ch2, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs2 := drainConfigs(t, ch2)

	if len(configs1) >= len(configs2) {
		t.Errorf("SkipCapability flow should be shorter; got %d vs %d", len(configs1), len(configs2))
	}
}

func TestPlanner_Plan_SkipLicense(t *testing.T) {
	p := NewPlanner()
	spec := makeBaseSpec()
	spec.RDP.SkipLicense = true

	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs1 := drainConfigs(t, ch)

	spec.RDP.SkipLicense = false
	ch2, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	configs2 := drainConfigs(t, ch2)

	// SkipLicense drops 2 packets (License Request + License Info).
	if len(configs2)-len(configs1) != 2 {
		t.Errorf("SkipLicense should drop exactly 2 packets; got diff %d", len(configs2)-len(configs1))
	}
}