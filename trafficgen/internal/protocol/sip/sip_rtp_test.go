package sip

// RTP media sub-flow test points for the SIP planner. These verify that
// the RTP media sub-flow is emitted at the right position in the SIP
// dialog (between ACK and BYE), with the right 4-tuple, RTP header
// fields, and FlowID. Derived from the SIPMedia struct spec in
// types.go and the emit-SIP-media algorithm in sip.go.

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// mediaSpec returns a spec with a 4-message dialog (INVITE → 200 → ACK → BYE)
// where ACK is flagged with EmitMedia=true so RTP frames land between ACK
// and BYE. The dialog mirrors the pcap sample
// /home/pcap_auto/monitor/IP-TCP-10.1.1.231-...-5060-...pcap.
func mediaSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 54100, DstPort: 5060,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		SIP: &core.SIPConfig{
			Dialog: []core.SIPMessage{
				{Method: "INVITE", URI: "sip:callee@example.com", Direction: "up"},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
				{Method: "ACK", URI: "sip:callee@example.com", Direction: "up", EmitMedia: true},
				{Method: "BYE", URI: "sip:callee@example.com", Direction: "up"},
				{StatusCode: 200, StatusText: "OK", Direction: "down"},
			},
			Media: &core.SIPMedia{
				Frames:     5,
				PayloadType: 0,
				FrameSize:  160,
			},
		},
	}
}

// findRTPPackets returns configs whose FlowID ends with ":rtp".
func findRTPPackets(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if strings.HasSuffix(c.FlowID, ":rtp") {
			out = append(out, c)
		}
	}
	return out
}

// findSignalingPackets returns configs whose FlowID does NOT end with ":rtp".
func findSignalingPackets(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if !strings.HasSuffix(c.FlowID, ":rtp") {
			out = append(out, c)
		}
	}
	return out
}

// findPacketWithPayload returns the first config whose L4 protocol is UDP
// (RTP is UDP). Useful for locating RTP packets in wire order.
func findFirstRTPIndex(cfgs []core.PacketConfig) int {
	for i, c := range cfgs {
		if c.L4.Protocol == "udp" {
			return i
		}
	}
	return -1
}

// findPacketWithSIPMethod returns the index of the first config whose payload
// contains the given SIP method (e.g. "ACK", "BYE").
func findPacketWithSIPMethod(cfgs []core.PacketConfig, method string) int {
	for i, c := range cfgs {
		if strings.Contains(string(c.Payload), method+" ") ||
			strings.Contains(string(c.Payload), method+"\r\n") {
			return i
		}
	}
	return -1
}

// TestSIPMedia_RTPSubFlowEmitted verifies that EmitMedia=true on ACK with
// Media set produces 5 RTP packets (Frames=5).
func TestSIPMedia_RTPSubFlowEmitted(t *testing.T) {
	spec := mediaSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)

	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatalf("no RTP packets emitted; want 5")
	}
	if got, want := len(rtp), 5; got != want {
		t.Errorf("len(rtp)=%d, want %d (Frames=5)", got, want)
	}
}

// TestSIPMedia_RTPPositionBetweenACKAndBYE verifies RTP frames land
// AFTER the ACK and BEFORE the BYE in wire order. This is the key SIP
// media semantics: media flows between call setup and teardown.
func TestSIPMedia_RTPPositionBetweenACKAndBYE(t *testing.T) {
	spec := mediaSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)

	idxACK := findPacketWithSIPMethod(cfgs, "ACK")
	if idxACK < 0 {
		t.Fatalf("ACK not found in wire order")
	}
	idxBYE := findPacketWithSIPMethod(cfgs, "BYE")
	if idxBYE < 0 {
		t.Fatalf("BYE not found in wire order")
	}
	if idxACK >= idxBYE {
		t.Fatalf("ACK at %d should precede BYE at %d", idxACK, idxBYE)
	}

	firstRTP := findFirstRTPIndex(cfgs)
	if firstRTP < 0 {
		t.Fatalf("no RTP packet found")
	}
	if firstRTP <= idxACK {
		t.Errorf("first RTP at %d should be after ACK at %d", firstRTP, idxACK)
	}
	if firstRTP >= idxBYE {
		t.Errorf("first RTP at %d should be before BYE at %d", firstRTP, idxBYE)
	}

	// All RTP packets must be between ACK and BYE.
	for i, c := range cfgs {
		if strings.HasSuffix(c.FlowID, ":rtp") {
			if i <= idxACK || i >= idxBYE {
				t.Errorf("RTP packet at index %d not between ACK (%d) and BYE (%d)",
					i, idxACK, idxBYE)
			}
		}
	}
}

// TestSIPMedia_DefaultPorts verifies default RTP ports 5004/5004 when
// the user does not set SrcPort/DstPort.
func TestSIPMedia_DefaultPorts(t *testing.T) {
	spec := mediaSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatalf("no RTP packets")
	}
	first := rtp[0]
	if first.L4.SrcPort != 5004 {
		t.Errorf("RTP SrcPort=%d, want 5004 (default)", first.L4.SrcPort)
	}
	if first.L4.DstPort != 5004 {
		t.Errorf("RTP DstPort=%d, want 5004 (default)", first.L4.DstPort)
	}
}

// TestSIPMedia_UserPortOverride verifies explicit SrcPort/DstPort override
// the 5004 defaults.
func TestSIPMedia_UserPortOverride(t *testing.T) {
	spec := mediaSpec()
	spec.SIP.Media.SrcPort = 10000
	spec.SIP.Media.DstPort = 10002
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatalf("no RTP packets")
	}
	if rtp[0].L4.SrcPort != 10000 {
		t.Errorf("SrcPort=%d, want 10000 (user override)", rtp[0].L4.SrcPort)
	}
	if rtp[0].L4.DstPort != 10002 {
		t.Errorf("DstPort=%d, want 10002 (user override)", rtp[0].L4.DstPort)
	}
}

// TestSIPMedia_RTPHeaderByte0 verifies byte 0 of RTP payload is 0x80
// (V=2, P=0, X=0, CC=0 per RFC 3550 §5.1).
func TestSIPMedia_RTPHeaderByte0(t *testing.T) {
	spec := mediaSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatalf("no RTP packets")
	}
	for i, c := range rtp {
		if len(c.Payload) < 12 {
			t.Errorf("rtp[%d] payload len=%d, want >= 12 (RTP header)", i, len(c.Payload))
			continue
		}
		if c.Payload[0] != 0x80 {
			t.Errorf("rtp[%d] byte0=%#02x, want 0x80 (V=2)", i, c.Payload[0])
		}
	}
}

// TestSIPMedia_RTPHeaderPayloadType verifies byte 1 of RTP payload carries
// the PayloadType in the lower 7 bits (M=0 bit).
func TestSIPMedia_RTPHeaderPayloadType(t *testing.T) {
	spec := mediaSpec()
	spec.SIP.Media.PayloadType = 8 // PCMA
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatalf("no RTP packets")
	}
	for i, c := range rtp {
		if c.Payload[1] != 0x08 {
			t.Errorf("rtp[%d] byte1=%#02x, want 0x08 (PT=8, M=0)", i, c.Payload[1])
		}
	}
}

// TestSIPMedia_RTPSequenceIncrements verifies the RTP sequence number in
// bytes 2-3 increments by 1 per frame.
func TestSIPMedia_RTPSequenceIncrements(t *testing.T) {
	spec := mediaSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) < 2 {
		t.Fatalf("len(rtp)=%d, want >= 2", len(rtp))
	}
	for i := 1; i < len(rtp); i++ {
		prev := uint16(rtp[i-1].Payload[2])<<8 | uint16(rtp[i-1].Payload[3])
		cur := uint16(rtp[i].Payload[2])<<8 | uint16(rtp[i].Payload[3])
		if cur != prev+1 {
			t.Errorf("rtp[%d].seq=%d, want %d (prev+1)", i, cur, prev+1)
		}
	}
}

// TestSIPMedia_RTPTimestampIncrements verifies the RTP timestamp in bytes 4-7
// increments by frameSize per frame (e.g. 160 for G.711 20ms @ 8kHz).
func TestSIPMedia_RTPTimestampIncrements(t *testing.T) {
	spec := mediaSpec()
	spec.SIP.Media.FrameSize = 160
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) < 2 {
		t.Fatalf("len(rtp)=%d, want >= 2", len(rtp))
	}
	for i := 1; i < len(rtp); i++ {
		prev := uint32(rtp[i-1].Payload[4])<<24 |
			uint32(rtp[i-1].Payload[5])<<16 |
			uint32(rtp[i-1].Payload[6])<<8 |
			uint32(rtp[i-1].Payload[7])
		cur := uint32(rtp[i].Payload[4])<<24 |
			uint32(rtp[i].Payload[5])<<16 |
			uint32(rtp[i].Payload[6])<<8 |
			uint32(rtp[i].Payload[7])
		if cur != prev+160 {
			t.Errorf("rtp[%d].ts=%d, want %d (prev+frameSize=160)", i, cur, prev+160)
		}
	}
}

// TestSIPMedia_RTPSSRCConstant verifies the SSRC field (bytes 8-11) is the
// same across all frames in one RTP stream (one SSRC = one stream).
func TestSIPMedia_RTPSSRCConstant(t *testing.T) {
	spec := mediaSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) < 2 {
		t.Fatalf("len(rtp)=%d, want >= 2", len(rtp))
	}
	first := uint32(rtp[0].Payload[8])<<24 |
		uint32(rtp[0].Payload[9])<<16 |
		uint32(rtp[0].Payload[10])<<8 |
		uint32(rtp[0].Payload[11])
	for i := 1; i < len(rtp); i++ {
		cur := uint32(rtp[i].Payload[8])<<24 |
			uint32(rtp[i].Payload[9])<<16 |
			uint32(rtp[i].Payload[10])<<8 |
			uint32(rtp[i].Payload[11])
		if cur != first {
			t.Errorf("rtp[%d].ssrc=%d, want %d (constant SSRC)", i, cur, first)
		}
	}
}

// TestSIPMedia_FlowIDSuffix verifies all RTP packets share the FlowID
// "{parent}:rtp" so they resequence as one stream.
func TestSIPMedia_FlowIDSuffix(t *testing.T) {
	spec := mediaSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatalf("no RTP packets")
	}
	want := "10.0.0.1-10.0.0.2-54100-5060:rtp"
	for i, c := range rtp {
		if c.FlowID != want {
			t.Errorf("rtp[%d].FlowID=%q, want %q", i, c.FlowID, want)
		}
	}
}

// TestSIPMedia_NoMedia verifies that Media=nil produces no RTP packets
// (backward compat with pre-media specs).
func TestSIPMedia_NoMedia(t *testing.T) {
	spec := validSIPSpec() // no Media
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) != 0 {
		t.Errorf("Media=nil but got %d RTP packets, want 0", len(rtp))
	}
}

// TestSIPMedia_EmitFlagFalse verifies that EmitMedia=false on all messages
// suppresses the RTP sub-flow, even when Media is set.
func TestSIPMedia_EmitFlagFalse(t *testing.T) {
	spec := mediaSpec()
	for i := range spec.SIP.Dialog {
		spec.SIP.Dialog[i].EmitMedia = false
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) != 0 {
		t.Errorf("EmitMedia=false but got %d RTP packets, want 0", len(rtp))
	}
}

// TestSIPMedia_FramesDefault verifies Frames=0 defaults to 1 RTP packet.
func TestSIPMedia_FramesDefault(t *testing.T) {
	spec := mediaSpec()
	spec.SIP.Media.Frames = 0
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) != 1 {
		t.Errorf("Frames=0 -> len(rtp)=%d, want 1 (default)", len(rtp))
	}
}

// TestSIPMedia_FrameSizeInPayload verifies the RTP payload is 12 (header) +
// frameSize (placeholder audio) bytes long.
func TestSIPMedia_FrameSizeInPayload(t *testing.T) {
	spec := mediaSpec()
	spec.SIP.Media.FrameSize = 200
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatalf("no RTP packets")
	}
	for i, c := range rtp {
		if len(c.Payload) != 12+200 {
			t.Errorf("rtp[%d] payload len=%d, want %d (12+frameSize=200)",
				i, len(c.Payload), 12+200)
		}
	}
}

// TestSIPMedia_SignalingChannelUnchanged verifies the signaling channel's
// packet count is unchanged when Media is added — the RTP sub-flow is
// purely additive.
func TestSIPMedia_SignalingChannelUnchanged(t *testing.T) {
	withMedia := mediaSpec()
	withoutMedia := mediaSpec()
	withoutMedia.SIP.Media = nil
	for i := range withoutMedia.SIP.Dialog {
		withoutMedia.SIP.Dialog[i].EmitMedia = false
	}

	ch1, _ := NewPlanner().Plan(context.Background(), withMedia)
	ch2, _ := NewPlanner().Plan(context.Background(), withoutMedia)
	cfgsWith := drain(ch1)
	cfgsWithout := drain(ch2)

	sigWith := findSignalingPackets(cfgsWith)
	sigWithout := findSignalingPackets(cfgsWithout)

	if len(sigWith) != len(sigWithout) {
		t.Errorf("signaling packet count: with media=%d, without=%d (should match)",
			len(sigWith), len(sigWithout))
	}
}

// TestSIPMedia_MultipleEmitFlags verifies EmitMedia=true on multiple
// messages emits the RTP sub-flow multiple times (e.g. re-INVITE
// triggering a new media stream).
func TestSIPMedia_MultipleEmitFlags(t *testing.T) {
	spec := mediaSpec()
	// Flag both ACK (already flagged) and BYE.
	for i, m := range spec.SIP.Dialog {
		if m.Method == "BYE" {
			spec.SIP.Dialog[i].EmitMedia = true
		}
	}
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	// 5 frames per emit * 2 emits = 10
	if got, want := len(rtp), 10; got != want {
		t.Errorf("len(rtp)=%d, want %d (2 emits * 5 frames)", got, want)
	}
}

// TestSIPMedia_IPv6Parent verifies RTP sub-flow uses IPv6 EtherType when
// the parent spec uses IPv6 addresses.
func TestSIPMedia_IPv6Parent(t *testing.T) {
	spec := mediaSpec()
	spec.SrcIP = "2001:db8::1"
	spec.DstIP = "2001:db8::2"
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatalf("no RTP packets")
	}
	for i, c := range rtp {
		if c.L2.EtherType != 0x86DD {
			t.Errorf("rtp[%d] EtherType=%#x, want 0x86DD (IPv6)", i, c.L2.EtherType)
		}
	}
}

// TestSIPMedia_Direction verifies RTP frames go in the "up" direction
// (caller→callee, the caller-side RTP stream).
func TestSIPMedia_Direction(t *testing.T) {
	spec := mediaSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) == 0 {
		t.Fatalf("no RTP packets")
	}
	for i, c := range rtp {
		if c.Direction != "up" {
			t.Errorf("rtp[%d] Direction=%q, want \"up\"", i, c.Direction)
		}
	}
}

// TestSIPMedia_PacketIndexContinuity verifies RTP packets' PacketIndex
// continues from the parent's index (no reset, no gaps).
func TestSIPMedia_PacketIndexContinuity(t *testing.T) {
	spec := mediaSpec()
	ch, err := NewPlanner().Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cfgs := drain(ch)
	rtp := findRTPPackets(cfgs)
	if len(rtp) < 2 {
		t.Fatalf("len(rtp)=%d, want >= 2", len(rtp))
	}
	for i := 1; i < len(rtp); i++ {
		if rtp[i].PacketIndex != rtp[i-1].PacketIndex+1 {
			t.Errorf("rtp[%d].PacketIndex=%d, want %d (prev+1)",
				i, rtp[i].PacketIndex, rtp[i-1].PacketIndex+1)
		}
	}
}
