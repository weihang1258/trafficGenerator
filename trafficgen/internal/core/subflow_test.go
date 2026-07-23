package core

import (
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"
)

// collectSubFlow runs EmitSubFlow against a buffered channel and returns the
// emitted PacketConfigs. The channel is closed by a goroutine after emit
// completes; this mirrors how a planner drives EmitSubFlow.
func collectSubFlow(t *testing.T, subIdx int, sub SubFlowSpec, parent FlowSpec, parentFlowID string) []PacketConfig {
	t.Helper()
	ch := make(chan PacketConfig, 512)
	var idx uint64
	ipIDCounter := uint16(1)
	nextIPID := func() uint16 {
		v := ipIDCounter
		ipIDCounter++
		return v
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		EmitSubFlow(ch, subIdx, sub, parent, parentFlowID, time.Now(), &idx, nextIPID)
		close(ch)
	}()

	var out []PacketConfig
	for p := range ch {
		out = append(out, p)
	}
	wg.Wait()
	return out
}

// mustFlowSpec builds a FlowSpec with valid IPs/MACs for sub-flow testing.
func mustFlowSpec() FlowSpec {
	return FlowSpec{
		SrcIP:  "10.0.0.1",
		DstIP:  "20.0.0.1",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		TTL:    64,
	}
}

// TestEmitSubFlow_TCP_HandshakeDataTeardown verifies a TCP sub-flow with
// handshake+data+termination emits the expected packet count: 3 (handshake)
// + 2*segments (each data segment + peer ACK) + 4 (teardown). For a
// 10-byte payload with default MSS=1460, there is 1 segment, so total =
// 3 + 2 + 4 = 9.
func TestEmitSubFlow_TCP_HandshakeDataTeardown(t *testing.T) {
	sub := SubFlowSpec{
		Protocol:    "tcp",
		SrcPort:     50000,
		DstPort:     44000,
		Direction:   "up",
		Payload:     "0123456789", // 10 bytes, single segment under MSS=1460
		Handshake:   true,
		Termination: true,
	}
	cfgs := collectSubFlow(t, 0, sub, mustFlowSpec(), "parent-flow")
	if got, want := len(cfgs), 9; got != want {
		t.Fatalf("len(cfgs)=%d, want %d (3 handshake + 2 data/ack + 4 teardown)", got, want)
	}

	// FlowID suffix: all packets share the parent's flow id + ":sub-0".
	for i, c := range cfgs {
		if c.FlowID != "parent-flow:sub-0" {
			t.Errorf("cfgs[%d].FlowID=%q, want \"parent-flow:sub-0\"", i, c.FlowID)
		}
	}

	// Handshake: SYN, SYN-ACK, ACK (directions up, down, up).
	if cfgs[0].L4.Flags != 0x02 {
		t.Errorf("cfgs[0] (SYN) Flags=0x%02x, want 0x02", cfgs[0].L4.Flags)
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("cfgs[0].Direction=%q, want \"up\"", cfgs[0].Direction)
	}
	if cfgs[1].L4.Flags != 0x12 {
		t.Errorf("cfgs[1] (SYN-ACK) Flags=0x%02x, want 0x12", cfgs[1].L4.Flags)
	}
	if cfgs[1].Direction != "down" {
		t.Errorf("cfgs[1].Direction=%q, want \"down\"", cfgs[1].Direction)
	}
	if cfgs[2].L4.Flags != 0x10 {
		t.Errorf("cfgs[2] (ACK) Flags=0x%02x, want 0x10", cfgs[2].L4.Flags)
	}

	// Data: PSH|ACK (0x18) carrying 10-byte payload, then pure ACK (0x10).
	if cfgs[3].L4.Flags != 0x18 {
		t.Errorf("cfgs[3] (PSH|ACK data) Flags=0x%02x, want 0x18", cfgs[3].L4.Flags)
	}
	if len(cfgs[3].Payload) != 10 {
		t.Errorf("cfgs[3] Payload len=%d, want 10", len(cfgs[3].Payload))
	}
	if cfgs[4].L4.Flags != 0x10 {
		t.Errorf("cfgs[4] (ACK) Flags=0x%02x, want 0x10", cfgs[4].L4.Flags)
	}
	if len(cfgs[4].Payload) != 0 {
		t.Errorf("cfgs[4] Payload len=%d, want 0 (pure ACK)", len(cfgs[4].Payload))
	}

	// Teardown: FIN|ACK, ACK, FIN|ACK, ACK (directions up, down, down, up).
	if cfgs[5].L4.Flags != 0x11 {
		t.Errorf("cfgs[5] (FIN|ACK) Flags=0x%02x, want 0x11", cfgs[5].L4.Flags)
	}
	if cfgs[6].L4.Flags != 0x10 {
		t.Errorf("cfgs[6] (ACK) Flags=0x%02x, want 0x10", cfgs[6].L4.Flags)
	}
	if cfgs[7].L4.Flags != 0x11 {
		t.Errorf("cfgs[7] (FIN|ACK) Flags=0x%02x, want 0x11", cfgs[7].L4.Flags)
	}
	if cfgs[8].L4.Flags != 0x10 {
		t.Errorf("cfgs[8] (ACK) Flags=0x%02x, want 0x10", cfgs[8].L4.Flags)
	}
}

// TestEmitSubFlow_TCP_MSSSegments verifies that a TCP payload larger than
// MSS is split into ceil(len/mss) segments, each followed by a peer ACK.
// For 3000 bytes / MSS=1400, that's 3 segments (1400 + 1400 + 200), so
// 3*2 = 6 data-plane packets, plus 3+4 = 7 control = 13 total.
func TestEmitSubFlow_TCP_MSSSegments(t *testing.T) {
	payload := make([]byte, 3000)
	for i := range payload {
		payload[i] = byte(i)
	}
	sub := SubFlowSpec{
		Protocol:    "tcp",
		SrcPort:     50000,
		DstPort:     44000,
		Direction:   "up",
		Payload:     string(payload),
		Handshake:   true,
		Termination: true,
		MSS:         1400,
	}
	cfgs := collectSubFlow(t, 0, sub, mustFlowSpec(), "parent")
	// 3 handshake + 3*(PSH+ACK) + 4 teardown = 3 + 6 + 4 = 13
	if got, want := len(cfgs), 13; got != want {
		t.Fatalf("len(cfgs)=%d, want %d (3 + 6 + 4)", got, want)
	}

	// Segments are at indices 3, 5, 7 (every other one in the data phase).
	// Segment sizes: 1400, 1400, 200.
	wantSizes := []int{1400, 1400, 200}
	for i, want := range wantSizes {
		idx := 3 + i*2
		if got := len(cfgs[idx].Payload); got != want {
			t.Errorf("segment %d (cfgs[%d]) len=%d, want %d", i, idx, got, want)
		}
	}
}

// TestEmitSubFlow_TCP_NoHandshake verifies that Handshake=false skips the
// 3-way handshake. Only data + teardown are emitted.
func TestEmitSubFlow_TCP_NoHandshake(t *testing.T) {
	sub := SubFlowSpec{
		Protocol:    "tcp",
		SrcPort:     50000,
		DstPort:     44000,
		Payload:     "hi",
		Handshake:   false,
		Termination: true,
	}
	cfgs := collectSubFlow(t, 0, sub, mustFlowSpec(), "p")
	// 0 handshake + 2 data + 4 teardown = 6
	if got, want := len(cfgs), 6; got != want {
		t.Fatalf("len(cfgs)=%d, want %d (0 + 2 + 4)", got, want)
	}
}

// TestEmitSubFlow_TCP_NoTermination verifies that Termination=false skips
// the 4-way teardown.
func TestEmitSubFlow_TCP_NoTermination(t *testing.T) {
	sub := SubFlowSpec{
		Protocol:    "tcp",
		SrcPort:     50000,
		DstPort:     44000,
		Payload:     "hi",
		Handshake:   true,
		Termination: false,
	}
	cfgs := collectSubFlow(t, 0, sub, mustFlowSpec(), "p")
	// 3 handshake + 2 data + 0 teardown = 5
	if got, want := len(cfgs), 5; got != want {
		t.Fatalf("len(cfgs)=%d, want %d (3 + 2 + 0)", got, want)
	}
}

// TestEmitSubFlow_TCP_DirectionDown verifies that Direction="down" sends
// data from server to client (Direction="down" on the data PSH-ACK packet).
// This is the FTP active-mode RETR shape: server pushes file to client.
func TestEmitSubFlow_TCP_DirectionDown(t *testing.T) {
	sub := SubFlowSpec{
		Protocol:    "tcp",
		SrcPort:     50000,
		DstPort:     44000,
		Direction:   "down",
		Payload:     "file-bytes",
		Handshake:   true,
		Termination: true,
	}
	cfgs := collectSubFlow(t, 0, sub, mustFlowSpec(), "p")
	// Data packet is at index 3 (after 3 handshake packets).
	if cfgs[3].Direction != "down" {
		t.Errorf("data packet Direction=%q, want \"down\" (server→client)", cfgs[3].Direction)
	}
	if cfgs[3].L4.SrcPort != 44000 || cfgs[3].L4.DstPort != 50000 {
		t.Errorf("data packet src/dst port swapped: src=%d dst=%d, want src=44000 dst=50000 (server→client)",
			cfgs[3].L4.SrcPort, cfgs[3].L4.DstPort)
	}
	// L2 MACs swapped too (server MAC is source now).
	if cfgs[3].L2.SrcMAC != "02:00:00:00:00:02" {
		t.Errorf("data packet L2.SrcMAC=%q, want server MAC", cfgs[3].L2.SrcMAC)
	}
	if cfgs[3].L3.SrcIP != "20.0.0.1" {
		t.Errorf("data packet L3.SrcIP=%q, want server IP", cfgs[3].L3.SrcIP)
	}
}

// TestEmitSubFlow_UDP_SingleDatagram verifies that a UDP sub-flow emits
// exactly one packet (no handshake, no teardown).
func TestEmitSubFlow_UDP_SingleDatagram(t *testing.T) {
	sub := SubFlowSpec{
		Protocol: "udp",
		SrcPort:  5004,
		DstPort:  5004,
		Payload:  "rtp-frame-data",
	}
	cfgs := collectSubFlow(t, 0, sub, mustFlowSpec(), "p")
	if got, want := len(cfgs), 1; got != want {
		t.Fatalf("len(cfgs)=%d, want %d (UDP = single datagram)", got, want)
	}
	if cfgs[0].L4.Protocol != "udp" {
		t.Errorf("Protocol=%q, want \"udp\"", cfgs[0].L4.Protocol)
	}
	if cfgs[0].L4.SrcPort != 5004 || cfgs[0].L4.DstPort != 5004 {
		t.Errorf("ports src=%d dst=%d, want 5004/5004", cfgs[0].L4.SrcPort, cfgs[0].L4.DstPort)
	}
	if string(cfgs[0].Payload) != "rtp-frame-data" {
		t.Errorf("Payload=%q, want \"rtp-frame-data\"", string(cfgs[0].Payload))
	}
	if cfgs[0].Direction != "up" {
		t.Errorf("Direction=%q, want \"up\" (default)", cfgs[0].Direction)
	}
}

// TestEmitSubFlow_UDP_Down verifies UDP Direction="down" emits server→client.
func TestEmitSubFlow_UDP_Down(t *testing.T) {
	sub := SubFlowSpec{
		Protocol:  "udp",
		SrcPort:   5004,
		DstPort:   5004,
		Direction: "down",
		Payload:   "x",
	}
	cfgs := collectSubFlow(t, 0, sub, mustFlowSpec(), "p")
	if cfgs[0].Direction != "down" {
		t.Errorf("Direction=%q, want \"down\"", cfgs[0].Direction)
	}
	if cfgs[0].L3.SrcIP != "20.0.0.1" {
		t.Errorf("L3.SrcIP=%q, want server IP", cfgs[0].L3.SrcIP)
	}
}

// TestEmitSubFlow_SCTP_HandshakeDataTeardown verifies an SCTP sub-flow
// emits 4-way handshake + 1 DATA + 3-way shutdown = 8 packets.
func TestEmitSubFlow_SCTP_HandshakeDataTeardown(t *testing.T) {
	sub := SubFlowSpec{
		Protocol:    "sctp",
		SrcPort:     38412,
		DstPort:     38412,
		Payload:     "sctp-data",
		Handshake:   true,
		Termination: true,
	}
	cfgs := collectSubFlow(t, 0, sub, mustFlowSpec(), "p")
	// 4 handshake + 1 data + 3 shutdown = 8
	if got, want := len(cfgs), 8; got != want {
		t.Fatalf("len(cfgs)=%d, want %d (4 + 1 + 3)", got, want)
	}

	// Verify SCTP L3 protocol number = 132.
	for i, c := range cfgs {
		if c.L3.Protocol != 132 {
			t.Errorf("cfgs[%d].L3.Protocol=%d, want 132 (SCTP)", i, c.L3.Protocol)
		}
		if c.L4.Protocol != "sctp" {
			t.Errorf("cfgs[%d].L4.Protocol=%q, want \"sctp\"", i, c.L4.Protocol)
		}
	}

	// Verify handshake payload sizes (INIT=20, INIT-ACK=20, COOKIE-ECHO=4, COOKIE-ACK=4).
	// DATA is 16+9 padded to 28. SHUTDOWN=8. SHUTDOWN-ACK/COMPLETE=4.
	wantPayloadSizes := []int{20, 20, 4, 4, 28 /*DATA 16+9=25 padded to 28*/, 8 /*SHUTDOWN*/, 4 /*SHUTDOWN-ACK*/, 4 /*SHUTDOWN-COMPLETE*/}
	for i, want := range wantPayloadSizes {
		if got := len(cfgs[i].Payload); got != want {
			t.Errorf("cfgs[%d] payload len=%d, want %d", i, got, want)
		}
	}

	// DATA chunk's reported length field (in the chunk header) is the
	// UN-padded length (25), not the buffer length (28). Verify this
	// so we know the wire bytes are correct even though the buffer is padded.
	dataChunk := cfgs[4].Payload
	if gotLen := uint16(dataChunk[2])<<8 | uint16(dataChunk[3]); gotLen != 25 {
		t.Errorf("DATA chunk Length field=%d, want 25 (un-padded)", gotLen)
	}
}

// TestEmitSubFlow_PayloadB64 verifies that PayloadB64 overrides Payload and
// is correctly decoded at emit time. Used for binary payloads (e.g. PNG file
// bytes for an FTP STOR).
func TestEmitSubFlow_PayloadB64(t *testing.T) {
	// "AAEC" is base64 for bytes 0x00 0x01 0x02.
	sub := SubFlowSpec{
		Protocol:   "udp",
		SrcPort:    5004,
		DstPort:    5004,
		Payload:    "WRONG",
		PayloadB64: "AAEC",
	}
	cfgs := collectSubFlow(t, 0, sub, mustFlowSpec(), "p")
	if len(cfgs) != 1 {
		t.Fatalf("len(cfgs)=%d, want 1", len(cfgs))
	}
	want := []byte{0x00, 0x01, 0x02}
	if got := cfgs[0].Payload; len(got) != len(want) {
		t.Fatalf("Payload len=%d, want %d", len(got), len(want))
	} else {
		for i, b := range want {
			if got[i] != b {
				t.Errorf("Payload[%d]=0x%02x, want 0x%02x", i, got[i], b)
			}
		}
	}
}

// TestEmitSubFlow_PayloadB64Invalid falls back to Payload when base64 is
// invalid. This avoids a silent zero-byte sub-flow if a user typo's the b64.
func TestEmitSubFlow_PayloadB64Invalid(t *testing.T) {
	sub := SubFlowSpec{
		Protocol:   "udp",
		SrcPort:    5004,
		DstPort:    5004,
		Payload:    "fallback-text",
		PayloadB64: "!!!not-base64!!!",
	}
	cfgs := collectSubFlow(t, 0, sub, mustFlowSpec(), "p")
	if string(cfgs[0].Payload) != "fallback-text" {
		t.Errorf("Payload=%q, want \"fallback-text\" (b64 decode failed, fall back to Payload)", string(cfgs[0].Payload))
	}
}

// TestEmitSubFlow_AltIPsMultiHoming verifies that AltSrcIP/AltDstIP override
// the parent's IPs. This is the SCTP multi-homing shape: heartbeat chunks
// ride a different 4-tuple than the primary association.
func TestEmitSubFlow_AltIPsMultiHoming(t *testing.T) {
	sub := SubFlowSpec{
		Protocol:  "udp",
		SrcPort:   5004,
		DstPort:   5004,
		AltSrcIP:  "10.0.0.2",
		AltDstIP:  "20.0.0.2",
		AltSrcMAC: "02:00:00:00:00:03",
		AltDstMAC: "02:00:00:00:00:04",
		Payload:   "x",
	}
	cfgs := collectSubFlow(t, 0, sub, mustFlowSpec(), "p")
	if cfgs[0].L3.SrcIP != "10.0.0.2" {
		t.Errorf("L3.SrcIP=%q, want \"10.0.0.2\" (AltSrcIP)", cfgs[0].L3.SrcIP)
	}
	if cfgs[0].L3.DstIP != "20.0.0.2" {
		t.Errorf("L3.DstIP=%q, want \"20.0.0.2\" (AltDstIP)", cfgs[0].L3.DstIP)
	}
	if cfgs[0].L2.SrcMAC != "02:00:00:00:00:03" {
		t.Errorf("L2.SrcMAC=%q, want \"02:00:00:00:00:03\" (AltSrcMAC)", cfgs[0].L2.SrcMAC)
	}
	if cfgs[0].L2.DstMAC != "02:00:00:00:00:04" {
		t.Errorf("L2.DstMAC=%q, want \"02:00:00:00:00:04\" (AltDstMAC)", cfgs[0].L2.DstMAC)
	}
}

// TestEmitSubFlow_AltIPsV6EtherType verifies that an IPv6 AltSrcIP switches
// EtherType to 0x86DD (IPv6) on the sub-flow's packets, even when the
// parent's primary flow is IPv4.
func TestEmitSubFlow_AltIPsV6EtherType(t *testing.T) {
	parent := mustFlowSpec() // IPv4 parent
	sub := SubFlowSpec{
		Protocol:  "udp",
		SrcPort:   5004,
		DstPort:   5004,
		AltSrcIP:  "fd00::1",
		AltDstIP:  "fd00::2",
		Payload:   "x",
	}
	cfgs := collectSubFlow(t, 0, sub, parent, "p")
	if cfgs[0].L2.EtherType != EtherTypeIPv6 {
		t.Errorf("EtherType=0x%04x, want 0x%04x (IPv6 from AltSrcIP)", cfgs[0].L2.EtherType, EtherTypeIPv6)
	}
}

// TestEmitSubFlow_IPv6Parent verifies that an IPv6 parent produces IPv6
// sub-flow packets (EtherType + L3 protocol).
func TestEmitSubFlow_IPv6Parent(t *testing.T) {
	parent := FlowSpec{
		SrcIP:  "fd00::1",
		DstIP:  "fd00::2",
		SrcMAC: "02:00:00:00:00:01",
		DstMAC: "02:00:00:00:00:02",
		TTL:    64,
	}
	sub := SubFlowSpec{
		Protocol: "tcp",
		SrcPort:  50000,
		DstPort:  44000,
		Payload:  "x",
	}
	cfgs := collectSubFlow(t, 0, sub, parent, "p")
	if cfgs[0].L2.EtherType != EtherTypeIPv6 {
		t.Errorf("EtherType=0x%04x, want 0x%04x (IPv6 parent)", cfgs[0].L2.EtherType, EtherTypeIPv6)
	}
}

// TestEmitSubFlow_PacketIndexContinuity verifies that EmitSubFlow increments
// the parent's packetIndex counter so the parent's numbering stays continuous
// across primary and sub-flow packets.
func TestEmitSubFlow_PacketIndexContinuity(t *testing.T) {
	sub := SubFlowSpec{
		Protocol: "udp",
		SrcPort:  5004,
		DstPort:  5004,
		Payload:  "x",
	}
	ch := make(chan PacketConfig, 16)
	var idx uint64 = 100 // parent has already emitted 100 packets
	nextIPID := func() uint16 { return 1 }
	EmitSubFlow(ch, 0, sub, mustFlowSpec(), "p", time.Now(), &idx, nextIPID)
	close(ch)

	var cfgs []PacketConfig
	for c := range ch {
		cfgs = append(cfgs, c)
	}
	if len(cfgs) != 1 {
		t.Fatalf("len(cfgs)=%d, want 1", len(cfgs))
	}
	if cfgs[0].PacketIndex != 100 {
		t.Errorf("PacketIndex=%d, want 100 (continuity from parent)", cfgs[0].PacketIndex)
	}
	if idx != 101 {
		t.Errorf("after emit, idx=%d, want 101 (incremented once)", idx)
	}
}

// TestEmitSubFlow_MultipleSubIndexes verifies that subIdx is reflected in the
// FlowID suffix. This is how a planner distinguishes sub-flow 0 from sub-flow
// 1 when emitting multiple sub-flows per parent (e.g. FTP LIST + RETR).
func TestEmitSubFlow_MultipleSubIndexes(t *testing.T) {
	sub := SubFlowSpec{Protocol: "udp", SrcPort: 5004, DstPort: 5004, Payload: "x"}
	for _, subIdx := range []int{0, 1, 2} {
		cfgs := collectSubFlow(t, subIdx, sub, mustFlowSpec(), "parent")
		want := fmt.Sprintf("parent:sub-%d", subIdx)
		if cfgs[0].FlowID != want {
			t.Errorf("subIdx=%d FlowID=%q, want %q", subIdx, cfgs[0].FlowID, want)
		}
	}
}

// TestEmitSubFlow_UnknownProtocol verifies that an unknown protocol emits
// nothing (silently ignored). This keeps the helper forward-compatible — a
// future "quic" sub-flow won't crash old planners.
func TestEmitSubFlow_UnknownProtocol(t *testing.T) {
	sub := SubFlowSpec{
		Protocol: "quic", // not yet implemented
		SrcPort:  443,
		DstPort:  443,
		Payload:  "x",
	}
	cfgs := collectSubFlow(t, 0, sub, mustFlowSpec(), "p")
	if len(cfgs) != 0 {
		t.Errorf("len(cfgs)=%d, want 0 (unknown protocol emits nothing)", len(cfgs))
	}
}

// TestEmitSubFlow_InheritsParentDSCP verifies that the sub-flow inherits the
// parent's DSCP — a parent flow tagged CS1 (0x08) should propagate to all
// sub-flow packets so DPI sees consistent QoS across the signaling+data
// pair.
func TestEmitSubFlow_InheritsParentDSCP(t *testing.T) {
	parent := mustFlowSpec()
	parent.DSCP = 0x08 // CS1
	sub := SubFlowSpec{
		Protocol: "udp",
		SrcPort:  5004,
		DstPort:  5004,
		Payload:  "x",
	}
	cfgs := collectSubFlow(t, 0, sub, parent, "p")
	if cfgs[0].L3.DSCP != 0x08 {
		t.Errorf("L3.DSCP=0x%02x, want 0x08 (inherited CS1 from parent)", cfgs[0].L3.DSCP)
	}
}

// TestEmitSubFlow_InheritsParentVLAN verifies that a VLAN tag on the parent
// propagates to the sub-flow's packets — DPI matching on VLAN should see
// both signaling and data in the same broadcast domain.
func TestEmitSubFlow_InheritsParentVLAN(t *testing.T) {
	parent := mustFlowSpec()
	parent.VLAN = &VLAN{ID: 100, Priority: 3}
	sub := SubFlowSpec{
		Protocol: "udp",
		SrcPort:  5004,
		DstPort:  5004,
		Payload:  "x",
	}
	cfgs := collectSubFlow(t, 0, sub, parent, "p")
	if cfgs[0].L2.VLAN == nil {
		t.Fatalf("L2.VLAN=nil, want inherited VLAN 100/3")
	}
	if cfgs[0].L2.VLAN.ID != 100 {
		t.Errorf("L2.VLAN.ID=%d, want 100", cfgs[0].L2.VLAN.ID)
	}
	if cfgs[0].L2.VLAN.Priority != 3 {
		t.Errorf("L2.VLAN.Priority=%d, want 3", cfgs[0].L2.VLAN.Priority)
	}
}

// TestEmitSubFlow_EmptyPayloadTCP verifies that a TCP sub-flow with no
// payload emits only handshake + teardown (no data packets).
func TestEmitSubFlow_EmptyPayloadTCP(t *testing.T) {
	sub := SubFlowSpec{
		Protocol:    "tcp",
		SrcPort:     50000,
		DstPort:     44000,
		Handshake:   true,
		Termination: true,
		// no payload
	}
	cfgs := collectSubFlow(t, 0, sub, mustFlowSpec(), "p")
	// 3 handshake + 0 data + 4 teardown = 7
	if got, want := len(cfgs), 7; got != want {
		t.Fatalf("len(cfgs)=%d, want %d (3 + 0 + 4, empty payload)", got, want)
	}
}

// TestEmitSubFlow_TTLInheritance verifies that an unset parent TTL falls
// back to DefaultTTL (64) on the sub-flow packets.
func TestEmitSubFlow_TTLInheritance(t *testing.T) {
	parent := mustFlowSpec()
	parent.TTL = 0 // unset
	sub := SubFlowSpec{
		Protocol: "udp",
		SrcPort:  5004,
		DstPort:  5004,
		Payload:  "x",
	}
	cfgs := collectSubFlow(t, 0, sub, parent, "p")
	if cfgs[0].L3.TTL != DefaultTTL {
		t.Errorf("L3.TTL=%d, want %d (DefaultTTL when parent TTL=0)", cfgs[0].L3.TTL, DefaultTTL)
	}
}

// TestSynMSSOptions_Content verifies the SYN options helper emits MSS,
// Window Scale, and SACK-Permitted — the three standard SYN options a real
// TCP stack sends on a sub-flow SYN.
func TestSynMSSOptions_Content(t *testing.T) {
	opts := synMSSOptions(1400)
	if len(opts) != 3 {
		t.Fatalf("len(opts)=%d, want 3 (MSS + WinScale + SACK-Permit)", len(opts))
	}
	if opts[0].Kind != TCPOptMSS {
		t.Errorf("opts[0].Kind=%d, want %d (MSS)", opts[0].Kind, TCPOptMSS)
	}
	if len(opts[0].Data) != 2 {
		t.Errorf("opts[0].Data len=%d, want 2 (MSS is 16-bit)", len(opts[0].Data))
	} else {
		got := uint16(opts[0].Data[0])<<8 | uint16(opts[0].Data[1])
		if got != 1400 {
			t.Errorf("opts[0] MSS=%d, want 1400", got)
		}
	}
	if opts[1].Kind != TCPOptWinScale {
		t.Errorf("opts[1].Kind=%d, want %d (WinScale)", opts[1].Kind, TCPOptWinScale)
	}
	if opts[2].Kind != TCPOptSACKPermit {
		t.Errorf("opts[2].Kind=%d, want %d (SACK-Permit)", opts[2].Kind, TCPOptSACKPermit)
	}
}

// TestSynMSSOptions_ZeroMSSDefaults verifies that passing MSS=0 returns the
// default 1460 — same fallback as the TCP planner's main path.
func TestSynMSSOptions_ZeroMSSDefaults(t *testing.T) {
	opts := synMSSOptions(0)
	if got := uint16(opts[0].Data[0])<<8 | uint16(opts[0].Data[1]); got != 1460 {
		t.Errorf("MSS=0 -> opts[0] MSS=%d, want 1460 (default)", got)
	}
}

// TestSCTPChunkBuilders verifies the SCTP chunk builders produce the correct
// type byte and length for each chunk type. These are wire-format checks
// against RFC 4960 §3.
func TestSCTPChunkBuilders(t *testing.T) {
	// INIT: Type=1, Length=20
	init := buildSCTPINITChunk(0xDEADBEEF)
	if len(init) != 20 {
		t.Errorf("INIT len=%d, want 20", len(init))
	}
	if init[0] != 1 {
		t.Errorf("INIT Type=%d, want 1", init[0])
	}
	if init[3] != 20 {
		t.Errorf("INIT Length=%d, want 20", init[3])
	}
	// InitiateTag at bytes 4-7
	got := uint32(init[4])<<24 | uint32(init[5])<<16 | uint32(init[6])<<8 | uint32(init[7])
	if got != 0xDEADBEEF {
		t.Errorf("INIT InitiateTag=0x%08x, want 0xDEADBEEF", got)
	}

	// COOKIE-ECHO: Type=10, Length=4
	ce := buildSCTPCookieEchoChunk()
	if len(ce) != 4 || ce[0] != 10 || ce[3] != 4 {
		t.Errorf("COOKIE-ECHO=%v, want Type=10 Length=4", ce)
	}

	// COOKIE-ACK: Type=11, Length=4
	ca := buildSCTPCookieAckChunk()
	if len(ca) != 4 || ca[0] != 11 || ca[3] != 4 {
		t.Errorf("COOKIE-ACK=%v, want Type=11 Length=4", ca)
	}

	// DATA: Type=0, Flags=0x03 (B+E), Length=16+len(data) padded to 4-byte boundary
	data := buildSCTPDATAChunk(0x12345678, []byte("hello"))
	// 16 + 5 = 21, padded to 24
	if len(data) != 24 {
		t.Errorf("DATA len=%d, want 24 (padded from 21)", len(data))
	}
	if data[0] != 0 {
		t.Errorf("DATA Type=%d, want 0", data[0])
	}
	if data[1] != 0x03 {
		t.Errorf("DATA Flags=0x%02x, want 0x03 (B+E)", data[1])
	}
	// Length field is the UN-padded length (21)
	gotLen := uint16(data[2])<<8 | uint16(data[3])
	if gotLen != 21 {
		t.Errorf("DATA Length=%d, want 21 (un-padded)", gotLen)
	}

	// SHUTDOWN: Type=7, Length=8
	sd := buildSCTPShutdownChunk(0x12345678)
	if len(sd) != 8 || sd[0] != 7 || sd[3] != 8 {
		t.Errorf("SHUTDOWN=%v, want Type=7 Length=8", sd)
	}

	// SHUTDOWN-ACK: Type=8, Length=4
	sa := buildSCTPShutdownAckChunk()
	if len(sa) != 4 || sa[0] != 8 || sa[3] != 4 {
		t.Errorf("SHUTDOWN-ACK=%v, want Type=8 Length=4", sa)
	}

	// SHUTDOWN-COMPLETE: Type=14, Length=4
	sc := buildSCTPShutdownCompleteChunk()
	if len(sc) != 4 || sc[0] != 14 || sc[3] != 4 {
		t.Errorf("SHUTDOWN-COMPLETE=%v, want Type=14 Length=4", sc)
	}
}

// TestEmitSubFlow_PayloadB64RoundTrip is a sanity check that a base64
// encoded binary payload (e.g. a PNG header) round-trips correctly through
// EmitSubFlow onto the wire.
func TestEmitSubFlow_PayloadB64RoundTrip(t *testing.T) {
	// 8-byte PNG signature.
	pngSig := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	encoded := base64.StdEncoding.EncodeToString(pngSig)
	sub := SubFlowSpec{
		Protocol:  "udp",
		SrcPort:   5004,
		DstPort:   5004,
		PayloadB64: encoded,
	}
	cfgs := collectSubFlow(t, 0, sub, mustFlowSpec(), "p")
	if len(cfgs) != 1 {
		t.Fatalf("len(cfgs)=%d, want 1", len(cfgs))
	}
	if string(cfgs[0].Payload) != string(pngSig) {
		t.Errorf("Payload=%v, want %v (PNG signature)", cfgs[0].Payload, pngSig)
	}
}
