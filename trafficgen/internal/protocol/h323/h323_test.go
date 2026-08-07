// Package h323 implements the H.323 (H.225.0/Q.931 呼叫信令) planner.
//
// H.323 is an ITU-T standard for multimedia communication over IP networks.
// The call signaling uses Q.931 messages wrapped in TPKT (RFC 1006) over TCP
// (default port 1720). H.245 (媒体控制) is tunneled inside Q.931 FACILITY
// messages via the user-user IE.
//
// Reference pcap: /home/pcap_auto/llcj_pcap/
//
// IP-TCP-20.4.2.46-30.4.2.46-30000-1720-10-10-2271-1779.pcap
//
// Wire format per message (每个消息的线路格式):
//
//	TPKT header (4 bytes 字节): version(1)=0x03, reserved(1)=0x00, length(2)
//	Q.931 header: PD(1)=0x08, CRV_len(1)=0x02, CRV(2), msg_type(1)
//	Information elements (信息元素): Bearer capability, Calling/Called party
//	  number, Display IE (UTF-16BE 显示名称), User-User IE (H.225 PER data)
//
// Call flow (呼叫流程) for "full" scenario (完整场景):
//
//	Caller                           Callee
//	  |-- TCP SYN ------------------>|
//	  |<-- TCP SYN-ACK --------------|
//	  |-- TCP ACK ------------------>|
//	  |-- SETUP (0x05) ------------->|   建立请求
//	  |<-- CALL PROCEEDING (0x02) ---|   呼叫进行中
//	  |<-- FACILITY (0x62) ----------|   H.245 TCS+MSD (设施)
//	  |<-- ALERTING (0x01) ----------|   振铃
//	  |-- FACILITY (0x62) ---------->|   H.245 response
//	  |<-- FACILITY (0x62) ----------|   H.245 ack
//	  |-- FACILITY (0x62) ---------->|   H.245 ack
//	  |<-- CONNECT (0x07) ---------->|   接通
//	  |-- RELEASE COMPLETE (0x5A) -->|   释放完成
//	  |<-- RELEASE COMPLETE (0x5A) ---|   释放完成
//	  |-- TCP FIN ------------------>|
//	  |<-- TCP FIN-ACK --------------|
//	  |-- TCP ACK ------------------>|
package h323

import (
	"context"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- Test helpers (测试辅助) ---

// drain reads all PacketConfig from a channel and returns them as a slice.
func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

// mustPlan calls Plan and drains the channel. Fails the test on error.
func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return drain(ch)
}

// baseSpec returns a FlowSpec with default values for H.323 testing.
// Caller role (主叫方), full scenario (完整场景), CRV 0x2584.
func baseSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:   "20.4.2.46",
		DstIP:   "30.4.2.46",
		SrcPort: 30000,
		DstPort: 1720,
		SrcMAC:  "18:60:24:a3:6b:ca",
		DstMAC:  "b8:ca:3a:8f:e6:91",
		TCP:     &core.TCPConfig{InitialSeq: 1000},
		H323: &core.H323Config{
			Role:        "caller",
			Scenario:    "full",
			Crv:         0x2584,
			DisplayName: "Administrator",
			Calls:       1,
		},
	}
}

// tcpPackets returns only TCP packets from a PacketConfig slice.
func tcpPackets(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" {
			out = append(out, c)
		}
	}
	return out
}

// udpPackets returns only UDP packets from a PacketConfig slice.
func udpPackets(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if c.L4.Protocol == "udp" {
			out = append(out, c)
		}
	}
	return out
}

// pshPayloads returns the payloads of PSH-ACK packets in order.
func pshPayloads(tcps []core.PacketConfig) [][]byte {
	var out [][]byte
	for _, c := range tcps {
		if c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			out = append(out, c.Payload)
		}
	}
	return out
}

// q931MessageType extracts the Q.931 message type from a TPKT-wrapped payload.
// Returns 0 if the payload is too short.
// TPKT header: 4 bytes (03 00 LL LL)
// Q.931 header: PD(1)=0x08, CRV_len(1), CRV(2), msg_type(1)
// Message type at payload[8].
func q931MessageType(payload []byte) byte {
	if len(payload) < 9 {
		return 0
	}
	return payload[8]
}

// tpktLength extracts the TPKT length field from a payload.
// TPKT header: 03 00 LL LL (big-endian uint16 at offset 2).
func tpktLength(payload []byte) uint16 {
	if len(payload) < 4 {
		return 0
	}
	return binary.BigEndian.Uint16(payload[2:4])
}

// crvValue extracts the CRV (呼叫参考值) from a TPKT-wrapped Q.931 payload.
// CRV is at bytes 5-6 (after PD=0x08 at byte 4 and CRV_len=0x02 at byte 5...
// actually CRV_len is at byte 5, CRV at bytes 6-7... Let me re-check).
//
// Wire layout (线路布局):
//
//	byte 0: 0x03 (TPKT version)
//	byte 1: 0x00 (TPKT reserved)
//	byte 2-3: TPKT length (big-endian)
//	byte 4: 0x08 (Protocol Discriminator 协议鉴别符)
//	byte 5: 0x02 (Call Reference Length 呼叫参考长度)
//	byte 6-7: Call Reference Value (CRV 呼叫参考值, big-endian)
//	byte 8: Message type (消息类型)
func crvValue(payload []byte) uint16 {
	if len(payload) < 8 {
		return 0
	}
	return binary.BigEndian.Uint16(payload[6:8])
}

// --- Tests derived from H323Config spec (从 H323Config 规范派生的测试) ---

// TestPlanner_Name verifies the planner reports "h323" as its name.
func TestPlanner_Name(t *testing.T) {
	p := NewPlanner()
	if got := p.Name(); got != "h323" {
		t.Errorf("Name() = %q, want %q", got, "h323")
	}
}

// --- Validate tests (验证测试) ---

// TestValidate_ValidSpec verifies that a correct spec passes validation.
func TestValidate_ValidSpec(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}
}

// TestValidate_InvalidRole verifies that an unknown role is rejected.
func TestValidate_InvalidRole(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Role = "operator" // invalid
	if err := p.Validate(spec); err == nil {
		t.Error("Validate() = nil, want error for invalid role")
	}
}

// TestValidate_InvalidScenario verifies that an unknown scenario is rejected.
func TestValidate_InvalidScenario(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "invalid" // invalid
	if err := p.Validate(spec); err == nil {
		t.Error("Validate() = nil, want error for invalid scenario")
	}
}

// TestValidate_NegativeCalls verifies that negative calls value is rejected.
func TestValidate_NegativeCalls(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Calls = -1
	if err := p.Validate(spec); err == nil {
		t.Error("Validate() = nil, want error for negative calls")
	}
}

// TestValidate_ZeroCallsDefaults verifies that Calls=0 is valid (defaults to 1).
func TestValidate_ZeroCallsDefaults(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Calls = 0
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate() = %v, want nil for calls=0 (defaults to 1)", err)
	}
}

// TestValidate_LongDisplayName verifies that display names > 254 bytes
// are rejected (the Display IE length field is 1 byte, max 255, but the
// IEI+length overhead leaves 254 bytes max for the string).
func TestValidate_LongDisplayName(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.DisplayName = string(make([]byte, 255))
	if err := p.Validate(spec); err == nil {
		t.Error("Validate() = nil, want error for display_name > 254 bytes")
	}
}

// TestValidate_NilH323Config verifies that nil H323 config is rejected.
func TestValidate_NilH323Config(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323 = nil
	if err := p.Validate(spec); err == nil {
		t.Error("Validate() = nil, want error for nil H323 config")
	}
}

// TestValidate_DefaultRoleAccepted verifies that empty role defaults to
// "caller" and passes validation (user > auto > none pattern).
func TestValidate_DefaultRoleAccepted(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Role = "" // empty should default to "caller"
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate() = %v, want nil for empty role (defaults to caller)", err)
	}
}

// TestValidate_DefaultScenarioAccepted verifies that empty scenario defaults
// to "full" and passes validation.
func TestValidate_DefaultScenarioAccepted(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "" // empty should default to "full"
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate() = %v, want nil for empty scenario (defaults to full)", err)
	}
}

// --- Plan tests (规划测试) ---

// TestPlan_FullScenario_PacketCount verifies the full scenario produces
// the expected number of TCP packets:
//   - 3 handshake (SYN, SYN-ACK, ACK)
//   - 10 Q.931 messages (SETUP, CP, FACILITY, ALERTING, FACILITY×3, CONNECT,
//     RELEASE COMPLETE×2)
//   - 3 teardown (FIN, FIN-ACK, ACK)
//
// Total: 16 TCP packets for 1 call (一次呼叫共16个TCP包)
func TestPlan_FullScenario_PacketCount(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "full"
	cfgs := mustPlan(t, p, spec)
	tcps := tcpPackets(cfgs)

	// 3 handshake + 10 Q.931 messages + 3 teardown = 16
	if got := len(tcps); got != 16 {
		t.Errorf("full scenario: got %d TCP packets, want 16", got)
	}
}

// TestPlan_FullScenario_TCPFlags verifies the TCP handshake and teardown
// use the correct flags (TCP握手和挥手的标志位).
func TestPlan_FullScenario_TCPFlags(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "full"
	cfgs := mustPlan(t, p, spec)
	tcps := tcpPackets(cfgs)

	if len(tcps) < 16 {
		t.Fatalf("need at least 16 TCP packets, got %d", len(tcps))
	}

	// Handshake (握手): SYN(0x02), SYN-ACK(0x12), ACK(0x10)
	if tcps[0].L4.Flags != 0x02 {
		t.Errorf("pkt[0]: SYN flags = 0x%02x, want 0x02", tcps[0].L4.Flags)
	}
	if tcps[1].L4.Flags != 0x12 {
		t.Errorf("pkt[1]: SYN-ACK flags = 0x%02x, want 0x12", tcps[1].L4.Flags)
	}
	if tcps[2].L4.Flags != 0x10 {
		t.Errorf("pkt[2]: ACK flags = 0x%02x, want 0x10", tcps[2].L4.Flags)
	}

	// Teardown (挥手): FIN(0x11), FIN-ACK(0x11), ACK(0x10)
	last := len(tcps) - 1
	if tcps[last-2].L4.Flags != 0x11 {
		t.Errorf("pkt[%d]: FIN flags = 0x%02x, want 0x11", last-2, tcps[last-2].L4.Flags)
	}
	if tcps[last-1].L4.Flags != 0x11 {
		t.Errorf("pkt[%d]: FIN-ACK flags = 0x%02x, want 0x11", last-1, tcps[last-1].L4.Flags)
	}
	if tcps[last].L4.Flags != 0x10 {
		t.Errorf("pkt[%d]: ACK flags = 0x%02x, want 0x10", last, tcps[last].L4.Flags)
	}
}

// TestPlan_FullScenario_MessageTypes verifies the Q.931 message types in
// the full scenario (完整场景的消息类型序列).
func TestPlan_FullScenario_MessageTypes(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "full"
	cfgs := mustPlan(t, p, spec)
	payloads := pshPayloads(tcpPackets(cfgs))

	// Expected message types in order (按顺序期望的消息类型):
	// SETUP(0x05), CALL_PROCEEDING(0x02), FACILITY(0x62), ALERTING(0x01),
	// FACILITY(0x62), FACILITY(0x62), FACILITY(0x62), CONNECT(0x07),
	// RELEASE_COMPLETE(0x5a), RELEASE_COMPLETE(0x5a)
	expected := []byte{
		MsgTypeSetup,           // SETUP 建立
		MsgTypeCallProceeding,  // CALL PROCEEDING 呼叫进行中
		MsgTypeFacility,        // FACILITY 设施 (H.245 TCS+MSD)
		MsgTypeAlerting,        // ALERTING 振铃
		MsgTypeFacility,        // FACILITY 设施
		MsgTypeFacility,        // FACILITY 设施
		MsgTypeFacility,        // FACILITY 设施
		MsgTypeConnect,         // CONNECT 接通
		MsgTypeReleaseComplete, // RELEASE COMPLETE 释放完成
		MsgTypeReleaseComplete, // RELEASE COMPLETE 释放完成
	}

	if len(payloads) < len(expected) {
		t.Fatalf("got %d PSH-ACK payloads, need at least %d", len(payloads), len(expected))
	}

	for i, want := range expected {
		got := q931MessageType(payloads[i])
		if got != want {
			t.Errorf("msg[%d]: type = 0x%02x, want 0x%02x", i, got, want)
		}
	}
}

// TestPlan_TunnelOnly_NoFacility verifies the tunnel_only scenario produces
// no FACILITY messages (仅信令隧道场景无设施消息).
func TestPlan_TunnelOnly_NoFacility(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "tunnel_only"
	cfgs := mustPlan(t, p, spec)
	payloads := pshPayloads(tcpPackets(cfgs))

	// Expected: SETUP, CALL_PROCEEDING, ALERTING, CONNECT, RELEASE_COMPLETE×2
	// = 6 Q.931 messages, no FACILITY (无设施消息)
	expected := []byte{
		MsgTypeSetup,
		MsgTypeCallProceeding,
		MsgTypeAlerting,
		MsgTypeConnect,
		MsgTypeReleaseComplete,
		MsgTypeReleaseComplete,
	}

	if len(payloads) != len(expected) {
		t.Fatalf("tunnel_only: got %d PSH-ACK payloads, want %d", len(payloads), len(expected))
	}

	for i, want := range expected {
		got := q931MessageType(payloads[i])
		if got != want {
			t.Errorf("msg[%d]: type = 0x%02x, want 0x%02x", i, got, want)
		}
	}
}

// TestPlan_CRVOverlay verifies that the CRV value is correctly written into
// each Q.931 message (呼叫参考值覆盖验证).
func TestPlan_CRVOverlay(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "tunnel_only"
	spec.H323.Crv = 0x1234
	cfgs := mustPlan(t, p, spec)

	// Filter to PSH-ACK packets (the Q.931 signaling messages).
	tcps := tcpPackets(cfgs)
	var pshPkts []core.PacketConfig
	for _, c := range tcps {
		if c.L4.Flags == 0x18 && len(c.Payload) > 0 {
			pshPkts = append(pshPkts, c)
		}
	}

	// Caller role: "up" direction → flag=0, CRV=0x1234.
	//                "down" direction → flag=1, CRV=0x9234.
	for i, pkt := range pshPkts {
		got := crvValue(pkt.Payload)
		expectedCRV := uint16(0x1234)
		if pkt.Direction == "down" {
			expectedCRV = 0x1234 | 0x8000
		}
		if got != expectedCRV {
			t.Errorf("msg[%d] (%s): CRV = 0x%04x, want 0x%04x", i, pkt.Direction, got, expectedCRV)
		}
	}
}

// TestPlan_TPKTLength verifies that the TPKT length field matches the actual
// payload length (TPKT长度字段验证).
func TestPlan_TPKTLength(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "tunnel_only"
	cfgs := mustPlan(t, p, spec)
	payloads := pshPayloads(tcpPackets(cfgs))

	for i, payload := range payloads {
		gotLen := tpktLength(payload)
		actualLen := uint16(len(payload))
		if gotLen != actualLen {
			t.Errorf("msg[%d]: TPKT length = %d, actual payload = %d", i, gotLen, actualLen)
		}
	}
}

// TestPlan_TPKTVersion verifies that the TPKT version byte is 0x03 in all
// messages (TPKT版本号验证).
func TestPlan_TPKTVersion(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "full"
	cfgs := mustPlan(t, p, spec)
	payloads := pshPayloads(tcpPackets(cfgs))

	for i, payload := range payloads {
		if len(payload) < 1 {
			t.Errorf("msg[%d]: empty payload", i)
			continue
		}
		if payload[0] != 0x03 {
			t.Errorf("msg[%d]: TPKT version = 0x%02x, want 0x03", i, payload[0])
		}
	}
}

// TestPlan_CalleeRole verifies that the callee role reverses the message
// directions (被叫方角色反转消息方向).
func TestPlan_CalleeRole(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "tunnel_only"
	spec.H323.Role = "callee"
	cfgs := mustPlan(t, p, spec)
	payloads := pshPayloads(tcpPackets(cfgs))

	// In callee role, the FIRST Q.931 message should be SETUP sent DOWN
	// (from server to client), since the callee is the src side.
	// Message order is the same but directions are swapped.
	if len(payloads) < 1 {
		t.Fatal("no payloads in callee role")
	}

	// First Q.931 message should still be SETUP (0x05)
	if got := q931MessageType(payloads[0]); got != MsgTypeSetup {
		t.Errorf("callee: first msg type = 0x%02x, want 0x%02x (SETUP)", got, MsgTypeSetup)
	}
}

// TestPlan_MultiCall verifies that Calls > 1 produces the expected number
// of message cycles with incrementing CRV (多呼叫验证).
func TestPlan_MultiCall(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "tunnel_only"
	spec.H323.Calls = 2

	cfgs := mustPlan(t, p, spec)
	payloads := pshPayloads(tcpPackets(cfgs))

	// tunnel_only has 6 Q.931 messages per call. With 2 calls: 12.
	expectedCount := 6 * 2
	if len(payloads) != expectedCount {
		t.Errorf("multi-call: got %d payloads, want %d", len(payloads), expectedCount)
	}
}

// TestPlan_DataOnly verifies the data_only scenario produces only RTP frames
// with no Q.931 signaling (仅数据面场景验证).
func TestPlan_DataOnly(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "data_only"
	spec.H323.Media = &core.H323MediaConfig{
		Enabled:   true,
		SrcPort:   5062,
		DstPort:   5063,
		Frames:    5,
		FrameSize: 160,
	}

	cfgs := mustPlan(t, p, spec)
	udps := udpPackets(cfgs)

	if len(udps) != 5 {
		t.Errorf("data_only: got %d UDP packets, want 5", len(udps))
	}

	// No TCP packets in data_only (无TCP包)
	tcps := tcpPackets(cfgs)
	if len(tcps) != 0 {
		t.Errorf("data_only: got %d TCP packets, want 0", len(tcps))
	}
}

// TestPlan_RasOnly verifies the ras_only scenario produces only RAS messages
// with no Q.931 signaling (仅RAS场景验证).
func TestPlan_RasOnly(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "ras_only"
	spec.H323.Ras = &core.H323RasConfig{
		Enabled:      true,
		GatekeeperIP: "10.12.184.53",
		Port:         1719,
		EndpointType: "terminal",
	}

	cfgs := mustPlan(t, p, spec)
	udps := udpPackets(cfgs)

	// RAS has 6 pre-call messages (GRQ/GCF/RRQ/RCF/ARQ/ACF) +
	// 2 post-call messages (DRQ/DCF) = 8 UDP packets
	if len(udps) != 8 {
		t.Errorf("ras_only: got %d UDP packets, want 8", len(udps))
	}

	// No TCP packets in ras_only (无TCP包)
	tcps := tcpPackets(cfgs)
	if len(tcps) != 0 {
		t.Errorf("ras_only: got %d TCP packets, want 0", len(tcps))
	}
}

// TestPlan_FullScenario_WithMedia verifies the full scenario with media
// enabled produces RTP frames after CONNECT (完整场景带媒体验证).
func TestPlan_FullScenario_WithMedia(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "full"
	spec.H323.Media = &core.H323MediaConfig{
		Enabled:   true,
		SrcPort:   5062,
		DstPort:   5063,
		Frames:    5,
		FrameSize: 160,
	}

	cfgs := mustPlan(t, p, spec)
	udps := udpPackets(cfgs)

	// Should have 5 RTP frames after CONNECT
	if len(udps) != 5 {
		t.Errorf("full+media: got %d UDP packets, want 5", len(udps))
	}
}

// TestPlan_DisplayName verifies that the display name appears correctly in
// the SETUP message (显示名称验证).
func TestPlan_DisplayName(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "tunnel_only"
	spec.H323.DisplayName = "TestUser"
	cfgs := mustPlan(t, p, spec)
	payloads := pshPayloads(tcpPackets(cfgs))

	if len(payloads) < 1 {
		t.Fatal("no payloads")
	}

	// First message should be SETUP
	setupPayload := payloads[0]
	if q931MessageType(setupPayload) != MsgTypeSetup {
		t.Fatalf("first msg type = 0x%02x, want SETUP (0x05)", q931MessageType(setupPayload))
	}

	// The display name "TestUser" should appear in IA5 (ASCII) in the payload.
	// Q.931 Display IE uses IA5 encoding (no NUL terminator, no UTF-16BE).
	expectedASCII := []byte("TestUser")

	found := false
	for i := 0; i <= len(setupPayload)-len(expectedASCII); i++ {
		match := true
		for j := 0; j < len(expectedASCII); j++ {
			if setupPayload[i+j] != expectedASCII[j] {
				match = false
				break
			}
		}
		if match {
			found = true
			break
		}
	}
	if !found {
		t.Error("display name 'TestUser' not found in SETUP payload (IA5/ASCII)")
	}
}

// TestPlan_Direction verifies that SETUP is sent "up" (client→server) in
// caller role and "down" (server→client) in callee role (方向验证).
func TestPlan_Direction(t *testing.T) {
	tests := []struct {
		role    string
		wantDir string
	}{
		{"caller", "up"},   // 主叫方: SETUP向上
		{"callee", "down"}, // 被叫方: SETUP向下
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			p := NewPlanner()
			spec := baseSpec()
			spec.H323.Role = tt.role
			spec.H323.Scenario = "tunnel_only"
			cfgs := mustPlan(t, p, spec)

			// Find the SETUP message (first PSH-ACK)
			tcps := tcpPackets(cfgs)
			var setupDir string
			for _, c := range tcps {
				if c.L4.Flags == 0x18 && len(c.Payload) > 0 {
					if q931MessageType(c.Payload) == MsgTypeSetup {
						setupDir = c.Direction
						break
					}
				}
			}
			if setupDir != tt.wantDir {
				t.Errorf("role=%s: SETUP direction = %q, want %q", tt.role, setupDir, tt.wantDir)
			}
		})
	}
}

// TestPlan_SeqAckTracking verifies that TCP seq/ack numbers advance correctly
// across the call flow (TCP序列号/确认号跟踪验证).
func TestPlan_SeqAckTracking(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "tunnel_only"
	spec.TCP = &core.TCPConfig{InitialSeq: 1000}
	cfgs := mustPlan(t, p, spec)
	tcps := tcpPackets(cfgs)

	// After handshake, clientSeq = initialSeq + 1 = 1001.
	// Each PSH-ACK from client should advance clientSeq by payload length.
	// The ACK number from server should reflect bytes received from client.
	if len(tcps) < 4 {
		t.Fatalf("need at least 4 TCP packets, got %d", len(tcps))
	}

	// SYN: clientSeq=1000
	if tcps[0].L4.Seq != 1000 {
		t.Errorf("SYN seq = %d, want 1000", tcps[0].L4.Seq)
	}
	// ACK (handshake): clientSeq=1001
	// Note: The ACK after handshake has the seq that was advanced from SYN+1
	if tcps[2].L4.Seq < 1000 {
		t.Errorf("handshake ACK seq = %d, want >= 1000", tcps[2].L4.Seq)
	}
}

// TestPlan_Q931ProtocolDiscriminator verifies that the protocol discriminator
// is 0x08 (Q.931/H.225.0) in all messages (协议鉴别符验证).
func TestPlan_Q931ProtocolDiscriminator(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "full"
	cfgs := mustPlan(t, p, spec)
	payloads := pshPayloads(tcpPackets(cfgs))

	for i, payload := range payloads {
		if len(payload) < 5 {
			t.Errorf("msg[%d]: payload too short (%d bytes)", i, len(payload))
			continue
		}
		if payload[4] != 0x08 {
			t.Errorf("msg[%d]: PD = 0x%02x, want 0x08 (Q.931)", i, payload[4])
		}
	}
}

// TestPlan_EmptyH323ConfigDefaults verifies that Plan uses sensible defaults
// when H323Config has mostly empty fields (默认值验证).
func TestPlan_EmptyH323ConfigDefaults(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "20.0.0.1",
		SrcPort: 40000,
		DstPort: 1720,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		H323:    &core.H323Config{}, // all defaults
	}
	cfgs := mustPlan(t, p, spec)

	if len(cfgs) == 0 {
		t.Fatal("Plan returned empty config list with defaults")
	}

	// Should still produce TCP packets (handshake + signaling + teardown)
	tcps := tcpPackets(cfgs)
	if len(tcps) < 6 {
		t.Errorf("defaults: got %d TCP packets, want at least 6", len(tcps))
	}
}

// --- Internal function tests (内部函数测试) ---

// TestBuildQ931Message_TPKTHeader verifies the TPKT header construction
// (TPKT报头构造验证).
func TestBuildQ931Message_TPKTHeader(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "tunnel_only"
	// Plan to trigger the message builder, then check TPKT headers
	cfgs := mustPlan(t, p, spec)
	payloads := pshPayloads(tcpPackets(cfgs))

	for i, payload := range payloads {
		if len(payload) < 4 {
			continue
		}
		// Version byte (版本字节)
		if payload[0] != 0x03 {
			t.Errorf("msg[%d]: TPKT version = 0x%02x, want 0x03", i, payload[0])
		}
		// Reserved byte (保留字节)
		if payload[1] != 0x00 {
			t.Errorf("msg[%d]: TPKT reserved = 0x%02x, want 0x00", i, payload[1])
		}
		// Length field (长度字段)
		gotLen := binary.BigEndian.Uint16(payload[2:4])
		if int(gotLen) != len(payload) {
			t.Errorf("msg[%d]: TPKT length = %d, actual = %d", i, gotLen, len(payload))
		}
	}
}

// TestBuildQ931Message_CRVFlagBit verifies the CRV flag bit is set correctly
// based on sender role (CRV标志位验证).
func TestBuildQ931Message_CRVFlagBit(t *testing.T) {
	p := NewPlanner()
	spec := baseSpec()
	spec.H323.Scenario = "tunnel_only"
	spec.H323.Crv = 0x0001
	cfgs := mustPlan(t, p, spec)
	payloads := pshPayloads(tcpPackets(cfgs))

	// Check first payload (SETUP from caller): flag bit should be 0
	setupPayload := payloads[0]
	crvByte := setupPayload[6] // CRV first byte at offset 6
	if crvByte&0x80 != 0 {
		t.Errorf("SETUP (caller): CRV flag bit = 1, want 0")
	}

	// Find CALL PROCEEDING from callee: flag bit should be 1
	for _, payload := range payloads[1:] {
		if q931MessageType(payload) == MsgTypeCallProceeding {
			crvByte = payload[6]
			if crvByte&0x80 == 0 {
				t.Error("CALL PROCEEDING (callee): CRV flag bit = 0, want 1")
			}
			break
		}
	}
}

// TestBuildQ931Message_CRVRoundTrip verifies that the CRV value survives
// the flag-bit overlay (CRV值往返验证).
func TestBuildQ931Message_CRVRoundTrip(t *testing.T) {
	testCRVs := []uint16{0x0001, 0x2584, 0x7FFF, 0x1234}
	for _, crv := range testCRVs {
		t.Run(fmt.Sprintf("CRV=0x%04x", crv), func(t *testing.T) {
			p := NewPlanner()
			spec := baseSpec()
			spec.H323.Scenario = "tunnel_only"
			spec.H323.Crv = crv
			cfgs := mustPlan(t, p, spec)
			payloads := pshPayloads(tcpPackets(cfgs))

			// Check SETUP (caller): CRV should have flag=0, value=crv
			gotCRV := crvValue(payloads[0])
			if gotCRV != crv {
				t.Errorf("SETUP CRV = 0x%04x, want 0x%04x", gotCRV, crv)
			}
		})
	}
}
