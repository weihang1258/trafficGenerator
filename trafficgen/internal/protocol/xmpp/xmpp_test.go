package xmpp

// XMPP planner tests, derived from the reference pcap
// /home/pcap_auto/llcj_pcap/IP-TCP-10.3.1.89-20.3.1.89-58340-5222-11-7-1203-1392.pcap
// (18 frames, SCRAM-SHA-1 auth session).
//
// Wire-order model: handshake 3 + signaling N (stream open, features, SASL
// auth, stream restart, post-auth features, bind, session) + presence + messages
// + stream close 2 + teardown 3. A PLAIN auth session with presence is 18 TCP
// packets. Bare ACKs from the reference pcap are not emitted — consistent with
// every other planner.

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- helpers (辅助函数) ---

func drain(ch <-chan core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return drain(ch)
}

func mustPlanCtx(t *testing.T, ctx context.Context, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	return drain(ch)
}

// xmppSpec returns a base XMPP spec (返回基础XMPP规格): PLAIN auth with presence,
// deterministic client ISN when initialSeq != 0.
func xmppSpec(initialSeq uint32) core.FlowSpec {
	boolTrue := true
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 58340, DstPort: 5222,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		Xmpp: &core.XmppConfig{
			Presence: &boolTrue,
		},
	}
	if initialSeq != 0 {
		spec.TCP = &core.TCPConfig{InitialSeq: initialSeq}
	}
	return spec
}

// tcpPackets returns the TCP packet configs in wire order (返回TCP包配置序列).
func tcpPackets(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" {
			out = append(out, c)
		}
	}
	return out
}

// pshPayloads returns the PSH-ACK payloads in wire order (返回PSH-ACK负载序列).
func pshPayloads(tcps []core.PacketConfig) []string {
	var out []string
	for _, c := range tcps {
		if c.L4.Flags == tcpPSHACK {
			out = append(out, string(c.Payload))
		}
	}
	return out
}

// --- §1 Validate (验证) ---

// TestValidate_NilConfig: XmppConfig 为 nil 时报错.
func TestValidate_NilConfig(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 58340, DstPort: 5222,
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "XmppConfig is required") {
		t.Errorf("Validate(nil config) = %v, want XmppConfig is required", err)
	}
}

// TestValidate_InvalidSrcIP: 无效 SrcIP 时报错.
func TestValidate_InvalidSrcIP(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "bad-ip", DstIP: "20.0.0.1",
		Xmpp: &core.XmppConfig{},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid SrcIP") {
		t.Errorf("Validate(bad SrcIP) = %v, want invalid SrcIP", err)
	}
}

// TestValidate_InvalidDstIP: 无效 DstIP 时报错.
func TestValidate_InvalidDstIP(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "bad-ip",
		Xmpp: &core.XmppConfig{},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid DstIP") {
		t.Errorf("Validate(bad DstIP) = %v, want invalid DstIP", err)
	}
}

// TestValidate_UnsupportedAuthMechanism: 不支持的认证机制报错.
func TestValidate_UnsupportedAuthMechanism(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		Xmpp: &core.XmppConfig{AuthMechanism: "GSSAPI"},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "unsupported auth mechanism") {
		t.Errorf("Validate(GSSAPI) = %v, want unsupported auth mechanism", err)
	}
}

// TestValidate_InvalidMessageDirection: 无效消息方向报错.
func TestValidate_InvalidMessageDirection(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		Xmpp: &core.XmppConfig{
			Messages: []core.XmppMessage{
				{Direction: "sideways"},
			},
		},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "invalid direction") {
		t.Errorf("Validate(bad msg direction) = %v, want invalid direction", err)
	}
}

// TestValidate_MSSTooSmall: MSS 过小报错.
func TestValidate_MSSTooSmall(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		TCP:  &core.TCPConfig{MSS: 100},
		Xmpp: &core.XmppConfig{},
	}
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "TCP.MSS") {
		t.Errorf("Validate(MSS=100) = %v, want TCP.MSS too small", err)
	}
}

// TestValidate_SupportedMechanisms: 所有支持的认证机制都通过.
func TestValidate_SupportedMechanisms(t *testing.T) {
	p := NewPlanner()
	for _, mech := range []string{"PLAIN", "DIGEST-MD5", "SCRAM-SHA-1", "ANONYMOUS"} {
		spec := core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
			Xmpp: &core.XmppConfig{AuthMechanism: mech},
		}
		if err := p.Validate(spec); err != nil {
			t.Errorf("Validate(%s) = %v, want nil", mech, err)
		}
	}
}

// TestValidate_IPv6: IPv6 地址通过验证.
func TestValidate_IPv6(t *testing.T) {
	p := NewPlanner()
	spec := core.FlowSpec{
		SrcIP: "2e01::46e", DstIP: "2e02::46e",
		Xmpp: &core.XmppConfig{},
	}
	if err := p.Validate(spec); err != nil {
		t.Errorf("Validate(IPv6) = %v, want nil", err)
	}
}

// --- §2 Plan packet count (包计数) ---

// TestPlan_PLAIN_PacketCount: PLAIN 认证的默认会话应有固定数量的 TCP 包.
// Handshake(3) + stream-open(1) + features(1) + auth-up(1) + success(1) +
// restart(1) + post-features(1) + bind(1) + bind-result(1) + session(1) +
// session-result(1) + presence(1) + stream-close(2) + teardown(3) = 19 packets.
func TestPlan_PLAIN_PacketCount(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100) // deterministic ISN
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)

	want := 19
	if len(tcps) != want {
		t.Fatalf("PLAIN session got %d TCP packets, want %d", len(tcps), want)
	}
}

// TestPlan_Names: Name() 返回 "xmpp".
func TestPlan_Names(t *testing.T) {
	p := NewPlanner()
	if got := p.Name(); got != "xmpp" {
		t.Errorf("Name() = %q, want %q", got, "xmpp")
	}
}

// TestPlan_DIGESTMD5_PacketCount: DIGEST-MD5 会话比 PLAIN 多 2 个包 (2 个挑战响应).
func TestPlan_DIGESTMD5_PacketCount(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	spec.Xmpp.AuthMechanism = "DIGEST-MD5"
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)

	// DIGEST-MD5: auth-up(1) + challenge(1) + response(1) + success(1)
	// vs PLAIN: auth-up(1) + success(1) = 2 more packets
	// Base PLAIN=19, +2 = 21
	want := 21
	if len(tcps) != want {
		t.Fatalf("DIGEST-MD5 session got %d TCP packets, want %d", len(tcps), want)
	}
}

// TestPlan_SCRAMSHA1_PacketCount: SCRAM-SHA-1 会话比 PLAIN 多 4 个包.
func TestPlan_SCRAMSHA1_PacketCount(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	spec.Xmpp.AuthMechanism = "SCRAM-SHA-1"
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)

	// SCRAM-SHA-1: auth(1) + challenge(1) + response(1) + challenge(1) + response(1) + success(1)
	// vs PLAIN: auth(1) + success(1) = 4 more packets
	// Base PLAIN=19, +4 = 23
	want := 23
	if len(tcps) != want {
		t.Fatalf("SCRAM-SHA-1 session got %d TCP packets, want %d", len(tcps), want)
	}
}

// TestPlan_ANONYMOUS_PacketCount: ANONYMOUS 会话与 PLAIN 包数相同.
func TestPlan_ANONYMOUS_PacketCount(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	spec.Xmpp.AuthMechanism = "ANONYMOUS"
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)

	want := 19
	if len(tcps) != want {
		t.Fatalf("ANONYMOUS session got %d TCP packets, want %d", len(tcps), want)
	}
}

// TestPlan_NoPresence_PacketCount: 关闭 presence 少 1 个包.
func TestPlan_NoPresence_PacketCount(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	boolFalse := false
	spec.Xmpp.Presence = &boolFalse
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)

	want := 18
	if len(tcps) != want {
		t.Fatalf("No-presence PLAIN session got %d TCP packets, want %d", len(tcps), want)
	}
}

// TestPlan_NilPresenceDefaultOn: nil Presence 指针默认为 true (发送 presence).
func TestPlan_NilPresenceDefaultOn(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	spec.Xmpp.Presence = nil // explicit nil → default on
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)

	// Should match PLAIN+presence = 19
	want := 19
	if len(tcps) != want {
		t.Fatalf("nil-Presence PLAIN session got %d TCP packets, want %d (presence should default on)", len(tcps), want)
	}
}

// TestPlan_WithMessages_PacketCount: 消息数影响包数.
func TestPlan_WithMessages_PacketCount(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	spec.Xmpp.Messages = []core.XmppMessage{
		{Direction: "up", Body: "Hello"},
		{Direction: "down", Body: "Hi"},
	}
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)

	// Base(19) + 2 messages = 21
	want := 21
	if len(tcps) != want {
		t.Fatalf("PLAIN+2msg session got %d TCP packets, want %d", len(tcps), want)
	}
}

// --- §3 TCP flags (TCP标志位) ---

// TestPlan_TCPFlags: 验证握手和挥手标志位.
func TestPlan_TCPFlags(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)

	// First 3 packets: SYN, SYN-ACK, ACK
	if tcps[0].L4.Flags != tcpSYN {
		t.Errorf("pkt[0] flags = 0x%02x, want SYN (0x02)", tcps[0].L4.Flags)
	}
	if tcps[1].L4.Flags != tcpSYNACK {
		t.Errorf("pkt[1] flags = 0x%02x, want SYN-ACK (0x12)", tcps[1].L4.Flags)
	}
	if tcps[2].L4.Flags != tcpACK {
		t.Errorf("pkt[2] flags = 0x%02x, want ACK (0x10)", tcps[2].L4.Flags)
	}

	// Last 3 packets: FIN-ACK, FIN-ACK, ACK
	last := len(tcps) - 3
	if tcps[last].L4.Flags != tcpFINACK {
		t.Errorf("pkt[%d] flags = 0x%02x, want FIN-ACK (0x11)", last, tcps[last].L4.Flags)
	}
	if tcps[last+1].L4.Flags != tcpFINACK {
		t.Errorf("pkt[%d] flags = 0x%02x, want FIN-ACK (0x11)", last+1, tcps[last+1].L4.Flags)
	}
	if tcps[last+2].L4.Flags != tcpACK {
		t.Errorf("pkt[%d] flags = 0x%02x, want ACK (0x10)", last+2, tcps[last+2].L4.Flags)
	}
}

// TestPlan_SYNHasTCPOptions: SYN 包应包含 TCP 选项 (MSS/WinScale/SACK).
func TestPlan_SYNHasTCPOptions(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)

	syn := tcps[0]
	if len(syn.L4.TCPOptions) != 3 {
		t.Fatalf("SYN TCPOptions count = %d, want 3 (MSS+WinScale+SACK)", len(syn.L4.TCPOptions))
	}
	if syn.L4.TCPOptions[0].Kind != core.TCPOptMSS {
		t.Errorf("opt[0] Kind = %d, want MSS (%d)", syn.L4.TCPOptions[0].Kind, core.TCPOptMSS)
	}
	if syn.L4.TCPOptions[1].Kind != core.TCPOptWinScale {
		t.Errorf("opt[1] Kind = %d, want WinScale (%d)", syn.L4.TCPOptions[1].Kind, core.TCPOptWinScale)
	}
	if syn.L4.TCPOptions[2].Kind != core.TCPOptSACKPermit {
		t.Errorf("opt[2] Kind = %d, want SACKPermit (%d)", syn.L4.TCPOptions[2].Kind, core.TCPOptSACKPermit)
	}
}

// --- §4 Payload content (负载内容) ---

// TestPlan_StreamOpenContent: 流开启标签内容正确.
func TestPlan_StreamOpenContent(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)
	payloads := pshPayloads(tcps)

	// First PSH-ACK (index 0) is the client stream open
	if len(payloads) < 1 {
		t.Fatal("no PSH-ACK payloads found")
	}
	want := "<?xml version='1.0' ?><stream:stream to='example.com' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
	if payloads[0] != want {
		t.Errorf("stream open = %q, want %q", payloads[0], want)
	}
}

// TestPlan_StreamFeaturesContent: 服务端流功能特性包含 SASL mechanisms.
func TestPlan_StreamFeaturesContent(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)
	payloads := pshPayloads(tcps)

	// Second PSH-ACK (index 1) is the server stream features
	if len(payloads) < 2 {
		t.Fatal("not enough PSH-ACK payloads")
	}
	features := payloads[1]
	if !strings.Contains(features, "<stream:features>") {
		t.Errorf("features missing <stream:features>: %q", features)
	}
	if !strings.Contains(features, "<mechanism>PLAIN</mechanism>") {
		t.Errorf("features missing PLAIN mechanism: %q", features)
	}
	if !strings.Contains(features, "<mechanism>SCRAM-SHA-1</mechanism>") {
		t.Errorf("features missing SCRAM-SHA-1 mechanism: %q", features)
	}
	if !strings.Contains(features, "<starttls") {
		t.Errorf("features missing starttls: %q", features)
	}
}

// TestPlan_PLAINAuthContent: PLAIN 认证负载正确编码.
func TestPlan_PLAINAuthContent(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	spec.Xmpp.Username = "alice"
	spec.Xmpp.Password = "secret"
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)
	payloads := pshPayloads(tcps)

	// Third PSH-ACK (index 2) is the auth element
	if len(payloads) < 3 {
		t.Fatal("not enough PSH-ACK payloads")
	}
	authPayload := payloads[2]
	if !strings.Contains(authPayload, "mechanism='PLAIN'") {
		t.Errorf("auth missing mechanism='PLAIN': %q", authPayload)
	}
	// Check base64 encoding: \0alice\0secret
	expected := base64.StdEncoding.EncodeToString([]byte("\x00alice\x00secret"))
	if !strings.Contains(authPayload, expected) {
		t.Errorf("auth payload missing base64 credentials %q: %q", expected, authPayload)
	}
}

// TestPlan_BindContent: 资源绑定请求内容正确.
func TestPlan_BindContent(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	spec.Xmpp.JID = "alice@example.com"
	spec.Xmpp.Resource = "phone"
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)
	payloads := pshPayloads(tcps)

	// Find bind request
	found := false
	for _, p := range payloads {
		if strings.Contains(p, "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'") &&
			strings.Contains(p, "<resource>phone</resource>") {
			found = true
			break
		}
	}
	if !found {
		t.Error("bind request with resource='phone' not found in payloads")
	}
}

// TestPlan_BindResultContent: 绑定结果包含完整 JID.
func TestPlan_BindResultContent(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	spec.Xmpp.JID = "alice@example.com"
	spec.Xmpp.Resource = "phone"
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)
	payloads := pshPayloads(tcps)

	found := false
	for _, p := range payloads {
		if strings.Contains(p, "<jid>alice@example.com/phone</jid>") {
			found = true
			break
		}
	}
	if !found {
		t.Error("bind result with full JID not found")
	}
}

// TestPlan_SessionIQ: 会话建立 IQ 请求和结果都存在.
func TestPlan_SessionIQ(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)
	payloads := pshPayloads(tcps)

	foundReq := false
	foundResult := false
	for _, p := range payloads {
		if strings.Contains(p, "type='set' id='sess_1'") &&
			strings.Contains(p, "session xmlns='urn:ietf:params:xml:ns:xmpp-session'") {
			foundReq = true
		}
		if strings.Contains(p, "type='result' id='sess_1'") {
			foundResult = true
		}
	}
	if !foundReq {
		t.Error("session request IQ not found")
	}
	if !foundResult {
		t.Error("session result IQ not found")
	}
}

// TestPlan_Presence: 存在状态 <presence/> 存在.
func TestPlan_Presence(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)
	payloads := pshPayloads(tcps)

	found := false
	for _, p := range payloads {
		if p == "<presence/>" {
			found = true
			break
		}
	}
	if !found {
		t.Error("presence stanza <presence/> not found in payloads")
	}
}

// TestPlan_StreamClose: 流关闭标签存在.
func TestPlan_StreamClose(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)
	payloads := pshPayloads(tcps)

	count := 0
	for _, p := range payloads {
		if p == "</stream:stream>" {
			count++
		}
	}
	// Both client and server send stream close
	if count != 2 {
		t.Errorf("stream close count = %d, want 2 (client + server)", count)
	}
}

// --- §5 Sequence numbers (序列号) ---

// TestPlan_SeqAckTracking: 验证序列号跟踪正确.
func TestPlan_SeqAckTracking(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(1000) // deterministic client ISN = 1000
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)

	// SYN packet: seq=1000, ack=0
	if tcps[0].L4.Seq != 1000 {
		t.Errorf("SYN seq = %d, want 1000", tcps[0].L4.Seq)
	}
	if tcps[0].L4.Ack != 0 {
		t.Errorf("SYN ack = %d, want 0", tcps[0].L4.Ack)
	}

	// SYN-ACK: seq=serverISN (random), ack=1001
	if tcps[1].L4.Ack != 1001 {
		t.Errorf("SYN-ACK ack = %d, want 1001", tcps[1].L4.Ack)
	}

	// ACK: seq=1001
	if tcps[2].L4.Seq != 1001 {
		t.Errorf("ACK seq = %d, want 1001", tcps[2].L4.Seq)
	}
}

// --- §6 Direction (方向) ---

// TestPlan_Directions: 验证每个包的方向.
func TestPlan_Directions(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	spec.Xmpp.Messages = []core.XmppMessage{
		{Direction: "up", Body: "Hello"},
		{Direction: "down", Body: "Hi back"},
	}
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)

	// First 3: up, down, up (handshake)
	wantDirs := []string{"up", "down", "up"}
	for i, want := range wantDirs {
		if tcps[i].Direction != want {
			t.Errorf("pkt[%d] direction = %q, want %q", i, tcps[i].Direction, want)
		}
	}

	// Find message payloads and check their directions
	payloads := make(map[string]string) // payload → direction
	for _, c := range tcps {
		if c.L4.Flags == tcpPSHACK {
			payloads[string(c.Payload)] = c.Direction
		}
	}
	if dir, ok := payloads["<message to='bob@example.com' type='chat'><body>Hello</body></message>"]; ok {
		if dir != "up" {
			t.Errorf("up message direction = %q, want up", dir)
		}
	} else {
		t.Error("Hello message not found")
	}
	if dir, ok := payloads["<message to='bob@example.com' type='chat'><body>Hi back</body></message>"]; ok {
		if dir != "down" {
			t.Errorf("down message direction = %q, want down", dir)
		}
	} else {
		t.Error("Hi back message not found")
	}
}

// --- §7 Custom config (自定义配置) ---

// TestPlan_CustomFrom: 自定义 From 域名.
func TestPlan_CustomFrom(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	spec.Xmpp.From = "custom.example.org"
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)
	payloads := pshPayloads(tcps)

	if !strings.Contains(payloads[0], "to='custom.example.org'") {
		t.Errorf("stream open missing custom from: %q", payloads[0])
	}
}

// TestPlan_CustomStreamID: 自定义流 ID.
func TestPlan_CustomStreamID(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	spec.Xmpp.StreamID = "deadbeef"
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)
	payloads := pshPayloads(tcps)

	if !strings.Contains(payloads[1], "id='deadbeef'") {
		t.Errorf("features missing custom stream id: %q", payloads[1])
	}
}

// TestPlan_CustomMessageTo: 自定义消息接收方.
func TestPlan_CustomMessageTo(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	spec.Xmpp.Messages = []core.XmppMessage{
		{Direction: "up", To: "charlie@example.com", Body: "Hey"},
	}
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)
	payloads := pshPayloads(tcps)

	found := false
	for _, p := range payloads {
		if strings.Contains(p, "to='charlie@example.com'") && strings.Contains(p, "<body>Hey</body>") {
			found = true
			break
		}
	}
	if !found {
		t.Error("custom message to charlie not found")
	}
}

// --- §8 L2/L3 fields (二层/三层字段) ---

// TestPlan_L2Fields: 验证 L2 MAC 和 EtherType.
func TestPlan_L2Fields(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)

	// SYN: client→server MACs
	if tcps[0].L2.SrcMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("SYN SrcMAC = %q, want aa:bb:cc:dd:ee:ff", tcps[0].L2.SrcMAC)
	}
	if tcps[0].L2.DstMAC != "11:22:33:44:55:66" {
		t.Errorf("SYN DstMAC = %q, want 11:22:33:44:55:66", tcps[0].L2.DstMAC)
	}
	// SYN-ACK: reversed MACs
	if tcps[1].L2.SrcMAC != "11:22:33:44:55:66" {
		t.Errorf("SYN-ACK SrcMAC = %q, want 11:22:33:44:55:66", tcps[1].L2.SrcMAC)
	}
}

// TestPlan_L3Protocol: IP 协议应为 6 (TCP).
func TestPlan_L3Protocol(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)

	for i, c := range tcps {
		if c.L3.Protocol != 6 {
			t.Errorf("pkt[%d] L3 protocol = %d, want 6 (TCP)", i, c.L3.Protocol)
		}
	}
}

// TestPlan_IPv6EtherType: IPv6 地址的 EtherType 为 0x86DD.
func TestPlan_IPv6EtherType(t *testing.T) {
	p := NewPlanner()
	boolTrue := true
	spec := core.FlowSpec{
		SrcIP: "2e01::46e", DstIP: "2e02::46e",
		SrcPort: 58340, DstPort: 5222,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		Xmpp:   &core.XmppConfig{Presence: &boolTrue},
	}
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)

	if tcps[0].L2.EtherType != 0x86DD {
		t.Errorf("IPv6 SYN EtherType = 0x%04x, want 0x86DD", tcps[0].L2.EtherType)
	}
}

// --- §9 Context cancellation (上下文取消) ---

// TestPlan_ContextCancellation: 上下文取消时 Plan 应优雅退出.
func TestPlan_ContextCancellation(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}

	// Drain should complete quickly since context is already cancelled
	pkts := drain(ch)
	// We may get 0 packets or very few; just verify no panic
	t.Logf("cancelled plan produced %d packets", len(pkts))
}

// --- §10 DIGEST-MD5 payload (DIGEST-MD5负载) ---

// TestPlan_DIGESTMD5_ChallengeResponse: DIGEST-MD5 挑战响应负载正确.
func TestPlan_DIGESTMD5_ChallengeResponse(t *testing.T) {
	p := NewPlanner()
	spec := xmppSpec(100)
	spec.Xmpp.AuthMechanism = "DIGEST-MD5"
	pkts := mustPlan(t, p, spec)
	tcps := tcpPackets(pkts)
	payloads := pshPayloads(tcps)

	// auth element
	foundAuth := false
	for _, p := range payloads {
		if strings.Contains(p, "mechanism='DIGEST-MD5'") {
			foundAuth = true
			break
		}
	}
	if !foundAuth {
		t.Error("DIGEST-MD5 auth element not found")
	}

	// challenge
	foundChallenge := false
	for _, p := range payloads {
		if strings.Contains(p, "<challenge") && strings.Contains(p, nsSASL) {
			foundChallenge = true
			break
		}
	}
	if !foundChallenge {
		t.Error("DIGEST-MD5 challenge not found")
	}

	// success
	foundSuccess := false
	for _, p := range payloads {
		if strings.Contains(p, "<success") && strings.Contains(p, nsSASL) {
			foundSuccess = true
			break
		}
	}
	if !foundSuccess {
		t.Error("DIGEST-MD5 success not found")
	}
}
