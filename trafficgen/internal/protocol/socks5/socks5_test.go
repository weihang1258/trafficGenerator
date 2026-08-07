package socks5

// SOCKS planner tests, derived from /tmp/l7_planner_design/testcases_socks5.md
// (§1 RFC 字段 / §2 字节布局 / §3 状态机 / §4 业务场景 / §5 数据面 / §6 边界 /
// §8 Validate) and the reference pcaps
// /home/pcap_auto/llcj_pcap (SOCKS5, 14 sessions) and
// /home/pcap_auto/llcj_mirror (SOCKS4, 10 sessions), both dport=1080.
//
// Wire-order model (bare ACKs from the reference pcaps are not emitted —
// consistent with every other planner): handshake 3 + signaling N + data +
// teardown 3. A SOCKS5 no-auth session is 10 TCP packets.

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// --- helpers ---

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

// socksSpec returns a base spec: SOCKS5 no-auth CONNECT www.example.com:80,
// with a deterministic client ISN when initialSeq != 0.
func socksSpec(initialSeq uint32) core.FlowSpec {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 36164, DstPort: 1080,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
	}
	if initialSeq != 0 {
		spec.TCP = &core.TCPConfig{InitialSeq: initialSeq}
	}
	return spec
}

// tcpPackets returns the TCP packet configs in wire order.
func tcpPackets(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if c.L4.Protocol == "tcp" {
			out = append(out, c)
		}
	}
	return out
}

// udpPackets returns the UDP (relay sub-flow) configs in wire order.
func udpPackets(cfgs []core.PacketConfig) []core.PacketConfig {
	var out []core.PacketConfig
	for _, c := range cfgs {
		if c.L4.Protocol == "udp" {
			out = append(out, c)
		}
	}
	return out
}

// pshPayloads returns the PSH-ACK payloads in wire order.
func pshPayloads(tcps []core.PacketConfig) []string {
	var out []string
	for _, c := range tcps {
		if c.L4.Flags == 0x18 {
			out = append(out, string(c.Payload))
		}
	}
	return out
}

func hexStr(b []byte) string { return hex.EncodeToString(b) }

// assertPayloads checks the PSH-ACK payload bytes in order.
func assertPayloads(t *testing.T, tcps []core.PacketConfig, want ...string) {
	t.Helper()
	got := pshPayloads(tcps)
	if len(got) != len(want) {
		t.Fatalf("got %d PSH-ACK payloads %v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("payload[%d] = %q (%s), want %q (%s)", i, got[i], hexStr([]byte(got[i])), want[i], hexStr([]byte(want[i])))
		}
	}
}

// --- §1 RFC 字段 ---

// TestGreeting_Bytes (1.1.1/1.1.2/1.1.4): greeting is the first PSH-ACK
// (up), NMETHODS matches METHODS: no_auth → `05 01 00`, password → `05 01 02`.
func TestGreeting_Bytes(t *testing.T) {
	cases := []struct {
		name string
		auth string
		want string
	}{
		{"no_auth", "no_auth", "\x05\x01\x00"},
		{"password", "password", "\x05\x01\x02"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := socksSpec(1000)
			spec.Socks = &core.SocksConfig{AuthMethod: tc.auth}
			cfgs := mustPlan(t, NewPlanner(), spec)
			tcps := tcpPackets(cfgs)
			if len(tcps) < 4 {
				t.Fatalf("got %d TCP packets, want >= 10", len(tcps))
			}
			greeting := tcps[3]
			if greeting.Direction != "up" || greeting.L4.Flags != 0x18 {
				t.Fatalf("greeting: direction=%s flags=%#x, want up/PSH-ACK", greeting.Direction, greeting.L4.Flags)
			}
			if string(greeting.Payload) != tc.want {
				t.Errorf("greeting = %s, want %s", hexStr(greeting.Payload), hexStr([]byte(tc.want)))
			}
		})
	}
}

// TestMethodResponse_Bytes (1.2.1/1.2.2): the method response is the second
// PSH-ACK (down), echoing the selected method: `05 00` / `05 02`.
func TestMethodResponse_Bytes(t *testing.T) {
	cases := []struct {
		auth string
		want string
	}{
		{"no_auth", "\x05\x00"},
		{"password", "\x05\x02"},
	}
	for _, tc := range cases {
		t.Run(tc.auth, func(t *testing.T) {
			spec := socksSpec(1000)
			spec.Socks = &core.SocksConfig{AuthMethod: tc.auth}
			cfgs := mustPlan(t, NewPlanner(), spec)
			tcps := tcpPackets(cfgs)
			// Packet 4 = greeting (up), 5 = method response (down).
			mresp := tcps[4]
			if mresp.Direction != "down" || mresp.L4.Flags != 0x18 {
				t.Fatalf("method response: direction=%s flags=%#x, want down/PSH-ACK", mresp.Direction, mresp.L4.Flags)
			}
			if string(mresp.Payload) != tc.want {
				t.Errorf("method response = %s, want %s", hexStr(mresp.Payload), hexStr([]byte(tc.want)))
			}
		})
	}
}

// TestAuthSubnegotiation (1.3.1/1.3.2/1.3.3/1.3.4): RFC 1929 request/response
// bytes and position — after method response, before request.
func TestAuthSubnegotiation(t *testing.T) {
	cases := []struct {
		name           string
		user, pass     string
		wantAuthReqHex string
	}{
		{"explicit", "alice", "s3cret", "0105616c69636506733363726574"},
		{"defaults", "", "", "0104757365720470617373"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := socksSpec(1000)
			spec.Socks = &core.SocksConfig{
				AuthMethod: "password",
				Username:   tc.user,
				Password:   tc.pass,
			}
			cfgs := mustPlan(t, NewPlanner(), spec)
			tcps := tcpPackets(cfgs)
			if len(tcps) != 12 {
				t.Fatalf("got %d TCP packets, want 12 (3 handshake + 6 signaling + 3 teardown)", len(tcps))
			}
			// 0 SYN | 1 SYN-ACK | 2 ACK | 3 greeting | 4 method | 5 auth-req |
			// 6 auth-resp | 7 request | 8 reply | 9-11 teardown.
			authReq := tcps[5]
			if authReq.Direction != "up" {
				t.Errorf("auth request direction = %s, want up", authReq.Direction)
			}
			if hexStr(authReq.Payload) != tc.wantAuthReqHex {
				t.Errorf("auth request = %s, want %s", hexStr(authReq.Payload), tc.wantAuthReqHex)
			}
			authResp := tcps[6]
			if authResp.Direction != "down" || hexStr(authResp.Payload) != "0100" {
				t.Errorf("auth response = %s (dir %s), want 0100 (down)", hexStr(authResp.Payload), authResp.Direction)
			}
			// Position check: request follows auth response (1.3.4).
			if hexStr(tcps[7].Payload)[:2] != "05" || hexStr(tcps[8].Payload)[:2] != "05" {
				t.Errorf("request/reply not after auth: %s / %s", hexStr(tcps[7].Payload), hexStr(tcps[8].Payload))
			}
		})
	}
}

// TestRequest_Bytes (1.4.1-1.4.8): SOCKS5 request field layout.
func TestRequest_Bytes(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		dstAddr string
		dstPort uint16
		want    string
	}{
		{"connect_domain", "connect", "www.example.com", 80,
			"050100030f7777772e6578616d706c652e636f6d0050"}, // reference pcap bytes
		{"connect_ipv4", "connect", "93.184.216.119", 443,
			"050100015db8d87701bb"},
		{"connect_ipv6", "connect", "2001:db8::1", 80,
			"0501000420010db80000000000000000000000010050"},
		{"bind", "bind", "www.example.com", 80,
			"050200030f7777772e6578616d706c652e636f6d0050"},
		{"udp_associate", "udp_associate", "www.example.com", 80,
			"050300030f7777772e6578616d706c652e636f6d0050"},
		{"port_max", "connect", "www.example.com", 65535,
			"050100030f7777772e6578616d706c652e636f6dffff"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := socksSpec(1000)
			spec.Socks = &core.SocksConfig{Cmd: tc.cmd, DstAddr: tc.dstAddr, DstPort: tc.dstPort}
			cfgs := mustPlan(t, NewPlanner(), spec)
			tcps := tcpPackets(cfgs)
			req := tcps[5] // no_auth: 3 handshake + greeting + method + request
			if req.Direction != "up" || req.L4.Flags != 0x18 {
				t.Fatalf("request: direction=%s flags=%#x", req.Direction, req.L4.Flags)
			}
			if hexStr(req.Payload) != tc.want {
				t.Errorf("request = %s, want %s", hexStr(req.Payload), tc.want)
			}
		})
	}
}

// TestRequest_DomainTruncation (1.4.7): a 256-char domain truncates to 255
// (1-byte length field) without panicking.
func TestRequest_DomainTruncation(t *testing.T) {
	longDomain := strings.Repeat("a", 256)
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{DstAddr: longDomain}
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)
	req := tcps[5].Payload
	if req[0] != 0x05 || req[3] != SOCKS5ATYPDomain {
		t.Fatalf("request header wrong: %s", hexStr(req))
	}
	if req[4] != 0xff {
		t.Errorf("domain length byte = %#x, want 0xff", req[4])
	}
	if len(req) != 4+1+255+2 {
		t.Errorf("request length = %d, want %d", len(req), 4+1+255+2)
	}
	if string(req[5:260]) != longDomain[:255] {
		t.Errorf("domain bytes truncated incorrectly")
	}
}

// TestReply_Bytes (1.5.1-1.5.6): SOCKS5 reply field layout.
func TestReply_Bytes(t *testing.T) {
	cases := []struct {
		name    string
		rep     int
		bndAddr string
		bndPort uint16
		want    string
	}{
		{"success_default", 0, "", 0,
			"05000001000000000000"}, // reference pcap reply bytes
		{"rep_5", 5, "", 0, "05050001000000000000"},
		{"bnd_ipv4", 0, "10.180.156.249", 57266,
			"050000010ab49cf9dfb2"}, // reference pcap BND bytes
		{"bnd_domain", 0, "proxy.example", 0,
			"050000030d70726f78792e6578616d706c650000"},
		{"bnd_ipv6", 0, "2001:db8::2", 0,
			"0500000420010db80000000000000000000000020000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := socksSpec(1000)
			spec.Socks = &core.SocksConfig{Rep: tc.rep, BndAddr: tc.bndAddr, BndPort: tc.bndPort}
			cfgs := mustPlan(t, NewPlanner(), spec)
			tcps := tcpPackets(cfgs)
			reply := tcps[6] // no_auth: reply is the 4th signaling packet
			if reply.Direction != "down" {
				t.Fatalf("reply direction = %s, want down", reply.Direction)
			}
			if hexStr(reply.Payload) != tc.want {
				t.Errorf("reply = %s, want %s", hexStr(reply.Payload), tc.want)
			}
		})
	}
}

// TestReply_AllRepValues (1.5.3): REP 1..8 are all carried, length 10 (IPv4
// BND).
func TestReply_AllRepValues(t *testing.T) {
	for rep := 1; rep <= 8; rep++ {
		spec := socksSpec(1000)
		spec.Socks = &core.SocksConfig{Rep: rep}
		cfgs := mustPlan(t, NewPlanner(), spec)
		reply := tcpPackets(cfgs)[6].Payload
		if len(reply) != 10 {
			t.Errorf("rep=%d: reply length %d, want 10", rep, len(reply))
		}
		if reply[1] != byte(rep) {
			t.Errorf("rep=%d: reply[1]=%#x, want %#x", rep, reply[1], rep)
		}
	}
}

// TestSocks4_Request (1.6.1-1.6.4): SOCKS4 request layout incl. SOCKS4a
// domain form (0.0.0.1 marker, domain after USERID terminator, no length
// prefix).
func TestSocks4_Request(t *testing.T) {
	cases := []struct {
		name    string
		cmd     string
		dstAddr string
		userID  string
		want    string
	}{
		{"connect_ipv4", "connect", "93.184.216.119", "",
			"040100505db8d87700"}, // reference pcap request bytes
		{"bind_ipv4", "bind", "93.184.216.119", "",
			"040200505db8d87700"},
		{"userid", "connect", "93.184.216.119", "user1",
			"040100505db8d877757365723100"},
		{"socks4a_domain", "connect", "www.example.com", "",
			"0401005000000001007777772e6578616d706c652e636f6d00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := socksSpec(1000)
			spec.Socks = &core.SocksConfig{Version: "socks4", Cmd: tc.cmd, DstAddr: tc.dstAddr, DstPort: 80, UserID: tc.userID}
			cfgs := mustPlan(t, NewPlanner(), spec)
			tcps := tcpPackets(cfgs)
			req := tcps[3] // socks4: request is the 1st signaling packet
			if req.Direction != "up" {
				t.Fatalf("request direction = %s, want up", req.Direction)
			}
			if hexStr(req.Payload) != tc.want {
				t.Errorf("request = %s, want %s", hexStr(req.Payload), tc.want)
			}
		})
	}
}

// TestSocks4_Reply (1.7.1-1.7.3): SOCKS4 reply `00 5A|5B <BNDPORT> <BNDIP>`.
func TestSocks4_Reply(t *testing.T) {
	cases := []struct {
		name    string
		rep     int
		bndAddr string
		bndPort uint16
		want    string
	}{
		{"granted", 0, "10.180.156.249", 57266,
			"005adfb20ab49cf9"}, // reference pcap reply bytes
		{"rejected", 5, "", 0, "005b000000000000"},
		{"granted_default", 0, "", 0, "005a000000000000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := socksSpec(1000)
			spec.Socks = &core.SocksConfig{Version: "socks4", DstAddr: "93.184.216.119", Rep: tc.rep, BndAddr: tc.bndAddr, BndPort: tc.bndPort}
			cfgs := mustPlan(t, NewPlanner(), spec)
			reply := tcpPackets(cfgs)[4] // request(up) then reply(down)
			if reply.Direction != "down" {
				t.Fatalf("reply direction = %s, want down", reply.Direction)
			}
			if hexStr(reply.Payload) != tc.want {
				t.Errorf("reply = %s, want %s", hexStr(reply.Payload), tc.want)
			}
		})
	}
}

// --- §2 字节布局 ---

// TestSocks5Session_FrameOrder (2.1.1/2.1.3): full session = SYN → SYN-ACK →
// ACK → greeting(up) → method(down) → request(up) → reply(down) → FIN →
// FIN-ACK → ACK, 10 TCP packets, each signaling message its own PSH-ACK.
func TestSocks5Session_FrameOrder(t *testing.T) {
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{}
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)
	if len(tcps) != 10 {
		t.Fatalf("got %d TCP packets, want 10 (3 handshake + 4 signaling + 3 teardown)", len(tcps))
	}
	dirs := []string{"up", "down", "up", "up", "down", "up", "down", "up", "down", "up"}
	flags := []uint8{0x02, 0x12, 0x10, 0x18, 0x18, 0x18, 0x18, 0x11, 0x11, 0x10}
	for i, p := range tcps {
		if p.Direction != dirs[i] {
			t.Errorf("packet[%d] direction = %s, want %s", i, p.Direction, dirs[i])
		}
		if p.L4.Flags != flags[i] {
			t.Errorf("packet[%d] flags = %#x, want %#x", i, p.L4.Flags, flags[i])
		}
	}
	assertPayloads(t, tcps,
		"\x05\x01\x00",                       // greeting
		"\x05\x00",                           // method response
		"\x05\x01\x00\x03\x0fwww.example.com\x00\x50", // request
		"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",     // reply
	)
	// Each signaling message occupies its own PSH-ACK (2.1.3): the 4
	// signaling messages must not be merged with adjacent data.
	if tcps[3].L4.Flags != 0x18 || tcps[4].L4.Flags != 0x18 || tcps[5].L4.Flags != 0x18 || tcps[6].L4.Flags != 0x18 {
		t.Errorf("signaling messages not each a separate PSH-ACK")
	}
}

// TestSocks4Session_FrameOrder (2.1.2): SYN×3 → request(up) → reply(down) →
// data → FIN×3.
func TestSocks4Session_FrameOrder(t *testing.T) {
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{
		Version: "socks4",
		DstAddr: "93.184.216.119",
		Data: []core.SocksDataMessage{
			{Direction: "up", Payload: "GET / HTTP/1.1\r\nHost: x\r\n\r\n"},
			{Direction: "down", Payload: "HTTP/1.1 200 OK\r\n\r\n"},
		},
	}
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)
	// 3 handshake + 2 signaling + 2 data + 3 teardown = 10.
	if len(tcps) != 10 {
		t.Fatalf("got %d TCP packets, want 10", len(tcps))
	}
	dirs := []string{"up", "down", "up", "up", "down", "up", "down", "up", "down", "up"}
	for i, p := range tcps {
		if p.Direction != dirs[i] {
			t.Errorf("packet[%d] direction = %s, want %s", i, p.Direction, dirs[i])
		}
	}
	assertPayloads(t, tcps,
		"\x04\x01\x00\x50\x5d\xb8\xd8\x77\x00", // request
		"\x00\x5a\x00\x00\x00\x00\x00\x00",     // reply (default BND)
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"HTTP/1.1 200 OK\r\n\r\n",
	)
}

// TestSeqAck_Continuity (2.2.1): same-direction seqs advance by payload
// length (+1 for SYN/FIN); ACKs cover the peer's bytes.
func TestSeqAck_Continuity(t *testing.T) {
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{}
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)

	// up packets: 0 SYN(1000), 2 ACK(1001), 3 greeting(1001+3),
	// 5 request(1004+22), 7 FIN(1026+1), 9 ACK(1027)
	wantUpSeq := []uint32{1000, 1001, 1001, 1004, 1026, 1027}
	// down packets: 1 SYN-ACK(S), 4 method(S+1+2), 6 reply(S+3+10),
	// 8 FIN-ACK(S+13+1)
	wantDownSeqLen := 4
	_ = wantDownSeqLen

	var up, down []core.PacketConfig
	for _, p := range tcps {
		if p.Direction == "up" {
			up = append(up, p)
		} else {
			down = append(down, p)
		}
	}
	for i, p := range up {
		if p.L4.Seq != wantUpSeq[i] {
			t.Errorf("up seq[%d] = %d, want %d", i, p.L4.Seq, wantUpSeq[i])
		}
	}
	// down seqs: SYN-ACK S, method S+1, reply S+3, FIN-ACK S+13.
	if down[0].L4.Seq != down[1].L4.Seq-1 || down[1].L4.Seq != down[2].L4.Seq-2 || down[2].L4.Seq != down[3].L4.Seq-10 {
		t.Errorf("down seqs not contiguous: %d %d %d %d", down[0].L4.Seq, down[1].L4.Seq, down[2].L4.Seq, down[3].L4.Seq)
	}
	// ACK coverage: SYN-ACK acks 1001 (client ISN+1); method acks client
	// seq after greeting (1004); reply acks after request (1026); FIN-ACK
	// acks after FIN (1027).
	wantAcks := []uint32{1001, 1004, 1026, 1027}
	for i, p := range down {
		if p.L4.Ack != wantAcks[i] {
			t.Errorf("down ack[%d] = %d, want %d", i, p.L4.Ack, wantAcks[i])
		}
	}
}

// TestMSS_Segmentation (2.2.2/5.6): a 4000-byte data message with MSS=1460
// emits 3 PSH-ACK segments (1460/1460/1080).
func TestMSS_Segmentation(t *testing.T) {
	spec := socksSpec(1000)
	spec.TCP = &core.TCPConfig{InitialSeq: 1000, MSS: 1460}
	payload := strings.Repeat("x", 4000)
	spec.Socks = &core.SocksConfig{Data: []core.SocksDataMessage{{Payload: payload}}}
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)
	// 10 base + 3 segments - 1 (the 4000-byte message replaces nothing:
	// it IS the data plane, so 10 base packets assume no data) = 13.
	if len(tcps) != 13 {
		t.Fatalf("got %d TCP packets, want 13 (10 base + 3 segments)", len(tcps))
	}
	data := pshPayloads(tcps[6:]) // reply + 3 data segments + teardown
	if len(data) != 4 {
		t.Fatalf("got %d PSH-ACK after reply, want 4", len(data))
	}
	segs := data[1:]
	if len(segs[0]) != 1460 || len(segs[1]) != 1460 || len(segs[2]) != 1080 {
		t.Errorf("segment lengths = %d/%d/%d, want 1460/1460/1080", len(segs[0]), len(segs[1]), len(segs[2]))
	}
	// All segments carry PSH-ACK and advance seq contiguously.
	joined := strings.Join(segs, "")
	if joined != payload {
		t.Errorf("segments do not reconstruct the payload")
	}
	for _, seg := range tcps[7:10] {
		if seg.L4.Flags != 0x18 {
			t.Errorf("segment flags = %#x, want 0x18", seg.L4.Flags)
		}
	}
	if tcps[7].L4.Seq+1460 != tcps[8].L4.Seq || tcps[8].L4.Seq+1460 != tcps[9].L4.Seq {
		t.Errorf("segment seqs not contiguous")
	}
}

// --- §3 状态机 ---

// TestStateMachine_Phases (3.1-3.3): signaling message counts by mode.
func TestStateMachine_Phases(t *testing.T) {
	cases := []struct {
		name     string
		version  string
		auth     string
		signaling int
		total    int
	}{
		{"socks5_password", "socks5", "password", 6, 12},
		{"socks5_no_auth", "socks5", "no_auth", 4, 10},
		{"socks4", "socks4", "no_auth", 2, 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := socksSpec(1000)
			spec.Socks = &core.SocksConfig{Version: tc.version, AuthMethod: tc.auth, DstAddr: "93.184.216.119"}
			cfgs := mustPlan(t, NewPlanner(), spec)
			tcps := tcpPackets(cfgs)
			if len(tcps) != tc.total {
				t.Fatalf("got %d TCP packets, want %d", len(tcps), tc.total)
			}
			var signaling int
			for _, p := range tcps {
				if p.L4.Flags == 0x18 {
					signaling++
				}
			}
			if signaling != tc.signaling {
				t.Errorf("signaling messages = %d, want %d", signaling, tc.signaling)
			}
		})
	}
}

// TestRep_SuppressesData (3.4/3.5): Rep=0 emits Data after the reply;
// Rep!=0 suppresses it entirely.
func TestRep_SuppressesData(t *testing.T) {
	data := []core.SocksDataMessage{{Payload: "secret bytes"}}
	for _, rep := range []int{0, 5} {
		spec := socksSpec(1000)
		spec.Socks = &core.SocksConfig{Rep: rep, Data: data}
		cfgs := mustPlan(t, NewPlanner(), spec)
		tcps := tcpPackets(cfgs)
		var dataPackets int
		for _, p := range tcps {
			if p.L4.Flags == 0x18 && string(p.Payload) == "secret bytes" {
				dataPackets++
			}
		}
		if rep == 0 {
			if dataPackets != 1 {
				t.Errorf("rep=0: data packets = %d, want 1", dataPackets)
			}
		} else if dataPackets != 0 {
			t.Errorf("rep=5: data packets = %d, want 0 (RFC 1928: close on failure)", dataPackets)
		}
	}
}

// TestUDPAssociate_Relay (3.6/3.6a/5.7/5.8/5.9): relay datagrams carry the
// §3.8 header (RSV+FRAG+ATYP+ADDR+PORT) + FrameSize payload; suppressed
// when Rep!=0.
func TestUDPAssociate_Relay(t *testing.T) {
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{
		Cmd:     "udp_associate",
		DstAddr: "10.0.0.1",
		UDP: &core.Socks5UDP{
			SrcPort:   50000,
			DstPort:   443,
			Frames:    3,
			FrameSize: 100,
			DstAddr:   "93.184.216.119",
			Direction: "down",
		},
	}
	cfgs := mustPlan(t, NewPlanner(), spec)
	udps := udpPackets(cfgs)
	if len(udps) != 3 {
		t.Fatalf("got %d UDP packets, want 3", len(udps))
	}
	for i, u := range udps {
		if u.Direction != "down" {
			t.Errorf("udp[%d] direction = %s, want down", i, u.Direction)
		}
		if u.L3.SrcIP != spec.DstIP || u.L3.DstIP != spec.SrcIP {
			t.Errorf("udp[%d] ip = %s->%s, want %s->%s", i, u.L3.SrcIP, u.L3.DstIP, spec.DstIP, spec.SrcIP)
		}
		if u.L4.SrcPort != 50000 || u.L4.DstPort != 443 {
			t.Errorf("udp[%d] ports = %d->%d, want 50000->443", i, u.L4.SrcPort, u.L4.DstPort)
		}
		if len(u.Payload) != 110 {
			t.Errorf("udp[%d] payload len = %d, want 110 (10 header + 100 data)", i, len(u.Payload))
		}
		if hexStr(u.Payload[:10]) != "000000015db8d87701bb" {
			t.Errorf("udp[%d] header = %s, want 000000015db8d87701bb", i, hexStr(u.Payload[:10]))
		}
		// Sub-flow id distinguishes the UDP relay from the TCP session.
		if !strings.HasSuffix(u.FlowID, ":udp") {
			t.Errorf("udp[%d] flow id %q, want :udp suffix", i, u.FlowID)
		}
	}

	// 3.6a: Rep!=0 suppresses the relay sub-flow.
	spec.Socks.Rep = 5
	cfgs = mustPlan(t, NewPlanner(), spec)
	if n := len(udpPackets(cfgs)); n != 0 {
		t.Errorf("rep=5: got %d UDP packets, want 0", n)
	}
}

// TestSocks4_UDPAssociateDowngrade (3.7): SOCKS4 + udp_associate degrades to
// connect — no UDP sub-flow, request CMD byte is CONNECT.
func TestSocks4_UDPAssociateDowngrade(t *testing.T) {
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{
		Version: "socks4",
		Cmd:     "udp_associate",
		DstAddr: "93.184.216.119",
		UDP:     &core.Socks5UDP{Frames: 2},
	}
	cfgs := mustPlan(t, NewPlanner(), spec)
	if n := len(udpPackets(cfgs)); n != 0 {
		t.Errorf("got %d UDP packets, want 0 (SOCKS4 has no UDP ASSOCIATE)", n)
	}
	req := tcpPackets(cfgs)[3].Payload
	if req[1] != SOCKS4CmdConnect {
		t.Errorf("request CD = %#x, want %#x (downgraded to connect)", req[1], SOCKS4CmdConnect)
	}
}

// --- §4 业务场景 ---

// TestScenario_Socks5NoAuth (4.1): 10 TCP packets, wire bytes match the
// reference pcap, no data plane.
func TestScenario_Socks5NoAuth(t *testing.T) {
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{DstAddr: "www.example.com", DstPort: 80}
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)
	if len(tcps) != 10 {
		t.Fatalf("got %d TCP packets, want 10", len(tcps))
	}
	assertPayloads(t, tcps,
		"\x05\x01\x00",
		"\x05\x00",
		"\x05\x01\x00\x03\x0fwww.example.com\x00\x50",
		"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",
	)
}

// TestScenario_Socks4TunneledHTTP (4.2): request/reply bytes match the
// reference pcap; tunneled HTTP flows through after the reply (GET up, 200
// down).
func TestScenario_Socks4TunneledHTTP(t *testing.T) {
	get := "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n"
	resp := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{
		Version: "socks4",
		DstAddr: "93.184.216.119",
		DstPort: 80,
		Data: []core.SocksDataMessage{
			{Direction: "up", Payload: get},
			{Direction: "down", Payload: resp},
		},
	}
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)
	// 3 handshake + 2 signaling + 2 data + 3 teardown = 10.
	if len(tcps) != 10 {
		t.Fatalf("got %d TCP packets, want 10", len(tcps))
	}
	assertPayloads(t, tcps,
		"\x04\x01\x00\x50\x5d\xb8\xd8\x77\x00", // request (reference pcap)
		"\x00\x5a\x00\x00\x00\x00\x00\x00",     // reply (reference pcap)
		get,
		resp,
	)
	// GET must appear after the reply (tcps[4]) and the 200 after GET.
	idx := func(want string) int {
		for i, p := range tcps {
			if string(p.Payload) == want {
				return i
			}
		}
		return -1
	}
	if r, g := idx(resp), idx(get); g != 5 || r != 6 {
		t.Errorf("data order wrong: GET at %d (want 5), 200 at %d (want 6)", g, r)
	}
}

// TestScenario_PasswordAuth (4.3): 6 signaling messages with correct auth
// bytes.
func TestScenario_PasswordAuth(t *testing.T) {
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{AuthMethod: "password", Username: "alice", Password: "s3cret"}
	cfgs := mustPlan(t, NewPlanner(), spec)
	assertPayloads(t, tcpPackets(cfgs),
		"\x05\x01\x02",                         // greeting offers password
		"\x05\x02",                             // method response picks password
		"\x01\x05alice\x06s3cret",              // RFC 1929 auth request
		"\x01\x00",                             // auth response
		"\x05\x01\x00\x03\x0fwww.example.com\x00\x50",
		"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",
	)
}

// TestMultiSession (4.6): two specs plan two independent flows with their
// own full sessions; wire bytes never interleave within a flow.
func TestMultiSession(t *testing.T) {
	specA := socksSpec(1000)
	specA.Socks = &core.SocksConfig{DstAddr: "www.example.com"}
	specB := socksSpec(2000)
	specB.SrcPort = 36165 // distinct 4-tuple → distinct flow
	specB.Socks = &core.SocksConfig{Version: "socks4", DstAddr: "93.184.216.119"}

	cfgsA := mustPlan(t, NewPlanner(), specA)
	cfgsB := mustPlan(t, NewPlanner(), specB)
	if len(cfgsA) != 10 || len(cfgsB) != 8 {
		t.Fatalf("flow lengths = %d/%d, want 10/8", len(cfgsA), len(cfgsB))
	}
	// Distinct flow ids.
	if cfgsA[0].FlowID == cfgsB[0].FlowID {
		t.Errorf("flow ids not distinct")
	}
	// Session A carries SOCKS5 signaling; B carries SOCKS4.
	if cfgsA[3].Payload[0] != 0x05 || cfgsB[3].Payload[0] != 0x04 {
		t.Errorf("wire bytes interleaved across flows")
	}
}

// --- §5 数据面 ---

// TestDataPlane_OrderAndDefaults (5.1/5.2/5.3): messages emit in list order,
// payload bytes verbatim, direction defaults to "up".
func TestDataPlane_OrderAndDefaults(t *testing.T) {
	up1 := "A" + strings.Repeat("a", 20)
	up2 := "B" + strings.Repeat("b", 20)
	down1 := "C" + strings.Repeat("c", 20)
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{Data: []core.SocksDataMessage{
		{Payload: up1},                      // no Direction → up (5.3)
		{Direction: "up", Payload: up2},
		{Direction: "down", Payload: down1},
	}}
	cfgs := mustPlan(t, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)
	assertPayloads(t, tcps,
		"\x05\x01\x00", "\x05\x00",
		"\x05\x01\x00\x03\x0fwww.example.com\x00\x50",
		"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",
		up1, up2, down1,
	)
	// Directions on the wire.
	dataIdx := 7
	if tcps[dataIdx].Direction != "up" || tcps[dataIdx+1].Direction != "up" || tcps[dataIdx+2].Direction != "down" {
		t.Errorf("data directions = %s/%s/%s, want up/up/down",
			tcps[dataIdx].Direction, tcps[dataIdx+1].Direction, tcps[dataIdx+2].Direction)
	}
}

// TestDataPlane_Empty (5.4): no Data → no data packets beyond signaling.
func TestDataPlane_Empty(t *testing.T) {
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{Data: []core.SocksDataMessage{}}
	cfgs := mustPlan(t, NewPlanner(), spec)
	if n := len(tcpPackets(cfgs)); n != 10 {
		t.Errorf("got %d TCP packets, want 10 (no data plane)", n)
	}
}

// TestDataPlane_FileSource (5.5): FileSource literal bytes replace Payload.
func TestDataPlane_FileSource(t *testing.T) {
	fs, err := filesystem.New(t.TempDir())
	if err != nil {
		t.Fatalf("filesystem.New: %v", err)
	}
	ctx := core.WithPayloadCache(context.Background(), core.NewPayloadCache(fs))
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{Data: []core.SocksDataMessage{
		{Direction: "up", FileSource: &filesystem.FileSource{Literal: "abc"}},
	}}
	cfgs := mustPlanCtx(t, ctx, NewPlanner(), spec)
	tcps := tcpPackets(cfgs)
	got := pshPayloads(tcps)
	if len(got) != 5 || got[4] != "abc" {
		t.Errorf("payloads = %v, want 5th = \"abc\"", got)
	}
}

// TestDataPlane_FileSourceNoCache (5.5 negative): without a payload cache in
// ctx, FileSource messages are skipped (no panic, session still completes).
func TestDataPlane_FileSourceNoCache(t *testing.T) {
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{Data: []core.SocksDataMessage{
		{Direction: "up", FileSource: &filesystem.FileSource{Literal: "abc"}},
	}}
	cfgs := mustPlanCtx(t, context.Background(), NewPlanner(), spec)
	got := pshPayloads(tcpPackets(cfgs))
	if len(got) != 4 {
		t.Errorf("payloads = %v, want 4 (FileSource skipped without cache)", got)
	}
}

// TestUDP_Defaults (6.10): Frames<=0 → 1, FrameSize==0 → 100.
func TestUDP_Defaults(t *testing.T) {
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{Cmd: "udp_associate", UDP: &core.Socks5UDP{}}
	cfgs := mustPlan(t, NewPlanner(), spec)
	udps := udpPackets(cfgs)
	if len(udps) != 1 {
		t.Fatalf("got %d UDP packets, want 1", len(udps))
	}
	if len(udps[0].Payload) != 10+100 {
		t.Errorf("payload len = %d, want 110 (header 10 + default frame 100)", len(udps[0].Payload))
	}
}

// TestUDP_IPv6Hosts (6.11): relay sub-flow on IPv6 hosts uses EtherType
// 0x86DD and an IPv6 relay-target header.
func TestUDP_IPv6Hosts(t *testing.T) {
	spec := socksSpec(0)
	spec.SrcIP = "2001:db8::1"
	spec.DstIP = "2001:db8::2"
	spec.Socks = &core.SocksConfig{
		Cmd:     "udp_associate",
		DstAddr: "2001:db8::1",
		UDP:     &core.Socks5UDP{Frames: 1, DstAddr: "2001:db8::3"},
	}
	cfgs := mustPlan(t, NewPlanner(), spec)
	udps := udpPackets(cfgs)
	if len(udps) != 1 {
		t.Fatalf("got %d UDP packets, want 1", len(udps))
	}
	if udps[0].L2.EtherType != 0x86DD {
		t.Errorf("EtherType = %#x, want 0x86DD (IPv6)", udps[0].L2.EtherType)
	}
	if hexStr(udps[0].Payload[:4]) != "00000004" {
		t.Errorf("relay header ATYP = %s, want 04 (IPv6)", hexStr(udps[0].Payload[:4]))
	}
}

// --- §6 边界值 / §8 Validate ---

// TestDefaults_AllEmpty (6.1/6.7/6.12): a zero SocksConfig generates a
// SOCKS5 no-auth CONNECT www.example.com:80 session with default MSS.
func TestDefaults_AllEmpty(t *testing.T) {
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{}
	cfgs := mustPlan(t, NewPlanner(), spec)
	assertPayloads(t, tcpPackets(cfgs),
		"\x05\x01\x00",
		"\x05\x00",
		"\x05\x01\x00\x03\x0fwww.example.com\x00\x50",
		"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00",
	)
	// 6.12: no MSS → default 1460 (greeting not segmented: 3 bytes in one
	// PSH-ACK).
	tcps := tcpPackets(cfgs)
	if len(tcps[3].Payload) != 3 {
		t.Errorf("greeting payload len = %d, want 3", len(tcps[3].Payload))
	}
}

// TestValidate_Errors (§1.6.5, 6.2-6.5, 8.1): invalid inputs rejected.
func TestValidate_Errors(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*core.FlowSpec)
		wantSub string
	}{
		{"nil_socks", func(s *core.FlowSpec) { s.Socks = nil }, "SocksConfig is required"},
		{"bad_version", func(s *core.FlowSpec) { s.Socks.Version = "socks6" }, "invalid version"},
		{"bad_auth", func(s *core.FlowSpec) { s.Socks.AuthMethod = "gssapi" }, "invalid AuthMethod"},
		{"bad_cmd", func(s *core.FlowSpec) { s.Socks.Cmd = "teleport" }, "invalid Cmd"},
		{"bad_dst_ip", func(s *core.FlowSpec) { s.Socks.DstAddr = "999.1.1.1" }, "malformed IPv4"},
		{"bad_dst_ipv6", func(s *core.FlowSpec) { s.Socks.DstAddr = "2001:db8::zzz" }, "malformed IPv6"},
		{"socks4_ipv6", func(s *core.FlowSpec) {
			s.Socks.Version = "socks4"
			s.Socks.DstAddr = "2001:db8::1"
		}, "must be IPv4 or domain"},
		{"socks4_bad_bnd", func(s *core.FlowSpec) {
			s.Socks.Version = "socks4"
			s.Socks.BndAddr = "proxy.example"
		}, "BndAddr must be an IPv4 address"},
		{"bad_src_ip", func(s *core.FlowSpec) { s.SrcIP = "not-an-ip" }, "invalid SrcIP"},
		{"mss_too_small", func(s *core.FlowSpec) { s.TCP = &core.TCPConfig{MSS: 100} }, "too small"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := socksSpec(0)
			spec.Socks = &core.SocksConfig{}
			tc.mutate(&spec)
			err := NewPlanner().Validate(spec)
			if err == nil {
				t.Fatalf("Validate accepted invalid spec, want error containing %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %v, want substring %q", err, tc.wantSub)
			}
		})
	}
}

// TestValidate_Acceptance: valid configurations pass.
func TestValidate_Acceptance(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*core.FlowSpec)
	}{
		{"socks5_defaults", func(s *core.FlowSpec) {}},
		{"socks5_password", func(s *core.FlowSpec) { s.Socks.AuthMethod = "password" }},
		{"socks5_ipv6_dst", func(s *core.FlowSpec) { s.Socks.DstAddr = "2001:db8::1" }},
		{"socks5_udp_associate", func(s *core.FlowSpec) {
			s.Socks.Cmd = "udp_associate"
			s.Socks.UDP = &core.Socks5UDP{Frames: 1}
		}},
		{"socks4_ipv4", func(s *core.FlowSpec) {
			s.Socks.Version = "socks4"
			s.Socks.DstAddr = "93.184.216.119"
		}},
		{"socks4_domain", func(s *core.FlowSpec) {
			s.Socks.Version = "socks4"
			s.Socks.DstAddr = "www.example.com"
		}},
		{"mss_exact_min", func(s *core.FlowSpec) { s.TCP = &core.TCPConfig{MSS: 536} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := socksSpec(0)
			spec.Socks = &core.SocksConfig{}
			tc.mutate(&spec)
			if err := NewPlanner().Validate(spec); err != nil {
				t.Errorf("Validate rejected valid spec: %v", err)
			}
		})
	}
}

// TestRep255 (6.9): REP=255 is carried verbatim (planner does not reject
// unknown REP values).
func TestRep255(t *testing.T) {
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{Rep: 255}
	cfgs := mustPlan(t, NewPlanner(), spec)
	reply := tcpPackets(cfgs)[6].Payload
	if reply[1] != 0xff {
		t.Errorf("reply[1] = %#x, want 0xff", reply[1])
	}
}

// TestDstPort_Default (6.8 superseded by S5): DstPort 0 is the "empty"
// marker and defaults to 80 (design §5 S5, reference pcap port) — a zero
// port cannot be expressed, same convention as MSS/TTL.
func TestDstPort_Default(t *testing.T) {
	spec := socksSpec(1000)
	spec.Socks = &core.SocksConfig{DstPort: 0}
	cfgs := mustPlan(t, NewPlanner(), spec)
	req := tcpPackets(cfgs)[5].Payload
	if !bytes.HasSuffix(req, []byte{0x00, 0x50}) {
		t.Errorf("request = %s, want suffix 0050 (default port 80)", hexStr(req))
	}
}

// TestGroupIDMeta: with a GroupID strategy, every packet carries the
// group_id metadata so control + relay sub-flow stay on one PacketWorker.
func TestGroupIDMeta(t *testing.T) {
	spec := socksSpec(1000)
	spec.GroupID = &core.StrategyConfig{Strategy: "fixed", Value: "g1"}
	spec.Socks = &core.SocksConfig{Cmd: "udp_associate", DstAddr: "10.0.0.1", UDP: &core.Socks5UDP{Frames: 1}}
	cfgs := mustPlan(t, NewPlanner(), spec)
	for _, c := range cfgs {
		if c.Metadata == nil || c.Metadata["group_id"] != "g1" {
			t.Errorf("packet %q missing group_id metadata: %v", c.FlowID, c.Metadata)
		}
	}
}
