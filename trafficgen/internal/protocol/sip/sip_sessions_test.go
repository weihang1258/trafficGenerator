package sip

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// D-SIP-2 WP-A 红例（failing 先行）：sessions[] 派生与显式赢。
// dialog 路径零字节回归线由既有 57 例套件守。

// 两 session（call_id 缺省）→ 派生 Call-ID "{flow}-{sess}@{srcIP}"，
// 每会话独立 TCP 生命周期（2×(3握手+2消息+4挥手)=18 包）。
func TestSIPSessionsDerivedCallID(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 12001, DstPort: 5060,
		SIP: &core.SIPConfig{Sessions: []core.SIPSession{
			{Dialog: []core.SIPMessage{
				{Method: "OPTIONS", URI: "sip:callee@20.0.0.1"},
				{StatusCode: 200, StatusText: "OK"},
			}},
			{Dialog: []core.SIPMessage{
				{Method: "OPTIONS", URI: "sip:callee@20.0.0.1"},
				{StatusCode: 200, StatusText: "OK"},
			}},
		}},
	}
	var p Planner
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	var callIDs []string
	for pkt := range ch {
		n++
		if len(pkt.Payload) > 0 && pkt.L4.Protocol == "tcp" {
			text := string(pkt.Payload)
			if strings.Contains(text, "Call-ID:") {
				for _, line := range strings.Split(text, "\r\n") {
					if strings.HasPrefix(line, "Call-ID:") {
						callIDs = append(callIDs, line)
					}
				}
			}
		}
	}
	if n != 18 {
		t.Fatalf("packets=%d want 18 (2 sessions × (3+2+4))", n)
	}
	joined := strings.Join(callIDs, "|")
	if !strings.Contains(joined, "0-0@10.0.0.1") || !strings.Contains(joined, "0-1@10.0.0.1") {
		t.Fatalf("derived Call-IDs missing: %q", joined)
	}
	if strings.Count(joined, "0-0@10.0.0.1") < 2 || strings.Count(joined, "0-1@10.0.0.1") < 2 {
		t.Fatalf("each session must carry its derived Call-ID on req+resp: %q", joined)
	}
}

// 显式赢：消息内显式 Call-ID 头 > session.CallID > 派生。
func TestSIPSessionsExplicitWins(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 12001, DstPort: 5060,
		SIP: &core.SIPConfig{Sessions: []core.SIPSession{
			{CallID: "sess-a@10.0.0.1", Dialog: []core.SIPMessage{
				{Method: "OPTIONS", URI: "sip:callee@20.0.0.1",
					Headers: []string{"Call-ID: explicit@10.0.0.1"}},
				{StatusCode: 200, StatusText: "OK"},
			}},
		}},
	}
	var p Planner
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for pkt := range ch {
		text := string(pkt.Payload)
		if strings.Contains(text, "Call-ID:") {
			if strings.Contains(text, "sess-a@10.0.0.1") {
				t.Fatalf("message-level explicit Call-ID must win over session.call_id: %q", text)
			}
			if !strings.Contains(text, "explicit@10.0.0.1") && strings.Contains(text, "OPTIONS") {
				t.Fatalf("explicit Call-ID missing from request: %q", text)
			}
		}
	}
}

// session 独立端口：每 session 独立 TCP 四元组（独立握手端口）。
func TestSIPSessionsDistinctPorts(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 12001, DstPort: 5060,
		SIP: &core.SIPConfig{Sessions: []core.SIPSession{
			{SrcPort: 22001, Dialog: []core.SIPMessage{{Method: "OPTIONS", URI: "sip:x"}}},
			{SrcPort: 22002, Dialog: []core.SIPMessage{{Method: "OPTIONS", URI: "sip:x"}}},
		}},
	}
	var p Planner
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	seen := map[uint16]bool{}
	for pkt := range ch {
		if pkt.Direction == "up" && pkt.L4.SrcPort != 0 {
			seen[pkt.L4.SrcPort] = true
		}
	}
	if !seen[22001] || !seen[22002] {
		t.Fatalf("per-session src ports missing: %v", seen)
	}
}

// 互斥背door：Planner.Validate 拒绝 sessions+dialog 同给（task-time）。
func TestSIPSessionsMutexValidate(t *testing.T) {
	spec := core.FlowSpec{
		SIP: &core.SIPConfig{
			Dialog:   []core.SIPMessage{{Method: "OPTIONS", URI: "sip:x"}},
			Sessions: []core.SIPSession{{Dialog: []core.SIPMessage{{Method: "OPTIONS", URI: "sip:x"}}}},
		},
	}
	var p Planner
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "sip: sessions and dialog are mutually exclusive") {
		t.Fatalf("want mutex anchor from Validate, got %v", err)
	}
}

// D-SIP-2 WP-B：双向交替（up 2 帧+down 2 帧→方向序 up,down,up,down）。
func TestSIPMediasBidirectionalAlternate(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12001, DstPort: 5060,
		SIP: &core.SIPConfig{Dialog: []core.SIPMessage{
			{Method: "INVITE", URI: "sip:callee@20.0.0.1", EmitMedia: true},
			{StatusCode: 200, StatusText: "OK"},
		}, Medias: []core.SIPMedia{
			{Direction: "up", Frames: 2},
			{Direction: "down", Frames: 2},
		}},
	}
	var p Planner
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var dirs []string
	for pkt := range ch {
		if pkt.L4.Protocol == "udp" {
			dirs = append(dirs, pkt.Direction)
		}
	}
	want := "up,down,up,down"
	if got := strings.Join(dirs, ","); got != want {
		t.Fatalf("RTP direction order=%q want %q (round-robin alternation)", got, want)
	}
}

// D-SIP-2 WP-B：interleave 交错调度（4 帧媒体夹在 3 条后续消息间：
// gap 划分 T=4 G=4→每 gap 1 帧；帧序=媒体,200,媒体,ACK,媒体,媒体）。
func TestSIPMediasInterleaveSchedule(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12001, DstPort: 5060,
		SIP: &core.SIPConfig{
			Interleave: true,
			Dialog: []core.SIPMessage{
				{Method: "INVITE", URI: "sip:callee@20.0.0.1", EmitMedia: true},
				{StatusCode: 200, StatusText: "OK"},
				{StatusCode: 200, StatusText: "OK"},
				{StatusCode: 200, StatusText: "OK"},
			},
			Medias: []core.SIPMedia{{Direction: "up", Frames: 4}},
		},
	}
	var p Planner
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var seq []string
	for pkt := range ch {
		if pkt.L4.Protocol == "udp" {
			seq = append(seq, "R")
		} else if len(pkt.Payload) > 0 {
			if strings.Contains(string(pkt.Payload), "SIP/2.0 200") {
				seq = append(seq, "M")
			}
		}
	}
	// gaps: after-INVITE/after-200a/after-200b/after-200c 各 1 帧
	want := "R,M,R,M,R,M,R"
	if got := strings.Join(seq, ","); got != want {
		t.Fatalf("interleave sequence=%q want %q", got, want)
	}
}

// D-SIP-2 WP-B：medias 互斥 Validate 背 door。
func TestSIPMediasMutexValidate(t *testing.T) {
	spec := core.FlowSpec{
		SIP: &core.SIPConfig{
			Media:  &core.SIPMedia{Frames: 1},
			Medias: []core.SIPMedia{{Direction: "up", Frames: 1}},
		},
	}
	var p Planner
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "sip: media and medias are mutually exclusive") {
		t.Fatalf("want medias mutex anchor from Validate, got %v", err)
	}
}

// D-SIP-2 WP-B：双向子流独立 ID（parent:rtp-up / parent:rtp-down）。
func TestSIPMediasFlowIDSuffix(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12001, DstPort: 5060,
		SIP: &core.SIPConfig{Dialog: []core.SIPMessage{
			{Method: "INVITE", URI: "sip:callee@20.0.0.1", EmitMedia: true},
			{StatusCode: 200, StatusText: "OK"},
		}, Medias: []core.SIPMedia{
			{Direction: "up", Frames: 1},
			{Direction: "down", Frames: 1},
		}},
	}
	var p Planner
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	fids := map[string]bool{}
	for pkt := range ch {
		if pkt.L4.Protocol == "udp" {
			fids[pkt.FlowID] = true
		}
	}
	if len(fids) != 2 {
		t.Fatalf("want 2 distinct RTP flow IDs (3.10 parent:sub-idx), got %v", fids)
	}
	for _, want := range []string{":rtp-up", ":rtp-down"} {
		found := false
		for id := range fids {
			if strings.HasSuffix(id, want) {
				found = true
			}
		}
		if !found {
			t.Fatalf("flow ID suffix %q missing: %v", want, fids)
		}
	}
}

// D-SIP-2 WP-C 红例：RFC 3581 §4 rport/received 回填。
// Via 带 bare rport 参数 → 发射期回填 rport=<实际端口>;received=<srcIP>。
func TestNATBareRPortFill(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12001, DstPort: 5060,
		SIP: &core.SIPConfig{Dialog: []core.SIPMessage{
			{Method: "OPTIONS", URI: "sip:callee@20.0.0.1",
				Headers: []string{"Via: SIP/2.0/TCP 10.0.0.1:9999;branch=z9hG4bKx;rport"}},
			{StatusCode: 200, StatusText: "OK",
				Headers: []string{"Via: SIP/2.0/TCP 10.0.0.1:9999;branch=z9hG4bKx;rport=9999;received=10.0.0.1"}},
		}},
	}
	var p Planner
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	reqOK, respOK := false, false
	for pkt := range ch {
		text := string(pkt.Payload)
		if strings.Contains(text, "OPTIONS") {
			if strings.Contains(text, "rport=12001;received=10.0.0.1") {
				reqOK = true
			}
			if strings.Contains(text, "rport;") || strings.HasSuffix(text, "rport\r\n") {
				t.Fatalf("bare rport must be filled on outbound request")
			}
		}
		if strings.Contains(text, "SIP/2.0 200") {
			// down 响应=回放用户原文（含已回填形）——不二次改写
			if strings.Contains(text, "rport=9999;received=10.0.0.1") {
				respOK = true
			}
			if strings.Contains(text, "rport=12001") {
				t.Fatalf("response must replay user bytes verbatim (no rewrite)")
			}
		}
	}
	if !reqOK || !respOK {
		t.Fatalf("req fill=%v resp replay=%v", reqOK, respOK)
	}
}

// nat.rport=true 且 Via 无 rport 参数 → 开关强制回填。
func TestNATSwitchForcesFill(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12001, DstPort: 5060,
		SIP: &core.SIPConfig{NAT: &core.SIPNAT{RPort: true}, Dialog: []core.SIPMessage{
			{Method: "OPTIONS", URI: "sip:callee@20.0.0.1",
				Headers: []string{"Via: SIP/2.0/TCP 10.0.0.1:12001;branch=z9hG4bKy"}},
			{StatusCode: 200, StatusText: "OK"},
		}},
	}
	var p Planner
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	found := false
	for pkt := range ch {
		if strings.Contains(string(pkt.Payload), "rport=12001;received=10.0.0.1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("nat.rport switch must force rport/received fill")
	}
}

// 缺省透传零变化：无 nat、无 rport 参数 → Via 原样。
func TestNATDefaultPassthrough(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12001, DstPort: 5060,
		SIP: &core.SIPConfig{Dialog: []core.SIPMessage{
			{Method: "OPTIONS", URI: "sip:callee@20.0.0.1",
				Headers: []string{"Via: SIP/2.0/TCP 10.0.0.1:12001;branch=z9hG4bKz"}},
			{StatusCode: 200, StatusText: "OK"},
		}},
	}
	var p Planner
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for pkt := range ch {
		text := string(pkt.Payload)
		if strings.Contains(text, "rport=") || strings.Contains(text, "received=") {
			t.Fatalf("default must pass Via through untouched: %q", text)
		}
	}
}

// sessions 模式：回填端口=会话实际端口（非 spec 端口）。
func TestNATSessionsActualPort(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12001, DstPort: 5060,
		SIP: &core.SIPConfig{NAT: &core.SIPNAT{RPort: true}, Sessions: []core.SIPSession{
			{SrcPort: 22001, Dialog: []core.SIPMessage{
				{Method: "OPTIONS", URI: "sip:callee@20.0.0.1",
					Headers: []string{"Via: SIP/2.0/TCP 10.0.0.1:22001;branch=z9hG4bKs"}},
			}},
		}},
	}
	var p Planner
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	found := false
	for pkt := range ch {
		if strings.Contains(string(pkt.Payload), "rport=22001;received=10.0.0.1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("sessions mode must fill the session's actual port")
	}
}
