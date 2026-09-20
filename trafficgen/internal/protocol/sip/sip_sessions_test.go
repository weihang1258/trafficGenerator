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
