package sip

// D-SIP-2 WP-D 红例（failing 先行）：事件面（[ip,tcp,(tls),sip] 链）。
// 头补全状态机/Via/NAT 全部复用自驱路径同函数——断言字节形状与自驱一致；
// [ip,sip] 自驱字节零回归线由既有 80 例套件守。

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// eventCollect drives the Generator in event mode over a synthetic chain and
// returns the emitted message events in order.
func eventCollect(t *testing.T, chainNames []string, cfg *core.SIPConfig) []layers.MessageEvent {
	t.Helper()
	g := &Generator{legacy: NewPlanner()}
	chain := make([]layers.Layer, len(chainNames))
	for i, n := range chainNames {
		chain[i] = layers.Layer{Name: n}
	}
	g.InitChain(chain)
	var evs []layers.MessageEvent
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{SIP: cfg, SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12001, DstPort: 5060},
		EmitMsg: func(ev layers.MessageEvent) error {
			evs = append(evs, ev)
			return nil
		},
	}
	if err := g.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return evs
}

var eventDialog = []core.SIPMessage{
	{Method: "OPTIONS", URI: "sip:callee@20.0.0.1"},
	{StatusCode: 200, StatusText: "OK"},
}

// 双模式分派：[ip,sip] 恒 nil（自驱字节零回归线）；链含 tcp/tls 才激活。
func TestSIPGeneratorDualModeDispatch(t *testing.T) {
	g := &Generator{legacy: NewPlanner()}
	if g.GenEvents() != nil {
		t.Fatal("raw [ip, sip] chain must stay self-drive (GenEvents nil)")
	}
	g.InitChain([]layers.Layer{{Name: "ip"}, {Name: "sip"}})
	if g.GenEvents() != nil {
		t.Fatal("[ip, sip] via InitChain must stay self-drive")
	}
	g.InitChain([]layers.Layer{{Name: "ip"}, {Name: "tcp"}, {Name: "sip"}})
	if g.GenEvents() == nil {
		t.Fatal("tcp chain must activate event mode")
	}
	g.InitChain([]layers.Layer{{Name: "ip"}, {Name: "tcp"}, {Name: "tls"}, {Name: "sip"}})
	if g.GenEvents() == nil {
		t.Fatal("tls chain must activate event mode")
	}
}

// 事件面基本流：dialog 翻 MessageEvents，方向 up/down 与自驱一致；
// 六强制头补全（RFC 3261 §8.1.1）在事件面同款生效。
func TestSIPEventModeBasic(t *testing.T) {
	evs := eventCollect(t, []string{"ip", "tcp", "sip"},
		&core.SIPConfig{Dialog: eventDialog})
	if len(evs) != 2 {
		t.Fatalf("events=%d want 2", len(evs))
	}
	if !evs[0].Up || evs[1].Up {
		t.Fatalf("directions wrong: ev0.Up=%v ev1.Up=%v", evs[0].Up, evs[1].Up)
	}
	req := string(evs[0].Bytes)
	for _, want := range []string{
		"OPTIONS sip:callee@20.0.0.1 SIP/2.0\r\n",
		"Via: SIP/2.0/TCP 10.0.0.1:12001;branch=",
		"Call-ID: ", "From: ", "To: ", "CSeq: 1 OPTIONS", "Max-Forwards: 70",
	} {
		if !strings.Contains(req, want) {
			t.Fatalf("request missing %q:\n%s", want, req)
		}
	}
	resp := string(evs[1].Bytes)
	if !strings.Contains(resp, "SIP/2.0 200 OK\r\n") {
		t.Fatalf("response status-line broken: %q", resp)
	}
	if !strings.Contains(resp, "CSeq: 1 OPTIONS") {
		t.Fatalf("response must echo the request CSeq (RFC 3261 §8.1.3.2): %q", resp)
	}
}

// tls 链：生成 Via 传输令牌 = TLS（RFC 3261 §26.2.1）；用户显式 Via 恒赢。
func TestSIPEventModeTLSViaTransport(t *testing.T) {
	evs := eventCollect(t, []string{"ip", "tcp", "tls", "sip"},
		&core.SIPConfig{Dialog: eventDialog})
	if !strings.Contains(string(evs[0].Bytes), "Via: SIP/2.0/TLS 10.0.0.1:12001;branch=") {
		t.Fatalf("tls chain must generate Via transport TLS: %q", evs[0].Bytes)
	}

	evs = eventCollect(t, []string{"ip", "tcp", "tls", "sip"},
		&core.SIPConfig{Dialog: []core.SIPMessage{
			{Method: "OPTIONS", URI: "sip:callee@20.0.0.1",
				Headers: []string{"Via: SIP/2.0/TCP 10.0.0.1:12001;branch=z9hG4bKu"}},
			{StatusCode: 200, StatusText: "OK"},
		}})
	if !strings.Contains(string(evs[0].Bytes), "Via: SIP/2.0/TCP 10.0.0.1:12001;branch=z9hG4bKu\r\n") {
		t.Fatalf("user Via must win verbatim on the tls chain: %q", evs[0].Bytes)
	}
}

// 事件面形状拒绝（mqtt 双保险纪律）：sessions 与 media/medias 无等价物。
func TestSIPEventModeShapeRejections(t *testing.T) {
	g := &Generator{legacy: NewPlanner()}
	g.InitChain([]layers.Layer{{Name: "ip"}, {Name: "tcp"}, {Name: "sip"}})
	emit := func(layers.MessageEvent) error { return nil }

	err := g.Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{SIP: &core.SIPConfig{Sessions: []core.SIPSession{
			{Dialog: eventDialog},
		}}, SrcIP: "10.0.0.1"}, EmitMsg: emit})
	if err == nil || !strings.Contains(err.Error(), "sessions are not supported on a tcp/tls sip chain") {
		t.Fatalf("want sessions rejection, got %v", err)
	}

	err = g.Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{SIP: &core.SIPConfig{
			Media: &core.SIPMedia{Frames: 2}, Dialog: eventDialog}, SrcIP: "10.0.0.1"}, EmitMsg: emit})
	if err == nil || !strings.Contains(err.Error(), "media is not supported on a tcp/tls sip chain") {
		t.Fatalf("want media rejection, got %v", err)
	}
}

// sips: URI 在无 tls 链上判死（RFC 3261 §26.2.2，运行时背 door）。
func TestSIPEventModeSIPSNeedsTLS(t *testing.T) {
	g := &Generator{legacy: NewPlanner()}
	g.InitChain([]layers.Layer{{Name: "ip"}, {Name: "tcp"}, {Name: "sip"}})
	err := g.Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{SIP: &core.SIPConfig{Dialog: []core.SIPMessage{
			{Method: "INVITE", URI: "sips:callee@20.0.0.1"},
		}}, SrcIP: "10.0.0.1"},
		EmitMsg: func(layers.MessageEvent) error { return nil }})
	if err == nil || !strings.Contains(err.Error(), "sip: sips uri requires a tls layer in the chain") {
		t.Fatalf("want sips-needs-tls rejection, got %v", err)
	}
}

// NAT rport 在事件面复用（WP-C 同一 rewrite 函数；端口=流真值 src 口）。
func TestSIPEventModeNATRPort(t *testing.T) {
	evs := eventCollect(t, []string{"ip", "tcp", "sip"},
		&core.SIPConfig{NAT: &core.SIPNAT{RPort: true}, Dialog: []core.SIPMessage{
			{Method: "OPTIONS", URI: "sip:callee@20.0.0.1",
				Headers: []string{"Via: SIP/2.0/TCP 10.0.0.1:12001;branch=z9hG4bKn"}},
			{StatusCode: 200, StatusText: "OK"},
		}})
	if !strings.Contains(string(evs[0].Bytes), "rport=12001;received=10.0.0.1") {
		t.Fatalf("nat rport must fill on the event plane: %q", evs[0].Bytes)
	}
}
