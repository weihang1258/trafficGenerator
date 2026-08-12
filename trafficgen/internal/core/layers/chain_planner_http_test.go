// 外部测试包：显式 import http 触发注册（内层 package layers 测试无法
// import http——layer_gen.go 的 http→layers 依赖会造成测试导入环）。
package layers_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	// 触发 http 包 init 注册 http 层生成器（RegisterHTTPGenerator 反向注册）。
	_ "github.com/trafficgen/trafficgen/internal/protocol/http"
)

// ---- 波 2 失败测试：http 链 [ip→tcp→http] 经 ChainPlanner 驱动 ----

// httpSpec builds a minimal HTTP flow spec with a GET request.
func httpSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 2000,
		DstPort: 80,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		HTTP: &core.HTTPConfig{
			Method: "GET",
			URI:    "/",
		},
	}
}

// TestChainPlanner_HTTP_ThreeLayerChain verifies the http chain
// [ip→tcp→http] drives through ChainPlanner: handshake (3), one
// request segment + one response segment (2), teardown (4) = 9 packets,
// with the data segments being PSH-ACK (0x18) with NO standalone ACKs
// between them (HTTP piggyback semantics, byte-compatible with http.go).
func TestChainPlanner_HTTP_ThreeLayerChain(t *testing.T) {
	p := layers.NewChainPlanner("http")
	ch, err := p.Plan(context.Background(), httpSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	// 9 packets: SYN, SYN-ACK, ACK, req(0x18), resp(0x18), FIN, ACK, FIN, ACK
	if len(pkts) != 9 {
		t.Fatalf("got %d packets, want 9 (handshake 3 + req/resp 2 + teardown 4)", len(pkts))
	}
	if pkts[0].L4.Flags != 0x02 {
		t.Errorf("packet 0 flags = 0x%x, want 0x02 SYN", pkts[0].L4.Flags)
	}
	if pkts[1].L4.Flags != 0x12 {
		t.Errorf("packet 1 flags = 0x%x, want 0x12 SYN-ACK", pkts[1].L4.Flags)
	}
	if pkts[2].L4.Flags != 0x10 {
		t.Errorf("packet 2 flags = 0x%x, want 0x10 ACK", pkts[2].L4.Flags)
	}
	// data segments: request (up, 0x18, carries request line), response (down, 0x18)
	if pkts[3].L4.Flags != 0x18 || pkts[3].Direction != "up" {
		t.Errorf("packet 3 = flags 0x%x dir %s, want 0x18 up (request)", pkts[3].L4.Flags, pkts[3].Direction)
	}
	if !strings.Contains(string(pkts[3].Payload), "GET / HTTP/1.1") {
		t.Errorf("request payload = %q, want request line", string(pkts[3].Payload))
	}
	if pkts[4].L4.Flags != 0x18 || pkts[4].Direction != "down" {
		t.Errorf("packet 4 = flags 0x%x dir %s, want 0x18 down (response)", pkts[4].L4.Flags, pkts[4].Direction)
	}
	if !strings.Contains(string(pkts[4].Payload), "HTTP/1.1 200") {
		t.Errorf("response payload = %q, want status line", string(pkts[4].Payload))
	}
	// teardown
	if pkts[5].L4.Flags != 0x11 || pkts[5].Direction != "up" {
		t.Errorf("packet 5 = flags 0x%x dir %s, want 0x11 up FIN-ACK", pkts[5].L4.Flags, pkts[5].Direction)
	}
	if pkts[6].L4.Flags != 0x10 || pkts[6].Direction != "down" {
		t.Errorf("packet 6 = flags 0x%x dir %s, want 0x10 down ACK", pkts[6].L4.Flags, pkts[6].Direction)
	}
	if pkts[7].L4.Flags != 0x11 || pkts[7].Direction != "down" {
		t.Errorf("packet 7 = flags 0x%x dir %s, want 0x11 down FIN-ACK", pkts[7].L4.Flags, pkts[7].Direction)
	}
	if pkts[8].L4.Flags != 0x10 || pkts[8].Direction != "up" {
		t.Errorf("packet 8 = flags 0x%x dir %s, want 0x10 up ACK", pkts[8].L4.Flags, pkts[8].Direction)
	}
}

// TestChainPlanner_HTTP_SeqAdvances verifies the bidirectional seq/ack
// progression of the http chain: request seq advances by its payload
// length, response seq advances by its payload length, the next
// direction's ack reflects the peer's current seq (piggyback).
func TestChainPlanner_HTTP_SeqAdvances(t *testing.T) {
	p := layers.NewChainPlanner("http")
	ch, err := p.Plan(context.Background(), httpSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	// seq anchors: SYN.Seq = clientSeq, SYN-ACK.Seq = serverSeq.
	clientISN := pkts[0].L4.Seq
	serverISN := pkts[1].L4.Seq
	reqLen := uint32(len(pkts[3].Payload))
	respLen := uint32(len(pkts[4].Payload))
	// request: seq = clientISN+1 (post-SYN), ack = serverISN+1 (post-SYN-ACK).
	if pkts[3].L4.Seq != clientISN+1 {
		t.Errorf("request seq = %d, want %d", pkts[3].L4.Seq, clientISN+1)
	}
	if pkts[3].L4.Ack != serverISN+1 {
		t.Errorf("request ack = %d, want %d", pkts[3].L4.Ack, serverISN+1)
	}
	// response: seq = serverISN+1, ack = clientISN+1+reqLen (acks the request).
	if pkts[4].L4.Seq != serverISN+1 {
		t.Errorf("response seq = %d, want %d", pkts[4].L4.Seq, serverISN+1)
	}
	if pkts[4].L4.Ack != clientISN+1+reqLen {
		t.Errorf("response ack = %d, want %d", pkts[4].L4.Ack, clientISN+1+reqLen)
	}
	// teardown: client FIN seq = clientISN+1+reqLen, ack = serverISN+1+respLen.
	if pkts[5].L4.Seq != clientISN+1+reqLen || pkts[5].L4.Ack != serverISN+1+respLen {
		t.Errorf("client FIN seq/ack = %d/%d, want %d/%d",
			pkts[5].L4.Seq, pkts[5].L4.Ack, clientISN+1+reqLen, serverISN+1+respLen)
	}
}

// TestChainPlanner_HTTP_NoStandaloneAckBetweenSegments verifies the
// critical HTTP semantic: segments carry piggybacked acks, never a
// standalone ACK packet between data segments (byte-compatible with the
// legacy http.go — the http tests assert this with exact packet counts).
func TestChainPlanner_HTTP_NoStandaloneAckBetweenSegments(t *testing.T) {
	spec := httpSpec()
	spec.HTTP = &core.HTTPConfig{
		Method: "POST",
		URI:    "/upload",
		// 3000 bytes forces 3 request segments at MSS 1460 (3*1460=4380).
		Body: strings.Repeat("x", 3000),
	}
	p := layers.NewChainPlanner("http")
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	// 3 handshake + 3 request segs + 1 response seg + 4 teardown = 11.
	if len(pkts) != 11 {
		t.Fatalf("got %d packets, want 11 (no standalone ACKs inserted)", len(pkts))
	}
	// every request segment is 0x18, no pure-ACK (0x10) data packets.
	for i := 3; i < 7; i++ {
		if pkts[i].L4.Flags != 0x18 {
			t.Errorf("packet %d flags = 0x%x, want 0x18 (no standalone ACK between segments)", i, pkts[i].L4.Flags)
		}
	}
}

// TestChainPlanner_HTTP_Pipelined verifies the pipelined transaction
// ordering: all requests before any response.
func TestChainPlanner_HTTP_Pipelined(t *testing.T) {
	spec := httpSpec()
	spec.HTTP = &core.HTTPConfig{Method: "GET", URI: "/", Transactions: 2, Pipelined: true}
	p := layers.NewChainPlanner("http")
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	// 3 handshake + 2 req + 2 resp + 4 teardown = 11.
	if len(pkts) != 11 {
		t.Fatalf("got %d packets, want 11", len(pkts))
	}
	// directions after handshake: up,up,down,down (all reqs then all resps).
	got := ""
	for _, p := range pkts[3:7] {
		if p.Direction == "up" {
			got += "U"
		} else {
			got += "D"
		}
	}
	if got != "UUDD" {
		t.Errorf("data directions = %s, want UUDD (pipelined: reqs then resps)", got)
	}
}

// ---- 波 2 review findings 回归测试 ----

// TestChainPlanner_HTTP_TCPSegConfigIgnored verifies the legacy http
// semantics (review finding 3): an http chain ignores spec.TCP's
// handshake/termination/rst switches — handshake and teardown always
// happen, no RST (legacy http.go never reads those fields). Only MSS and
// InitialSeq flow through (legacy http.go:126-151 reads those).
func TestChainPlanner_HTTP_TCPSegConfigIgnored(t *testing.T) {
	spec := httpSpec()
	spec.TCP = &core.TCPConfig{
		Handshake:   false,
		Termination: false,
		RST:         true,
		InitialSeq:  1000,
	}
	p := layers.NewChainPlanner("http")
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	// handshake always on: 9 packets (SYN + SYN-ACK + ACK + req + resp + 4 teardown).
	if len(pkts) != 9 {
		t.Fatalf("got %d packets, want 9 (handshake/termination always on, no RST)", len(pkts))
	}
	if pkts[0].L4.Flags != 0x02 {
		t.Errorf("packet 0 flags = 0x%x, want 0x02 SYN (handshake forced on)", pkts[0].L4.Flags)
	}
	// no RST anywhere.
	for i, pkt := range pkts {
		if pkt.L4.Flags&0x04 != 0 {
			t.Errorf("packet %d has RST flag 0x%x, want none (rst ignored for http)", i, pkt.L4.Flags)
		}
	}
	// window stays at the legacy hardcoded 65535 (spec.TCP.WindowSize is
	// never injected for http chains — legacy http.go hardcodes 65535).
	for i, pkt := range pkts {
		if pkt.L4.WindowSize != 65535 {
			t.Errorf("packet %d window = %d, want 65535 (legacy http constant)", i, pkt.L4.WindowSize)
		}
	}
	// InitialSeq still effective (legacy http.go:128-129 reads it).
	if pkts[0].L4.Seq != 1000 {
		t.Errorf("SYN seq = %d, want 1000 (InitialSeq flows through)", pkts[0].L4.Seq)
	}
}

// TestChainPlanner_HTTP_TCPGenFailAbortsWithoutHang guards the event-wiring
// shutdown invariant: when the tcp generator fails before consuming the
// event stream (resolveCfg reject), the drive must still converge and close
// out in bounded time — the http generator must never remain blocked on a
// full event channel. Review agent (MEDIUM-1) flagged a possible hang when
// events > eventCh capacity; analysis showed the hang is structurally
// unreachable today (EmitMsg's select listens on ctx.Done, the only way a
// producer can stall; tcp failure exits promptly and closes the stream), so
// this test pins the invariant: Plan must return in bounded time even with
// 200 events (> 64-channel capacity) and a failing tcp layer.
func TestChainPlanner_HTTP_TCPGenFailAbortsWithoutHang(t *testing.T) {
	spec := httpSpec()
	spec.HTTP.Transactions = 100 // 200 events >> 64-event channel capacity
	p := layers.NewChainPlanner("http")
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// 失败发生在 drive goroutine 内（被吞，Plan 返回空流——波 1 既有契约）：
	// 本测试只断言收敛（不挂死），不断言错误值。
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = p.Plan(context.Background(), spec)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("Plan hung (drive did not converge on tcp generator failure)")
	}
}

// TestChainPlanner_HTTP_HTTPGenCancelMidStreamConverges exercises the
// http-first-failure path (review verifier D3): when the http generator
// fails mid-stream — its EmitMsg select hits ctx.Done, the only failure
// path reachable in the wired context — drive's failure handling
// (lastErr != nil → close(eventCh) → <-tcpDone → close(innerCh) → <-genDone)
// must converge in bounded time, and the tail sends to out must finish
// before close(out) (no send-on-closed panic, the CRITICAL-1 class, but
// on the event-wiring branch). 200 events can be parked mid-write when the
// cancel lands, so convergence is the property under test.
func TestChainPlanner_HTTP_HTTPGenCancelMidStreamConverges(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := layers.NewChainPlanner("http")
	spec := httpSpec()
	spec.HTTP.Transactions = 100 // 200 events; pending EmitMsg sends at cancel
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	// Cancel right after the handshake: the http generator is mid-stream,
	// tcp 层正在消费事件。取消后三个生成器都必须经 select ctx.Done 收敛；
	// 已收集的包（≥3 握手）必须完整送达后才关闭 out。
	idx := 0
	var first core.PacketConfig
	done := make(chan struct{})
	go func() {
		defer close(done)
		for c := range ch {
			if idx == 3 {
				cancel()
			}
			if idx == 0 {
				first = c
			}
			_ = c
			idx++
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("http chain did not converge on http-generator cancel (goroutine leak / blocked send)")
	}
	if idx < 3 {
		t.Errorf("flow yielded %d packets, want >= 3 (handshake collected before cancel must be delivered)", idx)
	}
	if first.L4.Flags != 0x02 {
		t.Errorf("packet 0 flags = 0x%x, want 0x02 SYN (http chain handshake ran before cancel)", first.L4.Flags)
	}
}

// ---- review CRITICAL 回归：事件模式忽略 spec.Payload ----
// legacy http planner 从不读 spec.Payload——数据段只有 HTTP 报文。若
// TCPGenerator 在事件流前先发 Meta.Payload 单 payload 段，http flow 带
// spec.Payload 时会多出一个非 HTTP PSH-ACK 段（wire 上与 legacy 不兼容，
// 11 包 vs 9 包）。事件模式（Meta.Events != nil）必须跳过 payload 段。
func TestChainPlanner_HTTP_SpecPayloadIgnoredInEventMode(t *testing.T) {
	base := httpSpec()

	withPayload := base
	withPayload.Payload = []byte("EXTRA-FLOW-PAYLOAD") // 与 HTTP 子配置并存

	p := layers.NewChainPlanner("http")
	chNo, err := p.Plan(context.Background(), base)
	if err != nil {
		t.Fatalf("Plan(base): %v", err)
	}
	chYes, err := p.Plan(context.Background(), withPayload)
	if err != nil {
		t.Fatalf("Plan(withPayload): %v", err)
	}
	var no, yes []core.PacketConfig
	for c := range chNo {
		no = append(no, c)
	}
	for c := range chYes {
		yes = append(yes, c)
	}
	// 包数与每包 payload 均须一致：EXTRA-FLOW-PAYLOAD 不得出现在任何段里。
	if len(no) != len(yes) {
		t.Fatalf("with payload: %d packets, without: %d — payload must be ignored in event mode", len(yes), len(no))
	}
	for i := range no {
		if !bytes.Equal(no[i].Payload, yes[i].Payload) {
			t.Errorf("packet %d payload differs with/without spec.Payload:\nno   %q\nyes  %q",
				i, no[i].Payload, yes[i].Payload)
		}
	}
	if len(yes) != 9 {
		t.Errorf("with payload: %d packets, want 9 (handshake 3 + req/resp 2 + teardown 4)", len(yes))
	}
	for i, c := range yes {
		if bytes.Contains(c.Payload, []byte("EXTRA-FLOW-PAYLOAD")) {
			t.Errorf("packet %d contains spec.Payload bytes, want ignored in event mode", i)
		}
	}
}
