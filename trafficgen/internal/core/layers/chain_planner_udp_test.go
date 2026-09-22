// 外部测试包：独立 udp 链的字节级对比需要 legacy udp.NewPlanner
// （internal/protocol/udp）。external package 也让测试贴近真实调用方（main.go）。
package layers_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/udp"
)

// udpSpec builds a minimal UDP flow spec.
func udpSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP:   "10.0.0.1",
		DstIP:   "10.0.0.2",
		SrcPort: 12345,
		DstPort: 53,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		Payload: []byte("test"),
	}
}

// collect runs a planner's Plan and gathers all packets.
func collect(t *testing.T, p core.ProtocolPlanner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts
}

// maskRandomIPFields zeroes the IPv4 identification (offset 18-19) and IP
// header checksum (offset 24-25) bytes: IPID starts at a per-flow random
// value in both planners, and the IP checksum covers it, so two independent
// runs cannot match on those bytes. Everything else must be byte-identical.
func maskRandomIPFields(pkt []byte) []byte {
	out := append([]byte(nil), pkt...)
	if len(out) > 25 {
		out[18], out[19] = 0, 0 // IPID
		out[24], out[25] = 0, 0 // IP header checksum
	}
	return out
}

// TestChainPlanner_UDP_SingleDatagram verifies the standalone [ip→udp] chain:
// one up packet with the flow payload, ports and L3 protocol 17 (UDP),
// byte-identical to the legacy udp.NewPlanner output.
func TestChainPlanner_UDP_SingleDatagram(t *testing.T) {
	spec := udpSpec()
	chain := collect(t, layers.NewChainPlanner("udp"), spec)
	legacy := collect(t, udp.NewPlanner(), spec)

	if len(chain) != 1 {
		t.Fatalf("chain produced %d packets, want 1", len(chain))
	}
	if chain[0].Direction != "up" {
		t.Errorf("direction = %s, want up", chain[0].Direction)
	}
	if chain[0].L4.Protocol != "udp" {
		t.Errorf("L4.Protocol = %s, want udp", chain[0].L4.Protocol)
	}
	if chain[0].L4.SrcPort != 12345 || chain[0].L4.DstPort != 53 {
		t.Errorf("ports = %d/%d, want 12345/53", chain[0].L4.SrcPort, chain[0].L4.DstPort)
	}
	if chain[0].L3.Protocol != core.ProtocolUDP {
		t.Errorf("L3.Protocol = %d, want %d (UDP 17)", chain[0].L3.Protocol, core.ProtocolUDP)
	}
	if !bytes.Equal(chain[0].Payload, []byte("test")) {
		t.Errorf("payload = %q, want \"test\"", chain[0].Payload)
	}

	b := core.NewBuilder()
	chainBytes, err := b.Build(chain[0])
	if err != nil {
		t.Fatalf("Build(chain): %v", err)
	}
	legacyBytes, err := b.Build(legacy[0])
	if err != nil {
		t.Fatalf("Build(legacy): %v", err)
	}
	if !bytes.Equal(maskRandomIPFields(chainBytes), maskRandomIPFields(legacyBytes)) {
		t.Errorf("bytes differ from legacy planner:\nchain  %x\nlegacy %x", chainBytes, legacyBytes)
	}
}

// TestChainPlanner_UDP_ResponseDatagram verifies IsResponse=true adds the
// down datagram (swapped ports, swapped MACs, same payload), matching the
// legacy planner's 2-packet sequence byte-for-byte.
func TestChainPlanner_UDP_ResponseDatagram(t *testing.T) {
	spec := udpSpec()
	spec.UDP = &core.UDPConfig{IsResponse: true}
	chain := collect(t, layers.NewChainPlanner("udp"), spec)
	legacy := collect(t, udp.NewPlanner(), spec)

	if len(chain) != 2 {
		t.Fatalf("chain produced %d packets, want 2", len(chain))
	}
	if chain[0].Direction != "up" || chain[1].Direction != "down" {
		t.Errorf("directions = %s/%s, want up/down", chain[0].Direction, chain[1].Direction)
	}
	if chain[1].L4.SrcPort != 53 || chain[1].L4.DstPort != 12345 {
		t.Errorf("response ports = %d/%d, want 53/12345", chain[1].L4.SrcPort, chain[1].L4.DstPort)
	}
	if chain[1].L2.SrcMAC != "11:22:33:44:55:66" || chain[1].L2.DstMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("response MACs = %s→%s, want swapped", chain[1].L2.SrcMAC, chain[1].L2.DstMAC)
	}
	if !bytes.Equal(chain[1].Payload, []byte("test")) {
		t.Errorf("response payload = %q, want \"test\"", chain[1].Payload)
	}

	b := core.NewBuilder()
	for i := 0; i < 2; i++ {
		cb, err := b.Build(chain[i])
		if err != nil {
			t.Fatalf("Build(chain[%d]): %v", i, err)
		}
		lb, err := b.Build(legacy[i])
		if err != nil {
			t.Fatalf("Build(legacy[%d]): %v", i, err)
		}
		if !bytes.Equal(maskRandomIPFields(cb), maskRandomIPFields(lb)) {
			t.Errorf("packet %d bytes differ:\nchain  %x\nlegacy %x", i, cb, lb)
		}
	}
}

// TestChainPlanner_UDP_DisableChecksum verifies DisableChecksum flows through
// Meta.UDP into the packet Metadata, and the builder emits a zero UDP
// checksum field (builder writeUDP reads udp_disable_checksum).
func TestChainPlanner_UDP_DisableChecksum(t *testing.T) {
	spec := udpSpec()
	spec.UDP = &core.UDPConfig{DisableChecksum: true}
	chain := collect(t, layers.NewChainPlanner("udp"), spec)
	if v, ok := chain[0].Metadata["udp_disable_checksum"].(bool); !ok || !v {
		t.Fatalf("Metadata[udp_disable_checksum] = %v, want true", chain[0].Metadata["udp_disable_checksum"])
	}
	b := core.NewBuilder()
	pkt, err := b.Build(chain[0])
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// UDP header starts at 14 (eth) + 20 (IPv4) = 34; checksum = bytes 40-41.
	cksum := uint16(pkt[40])<<8 | uint16(pkt[41])
	if cksum != 0 {
		t.Errorf("UDP checksum = 0x%04x, want 0x0000 (disable_checksum)", cksum)
	}
}

// TestChainPlanner_UDP_LargePayloadWarnsOnly mirrors the legacy udp planner's
// Validate contract: payload > 1472 (typical MTU) warns but does not fail.
func TestChainPlanner_UDP_LargePayloadWarnsOnly(t *testing.T) {
	spec := udpSpec()
	spec.Payload = make([]byte, 2000) // > 1472 typical MTU
	if err := layers.NewChainPlanner("udp").Validate(spec); err != nil {
		t.Fatalf("Validate(large payload) error = %v, want warning only", err)
	}
}

// TestChainPlanner_UDP_MissingPorts verifies the udp chain validates the same
// spec as legacy udp (ports required).
func TestChainPlanner_UDP_MissingPorts(t *testing.T) {
	p := layers.NewChainPlanner("udp")
	spec := udpSpec()
	spec.SrcPort = 0
	if err := p.Validate(spec); err == nil {
		t.Error("Validate(missing src_port) = nil, want error")
	}
}

// ---- 波 3 泛化接线：终结层事件生成器 → udp 层 ----

// testTerminalGen is a test-only terminal generator: it emits scripted
// MessageEvents via req.EmitMsg, then returns (the ChainPlanner closes the
// event channel after Generate returns).
type testTerminalGen struct {
	events []layers.MessageEvent
}

// Name returns "testterminal".
func (g *testTerminalGen) Name() string { return "testterminal" }

// GenEvents marks this generator as an event producer.
func (g *testTerminalGen) GenEvents() layers.EventGenerator { return g }

// EmitEvent is the EventGenerator interface method; the wired path routes
// through req.EmitMsg, so calling this directly is an error.
func (g *testTerminalGen) EmitEvent(ev layers.MessageEvent) error {
	return nil
}

// Generate emits the scripted events in order. The udp layer consumes
// direction from each event (up → src:spec ports, down → swapped ports).
func (g *testTerminalGen) Generate(ctx context.Context, req *layers.GenRequest) error {
	for _, ev := range g.events {
		if err := req.EmitMsg(ev); err != nil {
			return err
		}
	}
	return nil
}

// TestChainPlanner_UDP_LayerChainEventWiring drives the full event-wiring
// generalization (波 3): a terminal layer named "udp-flow" (depends_on [udp],
// CategoryTerminal) is injected into a custom registry; its generator emits
// 2 events (up, down) through req.EmitMsg. Plan("udp-flow") builds
// [ip→udp→udp-flow] and the generalized branch must reach UDPGenerator: one
// datagram per event, direction from the event, ports swapped on down,
// L3.Protocol = 17. 若接线泛化失败（仍硬编码 TCPGenerator），断言会以
// panic 或错误暴露。
func TestChainPlanner_UDP_LayerChainEventWiring(t *testing.T) {
	layers.RegisterLayerGeneratorForTest("udp-flow", func() (layers.LayerGenerator, error) {
		return &testTerminalGen{events: []layers.MessageEvent{
			{Up: true, Bytes: []byte("query")},
			{Up: false, Bytes: []byte("answer")},
		}}, nil
	})
	t.Cleanup(func() { layers.UnregisterLayerGeneratorForTest("udp-flow") })

	r := layers.NewRegistry()
	if err := r.Register(layers.LayerSchema{Name: "udp-flow", Category: layers.CategoryTerminal,
		DependsOn: []string{"udp"}}); err != nil {
		t.Fatalf("register udp-flow: %v", err)
	}
	if err := r.Register(layers.LayerSchema{Name: "udp", Category: layers.CategoryTransport,
		DependsOn: []string{"ip"},
		Fields: map[string]layers.FieldSchema{
			"src_port": {Type: "uint16"},
			"dst_port": {Type: "uint16"},
		},
	}); err != nil {
		t.Fatalf("register udp: %v", err)
	}
	if err := r.Register(layers.LayerSchema{Name: "ip", Category: layers.CategoryNetwork,
		Fields: map[string]layers.FieldSchema{
			"src": {Type: "ip"}, "dst": {Type: "ip"},
		},
	}); err != nil {
		t.Fatalf("register ip: %v", err)
	}

	p := layers.NewChainPlannerWithRegistry("udp-flow", r)
	spec := udpSpec()
	spec.UDP = &core.UDPConfig{IsResponse: true} // 事件驱动下无作用（终结层决定方向）
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) != 2 {
		t.Fatalf("got %d packets, want 2 (one datagram per event)", len(pkts))
	}
	if pkts[0].Direction != "up" || pkts[1].Direction != "down" {
		t.Errorf("directions = %s/%s, want up/down (from events)", pkts[0].Direction, pkts[1].Direction)
	}
	if !bytes.Equal(pkts[0].Payload, []byte("query")) || !bytes.Equal(pkts[1].Payload, []byte("answer")) {
		t.Errorf("payloads = %q / %q, want \"query\"/\"answer\"", pkts[0].Payload, pkts[1].Payload)
	}
	if pkts[0].L3.Protocol != core.ProtocolUDP {
		t.Errorf("packet 0 L3.Protocol = %d, want %d (UDP 17)", pkts[0].L3.Protocol, core.ProtocolUDP)
	}
	if pkts[1].L4.SrcPort != 53 || pkts[1].L4.DstPort != 12345 {
		t.Errorf("down ports = %d/%d, want 53/12345 (swapped)", pkts[1].L4.SrcPort, pkts[1].L4.DstPort)
	}
	// 独立模式（无事件）的 IsResponse 双包在这里不能出现：事件流已接管。
	if pkts[0].L3.Protocol != core.ProtocolUDP {
		t.Errorf("packet 0 L3.Protocol = %d, want %d (UDP 17)", pkts[0].L3.Protocol, core.ProtocolUDP)
	}
}

// TestChainPlanner_UDP_EventDriven_EmptyEvents verifies the event-wiring
// shutdown semantics for the udp transport: a terminal generator that emits
// no events still converges — no packets, no hang, Plan returns promptly.
func TestChainPlanner_UDP_EventDriven_EmptyEvents(t *testing.T) {
	layers.RegisterLayerGeneratorForTest("udp-empty", func() (layers.LayerGenerator, error) {
		return &testTerminalGen{}, nil
	})
	t.Cleanup(func() { layers.UnregisterLayerGeneratorForTest("udp-empty") })
	r := layers.NewRegistry()
	for _, s := range []layers.LayerSchema{
		{Name: "udp-empty", Category: layers.CategoryTerminal, DependsOn: []string{"udp"}},
		{Name: "udp", Category: layers.CategoryTransport, DependsOn: []string{"ip"},
			Fields: map[string]layers.FieldSchema{
				"src_port": {Type: "uint16"},
				"dst_port": {Type: "uint16"},
			}},
		{Name: "ip", Category: layers.CategoryNetwork,
			Fields: map[string]layers.FieldSchema{"src": {Type: "ip"}, "dst": {Type: "ip"}}},
	} {
		if err := r.Register(s); err != nil {
			t.Fatalf("register %s: %v", s.Name, err)
		}
	}
	p := layers.NewChainPlannerWithRegistry("udp-empty", r)
	spec := udpSpec()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	for range ch {
		n++
	}
	if n != 0 {
		t.Errorf("got %d packets from empty event stream, want 0", n)
	}
}

// ---- review 回归：L3 事件模式 + DisableChecksum 组合 ----
// 事件模式下 meta() 恒写 udp_disable_checksum 键：false 也是显式键
// （legacy 语义），不能只写 true。事件流经 udp 层产包时必须带上该键。
func TestChainPlanner_UDP_EventDriven_DisableChecksumMeta(t *testing.T) {
	layers.RegisterLayerGeneratorForTest("udp-cksum", func() (layers.LayerGenerator, error) {
		return &testTerminalGen{events: []layers.MessageEvent{{Up: true, Bytes: []byte("q")}}}, nil
	})
	t.Cleanup(func() { layers.UnregisterLayerGeneratorForTest("udp-cksum") })
	r := layers.NewRegistry()
	for _, s := range []layers.LayerSchema{
		{Name: "udp-cksum", Category: layers.CategoryTerminal, DependsOn: []string{"udp"}},
		{Name: "udp", Category: layers.CategoryTransport, DependsOn: []string{"ip"},
			Fields: map[string]layers.FieldSchema{
				"src_port": {Type: "uint16"},
				"dst_port": {Type: "uint16"},
			}},
		{Name: "ip", Category: layers.CategoryNetwork,
			Fields: map[string]layers.FieldSchema{"src": {Type: "ip"}, "dst": {Type: "ip"}}},
	} {
		if err := r.Register(s); err != nil {
			t.Fatalf("register %s: %v", s.Name, err)
		}
	}
	spec := udpSpec()
	spec.UDP = &core.UDPConfig{DisableChecksum: true}
	p := layers.NewChainPlannerWithRegistry("udp-cksum", r)
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) != 1 {
		t.Fatalf("got %d packets, want 1", len(pkts))
	}
	if v, ok := pkts[0].Metadata["udp_disable_checksum"].(bool); !ok || !v {
		t.Errorf("event-mode Metadata[udp_disable_checksum] = %v, want true", pkts[0].Metadata["udp_disable_checksum"])
	}
}

// ---- review 回归：H2 事件接线 transport 断言失败路径 ----
// 泛化分支对传输层做 *TCPGenerator/*UDPGenerator 类型断言，default 必须
// 显式报错。注册一个"非 tcp/udp 传输层 + 事件终结层"的链，Plan 必须返回
// "cannot consume terminal events" 而非静默降级/吞掉事件。
func TestChainPlanner_UDP_UnsupportedTransportWithEventsFails(t *testing.T) {
	layers.RegisterLayerGeneratorForTest("gre-events", func() (layers.LayerGenerator, error) {
		return &testTerminalGen{events: []layers.MessageEvent{{Up: true, Bytes: []byte("x")}}}, nil
	})
	t.Cleanup(func() { layers.UnregisterLayerGeneratorForTest("gre-events") })
	// gre 也须可实例化：预检（newGenerator）通过后链才走到事件接线的
	// transport 断言分支——gre 不是 tcp/udp，断言必须显式报错。
	layers.RegisterLayerGeneratorForTest("gre", func() (layers.LayerGenerator, error) {
		return &testTerminalGen{}, nil
	})
	t.Cleanup(func() { layers.UnregisterLayerGeneratorForTest("gre") })
	r := layers.NewRegistry()
	for _, s := range []layers.LayerSchema{
		{Name: "gre-events", Category: layers.CategoryTerminal, DependsOn: []string{"gre"}},
		{Name: "gre", Category: layers.CategoryTransport, DependsOn: []string{"ip"}},
		{Name: "ip", Category: layers.CategoryNetwork,
			Fields: map[string]layers.FieldSchema{"src": {Type: "ip"}, "dst": {Type: "ip"}}},
	} {
		if err := r.Register(s); err != nil {
			t.Fatalf("register %s: %v", s.Name, err)
		}
	}
	p := layers.NewChainPlannerWithRegistry("gre-events", r)
	spec := udpSpec()
	_, err := p.Plan(context.Background(), spec)
	if err == nil {
		t.Fatal("Plan() = nil err, want 'cannot consume terminal events' for non-tcp/udp transport")
	}
	if !strings.Contains(err.Error(), "cannot consume terminal events") {
		t.Errorf("Plan() err = %v, want 'cannot consume terminal events'", err)
	}
}

// ---- review 回归：H3 udp 事件流 ctx 取消收敛 ----
// 事件流驱动中取消：udp 层的事件循环与终结层 EmitMsg 都必须经 select
// ctx.Done 收敛，已收集包（≥ 握手前即可 cancel，此处从事件第 1 包后取消）
// 完整送达后 Plan 返回，无 goroutine 泄漏/阻塞发送（防 send-on-closed）。
func TestChainPlanner_UDP_EventDrivenCancelConverges(t *testing.T) {
	layers.RegisterLayerGeneratorForTest("udp-cancel", func() (layers.LayerGenerator, error) {
		events := make([]layers.MessageEvent, 0, 300)
		for i := 0; i < 300; i++ {
			events = append(events, layers.MessageEvent{Up: true, Bytes: []byte("msg")})
		}
		return &testTerminalGen{events: events}, nil
	})
	t.Cleanup(func() { layers.UnregisterLayerGeneratorForTest("udp-cancel") })
	r := layers.NewRegistry()
	for _, s := range []layers.LayerSchema{
		{Name: "udp-cancel", Category: layers.CategoryTerminal, DependsOn: []string{"udp"}},
		{Name: "udp", Category: layers.CategoryTransport, DependsOn: []string{"ip"},
			Fields: map[string]layers.FieldSchema{
				"src_port": {Type: "uint16"},
				"dst_port": {Type: "uint16"},
			}},
		{Name: "ip", Category: layers.CategoryNetwork,
			Fields: map[string]layers.FieldSchema{"src": {Type: "ip"}, "dst": {Type: "ip"}}},
	} {
		if err := r.Register(s); err != nil {
			t.Fatalf("register %s: %v", s.Name, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := layers.NewChainPlannerWithRegistry("udp-cancel", r)
	spec := udpSpec()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	idx := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range ch {
			idx++
			if idx == 3 {
				cancel() // 事件流进行中取消
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("udp event flow did not converge on cancel (goroutine leak / blocked send)")
	}
	if idx < 3 {
		t.Errorf("flow yielded %d packets, want >= 3 (events before cancel must be delivered)", idx)
	}
}
