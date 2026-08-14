package tftp

// TFTP terminal-layer generator tests (P4a)。TFTPGenerator 复刻 legacy
// Planner.Plan——字节级对比断言保证两条路径（独立 flow Plan vs 终结层
// 事件适配）产出完全一致；链级测试通过 ChainPlanner 驱动完整
// [ip→udp→tftp] 链验证事件接线与线上字节。

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"go.uber.org/goleak"
)

// collectEvents drives TFTPGenerator.Generate and collects the emitted
// message events in order.
func collectEvents(t *testing.T, cfg *core.TFTPConfig) []layers.MessageEvent {
	t.Helper()
	var events []layers.MessageEvent
	gen := &TFTPGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP:   "10.0.0.100",
			DstIP:   "10.0.0.1",
			SrcPort: 49152,
			DstPort: 69,
			TFTP:    cfg,
		},
		EmitMsg: func(ev layers.MessageEvent) error {
			events = append(events, ev)
			return nil
		},
	}
	if err := gen.Generate(context.Background(), req); err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	return events
}

// TestLayerGen_EventsMatchLegacyPlan 字节级对比：事件序列与 legacy
// Planner.Plan 的 PacketConfig 序列在方向/端口/payload/元数据上逐包一致。
func TestLayerGen_EventsMatchLegacyPlan(t *testing.T) {
	cases := []struct {
		name string
		cfg  *core.TFTPConfig
	}{
		{"rrq short file", &core.TFTPConfig{Filename: "file.bin", BlocksCount: 1, DataPayloadPattern: []byte("x")}},
		{"wrq upload", &core.TFTPConfig{Filename: "up.bin", Mode: "write", BlocksCount: 1, DataPayloadPattern: []byte("x")}},
		{"blksize option", &core.TFTPConfig{Filename: "f", BlkSize: 1024, BlocksCount: 1, DataPayloadPattern: []byte("x")}},
		{"oack empty", &core.TFTPConfig{Filename: "f", IncludeOACK: true, BlocksCount: 1, DataPayloadPattern: []byte("x")}},
		{"immediate error", &core.TFTPConfig{Filename: "f", ErrorCode: 1, ErrorMsg: "not found"}},
		{"error after block", &core.TFTPConfig{Filename: "f", ErrorCode: 4, ErrorAfterBlock: 1, BlocksCount: 2, DataPayloadPattern: []byte("x")}},
		{"error client side", &core.TFTPConfig{Filename: "f", ErrorCode: 2, ErrorSide: "client"}},
		{"tid change", &core.TFTPConfig{Filename: "f", ServerTIDChange: true, ServerTIDChangeAtBlock: 1, BlocksCount: 2, DataPayloadPattern: []byte("x")}},
		{"retransmit", &core.TFTPConfig{Filename: "f", BlocksCount: 2, DataPayloadPattern: []byte("x"), RetransmitBlocks: []uint32{1}}},
		{"windowsize", &core.TFTPConfig{Filename: "f", WindowSize: 2, BlocksCount: 4, DataPayloadPattern: []byte("x")}},
		{"final block zero", &core.TFTPConfig{Filename: "f", FinalBlockZero: true, BlocksCount: 2, DataPayloadPattern: []byte("x")}},
		{"timeout+tsize", &core.TFTPConfig{Filename: "f", Timeout: 3, ClientTSize: 1000, BlocksCount: 1, DataPayloadPattern: []byte("x")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := tftpSpec(tc.cfg)
			legacy := mustPlan(t, &Planner{}, spec)
			events := collectEvents(t, tc.cfg)

			if len(events) != len(legacy) {
				t.Fatalf("events = %d, legacy packets = %d", len(events), len(legacy))
			}
			for i, ev := range events {
				pc := legacy[i]
				if (ev.Up && pc.Direction != "up") || (!ev.Up && pc.Direction != "down") {
					t.Errorf("event[%d] Up=%v, legacy Direction=%s", i, ev.Up, pc.Direction)
				}
				if ev.SrcPort != pc.L4.SrcPort || ev.DstPort != pc.L4.DstPort {
					t.Errorf("event[%d] ports %d->%d, legacy %d->%d",
						i, ev.SrcPort, ev.DstPort, pc.L4.SrcPort, pc.L4.DstPort)
				}
				if hexStr(ev.Bytes) != hexStr(pc.Payload) {
					t.Errorf("event[%d] payload = %s, legacy = %s", i, hexStr(ev.Bytes), hexStr(pc.Payload))
				}
				for k, v := range pc.Metadata {
					evV, ok := ev.Metadata[k]
					if !ok {
						t.Errorf("event[%d] metadata %q missing", i, k)
						continue
					}
					if evV != v {
						t.Errorf("event[%d] metadata %q = %v, legacy = %v", i, k, evV, v)
					}
				}
			}
		})
	}
}

// TestLayerGen_NoEventsOnInvalidSpec 负向：无效 spec 时 Generate 返回校验
// 错误，不产生任何事件（不能把校验失败静默成空序列）。
func TestLayerGen_NoEventsOnInvalidSpec(t *testing.T) {
	cfg := &core.TFTPConfig{} // 无 filename → Validate 必拒
	gen := &TFTPGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: "10.0.0.100", DstIP: "10.0.0.1",
			SrcPort: 49152, DstPort: 69,
			TFTP: cfg,
		},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	err := gen.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("expected validation error for empty filename, got nil")
	}
	if !strings.Contains(err.Error(), "tftp") {
		t.Errorf("error = %q, want tftp-prefixed message", err.Error())
	}
}

// TestLayerGen_NilConfig 负向：TFTP 配置缺失必须显式报错（层未被接线到
// flow spec 时不能静默产 0 包）。
func TestLayerGen_NilConfig(t *testing.T) {
	gen := &TFTPGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: "10.0.0.100", DstIP: "10.0.0.1",
			SrcPort: 49152, DstPort: 69,
		},
		EmitMsg: func(ev layers.MessageEvent) error { return nil },
	}
	err := gen.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for nil TFTP config, got nil")
	}
	if !strings.Contains(err.Error(), "TFTP config is nil") {
		t.Errorf("error = %q, want nil-config message", err.Error())
	}
}

// TestLayerGen_NilEmitMsg 负向：EmitMsg 未接线必须显式报错。
func TestLayerGen_NilEmitMsg(t *testing.T) {
	gen := &TFTPGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: "10.0.0.100", DstIP: "10.0.0.1",
			SrcPort: 49152, DstPort: 69,
			TFTP: &core.TFTPConfig{Filename: "f"},
		},
	}
	err := gen.Generate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for nil EmitMsg, got nil")
	}
}

// TestLayerGen_EmitMsgCancelBlocks 负向（failing-test-first）：EmitMsg 阻塞
// 时（传输层停止消费事件流）ctx 取消必须解除阻塞并返回取消错误——否则
// 传输层退出时生成器永久挂死（event-wiring 接线回调同款语义：
// chain_planner.go 的 `case <-ctx.Done(): return ctx.Err()`）。
func TestLayerGen_EmitMsgCancelBlocks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := &core.TFTPConfig{Filename: "f", BlocksCount: 10, DataPayloadPattern: []byte("x")}
	gen := &TFTPGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: "10.0.0.100", DstIP: "10.0.0.1",
			SrcPort: 49152, DstPort: 69,
			TFTP: cfg,
		},
		EmitMsg: func(ev layers.MessageEvent) error {
			// 永不消费：模拟传输层已退出（事件流无人读）。
			<-ctx.Done()
			return nil
		},
	}
	done := make(chan error, 1)
	go func() {
		done <- gen.Generate(ctx, req)
	}()
	// 事件缓冲 256 且序列只有 ~20 包，EmitMsg 必在序列完成前被阻塞。
	// 等待生成器确实阻塞在 EmitMsg 上（不能 sleep 竞态）。
	select {
	case err := <-done:
		t.Fatalf("Generate returned before cancel: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Generate error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Generate hung after cancel (EmitMsg not context-aware)")
	}
}

// TestLayerGen_EmitMsgErrorPropagates 负向：EmitMsg 返回错误必须终止
// 生成并原样传播（传输层失败不能静默吞掉）。
func TestLayerGen_EmitMsgErrorPropagates(t *testing.T) {
	cfg := &core.TFTPConfig{Filename: "f", BlocksCount: 10, DataPayloadPattern: []byte("x")}
	gen := &TFTPGenerator{}
	wantErr := errors.New("transport failed")
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: "10.0.0.100", DstIP: "10.0.0.1",
			SrcPort: 49152, DstPort: 69,
			TFTP: cfg,
		},
		EmitMsg: func(ev layers.MessageEvent) error { return wantErr },
	}
	err := gen.Generate(context.Background(), req)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Generate error = %v, want %v", err, wantErr)
	}
}

// TestLayerGen_EmitMsgErrorNoGoroutineLeak 负向（failing-test-first，
// MEDIUM-1）：EmitMsg 错误路径返回后，legacy Plan 的 producer goroutine
// 不得泄漏——Generate 必须把 channel 排空到关闭，producer 发完自然退出。
func TestLayerGen_EmitMsgErrorNoGoroutineLeak(t *testing.T) {
	cfg := &core.TFTPConfig{Filename: "f", BlocksCount: 200, DataPayloadPattern: []byte("x")}
	gen := &TFTPGenerator{}
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: "10.0.0.100", DstIP: "10.0.0.1",
			SrcPort: 49152, DstPort: 69,
			TFTP: cfg,
		},
		EmitMsg: func(ev layers.MessageEvent) error {
			return errors.New("transport failed")
		},
	}
	if err := gen.Generate(context.Background(), req); err == nil {
		t.Fatal("expected error from EmitMsg, got nil")
	}
	// 泄漏的 goroutine 会永久阻塞在 configChan <- pc 上，无法从外部观测；
	// goleak 是唯一可靠的泄漏检测（进程级 goroutine 快照）。
	goleak.VerifyNone(t)
}

// TestLayerGen_CancelMidSequence 负向：ctx 取消必须终止生成。legacy Plan
// 的取消语义有两条合法结束路径（取决于 cancel 时刻缓冲 channel 的存量）：
//   - 缓冲已空 → range 正常结束 → Generate 返回 nil（优雅排空）
//   - 缓冲未空 → 下一次循环体 ctx 检查命中 → Generate 返回 context.Canceled
// 共同的不变量：emitPacket 在 cancel 后不再发送（开头 ctx 检查是确定性的），
// 且 Generate 在取消后的迭代不会调用回调——事件数精确停在取消点。
func TestLayerGen_CancelMidSequence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := &core.TFTPConfig{Filename: "f", BlocksCount: 10, DataPayloadPattern: []byte("x")}
	gen := &TFTPGenerator{}
	var mu sync.Mutex
	count := 0
	req := &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: "10.0.0.100", DstIP: "10.0.0.1",
			SrcPort: 49152, DstPort: 69,
			TFTP: cfg,
		},
		EmitMsg: func(ev layers.MessageEvent) error {
			mu.Lock()
			count++
			n := count
			mu.Unlock()
			if n == 3 {
				cancel()
			}
			return nil
		},
	}
	err := gen.Generate(ctx, req)
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Generate error = %v, want nil or context.Canceled", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if count != 3 {
		t.Errorf("emitted %d events, want exactly 3 (cancel at event 3; cancel 后不得继续发)", count)
	}
}

// TestLayerGen_ChainPlannerBytes 端到端：ChainPlanner 驱动 [ip→udp→tftp]
// 链，最终包序列与 legacy 独立 flow 驱动字节级一致（udp 层事件模式 +
// ip 层装配后的线上字节）。
func TestLayerGen_ChainPlannerBytes(t *testing.T) {
	cfg := &core.TFTPConfig{Filename: "file.bin", Mode: "read",
		BlocksCount: 1, DataPayloadPattern: []byte("x")}
	spec := core.FlowSpec{
		SrcIP:   "10.0.0.100",
		DstIP:   "10.0.0.1",
		SrcPort: 49152,
		DstPort: 69,
		SrcMAC:  "aa:bb:cc:dd:ee:ff",
		DstMAC:  "11:22:33:44:55:66",
		IPFlags: core.IPFlagDF,
		TTL:     128,
		VLAN:    &core.VLAN{ID: 100},
		TFTP:    cfg,
	}
	chain := []layers.Layer{{Name: "ip"}, {Name: "udp"}, {Name: "tftp"}}
	p := layers.NewChainPlannerFromChain("test-tftp", chain)
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("chain Plan: %v", err)
	}
	got := drain(ch)
	legacy := mustPlan(t, &Planner{}, spec)

	if len(got) != len(legacy) {
		t.Fatalf("chain packets = %d, legacy = %d", len(got), len(legacy))
	}
	for i := range got {
		c, l := got[i], legacy[i]
		if c.Direction != l.Direction {
			t.Errorf("packet[%d] direction %s, legacy %s", i, c.Direction, l.Direction)
		}
		if c.L4.Protocol != l.L4.Protocol || c.L4.SrcPort != l.L4.SrcPort || c.L4.DstPort != l.L4.DstPort {
			t.Errorf("packet[%d] L4 %s %d->%d, legacy %s %d->%d",
				i, c.L4.Protocol, c.L4.SrcPort, c.L4.DstPort,
				l.L4.Protocol, l.L4.SrcPort, l.L4.DstPort)
		}
		if c.L3.SrcIP != l.L3.SrcIP || c.L3.DstIP != l.L3.DstIP {
			t.Errorf("packet[%d] L3 %s->%s, legacy %s->%s",
				i, c.L3.SrcIP, c.L3.DstIP, l.L3.SrcIP, l.L3.DstIP)
		}
		if c.L2.SrcMAC != l.L2.SrcMAC || c.L2.DstMAC != l.L2.DstMAC {
			t.Errorf("packet[%d] L2 %s->%s, legacy %s->%s",
				i, c.L2.SrcMAC, c.L2.DstMAC, l.L2.SrcMAC, l.L2.DstMAC)
		}
		if hexStr(c.Payload) != hexStr(l.Payload) {
			t.Errorf("packet[%d] payload = %s, legacy = %s", i, hexStr(c.Payload), hexStr(l.Payload))
		}
		if c.L3.Protocol != core.ProtocolUDP {
			t.Errorf("packet[%d] L3.Protocol = %d, want UDP", i, c.L3.Protocol)
		}
		// LOW-2（review）：finalEmit 负责的 flow 级字段必须实际落到链输出
		// （只断言 L4/L3/L2/payload 时，finalEmit 关掉这些回填测试照样绿）。
		if c.L3.Flags&core.IPFlagDF == 0 {
			t.Errorf("packet[%d] L3.Flags = %#x, want DF (%#x)", i, c.L3.Flags, core.IPFlagDF)
		}
		if c.L2.VLAN.ID != uint16(100) {
			t.Errorf("packet[%d] VLAN.ID = %d, want 100", i, c.L2.VLAN.ID)
		}
		if c.L3.TTL != 128 {
			t.Errorf("packet[%d] TTL = %d, want 128 (spec.TTL)", i, c.L3.TTL)
		}
		if i > 0 && c.L3.IPID <= got[i-1].L3.IPID {
			t.Errorf("packet[%d] IPID = %d, want strictly greater than previous %d",
				i, c.L3.IPID, got[i-1].L3.IPID)
		}
	}
}
