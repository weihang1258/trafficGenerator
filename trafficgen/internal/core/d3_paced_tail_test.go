package core

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// R8-D3 规格锁：任务级 bps = 全程速率上限（墙钟口径）。deadline 后在途包
// 限速排空（墙钟顺延），用户 stop 仍免速快速清空。
type d3Planner struct{}

func (p *d3Planner) Name() string                 { return "tcp" }
func (p *d3Planner) Validate(spec FlowSpec) error { return nil }
func (p *d3Planner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	ch := make(chan PacketConfig)
	go func() {
		defer close(ch)
		ch <- PacketConfig{
			FlowID:  "d3f",
			L2:      L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800},
			L3:      L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64},
			L4:      L4Config{Protocol: "udp", SrcPort: uint16(30000 + spec.FlowIndex%50), DstPort: 53},
			Payload: make([]byte, 60),
		}
	}()
	return ch, nil
}

func TestTaskLevelBPS_PacedTailDrain(t *testing.T) {
	writtenBytes := int64(0)
	var mu sync.Mutex
	e := NewEngine(EngineConfig{
		ConfigWorkers: 4, PacketWorkers: 8, OutputWorkers: 8,
		BufferSize: 4096, QueueSize: 1024, MaxBufferBytes: 100 << 20,
	})
	var builtCount atomic.Int64
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) {
		builtCount.Add(1)
		return make([]byte, 100), nil
	})
	e.RegisterOutputWriter("d3", &d3CountWriter{n: &writtenBytes, mu: &mu})

	pl := &d3Planner{}
	e.RegisterPlanner(pl)
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	task := Task{
		ID: "d3", Name: "d3", Protocol: "tcp", ClassID: "d3",
		ParentTaskID: "d3-parent",
		Spec:         FlowSpec{Duration: 4},
		TaskFCType:   "bps",
		TaskFCValue:  1_000_000, // 1Mbps = 125KB/s payload
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	start := time.Now()
	waitTaskDone(t, e, "d3", 30*time.Second)
	// payload bytes = built × 60; expect ≈ 125KB/s × 4s = 500KB
	// 口径（R8-D3 修复语义）：任务级 bps = 速率配额。deadline 时超出预算的
	// 在途包带核算丢弃——实发（写侧字节）≈ 速率×时长，墙钟≈deadline，任一
	// 时刻速率 ≤ 名义；截止照常快速终止（与复测 #3 P1 合并裁定）。
	wall := time.Since(start)
	mu.Lock()
	sent := writtenBytes
	mu.Unlock()
	rateMbps := float64(sent) * 8 / wall.Seconds() / 1e6
	t.Logf("D3: sentBytes=%d wall=%v rate=%.2fMbps (nominal 1.00)", sent, wall.Round(time.Millisecond), rateMbps)
	if rateMbps > 1.15 {
		t.Errorf("sent rate %.2fMbps >> 1.00Mbps nominal (D3: deadline 尾包不得免速冲出)", rateMbps)
	}
	if rateMbps < 0.75 {
		t.Errorf("sent rate %.2fMbps << 1.00Mbps nominal (限速器欠发)", rateMbps)
	}
	// R9 设计对齐：配额路径零丢弃——构建数 == 实发包数（写侧帧字节/100）。
	if built, want := builtCount.Load(), sent/100; built != want {
		t.Errorf("built=%d != sent=%d：配额路径存在丢弃（应为零丢弃）", built, want)
	}
}

// d3CountWriter counts written frame bytes (the rate-audit observation point).
type d3CountWriter struct {
	n  *int64
	mu *sync.Mutex
}

func (w *d3CountWriter) WritePackets(packets [][]byte) error {
	total := 0
	for _, p := range packets {
		total += len(p)
	}
	w.mu.Lock()
	*w.n += int64(total)
	w.mu.Unlock()
	return nil
}
func (w *d3CountWriter) Close() error { return nil }
