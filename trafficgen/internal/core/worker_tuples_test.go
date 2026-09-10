package core

import (
	"context"
	"sync"
	"testing"
	"time"
)

// T-FTP-7/8/9（D-FTP-2 §7 步骤3）：worker 策略循环 tuples 解析与 FlowIndex。
// specCapturingPlanner 捕获每流 Plan 收到的 spec（互斥锁保护，-race 友好），
// 引擎进程内驱动（与 engine_test.go 同写法）。协议名 "tcp"（在白名单内，
// worker 按 task.Protocol 分发到同名 planner）。
type tupleCapturingPlanner struct {
	mu    sync.Mutex
	specs []FlowSpec
}

func (p *tupleCapturingPlanner) Name() string { return "tcp" }
func (p *tupleCapturingPlanner) Validate(spec FlowSpec) error {
	return nil
}
func (p *tupleCapturingPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	p.mu.Lock()
	p.specs = append(p.specs, spec)
	p.mu.Unlock()
	ch := make(chan PacketConfig, 1)
	go func() {
		defer close(ch)
		ch <- PacketConfig{FlowID: "f", PacketIndex: 0}
	}()
	return ch, nil
}

func (p *tupleCapturingPlanner) captured() []FlowSpec {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]FlowSpec(nil), p.specs...)
}

func runTupleEngineTask(t *testing.T, task Task) []FlowSpec {
	t.Helper()
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 512, QueueSize: 128,
	})
	planner := &tupleCapturingPlanner{}
	e.RegisterPlanner(planner)
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return []byte{1}, nil })
	done := make(chan string, 1)
	e.OnTaskComplete = func(taskID string) { done <- taskID }
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("task did not complete within 8s")
	}
	return planner.captured()
}

// T-FTP-7：策略 tuples inc 四元组——第 i 流 src_ip=10.0.1.(1+i)、src_port=20000+i；
// dst 端未配 → 保留 spec 默认（20.0.0.1/80）。
func TestWorkerStrategyTuplesInc(t *testing.T) {
	spec := FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 80,
		Count: 5,
		Tuples: &TupleConfig{
			SrcIP:   StrategyConfig{Strategy: "inc", Range: []interface{}{"10.0.1.1", "10.0.1.5"}},
			SrcPort: StrategyConfig{Strategy: "inc", Range: []interface{}{20000, 20009}},
		},
	}
	specs := runTupleEngineTask(t, Task{ID: "t7", Name: "t7", Protocol: "tcp", Spec: spec})
	if len(specs) != 5 {
		t.Fatalf("specs=%d, want 5", len(specs))
	}
	for i, s := range specs {
		wantIP := "10.0.1." + string(rune('1'+i))
		if s.SrcIP != wantIP {
			t.Errorf("flow %d src_ip=%q, want %q", i, s.SrcIP, wantIP)
		}
		if want := 20000 + i; s.SrcPort != uint16(want) {
			t.Errorf("flow %d src_port=%d, want %d", i, s.SrcPort, want)
		}
		if s.DstIP != "20.0.0.1" || s.DstPort != 80 {
			t.Errorf("flow %d dst endpoints clobbered: %s:%d", i, s.DstIP, s.DstPort)
		}
	}
}

// T-FTP-8：rand 同 seed+序号可复现（两次运行全量比对）；inc/list/pattern 到尾回绕。
func TestWorkerTuplesReproducible(t *testing.T) {
	// rand reproducible: two runs, same seed
	mk := func() FlowSpec {
		return FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 80,
			Count: 100,
			Tuples: &TupleConfig{
				SrcIP: StrategyConfig{Strategy: "rand", Range: []interface{}{"10.0.0.1", "10.0.0.254"}, Seed: 42},
			},
		}
	}
	runA := runTupleEngineTask(t, Task{ID: "t8a", Name: "t8a", Protocol: "tcp", Spec: mk()})
	runB := runTupleEngineTask(t, Task{ID: "t8b", Name: "t8b", Protocol: "tcp", Spec: mk()})
	if len(runA) != 100 || len(runB) != 100 {
		t.Fatalf("len %d/%d, want 100/100", len(runA), len(runB))
	}
	seen := map[string]bool{}
	for i := range runA {
		if runA[i].SrcIP != runB[i].SrcIP {
			t.Fatalf("flow %d diverges: %q vs %q", i, runA[i].SrcIP, runB[i].SrcIP)
		}
		seen[runA[i].SrcIP] = true
	}
	if len(seen) < 2 {
		t.Errorf("rand produced %d distinct IPs over 100 flows — not varying", len(seen))
	}

	// inc wrap: range [1,3], flows=5 → 1,2,3,1,2
	wrapSpec := FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 80,
		Count: 5,
		Tuples: &TupleConfig{
			SrcPort: StrategyConfig{Strategy: "inc", Range: []interface{}{1, 3}},
		},
	}
	specs := runTupleEngineTask(t, Task{ID: "t8c", Name: "t8c", Protocol: "tcp", Spec: wrapSpec})
	for i, want := range []uint16{1, 2, 3, 1, 2} {
		if specs[i].SrcPort != want {
			t.Errorf("inc wrap flow %d src_port=%d, want %d", i, specs[i].SrcPort, want)
		}
	}

	// list rotate: ["a","b"] ×4 → a,b,a,b — ports encode list position
	listSpec := FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 80,
		Count: 4,
		Tuples: &TupleConfig{
			SrcPort: StrategyConfig{Strategy: "list", List: []string{"1", "2"}},
		},
	}
	specs = runTupleEngineTask(t, Task{ID: "t8d", Name: "t8d", Protocol: "tcp", Spec: listSpec})
	for i, want := range []uint16{1, 2, 1, 2} {
		if specs[i].SrcPort != want {
			t.Errorf("list rotate flow %d src_port=%d, want %d", i, specs[i].SrcPort, want)
		}
	}
}

// T-FTP-9：非零才覆盖 + fixed 端点 + 分片输入一致性——显式 src_port 51000
// 保持（tuples 未配 src_port / fixed 同值），dst_ip 递增覆盖；FlowIndex 逐流。
func TestWorkerTuplesOverridesOnlyNonzero(t *testing.T) {
	spec := FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 51000, DstPort: 80,
		Count: 2,
		Tuples: &TupleConfig{
			DstIP:   StrategyConfig{Strategy: "inc", Range: []interface{}{"20.0.1.1", "20.0.1.2"}},
			SrcPort: StrategyConfig{Strategy: "fixed", Value: 51000},
		},
	}
	specs := runTupleEngineTask(t, Task{ID: "t9", Name: "t9", Protocol: "tcp", Spec: spec})
	if len(specs) != 2 {
		t.Fatalf("specs=%d, want 2", len(specs))
	}
	want := []struct{ dstIP string; srcPort uint16 }{{"20.0.1.1", 51000}, {"20.0.1.2", 51000}}
	for i, s := range specs {
		if s.DstIP != want[i].dstIP {
			t.Errorf("flow %d dst_ip=%q, want %q", i, s.DstIP, want[i].dstIP)
		}
		if s.SrcPort != want[i].srcPort {
			t.Errorf("flow %d src_port=%d, want %d (explicit kept)", i, s.SrcPort, want[i].srcPort)
		}
		if s.FlowIndex != i {
			t.Errorf("flow %d FlowIndex=%d", i, s.FlowIndex)
		}
	}
}
