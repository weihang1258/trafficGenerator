package core

import (
	"context"
	"sync"
	"testing"
	"time"
)

// T-FTP-7/8/9 v3（D-FTP-3 §7 步骤3）：worker 策略循环层动态解析与 FlowIndex。
// 输入为 layers 数组形状（v2 扁平 tuples 已撤销）；engine 进程内驱动。
// specCapturingPlanner 捕获每流 Plan 收到的 spec（互斥锁保护，-race 友好）。
// 协议名 "tcp"（在白名单内，worker 按 task.Protocol 分发到同名 planner）。
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

// T-FTP-7 v3：层 ip/tcp 动态 inc——第 i 流 src_ip=10.0.1.(1+i)、src_port=20000+i；
// dst 端未配动态 → 保留默认（20.0.0.1/80）。
func TestWorkerLayerDynInc(t *testing.T) {
	cfg := map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{
				"src": map[string]any{"strategy": "inc", "range": []any{"10.0.1.1", "10.0.1.5"}},
				"dst": "20.0.0.1",
			}},
			map[string]any{"tcp": map[string]any{
				"src_port": map[string]any{"strategy": "inc", "range": []any{20000, 20009}},
				"dst_port": float64(80),
			}},
		},
	}
	spec := mapToFlowSpec(cfg, "tcp")
	spec.Count = 5
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

// T-FTP-8 v3：rand 同 seed+序号可复现（两次运行全量比对）；inc/list 回绕；MAC/TTL 名单字段。
func TestWorkerLayerDynReproducible(t *testing.T) {
	// rand reproducible: two runs, same seed
	mk := func() FlowSpec {
		spec := mapToFlowSpec(map[string]any{
			"layers": []any{
				map[string]any{"ip": map[string]any{
					"dst": map[string]any{"strategy": "rand", "range": []any{"20.0.0.1", "20.0.0.10"}, "seed": 42},
				}},
			},
		}, "tcp")
		spec.Count = 100
		return spec
	}
	runA := runTupleEngineTask(t, Task{ID: "t8a", Name: "t8a", Protocol: "tcp", Spec: mk()})
	runB := runTupleEngineTask(t, Task{ID: "t8b", Name: "t8b", Protocol: "tcp", Spec: mk()})
	if len(runA) != 100 || len(runB) != 100 {
		t.Fatalf("len %d/%d, want 100/100", len(runA), len(runB))
	}
	seen := map[string]bool{}
	for i := range runA {
		if runA[i].DstIP != runB[i].DstIP {
			t.Fatalf("flow %d diverges: %q vs %q", i, runA[i].DstIP, runB[i].DstIP)
		}
		seen[runA[i].DstIP] = true
	}
	if len(seen) < 2 {
		t.Errorf("rand produced %d distinct IPs over 100 flows — not varying", len(seen))
	}

	// inc wrap: range [1,3], flows=5 → 1,2,3,1,2
	wrapSpec := mapToFlowSpec(map[string]any{
		"layers": []any{map[string]any{"tcp": map[string]any{
			"src_port": map[string]any{"strategy": "inc", "range": []any{1, 3}},
		}}},
	}, "tcp")
	wrapSpec.Count = 5
	specs := runTupleEngineTask(t, Task{ID: "t8c", Name: "t8c", Protocol: "tcp", Spec: wrapSpec})
	for i, want := range []uint16{1, 2, 3, 1, 2} {
		if specs[i].SrcPort != want {
			t.Errorf("inc wrap flow %d src_port=%d, want %d", i, specs[i].SrcPort, want)
		}
	}

	// list rotate
	listSpec := mapToFlowSpec(map[string]any{
		"layers": []any{map[string]any{"tcp": map[string]any{
			"src_port": map[string]any{"strategy": "list", "list": []string{"1", "2"}},
		}}},
	}, "tcp")
	listSpec.Count = 4
	specs = runTupleEngineTask(t, Task{ID: "t8d", Name: "t8d", Protocol: "tcp", Spec: listSpec})
	for i, want := range []uint16{1, 2, 1, 2} {
		if specs[i].SrcPort != want {
			t.Errorf("list rotate flow %d src_port=%d, want %d", i, specs[i].SrcPort, want)
		}
	}

	// MAC inc: OUI preserved, low bytes advance
	macSpec := mapToFlowSpec(map[string]any{
		"layers": []any{map[string]any{"eth": map[string]any{
			"dst_mac": map[string]any{"strategy": "inc", "range": []any{"02:00:00:00:00:01", "02:00:00:00:00:03"}},
		}}},
	}, "tcp")
	macSpec.Count = 3
	specs = runTupleEngineTask(t, Task{ID: "t8e", Name: "t8e", Protocol: "tcp", Spec: macSpec})
	for i, want := range []string{"02:00:00:00:00:01", "02:00:00:00:00:02", "02:00:00:00:00:03"} {
		if specs[i].DstMAC != want {
			t.Errorf("mac flow %d dst_mac=%q, want %q", i, specs[i].DstMAC, want)
		}
	}

	// TTL inc with wrap
	ttlSpec := mapToFlowSpec(map[string]any{
		"layers": []any{map[string]any{"ip": map[string]any{
			"ttl": map[string]any{"strategy": "inc", "range": []any{64, 66}},
		}}},
	}, "tcp")
	ttlSpec.Count = 4
	specs = runTupleEngineTask(t, Task{ID: "t8f", Name: "t8f", Protocol: "tcp", Spec: ttlSpec})
	for i, want := range []uint8{64, 65, 66, 64} {
		if specs[i].TTL != want {
			t.Errorf("ttl flow %d =%d, want %d", i, specs[i].TTL, want)
		}
	}
}

// T-FTP-9 v3：fixed 解析值覆盖 + 未配端点保持 + 分片输入一致 + FlowIndex 逐流。
func TestWorkerLayerDynOverride(t *testing.T) {
	spec := mapToFlowSpec(map[string]any{
		"layers": []any{
			map[string]any{"ip": map[string]any{
				"dst": map[string]any{"strategy": "inc", "range": []any{"20.0.1.1", "20.0.1.2"}},
			}},
			map[string]any{"tcp": map[string]any{
				"src_port": map[string]any{"strategy": "fixed", "value": 51000},
			}},
		},
	}, "tcp")
	spec.Count = 2
	specs := runTupleEngineTask(t, Task{ID: "t9", Name: "t9", Protocol: "tcp", Spec: spec})
	if len(specs) != 2 {
		t.Fatalf("specs=%d, want 2", len(specs))
	}
	want := []struct {
		dstIP   string
		srcPort uint16
	}{{"20.0.1.1", 51000}, {"20.0.1.2", 51000}}
	for i, s := range specs {
		if s.DstIP != want[i].dstIP {
			t.Errorf("flow %d dst_ip=%q, want %q", i, s.DstIP, want[i].dstIP)
		}
		if s.SrcPort != want[i].srcPort {
			t.Errorf("flow %d src_port=%d, want %d", i, s.SrcPort, want[i].srcPort)
		}
		if s.FlowIndex != i {
			t.Errorf("flow %d FlowIndex=%d", i, s.FlowIndex)
		}
	}
}
