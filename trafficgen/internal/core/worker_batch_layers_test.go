package core

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

// 回归：batch class 带 "layers" 时必须走层链规划器（P2c 层链驱动生成），
// 而不是按协议名注册的默认 planner —— 后者 chain 为 nil，会 completeSynthesized
// 造全默认链，用户的层内静态字段（tcp.dst_port/http.uri/...）全部丢失，
// 任务却照常报 completed。
//
// 修复点：worker.processBatchTask 的 planner 分发（原 w.planners[class.Type]）。

// batchLayersCapture 记录 factory 收到的 (protocol, layersJSON) 与 Plan 次数。
type batchLayersCapture struct {
	mu     sync.Mutex
	built  []string // "proto|layersJSON"
	plans  int
	inner  ProtocolPlanner
	specCh chan FlowSpec
}

func (c *batchLayersCapture) record(proto string, raw json.RawMessage) {
	c.mu.Lock()
	c.built = append(c.built, proto+"|"+string(raw))
	c.mu.Unlock()
}

// nonLayerPlanCalls 统计「未携带层链的默认 planner」被调用的次数。
type countingPlanner struct {
	name  string
	mu    sync.Mutex
	plans int
	specs []FlowSpec
}

func (p *countingPlanner) Name() string                 { return p.name }
func (p *countingPlanner) Validate(spec FlowSpec) error { return nil }
func (p *countingPlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	p.mu.Lock()
	p.plans++
	p.specs = append(p.specs, spec)
	p.mu.Unlock()
	ch := make(chan PacketConfig, 1)
	ch <- PacketConfig{FlowID: "f", PacketIndex: 0, L4: L4Config{SrcPort: spec.SrcPort, DstPort: spec.DstPort}}
	close(ch)
	return ch, nil
}

func (p *countingPlanner) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.plans
}

// TestBatchClassLayersDispatchToChainPlanner 是核心回归：带 layers 的 batch
// class 必须经 layerPlannerFactory 构建类专属 planner 并分发给它。
func TestBatchClassLayersDispatchToChainPlanner(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 256,
	})
	defaultTCP := &countingPlanner{name: "tcp"}
	e.RegisterPlanner(defaultTCP)

	var mu sync.Mutex
	var builtRaw []string
	var chainPlanCalls int
	layersJSON := `[{"ip":{"src":"10.1.1.1","dst":"10.1.1.2"}},{"tcp":{"src_port":22000,"dst_port":8080}}]`

	e.SetLayerPlannerFactory(func(protocol string, raw json.RawMessage) (ProtocolPlanner, error) {
		mu.Lock()
		builtRaw = append(builtRaw, string(raw))
		mu.Unlock()
		return &chainCapturePlanner{onPlan: func() {
			mu.Lock()
			chainPlanCalls++
			mu.Unlock()
		}}, nil
	})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 64), nil })
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	done := make(chan string, 1)
	e.OnTaskComplete = func(id string) { done <- id }

	task := Task{
		ID: "b1", Name: "batch-layers", Protocol: "batch",
		Batch: &BatchSpec{Classes: []TrafficClass{{
			ID: "c1", Type: "tcp", FlowCount: 1,
			Config: map[string]interface{}{"layers": mustDecodeJSON(t, layersJSON)},
		}}},
	}
	if err := e.SubmitTask(task); err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("task did not finish")
	}

	mu.Lock()
	gotRaw, planCalls := append([]string(nil), builtRaw...), chainPlanCalls
	mu.Unlock()

	if len(gotRaw) == 0 {
		t.Fatal("layer planner factory never invoked for batch class carrying layers — " +
			"the class ran on the protocol-name default planner and lost every layer field")
	}
	// json.Marshal 对 map 键排序，逐字比较会误报——按语义比对。
	var gotLayers, wantLayers interface{}
	if err := json.Unmarshal([]byte(gotRaw[0]), &gotLayers); err != nil {
		t.Fatalf("factory layers not JSON: %v", err)
	}
	json.Unmarshal([]byte(layersJSON), &wantLayers)
	if !reflect.DeepEqual(gotLayers, wantLayers) {
		t.Errorf("factory got layers %v, want %v", gotLayers, wantLayers)
	}
	if planCalls == 0 {
		t.Error("chain planner built but never dispatched (Plan not called)")
	}
	if n := defaultTCP.callCount(); n != 0 {
		t.Errorf("protocol-name default planner ran %d times for a layers class; want 0", n)
	}
}

// TestBatchClassWithoutLayersKeepsDefaultPlanner 是对照面：无 layers 的 class
// 维持旧行为（走协议名 planner），修复不能把这条路径改掉。
func TestBatchClassWithoutLayersKeepsDefaultPlanner(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 256,
	})
	defaultTCP := &countingPlanner{name: "tcp"}
	e.RegisterPlanner(defaultTCP)

	factoryCalls := 0
	e.SetLayerPlannerFactory(func(protocol string, raw json.RawMessage) (ProtocolPlanner, error) {
		factoryCalls++
		return &chainCapturePlanner{}, nil
	})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 64), nil })
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	done := make(chan string, 1)
	e.OnTaskComplete = func(id string) { done <- id }

	if err := e.SubmitTask(Task{
		ID: "b2", Name: "batch-flat", Protocol: "batch",
		Batch: &BatchSpec{Classes: []TrafficClass{{
			ID: "c1", Type: "tcp", FlowCount: 2,
			Config: map[string]interface{}{},
		}}},
	}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("task did not finish")
	}
	if factoryCalls != 0 {
		t.Errorf("layer factory invoked %d times for a class without layers; want 0", factoryCalls)
	}
	if n := defaultTCP.callCount(); n != 2 {
		t.Errorf("default planner planned %d flows, want 2 (FlowCount)", n)
	}
}

// TestBatchClassLayersFactoryErrorFailsClass：factory 报错必须让该类计失败，
// 不能让任务静默 completed 出 0 包。
func TestBatchClassLayersFactoryErrorFailsClass(t *testing.T) {
	e := NewEngine(EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 256,
	})
	e.RegisterPlanner(&countingPlanner{name: "tcp"})
	e.SetLayerPlannerFactory(func(protocol string, raw json.RawMessage) (ProtocolPlanner, error) {
		return nil, fmt.Errorf("layers: bogus chain")
	})
	e.SetBuildFunc(func(c PacketConfig) ([]byte, error) { return make([]byte, 64), nil })
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer e.Stop()

	failed := make(chan string, 1)
	e.OnTaskFailed = func(id, msg string) { failed <- msg }

	if err := e.SubmitTask(Task{
		ID: "b3", Name: "batch-bad-layers", Protocol: "batch",
		Batch: &BatchSpec{Classes: []TrafficClass{{
			ID: "c1", Type: "tcp", FlowCount: 1,
			Config: map[string]interface{}{"layers": mustDecodeJSON(t, `[{"tcp":{}}]`)},
		}}},
	}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	select {
	case msg := <-failed:
		t.Logf("task failed as expected: %s", msg)
	case <-time.After(8 * time.Second):
		t.Fatal("batch with unbuildable layers chain did not fail — silently completed with 0 packets")
	}
}

// chainCapturePlanner 是 factory 返回的替身，记录 Plan 调用。
type chainCapturePlanner struct {
	onPlan func()
}

func (p *chainCapturePlanner) Name() string                 { return "tcp" }
func (p *chainCapturePlanner) Validate(spec FlowSpec) error { return nil }
func (p *chainCapturePlanner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	if p.onPlan != nil {
		p.onPlan()
	}
	ch := make(chan PacketConfig, 1)
	ch <- PacketConfig{FlowID: "f", PacketIndex: 0}
	close(ch)
	return ch, nil
}

// mustDecodeJSON 把 layers JSON 解成 batch class Config 里的 []interface{} 形状
// （与 REST 绑定后的实际内存形状一致）。
func mustDecodeJSON(t *testing.T, s string) interface{} {
	t.Helper()
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("decode %s: %v", s, err)
	}
	return v
}
