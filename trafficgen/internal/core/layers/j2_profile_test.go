package layers

// J2 管线 profile 变体（D-REQ-1 批 3）：与 internal/core/j2_profile_test.go
// 同形态，但走**真实 ChainPlanner**（BuildLayersPlanner + 逐流动态解析）
// ——core 包测试不能 import layers（环），链路证据必须在这里取。
//
// 跑法：TG_J2_PROFILE=1 go test ./internal/core/layers/ -run TestJ2ChainProfile \
//        -count=1 -timeout=600s -v
// 产物：/tmp/j2_chain.pprof + 耗时摘要。

import (
	"encoding/json"
	"os"
	"runtime"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/output"
)

type j2PcapWriter struct{ w *output.PCAPWriter }

func (a *j2PcapWriter) WritePackets(packets [][]byte) error { return a.w.Write(packets) }
func (a *j2PcapWriter) Close() error                        { return a.w.Close() }

func TestJ2ChainProfile(t *testing.T) {
	if os.Getenv("TG_J2_PROFILE") != "1" {
		t.Skip("set TG_J2_PROFILE=1 to run the J2 chain-planner profile (writes /tmp/j2_chain.pprof)")
	}
	const flows = 10000
	const perFlow = 10 // udp payload 10×1472B → 每流 10 数据报

	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 4, PacketWorkers: 8, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 1024, MaxBufferBytes: 100 << 20,
	})
	e.SetLayerPlannerFactory(BuildLayersPlanner)
	e.SetBuildFunc(core.NewBuilder().Build)
	pcapPath := "/tmp/j2_chain.pcap"
	w, err := output.NewPCAPWriter(pcapPath)
	if err != nil {
		t.Fatalf("pcap writer: %v", err)
	}
	e.RegisterOutputWriter("j2-chain", &j2PcapWriter{w: w})
	e.OnTaskFailed = func(taskID string, errMsg string) {
		t.Logf("TASK FAILED: %s: %s", taskID, errMsg)
	}
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	pf, err := os.Create("/tmp/j2_chain.pprof")
	if err != nil {
		t.Fatalf("profile file: %v", err)
	}
	if err := pprof.StartCPUProfile(pf); err != nil {
		t.Fatalf("start cpu profile: %v", err)
	}
	// 剖面被 GC 支配（首轮 CPU top：gcDrain cum 75%）——补分配面证据。
	defer func() {
		mf, err := os.Create("/tmp/j2_chain_mem.pprof")
		if err == nil {
			runtime.GC()
			_ = pprof.WriteHeapProfile(mf)
			mf.Close()
		}
	}()

	layersJSON, _ := json.Marshal([]map[string]interface{}{
		{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
		// src_port 钉标量（链校验要求显式源端口；CPU 剖面与四元组多样性
		// 无关，逐流成本=Plan+Build+输出，钉值不影响结论）。
		{"udp": map[string]interface{}{"src_port": 30000, "dst_port": 53}},
	})
	start := time.Now()
	task := core.Task{
		ID: "j2-chain", Name: "j2-chain", Protocol: "udp", ClassID: "j2-chain",
		ParentTaskID: "j2-chain-parent",
		// 生产链路：REST mapToFlowSpec 从层链提取四元组进 spec（引擎
		// 运行态校验读 spec）；直发引擎须自提——与钉值一致。
		Spec:   core.FlowSpec{Count: flows, SrcPort: 30000, DstPort: 53},
		Layers: layersJSON,
	}
	if err := e.SubmitTask(task); err != nil {
		pprof.StopCPUProfile()
		t.Fatalf("submit: %v", err)
	}
	waitJ2(t, e, "j2-chain")
	elapsed := time.Since(start)
	pprof.StopCPUProfile()
	pf.Close()

	perFlowUs := elapsed.Microseconds() / flows
	// 裸 [ip→udp] 链每流 1 数据报（无事件层）——perFlow 仅控制生成器形态。
	t.Logf("J2-CHAIN: %d flows (1 datagram/flow bare udp chain) in %v (%d µs/flow, %.0f flows/s)",
		flows, elapsed, perFlowUs, float64(flows)/elapsed.Seconds())
}

func waitJ2(t *testing.T, e *core.Engine, taskID string) {
	t.Helper()
	deadline := time.After(300 * time.Second)
	for {
		if _, err := e.GetTaskStatus(taskID); err != nil {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("task %s did not finish within 300s", taskID)
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}
