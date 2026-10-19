package core

// J2 管线 profile（D-REQ-1 批 3）：复现客户端形态——1 万流走真实引擎管线
// （真实 Builder + 真实 PCAP 输出），量化每流成本并落 CPU profile。
// 设计铁律（CORE_MEMORY §5.4）：禁止无数据优化——本测试就是数据源。
//
// 跑法：TG_J2_PROFILE=1 go test ./internal/core/ -run TestJ2PipelineProfile \
//        -count=1 -timeout=600s -v
// 产物：/tmp/j2_pipeline.pprof（go tool pprof 分析）+ 日志耗时摘要。

import (
	"context"
	"os"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/internal/output"
)

// j2Planner emits j2PacketsPerFlow UDP packets per flow (chain-planner-like
// shape: small per-flow packet count, many flows).
type j2Planner struct{ perFlow int }

func (p *j2Planner) Name() string                 { return "udp" }
func (p *j2Planner) Validate(spec FlowSpec) error { return nil }
func (p *j2Planner) Plan(ctx context.Context, spec FlowSpec) (<-chan PacketConfig, error) {
	ch := make(chan PacketConfig, 256)
	go func() {
		defer close(ch)
		for i := 0; i < p.perFlow; i++ {
			ch <- PacketConfig{
				FlowID: "j2f", PacketIndex: uint64(i),
				L2: L2Config{SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66", EtherType: 0x0800},
				L3: L3Config{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 17, TTL: 64},
				L4: L4Config{Protocol: "udp", SrcPort: 30000, DstPort: 53},
			}
		}
	}()
	return ch, nil
}

// j2PcapWriter adapts output.PCAPWriter to core.PacketWriter（rest 层
// pcapPacketWriter 同款直连形态）。
type j2PcapWriter struct{ w *output.PCAPWriter }

func (a *j2PcapWriter) WritePackets(packets [][]byte) error { return a.w.Write(packets) }
func (a *j2PcapWriter) Close() error                        { return a.w.Close() }

func TestJ2PipelineProfile(t *testing.T) {
	if os.Getenv("TG_J2_PROFILE") != "1" {
		t.Skip("set TG_J2_PROFILE=1 to run the J2 pipeline profile (writes /tmp/j2_pipeline.pprof)")
	}
	const flows = 10000
	const perFlow = 10

	e := NewEngine(EngineConfig{
		ConfigWorkers: 4, PacketWorkers: 8, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 1024, MaxBufferBytes: 100 << 20,
	})
	e.RegisterPlanner(&j2Planner{perFlow: perFlow})
	e.SetBuildFunc(NewBuilder().Build)
	pcapPath := "/tmp/j2_pipeline.pcap"
	w, err := output.NewPCAPWriter(pcapPath)
	if err != nil {
		t.Fatalf("pcap writer: %v", err)
	}
	e.RegisterOutputWriter("j2-task", &j2PcapWriter{w: w})
	if err := e.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { e.Stop() })

	pf, err := os.Create("/tmp/j2_pipeline.pprof")
	if err != nil {
		t.Fatalf("profile file: %v", err)
	}
	if err := pprof.StartCPUProfile(pf); err != nil {
		t.Fatalf("start cpu profile: %v", err)
	}

	start := time.Now()
	task := Task{
		ID: "j2-task", Name: "j2", Protocol: "udp", ClassID: "j2-task",
		ParentTaskID: "j2-parent",
		Spec:         FlowSpec{Count: flows},
	}
	if err := e.SubmitTask(task); err != nil {
		pprof.StopCPUProfile()
		t.Fatalf("submit: %v", err)
	}
	waitTaskDone(t, e, "j2-task", 300*time.Second)
	elapsed := time.Since(start)
	pprof.StopCPUProfile()
	pf.Close()

	perFlowUs := elapsed.Microseconds() / flows
	t.Logf("J2: %d flows × %d pkts = %d packets in %v (%d µs/flow, %.0f pkts/s)",
		flows, perFlow, flows*perFlow, elapsed, perFlowUs, float64(flows*perFlow)/elapsed.Seconds())
}
