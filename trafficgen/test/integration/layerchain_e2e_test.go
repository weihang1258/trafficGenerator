package integration_test

// T5.2 layerchain e2e：in-process 全链路集成 —— Engine → (layers factory)
// ChainPlanner → PacketWorker → Builder → OutputWorker → PCAPWriter →
// pcap 文件 → gopacket 解析断言。
//
// 补的是 test/protocol_pcap（MCP 驱动 live server）与 internal/core 单测
// 之间的缺口：既有测试要么只到 Plan() 通道（tcp_retransmit_wire_test），
// 要么用 mock planner（flowcontrol_test）——engine → 层链 planner → worker
// → 真实 builder → pcap 文件这条产线路径此前没有 in-process 集成测试
// （CLAUDE.md 测试政策 §4：跨层功能必须有全路径测试）。
//
// Run: go test ./test/integration/ -run TestLayerChainE2E -count=1 -timeout 60s

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	gplayers "github.com/google/gopacket/layers"
	gpcap "github.com/google/gopacket/pcap"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/output"
	"github.com/trafficgen/trafficgen/internal/replay"

	// 层生成器经包 init 反向注册（同 cmd/server/main.go 空导入机制）：
	// 测试二进制不导入协议包则 registry 无该层生成器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/dns"
)

// newLayerChainEngine builds a production-shaped engine: real builder +
// replay dispatch wrapper + layer planner factory + ChainPlanner for the
// given protocol names.
func newLayerChainEngine(t *testing.T, protos ...string) *core.Engine {
	t.Helper()
	e := core.NewEngine(core.EngineConfig{
		ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1,
		BufferSize: 4096, QueueSize: 64,
	})
	for _, p := range protos {
		e.RegisterPlanner(layers.NewChainPlanner(p))
	}
	builder := core.NewBuilder()
	e.SetBuildFunc(replay.NewBuildFunc(builder.Build))
	e.SetLayerPlannerFactory(layers.BuildLayersPlanner)
	if err := e.Start(); err != nil {
		t.Fatalf("start engine: %v", err)
	}
	t.Cleanup(func() { e.Stop() })
	return e
}

// waitTaskTerminal blocks until the task leaves the engine store, logging
// the last observed status for diagnosis.
func waitTaskTerminal(t *testing.T, e *core.Engine, taskID string) *core.TaskStatus {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	var last *core.TaskStatus
	for {
		st, err := e.GetTaskStatus(taskID)
		if err != nil {
			return last // removed = terminal
		}
		last = st
		if time.Now().After(deadline) {
			t.Fatalf("task %s did not finish within 20s", taskID)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// parsePcapTCP decodes Ethernet/TCP packets from a pcap file.
type wirePacket struct {
	tcp    gplayers.TCP
	hasTCP bool
}

func parsePcapTCP(t *testing.T, path string) []wirePacket {
	t.Helper()
	handle, err := gpcap.OpenOffline(path)
	if err != nil {
		t.Fatalf("open pcap %s: %v", path, err)
	}
	defer handle.Close()
	var out []wirePacket
	packetSource := gopacket.NewPacketSource(handle, gplayers.LinkTypeEthernet)
	for packet := range packetSource.Packets() {
		var wp wirePacket
		if tcpL := packet.Layer(gplayers.LayerTypeTCP); tcpL != nil {
			wp.tcp = *tcpL.(*gplayers.TCP)
			wp.hasTCP = true
		}
		out = append(out, wp)
	}
	return out
}

// TestLayerChainE2E_TCPTerminalChain pcap 全链路：[{"tcp":{}}] 层链任务经
// engine 产出 pcap，SYN/PSH/FIN 序列完整（3 握手 + 1 数据段 + 4 挥手）。
func TestLayerChainE2E_TCPTerminalChain(t *testing.T) {
	e := newLayerChainEngine(t, "tcp")
	taskID := "l2e-tcp"
	pcapPath := filepath.Join(t.TempDir(), "l2e-tcp.pcap")

	// 输出 writer 按 taskID 注册（OutputWorker 按 metadata.task_id 路由）。
	pw, err := output.NewPCAPWriter(pcapPath)
	if err != nil {
		t.Fatalf("create pcap writer: %v", err)
	}
	e.RegisterOutputWriter(taskID, &timedPcapWriter{w: pw})
	t.Cleanup(func() { e.UnregisterOutputWriter(taskID) })

	var raw json.RawMessage = []byte(`[{"tcp": {"mss": 1460}}]`)
	if err := e.SubmitTask(core.Task{
		ID: taskID, Name: "layerchain-e2e-tcp", Protocol: "tcp",
		ClassID: taskID, ParentTaskID: taskID,
		Spec: core.FlowSpec{
			Count: 1, SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 80,
			Payload: []byte("layerchain-e2e-payload"),
		},
		// Layers 路由到 BuildLayersPlanner（engine.go SubmitTask）。
		Layers: raw,
	}); err != nil {
		t.Fatalf("submit task: %v", err)
	}
	st := waitTaskTerminal(t, e, taskID)
	if st != nil {
		t.Logf("terminal status=%s error=%q stats=%+v", st.Status, st.Error, st.Stats)
	}
	if err := pw.Close(); err != nil {
		t.Fatalf("close pcap writer: %v", err)
	}
	t.Logf("pcap written=%d path=%s", pw.Written(), pcapPath)

	pkts := parsePcapTCP(t, pcapPath)
	if len(pkts) == 0 {
		t.Fatalf("pcap has no packets — engine→chain→worker→writer path broken")
	}

	var syn, synack, fin, psh int
	for _, p := range pkts {
		if !p.hasTCP {
			t.Fatalf("non-TCP packet in tcp chain pcap")
		}
		switch {
		case p.tcp.SYN && p.tcp.ACK:
			synack++
		case p.tcp.SYN:
			syn++
		case p.tcp.FIN:
			fin++
		case p.tcp.PSH:
			psh++
		}
	}
	if syn != 1 || synack != 1 {
		t.Errorf("handshake: SYN=%d SYN-ACK=%d, want 1/1", syn, synack)
	}
	if psh != 1 {
		t.Errorf("data segments: PSH=%d, want 1 (default terminal payload)", psh)
	}
	if fin != 2 {
		t.Errorf("teardown: FIN packets=%d, want 2 (client+server)", fin)
	}
}

// timedPcapWriter adapts output.PCAPWriter to core.PacketWriter with the
// TimedWriter path (same shape as task_handler.go's pcapPacketWriter).
type timedPcapWriter struct {
	w *output.PCAPWriter
}

func (pw *timedPcapWriter) WritePackets(packets [][]byte) error {
	return pw.w.Write(packets)
}

func (pw *timedPcapWriter) WriteTimedPackets(packets []core.PacketOutput) error {
	tp := make([]output.TimedPacket, len(packets))
	for i, p := range packets {
		tp[i] = output.TimedPacket{Data: p.Data, Timestamp: p.Timestamp}
	}
	return pw.w.WriteTimed(tp)
}

func (pw *timedPcapWriter) Close() error { return pw.w.Close() }

// TestLayerChainE2E_InvalidLayerRejectedAtSubmit 断层链错误在 SubmitTask 即被拒绝
// （factory 报错路径），而非静默 completed-0 包（CLAUDE.md 政策 §4 反模式）。
func TestLayerChainE2E_InvalidLayerRejectedAtSubmit(t *testing.T) {
	e := newLayerChainEngine(t, "tcp")
	var raw json.RawMessage = []byte(`[{"nosuchlayer": {}}]`)
	err := e.SubmitTask(core.Task{
		ID: "l2e-bad", Name: "layerchain-e2e-bad", Protocol: "tcp",
		ClassID: "l2e-bad", ParentTaskID: "l2e-bad",
		Spec: core.FlowSpec{Count: 1, SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 80},
		Layers: raw,
	})
	if err == nil {
		t.Fatalf("task with unknown layer [nosuchlayer] must be rejected at submit, got nil error")
	}
}

// TestLayerChainE2E_UDPChainDNS exercises a second chain shape ([udp→dns])
// through the same full path: the factory wires arbitrary chains, not just
// the tcp terminal, and the udp datagram carrier reaches the pcap.
func TestLayerChainE2E_UDPChainDNS(t *testing.T) {
	e := newLayerChainEngine(t, "dns")
	taskID := "l2e-dns"
	pcapPath := filepath.Join(t.TempDir(), "l2e-dns.pcap")
	pw, err := output.NewPCAPWriter(pcapPath)
	if err != nil {
		t.Fatalf("create pcap writer: %v", err)
	}
	e.RegisterOutputWriter(taskID, &timedPcapWriter{w: pw})
	t.Cleanup(func() { e.UnregisterOutputWriter(taskID) })

	var raw json.RawMessage = []byte(`[{"udp": {}}, {"dns": {}}]`)
	if err := e.SubmitTask(core.Task{
		ID: taskID, Name: "layerchain-e2e-dns", Protocol: "dns",
		ClassID: taskID, ParentTaskID: taskID,
		Spec: core.FlowSpec{Count: 1, SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40069, DstPort: 53},
		Layers: raw,
	}); err != nil {
		t.Fatalf("submit dns chain task: %v", err)
	}
	waitTaskTerminal(t, e, taskID)
	if err := pw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	handle, err := gpcap.OpenOffline(pcapPath)
	if err != nil {
		t.Fatalf("open pcap: %v", err)
	}
	defer handle.Close()
	src := gopacket.NewPacketSource(handle, gplayers.LinkTypeEthernet)
	var udpCount, dnsCount int
	for packet := range src.Packets() {
		if packet.Layer(gplayers.LayerTypeUDP) != nil {
			udpCount++
		}
		if packet.Layer(gplayers.LayerTypeDNS) != nil {
			dnsCount++
		}
	}
	if udpCount == 0 {
		t.Errorf("pcap has no UDP packets — [udp→dns] chain path broken")
	}
	if dnsCount == 0 {
		t.Errorf("pcap has no decodable DNS packets (payload or port mismatch)")
	}
}
