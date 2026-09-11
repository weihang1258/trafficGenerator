package ftp_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ftp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tcp"
)

// FTP 链化等价 harness（Task 0 建、Task 6 填）：链路径 [tcp,ftp] 与 legacy
// Plan（ftp_sessions_test.go 同款断言）逐用例对拍。collectChainFTP 用
// BuildLayersPlanner 走真实链路径（翻译→事件→tcp 层），不经扁平分支。

// collectChainFTP drives the chain planner for one ftp layers JSON and
// collects every emitted packet.
func collectChainFTP(t *testing.T, layersJSON string, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	chain, err := layers.BuildLayersPlanner("ftp", json.RawMessage(layersJSON))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := chain.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for p := range ch {
		pkts = append(pkts, p)
	}
	return pkts
}

// T-FTP-5 链版（legacy TestFTPEmptySession 对拍）：空会话仅握手 3 + 挥手 4
// = 7 包，连接端口 = 会话 src_port（23001），不是 tcp 层缺省端口。
// 生成器对零事件空会话补端口专属建连事件（纯控制，无载荷），tcp 层对无
// 载荷 CloseConn 事件不产空 PSH 段。
func TestFTPChain_EmptySession_SevenPackets(t *testing.T) {
	pkts := collectChainFTP(t,
		`[{"tcp":{"src_port":23000,"dst_port":21}},{"ftp":{"sessions":[{"src_port":23001}]}}]`,
		core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 23000, DstPort: 21})
	if len(pkts) != 7 {
		t.Fatalf("empty session chain pkts=%d, want 7 (3 handshake + 4 teardown)", len(pkts))
	}
	for i, p := range pkts {
		if p.L4.SrcPort != 23001 && p.L4.DstPort != 23001 {
			t.Fatalf("pkt[%d] ports %d→%d, want session port 23001 involved", i, p.L4.SrcPort, p.L4.DstPort)
		}
		peer := p.L4.SrcPort
		if peer == 23001 {
			peer = p.L4.DstPort
		}
		if peer != 21 {
			t.Fatalf("pkt[%d] peer port %d, want 21", i, peer)
		}
	}
}

// 双空会话（legacy planSessions 逐会话独立连接）：2×7 = 14 包，两条连接
// 端口 23001/23002 各自独立握手/挥手。
func TestFTPChain_TwoEmptySessions(t *testing.T) {
	pkts := collectChainFTP(t,
		`[{"tcp":{"src_port":23000,"dst_port":21}},{"ftp":{"sessions":[{"src_port":23001},{"src_port":23002}]}}]`,
		core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 23000, DstPort: 21})
	if len(pkts) != 14 {
		t.Fatalf("two empty sessions chain pkts=%d, want 14 (2×7)", len(pkts))
	}
	var c1, c2 int
	for _, p := range pkts {
		if p.L4.SrcPort == 23001 || p.L4.DstPort == 23001 {
			c1++
		}
		if p.L4.SrcPort == 23002 || p.L4.DstPort == 23002 {
			c2++
		}
	}
	if c1 != 7 || c2 != 7 {
		t.Fatalf("per-session packets = %d/%d, want 7/7 (independent connections)", c1, c2)
	}
}
