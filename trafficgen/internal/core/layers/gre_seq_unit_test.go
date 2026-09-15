package layers_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/gre"
	_ "github.com/trafficgen/trafficgen/internal/protocol/http"
)

// D-GRE-2 T-GRE-8 生成器级补充：GRE Sequence 逐帧递增 0..N-1（RFC 2890
// §3.2）。tshark 3.6 不暴露 gre 序号值字段（只有位标志），逐帧序号断言
// 进不了 pcap 断言——序号算法（sequenceNum++ 起基 0）在此钉死；pcap 侧
// 由 gre_sequence_multi 的首末帧 hex（00 00 00 00 / 00 00 00 08）双钉。
func TestGREChain_SequenceIncrements(t *testing.T) {
	raw, _ := json.Marshal([]map[string]map[string]interface{}{
		{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{"gre": {"sequence": true}},
		{"ip": {"src": "10.0.0.1", "dst": "20.0.0.1"}},
		{"tcp": {"src_port": 12345, "dst_port": 80}},
		{"http": {}},
	})
	p, err := layers.BuildLayersPlanner("gre", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 80}
	out, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	i := 0
	for pkt := range out {
		gre := pkt.L2.GRE
		if gre == nil {
			t.Fatalf("pkt %d: no GRE config", i)
		}
		if !gre.SequencePresent {
			t.Fatalf("pkt %d: SequencePresent = false", i)
		}
		if gre.Sequence != uint32(i) {
			t.Errorf("pkt %d: GRE Sequence = %d, want %d", i, gre.Sequence, i)
		}
		i++
	}
	if i != 9 {
		t.Errorf("packets = %d, want 9 (3 handshake + 2 data + 4 teardown)", i)
	}
}
