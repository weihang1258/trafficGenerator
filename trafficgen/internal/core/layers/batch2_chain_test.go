package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/geneve"   // 终结层生成器注册
	_ "github.com/trafficgen/trafficgen/internal/protocol/gnutella" // 终结层生成器注册
	_ "github.com/trafficgen/trafficgen/internal/protocol/grpc"
	_ "github.com/trafficgen/trafficgen/internal/protocol/gtp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ike"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ike_nat_t"
)

// Batch 2 接线冒烟：每个此前缺 translator case 的协议，层 config 必须
// 进入对应 spec 字段并驱动生成器出包（dhcp/dnp3/doh 同款端到端口径）。
func TestBatch2LayerConfigTranslators(t *testing.T) {
	cases := []struct {
		name    string
		chain   []layers.Layer
		spec    core.FlowSpec
		check   func(*core.FlowSpec) bool
		protoOk func(core.PacketConfig) bool
	}{
		{
			name: "gbt",
			chain: []layers.Layer{
				{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
				{Name: "tcp", Config: map[string]interface{}{"src_port": 40000, "dst_port": 8332}},
				{Name: "http", Config: map[string]interface{}{}},
				{Name: "gbt", Config: map[string]interface{}{"concurrent": false}},
			},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 8332},
			check: func(s *core.FlowSpec) bool { return s.GBT != nil },
		},
		{
			name: "getwork",
			chain: []layers.Layer{
				{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
				{Name: "tcp", Config: map[string]interface{}{"src_port": 40000, "dst_port": 8332}},
				{Name: "http", Config: map[string]interface{}{}},
				{Name: "getwork", Config: map[string]interface{}{"concurrent": false}},
			},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 8332},
			check: func(s *core.FlowSpec) bool { return s.GetWork != nil },
		},
		{
			name: "gnutella",
			chain: []layers.Layer{
				{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
				{Name: "tcp", Config: map[string]interface{}{"src_port": 40000, "dst_port": 6346}},
				{Name: "gnutella", Config: map[string]interface{}{"profile": "gnutella_v060"}},
			},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 6346},
			check: func(s *core.FlowSpec) bool { return s.Gnutella != nil },
		},
		{
			name: "grpc",
			chain: []layers.Layer{
				{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
				{Name: "tcp", Config: map[string]interface{}{"src_port": 40000, "dst_port": 8604}},
				{Name: "grpc", Config: map[string]interface{}{"service": "t.S", "method": "M"}},
			},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 8604},
			check: func(s *core.FlowSpec) bool { return s.GRPC != nil && s.GRPC.Service == "t.S" },
		},
		{
			name: "gtp",
			chain: []layers.Layer{
				{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
				{Name: "udp", Config: map[string]interface{}{"src_port": 2152, "dst_port": 2152}},
				{Name: "gtp", Config: map[string]interface{}{"mode": "u", "version": 1, "teid": 305419896}},
			},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 2152, DstPort: 2152},
			check: func(s *core.FlowSpec) bool { return s.GTP != nil && s.GTP.TEID == 0x12345678 },
		},
		{
			name: "ike",
			chain: []layers.Layer{
				{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
				{Name: "udp", Config: map[string]interface{}{"src_port": 45000, "dst_port": 500}},
				{Name: "ike", Config: map[string]interface{}{"role": "initiator", "scenario": "standard_v2"}},
			},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 45000, DstPort: 500},
			check: func(s *core.FlowSpec) bool { return s.IKE != nil },
		},
		{
			name: "ike_nat_t",
			chain: []layers.Layer{
				{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
				{Name: "udp", Config: map[string]interface{}{"src_port": 4500, "dst_port": 4500}},
				{Name: "ike_nat_t", Config: map[string]interface{}{"port_float": true}},
			},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 4500, DstPort: 4500},
			check: func(s *core.FlowSpec) bool { return s.IKENATT != nil },
		},
		{
			name: "gre",
			chain: []layers.Layer{
				{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
				{Name: "gre", Config: map[string]interface{}{"key": float64(42)}}, // JSON 往返语义：数字=float64
				{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
				{Name: "tcp", Config: map[string]interface{}{"src_port": 40000, "dst_port": 80}},
				{Name: "http", Config: map[string]interface{}{}},
			},
			spec:    core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 80},
			check:   func(s *core.FlowSpec) bool { return true }, // gre 生成器直读层 config，不经 spec.GRE
			protoOk: func(p core.PacketConfig) bool { return p.L2.GRE != nil && p.L2.GRE.Key == 42 },
		},
		{
			name: "geneve",
			chain: []layers.Layer{
				{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}},
				{Name: "udp", Config: map[string]interface{}{"src_port": 6081, "dst_port": 6081}},
				{Name: "geneve", Config: map[string]interface{}{"vni": 7}},
			},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 6081, DstPort: 6081},
			check: func(s *core.FlowSpec) bool { return s.Geneve != nil && s.Geneve.VNI == 7 },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := layers.NewChainPlannerFromChain(tc.name, tc.chain)
			spec, err := p.ValidateSpec(tc.spec)
			if err != nil {
				t.Fatalf("ValidateSpec: %v", err)
			}
			if !tc.check(&spec) {
				t.Fatalf("layer config was not translated into the spec field")
			}
			ch, err := p.Plan(context.Background(), spec)
			if err != nil {
				t.Fatalf("Plan: %v", err)
			}
			count := 0
			for pkt := range ch {
				if tc.protoOk != nil && !tc.protoOk(pkt) {
					t.Fatalf("packet wire check failed: %+v", pkt)
				}
				count++
			}
			if count == 0 {
				t.Fatal("Plan produced no packets")
			}
		})
	}
}
