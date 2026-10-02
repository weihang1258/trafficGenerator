package layers_test

import (
	"context"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/l2tp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ldp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mdns"
	_ "github.com/trafficgen/trafficgen/internal/protocol/modbus"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mysql"
	_ "github.com/trafficgen/trafficgen/internal/protocol/nmea"
	_ "github.com/trafficgen/trafficgen/internal/protocol/ntp"
	_ "github.com/trafficgen/trafficgen/internal/protocol/nvgre"
	_ "github.com/trafficgen/trafficgen/internal/protocol/onvif"
)

// Batch 3 接线冒烟：l2tp/ldp/mdns/modbus/mysql/nmea/ntp/nvgre/onvif 此前
// 层 config 在链路径被静默丢弃（spec 字段无翻译入口），本组钉住层 config
// 必须进入对应 spec 字段并出包。
func TestBatch3LayerConfigTranslators(t *testing.T) {
	ip := func() layers.Layer {
		return layers.Layer{Name: "ip", Config: map[string]interface{}{"src": "10.0.0.1", "dst": "10.0.0.2"}}
	}
	udp := func(sp, dp uint16) layers.Layer {
		return layers.Layer{Name: "udp", Config: map[string]interface{}{"src_port": float64(sp), "dst_port": float64(dp)}}
	}
	tcp := func(sp, dp uint16) layers.Layer {
		return layers.Layer{Name: "tcp", Config: map[string]interface{}{"src_port": float64(sp), "dst_port": float64(dp)}}
	}
	cases := []struct {
		name  string
		chain []layers.Layer
		spec  core.FlowSpec
		check func(*core.FlowSpec) bool
	}{
		{
			name: "l2tp",
			chain: []layers.Layer{ip(), udp(1701, 1701), {Name: "l2tp", Config: map[string]interface{}{
				"version": 2, "role": "lac", "local_tunnel_id": 11, "peer_tunnel_id": 22, "scenario": "tunnel_with_data",
			}}},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1701, DstPort: 1701},
			check: func(s *core.FlowSpec) bool { return s.L2TP != nil && s.L2TP.LocalTunnelID == 11 },
		},
		{
			name: "ldp",
			chain: []layers.Layer{ip(), udp(646, 646), {Name: "ldp", Config: map[string]interface{}{
				"lsr_id": "1.1.1.1", "events": []interface{}{map[string]interface{}{"kind": "hello", "direction": "c2s"}},
			}}},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 646, DstPort: 646},
			check: func(s *core.FlowSpec) bool { return s.LDP != nil && s.LDP.LSRID == "1.1.1.1" },
		},
		{
			name: "mdns",
			chain: []layers.Layer{ip(), udp(5353, 5353), {Name: "mdns", Config: map[string]interface{}{
				"mode": "query", "questions": []interface{}{map[string]interface{}{"name": "_services._dns-sd._udp.local", "type": 12}},
			}}},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "224.0.0.251", SrcPort: 5353, DstPort: 5353},
			check: func(s *core.FlowSpec) bool { return s.MDNS != nil && s.MDNS.Mode == "query" },
		},
		{
			name: "modbus",
			chain: []layers.Layer{ip(), tcp(40000, 502), {Name: "modbus", Config: map[string]interface{}{
				"unit_id": 3, "transactions": []interface{}{map[string]interface{}{"function_code": 1, "starting_address": 0, "quantity": 8}},
			}}},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 502},
			check: func(s *core.FlowSpec) bool { return s.MODBUS != nil && s.MODBUS.UnitID != nil && *s.MODBUS.UnitID == 3 },
		},
		{
			name: "mysql",
			chain: []layers.Layer{ip(), tcp(40000, 3306), {Name: "mysql", Config: map[string]interface{}{
				"server_version": "8.0.30", "username": "u", "database": "db",
			}}},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 3306},
			check: func(s *core.FlowSpec) bool { return s.MySQL != nil && s.MySQL.ServerVersion == "8.0.30" },
		},
		{
			name: "nmea",
			chain: []layers.Layer{ip(), tcp(40000, 10110), {Name: "nmea", Config: map[string]interface{}{
				"sessions": []interface{}{map[string]interface{}{
					"events": []interface{}{map[string]interface{}{"kind": "sentence", "talker": "GP", "type": "GSV", "fields": []interface{}{"1", "1", "1"}}},
				}},
			}}},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 10110},
			check: func(s *core.FlowSpec) bool { return s.NMEA != nil && len(s.NMEA.Sessions) == 1 },
		},
		{
			name: "ntp",
			chain: []layers.Layer{ip(), udp(123, 123), {Name: "ntp", Config: map[string]interface{}{
				"version": 4, "mode": 3, "stratum": 2,
			}}},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 123, DstPort: 123},
			check: func(s *core.FlowSpec) bool { return s.NTP != nil && s.NTP.Stratum == 2 },
		},
		{
			name:  "nvgre",
			chain: []layers.Layer{ip(), {Name: "nvgre", Config: map[string]interface{}{"vsid": 5001}}},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"},
			check: func(s *core.FlowSpec) bool { return s.NVGRE != nil && s.NVGRE.VSID == 5001 },
		},
		{
			name: "onvif",
			chain: []layers.Layer{ip(), tcp(40000, 80), {Name: "http", Config: map[string]interface{}{}}, {Name: "onvif", Config: map[string]interface{}{
				"profile": "onvif_soap12_http", "sessions": []interface{}{map[string]interface{}{
					"events": []interface{}{map[string]interface{}{"kind": "request", "service": "device", "operation": "GetSystemDateAndTime"}},
				}},
			}}},
			spec:  core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 80},
			check: func(s *core.FlowSpec) bool { return s.ONVIF != nil && s.ONVIF.Profile == "onvif_soap12_http" },
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
			for range ch {
				count++
			}
			if count == 0 {
				t.Fatal("Plan produced no packets")
			}
		})
	}
}
