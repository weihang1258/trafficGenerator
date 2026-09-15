package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dns" // init 注册 dns 终结层生成器
)

// D-DNS-1 步骤 0 红例族（failing 先行，2026-09-15）。
// 实现前全红：①顶层 dns presence 未判死（放行）；②注册表仅 2 键（name
// 是未知字段 V9 拒）；③allowlist 无 dns 行（name 动态即 does not support
// dynamic）。红例走 BuildLayersPlanner 全链口径（P2c 真实入口）。

func dnsMigrateChain(t *testing.T, dnsCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	chain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 12345, "dst_port": 53}},
		map[string]interface{}{"dns": dnsCfg},
	}
	out, _ := json.Marshal(chain)
	return out
}

func dnsMigrateSpec() core.FlowSpec {
	return core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 53}
}

// 红例1【D-DNS-1 §5】：顶层 dns 子映射 presence 判死——空 map 也死
//（http 族 9 协议先例）。现状：放行。
func TestDNSChain_FlatPresenceRejected(t *testing.T) {
	// 顶层 dns 子映射走 CheckProtoFlat 执法（与 schema 层同口径，共用一函数）。
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"udp": map[string]interface{}{}},
			map[string]interface{}{"dns": map[string]interface{}{}},
		},
		"dns": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("dns", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(dns, {layers, dns:{}}) = \"\", want top-level dns presence rejection")
	}
	if msg := core.CheckProtoFlat("dns", cfg); !strings.Contains(msg, "no longer accepts a top-level dns sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q, want sub-anchor `no longer accepts a top-level dns sub-config`", msg)
	}
}

// 红例2【D-DNS-1 §4】：dns 层 14 键——txid/is_response/response_ip 层值
// 翻译进 spec.DNS（现状：注册表仅 name/query_type 两键，txid 即 V9 未知
// 字段拒绝）。
func TestDNSChain_Layer14KeysTranslate(t *testing.T) {
	raw := dnsMigrateChain(t, map[string]interface{}{
		"name": "a.com", "query_type": 28, "txid": 1000,
		"is_response": true, "response_ip": "2001:db8::1",
	})
	p, err := layers.BuildLayersPlanner("dns", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v (层 14 键应由注册表接受；现状 2 键即 V9 拒绝)", err)
	}
	if err := p.Validate(dnsMigrateSpec()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), dnsSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	for pkt := range ch {
		if pkt.L4.Protocol != "udp" {
			t.Errorf("packet L4 protocol = %q, want udp", pkt.L4.Protocol)
		}
		n++
	}
	if n != 2 {
		t.Errorf("packets = %d, want 2 (query up + response down; is_response 层值须生效)", n)
	}
}

// 红例3【D-DNS-1 §12】：dns.name 动态对象——allowlist 加行后走 string 面
// list（双流 distinct 由 flows=2 逐流解析；现状：allowlist 无 dns 行即
// `does not support dynamic`）。
func TestDNSChain_NameDynamicAllowed(t *testing.T) {
	raw := dnsMigrateChain(t, map[string]interface{}{
		"name": map[string]interface{}{"strategy": "list", "list": []interface{}{"a.com", "b.com"}},
	})
	p, err := layers.BuildLayersPlanner("dns", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v (name 动态应由 allowlist dns 行放行，现状 does not support dynamic)", err)
	}
	if err := p.Validate(dnsMigrateSpec()); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}
