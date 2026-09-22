package layers_test

// 66-doh 链上 planner 级单测：空配置默认流（layer_gen.go 的 cfg==nil /
// Sessions 空分支——P0b 空配置默认家族）、载体拒绝（validate_layers.go 的
// doh carrier 检查）、wire_fault 经 ValidateSpec 的传播（负例锚词通道）。
// 110 例离线套件（cases/doh.json）覆盖语义面；此处补分支级证据。
import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/doh"  // 终结层生成器注册
	_ "github.com/trafficgen/trafficgen/internal/protocol/http" // 载体层生成器注册
)

// planDOH runs the full factory path for an [tcp→http→doh] chain and returns
// the emitted packet configs. cfg 经 JSON round-trip 归一（数字 → float64）。
func planDOH(t *testing.T, cfg map[string]interface{}) []core.PacketConfig {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal cfg: %v", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("unmarshal cfg: %v", err)
	}
	spec := core.MapToFlowSpec(cfg, "doh")
	rawLayers, err := json.Marshal([]map[string]map[string]interface{}{
		{"tcp": {}}, {"http": {}}, {"doh": {}},
	})
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	pl, err := layers.BuildLayersPlanner("doh", rawLayers)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := pl.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var out []core.PacketConfig
	for p := range ch {
		out = append(out, p)
	}
	return out
}

// dohBase 是不含 doh 子映射的最小 spec（触发生成器 cfg==nil 默认分支）。
func dohBase(withDohKey bool) map[string]interface{} {
	cfg := map[string]interface{}{
		"src_ip": "192.0.2.66", "dst_ip": "198.51.100.66",
		"src_port": 42066, "dst_port": 80,
	}
	if withDohKey {
		cfg["doh"] = map[string]interface{}{}
	}
	return cfg
}

// TestDOHChainEmptyConfigDefault：{"doh":{}} 空 Map（spec.DOH 非 nil）→
// 基线单事务——POST www.example.com A → 200 NOERROR + A 192.0.2.1 TTL 300。
// 9 包（3 握手 + 请求/响应各 1 段 + 4 挥手）；请求段携带完整 POST 帧
// （Content-Length: 33），响应段携带 2xx 帧（Content-Length: 64 + max-age 300）。
// 对照：完全不带 "doh" 键（spec.DOH == nil）时 http 层走自身默认终结路径
// （GET /，与 gbt/cwmp/getwork 同款家族行为），不是 doh 默认——同测断言防混淆。
func TestDOHChainEmptyConfigDefault(t *testing.T) {
	// 带 "doh": {} → doh 基线。
	pkts := planDOH(t, dohBase(true))
	if len(pkts) != 9 {
		t.Fatalf("empty doh config = %d packets, want 9 (3+2+4)", len(pkts))
	}
	req := string(pkts[3].Payload)
	if !strings.HasPrefix(req, "POST /dns-query HTTP/1.1\r\n") {
		t.Errorf("default request frame head: %q", req[:40])
	}
	if !strings.Contains(req, "Content-Length: 33\r\n") {
		t.Errorf("default request must carry the 33B baseline query wire")
	}
	resp := string(pkts[4].Payload)
	if !strings.HasPrefix(resp, "HTTP/1.1 200 OK\r\n") {
		t.Errorf("default response frame head: %q", resp[:40])
	}
	if !strings.Contains(resp, "Content-Length: 64\r\n") ||
		!strings.Contains(resp, "Cache-Control: max-age=300\r\n") {
		t.Errorf("default response must be the 64B +A baseline with max-age=300")
	}
	if pkts[3].Direction != "up" || pkts[4].Direction != "down" {
		t.Errorf("default frames: packet 4 = %q, packet 5 = %q (want up/down)", pkts[3].Direction, pkts[4].Direction)
	}

	// 不带 "doh" 键 → http 层自身默认（GET /），非 doh 基线。
	pkts = planDOH(t, dohBase(false))
	if len(pkts) != 9 {
		t.Fatalf("no doh key = %d packets, want 9 (http-layer default)", len(pkts))
	}
	if head := string(pkts[3].Payload); !strings.HasPrefix(head, "GET / HTTP/1.1\r\n") {
		t.Errorf("no doh key must fall back to the http-layer default, got: %q", head[:40])
	}
}

// TestDOHChainCarrierRejected：tcp→doh 直连（缺 http 载体）在
// BuildLayersPlanner 即拒绝，错误携带锚词 carrier（负例
// doh_neg_layer_chain_missing_http 的 planner 级证据）。
func TestDOHChainCarrierRejected(t *testing.T) {
	rawLayers, err := json.Marshal([]map[string]map[string]interface{}{
		{"tcp": {}}, {"doh": {}},
	})
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	_, err = layers.BuildLayersPlanner("doh", rawLayers)
	if err == nil {
		t.Fatal("tcp→doh direct chain must be rejected at planner construction")
	}
	if !strings.Contains(err.Error(), "carrier") {
		t.Errorf("carrier rejection error must carry the anchor 'carrier', got: %v", err)
	}
}

// TestDOHChainWireFaultPropagates：wire_fault 注入经 ValidateSpec 拒绝并携带
// 主锚词（任务错误通道，防 0 包假成功）。抽查三档：query_missing（GET 族）、
// content_length（HTTP 语义族）、z_nonzero（值域族）。
func TestDOHChainWireFaultPropagates(t *testing.T) {
	for _, wf := range []struct{ fault, anchor string }{
		{"query_missing", "dns"},
		{"content_length", "content-length"},
		{"z_nonzero", "z"},
	} {
		cfg := dohBase(true)
		cfg["doh"].(map[string]interface{})["wire_fault"] = wf.fault
		b, _ := json.Marshal(cfg)
		var norm map[string]interface{}
		json.Unmarshal(b, &norm)
		spec := core.MapToFlowSpec(norm, "doh")
		rawLayers, _ := json.Marshal([]map[string]map[string]interface{}{
			{"tcp": {}}, {"http": {}}, {"doh": {}},
		})
		pl, err := layers.BuildLayersPlanner("doh", rawLayers)
		if err != nil {
			t.Fatalf("BuildLayersPlanner: %v", err)
		}
		if err := pl.Validate(spec); err == nil {
			t.Errorf("wire_fault %s must be rejected", wf.fault)
		} else if !strings.Contains(err.Error(), wf.anchor) {
			t.Errorf("wire_fault %s error must carry anchor %q, got: %v", wf.fault, wf.anchor, err)
		}
	}
}
