package core_test

import (
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/schema"
)

// D-REWORK-1（CORE_MEMORY 1.11-1.13 顶层白名单，2026-09-19 用户指令）。
// 三条失败先行：
// ① eth 层静态 MAC 必须被消费进 spec（此前链驱动只读顶层 src_mac——
//    1.11 判顶层游离违规后，eth 层成为 MAC 唯一合法住处，静态标量必须生效；
//    动态对象走 resolveLayerTuple 既有）。
// ② ip 层显式 ttl 必须回填 spec.TTL（此前只有顶层 ttl 被读——http_ttl_custom
//    顶层影子迁除后帧 TTL 才能保持 128）。
// ③ layers 与顶层 src_mac/dst_mac 并存必须 400（checkLayerFlatConflict
//    家族扩列——1.4 五键是例举不是全集）。

func TestEthLayerStaticMACConsumed(t *testing.T) {
	spec := core.MapToFlowSpec(map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"eth": map[string]interface{}{
				"src_mac": "aa:bb:cc:00:00:01",
				"dst_mac": "01:0c:cd:01:00:01",
			}},
			map[string]interface{}{"sv": map[string]interface{}{
				"sv_id": "x", "appid": 16384, "conf_rev": 1, "samples_per_cycle": 80,
				"data": []interface{}{map[string]interface{}{"name": "I_A", "type": "int32", "inst_mag": 100}},
			}},
		},
	}, "sv")
	if spec.SrcMAC != "aa:bb:cc:00:00:01" {
		t.Fatalf("eth layer static src_mac must flow into spec.SrcMAC, got %q", spec.SrcMAC)
	}
	if spec.DstMAC != "01:0c:cd:01:00:01" {
		t.Fatalf("eth layer static dst_mac must flow into spec.DstMAC, got %q", spec.DstMAC)
	}
}

func TestIPLayerTTLConsumed(t *testing.T) {
	spec := core.MapToFlowSpec(map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{
				"src": "192.0.2.10", "dst": "198.51.100.20", "ttl": 128,
			}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": 40046, "dst_port": 80}},
			map[string]interface{}{"http": map[string]interface{}{"method": "GET", "uri": "/ttl", "version": "1.1"}},
		},
	}, "http")
	if spec.TTL != 128 {
		t.Fatalf("ip layer explicit ttl must backfill spec.TTL, got %d (want 128)", spec.TTL)
	}
}

func TestTopLevelMACWithLayersRejected(t *testing.T) {
	_, errs := schema.ValidateStrategy("synth", "sv", map[string]any{
		"src_mac": "aa:bb:cc:dd:ee:03",
		"layers": []any{
			map[string]any{"eth": map[string]any{}},
			map[string]any{"sv": map[string]any{
				"sv_id": "x", "appid": 16384, "conf_rev": 1, "samples_per_cycle": 80,
				"data": []any{map[string]any{"name": "I_A", "type": "int32", "inst_mag": 100}},
			}},
		},
	}, &schema.FlowControl{Type: "flows", Value: 1})
	found := false
	for _, e := range errs {
		if strings.Contains(e.Message, "config mixes layers") {
			found = true
		}
	}
	if !found {
		t.Fatalf("top-level src_mac + layers must be rejected as mixed config (1.11 whitelist), got %v", errs)
	}
}
