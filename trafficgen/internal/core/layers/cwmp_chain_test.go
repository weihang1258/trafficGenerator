package layers_test

// D-CWMP-1 P4 链级红例（failing 先行，smtp_migrate_test.go 同构）：
// ①顶层 cwmp 子映射 presence 判死；②层 config 翻译进 spec.CWMP
// （现状：顶层注入形，translate 无 case "cwmp"，层值被忽略）；
// ③registry 六键 V9 allowlist（未知字段拒）；④空层=P0b 基线单会话
// （13.20 缺省面，现状口径零改动）；⑤事务级 device_id 上线（P4 勘误，
// B6 遗留死配置）。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/cwmp" // init 注册 cwmp 终结层生成器
)

func cwmpMigrateChain(t *testing.T, cwmpCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	chain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 50065, "dst_port": 7547}},
		map[string]interface{}{"http": map[string]interface{}{}},
		map[string]interface{}{"cwmp": cwmpCfg},
	}
	out, _ := json.Marshal(chain)
	return out
}

func cwmpMigrateSpec() core.FlowSpec {
	return core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 50065, DstPort: 7547}
}

// 红例①【D-CWMP-1 裁定4】：顶层 cwmp 子映射 presence 判死（空 map 也死，
// dns/mqtt/smtp 先例）。现状：放行（B6 注入形）。
func TestCWMPChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"tcp": map[string]interface{}{}},
			map[string]interface{}{"http": map[string]interface{}{}},
			map[string]interface{}{"cwmp": map[string]interface{}{}},
		},
		"cwmp": map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("cwmp", cfg)
	if msg == "" {
		t.Fatal(`CheckProtoFlat(cwmp, {layers, cwmp:{}}) = "", want top-level cwmp presence rejection`)
	}
	if !strings.Contains(msg, "no longer accepts a top-level cwmp sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q, want sub-anchor `no longer accepts a top-level cwmp sub-config`", msg)
	}
}

// 红例②【D-CWMP-1 裁定3】：层 config 翻译进 spec.CWMP——自定义 inform
// DeviceIdStruct.serial 必须上线（现状：层值被忽略，serial 不出现在字节面）。
func TestCWMPChain_LayerConfigTranslates(t *testing.T) {
	raw := cwmpMigrateChain(t, map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"transactions": []interface{}{
					map[string]interface{}{
						"kind": "inform", "id": "1",
						"events":    []interface{}{map[string]interface{}{"code": "2 PERIODIC"}},
						"device_id": map[string]interface{}{"manufacturer": "Example", "oui": "001122", "product_class": "GW", "serial": "SN-CUSTOM-42"},
					},
					map[string]interface{}{"kind": "inform_response", "id": "1"},
				},
			},
		},
	})
	p, err := layers.BuildLayersPlanner("cwmp", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), cwmpMigrateSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	found := false
	for pkt := range ch {
		if len(pkt.Payload) > 0 && strings.Contains(string(pkt.Payload), "SN-CUSTOM-42") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("layer cwmp config not translated: custom inform serial never emitted (translate case missing?)")
	}
}

// 红例③【D-CWMP-1 裁定2】：registry 六键 V9 allowlist——未知字段拒
// （现状：层 Fields 空，任何字段都拒；实现后 profile 等六键放行）。
func TestCWMPChain_V9Allowlist(t *testing.T) {
	// 未知字段：六键之外必拒（V9 锚 unknown field）。
	bad := cwmpMigrateChain(t, map[string]interface{}{"nope": 1})
	if _, err := layers.ValidateLayers(bad, "cwmp"); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field must be rejected, got %v", err)
	}
	// 六键放行（V9 只验顶层键，嵌套值语义归 translate/validator）。
	ok := cwmpMigrateChain(t, map[string]interface{}{
		"profile":    "cwmp_http_v1",
		"namespace":  "urn:dslforum-org:cwmp-1-2",
		"concurrent": true,
		"sessions":   []interface{}{},
		"flows":      []interface{}{},
		"auth":       map[string]interface{}{"username": "cpe"},
	})
	if _, err := layers.ValidateLayers(ok, "cwmp"); err != nil {
		t.Fatalf("six contract keys must pass V9: %v", err)
	}
}

// 红例⑤【D-CWMP-1 P4 勘误】：事务级 device_id 必须上线（B6 遗留死配置——
// validator 校验 tx.DeviceID（planner.go validateDeviceIDRef）但发射路径只读
// 会话级 ifaceDevice(run.sess.DeviceID)，155 处事务级 device_id 静默忽略）。
// 修复口径：tx 级优先，回退会话级（会话级 nil 已在生成器补夹具默认）。
func TestCWMPChain_TxDeviceIDEmitted(t *testing.T) {
	raw := cwmpMigrateChain(t, map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"device_id": map[string]interface{}{"manufacturer": "Example", "oui": "001122", "product_class": "GW", "serial": "SN-SESSION-1"},
				"transactions": []interface{}{
					map[string]interface{}{
						"kind": "inform", "id": "1",
						"events":    []interface{}{map[string]interface{}{"code": "2 PERIODIC"}},
						"device_id": map[string]interface{}{"manufacturer": "Example", "oui": "003344", "product_class": "ONU", "serial": "SN-TX-99"},
					},
					map[string]interface{}{"kind": "inform_response", "id": "1"},
				},
			},
		},
	})
	p, err := layers.BuildLayersPlanner("cwmp", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), cwmpMigrateSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var sawTx, sawSession bool
	for pkt := range ch {
		s := string(pkt.Payload)
		if strings.Contains(s, "SN-TX-99") {
			sawTx = true
		}
		if strings.Contains(s, "SN-SESSION-1") {
			sawSession = true
		}
	}
	if !sawTx {
		t.Fatal("tx-level device_id not emitted (dead config: validator validates but emit ignores)")
	}
	if sawSession {
		t.Fatal("session serial leaked into tx-level override transaction")
	}
}

// 红例④【D-CWMP-1 裁定3/6③】：空层 {"cwmp":{}} = P0b 基线单会话 11 包
// （3 握手 + inform/inform_response + 空 POST/204 + 4 挥手）——13.20 缺省面，
// 现状口径零改动（validator nil 放行 + 生成器 len==0 补基线）。
func TestCWMPChain_EmptyLayerBaseline(t *testing.T) {
	raw := cwmpMigrateChain(t, map[string]interface{}{})
	p, err := layers.BuildLayersPlanner("cwmp", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), cwmpMigrateSpec())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	for range ch {
		n++
	}
	if n != 11 {
		t.Fatalf("packets=%d, want 11 (P0b baseline single session)", n)
	}
}
