package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mqtt"
)

// D-MQTT-1 步骤 0 红例族（failing 先行，2026-09-16）。
// 实现前：①顶层 mqtt presence 未判死（放行）；②allowlist 无 mqtt 行
//（client_id 动态即 does not support dynamic）；③flat-wins 早返吞层值
//（层内 client_id 不生效）。红例走 BuildLayersPlanner 全链口径
//（P2c 真实入口）。

func mqttMigrateChain(t *testing.T, mqttCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	chain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "20.0.0.1"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 10000, "dst_port": 1883}},
		map[string]interface{}{"mqtt": mqttCfg},
	}
	out, _ := json.Marshal(chain)
	return out
}

func mqttMigrateSpec() core.FlowSpec {
	return core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 10000, DstPort: 1883}
}

// firstMQTTDataPayload returns the first up-direction data-frame payload from
// a planned chain (CONNECT frame). nil = no data frame found.
func firstMQTTDataPayload(t *testing.T, p core.ProtocolPlanner, spec core.FlowSpec) []byte {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for pkt := range ch {
		if pkt.L4.Protocol == "tcp" && pkt.Direction == "up" && len(pkt.Payload) > 0 {
			// data frames carry PSH-ACK; skip pure SYN (Payload empty) —
			// handshake packets have no payload in this planner's output.
			if pkt.L4.Flags != 0x18 {
				continue
			}
			return pkt.Payload
		}
	}
	return nil
}

// 红例1【D-MQTT-1 §1/§5】：顶层 mqtt 子映射 presence 判死——空 map 也死
// （dns/http 族先例）。现状：放行。
func TestMQTTChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"tcp": map[string]interface{}{}},
			map[string]interface{}{"mqtt": map[string]interface{}{}},
		},
		"mqtt": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("mqtt", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(mqtt, {layers, mqtt:{}}) = \"\", want top-level mqtt presence rejection")
	}
	if msg := core.CheckProtoFlat("mqtt", cfg); !strings.Contains(msg, "rejects a top-level mqtt sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q, want sub-anchor `rejects a top-level mqtt sub-config`", msg)
	}
}

// 红例2【D-MQTT-1 §12】：mqtt.client_id 动态对象——allowlist 加行后走
// string 面 list（现状：allowlist 无 mqtt 行即 `does not support dynamic`）。
func TestMQTTChain_ClientIDDynamicAllowed(t *testing.T) {
	raw := mqttMigrateChain(t, map[string]interface{}{
		"client_id": map[string]interface{}{"strategy": "list", "list": []interface{}{"c1", "c2"}},
	})
	if _, err := layers.BuildLayersPlanner("mqtt", raw); err != nil {
		t.Fatalf("BuildLayersPlanner mqtt client_id list: %v (allowlist mqtt 行应放行，现状 does not support dynamic)", err)
	}
	if err := core.CheckLayerDynShape("mqtt", "client_id", map[string]interface{}{
		"strategy": "list", "list": []interface{}{"c1", "c2"},
	}); err != "" {
		t.Fatalf("CheckLayerDynShape(mqtt, client_id, list) = %q, want clean (string 面)", err)
	}
	// inc/rand 关（string 面，dns.name/tls.sni 同款锚词）。
	if msg := core.CheckLayerDynShape("mqtt", "client_id", map[string]interface{}{
		"strategy": "inc", "range": []interface{}{1, 2},
	}); msg == "" || !strings.Contains(msg, "not supported for string field") {
		t.Fatalf("client_id/inc: want string-surface rejection, got %q", msg)
	}
}

// 红例3【D-MQTT-1 §1】：空壳例外——resolveLayerTuple 防御性补建的空
// spec.MQTT（ClientID/Messages/Will/Subscriptions/User/Properties 全空）
// 不触发 flat 权威，层内 client_id 字节级生效（http :839 空壳例外同款）。
// 断言取 CONNECT 帧 payload 的 client_id 字节段（v4：固定头 2 + 协议名 6 +
// level/flags/keepalive 4 → 长度在偏移 12-13、串在 14 起，MQTT 3.1.1 §3.1.2.1/§3.1.3.1）。
func TestMQTTChain_LayerWinsOverFlat(t *testing.T) {
	raw := mqttMigrateChain(t, map[string]interface{}{"client_id": "layer-client"})
	p, err := layers.BuildLayersPlanner("mqtt", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	// 空壳 spec.MQTT（worker 防御性补建产物）——层翻译必须继续，层值生效。
	spec := mqttMigrateSpec()
	spec.MQTT = &core.MQTTConfig{}
	// Plan 会走 ValidateSpec → translateTerminalConfig：实现后 CONNECT 帧
	// client_id = "layer-client"。
	payload := firstMQTTDataPayload(t, p, spec)
	if payload == nil {
		t.Fatal("Plan produced no MQTT data frame, want CONNECT")
	}
	if len(payload) < 14 || payload[0]&0xF0 != 0x10 || string(payload[4:8]) != "MQTT" {
		t.Fatalf("first up data frame is not CONNECT: %x", payload[:min(14, len(payload))])
	}
	idLen := int(payload[12])<<8 | int(payload[13])
	got := string(payload[14 : 14+idLen])
	if got != "layer-client" {
		t.Fatalf("CONNECT client_id = %q, want \"layer-client\" (layer value must win over flat)", got)
	}
}
