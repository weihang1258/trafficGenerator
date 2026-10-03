package layers_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/rtmfp" // init 注册 rtmfp 终结层生成器+校验器
)

// D-RTMFP-1 P4 链级测试（tds_chain_test.go 同构）：
// ①层条目→spec.RTMFP 翻译端到端（[ip,udp,rtmfp] 出包，事件数 = datagram 数）
// ②presence 与顶层游离键判死（CheckProtoFlat rtmfp 分支）
// ③载体预检：夹 tcp 拒 / 缺 udp 拒（锚词 carrier，TransportOn=[udp]）
// ④用例文件收官自查（29 例：16 正 + 13 负；非负例顶层键 ⊆ 白名单）

func rJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	return out
}

func rLayers(rtmfpCfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.10", "dst": "198.51.100.20"}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 40000, "dst_port": 1935}},
		map[string]interface{}{"rtmfp": rtmfpCfg},
	}
}

// rHandshakeSessions 是最小四事件握手（hello/hello_ack/cookie/session_confirm）。
func rHandshakeSessions() map[string]interface{} {
	return map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"session_id": 1,
				"events": []interface{}{
					map[string]interface{}{"kind": "hello", "direction": "c2s"},
					map[string]interface{}{"kind": "hello_ack", "direction": "s2c"},
					map[string]interface{}{"kind": "cookie", "direction": "s2c"},
					map[string]interface{}{"kind": "session_confirm", "direction": "c2s"},
				},
			},
		},
	}
}

func rPlan(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	p, err := layers.BuildLayersPlanner("rtmfp", rJSON(t, layersArr))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts
}

// ①层条目→spec.RTMFP 翻译端到端：纯 layers 形（无顶层 rtmfp 子映射）出 4 包，
// 首包 UDP payload = hello 16B 自建头（marker 0x0E/kind 0x01/len 0x0010），
// 第三包 cookie 为确定性派生 8 字节（sid=1 → 00000001 deadbeee）。
func TestRTMFPChain_LayerToSpecPlan(t *testing.T) {
	pkts := rPlan(t, rLayers(rHandshakeSessions()))
	if len(pkts) != 4 {
		t.Fatalf("got %d packets, want 4 (one datagram per event)", len(pkts))
	}
	if got := len(pkts[0].Payload); got != 16 {
		t.Fatalf("hello payload len = %d, want 16 (header only)", got)
	}
	wantHello := "0e010010000000010000000000000000"
	if got := string(mustHex(t, pkts[0].Payload)); got != wantHello {
		t.Fatalf("hello header = %s, want %s", got, wantHello)
	}
	wantCookie := "0e030018000000010000000000000000" + "00000001deadbeee"
	if got := string(mustHex(t, pkts[2].Payload)); got != wantCookie {
		t.Fatalf("cookie frame = %s, want %s (deterministic derivation sid||sid^0xDEADBEEF)", got, wantCookie)
	}
	if pkts[0].L4.Protocol != "udp" || pkts[0].L4.DstPort != 1935 {
		t.Fatalf("packet 0 L4 = %+v, want udp dst 1935", pkts[0].L4)
	}
	// s2c 方向端口交换（planner.go:106-116）。
	if pkts[1].L4.SrcPort != 1935 || pkts[1].L4.DstPort != 40000 {
		t.Fatalf("packet 1 L4 = %+v, want swapped (src 1935 / dst 40000)", pkts[1].L4)
	}
}

// ②presence 与顶层游离键判死（CheckProtoFlat rtmfp 分支；空 map 也死）。
func TestRTMFPChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": rLayers(map[string]interface{}{}),
		"rtmfp":  map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("rtmfp", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(rtmfp, {layers, rtmfp:{}}) = \"\", want top-level rtmfp presence rejection")
	} else if !strings.Contains(msg, "rejects a top-level rtmfp sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if msg := core.CheckProtoFlat("rtmfp", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(rtmfp, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
}

// ③载体预检（TransportOn=[udp]）：夹 tcp 拒、缺 udp 拒，锚词 carrier。
func TestRTMFPChain_CarrierRejected(t *testing.T) {
	withTCP := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.10", "dst": "198.51.100.20"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 40000, "dst_port": 1935}},
		map[string]interface{}{"rtmfp": map[string]interface{}{}},
	}
	_, err := layers.BuildLayersPlanner("rtmfp", rJSON(t, withTCP))
	if err == nil {
		t.Fatal("BuildLayersPlanner([ip,tcp,rtmfp]) = nil, want carrier rejection")
	}
	if !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("tcp carrier error = %q, want anchor \"carrier\"", err.Error())
	}
	missingUDP := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.10", "dst": "198.51.100.20"}},
		map[string]interface{}{"rtmfp": map[string]interface{}{}},
	}
	_, err = layers.BuildLayersPlanner("rtmfp", rJSON(t, missingUDP))
	if err == nil {
		t.Fatal("BuildLayersPlanner([ip,rtmfp]) = nil, want missing-udp rejection")
	}
	if !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("missing udp error = %q, want anchor \"carrier\"", err.Error())
	}
	// 混族 ip 层同面预检（bacnet 同构）。
	mixed := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.10", "dst": "2001:db8::20"}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 40000, "dst_port": 1935}},
		map[string]interface{}{"rtmfp": map[string]interface{}{}},
	}
	_, err = layers.BuildLayersPlanner("rtmfp", rJSON(t, mixed))
	if err == nil || !strings.Contains(err.Error(), "family") {
		t.Fatalf("mixed-family error = %v, want anchor \"family\"", err)
	}
}

// ④用例文件收官自查：29 例（16 正 + 13 负 = 9 协议负例 + §12-P2 四链级红例）；
// 非负例顶层键 ⊆ {layers,flow_control,output}；presence/游离键红例在案；
// 负例 expect 键集严格 = {expect_error, error_contains}；断言无 rtmfp.* 字段。
func TestRTMFPChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/rtmfp.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 29 {
		t.Fatalf("want 29 cases (16 pos + 13 neg), got %d", len(cases))
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "output": true}
	presence, stray := false, false
	pos, neg := 0, 0
	for _, c := range cases {
		id, _ := c["id"].(string)
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		isNeg := exp != nil && exp["expect_error"] == true
		if isNeg {
			neg++
			if len(exp) != 2 || exp["error_contains"] == nil {
				t.Fatalf("%s: negative expect keys = %v, want exactly {expect_error, error_contains}", id, exp)
			}
		} else {
			pos++
			for k := range sj {
				if !allowed[k] {
					t.Fatalf("%s: non-negative top-level key %q (want ⊆ layers/flow_control/output)", id, k)
				}
			}
		}
		if _, has := sj["rtmfp"]; has {
			if !isNeg {
				t.Fatalf("%s: top-level rtmfp on non-negative case", id)
			}
			presence = true
		}
		if _, has := sj["src_ip"]; has {
			if !isNeg {
				t.Fatalf("%s: top-level src_ip on non-negative case", id)
			}
			stray = true
		}
		// 断言通道诚实性：无 rtmfp.* 字段（tshark 无 dissector）。
		if fields, ok := exp["fields"].([]interface{}); ok {
			for _, fi := range fields {
				fm, _ := fi.(map[string]interface{})
				if f, _ := fm["field"].(string); strings.HasPrefix(f, "rtmfp.") {
					t.Fatalf("%s: rtmfp.* field assertion %q (no dissector; use frames hex)", id, f)
				}
			}
		}
	}
	if pos != 16 || neg != 13 {
		t.Fatalf("want 16 pos + 13 neg, got %d pos + %d neg", pos, neg)
	}
	if !presence {
		t.Fatal("want presence negative (layers + top-level rtmfp), found none")
	}
	if !stray {
		t.Fatal("want stray top-level key negative (layers + src_ip), found none")
	}
}

func mustHex(t *testing.T, b []byte) []byte {
	t.Helper()
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		out = append(out, hexdigits[v>>4], hexdigits[v&0x0f])
	}
	return out
}
