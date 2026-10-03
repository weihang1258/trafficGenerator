package layers_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/core/schema"
	_ "github.com/trafficgen/trafficgen/internal/protocol/bgp" // init 注册 bgp 终结层生成器+校验器
)

// D-BGP-1 P4/P5 链级测试（tds/enip_chain_test 同构）。覆盖：
//  ① G-BGP-5：层内 events/sessions 翻译生效（registry 补键 + translate
//    case 之前恒 "unknown field" / 事件面丢失）；
//  ② G-BGP-6 presence 负例形状（M5 清单①）：层链 + 顶层空 bgp 子映射并存判死；
//  ③ 白名单外游离键判死（M5 清单②，1.11–1.13）：CheckProtoFlat 五键 +
//    schema 语义门 MAC 键；
//  ④ G-BGP-7：hold_time 1–2 校验面拒绝（RFC 4271 §4.2：0 或 ≥3）；
//  ⑤ 收官自查行（M5 清单④）：用例文件全例「非负例顶层键=0」。

const (
	bCli   = "10.0.0.1"
	bSrv   = "20.0.0.1"
	bSport = 12345
	bDport = 179
)

func bgpLayers(cfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": bCli, "dst": bSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": bSport}},
		map[string]interface{}{"bgp": cfg},
	}
}

func bgpOpenPair() []interface{} {
	return []interface{}{
		map[string]interface{}{"kind": "open", "direction": "c2s", "version": 4,
			"my_as": 64512, "hold_time": 90, "identifier": "192.0.2.1"},
		map[string]interface{}{"kind": "open", "direction": "s2c", "version": 4,
			"my_as": 64513, "hold_time": 90, "identifier": "192.0.2.2"},
	}
}

func planBGP(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	raw, _ := json.Marshal(layersArr)
	p, err := layers.BuildLayersPlanner("bgp", raw)
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: bCli, DstIP: bSrv, SrcPort: bSport}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		return nil, err
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts, nil
}

// ① G-BGP-5：层内 events 翻译端到端——双 OPEN + 双 KEEPALIVE = 3 + 4 + 4 = 11 包，
// 第 4 包（索引 3）是首个应用事件 OPEN（payload 29 字节）。
func TestBGPChain_LayerEventsTranslated(t *testing.T) {
	events := append(bgpOpenPair(),
		map[string]interface{}{"kind": "keepalive", "direction": "c2s"},
		map[string]interface{}{"kind": "keepalive", "direction": "s2c"})
	pkts, err := planBGP(t, bgpLayers(map[string]interface{}{
		"wire_profile": "bgp_rfc4271_ipv4_unicast",
		"events":       events,
	}))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(pkts) != 11 {
		t.Fatalf("got %d packets, want 11 (handshake 3 + events 4 + teardown 4)", len(pkts))
	}
	if pkts[0].L4.Flags != 0x02 {
		t.Fatalf("packet 0 flags = 0x%02x, want SYN 0x02", pkts[0].L4.Flags)
	}
	if len(pkts[3].Payload) != 29 {
		t.Fatalf("packet 3 payload = %d bytes, want OPEN 29", len(pkts[3].Payload))
	}
	// OPEN 头逐字节：marker 全 ff + length 0x001d + type 01 + version 04。
	want := []byte{0x00, 0x1d, 0x01, 0x04}
	got := pkts[3].Payload[16:20]
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("OPEN header bytes[%d..] = % x, want % x", 16, got, want)
		}
	}
}

// ①b 层内 sessions 翻译（多会话展开）：两条 session 各自独立连接 = 22 包，
// 且两个不同源端口都出现。
func TestBGPChain_LayerSessionsTranslated(t *testing.T) {
	sessionEvents := append(bgpOpenPair(),
		map[string]interface{}{"kind": "keepalive", "direction": "c2s"},
		map[string]interface{}{"kind": "keepalive", "direction": "s2c"})
	pkts, err := planBGP(t, bgpLayers(map[string]interface{}{
		"wire_profile": "bgp_rfc4271_ipv4_unicast",
		"sessions": []interface{}{
			map[string]interface{}{"src_port": 12345, "events": sessionEvents},
			map[string]interface{}{"src_port": 12346, "events": sessionEvents},
		},
	}))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(pkts) != 22 {
		t.Fatalf("got %d packets, want 22 (2 sessions x 11)", len(pkts))
	}
	seen := map[uint16]bool{}
	for _, p := range pkts {
		if p.L4.SrcPort != 0 {
			seen[p.L4.SrcPort] = true
		}
	}
	if !seen[12345] || !seen[12346] {
		t.Fatalf("session source ports seen = %v, want both 12345 and 12346", seen)
	}
}

// ①c events 缺键 → 默认 6 事件流（layer_gen defaultDualEvents）= 3 + 6 + 4 = 13；
// 显式 events:[] → connect-only = 7（缺键与空列表必须可区分）。
func TestBGPChain_EventsKeyAbsentVsEmpty(t *testing.T) {
	absent, err := planBGP(t, bgpLayers(map[string]interface{}{
		"wire_profile": "bgp_rfc4271_ipv4_unicast",
	}))
	if err != nil {
		t.Fatalf("Plan(absent): %v", err)
	}
	if len(absent) != 13 {
		t.Fatalf("events absent: got %d packets, want 13 (default 6-event stream)", len(absent))
	}
	empty, err := planBGP(t, bgpLayers(map[string]interface{}{
		"wire_profile": "bgp_rfc4271_ipv4_unicast",
		"events":       []interface{}{},
	}))
	if err != nil {
		t.Fatalf("Plan(empty): %v", err)
	}
	if len(empty) != 7 {
		t.Fatalf("events []: got %d packets, want 7 (connect-only)", len(empty))
	}
}

// ② presence 与顶层游离键判死。
func TestBGPChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": bgpLayers(map[string]interface{}{}),
		"bgp":    map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("bgp", cfg)
	if msg == "" {
		t.Fatal("CheckProtoFlat(bgp, {layers, bgp:{}}) = \"\", want top-level bgp presence rejection")
	}
	if !strings.Contains(msg, "rejects a top-level bgp sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": bgpLayers(map[string]interface{}{}), k: 1}
		m := core.CheckProtoFlat("bgp", bad)
		if m == "" {
			t.Fatalf("CheckProtoFlat(bgp, {layers, %s}) = \"\", want flat-field rejection", k)
		}
		if !strings.Contains(m, k) {
			t.Fatalf("CheckProtoFlat msg for %s = %q (must name the key)", k, m)
		}
	}
	// MAC 类走 schema 语义门（checkLayerFlatConflict 六键）。
	_, errs := schema.ValidateStrategy("synth", "bgp", map[string]any{
		"layers":  bgpLayers(map[string]interface{}{}),
		"src_mac": "aa:bb:cc:dd:ee:01",
	}, nil)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "src_mac") {
			found = true
		}
	}
	if !found {
		t.Fatalf("schema must reject top-level src_mac alongside layers, errs=%v", errs)
	}
}

// ③ udp 载体拒（DependsOn tcp，complete.go 通用 tcp-only 锚词）。
func TestBGPChain_UDPCarrierRejected(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": bCli, "dst": bSrv}},
		map[string]interface{}{"udp": map[string]interface{}{"dst_port": 179}},
		map[string]interface{}{"bgp": map[string]interface{}{"events": []interface{}{}}},
	}
	raw, _ := json.Marshal(arr)
	_, err := layers.BuildLayersPlanner("bgp", raw)
	if err == nil {
		t.Fatal("BuildLayersPlanner([ip,udp,bgp]) = nil, want carrier rejection")
	}
	if !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("carrier error = %q, want anchor \"carrier\"", err.Error())
	}
}

// ④ G-BGP-7：hold_time 1–2 拒绝（RFC 4271 §4.2：0 或 ≥3），锚词 hold_time；
// 0 与 3 必须放行（边界两侧）。
func TestBGPChain_HoldTimeSmallValues(t *testing.T) {
	openWith := func(hold int) []interface{} {
		return []interface{}{
			map[string]interface{}{"kind": "open", "direction": "c2s", "version": 4,
				"my_as": 64512, "hold_time": hold, "identifier": "192.0.2.1"},
			map[string]interface{}{"kind": "open", "direction": "s2c", "version": 4,
				"my_as": 64513, "hold_time": hold, "identifier": "192.0.2.2"},
		}
	}
	for _, hold := range []int{1, 2} {
		_, err := planBGP(t, bgpLayers(map[string]interface{}{"events": openWith(hold)}))
		if err == nil {
			t.Fatalf("hold_time=%d accepted, want rejection (RFC 4271 §4.2: 0 or >=3)", hold)
		}
		if !strings.Contains(err.Error(), "hold_time") {
			t.Fatalf("hold_time=%d error = %q, want anchor \"hold_time\"", hold, err.Error())
		}
	}
	for _, hold := range []int{0, 3} {
		pkts, err := planBGP(t, bgpLayers(map[string]interface{}{"events": openWith(hold)}))
		if err != nil {
			t.Fatalf("hold_time=%d rejected: %v (0 and >=3 are legal)", hold, err)
		}
		if len(pkts) != 9 {
			t.Fatalf("hold_time=%d: got %d packets, want 9 (handshake 3 + 2 opens + teardown 4)", hold, len(pkts))
		}
	}
}

// ⑤ 用例文件收官自查：全例非负例顶层键 ⊆ {layers}；presence/游离键负例在案。
func TestBGPChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/bgp.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	allowed := map[string]bool{"layers": true, "group_id": true}
	presence := false
	for _, c := range cases {
		id, _ := c["id"].(string)
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		neg := exp != nil && exp["expect_error"] == true
		if !neg {
			for k := range sj {
				if !allowed[k] {
					t.Fatalf("%s: non-negative top-level key %q (want ⊆ layers/group_id)", id, k)
				}
			}
		}
		if _, hasBGP := sj["bgp"]; hasBGP {
			if !neg {
				t.Fatalf("%s: top-level bgp on non-negative case", id)
			}
			presence = true
		}
	}
	if !presence {
		t.Fatal("want 1 presence negative (layers + top-level bgp), found none")
	}
	// 负例锚词在案（M5 清单③）：每条负例都必须带 error_contains。
	for _, c := range cases {
		exp, _ := c["expect"].(map[string]interface{})
		if exp == nil || exp["expect_error"] != true {
			continue
		}
		if s, _ := exp["error_contains"].(string); s == "" {
			t.Fatalf("%s: negative case without error_contains", c["id"])
		}
	}
}
