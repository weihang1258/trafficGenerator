package layers_test

// D-OSPF-1 P4 链级红例：[ip→ospf] raw-IP 链（RFC 2328 OSPFv2，IP proto 89；
// ip-layer raw 族第 15 连，igmp/icmp 同构）。红例面（契约 §14-P2）：
// ①顶层 ospf 子映射 presence 判死（空 map 也死）；
// ②白名单外游离键拒（顶层 src_ip/count 走 CheckProtoFlat，src_mac/ttl 走
//   schema 层链形状门）；
// ③链夹 tcp/udp 拒（carrier 锚）；
// ④链缺 ip 拒（carrier 锚，DependsOn 自动补全前拦）；
// ⑤层 config → spec.OSPF 翻译端到端（strict 解码：嵌套未知键拒，bgp 范式）。

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/core/schema"
	// 触发 ospf 包 init 注册层生成器 + 校验器。
	_ "github.com/trafficgen/trafficgen/internal/protocol/ospf"
)

func ospfChainRaw(t *testing.T, ospfCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	b, err := json.Marshal([]map[string]interface{}{
		{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "224.0.0.5", "ttl": 1}},
		{"ospf": ospfCfg},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// 红①【D-OSPF-1 §14-P2】：顶层 ospf 子映射 presence 判死（层链+顶层并存，
// 空映射同判死——debug 文案锚词 "no longer accepts a top-level ospf sub-config"）。
func TestOSPFChain_FlatPresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "224.0.0.5"}},
			map[string]interface{}{"ospf": map[string]interface{}{}},
		},
		"ospf": map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("ospf", cfg); msg == "" {
		t.Fatal(`CheckProtoFlat(ospf, {layers, ospf:{}}) = "", want top-level ospf presence rejection`)
	} else if !strings.Contains(msg, "no longer accepts a top-level ospf sub-config") {
		t.Fatalf("anchor mismatch: %q", msg)
	}
}

// 红②【D-OSPF-1 §14-P2】：白名单外游离键判死——顶层 src_ip/count 走
// CheckProtoFlat 文案，src_mac/ttl 走 schema 层链形状门（层链唯一真相）。
func TestOSPFChain_StrayTopLevelKeys(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "224.0.0.5"}},
		map[string]interface{}{"ospf": map[string]interface{}{"packet_type": "hello"}},
	}
	for _, k := range []string{"src_ip", "dst_ip", "count"} {
		if msg := core.CheckProtoFlat("ospf", map[string]interface{}{"layers": arr, k: 1}); msg == "" {
			t.Fatalf("CheckProtoFlat(ospf, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
	// 顶层 ttl（数值）与 layers 并存：CheckProtoFlat 五键不含 ttl（ttl 走
	// 层/扁平二态，非判死键），此处只锁 MAC 类游离键由 schema 形状门拒。
	if _, errs := schema.ValidateStrategy("synth", "ospf", map[string]any{
		"layers": arr, "src_mac": "aa:bb:cc:dd:ee:01",
	}, nil); len(errs) == 0 {
		t.Fatal("schema must reject top-level src_mac alongside layers")
	} else {
		found := false
		for _, e := range errs {
			if strings.Contains(e.Error(), "src_mac") {
				found = true
			}
		}
		if !found {
			t.Fatalf("src_mac stray key errs = %v, want src_mac mention", errs)
		}
	}
}

// 红③④【D-OSPF-1 §14-P2】：单载体 raw-IP 终结层——链夹 tcp/udp 拒、缺 ip
// 拒（DependsOn 自动补全前拦），锚词 carrier。
func TestOSPFChain_CarrierRejected(t *testing.T) {
	withTCP := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "224.0.0.5"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 40000, "dst_port": 89}},
		map[string]interface{}{"ospf": map[string]interface{}{}},
	}
	if _, err := layers.BuildLayersPlanner("ospf", mustJSON(t, withTCP)); err == nil ||
		!strings.Contains(err.Error(), "carrier") {
		t.Fatalf("tcp carrier: err = %v, want anchor \"carrier\"", err)
	}
	withUDP := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "224.0.0.5"}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 40000, "dst_port": 89}},
		map[string]interface{}{"ospf": map[string]interface{}{}},
	}
	if _, err := layers.BuildLayersPlanner("ospf", mustJSON(t, withUDP)); err == nil ||
		!strings.Contains(err.Error(), "carrier") {
		t.Fatalf("udp carrier: err = %v, want anchor \"carrier\"", err)
	}
	bare := []interface{}{map[string]interface{}{"ospf": map[string]interface{}{"packet_type": "hello"}}}
	if _, err := layers.BuildLayersPlanner("ospf", mustJSON(t, bare)); err == nil ||
		!strings.Contains(err.Error(), "carrier") {
		t.Fatalf("missing ip: err = %v, want anchor \"carrier\"", err)
	}
}

// 红⑤【D-OSPF-1 §15】：层 config → spec.OSPF 翻译端到端（strict 解码）。
// 非缺省 fixture 出 1 包：L3 proto=89 / TTL=1 / dst=224.0.0.5，payload 为
// 24B 公共头 + 20B Hello body + 4B 邻居（Version 2 / Type 1 / RouterID
// 9.9.9.9 / AreaID 0.0.0.9 —— 缺省 hello 是 1.1.1.1/0.0.0.0，能区分翻译
// 是否上线）。
func TestOSPFChain_LayerToSpecPlan(t *testing.T) {
	p, err := layers.BuildLayersPlanner("ospf", ospfChainRaw(t, map[string]interface{}{
		"version": 2, "profile": "rfc2328_ipv4", "packet_type": "hello",
		"router_id": "9.9.9.9", "area_id": "0.0.0.9", "auth_type": 0,
		"checksum_mode": "auto", "network_mask": "255.255.255.0",
		"hello_interval": 10, "dead_interval": 40, "options": 2, "priority": 1,
		"designated_router": "10.0.0.2", "backup_designated_router": "10.0.0.3",
		"neighbors": []interface{}{"2.2.2.2"},
	}))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "224.0.0.5", TTL: 1}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	if len(pkts) != 1 {
		t.Fatalf("packets=%d want 1", len(pkts))
	}
	pkt := pkts[0]
	if pkt.L3.Protocol != core.ProtocolOSPF {
		t.Fatalf("L3.Protocol=%d want 89", pkt.L3.Protocol)
	}
	if pkt.L3.TTL != 1 {
		t.Fatalf("L3.TTL=%d want 1 (generator hardcodes TTL=1, RFC 2328)", pkt.L3.TTL)
	}
	if pkt.L3.DstIP != "224.0.0.5" {
		t.Fatalf("L3.DstIP=%q want 224.0.0.5 (AllSPFRouters)", pkt.L3.DstIP)
	}
	if len(pkt.Payload) != 48 {
		t.Fatalf("payload len=%d want 48 (24 hdr + 20 hello + 4 neighbor)", len(pkt.Payload))
	}
	if pkt.Payload[0] != 2 || pkt.Payload[1] != 1 {
		t.Fatalf("payload[0:2]=%v want [2 1] (version 2 / type hello)", pkt.Payload[0:2])
	}
	if got := pkt.Payload[4:8]; string(got) != string([]byte{9, 9, 9, 9}) {
		t.Fatalf("router_id bytes=% x want 09 09 09 09 (layer config must reach spec.OSPF)", got)
	}
	if got := pkt.Payload[8:12]; string(got) != string([]byte{0, 0, 0, 9}) {
		t.Fatalf("area_id bytes=% x want 00 00 00 09", got)
	}
}

// 红⑤′：strict 解码（bgp 范式）——ospf 层内嵌套未知键同步拒（V9 只查层
// 一级字段，events[] 下钻必须由 translate 的 DisallowUnknownFields 兜）。
// 翻译跑在 ValidateSpec（Plan/worker 预检）而非 BuildLayersPlanner，故以
// Plan 面断言（错误经 ValidationErrors 统一拦截转发）。
func TestOSPFChain_StrictDecodeNestedUnknownKey(t *testing.T) {
	p, err := layers.BuildLayersPlanner("ospf", ospfChainRaw(t, map[string]interface{}{
		"version": 2, "router_id": "1.1.1.1", "area_id": "0.0.0.0",
		"events": []interface{}{
			map[string]interface{}{"kind": "hello", "bogus_nested": 1},
		},
	}))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	_, err = p.Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "224.0.0.5", TTL: 1})
	if err == nil || !strings.Contains(err.Error(), "bogus_nested") {
		t.Fatalf("nested unknown key: err = %v, want strict-decode rejection naming the key", err)
	}
}

// 红⑥【D-OSPF-1 §10 TTL 面 P4 实测】：ip 层 ttl 值对 OSPF 出包**惰性**——
// 生成器固写 TTL=1（layer_gen.go:44-45 单报文 / :81 事件），raw-IP 分支的
// finalEmit 仅 TTL==0 时填 spec.TTL（chain_planner.go:1509-1510），故层值
// 被生成器值恒胜出。设计 §10 把此面留作"P4 实测为准"，此处钉死实测结论：
// 层写 7/255 仍出 TTL=1（RFC 2328 的 TTL=1 语义由生成器保证，不靠配置）。
// 存量 18/20 用例 ttl=1 与该硬编码值巧合一致，改写后断言口径不变。
func TestOSPFChain_LayerTTLIsInert(t *testing.T) {
	for _, ttl := range []int{1, 7, 255} {
		p, err := layers.BuildLayersPlanner("ospf", mustJSON(t, []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "10.0.0.1", "dst": "224.0.0.5", "ttl": ttl}},
			map[string]interface{}{"ospf": map[string]interface{}{"version": 2, "packet_type": "hello", "router_id": "1.1.1.1", "area_id": "0.0.0.0"}},
		}))
		if err != nil {
			t.Fatalf("ttl=%d: BuildLayersPlanner: %v", ttl, err)
		}
		ch, err := p.Plan(context.Background(), core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "224.0.0.5", TTL: uint8(ttl)})
		if err != nil {
			t.Fatalf("ttl=%d: Plan: %v", ttl, err)
		}
		for pk := range ch {
			if pk.L3.TTL != 1 {
				t.Fatalf("ip.ttl=%d -> L3.TTL=%d, want 1 (generator hardcodes RFC 2328 TTL=1)", ttl, pk.L3.TTL)
			}
			break
		}
	}
}

func mustJSON(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
