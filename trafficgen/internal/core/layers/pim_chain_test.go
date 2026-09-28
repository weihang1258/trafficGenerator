package layers_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/pim" // init 注册 pim 终结层生成器+校验器
)

// D-PIM-1 P4 链级红例（igmp_chain_test / bgp_chain_test 同构）。覆盖：
//  ① G-PIM-1：层内 profile/checksum_mode/events 翻译生效（此前 registry
//    pim 行 Fields 为空 → 层内业务键 V9 判 unknown field；且无 translate
//    case → 事件面丢失）；
//  ② G-PIM-2 presence 负例形状（M5 清单①）：层链 + 顶层空 pim 子映射并存判死；
//  ③ 白名单外游离键判死（M5 清单②，1.11–1.13）：CheckProtoFlat 五键；
//  ④ G-PIM-3 载体判死（M5 清单③）：[ip,udp,pim] / [ip,tcp,pim] 夹传输层拒、
//    裸 [pim] 缺 ip 载体拒（锚 carrier，先于 DependsOn 自动补全判）；
//  ⑤ 收官自查行（M5 清单④）：用例文件全例「非负例顶层键=0」+ 负例两键严格。

const (
	pimCli   = "192.0.2.1"
	pimMcast = "224.0.0.13"
)

func pimChainRaw(t *testing.T, pimCfg map[string]interface{}, ipCfg map[string]interface{}) json.RawMessage {
	t.Helper()
	if ipCfg == nil {
		ipCfg = map[string]interface{}{"src": pimCli, "dst": pimMcast, "ttl": 1}
	}
	b, err := json.Marshal([]map[string]interface{}{
		{"ip": ipCfg},
		{"pim": pimCfg},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func pimHelloEvent(dir string) map[string]interface{} {
	return map[string]interface{}{"kind": "hello", "direction": dir, "holdtime": 105}
}

// ① G-PIM-1：层内 events 翻译端到端——[ip,pim] 双 Hello 事件（c2s+s2c）出 2 包，
// PIM 起点 payload[0..1] = 0x20 0x00（Version 2 | Type 0），checksum 非零；
// s2c 事件走 down 方向，L3 源目由 raw-IP 分支交换。
func TestPIMChain_LayerEventsTranslated(t *testing.T) {
	p, err := layers.BuildLayersPlanner("pim", pimChainRaw(t, map[string]interface{}{
		"profile":       "pim_sm_rfc7761_ipv4",
		"checksum_mode": "auto",
		"events":        []interface{}{pimHelloEvent("c2s"), pimHelloEvent("s2c")},
	}, nil))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: pimCli, DstIP: pimMcast, TTL: 1}
	if err := p.Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for pkt := range ch {
		pkts = append(pkts, pkt)
	}
	if len(pkts) != 2 {
		t.Fatalf("got %d packets, want 2 (one per event)", len(pkts))
	}
	// 首包（c2s = up）：L3 原样，Protocol 103 固写。
	if pkts[0].L3.Protocol != core.ProtocolPIM {
		t.Fatalf("packet 0 L3.Protocol = %d, want %d (PIM)", pkts[0].L3.Protocol, core.ProtocolPIM)
	}
	if len(pkts[0].Payload) < 8 {
		t.Fatalf("packet 0 payload = %d bytes, want >= 8 (4B common header + holdtime option)", len(pkts[0].Payload))
	}
	if pkts[0].Payload[0] != 0x20 || pkts[0].Payload[1] != 0x00 {
		t.Fatalf("packet 0 first two bytes = % x, want 20 00 (Version 2 | Type Hello)", pkts[0].Payload[:2])
	}
	if ck := pkts[0].Payload[2:4]; ck[0] == 0 && ck[1] == 0 {
		t.Fatalf("packet 0 pim checksum is zero, want computed (checksum_mode=auto)")
	}
	// Holdtime option at payload[4..9]: type 0x0001, len 0x0002, value 105
	// (RFC 7761 §4.9.2 —— builder.go:198-200 三字段顺序 type/len/value).
	if got := pkts[0].Payload[4:10]; got[0] != 0x00 || got[1] != 0x01 ||
		got[2] != 0x00 || got[3] != 0x02 || got[4] != 0x00 || got[5] != 0x69 {
		t.Fatalf("packet 0 holdtime option = % x, want 00 01 00 02 00 69 (type=1 len=2 value=105)", got)
	}
	// 次包（s2c = down）：raw-IP 分支交换 L3 源目。
	if pkts[1].Direction != "down" {
		t.Fatalf("packet 1 direction = %q, want down (s2c)", pkts[1].Direction)
	}
	if pkts[1].L3.SrcIP != pimMcast || pkts[1].L3.DstIP != pimCli {
		t.Fatalf("packet 1 L3 = %s -> %s, want swapped %s -> %s (down)", pkts[1].L3.SrcIP, pkts[1].L3.DstIP, pimMcast, pimCli)
	}
}

// ①b 非法 profile 走层链同样判死（translate 后 spec.PIM 进 validator，
// 锚词 profile 与用例 #18 一致）。
func TestPIMChain_LayerProfileRejected(t *testing.T) {
	p, err := layers.BuildLayersPlanner("pim", pimChainRaw(t, map[string]interface{}{
		"profile": "pim_rfc7761_ipv6_pending",
		"events":  []interface{}{pimHelloEvent("c2s")},
	}, nil))
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	err = p.Validate(core.FlowSpec{SrcIP: pimCli, DstIP: pimMcast, TTL: 1})
	if err == nil {
		t.Fatal("Validate accepted IPv6 profile, want rejection")
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Fatalf("anchor mismatch: %v", err)
	}
}

// ② presence 判死【D-PIM-1 §14-P2】：层链 + 顶层空 pim 子映射并存（空 map 也死）。
func TestPIMChain_PresenceRejected(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": pimCli}},
			map[string]interface{}{"pim": map[string]interface{}{}},
		},
		"pim": map[string]interface{}{},
	}
	msg := core.CheckProtoFlat("pim", cfg)
	if msg == "" {
		t.Fatal(`CheckProtoFlat(pim, {layers, pim:{}}) = "", want top-level pim presence rejection`)
	}
	if !strings.Contains(msg, "no longer accepts a top-level pim sub-config") {
		t.Fatalf("anchor mismatch: %q", msg)
	}
}

// ③ 白名单外游离键判死（M5 清单②）：CheckProtoFlat 五键逐个点名。
func TestPIMChain_StrayTopLevelKeysRejected(t *testing.T) {
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{
			"layers": []interface{}{
				map[string]interface{}{"ip": map[string]interface{}{"src": pimCli}},
				map[string]interface{}{"pim": map[string]interface{}{}},
			},
			k: 1,
		}
		m := core.CheckProtoFlat("pim", bad)
		if m == "" {
			t.Fatalf("CheckProtoFlat(pim, {layers, %s}) = \"\", want flat-field rejection", k)
		}
		if !strings.Contains(m, k) {
			t.Fatalf("CheckProtoFlat msg for %s = %q (must name the key)", k, m)
		}
	}
	// 层内白名单外键（registry Fields 外）走 V9 unknown field。
	raw := pimChainRaw(t, map[string]interface{}{
		"profile": "pim_sm_rfc7761_ipv4",
		"events":  []interface{}{pimHelloEvent("c2s")},
		"port":    1234,
	}, nil)
	if _, err := layers.BuildLayersPlanner("pim", raw); err == nil {
		t.Fatal("BuildLayersPlanner accepted stray layer key `port`, want unknown-field rejection")
	} else if !strings.Contains(err.Error(), "unknown field") || !strings.Contains(err.Error(), "port") {
		t.Fatalf("anchor mismatch: %v", err)
	}
}

// ④ 载体判死（M5 清单③）：夹 tcp/udp 拒（PIM 裸 IP protocol 103，无传输层）；
// 裸 [pim] 缺 ip 载体拒（先于 DependsOn ["ip"] 自动补全判）。
func TestPIMChain_CarrierRejected(t *testing.T) {
	for _, carrier := range []string{"udp", "tcp"} {
		b, err := json.Marshal([]map[string]interface{}{
			{"ip": map[string]interface{}{"src": pimCli}},
			{carrier: map[string]interface{}{"dst_port": 103}},
			{"pim": map[string]interface{}{}},
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := layers.BuildLayersPlanner("pim", b); err == nil {
			t.Fatalf("BuildLayersPlanner([ip,%s,pim]) accepted, want carrier rejection", carrier)
		} else if !strings.Contains(err.Error(), "carrier") || !strings.Contains(err.Error(), carrier) {
			t.Fatalf("%s carrier error = %q, want anchors \"carrier\" + %q", carrier, err.Error(), carrier)
		}
	}
	b, err := json.Marshal([]map[string]interface{}{
		{"pim": map[string]interface{}{"profile": "pim_sm_rfc7761_ipv4", "events": []interface{}{pimHelloEvent("c2s")}}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := layers.BuildLayersPlanner("pim", b); err == nil {
		t.Fatal("BuildLayersPlanner(bare [pim]) accepted, want missing-ip carrier rejection")
	} else if !strings.Contains(err.Error(), "carrier") || !strings.Contains(err.Error(), "ip") {
		t.Fatalf("missing-ip error = %q, want anchors \"carrier\" + \"ip\"", err.Error())
	}
}

// ⑤ 用例文件收官自查（M5 清单④）：24 契约例（17 正 + 7 负）+ 4 链级红例；
// 非负例顶层键=0（仅 layers）；负例 expect 严格两键且锚词在案。
func TestPIMChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/pim.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) != 28 {
		t.Fatalf("got %d cases, want 28 (24 契约 + 4 链级红例)", len(cases))
	}
	allowedTop := map[string]bool{"layers": true, "group_id": true}
	nPos, nNeg := 0, 0
	presence := false
	for _, c := range cases {
		id, _ := c["id"].(string)
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		if exp == nil {
			t.Fatalf("%s: expect missing", id)
		}
		neg := exp["expect_error"] == true
		if neg {
			nNeg++
			// §14.1：负例 expect 键集合严格 = {expect_error, error_contains}
			// （7 契约负例 + 4 链级红例同口径，igmp/bgp 先例）。
			if len(exp) != 2 || exp["error_contains"] == nil {
				t.Fatalf("%s: negative expect must be exactly {expect_error, error_contains}, got %v", id, exp)
			}
		} else {
			nPos++
			for k := range sj {
				if !allowedTop[k] {
					t.Fatalf("%s: non-negative top-level key %q (want ⊆ layers/group_id)", id, k)
				}
			}
			for _, k := range []string{"packet_count", "fields", "frames", "has_payload"} {
				if _, ok := exp[k]; !ok {
					t.Fatalf("%s: positive expect missing %q", id, k)
				}
			}
		}
		if _, hasPIM := sj["pim"]; hasPIM {
			if !neg {
				t.Fatalf("%s: top-level pim on non-negative case", id)
			}
			anchor, _ := exp["error_contains"].(string)
			if !strings.Contains(anchor, "top-level") {
				t.Fatalf("%s: top-level pim case anchor = %q, want \"top-level\"", id, anchor)
			}
			presence = true
		}
	}
	if nPos != 17 || nNeg != 11 {
		t.Fatalf("pos/neg = %d/%d, want 17 pos / 11 neg (7 契约 + 4 链级红例)", nPos, nNeg)
	}
	if !presence {
		t.Fatal("want 1 presence negative (layers + top-level pim), found none")
	}
}
