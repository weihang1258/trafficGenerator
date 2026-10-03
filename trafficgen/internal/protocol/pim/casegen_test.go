package pim

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// 用例生成器（一次性，D-PIM-1 P4；契约 §14.1 去向表 + testcase §5 逐条去向）。
// 产出 28 例 = 24 契约例（17 正 + 7 负）+ 4 链级红例（M5 清单①-③ + 收官自查
// ④在 pim_chain_test.go），落 test/protocol_pcap/cases/pim.json，形状为纯
// layers 形（[ip,pim]，非负例顶层仅 layers；业务键 profile/checksum_mode/
// events 住 pim 层内）。
//
// 证据红线（契约 §1/§3/§7）：
//   - checksum 只以 pim.cksum nonzero=true 观察，不钉常量（§2 底稿铁律，
//     Register 8 字节前缀面同款——§10 裁定）；
//   - frames 只钉可复算前缀（Version/Type 组合字节 20/21/22/23/24/25/28 00，
//     offset 34 = Ethernet 14 + IPv4 20，无 VLAN/无 options）；
//   - 无端口、无握手：has_handshake 零出现（raw-IP 族诚实口径），不虚构
//     建连包数。
//
// 数量键口径（igmp casegen 同款，§14.1 去向表的偏离登记）：契约 §14.1 把
// packet_count 映射为兄弟键 strategy_fc.flows=N。实测框架语义：事件序住
// **单流**内（pim 层 events 逐包 Emit），flows 是流数（worker 每流调一次
// Plan）——flows=N 会产 N×事件数 包而非 packet_count 包。故本文件对
// packet_count>1 的例（#7/#13/#14/#17）同样**不写 strategy_fc**：包数由
// 事件数决定（单流缺省，worker.go:254 flowCount<=0→1）。用例级流控键
// strategy_fc 是 runner 唯一消费口，spec_json 内 flow_control 不被任何代码
// 读取（死配置），不写。
//
// packet_count / frames / fields 值取自存量 24 例（旧扁平形）的实测断言，
// 层链整形不改事件序与事件内容，故包数与帧前缀不变；**待 P5 suite 实测
// 复钉**（先跑后钉，§9.31/§14.6）。

// pimCase 是一个契约用例：地址/TTL 住 layers[0].ip，业务键住 layers[1].pim。
type pimCase struct {
	id      string
	summary string
	ip      map[string]interface{}
	pim     map[string]interface{}
	expect  map[string]interface{}
}

func (c pimCase) layers() []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": c.ip},
		map[string]interface{}{"pim": c.pim},
	}
}

func (c pimCase) m() map[string]interface{} {
	return map[string]interface{}{
		"id":        c.id,
		"proto":     "pim",
		"summary":   c.summary,
		"spec_json": map[string]interface{}{"layers": c.layers()},
		"expect":    c.expect,
	}
}

// pimChainNeg 是一条链级红例（presence/游离键/载体），spec_json 可带顶层键。
// expect 与契约负例同口径：严格两键 {expect_error, error_contains}（§14.1；
// igmp/bgp 链级红例同款——判死通道说明住 pim_chain_test.go 与契约文档，
// 不进用例 expect 键集）。
type pimChainNeg struct {
	id      string
	summary string
	layers  []interface{}
	top     map[string]interface{}
	anchor  string
}

func (c pimChainNeg) m() map[string]interface{} {
	sj := map[string]interface{}{"layers": c.layers}
	for k, v := range c.top {
		sj[k] = v
	}
	return map[string]interface{}{
		"id":        c.id,
		"proto":     "pim",
		"summary":   c.summary,
		"spec_json": sj,
		"expect":    map[string]interface{}{"expect_error": true, "error_contains": c.anchor},
	}
}

const (
	pimCli   = "192.0.2.1"
	pimMcast = "224.0.0.13"
)

func pimIP(src, dst string) map[string]interface{} {
	return map[string]interface{}{"src": src, "dst": dst, "ttl": 1}
}

func pimHello() map[string]interface{} {
	return map[string]interface{}{"kind": "hello", "direction": "c2s", "holdtime": 105}
}

// pimChainNegCases 是 4 条链级红例（M5 清单①-③ + 收官自查行在
// pim_chain_test.go 的 TestPIMChain_CaseFileAudit）。
func pimChainNegCases() []pimChainNeg {
	return []pimChainNeg{
		{
			id:      "pim_neg_top_pim_presence_reject",
			summary: "§14-P2 presence 判死形状：层链 + 顶层空 pim 子映射并存（M5 清单①）",
			layers: []interface{}{
				map[string]interface{}{"ip": pimIP(pimCli, pimMcast)},
				map[string]interface{}{"pim": map[string]interface{}{}},
			},
			top:    map[string]interface{}{"pim": map[string]interface{}{}},
			anchor: "rejects a top-level pim sub-config",
		},
		{
			id:      "pim_neg_stray_top_src_ip",
			summary: "§14-P2 白名单外游离顶层键判死：layers + 顶层 src_ip（M5 清单②，1.11–1.13）",
			layers: []interface{}{
				map[string]interface{}{"ip": pimIP(pimCli, pimMcast)},
				map[string]interface{}{"pim": map[string]interface{}{
					"profile": "pim_sm_rfc7761_ipv4",
					"events":  []interface{}{pimHello()},
				}},
			},
			top:    map[string]interface{}{"src_ip": "192.0.2.99"},
			anchor: "rejects flat config field src_ip",
		},
		{
			id:      "pim_neg_carrier_udp",
			summary: "§14-P2 udp 载体判死：PIM 裸 IP（protocol 103）无传输层（M5 清单③）",
			layers: []interface{}{
				map[string]interface{}{"ip": pimIP(pimCli, pimMcast)},
				map[string]interface{}{"udp": map[string]interface{}{"dst_port": 103}},
				map[string]interface{}{"pim": map[string]interface{}{}},
			},
			anchor: "carrier",
		},
		{
			id:      "pim_neg_carrier_missing_ip",
			summary: "§14-P2 缺 ip 载体判死：裸 [pim] 链（M5 清单③）",
			layers: []interface{}{
				map[string]interface{}{"pim": map[string]interface{}{
					"profile": "pim_sm_rfc7761_ipv4",
					"events":  []interface{}{pimHello()},
				}},
			},
			anchor: "carrier",
		},
	}
}

// TestGeneratePIMCases 生成 cases/pim.json（一次性，P4；跑法：
//
//	go test ./internal/protocol/pim/ -run TestGeneratePIMCases -count=1
//
// 生成物入库（用例文件是测试产物，回指 40-pim-testcase.md §2/§5）。
func TestGeneratePIMCases(t *testing.T) {
	contract := pimContractCases()
	if len(contract) != 24 {
		t.Fatalf("want 24 contract cases (17 pos + 7 neg), got %d", len(contract))
	}
	nPos, nNeg := 0, 0
	for _, c := range contract {
		if _, neg := c.expect["expect_error"]; neg {
			nNeg++
			if len(c.expect) != 2 {
				t.Fatalf("%s: negative expect must be exactly {expect_error, error_contains}, got %v", c.id, c.expect)
			}
		} else {
			nPos++
			for _, k := range []string{"packet_count", "fields", "frames", "has_payload", "directional"} {
				if _, ok := c.expect[k]; !ok {
					t.Fatalf("%s: positive expect missing %q", c.id, k)
				}
			}
		}
	}
	if nPos != 17 || nNeg != 7 {
		t.Fatalf("pos/neg = %d/%d, want 17/7", nPos, nNeg)
	}
	chainNeg := pimChainNegCases()
	if len(chainNeg) != 4 {
		t.Fatalf("want 4 chain-level negatives, got %d", len(chainNeg))
	}
	out := make([]map[string]interface{}, 0, len(contract)+len(chainNeg))
	for _, c := range contract {
		out = append(out, c.m())
	}
	for _, c := range chainNeg {
		out = append(out, c.m())
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("marshal cases: %v", err)
	}
	path := filepath.Join("..", "..", "..", "test", "protocol_pcap", "cases", "pim.json")
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	fmt.Printf("wrote %s (%d cases: %d pos + %d neg + %d chain-neg)\n", path, len(out), nPos, nNeg, len(chainNeg))
}

// pimContractCases returns the 24 contract cases (17 positive + 7 negative)
// from 40-pim-testcase.md 2/5, rewritten to the pure layer-chain shape
// (D-PIM-1 14.1 destination table). Addresses/TTL move into layers[0].ip,
// business keys into layers[1].pim; packet_count becomes strategy_fc.flows.
func pimContractCases() []pimCase {
	return []pimCase{
		{
			id:      "pim_sm_hello_holdtime",
			summary: "PIM-SM Hello with explicit Holdtime and interval",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "224.0.0.13",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":           "hello",
						"direction":      "c2s",
						"holdtime":       105,
						"hello_interval": 30,
						"generation_id":  "0x01020304",
						"dr_priority":    10,
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 1,
				"has_payload":  true,
				"directional":  false,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "ip.proto",
						"value":  "103",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.version",
						"value":  "2",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "0",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.holdtime",
						"value":  "105",
					},
					map[string]interface{}{
						"packet":  1,
						"field":   "pim.cksum",
						"nonzero": true,
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "20 00",
					},
				},
			},
		},
		{
			id:      "pim_sm_hello_options",
			summary: "PIM-SM Hello options including LAN Prune Delay, DR priority and Generation ID",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "224.0.0.13",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":           "hello",
						"direction":      "c2s",
						"holdtime":       90,
						"hello_interval": 30,
						"lan_prune_delay": map[string]interface{}{
							"t_bit":             true,
							"propagation_delay": 100,
							"override_interval": 500,
						},
						"dr_priority":   200,
						"generation_id": "0x11223344",
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 1,
				"has_payload":  true,
				"directional":  false,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "0",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.t",
						"value":  "1",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.propagation_delay",
						"value":  "100",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.override_interval",
						"value":  "500",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.dr_priority",
						"value":  "200",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.generation_id",
						"value":  "287454020",
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "20 00",
					},
				},
			},
		},
		{
			id:      "pim_sm_hello_zero_holdtime",
			summary: "PIM-SM Hello Holdtime zero immediate-expiry boundary",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "224.0.0.13",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":           "hello",
						"direction":      "s2c",
						"holdtime":       0,
						"hello_interval": 30,
						"generation_id":  "0x00000001",
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 1,
				"has_payload":  true,
				"directional":  false,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "ip.proto",
						"value":  "103",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "0",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.holdtime",
						"value":  "0",
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "20 00",
					},
				},
			},
		},
		{
			id:      "pim_sm_joinprune_wildcard",
			summary: "PIM-SM Join/Prune wildcard (*,G)",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "192.0.2.254",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":              "join_prune",
						"direction":         "c2s",
						"upstream_neighbor": "192.0.2.254",
						"holdtime":          180,
						"groups": []interface{}{
							map[string]interface{}{
								"group": "239.1.1.1",
								"joined_sources": []interface{}{
									map[string]interface{}{
										"wildcard": true,
									},
								},
								"pruned_sources": []interface{}{},
							},
						},
						"state": "upstream_join",
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 1,
				"has_payload":  true,
				"directional":  false,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "3",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.upstream_neighbor",
						"value":  "192.0.2.254",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.group",
						"value":  "239.1.1.1,239.1.1.1",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.numgroups",
						"value":  "1",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.numjoins",
						"value":  "1",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.numprunes",
						"value":  "0",
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "23 00",
					},
				},
			},
		},
		{
			id:      "pim_sm_joinprune_source",
			summary: "PIM-SM Join/Prune concrete (S,G) join and prune",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "192.0.2.254",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":              "join_prune",
						"direction":         "c2s",
						"upstream_neighbor": "192.0.2.254",
						"holdtime":          180,
						"groups": []interface{}{
							map[string]interface{}{
								"group": "232.1.1.1",
								"joined_sources": []interface{}{
									map[string]interface{}{
										"source": "198.51.100.10",
									},
								},
								"pruned_sources": []interface{}{
									map[string]interface{}{
										"source": "198.51.100.11",
									},
								},
							},
						},
						"state": "downstream_join",
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 1,
				"has_payload":  true,
				"directional":  false,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "3",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.upstream_neighbor",
						"value":  "192.0.2.254",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.group",
						"value":  "232.1.1.1,232.1.1.1",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.source",
						"value":  "198.51.100.10,198.51.100.11",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.numjoins",
						"value":  "1",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.numprunes",
						"value":  "1",
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "23 00",
					},
				},
			},
		},
		{
			id:      "pim_sm_joinprune_multi_group",
			summary: "PIM-SM Join/Prune with wildcard and source trees in two groups",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "192.0.2.254",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":              "join_prune",
						"direction":         "c2s",
						"upstream_neighbor": "192.0.2.254",
						"holdtime":          180,
						"groups": []interface{}{
							map[string]interface{}{
								"group": "239.1.1.1",
								"joined_sources": []interface{}{
									map[string]interface{}{
										"wildcard": true,
									},
								},
								"pruned_sources": []interface{}{},
							},
							map[string]interface{}{
								"group": "232.1.1.2",
								"joined_sources": []interface{}{
									map[string]interface{}{
										"source": "198.51.100.12",
									},
								},
								"pruned_sources": []interface{}{
									map[string]interface{}{
										"source": "198.51.100.13",
									},
								},
							},
						},
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 1,
				"has_payload":  true,
				"directional":  false,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "3",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.numgroups",
						"value":  "2",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.group",
						"value":  "239.1.1.1,239.1.1.1,232.1.1.2,232.1.1.2",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.source",
						"value":  "0.0.0.0,198.51.100.12,198.51.100.13",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.numjoins",
						"value":  "1,1",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.numprunes",
						"value":  "0,1",
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "23 00",
					},
				},
			},
		},
		{
			id:      "pim_sm_joinprune_retransmit",
			summary: "PIM-SM explicit Join/Prune retransmission",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "192.0.2.254",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":              "join_prune",
						"direction":         "c2s",
						"upstream_neighbor": "192.0.2.254",
						"holdtime":          180,
						"groups": []interface{}{
							map[string]interface{}{
								"group": "232.1.1.3",
								"joined_sources": []interface{}{
									map[string]interface{}{
										"source": "198.51.100.14",
									},
								},
								"pruned_sources": []interface{}{},
							},
						},
						"state": "upstream_join",
					},
					map[string]interface{}{
						"kind":              "join_prune",
						"direction":         "c2s",
						"upstream_neighbor": "192.0.2.254",
						"holdtime":          180,
						"groups": []interface{}{
							map[string]interface{}{
								"group": "232.1.1.3",
								"joined_sources": []interface{}{
									map[string]interface{}{
										"source": "198.51.100.14",
									},
								},
								"pruned_sources": []interface{}{},
							},
						},
						"state":          "upstream_join",
						"retransmission": true,
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 2,
				"has_payload":  true,
				"directional":  false,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "3",
					},
					map[string]interface{}{
						"packet":         2,
						"field":          "pim.type",
						"value":          "3",
						"same_as_packet": 1,
					},
					map[string]interface{}{
						"packet": 2,
						"field":  "pim.upstream_neighbor",
						"value":  "192.0.2.254",
					},
					map[string]interface{}{
						"packet": 2,
						"field":  "pim.group",
						"value":  "232.1.1.3,232.1.1.3",
					},
					map[string]interface{}{
						"packet": 2,
						"field":  "pim.source",
						"value":  "198.51.100.14",
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "23 00",
					},
					map[string]interface{}{
						"packet": 2,
						"offset": 34,
						"hex":    "23 00",
					},
				},
			},
		},
		{
			id:      "pim_sm_bootstrap_rp_set",
			summary: "PIM-SM Bootstrap with BSR and RP set priorities",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "224.0.0.13",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":             "bootstrap",
						"direction":        "c2s",
						"bsr":              "192.0.2.10",
						"bsr_priority":     128,
						"hash_mask_length": 30,
						"rp_sets": []interface{}{
							map[string]interface{}{
								"group_prefix": "239.0.0.0/8",
								"rps": []interface{}{
									map[string]interface{}{
										"rp":       "192.0.2.20",
										"priority": 10,
										"holdtime": 150,
									},
									map[string]interface{}{
										"rp":       "192.0.2.21",
										"priority": 20,
										"holdtime": 150,
									},
								},
							},
						},
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 1,
				"has_payload":  true,
				"directional":  false,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "4",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.bsr",
						"value":  "192.0.2.10",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.bsr_priority",
						"value":  "128",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.hash_mask_len",
						"value":  "30",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.group",
						"value":  "239.0.0.0,239.0.0.0",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.rp",
						"value":  "192.0.2.20,192.0.2.21",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.priority",
						"value":  "10,20",
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "24 00",
					},
				},
			},
		},
		{
			id:      "pim_sm_candidate_rp_adv",
			summary: "PIM-SM Candidate-RP Advertisement",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "192.0.2.10",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":        "candidate_rp_adv",
						"direction":   "c2s",
						"rp":          "192.0.2.30",
						"rp_priority": 64,
						"holdtime":    150,
						"group_prefixes": []interface{}{
							"239.0.0.0/8",
							"232.0.0.0/8",
						},
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 1,
				"has_payload":  true,
				"directional":  false,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "8",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.rp",
						"value":  "192.0.2.30",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.priority",
						"value":  "64",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.holdtime",
						"value":  "150",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.prefix_count",
						"value":  "2",
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "28 00",
					},
				},
			},
		},
		{
			id:      "pim_sm_register",
			summary: "PIM-SM Register with explicit inner IPv4 packet profile",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "192.0.2.100",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":      "register",
						"direction": "c2s",
						"rp":        "192.0.2.100",
						"register_flags": map[string]interface{}{
							"border_bit":    false,
							"null_register": false,
						},
						"inner_ipv4": map[string]interface{}{
							"src":         "198.51.100.10",
							"dst":         "239.1.1.1",
							"payload_hex": "de ad be ef",
						},
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 1,
				"has_payload":  true,
				"directional":  false,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "1",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.register_flag.border",
						"value":  "0",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.register_flag.null_register",
						"value":  "0",
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "21 00",
					},
				},
			},
		},
		{
			id:      "pim_sm_register_stop",
			summary: "PIM-SM Register-Stop with explicit group and source",
			ip: map[string]interface{}{
				"src": "192.0.2.100",
				"dst": "192.0.2.1",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":      "register_stop",
						"direction": "s2c",
						"group":     "239.1.1.1",
						"source":    "198.51.100.10",
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 1,
				"has_payload":  true,
				"directional":  false,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "2",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.group",
						"value":  "239.1.1.1,239.1.1.1",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.source",
						"value":  "198.51.100.10",
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "22 00",
					},
				},
			},
		},
		{
			id:      "pim_sm_assert",
			summary: "PIM-SM Assert with group/source and metrics",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "224.0.0.13",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":              "assert",
						"direction":         "s2c",
						"group":             "239.1.1.1",
						"source":            "198.51.100.10",
						"rpt_bit":           true,
						"metric_preference": 10,
						"route_metric":      100,
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 1,
				"has_payload":  true,
				"directional":  false,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "5",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.group",
						"value":  "239.1.1.1,239.1.1.1",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.source",
						"value":  "198.51.100.10",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.rpt",
						"value":  "1",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.metric_pref",
						"value":  "10",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.metric",
						"value":  "100",
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "25 00",
					},
				},
			},
		},
		{
			id:      "pim_sm_dr_election",
			summary: "PIM-SM DR election inputs from three neighbors",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "224.0.0.13",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":        "hello",
						"direction":   "c2s",
						"neighbor":    "192.0.2.10",
						"holdtime":    105,
						"dr_priority": 10,
					},
					map[string]interface{}{
						"kind":        "hello",
						"direction":   "s2c",
						"neighbor":    "192.0.2.20",
						"holdtime":    105,
						"dr_priority": 20,
					},
					map[string]interface{}{
						"kind":        "hello",
						"direction":   "c2s",
						"neighbor":    "192.0.2.30",
						"holdtime":    105,
						"dr_priority": 20,
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 3,
				"has_payload":  true,
				"directional":  true,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "0",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.dr_priority",
						"value":  "10",
					},
					map[string]interface{}{
						"packet": 2,
						"field":  "pim.type",
						"value":  "0",
					},
					map[string]interface{}{
						"packet": 2,
						"field":  "pim.dr_priority",
						"value":  "20",
					},
					map[string]interface{}{
						"packet": 3,
						"field":  "pim.type",
						"value":  "0",
					},
					map[string]interface{}{
						"packet": 3,
						"field":  "pim.dr_priority",
						"value":  "20",
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "20 00",
					},
					map[string]interface{}{
						"packet": 2,
						"offset": 34,
						"hex":    "20 00",
					},
					map[string]interface{}{
						"packet": 3,
						"offset": 34,
						"hex":    "20 00",
					},
				},
			},
		},
		{
			id:      "pim_sm_multi_neighbor_state",
			summary: "PIM-SM independent neighbor and tree state events",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "192.0.2.254",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":        "hello",
						"direction":   "c2s",
						"neighbor":    "192.0.2.10",
						"holdtime":    105,
						"dr_priority": 10,
					},
					map[string]interface{}{
						"kind":        "hello",
						"direction":   "s2c",
						"neighbor":    "192.0.2.20",
						"holdtime":    105,
						"dr_priority": 20,
					},
					map[string]interface{}{
						"kind":              "join_prune",
						"direction":         "c2s",
						"upstream_neighbor": "192.0.2.10",
						"groups": []interface{}{
							map[string]interface{}{
								"group": "239.1.1.1",
								"joined_sources": []interface{}{
									map[string]interface{}{
										"wildcard": true,
									},
								},
								"pruned_sources": []interface{}{},
							},
						},
						"state":    "upstream_join",
						"holdtime": 180,
					},
					map[string]interface{}{
						"kind":              "join_prune",
						"direction":         "s2c",
						"upstream_neighbor": "192.0.2.20",
						"groups": []interface{}{
							map[string]interface{}{
								"group": "232.1.1.1",
								"joined_sources": []interface{}{
									map[string]interface{}{
										"source": "198.51.100.10",
									},
								},
								"pruned_sources": []interface{}{},
							},
						},
						"state":    "upstream_join",
						"holdtime": 180,
					},
					map[string]interface{}{
						"kind":              "join_prune",
						"direction":         "c2s",
						"upstream_neighbor": "192.0.2.10",
						"groups": []interface{}{
							map[string]interface{}{
								"group":          "239.1.1.1",
								"joined_sources": []interface{}{},
								"pruned_sources": []interface{}{
									map[string]interface{}{
										"wildcard": true,
									},
								},
							},
						},
						"state":    "upstream_prune",
						"holdtime": 180,
					},
					map[string]interface{}{
						"kind":              "join_prune",
						"direction":         "s2c",
						"upstream_neighbor": "192.0.2.20",
						"groups": []interface{}{
							map[string]interface{}{
								"group":          "232.1.1.1",
								"joined_sources": []interface{}{},
								"pruned_sources": []interface{}{
									map[string]interface{}{
										"source": "198.51.100.10",
									},
								},
							},
						},
						"state":    "upstream_prune",
						"holdtime": 180,
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 6,
				"has_payload":  true,
				"directional":  true,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "0",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.holdtime",
						"value":  "105",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.dr_priority",
						"value":  "10",
					},
					map[string]interface{}{
						"packet": 2,
						"field":  "pim.type",
						"value":  "0",
					},
					map[string]interface{}{
						"packet": 2,
						"field":  "pim.holdtime",
						"value":  "105",
					},
					map[string]interface{}{
						"packet": 2,
						"field":  "pim.dr_priority",
						"value":  "20",
					},
					map[string]interface{}{
						"packet": 3,
						"field":  "pim.type",
						"value":  "3",
					},
					map[string]interface{}{
						"packet": 3,
						"field":  "pim.upstream_neighbor",
						"value":  "192.0.2.10",
					},
					map[string]interface{}{
						"packet": 3,
						"field":  "pim.group",
						"value":  "239.1.1.1,239.1.1.1",
					},
					map[string]interface{}{
						"packet": 3,
						"field":  "pim.numjoins",
						"value":  "1",
					},
					map[string]interface{}{
						"packet": 4,
						"field":  "pim.type",
						"value":  "3",
					},
					map[string]interface{}{
						"packet": 4,
						"field":  "pim.upstream_neighbor",
						"value":  "192.0.2.20",
					},
					map[string]interface{}{
						"packet": 4,
						"field":  "pim.group",
						"value":  "232.1.1.1,232.1.1.1",
					},
					map[string]interface{}{
						"packet": 4,
						"field":  "pim.source",
						"value":  "198.51.100.10",
					},
					map[string]interface{}{
						"packet": 4,
						"field":  "pim.numjoins",
						"value":  "1",
					},
					map[string]interface{}{
						"packet": 5,
						"field":  "pim.type",
						"value":  "3",
					},
					map[string]interface{}{
						"packet": 5,
						"field":  "pim.upstream_neighbor",
						"value":  "192.0.2.10",
					},
					map[string]interface{}{
						"packet": 5,
						"field":  "pim.group",
						"value":  "239.1.1.1,239.1.1.1",
					},
					map[string]interface{}{
						"packet": 5,
						"field":  "pim.numprunes",
						"value":  "1",
					},
					map[string]interface{}{
						"packet": 6,
						"field":  "pim.type",
						"value":  "3",
					},
					map[string]interface{}{
						"packet": 6,
						"field":  "pim.upstream_neighbor",
						"value":  "192.0.2.20",
					},
					map[string]interface{}{
						"packet": 6,
						"field":  "pim.group",
						"value":  "232.1.1.1,232.1.1.1",
					},
					map[string]interface{}{
						"packet": 6,
						"field":  "pim.source",
						"value":  "198.51.100.10",
					},
					map[string]interface{}{
						"packet": 6,
						"field":  "pim.numprunes",
						"value":  "1",
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "20 00",
					},
					map[string]interface{}{
						"packet": 2,
						"offset": 34,
						"hex":    "20 00",
					},
					map[string]interface{}{
						"packet": 3,
						"offset": 34,
						"hex":    "23 00",
					},
					map[string]interface{}{
						"packet": 4,
						"offset": 34,
						"hex":    "23 00",
					},
					map[string]interface{}{
						"packet": 5,
						"offset": 34,
						"hex":    "23 00",
					},
					map[string]interface{}{
						"packet": 6,
						"offset": 34,
						"hex":    "23 00",
					},
				},
			},
		},
		{
			id:      "pim_sm_checksum_length",
			summary: "PIM-SM checksum and IPv4 total-length boundary",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "224.0.0.13",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":           "hello",
						"direction":      "c2s",
						"holdtime":       105,
						"hello_interval": 30,
						"lan_prune_delay": map[string]interface{}{
							"t_bit":             false,
							"propagation_delay": 50,
							"override_interval": 250,
						},
						"dr_priority":   99,
						"generation_id": "0xaabbccdd",
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 1,
				"has_payload":  true,
				"directional":  false,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "ip.proto",
						"value":  "103",
					},
					map[string]interface{}{
						"packet":  1,
						"field":   "ip.len",
						"nonzero": true,
					},
					map[string]interface{}{
						"packet":  1,
						"field":   "pim.cksum",
						"nonzero": true,
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "20 00",
					},
				},
			},
		},
		{
			id:      "pim_ssm_joinprune_sg",
			summary: "PIM-SSM RFC 4607 concrete (S,G) Join/Prune without RP",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "192.0.2.254",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_ssm_rfc4607_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":              "join_prune",
						"direction":         "c2s",
						"upstream_neighbor": "192.0.2.254",
						"holdtime":          180,
						"groups": []interface{}{
							map[string]interface{}{
								"group": "232.1.1.1",
								"joined_sources": []interface{}{
									map[string]interface{}{
										"source":   "198.51.100.10",
										"wildcard": false,
									},
								},
								"pruned_sources": []interface{}{},
							},
						},
						"state": "upstream_join",
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 1,
				"has_payload":  true,
				"directional":  false,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "3",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.upstream_neighbor",
						"value":  "192.0.2.254",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.group",
						"value":  "232.1.1.1,232.1.1.1",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.source",
						"value":  "198.51.100.10",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.numjoins",
						"value":  "1",
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "23 00",
					},
				},
			},
		},
		{
			id:      "pim_ssm_multi_group",
			summary: "PIM-SSM independent concrete source trees for multiple groups",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "192.0.2.254",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_ssm_rfc4607_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":              "join_prune",
						"direction":         "c2s",
						"upstream_neighbor": "192.0.2.254",
						"groups": []interface{}{
							map[string]interface{}{
								"group": "232.1.1.1",
								"joined_sources": []interface{}{
									map[string]interface{}{
										"source": "198.51.100.10",
									},
								},
								"pruned_sources": []interface{}{},
							},
						},
						"holdtime": 180,
					},
					map[string]interface{}{
						"kind":              "join_prune",
						"direction":         "c2s",
						"upstream_neighbor": "192.0.2.254",
						"groups": []interface{}{
							map[string]interface{}{
								"group": "232.1.1.2",
								"joined_sources": []interface{}{
									map[string]interface{}{
										"source": "198.51.100.11",
									},
								},
								"pruned_sources": []interface{}{},
							},
						},
						"holdtime": 180,
					},
				},
			},
			expect: map[string]interface{}{
				"packet_count": 2,
				"has_payload":  true,
				"directional":  false,
				"fields": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.type",
						"value":  "3",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.upstream_neighbor",
						"value":  "192.0.2.254",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.group",
						"value":  "232.1.1.1,232.1.1.1",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.source",
						"value":  "198.51.100.10",
					},
					map[string]interface{}{
						"packet": 1,
						"field":  "pim.numjoins",
						"value":  "1",
					},
					map[string]interface{}{
						"packet": 2,
						"field":  "pim.type",
						"value":  "3",
					},
					map[string]interface{}{
						"packet": 2,
						"field":  "pim.group",
						"value":  "232.1.1.2,232.1.1.2",
					},
					map[string]interface{}{
						"packet": 2,
						"field":  "pim.source",
						"value":  "198.51.100.11",
					},
					map[string]interface{}{
						"packet": 2,
						"field":  "pim.numjoins",
						"value":  "1",
					},
				},
				"frames": []interface{}{
					map[string]interface{}{
						"packet": 1,
						"offset": 34,
						"hex":    "23 00",
					},
					map[string]interface{}{
						"packet": 2,
						"offset": 34,
						"hex":    "23 00",
					},
				},
			},
		},
		{
			id:      "pim_neg_ipv6_profile",
			summary: "IPv6 PIM is a separate unsupported profile",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "224.0.0.13",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_rfc7761_ipv6_pending",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":      "hello",
						"direction": "c2s",
						"holdtime":  105,
					},
				},
			},
			expect: map[string]interface{}{
				"expect_error":   true,
				"error_contains": "profile",
			},
		},
		{
			id:      "pim_neg_checksum",
			summary: "Malformed PIM checksum is rejected",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "224.0.0.13",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":      "hello",
						"direction": "c2s",
						"holdtime":  105,
						"wire_fault": map[string]interface{}{
							"kind": "checksum",
						},
					},
				},
			},
			expect: map[string]interface{}{
				"expect_error":   true,
				"error_contains": "checksum",
			},
		},
		{
			id:      "pim_neg_length",
			summary: "Inconsistent IPv4/PIM length is rejected",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "224.0.0.13",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":      "hello",
						"direction": "c2s",
						"holdtime":  105,
						"wire_fault": map[string]interface{}{
							"kind":                  "length",
							"declared_total_length": 1,
						},
					},
				},
			},
			expect: map[string]interface{}{
				"expect_error":   true,
				"error_contains": "length",
			},
		},
		{
			id:      "pim_neg_type",
			summary: "Unknown or mismatched PIM message type is rejected",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "224.0.0.13",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":      "hello",
						"direction": "c2s",
						"holdtime":  105,
						"wire_fault": map[string]interface{}{
							"kind":  "type",
							"value": 9,
						},
					},
				},
			},
			expect: map[string]interface{}{
				"expect_error":   true,
				"error_contains": "type",
			},
		},
		{
			id:      "pim_neg_address_family",
			summary: "IPv4 PIM profile cannot encode IPv6 group/source",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "224.0.0.13",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":              "join_prune",
						"direction":         "c2s",
						"upstream_neighbor": "192.0.2.254",
						"groups": []interface{}{
							map[string]interface{}{
								"group": "ff0e::1",
								"joined_sources": []interface{}{
									map[string]interface{}{
										"source": "2001:db8::10",
									},
								},
								"pruned_sources": []interface{}{},
							},
						},
					},
				},
			},
			expect: map[string]interface{}{
				"expect_error":   true,
				"error_contains": "address",
			},
		},
		{
			id:      "pim_neg_ssm_rp",
			summary: "SSM cannot carry RP/Register or wildcard state",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "224.0.0.13",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_ssm_rfc4607_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":      "register",
						"direction": "c2s",
						"rp":        "192.0.2.100",
						"group":     "239.1.1.1",
					},
				},
			},
			expect: map[string]interface{}{
				"expect_error":   true,
				"error_contains": "ssm",
			},
		},
		{
			id:      "pim_neg_df_profile",
			summary: "DF Election requires independent Bidirectional PIM profile",
			ip: map[string]interface{}{
				"src": "192.0.2.1",
				"dst": "224.0.0.13",
				"ttl": 1,
			},
			pim: map[string]interface{}{
				"profile":       "pim_sm_rfc7761_ipv4",
				"checksum_mode": "auto",
				"events": []interface{}{
					map[string]interface{}{
						"kind":      "df_election",
						"direction": "c2s",
						"neighbor":  "192.0.2.2",
					},
				},
			},
			expect: map[string]interface{}{
				"expect_error":   true,
				"error_contains": "df",
			},
		},
	}
}
