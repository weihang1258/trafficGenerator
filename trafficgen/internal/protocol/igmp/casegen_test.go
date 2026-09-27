package igmp

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 用例生成器（一次性，D-IGMP-1 P4；契约 §14.1 去向表 + testcase §5 逐条去向）。
// 产出 25 例（17 正 + 8 负），落 test/protocol_pcap/cases/igmp.json，形状为
// 纯 layers 形（[ip,igmp]，顶层仅 layers；事件例 events 住 igmp 层内）。
//
// 证据红线（契约 §1/§3/§7）：
//   - checksum 只以 igmp.checksum nonzero=true 观察，不钉常量（§7 底稿铁律）；
//   - frames 只钉可复算前缀（Type/MRT、group、S/R/QRV+QQIC+N、source list、
//     record 头），逐字节由本文件的 ip4hex/recordHex 计算，不手打；
//   - 无端口、无握手：has_handshake 零出现（0/25），不虚构建连包数。
//
// 偏离登记（本文件即权威，随 P5 先跑后钉校准）：契约 §14.1 去向表把
// `count` 映射为 `flow_control.flows=packet_count`（#13/#14/#15 写 3/3/4）。
// 实测框架语义：事件序住**单流**内（igmp 层 events 逐包 Emit），flows 是
// 流数（worker 每流调一次 Plan）——flows=3 会产 3×3=9 包而非 3 包。故
// 单流缺省（不写 strategy_fc），#13/#14/#15 由事件数决定包数。用例级流控
// 键 `strategy_fc` 是 runner 唯一消费口（nfs/enip/tftp/smb 先例），
// spec_json 内 flow_control 不被任何代码读取（死配置），不写。

const (
	iSrc     = "192.0.2.10"
	iGroup1  = "239.1.1.1"
	iGroup2  = "239.1.1.2"
	iGroup3  = "239.1.1.3"
	iGroup4  = "239.1.1.4"
	iGroup9  = "239.1.1.9"
	iSrcIP1  = "198.51.100.1"
	iSrcIP2  = "198.51.100.2"
	iSrcIP3  = "198.51.100.3"
	iSrcIP4  = "198.51.100.4"
	iSrcIP5  = "198.51.100.5"
	iSrcIP6  = "198.51.100.6"
	igmpType = 34 // IGMP 起点：Ethernet 14 + IPv4 20（无 VLAN/无 options）
)

// ip4hex renders one IPv4 address as the frame hex byte string
// ("ef 01 01 01"). Computed, never hand-typed.
func ip4hex(addr string) string {
	ip := net.ParseIP(addr).To4()
	if ip == nil {
		panic("bad ipv4 " + addr)
	}
	parts := make([]string, 4)
	for i, b := range ip {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, " ")
}

// typeHex renders the IGMP type + MaxResp/MRC byte pair (offset 34).
func typeHex(typ, code byte) string { return fmt.Sprintf("%02x %02x", typ, code) }

// v3QueryBodyHex renders offset 42's four bytes: Resv/S/QRV, QQIC, N(2).
func v3QueryBodyHex(sFlag, qrv, qqic byte, n int) string {
	return fmt.Sprintf("%02x %02x %02x %02x", sFlag<<3|qrv&0x7, qqic, byte(n>>8), byte(n))
}

// recordHex renders one v3 Group Record header (type, auxlen=0, N, group).
func recordHex(recType byte, group string, nSources int) string {
	return fmt.Sprintf("%02x 00 %02x %02x %s", recType, byte(nSources>>8), byte(nSources), ip4hex(group))
}

// srcListHex renders a source list at its own offset.
func srcListHex(addrs ...string) string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = ip4hex(a)
	}
	return strings.Join(out, " ")
}

func field(packet int, name, value string) map[string]interface{} {
	return map[string]interface{}{"packet": packet, "field": name, "value": value}
}

func fieldNZ(packet int, name string) map[string]interface{} {
	return map[string]interface{}{"packet": packet, "field": name, "nonzero": true}
}

func fieldSame(packet int, name string, same int) map[string]interface{} {
	return map[string]interface{}{"packet": packet, "field": name, "same_as_packet": same}
}

func frame(packet, offset int, hex string) map[string]interface{} {
	return map[string]interface{}{"packet": packet, "offset": offset, "hex": hex}
}

// carrier asserts the IPv4 invariants shared by every IGMP packet (契约 §3).
func carrier(packet int, dst string) []map[string]interface{} {
	return []map[string]interface{}{
		field(packet, "ip.proto", "2"),
		field(packet, "ip.ttl", "1"),
		field(packet, "ip.dst", dst),
	}
}

type igmpCase struct {
	id      string
	summary string
	ip      map[string]interface{} // layers[0].ip（事件例无 dst）
	cfg     map[string]interface{} // layers[1].igmp 单报文配置
	events  []interface{}          // 事件例：layers[1].igmp.events
	expect  map[string]interface{}
}

func (c igmpCase) layers() []interface{} {
	ig := map[string]interface{}{}
	for k, v := range c.cfg {
		ig[k] = v
	}
	if c.events != nil {
		ig["events"] = c.events
	}
	return []interface{}{
		map[string]interface{}{"ip": c.ip},
		map[string]interface{}{"igmp": ig},
	}
}

func (c igmpCase) m() map[string]interface{} {
	return map[string]interface{}{
		"id":        c.id,
		"proto":     "igmp",
		"summary":   c.summary,
		"spec_json": map[string]interface{}{"layers": c.layers()},
		"expect":    c.expect,
	}
}

func posExpect(packets int, fields, frames []map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"packet_count": packets,
		"has_payload":  true,
		"directional":  false,
		"fields":       fields,
		"frames":       frames,
	}
}

func negExpect(anchor string) map[string]interface{} {
	return map[string]interface{}{"expect_error": true, "error_contains": anchor}
}

func igmpCases() []igmpCase {
	out := []igmpCase{
		{
			id: "igmp_v1_general_query", summary: "v1 General Query",
			ip: map[string]interface{}{"src": iSrc, "dst": "224.0.0.1", "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v1", "kind": "query", "group": "0.0.0.0", "max_response_time": 0,
			},
			expect: posExpect(1,
				append(carrier(1, "224.0.0.1"),
					field(1, "igmp.type", "0x11"), fieldNZ(1, "igmp.checksum"),
					field(1, "igmp.maddr", "0.0.0.0")),
				[]map[string]interface{}{
					frame(1, igmpType, typeHex(0x11, 0)),
					frame(1, igmpType+4, ip4hex("0.0.0.0")),
				}),
		},
		{
			id: "igmp_v1_report", summary: "v1 Membership Report",
			ip: map[string]interface{}{"src": iSrc, "dst": iGroup1, "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v1", "kind": "report", "group": iGroup1,
			},
			expect: posExpect(1,
				append(carrier(1, iGroup1),
					field(1, "igmp.type", "0x12"), fieldNZ(1, "igmp.checksum"),
					field(1, "igmp.maddr", iGroup1)),
				[]map[string]interface{}{
					frame(1, igmpType, typeHex(0x12, 0)),
					frame(1, igmpType+4, ip4hex(iGroup1)),
				}),
		},
		{
			id: "igmp_v2_general_query", summary: "v2 General Query",
			ip: map[string]interface{}{"src": iSrc, "dst": "224.0.0.1", "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v2", "kind": "query", "group": "0.0.0.0", "max_response_time": 10,
			},
			expect: posExpect(1,
				append(carrier(1, "224.0.0.1"),
					field(1, "igmp.type", "0x11"), fieldNZ(1, "igmp.checksum"),
					field(1, "igmp.max_resp", "10"), field(1, "igmp.maddr", "0.0.0.0")),
				[]map[string]interface{}{
					frame(1, igmpType, typeHex(0x11, 10)),
					frame(1, igmpType+4, ip4hex("0.0.0.0")),
				}),
		},
		{
			id: "igmp_v2_group_specific_query", summary: "v2 Group-Specific Query",
			ip: map[string]interface{}{"src": iSrc, "dst": iGroup1, "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v2", "kind": "query", "group": iGroup1, "max_response_time": 10,
			},
			expect: posExpect(1,
				append(carrier(1, iGroup1),
					field(1, "igmp.type", "0x11"), fieldNZ(1, "igmp.checksum"),
					field(1, "igmp.max_resp", "10"), field(1, "igmp.maddr", iGroup1)),
				[]map[string]interface{}{
					frame(1, igmpType, typeHex(0x11, 10)),
					frame(1, igmpType+4, ip4hex(iGroup1)),
				}),
		},
		{
			id: "igmp_v2_report", summary: "v2 Membership Report",
			ip: map[string]interface{}{"src": iSrc, "dst": iGroup1, "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v2", "kind": "report", "group": iGroup1,
			},
			expect: posExpect(1,
				append(carrier(1, iGroup1),
					field(1, "igmp.type", "0x16"), fieldNZ(1, "igmp.checksum"),
					field(1, "igmp.maddr", iGroup1)),
				[]map[string]interface{}{
					frame(1, igmpType, typeHex(0x16, 0)),
					frame(1, igmpType+4, ip4hex(iGroup1)),
				}),
		},
		{
			id: "igmp_v2_leave", summary: "v2 Leave Group (224.0.0.2)",
			ip: map[string]interface{}{"src": iSrc, "dst": "224.0.0.2", "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v2", "kind": "leave", "group": iGroup1,
			},
			expect: posExpect(1,
				append(carrier(1, "224.0.0.2"),
					field(1, "igmp.type", "0x17"), fieldNZ(1, "igmp.checksum"),
					field(1, "igmp.maddr", iGroup1)),
				[]map[string]interface{}{
					frame(1, igmpType, typeHex(0x17, 0)),
					frame(1, igmpType+4, ip4hex(iGroup1)),
				}),
		},
		{
			id: "igmp_v3_general_query", summary: "v3 General Query (MRC/QRV/QQIC)",
			ip: map[string]interface{}{"src": iSrc, "dst": "224.0.0.1", "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v3", "kind": "query", "group": "0.0.0.0",
				"max_response_code": 10, "s_flag": 0, "qrv": 2, "qqic": 125,
				"sources": []interface{}{},
			},
			expect: posExpect(1,
				append(carrier(1, "224.0.0.1"),
					field(1, "igmp.type", "0x11"), fieldNZ(1, "igmp.checksum"),
					field(1, "igmp.max_resp", "10"), field(1, "igmp.qrv", "2"),
					field(1, "igmp.qqic", "125"), field(1, "igmp.num_src", "0"),
					field(1, "igmp.maddr", "0.0.0.0")),
				[]map[string]interface{}{
					frame(1, igmpType+8, v3QueryBodyHex(0, 2, 125, 0)),
				}),
		},
		{
			id: "igmp_v3_source_specific_query", summary: "v3 Source-Specific Query (S/QRV, 2 sources)",
			ip: map[string]interface{}{"src": iSrc, "dst": iGroup1, "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v3", "kind": "query", "group": iGroup1,
				"max_response_code": 10, "s_flag": 0, "qrv": 2, "qqic": 125,
				"sources": []interface{}{iSrcIP1, iSrcIP2},
			},
			expect: posExpect(1,
				append(carrier(1, iGroup1),
					field(1, "igmp.type", "0x11"), fieldNZ(1, "igmp.checksum"),
					field(1, "igmp.num_src", "2"),
					field(1, "igmp.saddr", iSrcIP1+","+iSrcIP2)),
				[]map[string]interface{}{
					frame(1, igmpType+8, v3QueryBodyHex(0, 2, 125, 2)),
					frame(1, igmpType+12, srcListHex(iSrcIP1, iSrcIP2)),
				}),
		},
		{
			id: "igmp_v3_include_record", summary: "v3 MODE_IS_INCLUDE Group Record",
			ip: map[string]interface{}{"src": iSrc, "dst": "224.0.0.22", "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v3", "kind": "report", "group": iGroup1,
				"records": []interface{}{
					map[string]interface{}{
						"record_type": "mode_is_include", "group": iGroup1,
						"sources": []interface{}{iSrcIP1, iSrcIP2},
					},
				},
			},
			expect: posExpect(1,
				append(carrier(1, "224.0.0.22"),
					field(1, "igmp.type", "0x22"), fieldNZ(1, "igmp.checksum"),
					field(1, "igmp.num_grp_recs", "1"), field(1, "igmp.record_type", "1"),
					field(1, "igmp.num_src", "2"), field(1, "igmp.maddr", iGroup1),
					field(1, "igmp.saddr", iSrcIP1+","+iSrcIP2)),
				[]map[string]interface{}{
					frame(1, igmpType, typeHex(0x22, 0)),
					frame(1, igmpType+8, recordHex(1, iGroup1, 2)),
					frame(1, igmpType+16, srcListHex(iSrcIP1, iSrcIP2)),
				}),
		},
		{
			id: "igmp_v3_exclude_record", summary: "v3 MODE_IS_EXCLUDE Group Record",
			ip: map[string]interface{}{"src": iSrc, "dst": "224.0.0.22", "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v3", "kind": "report", "group": iGroup1,
				"records": []interface{}{
					map[string]interface{}{
						"record_type": "mode_is_exclude", "group": iGroup1,
						"sources": []interface{}{iSrcIP1},
					},
				},
			},
			expect: posExpect(1,
				append(carrier(1, "224.0.0.22"),
					field(1, "igmp.type", "0x22"), fieldNZ(1, "igmp.checksum"),
					field(1, "igmp.record_type", "2"), field(1, "igmp.num_src", "1")),
				[]map[string]interface{}{
					frame(1, igmpType, typeHex(0x22, 0)),
					frame(1, igmpType+8, recordHex(2, iGroup1, 1)),
					frame(1, igmpType+16, srcListHex(iSrcIP1)),
				}),
		},
		{
			id: "igmp_v3_change_records", summary: "v3 mode-change records (empty + single source)",
			ip: map[string]interface{}{"src": iSrc, "dst": "224.0.0.22", "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v3", "kind": "report", "group": iGroup1,
				"records": []interface{}{
					map[string]interface{}{
						"record_type": "change_to_include_mode", "group": iGroup1,
						"sources": []interface{}{},
					},
					map[string]interface{}{
						"record_type": "change_to_exclude_mode", "group": iGroup2,
						"sources": []interface{}{iSrcIP3},
					},
				},
			},
			expect: posExpect(1,
				append(carrier(1, "224.0.0.22"),
					field(1, "igmp.type", "0x22"), fieldNZ(1, "igmp.checksum"),
					field(1, "igmp.num_grp_recs", "2"), field(1, "igmp.record_type", "3,4"),
					field(1, "igmp.maddr", iGroup1+","+iGroup2)),
				[]map[string]interface{}{
					frame(1, igmpType, typeHex(0x22, 0)),
					frame(1, igmpType+8, recordHex(3, iGroup1, 0)),
					frame(1, igmpType+16, recordHex(4, iGroup2, 1)),
					frame(1, igmpType+24, srcListHex(iSrcIP3)),
				}),
		},
		{
			id: "igmp_v3_allow_block_sources", summary: "v3 ALLOW_NEW_SOURCES + BLOCK_OLD_SOURCES",
			ip: map[string]interface{}{"src": iSrc, "dst": "224.0.0.22", "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v3", "kind": "report", "group": iGroup1,
				"records": []interface{}{
					map[string]interface{}{
						"record_type": "allow_new_sources", "group": iGroup1,
						"sources": []interface{}{iSrcIP4},
					},
					map[string]interface{}{
						"record_type": "block_old_sources", "group": iGroup1,
						"sources": []interface{}{iSrcIP5, iSrcIP6},
					},
				},
			},
			expect: posExpect(1,
				append(carrier(1, "224.0.0.22"),
					field(1, "igmp.type", "0x22"), fieldNZ(1, "igmp.checksum"),
					field(1, "igmp.num_grp_recs", "2"), field(1, "igmp.record_type", "5,6"),
					field(1, "igmp.num_src", "1,2")),
				[]map[string]interface{}{
					frame(1, igmpType, typeHex(0x22, 0)),
					frame(1, igmpType+8, recordHex(5, iGroup1, 1)),
					frame(1, igmpType+16, srcListHex(iSrcIP4)),
					frame(1, igmpType+20, recordHex(6, iGroup1, 2)),
					frame(1, igmpType+28, srcListHex(iSrcIP5, iSrcIP6)),
				}),
		},
		{
			id: "igmp_profile_matrix", summary: "v1/v2/v3 profile matrix (3 events)",
			ip: map[string]interface{}{"src": iSrc, "ttl": 1},
			events: []interface{}{
				map[string]interface{}{"profile": "v1", "kind": "query", "group": "0.0.0.0"},
				map[string]interface{}{"profile": "v2", "kind": "report", "group": iGroup1},
				map[string]interface{}{"profile": "v3", "kind": "report", "group": iGroup2,
					"records": []interface{}{
						map[string]interface{}{
							"record_type": "mode_is_include", "group": iGroup2,
							"sources": []interface{}{iSrcIP1},
						},
					}},
			},
			expect: posExpect(3,
				concat(
					carrier(1, "224.0.0.1"),
					[]map[string]interface{}{
						field(1, "igmp.type", "0x11"), fieldNZ(1, "igmp.checksum"),
						field(1, "igmp.maddr", "0.0.0.0"),
					},
					carrier(2, iGroup1),
					[]map[string]interface{}{
						field(2, "igmp.type", "0x16"), fieldNZ(2, "igmp.checksum"),
						field(2, "igmp.maddr", iGroup1),
					},
					carrier(3, "224.0.0.22"),
					[]map[string]interface{}{
						field(3, "igmp.type", "0x22"), fieldNZ(3, "igmp.checksum"),
						field(3, "igmp.record_type", "1"),
					}),
				[]map[string]interface{}{
					frame(1, igmpType, typeHex(0x11, 0)),
					frame(1, igmpType+4, ip4hex("0.0.0.0")),
					frame(2, igmpType, typeHex(0x16, 0)),
					frame(2, igmpType+4, ip4hex(iGroup1)),
					frame(3, igmpType, typeHex(0x22, 0)),
					frame(3, igmpType+8, recordHex(1, iGroup2, 1)),
					frame(3, igmpType+16, srcListHex(iSrcIP1)),
				}),
		},
		{
			id: "igmp_retransmit_state", summary: "querying → member, retransmit identical report",
			ip: map[string]interface{}{"src": iSrc, "ttl": 1},
			events: []interface{}{
				map[string]interface{}{"profile": "v2", "kind": "query", "group": "0.0.0.0", "state": "querying"},
				map[string]interface{}{"profile": "v2", "kind": "report", "group": iGroup1, "state": "member"},
				map[string]interface{}{"profile": "v2", "kind": "report", "group": iGroup1, "state": "member", "retransmit": true},
			},
			expect: posExpect(3,
				concat(
					carrier(1, "224.0.0.1"),
					[]map[string]interface{}{
						field(1, "igmp.type", "0x11"), fieldNZ(1, "igmp.checksum"),
					},
					carrier(2, iGroup1),
					[]map[string]interface{}{
						field(2, "igmp.type", "0x16"), fieldNZ(2, "igmp.checksum"),
						field(2, "igmp.maddr", iGroup1),
					},
					carrier(3, iGroup1),
					[]map[string]interface{}{
						field(3, "igmp.type", "0x16"), fieldNZ(3, "igmp.checksum"),
						fieldSame(3, "igmp.maddr", 2),
					}),
				[]map[string]interface{}{
					frame(1, igmpType, typeHex(0x11, 0)),
					frame(1, igmpType+4, ip4hex("0.0.0.0")),
					frame(2, igmpType, typeHex(0x16, 0)),
					frame(2, igmpType+4, ip4hex(iGroup1)),
					frame(3, igmpType, typeHex(0x16, 0)),
					frame(3, igmpType+4, ip4hex(iGroup1)),
				}),
		},
		{
			id: "igmp_multi_group_sessions", summary: "multi-session a/b/c across v1/v2/v3",
			ip: map[string]interface{}{"src": iSrc, "ttl": 1},
			events: []interface{}{
				map[string]interface{}{"session": "a", "profile": "v1", "kind": "report", "group": iGroup1},
				map[string]interface{}{"session": "b", "profile": "v2", "kind": "report", "group": iGroup2},
				map[string]interface{}{"session": "c", "profile": "v3", "kind": "report", "group": iGroup3,
					"records": []interface{}{
						map[string]interface{}{
							"record_type": "mode_is_include", "group": iGroup3,
							"sources": []interface{}{iSrcIP3},
						},
					}},
				map[string]interface{}{"session": "b", "profile": "v2", "kind": "leave", "group": iGroup2},
			},
			expect: posExpect(4,
				concat(
					carrier(1, iGroup1),
					[]map[string]interface{}{
						field(1, "igmp.type", "0x12"), fieldNZ(1, "igmp.checksum"),
						field(1, "igmp.maddr", iGroup1),
					},
					carrier(2, iGroup2),
					[]map[string]interface{}{
						field(2, "igmp.type", "0x16"), fieldNZ(2, "igmp.checksum"),
						field(2, "igmp.maddr", iGroup2),
					},
					carrier(3, "224.0.0.22"),
					[]map[string]interface{}{
						field(3, "igmp.type", "0x22"), fieldNZ(3, "igmp.checksum"),
						field(3, "igmp.maddr", iGroup3),
					},
					carrier(4, "224.0.0.2"),
					[]map[string]interface{}{
						field(4, "igmp.type", "0x17"), fieldNZ(4, "igmp.checksum"),
						field(4, "igmp.maddr", iGroup2),
					}),
				[]map[string]interface{}{
					frame(1, igmpType, typeHex(0x12, 0)),
					frame(1, igmpType+4, ip4hex(iGroup1)),
					frame(2, igmpType, typeHex(0x16, 0)),
					frame(2, igmpType+4, ip4hex(iGroup2)),
					frame(3, igmpType, typeHex(0x22, 0)),
					frame(3, igmpType+8, recordHex(1, iGroup3, 1)),
					frame(3, igmpType+16, srcListHex(iSrcIP3)),
					frame(4, igmpType, typeHex(0x17, 0)),
					frame(4, igmpType+4, ip4hex(iGroup2)),
				}),
		},
		{
			id: "igmp_ipv4_outer_invariants", summary: "IPv4 carrier invariants (proto 2 / TTL 1 / group dst)",
			ip: map[string]interface{}{"src": iSrc, "dst": iGroup9, "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v2", "kind": "report", "group": iGroup9,
			},
			expect: posExpect(1,
				append(carrier(1, iGroup9),
					field(1, "igmp.type", "0x16"), fieldNZ(1, "igmp.checksum"),
					field(1, "igmp.maddr", iGroup9)),
				[]map[string]interface{}{
					frame(1, igmpType, typeHex(0x16, 0)),
					frame(1, igmpType+4, ip4hex(iGroup9)),
				}),
		},
		{
			id: "igmp_v3_query_boundaries", summary: "v3 boundaries: MRC=255 float code, QRV=7, QQIC=255, 3 sources",
			ip: map[string]interface{}{"src": iSrc, "dst": iGroup4, "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v3", "kind": "query", "group": iGroup4,
				"max_response_code": 255, "s_flag": 1, "qrv": 7, "qqic": 255,
				"sources": []interface{}{iSrcIP1, iSrcIP2, iSrcIP3},
			},
			expect: posExpect(1,
				append(carrier(1, iGroup4),
					field(1, "igmp.type", "0x11"), fieldNZ(1, "igmp.checksum"),
					field(1, "igmp.max_resp", "31744"), field(1, "igmp.s", "1"),
					field(1, "igmp.qrv", "7"), field(1, "igmp.qqic", "255"),
					field(1, "igmp.num_src", "3")),
				[]map[string]interface{}{
					frame(1, igmpType+8, v3QueryBodyHex(1, 7, 255, 3)),
					frame(1, igmpType+12, srcListHex(iSrcIP1, iSrcIP2, iSrcIP3)),
				}),
		},
		{
			id: "igmp_neg_ipv6", summary: "IPv6 is N/A and rejected",
			ip: map[string]interface{}{"src": iSrc, "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v3", "kind": "query", "group": "ff02::1", "address_family": "ipv6",
			},
			expect: negExpect("IPv6"),
		},
		{
			id: "igmp_neg_nonmulticast_destination", summary: "unicast destination rejected",
			ip: map[string]interface{}{"src": iSrc, "dst": "192.0.2.20", "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v2", "kind": "report", "group": iGroup1,
			},
			expect: negExpect("multicast"),
		},
		{
			id: "igmp_neg_ttl_not_one", summary: "TTL != 1 rejected",
			ip: map[string]interface{}{"src": iSrc, "dst": iGroup1, "ttl": 64},
			cfg: map[string]interface{}{
				"profile": "v2", "kind": "report", "group": iGroup1,
			},
			expect: negExpect("TTL"),
		},
		{
			id: "igmp_neg_protocol_not_two", summary: "non-2 IPv4 protocol rejected",
			ip: map[string]interface{}{"src": iSrc, "dst": iGroup1, "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v2", "kind": "report", "group": iGroup1,
				"wire_fault": map[string]interface{}{"kind": "protocol", "value": 17},
			},
			expect: negExpect("Protocol 2"),
		},
		{
			id: "igmp_neg_bad_checksum", summary: "injected bad checksum rejected",
			ip: map[string]interface{}{"src": iSrc, "dst": iGroup1, "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v2", "kind": "report", "group": iGroup1,
				"checksum_mode": "invalid",
				"wire_fault":    map[string]interface{}{"kind": "checksum"},
			},
			expect: negExpect("checksum"),
		},
		{
			id: "igmp_neg_invalid_v3_record", summary: "numeric record_type rejected at decode",
			ip: map[string]interface{}{"src": iSrc, "dst": "224.0.0.22", "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v3", "kind": "report", "group": iGroup1,
				"records": []interface{}{
					map[string]interface{}{
						"record_type": 99, "group": iGroup1,
						"sources": []interface{}{iSrcIP1},
					},
				},
				"wire_fault": map[string]interface{}{"kind": "record"},
			},
			expect: negExpect("record"),
		},
		{
			id: "igmp_neg_invalid_profile_version", summary: "v1 + leave (profile/kind mismatch) rejected",
			ip: map[string]interface{}{"src": iSrc, "dst": iGroup1, "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v1", "kind": "leave", "group": iGroup1,
			},
			expect: negExpect("profile"),
		},
		{
			id: "igmp_neg_query_source_count_length", summary: "source_count != len(sources) rejected",
			ip: map[string]interface{}{"src": iSrc, "dst": iGroup1, "ttl": 1},
			cfg: map[string]interface{}{
				"profile": "v3", "kind": "query", "group": iGroup1,
				"sources": []interface{}{iSrcIP1}, "source_count": 2,
				"wire_fault": map[string]interface{}{"kind": "source_count"},
			},
			expect: negExpect("source count"),
		},
	}
	return out
}

func concat(parts ...[]map[string]interface{}) []map[string]interface{} {
	var out []map[string]interface{}
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestGenerateIGMPCases(t *testing.T) {
	cases := igmpCases()
	if len(cases) != 25 {
		t.Fatalf("want 25 cases (17 pos + 8 neg), got %d", len(cases))
	}
	nPos, nNeg := 0, 0
	for _, c := range cases {
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
	if nPos != 17 || nNeg != 8 {
		t.Fatalf("pos/neg = %d/%d, want 17/8", nPos, nNeg)
	}
	out := make([]map[string]interface{}, len(cases))
	for i, c := range cases {
		out[i] = c.m()
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("marshal cases: %v", err)
	}
	path := filepath.Join("..", "..", "..", "test", "protocol_pcap", "cases", "igmp.json")
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	fmt.Printf("wrote %s (%d cases: %d pos + %d neg)\n", path, len(out), nPos, nNeg)
}
