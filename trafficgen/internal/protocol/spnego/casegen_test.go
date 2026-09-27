// Package spnego — casegen 一次性用例生成器（D-SPNEGO-1 P5）。
//
// 20 例（14 正 + 6 负），按用例文档 §2 权威序（61-spnego-testcase.md v1.2.0）。
// 正例帧断言取自全链真实回放（BuildLayersPlanner→Plan——单权威，无重复编码）
// + tshark 字段名（design §10.4 ③ OID 名库 + §10.7 M-shape-5 通道分流）：
// HTTP carrier 走 `spnego.*`/`http.*` 字段，裸 TCP carrier 走 frames hex
//（-V 无 OID 行 + decode_as 全禁，v1.2.0 勘正）。
//
// 先跑后钉口径（P5 实测计数 vs 设计 §2/§9 约定计数）；包数以落盘 pcap 实测
// 校准，不照抄契约约定值：
//
//	TCP 算术 = 3 握手 + 每事件一数据段（无 MSS 超出、无多事件合并时）+
//	4 挥手。事件数 E 的会话 → 3+E+4。
package spnego

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/http" // http 底座生成器（HTTP profile 链 [ip,tcp,http,spnego] 回放用；layers_test 共享文件同款）
)

type sfld struct {
	Packet   int
	Field    string
	Value    string
	Nonzero  bool
	Same     int
	Distinct []string
	Exclude  []string
}

func (f sfld) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "field": f.Field}
	if f.Value != "" {
		m["value"] = f.Value
	}
	if f.Nonzero {
		m["nonzero"] = true
	}
	if f.Same > 0 {
		m["same_as_packet"] = f.Same
	}
	if len(f.Distinct) > 0 {
		m["distinct_values"] = f.Distinct
	}
	if len(f.Exclude) > 0 {
		m["distinct_exclude"] = f.Exclude
	}
	return m
}

type sfr struct {
	Packet int
	Offset int
	Hex    string
}

func (f sfr) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "hex": f.Hex}
	if f.Offset != 0 {
		m["offset"] = f.Offset
	}
	return m
}

// scase 是生成中的一例。flows = 该例实际生成的流数（strategy_flow_control
// 的 flows 值；>1 时套件捕获含多流，packet_count = 单流回放包数 × flows）。
type scase struct {
	id         string
	summary    string
	spec       map[string]interface{}
	strategyFC map[string]interface{}
	flows      int
	fields     []sfld
	frames     []sfr
	pcount     int
	err        string
}

func (c *scase) emit(t *testing.T) map[string]interface{} {
	t.Helper()
	expect := map[string]interface{}{}
	if c.err != "" {
		expect["expect_error"] = true
		expect["error_contains"] = c.err
	} else {
		var fs []interface{}
		for _, f := range c.fields {
			fs = append(fs, f.m())
		}
		var fr []interface{}
		for _, f := range c.frames {
			fr = append(fr, f.m())
		}
		if fs != nil {
			expect["fields"] = fs
		}
		if fr != nil {
			expect["frames"] = fr
		}
		flows := c.flows
		if flows == 0 {
			flows = 1
		}
		expect["packet_count"] = c.pcount * flows
	}
	out := map[string]interface{}{
		"id": c.id, "proto": "spnego", "summary": c.summary,
		"spec_json": c.spec, "expect": expect,
	}
	// 多流例：flows 走 strategy_flow_control（策略级真值；spec_json 内的
	// flow_control 是声明性记录，不驱动流数——套件据 case 的 strategy_fc
	// 设置 generate_traffic 参数，dns_name_dynamic 先例）。
	if c.strategyFC != nil {
		out["strategy_fc"] = c.strategyFC
	}
	return out
}

// sLayers 组装一例的 spec_json（四元组住 ip/tcp 层；顶层仅 layers +
// flow_control；数量走 flow_control.flows）。
func sLayers(ip map[string]interface{}, tcp map[string]interface{}, extra []interface{}, spnego map[string]interface{}, flows int) map[string]interface{} {
	arr := []interface{}{map[string]interface{}{"ip": ip}, map[string]interface{}{"tcp": tcp}}
	arr = append(arr, extra...)
	arr = append(arr, map[string]interface{}{"spnego": spnego})
	return map[string]interface{}{
		"layers":       arr,
		"flow_control": map[string]interface{}{"flows": flows},
	}
}

func sEv(kind string) map[string]interface{} { return map[string]interface{}{"kind": kind} }

// sDriveCase 全链回放一例的 spec（与套件同路径）：Plan→payload 流→返回
// 数据包负载（逐事件一单元的真实字节——正例 frames/字段钉死的单权威来源）。
func sDriveCase(t *testing.T, spec map[string]interface{}) []core.PacketConfig {
	t.Helper()
	raw, err := json.Marshal(spec["layers"])
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	p, err := layers.BuildLayersPlanner("spnego", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	// 四元组回填：以链声明为准（spnego_chain_test 同款）。
	arr, _ := spec["layers"].([]interface{})
	fspec := core.FlowSpec{SrcIP: "192.0.2.61", DstIP: "198.51.100.61", SrcPort: 45061, DstPort: 445}
	for _, item := range arr {
		m, _ := item.(map[string]interface{})
		if m == nil {
			continue
		}
		if ipc, ok := m["ip"].(map[string]interface{}); ok {
			if v, ok := ipc["src"].(string); ok && v != "" {
				fspec.SrcIP = v
			}
			if v, ok := ipc["dst"].(string); ok && v != "" {
				fspec.DstIP = v
			}
		}
		if tcpc, ok := m["tcp"].(map[string]interface{}); ok {
			switch v := tcpc["src_port"].(type) {
			case float64:
				fspec.SrcPort = uint16(v)
			case int:
				fspec.SrcPort = uint16(v)
			}
			switch v := tcpc["dst_port"].(type) {
			case float64:
				fspec.DstPort = uint16(v)
			case int:
				fspec.DstPort = uint16(v)
			}
		}
	}
	ch, err := p.Plan(context.Background(), fspec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts
}

func sCount(pkts []core.PacketConfig) int { return len(pkts) }

// TestSPNEGOCasegenOnce 一次性生成 20 例到 cases/spnego.json（P5 落盘）。
func TestSPNEGOCasegenOnce(t *testing.T) {
	cli := map[string]interface{}{"src": "192.0.2.61", "dst": "198.51.100.61"}
	cli6 := map[string]interface{}{"src": "2001:db8::61", "dst": "2001:db8:ffff::61"}
	tcp445 := map[string]interface{}{"src_port": 45061, "dst_port": 445}
	tcp80 := map[string]interface{}{"src_port": 45062, "dst_port": 80}
	httpL := []interface{}{map[string]interface{}{"http": map[string]interface{}{"method": "GET", "uri": "/", "keep_alive": true}}}
	krb := "1.2.840.113554.1.2.2"
	mskrb := "1.2.840.48018.1.2.2"
	ntlmOID := "1.3.6.1.4.1.311.2.2.10"

	cases := []*scase{
		// #1 HTTP/IPv4 全链（init_resp 双消息 + 200）。
		{
			id: "spnego_http_ipv4_init", summary: "HTTP Negotiate/IPv4：401→Authorization(init)→WWW-Authenticate(resp)→200 + InitialContextToken/negTokenInit",
			spec: sLayers(cli, tcp80, httpL, map[string]interface{}{
				"profile": "http", "negotiation": "init_resp",
				"mech_types": []interface{}{krb, mskrb},
				"mech_token": map[string]interface{}{"opaque": true},
				"sessions": []interface{}{map[string]interface{}{"id": "s1", "events": []interface{}{
					sEv("challenge"), sEv("init"), sEv("resp"),
					map[string]interface{}{"kind": "http_success"},
				}}},
			}, 1),
		},
		// #2 HTTP/IPv6 独立 fixture。
		{
			id: "spnego_http_ipv6_init", summary: "HTTP Negotiate/IPv6 独立 fixture：ipv6.nxt=6 + 地址族 + HTTP Negotiate 方向与 DER 外层",
			spec: sLayers(cli6, tcp80, httpL, map[string]interface{}{
				"profile": "http", "negotiation": "init_resp",
				"mech_types": []interface{}{krb, mskrb},
				"mech_token": map[string]interface{}{"opaque": true},
				"sessions": []interface{}{map[string]interface{}{"id": "s1", "events": []interface{}{
					sEv("challenge"), sEv("init"), sEv("resp"),
					map[string]interface{}{"kind": "http_success"},
				}}},
			}, 1),
		},
		// #3 裸 TCP/IPv4（frames hex 通道）。
		{
			id: "spnego_tcp_ipv4_init", summary: "裸 TCP/IPv4 stream 携带 InitialContextToken/negTokenInit：重组 stream + DER 父长度 + SPNEGO OID",
			spec: sLayers(cli, tcp445, nil, map[string]interface{}{
				"profile": "tcp", "negotiation": "init_resp",
				"mech_types": []interface{}{krb, mskrb, ntlmOID},
				"mech_token": map[string]interface{}{"opaque": true},
				"sessions": []interface{}{map[string]interface{}{"id": "s1", "events": []interface{}{
					sEv("init"), sEv("resp"),
				}}},
			}, 1),
		},
		// #4 裸 TCP/IPv6（frames hex，payload 起点 74）。
		{
			id: "spnego_tcp_ipv6_init", summary: "裸 TCP/IPv6 stream 携带 token：ipv6.nxt=6 + IPv6 checksum + token 重组",
			spec: sLayers(cli6, tcp445, nil, map[string]interface{}{
				"profile": "tcp", "negotiation": "init_resp",
				"mech_types": []interface{}{krb, mskrb, ntlmOID},
				"mech_token": map[string]interface{}{"opaque": true},
				"sessions": []interface{}{map[string]interface{}{"id": "s1", "events": []interface{}{
					sEv("init"), sEv("resp"),
				}}},
			}, 1),
		},
		// #5 negTokenInit 可选字段 + dissector 形 negHints（RFC 形 MIC 不共存）。
		{
			id: "spnego_neg_token_init_hints", summary: "negTokenInit：有序 mechTypes + reqFlags + negHints([3] dissector 形) + mechToken；RFC 形 MIC 不共存",
			spec: sLayers(cli, tcp80, httpL, map[string]interface{}{
				"profile": "http", "negotiation": "init_resp",
				"mech_types": []interface{}{krb, mskrb},
				"req_flags":  0xC0,
				"neg_hints": map[string]interface{}{
					"carry": "dissector", "hint_name": "hint.example", "hint_address": "C0000201",
				},
				"mech_token": map[string]interface{}{"opaque": true, "len": 4},
				"sessions": []interface{}{map[string]interface{}{"id": "s1", "events": []interface{}{
					sEv("challenge"), sEv("init"), sEv("resp"),
					map[string]interface{}{"kind": "http_success"},
				}}},
			}, 1),
		},
		// #6 negTokenResp 选定（accept_incomplete→completed 链）。
		{
			id: "spnego_neg_token_resp_selection", summary: "negTokenResp：negResult + supportedMech(∈列表) + responseToken；accept_incomplete(1)→completed",
			spec: sLayers(cli, tcp80, httpL, map[string]interface{}{
				"profile": "http", "negotiation": "init_resp",
				"mech_types": []interface{}{krb, mskrb},
				"supported_mech": mskrb, "neg_result": 1,
				"mech_token":     map[string]interface{}{"opaque": true},
				"response_token": map[string]interface{}{"opaque": true},
				"sessions": []interface{}{map[string]interface{}{"id": "s1", "events": []interface{}{
					sEv("challenge"), sEv("init"), sEv("resp"),
					map[string]interface{}{"kind": "http_success"},
				}}},
			}, 1),
		},
		// #7 旧式 negTokenTarg（RFC 2478 §3.2.1 字段序）。
		{
			id: "spnego_neg_token_targ_legacy", summary: "旧式 negTokenTarg：显式 init_targ 声明 + [0]negResult/[1]supportedMech/[2]responseToken 字段序",
			spec: sLayers(cli, tcp445, nil, map[string]interface{}{
				"profile": "tcp", "negotiation": "init_targ", "neg_result": 0,
				"mech_types": []interface{}{krb, mskrb},
				"supported_mech": mskrb,
				"sessions": []interface{}{map[string]interface{}{"id": "s1", "events": []interface{}{
					sEv("init"), sEv("targ"),
				}}},
			}, 1),
		},
		// #8 三 OID 变体与列表序。
		{
			id: "spnego_mech_oid_variants", summary: "三机制 OID 变体：Kerberos/msKrb5/NTLM 逐字节 DER + supportedMech 列表绑定",
			spec: sLayers(cli, tcp445, nil, map[string]interface{}{
				"profile": "tcp", "negotiation": "init_resp",
				"mech_types": []interface{}{krb, mskrb, ntlmOID},
				"supported_mech": ntlmOID,
				"mech_token":     map[string]interface{}{"opaque": true},
				"sessions": []interface{}{map[string]interface{}{"id": "s1", "events": []interface{}{
					sEv("init"), sEv("resp"),
				}}},
			}, 1),
		},
		// #9 opaque token 存在/长度/重传相等边界（零长占位 + 非零）。
		{
			id: "spnego_mech_token_opaque", summary: "不透明 token：零长占位 + 非零负载 + OCTET STRING length/nonzero（内层不解析）",
			spec: sLayers(cli, tcp445, nil, map[string]interface{}{
				"profile": "tcp", "negotiation": "init_resp",
				"mech_types": []interface{}{krb},
				"mech_token": map[string]interface{}{"opaque": true, "len": 0},
				"response_token": map[string]interface{}{"opaque": true},
				"sessions": []interface{}{map[string]interface{}{"id": "s1", "events": []interface{}{
					sEv("init"), sEv("resp"),
				}}},
			}, 1),
		},
		// #10 mechListMIC（RFC 形 [3]，frames hex 通道 + mechTypes/responseToken 字段）。
		{
			id: "spnego_mechlist_mic", summary: "mechListMIC：request-mic(3)→补 MIC；验证输入=原始 DER mechTypes；线位 RFC [3]",
			spec: sLayers(cli, tcp445, nil, map[string]interface{}{
				"profile": "tcp", "negotiation": "init_resp",
				"mech_types": []interface{}{krb, mskrb},
				"supported_mech": mskrb, "neg_result": 3,
				"mech_token":    map[string]interface{}{"opaque": true},
				"mech_list_mic": map[string]interface{}{"layout": "rfc4178", "opaque": true},
				"sessions": []interface{}{map[string]interface{}{"id": "s1", "events": []interface{}{
					sEv("init"), sEv("resp"), sEv("mic"),
				}}},
			}, 1),
		},
		// #11 DER canonical 边界（短/长 length + 空可选字段）。
		{
			id: "spnego_der_canonical_boundaries", summary: "DER 边界：空可选字段 + 短/长 length（200B token 长形 0x82 档）+ 父长度覆盖子 TLV",
			spec: sLayers(cli, tcp445, nil, map[string]interface{}{
				"profile": "tcp", "negotiation": "init_resp",
				"mech_types": []interface{}{krb, mskrb, ntlmOID},
				"mech_token": map[string]interface{}{"opaque": true, "len": 200},
				"sessions": []interface{}{map[string]interface{}{"id": "s1", "events": []interface{}{
					sEv("init"), sEv("resp"),
				}}},
			}, 1),
		},
		// #12 降级防护（reject 终态）。
		{
			id: "spnego_downgrade_prevention", summary: "降级防护：selectedMech ∈ 列表 + reject(2)→终止；supportedMech 由会话级覆盖钉死",
			spec: sLayers(cli, tcp445, nil, map[string]interface{}{
				"profile": "tcp", "negotiation": "init_resp",
				"mech_types": []interface{}{krb, mskrb},
				"sessions": []interface{}{map[string]interface{}{
					"id": "s1", "supported_mech": mskrb, "neg_result": 2,
					"events": []interface{}{
						sEv("init"), sEv("resp"),
					},
				}},
			}, 1),
		},
		// #13 多流多会话（flows=2 × 动态 src_port = 两条独立 TCP stream；
		// 每流承载 s1(krb+mskrb→accept_completed) 与 s2(NTLM→reject 异常
		// 终止) 两会话；候选列表/选定机制/状态/四元组按流按会话隔离）。
		// 交织维度 ≥3：多会话 × 多事务（每流 2 次协商）× 多流（2 四元组）
		// × 异常分支（s2 reject）。
		{
			id: "spnego_multi_session_stream", summary: "多流多会话隔离：flows=2 两条独立 TCP stream（45061/45062→445，四元组隔离）+ 每流 s1(Kerberos+msKrb5→accept_completed)/s2(NTLM→reject 异常终止) 会话；候选列表/选定机制/状态不串用",
			spec: map[string]interface{}{
				"layers": []interface{}{
					map[string]interface{}{"ip": cli},
					map[string]interface{}{"tcp": map[string]interface{}{
						"src_port": map[string]interface{}{"strategy": "inc", "range": []interface{}{45061, 45070}, "step": 1},
						"dst_port": 445,
					}},
					map[string]interface{}{"spnego": map[string]interface{}{
						"profile": "tcp", "negotiation": "init_resp",
						"mech_types": []interface{}{krb, mskrb},
						"mech_token": map[string]interface{}{"opaque": true},
						"sessions": []interface{}{
							map[string]interface{}{"id": "s1", "neg_result": 0, "events": []interface{}{
								sEv("init"), sEv("resp"),
							}},
							map[string]interface{}{"id": "s2", "mech_types": []interface{}{ntlmOID},
								"supported_mech": ntlmOID, "neg_result": 2,
								"events": []interface{}{
									sEv("init"), sEv("resp"),
								}},
						},
					}},
				},
				"flow_control": map[string]interface{}{"flows": 2},
			},
			strategyFC: map[string]interface{}{"type": "flows", "value": 2},
			flows:      2,
		},
		// #14 PCAP/NIC 一致性（稳定 fixture）。
		{
			id: "spnego_pcap_nic_consistency", summary: "PCAP/NIC 双路一致：TCP carrier/方向/端口/HTTP header/DER 外层/OID/token 长度一致",
			spec: sLayers(cli, tcp80, httpL, map[string]interface{}{
				"profile": "http", "negotiation": "init_resp",
				"mech_types": []interface{}{krb, mskrb},
				"mech_token": map[string]interface{}{"opaque": true, "len": 32},
				"sessions": []interface{}{map[string]interface{}{"id": "s1", "events": []interface{}{
					sEv("challenge"), sEv("init"), sEv("resp"),
					map[string]interface{}{"kind": "http_success"},
				}}},
			}, 1),
		},
		// #15–#20 六负例（wire_fault 一行一注入；expect 键集严格）。
		{id: "spnego_neg_der_truncated", summary: "DER tag/length/子 TLV 截断（wire_fault 注入）",
			spec: sLayers(cli, tcp445, nil, map[string]interface{}{"wire_fault": "der_truncated"}, 1), err: "der"},
		{id: "spnego_neg_der_length_overflow", summary: "长形式溢出/父子长度不一致/非最短编码（wire_fault 注入）",
			spec: sLayers(cli, tcp445, nil, map[string]interface{}{"wire_fault": "der_length"}, 1), err: "length"},
		{id: "spnego_neg_invalid_token_choice", summary: "未知 choice/错误 tag class/init-resp-targ 混用（wire_fault 注入）",
			spec: sLayers(cli, tcp445, nil, map[string]interface{}{"wire_fault": "choice"}, 1), err: "choice"},
		{id: "spnego_neg_mech_oid_selection", summary: "非法 OID/选定机制绑定错误（wire_fault 注入）",
			spec: sLayers(cli, tcp445, nil, map[string]interface{}{"wire_fault": "mech_oid"}, 1), err: "oid"},
		{id: "spnego_neg_mic_downgrade", summary: "MIC 缺失/不匹配/列表改写或降级选择（wire_fault 注入）",
			spec: sLayers(cli, tcp445, nil, map[string]interface{}{"wire_fault": "mic"}, 1), err: "mic"},
		{id: "spnego_neg_carrier_profile", summary: "HTTP/TCP profile/端口/stream 边界错误（wire_fault 注入）",
			spec: sLayers(cli, tcp445, nil, map[string]interface{}{"wire_fault": "carrier"}, 1), err: "carrier"},
	}

	// 回放 + 钉包数 + 钉断言（字段名按通道分流：HTTP=spnego.*/http.* 字段面，
	// 裸 TCP=frames hex；裸 TCP carrier 无 spnego 字段通道——testcase §3.1）。
	for i, c := range cases {
		if c.err != "" {
			continue
		}
		pkts := sDriveCase(t, c.spec)
		c.pcount = sCount(pkts)
		c.fields, c.frames = nailExpect(t, i, c, pkts)
	}

	var out []map[string]interface{}
	for _, c := range cases {
		out = append(out, c.emit(t))
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// 落盘到 test/protocol_pcap/cases/spnego.json（相对本文件三级上跳）。
	dst := "spnego.json.staged"
	if v := os.Getenv("SPNEGO_CASEGEN_OUT"); v != "" {
		dst = v
	}
	if err := os.WriteFile(dst, append(raw, '\n'), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Logf("staged %d cases -> %s (counts: %s)", len(out), dst, countsLine(cases))
}

func countsLine(cases []*scase) string {
	var parts []string
	for _, c := range cases {
		if c.err == "" {
			parts = append(parts, fmt.Sprintf("%s=%d", c.id, c.pcount))
		}
	}
	return strings.Join(parts, " ")
}

// nailExpect 按用例序号钉断言（字段/frames；包号按 3+E+4 算术逐例定位）。
func nailExpect(t *testing.T, i int, c *scase, pkts []core.PacketConfig) ([]sfld, []sfr) {
	t.Helper()
	switch c.id {
	case "spnego_http_ipv4_init":
		return []sfld{
			{1, "tcp.dstport", "80", false, 0, nil, nil},
			{1, "ip.proto", "6", false, 0, nil, nil},
			{4, "http.response.code", "401", false, 0, nil, nil},
			{4, "http.www_authenticate", "", true, 0, nil, nil},
			{5, "http.authorization", "", true, 0, nil, nil},
			{5, "spnego.negTokenInit_element", "1", false, 0, nil, nil},
			{5, "spnego.mechTypes", "2", false, 0, nil, nil},
			{7, "http.response.code", "200", false, 0, nil, nil},
		}, nil
	case "spnego_http_ipv6_init":
		return []sfld{
			{1, "ipv6.nxt", "6", false, 0, nil, nil},
			{4, "http.response.code", "401", false, 0, nil, nil},
			{5, "spnego.negTokenInit_element", "1", false, 0, nil, nil},
			{7, "http.response.code", "200", false, 0, nil, nil},
		}, nil
	case "spnego_tcp_ipv4_init":
		return []sfld{
			{1, "tcp.dstport", "445", false, 0, nil, nil},
			{1, "ip.proto", "6", false, 0, nil, nil},
		}, hexOf(pkts, 4, 54)
	case "spnego_tcp_ipv6_init":
		return []sfld{
			{1, "tcp.dstport", "445", false, 0, nil, nil},
			{1, "ipv6.nxt", "6", false, 0, nil, nil},
		}, hexOf(pkts, 4, 74)
	case "spnego_neg_token_init_hints":
		return []sfld{
			{5, "spnego.negTokenInit_element", "1", false, 0, nil, nil},
			{5, "spnego.reqFlags", "c0", false, 0, nil, nil},
			{5, "spnego.mechToken", "", true, 0, nil, nil},
		}, nil
	case "spnego_neg_token_resp_selection":
		return []sfld{
			{6, "spnego.negResult", "1", false, 0, nil, nil},
			{6, "spnego.supportedMech", "1.2.840.48018.1.2.2", false, 0, nil, nil},
			{6, "spnego.responseToken", "", true, 0, nil, nil},
			{7, "http.response.code", "200", false, 0, nil, nil},
		}, nil
	case "spnego_neg_token_targ_legacy":
		return []sfld{
			{1, "tcp.dstport", "445", false, 0, nil, nil},
			{1, "ip.proto", "6", false, 0, nil, nil},
		}, hexOf(pkts, 4, 54)
	case "spnego_mech_oid_variants":
		// m1（P6 修轮）：resp 帧同样钉死——supportedMech 必须 ∈ 原始列表，
		// 且本档显式选定列表第三项 NTLM（selectedMech 绑定面，非仅 init 侧）。
		return []sfld{
			{1, "tcp.dstport", "445", false, 0, nil, nil},
			{1, "ip.proto", "6", false, 0, nil, nil},
		}, append(hexOf(pkts, 4, 54), hexOf(pkts, 5, 54)...)
	case "spnego_mech_token_opaque":
		return []sfld{
			{1, "tcp.dstport", "445", false, 0, nil, nil},
			{1, "ip.proto", "6", false, 0, nil, nil},
		}, hexOf(pkts, 4, 54)
	case "spnego_mechlist_mic":
		return []sfld{
			{1, "tcp.dstport", "445", false, 0, nil, nil},
			{1, "ip.proto", "6", false, 0, nil, nil},
		}, micHex(pkts)
	case "spnego_der_canonical_boundaries":
		return []sfld{
			{4, "ip.proto", "6", false, 0, nil, nil},
			{4, "tcp.dstport", "445", false, 0, nil, nil},
		}, longHex(pkts)
	case "spnego_downgrade_prevention":
		return []sfld{
			{1, "tcp.dstport", "445", false, 0, nil, nil},
			{1, "ip.proto", "6", false, 0, nil, nil},
		}, hexOf(pkts, 5, 54)
	case "spnego_multi_session_stream":
		// 单流回放 11 包（3 握手 + 4 事件 + 4 挥手）；flows=2 → 全局第 12–22
		// 包为第二条流，字节与第一条逐字节相同（仅四元组不同）——按流基数
		// 折算回单流回放索引取 hex。
		const sPerFlow = 11
		up := func(n int) string {
			i := n
			if n > sPerFlow {
				i = n - sPerFlow
			}
			return sWirePin(pkts, i)
		}
		return []sfld{
			{1, "tcp.dstport", "445", false, 0, nil, nil},
			{1, "tcp.srcport", "45061", false, 0, nil, nil},
			{12, "tcp.srcport", "45062", false, 0, nil, nil},
			{1, "ip.proto", "6", false, 0, nil, nil},
			// 全捕获恰两条客户端流（四元组隔离）：distinct 语义=恰好这些值，
			// 服务端方向 srcport 445 排除。
			{0, "tcp.srcport", "", false, 0, []string{"45061", "45062"}, []string{"445"}},
		}, []sfr{
			{4, 54, up(4)},   // 流 1 s1 init（krb+mskrb 双候选）
			{5, 54, up(5)},   // 流 1 s1 resp（accept_completed 0 + supportedMech=krb）
			{6, 54, up(6)},   // 流 1 s2 init（NTLM 单候选——候选列表不串用）
			{7, 54, up(7)},   // 流 1 s2 resp（reject 2——异常终止分支）
			{15, 54, up(15)}, // 流 2 s1 init（同字节、独立四元组）
			{18, 54, up(18)}, // 流 2 s2 resp（reject——两流状态一致且各流独立）
		}
	case "spnego_pcap_nic_consistency":
		return []sfld{
			{1, "tcp.dstport", "80", false, 0, nil, nil},
			{4, "ip.proto", "6", false, 0, nil, nil},
			{5, "spnego.negTokenInit_element", "1", false, 0, nil, nil},
		}, nil
	default:
		t.Fatalf("nailExpect: unknown case %s", c.id)
		return nil, nil
	}
}

// sWirePin 取第 n 包（1-based）transport payload 的完整大写 hex（ntlm
// nWirePin 同款——frames 断言走全帧 offset 处的前缀匹配，hex 内容权威=
/// 全链回放的真实字节）。
func sWirePin(pkts []core.PacketConfig, n int) string {
	if n < 1 || n > len(pkts) || len(pkts[n-1].Payload) == 0 {
		return ""
	}
	return strings.ToUpper(hex.EncodeToString(pkts[n-1].Payload))
}

// hexOf 取第 n 包的整 DER hex（裸 TCP 通道：payload 起点 offset（54/74）。
func hexOf(pkts []core.PacketConfig, n, off int) []sfr {
	return []sfr{{Packet: n, Offset: off, Hex: sWirePin(pkts, n)}}
}

// micHex 取 MIC 事件包（#10 p6）的 [3] 槽 hex（A3+len+04+len 锚——整
// payload 前缀钉，含槽位）。
func micHex(pkts []core.PacketConfig) []sfr { return hexOf(pkts, 6, 54) }

// longHex 取长形 DER 包（#11 p4，200B token 0x82 档）的整 payload hex。
func longHex(pkts []core.PacketConfig) []sfr { return hexOf(pkts, 4, 54) }
